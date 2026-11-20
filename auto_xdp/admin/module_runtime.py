"""Built-in modules using the common handler generation/ownership transaction.

SYN Cookie has a TC ingress companion instead of a TC egress dispatch entry.
Only that hook and its capability/sysctl requirements are module-specific.
"""
from __future__ import annotations

import argparse
import json
import os
import socket
import subprocess
import sys
from pathlib import Path

from auto_xdp.admin import config_file, handlers, kernel_modules
from auto_xdp import config as configuration
from auto_xdp.bpf.maps import BpfRuntimeConfigMap, XDP_CFG_FLAG_ICMP_REPLY
from auto_xdp.bpf.syncookie import acquire_sysctl, probe_syncookie_capability, release_sysctl
from auto_xdp.bpf.syscall import obj_get, program_id


_PROGRAM_PINS = ("prog", "ingress")
TC_PRIORITY = 49151
TC_HANDLE = 2


_ICMP_KEYS = (1, 58)


def load_icmp(root: Path, obj: Path) -> None:
    """Publish IPv4 and IPv6 together, after the common loader resolves .ko dependencies."""
    with handlers._handler_lock(root):
        handlers._load_handler_bundle(
            root / "proto_handlers", 1, [("prog", obj, "xdp")], root / "modules/icmp",
            [handlers.program_array_binding(root / "proto_handlers", 58)],
        )
    _clear_degraded("icmp", root)


def _icmp_bound(root: Path) -> bool:
    pin, table = root / "modules/icmp/prog", root / "proto_handlers"
    if not pin.exists():
        return False
    fd = obj_get(str(pin))
    try:
        ident = program_id(fd)
    finally:
        os.close(fd)
    return all(handlers.program_array_binding(table, key).read() == ident for key in _ICMP_KEYS)


def _icmp_gate(root: Path) -> bool:
    runtime = BpfRuntimeConfigMap(str(root / "xdp_runtime_cfg"))
    try:
        flags = runtime.get_cfg_flags()
    finally:
        runtime.close()
    if flags is None:
        raise RuntimeError("Cannot read the ICMP runtime gate")
    return bool(flags & XDP_CFG_FLAG_ICMP_REPLY)


def icmp_slots_free(root: Path) -> bool:
    """Both ICMP protocol slots are empty: with the gate set, Echo Replies drop.

    A program in slot 1 or 58 that is not the managed handler (for example a
    raw [slots] entry) would receive Echo Replies instead of the drop in
    slots.h, so a failed handler load is not a fail-closed state there.
    """
    table = root / "proto_handlers"
    return all(handlers.program_array_binding(table, key).read() is None for key in _ICMP_KEYS)


def icmp_live_degraded(root: Path) -> str | None:
    """How a generation with the reply gate set but no ICMP handler treats Echo Replies.

    None when the gate is off or the managed handler is bound; "dropped" when
    both protocol slots are empty (slots.h drops them); "foreign" when another
    program holds slot 1 or 58 and receives them instead.
    """
    if not _icmp_gate(root) or _icmp_bound(root):
        return None
    return "dropped" if icmp_slots_free(root) else "foreign"


def prepare_icmp(root: Path, *, enabled: bool) -> None:
    """Reconcile config reloads before the backend publishes the runtime gate."""
    if not enabled:
        remove_icmp(root)
        return
    if _icmp_bound(root):
        _clear_degraded("icmp", root)
        return
    load_icmp(root, kernel_modules.sdk_directory() / "icmp_handler.o")


# An enabled module that cannot be activated is degraded, not fatal: the data
# plane already fails closed for it (the ICMP gate drops Echo Replies in
# slots.h; the backend admits a cookie endpoint only while the cookie program
# is dispatched), so the core firewall can stay attached. One marker per module
# keeps the report to a single error across the loader, the daemon and their
# retries, and feeds `axdp status`.
DEGRADABLE_MODULES = {
    "icmp": "reply handler not loaded, Echo Replies are dropped",
    "syncookie": "module not active, TCP endpoints that use SYN cookies stay closed",
}


def degraded_modules(root: Path, run_state_dir: Path, config: Path | None,
                     interfaces: list[str]) -> dict[str, str]:
    """Enabled modules whose traffic is held closed, for `axdp status`.

    The state is read from the live generation; a marker only supplies the
    reason. A marker left behind after the module was fixed or disabled is
    ignored, and a degraded state is shown even when its marker is missing.
    """
    try:
        # A missing file reads as an empty configuration; here it means unknown.
        modules: dict | None = (configuration.module_configs(config_file.load_toml(config))
                                if config is not None and config.is_file() else None)
    except (OSError, ValueError):
        modules = None
    _errors = (OSError, RuntimeError, ValueError, subprocess.SubprocessError)
    result: dict[str, str] = {}

    enabled = None if modules is None else bool(modules.get("icmp", {}).get("enabled", False))
    reason = degraded_reason("icmp", run_state_dir)
    held: str | None = "dropped" if reason else None  # unknown configuration or state: trust the marker
    if enabled is False:
        held = None
    elif enabled and (root / "xdp_runtime_cfg").exists():
        try:
            held = icmp_live_degraded(root)
        except _errors:
            pass
    if held == "dropped":
        result["icmp"] = f"{DEGRADABLE_MODULES['icmp']}: {reason or 'no handler is bound'}"
    elif held == "foreign":
        result["icmp"] = ("reply handler not loaded and protocol slot 1 or 58 holds another program, "
                          f"which receives Echo Replies: {reason or 'no handler is bound'}")

    cookie = {} if modules is None else modules.get("syncookie", {})
    enabled = None if modules is None else bool(cookie.get("enabled", False))
    if enabled and all(str(mode).lower() == "off" for mode in _syncookie_modes(cookie)):
        enabled = False  # no endpoint uses cookies, so none is held closed
    reason = degraded_reason("syncookie", run_state_dir)
    if enabled is None and reason:
        result["syncookie"] = f"{DEGRADABLE_MODULES['syncookie']}: {reason}"
    elif enabled:
        try:
            verify_syncookie(root, interfaces)
        except _errors as error:
            cause = reason or str(error)
            try:
                partial = program_available(root)
            except _errors:
                partial = False
            effect = ("previous cookie program dispatched but not verified on every interface" if partial
                      else DEGRADABLE_MODULES["syncookie"])
            result["syncookie"] = f"{effect}: {cause}"
    return result


def _degraded_marker(module: str, run_state_dir: Path | None = None) -> Path:
    return (run_state_dir or Path(os.environ.get("RUN_STATE_DIR", "/run/auto_xdp"))) / f"{module}_degraded"


def degraded_reason(module: str, run_state_dir: Path | None = None) -> str | None:
    try:
        lines = _degraded_marker(module, run_state_dir).read_text().splitlines()
    except OSError:
        return None
    return (lines[0].strip() if lines else "") or "could not be activated"


def _is_candidate_root(root: Path | None) -> bool:
    # The runtime stages a generation in ${BPF_PIN_DIR}_next. Its success says
    # nothing about the live generation until it is committed under the live
    # name, after which the next load there clears the marker.
    return root is not None and root.name.endswith("_next")


def _clear_degraded(module: str, root: Path | None = None) -> None:
    if _is_candidate_root(root):
        return
    try:
        _degraded_marker(module).unlink()
    except OSError:
        pass


def _failure_cause(exc: BaseException) -> str:
    """One line from a loader error that may carry a whole verifier log."""
    lines = [line.strip() for line in str(exc).splitlines() if line.strip()]
    if not lines:
        return type(exc).__name__
    for line in lines[1:]:
        if "kernel function" in line and "is not allowed" in line:
            return (f"{lines[0]}: {line} (the kernel module providing it registers no such "
                    f"kfunc on kernel {os.uname().release}; rebuild or upgrade it)")
    return lines[0] if len(lines) == 1 else f"{lines[0]}: {lines[-1]}"


def _note_degraded(module: str, exc: BaseException, *, always: bool = False) -> Path | None:
    """Record the degraded state; return the marker when it should be reported.

    The runtime start reports on every run (`always`): one error per start,
    whatever an earlier marker says. The daemon's retries report only a cause
    that differs from the recorded one.
    """
    marker = _degraded_marker(module)
    first = always or degraded_reason(module, marker.parent) != _failure_cause(exc)
    try:
        marker.parent.mkdir(parents=True, exist_ok=True)
        temporary = marker.with_name(f".{marker.name}.{os.getpid()}")
        temporary.write_text(f"{_failure_cause(exc)}\n\n{exc}\n")
        temporary.replace(marker)
    except OSError:
        pass
    return marker if first else None


def icmp_degraded_reason(run_state_dir: Path | None = None) -> str | None:
    return degraded_reason("icmp", run_state_dir)


def note_icmp_degraded(exc: BaseException, *, always: bool = False) -> str | None:
    """Record the degraded state; return the operator message when it should be reported."""
    marker = _note_degraded("icmp", exc, always=always)
    if marker is None:
        return None
    return (f"ICMP reply protection is degraded: its handler could not be loaded ({_failure_cause(exc)}). "
            "The firewall stays active and drops inbound Echo Replies until the handler loads. "
            "Fix the cause, then run 'axdp handler apply icmp --set enabled=true'; or set "
            f"[modules.icmp] enabled = false to pass Echo Replies again. Details: {marker}")


def degrade_icmp(root: Path, exc: BaseException) -> str | None:
    """Keep this generation usable after a failed load; return a message to report.

    Only the caller knows that rejecting the generation would protect nothing.
    Echo Replies must still fail closed, so an unpublishable gate stays fatal.
    """
    try:
        if _icmp_bound(root):
            return f"ICMP handler could not be reloaded; the loaded handler stays active: {_failure_cause(exc)}"
    except (OSError, RuntimeError, subprocess.SubprocessError):
        pass
    # Hold the root's handler lock from the slot check to the gate write, so a
    # protocol-slot load cannot slip a program into slot 1 or 58 in between
    # (load_protocol_handler checks the gate under the same lock).
    with handlers._handler_lock(root):
        try:
            free = icmp_slots_free(root)
        except (OSError, RuntimeError, subprocess.SubprocessError) as error:
            raise RuntimeError(f"ICMP handler could not be loaded and its protocol slots cannot be read ({error}): {exc}") from exc
        if not free:
            raise RuntimeError("ICMP handler could not be loaded and protocol slot 1 or 58 holds another program, "
                               f"so Echo Replies would not be dropped: {exc}") from exc
        runtime = BpfRuntimeConfigMap(str(root / "xdp_runtime_cfg"))
        try:
            flags, values = runtime.get_cfg_flags(), runtime.get()
            if flags is None or values is None or not (
                    flags & XDP_CFG_FLAG_ICMP_REPLY or runtime.set(values, flags | XDP_CFG_FLAG_ICMP_REPLY)):
                raise RuntimeError(f"ICMP handler could not be loaded and Echo Replies could not be closed: {exc}") from exc
        finally:
            runtime.close()
    return note_icmp_degraded(exc, always=True)


def remove_icmp(root: Path) -> None:
    table, live = root / "proto_handlers", root / "modules/icmp"
    if not table.exists():
        if live.exists():
            raise RuntimeError("ICMP dispatch table is missing; ownership pins retained")
        _clear_degraded("icmp", root)
        return
    with handlers._handler_lock(root):
        # Withdraw the main program's requirement before removing its handlers.
        # A failed removal restores both dispatch entries and the old flag.
        runtime = BpfRuntimeConfigMap(str(root / "xdp_runtime_cfg"))
        try:
            old = runtime.get_cfg_flags()
            values = runtime.get()
            if old is None or values is None:
                raise RuntimeError("Cannot read ICMP runtime state")
            if old & XDP_CFG_FLAG_ICMP_REPLY and not runtime.set(values, old & ~XDP_CFG_FLAG_ICMP_REPLY):
                raise RuntimeError("Cannot disable ICMP dispatch")
            try:
                handlers._transactional_handler_bindings(
                    [handlers.program_array_binding(table, key) for key in (1, 58)], "icmp", None, live,
                )
            except BaseException:
                if not runtime.set(values, old):
                    raise RuntimeError("ICMP removal failed and its runtime flag could not be restored")
                raise
        finally:
            runtime.close()
    _clear_degraded("icmp", root)


def verify_icmp(root: Path, *, enabled: bool = True) -> int | None:
    table, pin = root / "proto_handlers", root / "modules/icmp/prog"
    ids = [handlers.program_array_binding(table, key).read() if table.exists() else None for key in (1, 58)]
    if not enabled:
        if any(value is not None for value in ids) or pin.exists():
            raise RuntimeError("ICMP is still dispatched after Disable")
        if (root / "xdp_runtime_cfg").exists():
            runtime = BpfRuntimeConfigMap(str(root / "xdp_runtime_cfg"))
            try:
                flags = runtime.get_cfg_flags()
                if flags is None or flags & XDP_CFG_FLAG_ICMP_REPLY:
                    raise RuntimeError("ICMP runtime gate was not confirmed disabled")
            finally:
                runtime.close()
        return None
    if not pin.exists():
        reason = icmp_degraded_reason()
        raise RuntimeError("ICMP module has not been loaded" + (f": {reason}" if reason else ""))
    ident = handlers.pinned_program_id(pin)
    if ids != [ident, ident]:
        raise RuntimeError("ICMP IPv4/IPv6 bindings do not match their ownership pin")
    runtime = BpfRuntimeConfigMap(str(root / "xdp_runtime_cfg"))
    try:
        if not (runtime.get_cfg_flags() or 0) & XDP_CFG_FLAG_ICMP_REPLY:
            raise RuntimeError("ICMP handler is loaded but reply protection is not enabled")
    finally:
        runtime.close()
    return ident


def reconcile_icmp(root: Path, obj: Path, config: Path, *, allow_degraded: bool = False) -> None:
    settings = configuration.parse_toml_config(config_file.load_toml(config))
    # The daemon loads the SDK copy by its resolved path; use the same name so
    # both report the same cause and the daemon does not repeat the error.
    obj = obj.resolve()
    if not settings.ICMP_REPLY_ENABLED:
        remove_icmp(root)
        return
    try:
        load_icmp(root, obj)
    except (OSError, RuntimeError, subprocess.SubprocessError) as exc:
        if not allow_degraded:
            raise
        message = degrade_icmp(root, exc)
        if message:
            print(f"[auto_xdp] error: {message}", file=sys.stderr)


class ForeignHookError(RuntimeError):
    """The reserved filter position is occupied, but not by a BPF module."""


def module_dir(root: Path) -> Path:
    return root / "modules" / "syncookie"


def program_pin(root: Path, name: str = "prog") -> Path:
    return module_dir(root) / name


def tc_program_id(iface: str) -> int | None:
    result = subprocess.run(["tc", "-j", "filter", "show", "dev", iface, "ingress"],
                            capture_output=True, text=True, timeout=5)
    try:
        rows = json.loads(result.stdout)
        if result.returncode or not isinstance(rows, list):
            raise ValueError(result.stderr)
        matches = []
        for row in rows:
            if not isinstance(row, dict) or row.get("pref") != TC_PRIORITY:
                continue
            options = row.get("options")
            if not isinstance(options, dict):  # tc also emits a priority summary.
                continue
            handle = options.get("handle", row.get("handle", 0))
            if int(str(handle), 0) != TC_HANDLE:
                continue
            if row.get("kind") != "bpf" or row.get("protocol", "all") != "all":
                raise ForeignHookError(f"Cannot verify SYN Cookie TC ingress on {iface}: hook occupied by a different filter")
            value = options.get("id")
            if value is None and isinstance(options.get("prog"), dict):
                value = options["prog"].get("id")
            if type(value) is not int or value <= 0:
                raise ValueError("module TC program ID is unreadable")
            matches.append(value)
        if len(matches) > 1:
            raise ValueError("ambiguous module TC filters")
        return matches[0] if matches else None
    except (ValueError, TypeError, AttributeError) as exc:
        raise RuntimeError(f"Cannot verify SYN Cookie TC ingress on {iface}: {exc}") from exc


def _tc_binding(iface: str, *, enabled: bool = True) -> handlers.ProgramBinding:
    def write(pin: Path | None, program_id: int | None) -> None:
        if program_id is None:
            if tc_program_id(iface) is None:
                return
            command = ["tc", "filter", "del", "dev", iface, "ingress", "protocol", "all",
                       "pref", str(TC_PRIORITY), "handle", str(TC_HANDLE), "bpf"]
        else:
            assert pin is not None
            # An existing clsact qdisc is expected; the filter operation below
            # reports any real failure without removing another qdisc.
            subprocess.run(["tc", "qdisc", "add", "dev", iface, "clsact"],
                           capture_output=True, text=True, timeout=5)
            command = ["tc", "filter", "replace", "dev", iface, "ingress", "protocol", "all",
                       "pref", str(TC_PRIORITY), "handle", str(TC_HANDLE),
                       "bpf", "direct-action", "object-pinned", str(pin)]
        handlers.run_checked(command, f"Cannot update SYN Cookie TC ingress on {iface}", include_detail=True)

    return handlers.ProgramBinding("ingress", lambda: tc_program_id(iface), write, enabled)


def _companions(root: Path, interfaces: list[str]) -> list[handlers.ProgramBinding]:
    targets = set(interfaces)
    previous = program_pin(root, "ingress")
    if previous.exists():
        previous_id = handlers.pinned_program_id(previous)
        # Also withdraw owned hooks from interfaces removed from configuration.
        for _, iface in socket.if_nameindex():
            if iface not in targets:
                try:
                    if tc_program_id(iface) == previous_id:
                        targets.add(iface)
                except ForeignHookError:
                    continue  # A clearly foreign filter on another interface.
    return [_tc_binding(iface, enabled=iface in interfaces) for iface in sorted(targets)]


def remove_syncookie(root: Path, interfaces: list[str]) -> None:
    if not root.exists():
        return
    with handlers._handler_lock(root):
        table = root / "syncookie_prog_array"
        bindings = [handlers.program_array_binding(table, 0)] if table.exists() else []
        bindings.extend(_companions(root, interfaces))
        handlers._transactional_handler_bindings(bindings, "syncookie", None, module_dir(root))


def load_syncookie(root: Path, xdp: Path, tc: Path, interfaces: list[str]) -> None:
    if not interfaces:
        raise RuntimeError("SYN Cookie requires at least one configured interface")
    with handlers._handler_lock(root):
        handlers._load_handler_bundle(
            root / "syncookie_prog_array", 0,
            [("prog", xdp, "xdp"), ("ingress", tc, "classifier")],
            module_dir(root), _companions(root, interfaces),
        )


def verify_syncookie(root: Path, interfaces: list[str], *, enabled: bool = True) -> int | None:
    """Read back both hooks, including absence after Disable."""
    table = root / "syncookie_prog_array"
    active = handlers.program_array_binding(table, 0).read() if table.exists() else None
    if not enabled:
        if active is not None or any(program_pin(root, name).exists() for name in _PROGRAM_PINS):
            raise RuntimeError("SYN Cookie is still loaded after Disable")
        if any(tc_program_id(iface) is not None for iface in interfaces):
            raise RuntimeError("SYN Cookie TC ingress is still attached after Disable")
        return None
    pin = program_pin(root)
    if not pin.exists():
        raise RuntimeError("SYN Cookie was not activated; check kernel capability and runtime diagnostics")
    program_id = handlers.pinned_program_id(pin)
    if active != program_id:
        raise RuntimeError("SYN Cookie dispatch entry does not match the loaded program")
    tc_id = handlers.pinned_program_id(program_pin(root, "ingress"))
    if not interfaces:
        raise RuntimeError("Cannot verify SYN Cookie TC ingress: no configured interfaces")
    for iface in interfaces:
        if tc_program_id(iface) != tc_id:
            raise RuntimeError(f"SYN Cookie TC ingress is not attached on {iface}")
    return program_id


def program_available(root: Path) -> bool:
    pin = program_pin(root)
    if not pin.exists():
        return False
    try:
        active = handlers.program_array_binding(root / "syncookie_prog_array", 0).read()
        if active is None:
            return False
        # Reconciliation checks this for every protected endpoint. Use kernel
        # readback directly rather than starting bpftool for every endpoint.
        fd = obj_get(str(pin))
        try:
            return active == program_id(fd)
        finally:
            os.close(fd)
    except (OSError, RuntimeError, subprocess.SubprocessError):
        return False


def retain_syncookie(root: Path, candidate: Path) -> None:
    """Retain ownership pins across the main firewall's map-root replacement.

    TC hooks outlive a pin directory. The later module transaction must have
    their old pins available to check ownership and roll back a failed switch.
    No old XDP dispatch entry or old policy maps are copied into the new root.
    """
    with handlers._handler_lock(root):
        for name in _PROGRAM_PINS:
            old = program_pin(root, name)
            if old.exists():
                destination = module_dir(candidate) / name
                destination.parent.mkdir(parents=True, exist_ok=True)
                handlers.run_checked(["bpftool", "prog", "pin", "pinned", str(old), str(destination)],
                                     "Cannot retain the previous SYN Cookie module", include_detail=True)


class ModuleActivationError(RuntimeError):
    """An enabled module could not be activated (as opposed to disabled or misconfigured)."""


class ModuleTeardownError(RuntimeError):
    """Withdrawing a module failed; never degraded, whatever triggered the withdrawal."""


def degrade_syncookie(root: Path, interfaces: list[str], exc: BaseException) -> str | None:
    """Keep the firewall running when the cookie module cannot be activated.

    Nothing has to be published: without a dispatched cookie program the
    backend blocks every endpoint whose SYN-cookie mode is not "off". A
    previous module counts as still active only when both of its hooks are
    verified on every configured interface.
    """
    try:
        verify_syncookie(root, interfaces)
    except (OSError, RuntimeError, ValueError, subprocess.SubprocessError) as error:
        unverified = str(error)
    else:
        return f"SYN-cookie module could not be reloaded; the loaded module stays active: {_failure_cause(exc)}"
    marker = _note_degraded("syncookie", exc, always=True)
    if marker is None:
        return None
    if program_available(root):
        state = (f"The previous cookie program is still dispatched but not verified on every interface "
                 f"({unverified}); cookie challenges on such an interface are not handed off.")
    else:
        state = "TCP endpoints that use SYN cookies stay closed until it loads."
    return (f"SYN-cookie protection is degraded: the module could not be activated ({_failure_cause(exc)}). "
            f"The firewall stays active. {state} "
            "Fix the cause, then run 'axdp handler apply syncookie --set enabled=true'; or set their "
            f"mode to \"off\" / [modules.syncookie] enabled = false to admit them without cookies. Details: {marker}")


def reconcile_syncookie(root: Path, xdp: Path, tc: Path, interfaces: list[str],
                       config: Path, sysctl_state: Path, capability: str = "") -> None:
    data = config_file.load_toml(config)
    configuration.parse_toml_config(data)
    settings = configuration.module_configs(data).get("syncookie", {})
    if not settings.get("enabled", False):
        remove_syncookie(root, interfaces)
        if sysctl_state.exists() and not release_sysctl(sysctl_state):
            print("[auto_xdp] warning: SYN Cookie disabled; changed sysctl ownership was retained", file=sys.stderr)
        _clear_degraded("syncookie", root)
        return
    try:
        _activate_syncookie(root, xdp, tc, interfaces, settings, sysctl_state, capability)
    except (ModuleActivationError, ModuleTeardownError):
        raise
    except (OSError, RuntimeError, subprocess.SubprocessError) as exc:
        # Only a failure to activate an enabled module may be degraded by the
        # runtime; disable failures and configuration errors stay fatal.
        raise ModuleActivationError(str(exc)) from exc


def _syncookie_modes(settings: dict) -> list:
    modes = [settings.get("default_mode", "auto")]
    for scope in ("by_port", "by_proc", "by_service"):
        values = settings.get(scope, {})
        if isinstance(values, dict):
            modes.extend(values.values())
    return modes


def _activate_syncookie(root: Path, xdp: Path, tc: Path, interfaces: list[str], settings: dict,
                        sysctl_state: Path, capability: str) -> None:
    strict = "always" in _syncookie_modes(settings)
    if capability:
        parts = capability.splitlines()
        if len(parts) != 3 or parts[0] not in {"0", "1", "2"} or parts[2] not in {"0", "1"}:
            raise RuntimeError("Invalid cached SYN Cookie capability result")
        level, reason, ready = int(parts[0]), parts[1], parts[2] == "1"
    else:
        probe = probe_syncookie_capability()
        level, reason, ready = probe.level, probe.reason, probe.handoff_environment_ready
    if not ready or level != 2 or not xdp.is_file() or not tc.is_file():
        try:
            remove_syncookie(root, interfaces)
        except (OSError, RuntimeError, subprocess.SubprocessError) as exc:
            # The refused module may still be attached: that is not a degraded
            # activation but a failed withdrawal, and stays fatal.
            raise ModuleTeardownError(f"SYN-cookie module was refused but could not be withdrawn: {exc}") from exc
        if sysctl_state.exists():
            release_sysctl(sysctl_state)
        detail = reason or "requires Linux 6.11+ and both optional objects"
        if not ready:
            raise RuntimeError(f"refusing SYN-cookie enablement: {detail}")
        if strict:
            raise RuntimeError(f"SYN-cookie listener handoff unavailable: {detail}")
        print(f"[auto_xdp] warning: SYN-cookie listener handoff unavailable: {detail}", file=sys.stderr)
        # Same state as a refused strict activation: cookie endpoints stay closed.
        _note_degraded("syncookie", RuntimeError(f"SYN-cookie listener handoff unavailable: {detail}"))
        return
    acquired = not sysctl_state.exists()
    acquire_sysctl(sysctl_state)
    try:
        load_syncookie(root, xdp, tc, interfaces)
    except BaseException:
        # A failed rollback may leave a live candidate: never remove the
        # prerequisite in that case. Recovery generations remain pinned.
        recovery = list(module_dir(root).parent.glob("syncookie_next_*"))
        if acquired and not program_pin(root).exists() and not recovery:
            release_sysctl(sysctl_state)
        raise
    _clear_degraded("syncookie", root)
    print(f"[auto_xdp] SYN-cookie Level 2 module enabled on {' '.join(interfaces)}.")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("apply", "remove", "retain", "verify", "unprotected"))
    parser.add_argument("module", choices=("syncookie", "icmp"))
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--iface", action="append", default=[])
    parser.add_argument("--config", type=Path)
    parser.add_argument("--xdp", type=Path)
    parser.add_argument("--tc", type=Path)
    parser.add_argument("--sysctl-state", type=Path)
    parser.add_argument("--capability", default="")
    parser.add_argument("--candidate", type=Path)
    parser.add_argument("--allow-degraded", action="store_true",
                        help="apply: if the module cannot be activated, keep the firewall running with the "
                             "module's traffic fail-closed and report it as degraded")
    args = parser.parse_args(argv)
    if args.action == "unprotected":
        # Exit status only: 0 when the generation at --root has no working ICMP
        # protection (no managed handler bound, or the reply gate is off), so a
        # candidate whose handler cannot load loses nothing by replacing it.
        # Any doubt answers "protected" (1).
        if args.module != "icmp":
            parser.error("unprotected is only defined for icmp")
        try:
            # A bound handler protects only while the reply gate sends it traffic.
            return 1 if _icmp_bound(args.root) and _icmp_gate(args.root) else 0
        except (OSError, RuntimeError, ValueError, subprocess.SubprocessError):
            return 1
    try:
        if args.module == "icmp":
            if args.action == "apply":
                if args.config is None or args.xdp is None:
                    parser.error("ICMP apply requires --config and --xdp")
                reconcile_icmp(args.root, args.xdp, args.config, allow_degraded=args.allow_degraded)
            elif args.action == "remove":
                remove_icmp(args.root)
            elif args.action == "verify":
                verify_icmp(args.root)
            else:
                parser.error("ICMP has no external hook to retain")
        elif args.action == "retain":
            if args.candidate is None:
                parser.error("retain requires --candidate")
            retain_syncookie(args.root, args.candidate)
        elif args.action == "verify":
            verify_syncookie(args.root, args.iface)
        elif args.action == "remove":
            remove_syncookie(args.root, args.iface)
        else:
            if any(value is None for value in (args.config, args.xdp, args.tc, args.sysctl_state)):
                parser.error("apply requires --config, --xdp, --tc and --sysctl-state")
            try:
                reconcile_syncookie(args.root, args.xdp, args.tc, args.iface,
                                   args.config, args.sysctl_state, args.capability)
            except ModuleActivationError as exc:
                if not args.allow_degraded:
                    raise
                message = degrade_syncookie(args.root, args.iface, exc)
                if message:
                    print(f"[auto_xdp] error: {message}", file=sys.stderr)
    except (OSError, RuntimeError, ValueError, subprocess.SubprocessError) as exc:
        print(f"[auto_xdp] error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
