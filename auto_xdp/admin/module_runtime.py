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


def load_icmp(root: Path, obj: Path) -> None:
    """Publish IPv4 and IPv6 together, after the common loader resolves .ko dependencies."""
    with handlers._handler_lock(root):
        handlers._load_handler_bundle(
            root / "proto_handlers", 1, [("prog", obj, "xdp")], root / "modules/icmp",
            [handlers.program_array_binding(root / "proto_handlers", 58)],
        )


def prepare_icmp(root: Path, *, enabled: bool) -> None:
    """Reconcile config reloads before the backend publishes the runtime gate."""
    if not enabled:
        remove_icmp(root)
        return
    pin, table = root / "modules/icmp/prog", root / "proto_handlers"
    if pin.exists():
        fd = obj_get(str(pin))
        try:
            ident = program_id(fd)
        finally:
            os.close(fd)
        if all(handlers.program_array_binding(table, key).read() == ident for key in (1, 58)):
            return
    load_icmp(root, kernel_modules.sdk_directory() / "icmp_handler.o")


def remove_icmp(root: Path) -> None:
    table, live = root / "proto_handlers", root / "modules/icmp"
    if not table.exists():
        if live.exists():
            raise RuntimeError("ICMP dispatch table is missing; ownership pins retained")
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
        raise RuntimeError("ICMP module has not been loaded")
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


def reconcile_icmp(root: Path, obj: Path, config: Path) -> None:
    settings = configuration.parse_toml_config(config_file.load_toml(config))
    if settings.ICMP_REPLY_ENABLED:
        load_icmp(root, obj)
    else:
        remove_icmp(root)


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


def reconcile_syncookie(root: Path, xdp: Path, tc: Path, interfaces: list[str],
                       config: Path, sysctl_state: Path, capability: str = "") -> None:
    data = config_file.load_toml(config)
    configuration.parse_toml_config(data)
    settings = configuration.module_configs(data).get("syncookie", {})
    if not settings.get("enabled", False):
        remove_syncookie(root, interfaces)
        if sysctl_state.exists() and not release_sysctl(sysctl_state):
            print("[auto_xdp] warning: SYN Cookie disabled; changed sysctl ownership was retained", file=sys.stderr)
        return
    modes = [settings.get("default_mode", "auto")]
    for scope in ("by_port", "by_proc", "by_service"):
        modes.extend(settings.get(scope, {}).values())
    strict = "always" in modes
    if capability:
        parts = capability.splitlines()
        if len(parts) != 3 or parts[0] not in {"0", "1", "2"} or parts[2] not in {"0", "1"}:
            raise RuntimeError("Invalid cached SYN Cookie capability result")
        level, reason, ready = int(parts[0]), parts[1], parts[2] == "1"
    else:
        probe = probe_syncookie_capability()
        level, reason, ready = probe.level, probe.reason, probe.handoff_environment_ready
    if not ready or level != 2 or not xdp.is_file() or not tc.is_file():
        remove_syncookie(root, interfaces)
        if sysctl_state.exists():
            release_sysctl(sysctl_state)
        detail = reason or "requires Linux 6.11+ and both optional objects"
        if not ready:
            raise RuntimeError(f"refusing SYN-cookie enablement: {detail}")
        if strict:
            raise RuntimeError(f"SYN-cookie listener handoff unavailable: {detail}")
        print(f"[auto_xdp] warning: SYN-cookie listener handoff unavailable: {detail}", file=sys.stderr)
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
    print(f"[auto_xdp] SYN-cookie Level 2 module enabled on {' '.join(interfaces)}.")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("apply", "remove", "retain", "verify"))
    parser.add_argument("module", choices=("syncookie", "icmp"))
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--iface", action="append", default=[])
    parser.add_argument("--config", type=Path)
    parser.add_argument("--xdp", type=Path)
    parser.add_argument("--tc", type=Path)
    parser.add_argument("--sysctl-state", type=Path)
    parser.add_argument("--capability", default="")
    parser.add_argument("--candidate", type=Path)
    args = parser.parse_args(argv)
    try:
        if args.module == "icmp":
            if args.action == "apply":
                if args.config is None or args.xdp is None:
                    parser.error("ICMP apply requires --config and --xdp")
                reconcile_icmp(args.root, args.xdp, args.config)
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
            reconcile_syncookie(args.root, args.xdp, args.tc, args.iface,
                               args.config, args.sysctl_state, args.capability)
    except (OSError, RuntimeError, ValueError, subprocess.SubprocessError) as exc:
        print(f"[auto_xdp] error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
