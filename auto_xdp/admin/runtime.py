from __future__ import annotations

import json
import os
import shlex
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from auto_xdp.admin.detect import detect_backend as _detect_backend_impl
from auto_xdp.admin.detect import iface_xdp_state as _iface_xdp_state
from auto_xdp.install_state import interface_details, read_system_links, select_interfaces


@dataclass
class RuntimeContext:
    env_config: Path
    bpf_pin_dir: Path
    run_state_dir: Path
    nft_family: str
    nft_table: str
    interface: str = ""


@dataclass
class BackendReport:
    backend: str
    preferred_backend: str
    interfaces: list[str]
    xdp_mode: str
    xdp_attach: dict[str, str]
    generation: str
    healthy: bool
    fallback_reason: str | None
    excluded_interfaces: dict[str, str]
    policy: str
    release: str
    install_transition: str | None
    interface_details: dict[str, dict[str, object]] = field(default_factory=dict)
    unprotected_interfaces: list[str] = field(default_factory=list)
    interface_discovery_error: str | None = None


def _load_env_file(path: Path) -> dict[str, str]:
    if not path.exists():
        return {}

    data: dict[str, str] = {}
    for raw_line in path.read_text().splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        try:
            parsed = shlex.split(value, posix=True)
        except ValueError:
            parsed = [value.strip().strip('"').strip("'")]
        data[key.strip()] = parsed[0] if parsed else ""
    return data


def _command_exists(name: str) -> bool:
    return any(
        os.access(Path(entry) / name, os.X_OK)
        for entry in os.environ.get("PATH", "").split(os.pathsep)
        if entry
    )


def _run_text(cmd: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, capture_output=True, text=True)


def _load_json_file(path: Path) -> dict[str, object]:
    if not path.exists():
        return {}
    try:
        value = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return {}
    return value if isinstance(value, dict) else {}


def _nft_policy_schema(family: str, table: str) -> str:
    if not _command_exists("nft"):
        return "unavailable"
    result = _run_text(["nft", "list", "table", family, table])
    if result.returncode != 0:
        return "missing"
    if "set tcp_ports" in result.stdout and "chain input" in result.stdout:
        return "policy_schema_v2"
    return "legacy"


def _ip_default_iface() -> str:
    result = _run_text(["ip", "route", "show", "default"])
    if result.returncode != 0:
        return ""
    for line in result.stdout.splitlines():
        parts = line.split()
        if parts and parts[0] == "default" and len(parts) >= 5:
            return parts[4]
    return ""


def _iface_xdp_program_id(iface: str) -> int | None:
    result = _run_text(["ip", "-j", "-d", "link", "show", "dev", iface])
    if result.returncode != 0:
        return None
    try:
        value = json.loads(result.stdout)
    except json.JSONDecodeError:
        return None

    def program_id(node: object) -> int | None:
        if isinstance(node, dict):
            for key, child in node.items():
                if (key == "id" or key.endswith("prog_id")) and isinstance(child, int):
                    return child
                found = program_id(child)
                if found is not None:
                    return found
        elif isinstance(node, list):
            for child in node:
                found = program_id(child)
                if found is not None:
                    return found
        return None

    def find_xdp(node: object) -> int | None:
        if isinstance(node, dict):
            for key, child in node.items():
                if key == "xdp":
                    found = program_id(child)
                    if found is not None:
                        return found
                else:
                    found = find_xdp(child)
                    if found is not None:
                        return found
        elif isinstance(node, list):
            for child in node:
                found = find_xdp(child)
                if found is not None:
                    return found
        return None

    return find_xdp(value)


def _pinned_xdp_program_id(path: Path) -> int | None:
    if not path.exists() or not _command_exists("bpftool"):
        return None
    result = _run_text(["bpftool", "-j", "prog", "show", "pinned", str(path)])
    if result.returncode != 0:
        return None
    try:
        value = json.loads(result.stdout)
        if isinstance(value, list):
            value = value[0]
        program_id = value.get("id") if isinstance(value, dict) else None
    except (IndexError, json.JSONDecodeError):
        return None
    return program_id if isinstance(program_id, int) else None


def _all_interface_names() -> list[str]:
    result = _run_text(["ip", "-j", "link", "show"])
    if result.returncode != 0:
        return []
    try:
        value = json.loads(result.stdout)
    except json.JSONDecodeError:
        return []
    if not isinstance(value, list):
        return []
    return [str(item["ifname"]) for item in value if isinstance(item, dict) and item.get("ifname")]


def _detach_handler_egress(pin_root: Path, interfaces: list[str]) -> list[str]:
    """Remove only the TC classifier identified by our retained program pin."""
    # The retired name is recognized only to detach/clean a pre-migration hook.
    program_ids = {
        program_id for name in ("tc_egress_dispatch_prog", "minecraft_egress_prog")
        if (pin_root / name).exists()
        and (program_id := _pinned_xdp_program_id(pin_root / name)) is not None
    }
    if not program_ids:
        return []
    if not _command_exists("tc"):
        raise RuntimeError("tc is required to detach the pinned handler egress dispatcher")
    messages = []
    for iface in sorted(set(interfaces)):
        result = _run_text(["tc", "-j", "filter", "show", "dev", iface, "egress", "pref", "49153"])
        if result.returncode:
            raise RuntimeError(f"Cannot inspect handler egress on {iface}: {result.stderr.strip()}")
        try:
            filters = json.loads(result.stdout)
            if not isinstance(filters, list):
                raise ValueError("filter inventory is not an array")
            owned = any(
                row.get("kind") == "bpf"
                and row.get("options", {}).get("id", row.get("options", {}).get("prog", {}).get("id")) in program_ids
                and int(str(row.get("options", {}).get("handle", "0")), 0) == 2
                for row in filters
            )
        except (TypeError, ValueError, AttributeError) as exc:
            raise RuntimeError(f"Cannot decode handler egress filters on {iface}") from exc
        if not owned:
            continue
        result = _run_text(["tc", "filter", "del", "dev", iface, "egress", "protocol", "all",
                            "pref", "49153", "handle", "2", "bpf"])
        if result.returncode:
            raise RuntimeError(f"Cannot detach handler egress on {iface}: {result.stderr.strip()}")
        messages.append(f"detached handler egress from {iface}")
    return messages


def deactivate_runtime(ctx: RuntimeContext) -> list[str]:
    """Detach only the pinned Auto XDP generation and remove its nft table."""
    pin_root = ctx.bpf_pin_dir
    if not pin_root.is_absolute() or pin_root == Path("/") or len(pin_root.parts) < 3:
        raise RuntimeError(f"refusing to remove unsafe BPF pin path: {pin_root}")
    env = _load_env_file(ctx.env_config)
    interfaces = _configured_ifaces(env)
    runtime_path = Path(env.get("RUNTIME_STATE", "/etc/auto_xdp/runtime-state.json"))
    saved_interfaces = _load_json_file(runtime_path).get("interfaces", {})
    if isinstance(saved_interfaces, dict):
        interfaces = list(dict.fromkeys([*interfaces, *map(str, saved_interfaces)]))
    if ctx.interface:
        interfaces = [ctx.interface]
    messages: list[str] = []

    pinned_program = ctx.bpf_pin_dir / "prog"
    expected_id = _pinned_xdp_program_id(pinned_program)
    attached = {iface: _iface_xdp_program_id(iface) for iface in interfaces}
    active_ids = {program_id for program_id in attached.values() if program_id is not None}
    if active_ids and expected_id is None:
        raise RuntimeError("XDP is attached but the Auto XDP pinned program cannot be identified; refusing to detach it")
    conflicts = {
        iface: program_id for iface, program_id in attached.items()
        if program_id is not None and program_id != expected_id
    }
    if conflicts:
        detail = ", ".join(f"{iface}=program-{program_id}" for iface, program_id in sorted(conflicts.items()))
        raise RuntimeError(f"non-Auto-XDP programs are attached ({detail}); refusing to detach them")
    if expected_id is not None and not ctx.interface:
        for iface in _all_interface_names():
            if iface not in attached and _iface_xdp_program_id(iface) == expected_id:
                attached[iface] = expected_id

    for iface, program_id in attached.items():
        if program_id is None:
            continue
        mode = _iface_xdp_state(iface)
        if mode not in {"native", "generic", "offload"}:
            raise RuntimeError(
                f"cannot determine a single XDP attachment mode on {iface} ({mode}); refusing to detach it"
            )
        keyword = "xdpgeneric" if mode == "generic" else "xdpoffload" if mode == "offload" else "xdp"
        result = _run_text(["ip", "link", "set", "dev", iface, keyword, "off"])
        if result.returncode != 0 or _iface_xdp_program_id(iface) is not None:
            raise RuntimeError(f"failed to detach Auto XDP from {iface}: {result.stderr.strip()}")
        messages.append(f"detached Auto XDP from {iface}")

    tc_interfaces = list(attached)
    if not ctx.interface and any((pin_root / name).exists() for name in
                                 ("tc_egress_dispatch_prog", "minecraft_egress_prog")):
        tc_interfaces.extend(_all_interface_names())
    messages.extend(_detach_handler_egress(pin_root, tc_interfaces))

    backend_marker = ctx.run_state_dir / "backend"
    active_backend = backend_marker.read_text().strip() if backend_marker.exists() else ""
    if _command_exists("nft"):
        if not ctx.interface:
            from auto_xdp.bpf.conntrack import configure as configure_conntrack
            configure_conntrack(remove=True)
        present = _run_text(["nft", "list", "table", ctx.nft_family, ctx.nft_table]).returncode == 0
        if present:
            result = _run_text(["nft", "delete", "table", ctx.nft_family, ctx.nft_table])
            if result.returncode != 0:
                raise RuntimeError(f"failed to remove nftables table: {result.stderr.strip()}")
            messages.append(f"removed nftables table {ctx.nft_family} {ctx.nft_table}")
    elif active_backend in {"nftables", "xdp"}:
        raise RuntimeError("nft is required to remove Auto XDP policy/conntrack tables")

    if pin_root.exists():
        try:
            shutil.rmtree(pin_root)
        except OSError as exc:
            raise RuntimeError(f"failed to remove BPF pins {pin_root}: {exc}") from exc
        messages.append(f"removed BPF pins {pin_root}")
    for suffix in ("_next", "_rollback"):
        candidate = Path(f"{pin_root}{suffix}")
        if candidate.exists():
            try:
                shutil.rmtree(candidate)
            except OSError as exc:
                raise RuntimeError(f"failed to remove staged BPF pins {candidate}: {exc}") from exc
    for marker in (backend_marker, ctx.run_state_dir / "xdp_mode"):
        marker.unlink(missing_ok=True)
    return messages


def _configured_ifaces(env: dict[str, str]) -> list[str]:
    if env.get("IFACES"):
        return env["IFACES"].split()
    if env.get("IFACE"):
        return [env["IFACE"]]
    return []


def _preferred_backend(env: dict[str, str]) -> str:
    default = env.get("PREFERRED_BACKEND", "auto")
    path = Path(env.get("TOML_CONFIG", "/etc/auto_xdp/config.toml"))
    if not path.exists():
        return default
    try:
        try:
            import tomllib
        except ImportError:
            import tomli as tomllib

        with path.open("rb") as handle:
            value = str(tomllib.load(handle).get("daemon", {}).get("preferred_backend", default)).lower()
    except (ImportError, OSError, ValueError):
        return default
    return value if value in {"auto", "xdp", "nftables"} else default


def _policy_mode(env: dict[str, str]) -> str:
    path = Path(env.get("TOML_CONFIG", "/etc/auto_xdp/config.toml"))
    try:
        try:
            import tomllib
        except ImportError:
            import tomli as tomllib
        with path.open("rb") as handle:
            value = str(tomllib.load(handle).get("policy", {}).get("mode", "audit")).lower()
    except (ImportError, OSError, ValueError):
        return "audit"
    return value if value in {"observe", "audit", "enforce"} else "audit"


def _interface_exclusions(env: dict[str, str], saved: dict[str, object]) -> list[str]:
    fallback = [str(name) for name, reason in saved.items() if reason == "configured exclusion"]
    path = Path(env.get("TOML_CONFIG", "/etc/auto_xdp/config.toml"))
    try:
        try:
            import tomllib
        except ImportError:
            import tomli as tomllib
        with path.open("rb") as handle:
            table = tomllib.load(handle).get("interfaces")
    except (ImportError, OSError, ValueError):
        return fallback
    if not isinstance(table, dict):
        return fallback
    names = table.get("exclude", [])
    if not isinstance(names, list) or not all(isinstance(name, str) for name in names):
        return fallback
    # Older machine state omitted exclusions for interfaces absent at install.
    return names


def detect_backend(ctx: RuntimeContext, interfaces: list[str]) -> str:
    return _detect_backend_impl(
        ctx.bpf_pin_dir, ctx.run_state_dir, interfaces, ctx.nft_family, ctx.nft_table
    )


def collect_backend_report(ctx: RuntimeContext) -> BackendReport:
    env = _load_env_file(ctx.env_config)
    policy_mode = _policy_mode(env)
    preferred_backend = _preferred_backend(env)
    interfaces = _configured_ifaces(env)
    iface = ctx.interface or (interfaces[0] if interfaces else "") or _ip_default_iface()
    if not iface:
        raise RuntimeError("Could not detect interface. Use --interface IFACE.")
    if not interfaces:
        interfaces = [iface]

    check_ifaces = [ctx.interface] if ctx.interface else interfaces
    try:
        backend = detect_backend(ctx, check_ifaces)
    except RuntimeError:
        if policy_mode == "enforce":
            raise
        backend = "inactive"
    xdp_mode_path = ctx.run_state_dir / "xdp_mode"
    xdp_mode = xdp_mode_path.read_text().strip() if xdp_mode_path.exists() else "-"

    xdp_attach = {name: _iface_xdp_state(name) for name in interfaces}
    runtime_path = Path(env.get("RUNTIME_STATE", "/etc/auto_xdp/runtime-state.json"))
    machine_path = Path(env.get("MACHINE_STATE", "/etc/auto_xdp/machine-state.json"))
    persistent = _load_json_file(runtime_path)
    machine = _load_json_file(machine_path)
    install_dir = Path(env.get("INSTALL_DIR", "/usr/local/lib/auto_xdp/current"))
    release_meta = _load_json_file(install_dir / "release.json")
    release = str(release_meta.get("release", "legacy"))
    transition = _load_json_file(
        Path(env.get("INSTALL_TRANSACTION_FILE", "/etc/auto_xdp/install-transaction.json"))
    )
    transition_state = None
    transition_status = str(transition.get("status", ""))
    if transition_status == "active":
        transition_state = str(transition.get("phase", "unknown"))
    elif transition_status == "failed":
        transition_state = f"failed/{transition.get('phase', 'unknown')}"
    excluded = machine.get("excluded", {})
    if not isinstance(excluded, dict):
        excluded = {}
    details: dict[str, dict[str, object]] = {}
    unprotected: list[str] = []
    discovery_error = None
    try:
        links = read_system_links()
        details = {str(link["ifname"]): interface_details(link) for link in links}
        eligible, current_excluded = select_interfaces(
            links, excluded_names=_interface_exclusions(env, excluded),
        )
        # XDP coverage follows the attachment list. The nftables INPUT hook
        # already sees traffic from all interfaces, including newly added ones.
        if backend == "xdp":
            unprotected = sorted(set(eligible) - set(interfaces))
        if machine.get("selection") == "auto":
            excluded = current_excluded
    except ValueError as exc:
        discovery_error = str(exc)
    clean_generation = not any(
        path.exists()
        for path in (
            Path(f"{ctx.bpf_pin_dir}_next"),
            Path(f"{ctx.bpf_pin_dir}_rollback"),
        )
    )
    if backend == "inactive":
        policy = f"{policy_mode} (data plane inactive)"
        healthy = clean_generation and all(value in {"off", "missing"} for value in xdp_attach.values())
    elif backend == "xdp":
        attachments_ok = all(
            value in {"native", "generic", "offload"} for value in xdp_attach.values()
        )
        saved_interfaces = persistent.get("interfaces", {})
        ids_ok = True
        if isinstance(saved_interfaces, dict) and saved_interfaces:
            for name in interfaces:
                saved = saved_interfaces.get(name, {})
                expected = saved.get("program_id") if isinstance(saved, dict) else None
                if not isinstance(expected, int) or _iface_xdp_program_id(name) != expected:
                    ids_ok = False
                    break
        policy = "BPF maps pinned"
        healthy = attachments_ok and ids_ok and clean_generation
    else:
        schema = _nft_policy_schema(ctx.nft_family, ctx.nft_table)
        policy = f"{ctx.nft_family} {ctx.nft_table} / {schema}"
        healthy = schema == "policy_schema_v2" and clean_generation
    if persistent and backend != "inactive":
        healthy = healthy and bool(persistent.get("healthy", False))
        xdp_mode = str(persistent.get("xdp_mode", xdp_mode))
    generation = str(persistent.get("generation", "legacy"))
    if backend != "inactive" and release != "legacy" and generation not in {release, "verified"}:
        healthy = False
    if transition_state:
        healthy = False
    if backend == "xdp" and machine.get("selection") == "auto" and (unprotected or discovery_error):
        healthy = False

    return BackendReport(
        backend=backend,
        preferred_backend=preferred_backend,
        interfaces=interfaces,
        xdp_mode=xdp_mode,
        xdp_attach=xdp_attach,
        generation=generation if clean_generation else "recovery-required",
        healthy=healthy,
        fallback_reason=(
            str(persistent["fallback_reason"])
            if persistent.get("fallback_reason")
            else None
        ),
        excluded_interfaces={str(key): str(value) for key, value in excluded.items()},
        policy=policy,
        release=release,
        install_transition=transition_state,
        interface_details=details,
        unprotected_interfaces=unprotected,
        interface_discovery_error=discovery_error,
    )


def render_backend_text(report: BackendReport) -> str:
    interfaces = " ".join(report.interfaces)
    xdp_attach = " ".join(f"{iface}={state}" for iface, state in report.xdp_attach.items()) or "-"
    lines = [
            f"Backend   : {report.backend}",
            f"Preferred : {report.preferred_backend}",
            f"Health    : {'healthy' if report.healthy else 'degraded'}",
            f"Generation: {report.generation}",
            f"Release   : {report.release}",
            f"Policy    : {report.policy}",
            f"Interfaces: {interfaces}",
            f"XDP mode  : {report.xdp_mode}",
            f"XDP attach: {xdp_attach}",
        ]
    if report.fallback_reason:
        lines.append(f"Fallback  : {report.fallback_reason}")
    if report.install_transition:
        lines.append(f"Install   : transaction/{report.install_transition}")
    if report.interface_details:
        lines.append("Link types: " + " ".join(
            f"{name}={details['kind']}" + (f"/{details['driver']}" if details.get("driver") else "")
            for name, details in sorted(report.interface_details.items())
        ))
    if report.unprotected_interfaces:
        lines.append("Unselected: " + " ".join(report.unprotected_interfaces) + " (not covered by this installation)")
    if report.interface_discovery_error:
        lines.append(f"Discovery : {report.interface_discovery_error}")
    if report.excluded_interfaces:
        excluded = " ".join(
            f"{name}={reason.replace(' ', '-')}"
            for name, reason in sorted(report.excluded_interfaces.items())
        )
        lines.append(f"Excluded  : {excluded}")
    return "\n".join(lines)


def render_backend_json(report: BackendReport) -> str:
    return json.dumps(
        {
            "backend": report.backend,
            "preferred_backend": report.preferred_backend,
            "interfaces": report.interfaces,
            "xdp_mode": report.xdp_mode,
            "xdp_attach": report.xdp_attach,
            "generation": report.generation,
            "healthy": report.healthy,
            "fallback_reason": report.fallback_reason,
            "excluded_interfaces": report.excluded_interfaces,
            "policy": report.policy,
            "release": report.release,
            "install_transition": report.install_transition,
            "interface_details": report.interface_details,
            "unprotected_interfaces": report.unprotected_interfaces,
            "interface_discovery_error": report.interface_discovery_error,
        },
        sort_keys=True,
    )
