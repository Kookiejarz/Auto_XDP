from __future__ import annotations

import json
import os
import shlex
import subprocess
from dataclasses import dataclass
from pathlib import Path

from auto_xdp.admin.detect import detect_backend as _detect_backend_impl


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
    tc_egress: dict[str, str]
    conntrack: dict[str, int]


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


def _ip_default_iface() -> str:
    result = _run_text(["ip", "route", "show", "default"])
    if result.returncode != 0:
        return ""
    for line in result.stdout.splitlines():
        parts = line.split()
        if parts and parts[0] == "default" and len(parts) >= 5:
            return parts[4]
    return ""


def _iface_info(iface: str) -> str:
    result = _run_text(["ip", "-d", "link", "show", "dev", iface])
    return result.stdout if result.returncode == 0 else ""


def _iface_xdp_state(iface: str) -> str:
    info = _iface_info(iface)
    if not info:
        return "missing"
    if "xdpgeneric" in info:
        return "generic"
    if "xdp" in info or "xdpoffload" in info:
        return "native"
    return "off"


def _iface_tc_egress_state(iface: str) -> str:
    if not _command_exists("tc"):
        return "unavailable"
    result = _run_text(["tc", "filter", "show", "dev", iface, "egress", "pref", "49152"])
    return "attached" if result.returncode == 0 and result.stdout.strip() else "off"


def _count_conntrack_entries(map_path: Path) -> int:
    if not map_path.exists() or not _command_exists("bpftool"):
        return 0
    result = _run_text(["bpftool", "-j", "map", "dump", "pinned", str(map_path)])
    if result.returncode != 0:
        return 0
    try:
        rows = json.loads(result.stdout)
    except json.JSONDecodeError:
        return 0
    return len(rows) if isinstance(rows, list) else 0


def _count_conntrack_entries_many(*map_paths: Path) -> int:
    return sum(_count_conntrack_entries(path) for path in map_paths)


def _configured_ifaces(env: dict[str, str]) -> list[str]:
    if env.get("IFACES"):
        return env["IFACES"].split()
    if env.get("IFACE"):
        return [env["IFACE"]]
    return []


def detect_backend(ctx: RuntimeContext, interfaces: list[str]) -> str:
    return _detect_backend_impl(
        ctx.bpf_pin_dir, ctx.run_state_dir, interfaces, ctx.nft_family, ctx.nft_table
    )


def collect_backend_report(ctx: RuntimeContext) -> BackendReport:
    env = _load_env_file(ctx.env_config)
    interfaces = _configured_ifaces(env)
    iface = ctx.interface or (interfaces[0] if interfaces else "") or _ip_default_iface()
    if not iface:
        raise RuntimeError("Could not detect interface. Use --interface IFACE.")
    if not interfaces:
        interfaces = [iface]

    check_ifaces = [ctx.interface] if ctx.interface else interfaces
    backend = detect_backend(ctx, check_ifaces)
    xdp_mode_path = ctx.run_state_dir / "xdp_mode"
    xdp_mode = xdp_mode_path.read_text().strip() if xdp_mode_path.exists() else "-"

    xdp_attach = {name: _iface_xdp_state(name) for name in interfaces}
    tc_egress = {name: _iface_tc_egress_state(name) for name in interfaces}

    return BackendReport(
        backend=backend,
        preferred_backend=env.get("PREFERRED_BACKEND", "auto"),
        interfaces=interfaces,
        xdp_mode=xdp_mode,
        xdp_attach=xdp_attach,
        tc_egress=tc_egress,
        conntrack={
            "tcp": _count_conntrack_entries_many(
                ctx.bpf_pin_dir / "tcp_ct4",
                ctx.bpf_pin_dir / "tcp_ct6",
            ),
            "udp": _count_conntrack_entries_many(
                ctx.bpf_pin_dir / "udp_ct4",
                ctx.bpf_pin_dir / "udp_ct6",
            ),
        },
    )


def render_backend_text(report: BackendReport) -> str:
    interfaces = " ".join(report.interfaces)
    xdp_attach = " ".join(f"{iface}={state}" for iface, state in report.xdp_attach.items()) or "-"
    tc_egress = " ".join(f"{iface}={state}" for iface, state in report.tc_egress.items()) or "-"
    return "\n".join(
        [
            f"Backend   : {report.backend}",
            f"Preferred : {report.preferred_backend}",
            f"Interfaces: {interfaces}",
            f"XDP mode  : {report.xdp_mode}",
            f"XDP attach: {xdp_attach}",
            f"tc egress : {tc_egress}",
            f"Conntrack : tcp={report.conntrack['tcp']} udp={report.conntrack['udp']}",
        ]
    )


def render_backend_json(report: BackendReport) -> str:
    return json.dumps(
        {
            "backend": report.backend,
            "preferred_backend": report.preferred_backend,
            "interfaces": report.interfaces,
            "xdp_mode": report.xdp_mode,
            "xdp_attach": report.xdp_attach,
            "tc_egress": report.tc_egress,
            "conntrack": report.conntrack,
        },
        sort_keys=True,
    )
