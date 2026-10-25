from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

from auto_xdp.xdp_link import xdp_mode_from_link


def iface_xdp_state(iface: str) -> str:
    """Return the XDP attach state for iface."""
    if not iface:
        return "missing"
    try:
        info = subprocess.check_output(
            ["ip", "-j", "-d", "link", "show", "dev", iface],
            stderr=subprocess.PIPE,
            text=True,
        )
    except subprocess.CalledProcessError as exc:
        error = str(exc.stderr or "").lower()
        if any(text in error for text in ("does not exist", "no such device", "cannot find device")):
            return "missing"
        return "unknown"
    except OSError:
        return "unknown"
    try:
        return xdp_mode_from_link(json.loads(info))
    except ValueError:
        return "unknown"


def _iface_has_xdp(iface: str) -> bool:
    return iface_xdp_state(iface) in ("generic", "native", "offload", "multi")


def _nft_table_exists(family: str, table: str) -> bool:
    if not shutil.which("nft"):
        return False
    return (
        subprocess.run(
            ["nft", "list", "table", family, table], capture_output=True
        ).returncode
        == 0
    )


def detect_backend(
    bpf_pin_dir: Path,
    run_state_dir: Path,
    interfaces: list[str],
    nft_family: str,
    nft_table: str,
) -> str:
    """Return 'xdp' or 'nftables'; raise RuntimeError if neither is active."""
    pkt_counters = bpf_pin_dir / "pkt_counters"

    candidate = ""
    backend_file = run_state_dir / "backend"
    if backend_file.exists():
        try:
            candidate = backend_file.read_text().strip()
        except OSError:
            pass

    any_xdp_iface = any(_iface_has_xdp(i) for i in interfaces)
    nft_exists = _nft_table_exists(nft_family, nft_table)

    if candidate == "xdp" and (pkt_counters.exists() or any_xdp_iface):
        return "xdp"
    if candidate == "nftables" and nft_exists:
        return "nftables"
    if pkt_counters.exists() and any_xdp_iface:
        return "xdp"
    if nft_exists:
        return "nftables"
    if pkt_counters.exists():
        return "xdp"
    raise RuntimeError("No active Auto XDP backend detected.")


def autodetect_iface() -> str:
    """Return the default-route interface name, or raise RuntimeError."""
    try:
        out = subprocess.check_output(
            ["ip", "route", "show", "default"], stderr=subprocess.DEVNULL, text=True
        )
    except (subprocess.CalledProcessError, OSError):
        out = ""
    for line in out.splitlines():
        parts = line.split()
        # format: default via ... dev IFACE ...
        if "dev" in parts:
            idx = parts.index("dev")
            if idx + 1 < len(parts):
                return parts[idx + 1]
    raise RuntimeError("Could not detect interface. Use --iface IFACE.")
