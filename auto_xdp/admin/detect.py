from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path


def _iface_has_xdp(iface: str) -> bool:
    if not iface:
        return False
    try:
        out = subprocess.check_output(
            ["ip", "-d", "link", "show", "dev", iface],
            stderr=subprocess.DEVNULL,
            text=True,
        )
        return bool(re.search(r"xdp|xdpgeneric|xdpoffload", out))
    except (subprocess.CalledProcessError, OSError):
        return False


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
