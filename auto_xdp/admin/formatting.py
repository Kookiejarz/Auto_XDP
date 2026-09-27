"""Display units shared by the CLI and terminal views."""
from __future__ import annotations


def human_bytes(value: int) -> str:
    if value == -1:
        return "-"
    units = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"]
    val = float(value)
    idx = 0
    while val >= 1024 and idx < len(units) - 1:
        val /= 1024
        idx += 1
    if idx == 0:
        return f"{val:.0f} {units[idx]}"
    return f"{val:.2f} {units[idx]}"


def human_bps(value: int) -> str:
    if value == -1:
        return "-"
    units = ["bps", "Kbps", "Mbps", "Gbps", "Tbps"]
    val = float(value)
    idx = 0
    while val >= 1000 and idx < len(units) - 1:
        val /= 1000
        idx += 1
    if idx == 0:
        return f"{val:.0f} {units[idx]}"
    return f"{val:.2f} {units[idx]}"


def format_rate(packet_delta: int, byte_delta: int, elapsed: float) -> str:
    if packet_delta == -1 or elapsed == 0:
        return "-"
    pps = packet_delta / elapsed
    if byte_delta == -1:
        return f"{pps:.2f} pps / -"
    bps = int(byte_delta * 8 / elapsed)
    return f"{pps:.2f} pps / {human_bps(bps)}"
