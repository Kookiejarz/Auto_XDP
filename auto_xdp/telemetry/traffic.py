"""Retained-event summaries and diagnostic models, with no I/O or curses."""
from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Any

from auto_xdp.telemetry.events import COUNTER_NAMES


@dataclass
class TrafficRow:
    ip: str
    proto: str
    port: str
    packets: int
    bytes_: int | None
    verdict: str
    last_seen: float
    allows: int = 0
    drops: int = 0
    bytes_events: int = 0
    cookie_verified: bool = False


def _event_bytes(ev: dict[str, Any]) -> int | None:
    for key in ("pkt_len", "bytes", "size", "len", "packet_len"):
        value = ev.get(key)
        if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
            return value
    return None


def event_time(ev: dict[str, Any]) -> float:
    try:
        value = float(ev.get("seen_at") or 0.0)
        return value if math.isfinite(value) and 0 <= value <= 253402300799 else 0.0
    except (ValueError, TypeError, OverflowError):
        return 0.0


def _collect_top_traffic(events: list[dict[str, Any]], limit: int = 10) -> list[TrafficRow]:
    totals: dict[tuple[str, str, str], TrafficRow] = {}
    for ev in events:
        if ev.get("type") == "port_change" or not ev.get("src"):
            continue
        key = str(ev["src"]), str(ev.get("proto") or "-"), str(ev.get("dport") or "-")
        row = totals.setdefault(key, TrafficRow(*key, 0, None, "-", 0.0))
        row.packets += 1
        verdict = str(ev.get("verdict") or "-")
        row.allows += verdict == "ALLOW"
        row.drops += verdict == "DROP"
        byte_count = _event_bytes(ev)
        if byte_count is not None:
            row.bytes_ = (row.bytes_ or 0) + byte_count
            row.bytes_events += 1
        last_seen = event_time(ev)
        if last_seen >= row.last_seen:
            row.last_seen, row.verdict = last_seen, verdict
        if ev.get("reason") == "SYN_COOKIE_VALID":
            row.cookie_verified = True
    return sorted(totals.values(),
                  key=lambda row: (-(row.bytes_ or 0), -row.packets, row.ip, row.proto, row.port))[:max(0, limit)]


def cookie_counters(stats: list[tuple[str, int, int, str]]) -> list[tuple[str, int | None, str]]:
    """Diagnostic counters overlap; never sum them to infer total DROP."""
    observed = {name: (packets, rate) for name, packets, _, rate in stats if packets >= 0}
    names = [name for name in COUNTER_NAMES
             if name.startswith("SYN_COOKIE_") or name == "SYN_GUARD_SHED_ENTER"]
    return [(name, *observed.get(name, (None, "unknown"))) for name in names]


def counter_value(stats: list[tuple[str, int, int, str]], name: str) -> str:
    return next((str(packets) for key, packets, _, _ in stats if key == name and packets >= 0), "unknown")
