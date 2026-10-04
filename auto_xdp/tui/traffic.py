"""Traffic, event and cookie views; rendering never reads kernel maps."""
from __future__ import annotations

import curses
import datetime as _dt
from typing import Any

from auto_xdp.admin.formatting import human_bytes
from auto_xdp.telemetry.relay_client import RelayClient
from auto_xdp.telemetry.events import describe_reason
from auto_xdp.telemetry.traffic import _collect_top_traffic, cookie_counters, counter_value, event_time
from auto_xdp.tui.widgets import _add, _box, _CP_GREEN, _CP_RED


def _event_bottom_top(relay: RelayClient, visible: int) -> int:
    return max(relay.events_offset, relay.events_end - visible)


def _clamp_event_top(relay: RelayClient, visible: int, top: int) -> int:
    return max(relay.events_offset, min(top, _event_bottom_top(relay, visible)))


def _event_window(relay: RelayClient, visible: int, top: int) -> tuple[int, int, list[dict[str, Any]]]:
    top = _clamp_event_top(relay, visible, top)
    start = max(0, top - relay.events_offset)
    return top, start, relay.events[start:start + visible] if visible else []


def _event_visible(win: Any) -> int:
    return max(0, (win.getmaxyx()[0] - 3) // 2)


def _draw_event_row(win: Any, i: int, ev: dict[str, Any]) -> None:
    ts = event_time(ev)
    tstr = _dt.datetime.fromtimestamp(ts).strftime("%H:%M:%S") if ts else "--:--:--"
    if ev.get("type") == "port_change":
        _add(win, i, 1, f"{tstr} port {ev.get('action', 'change')} {ev.get('proto', '-')}:{ev.get('port', '-')}")
        return
    verdict = str(ev.get("verdict", "-"))
    attr = curses.color_pair(_CP_GREEN) if verdict == "ALLOW" else curses.color_pair(_CP_RED)
    source = f"{ev.get('src', '-')}/{ev.get('sport', '-')}"
    source_width = min(39, max(12, win.getmaxyx()[1] - 36))
    reason = str(ev.get("reason", "unknown"))
    line = (f"{tstr:<8} {verdict:<5} {str(ev.get('proto', '-')):<8.8} "
            f"{source:<{source_width}.{source_width}} {str(ev.get('dport', '-')):>5} {reason}")
    _add(win, i, 1, line, attr)
    ifindex = ev.get("ifindex")
    length = ev.get("pkt_len")
    _add(win, i + 1, 2,
         f"if={ifindex if ifindex is not None else '?'} len={length if length is not None else '?'} "
         f"{reason}: {describe_reason(reason)}", curses.A_DIM)


def _draw_events(win: Any, relay: RelayClient, snap: Any, top: int, focused: bool,
                 dport_filter: int | None = None, filter_scroll: int = 0) -> None:
    source_width = min(39, max(12, win.getmaxyx()[1] - 36))
    header = f"{'time':<8} {'v':<5} {'protocol':<8} {'source':<{source_width}} {'dport':>5} reason"
    visible = _event_visible(win)
    _box(win, (f"events [port {dport_filter}]" if dport_filter is not None else "events") + (" *" if focused else ""))
    _add(win, 1, 1, header)
    if dport_filter is not None:
        filtered = [ev for ev in relay.events if ev.get("type") != "port_change"
                    and str(ev.get("dport")) == str(dport_filter)]
        start = max(0, min(filter_scroll, max(0, len(filtered) - visible)))
        events = filtered[start:start + visible]
        footer = f"{len(filtered)} retained matches  enter:clear filter  {relay.status}"
    else:
        _, start, events = _event_window(relay, visible, top)
        follow = top >= _event_bottom_top(relay, visible)
        tag = "LIVE" if follow else "PAUSED"
        footer = f"{start + bool(events)}-{start + len(events)}/{len(relay.events)} [{tag}] {relay.status}"
    for i, ev in enumerate(events):
        _draw_event_row(win, 2 + i * 2, ev)
    if snap.under_attack:
        footer = "packet events suppressed (under-attack config)"
    _add(win, win.getmaxyx()[0] - 1, 2, footer, curses.A_DIM)


def _draw_drop_reasons(win: Any, relay: RelayClient, scroll: int = 0) -> None:
    rows = sorted(relay.reason_totals.items(), key=lambda item: (-item[1], item[0]))
    total = sum(count for _, count in rows)
    _box(win, f"DROP reasons: {total} retained events")
    _add(win, 1, 1, f"{'reason':<38} {'events':>7} {'%':>6}  description below")
    visible = max(0, (win.getmaxyx()[0] - 3) // 2)
    scroll = max(0, min(scroll, max(0, len(rows) - visible)))
    for idx, (reason, count) in enumerate(rows[scroll:scroll + visible]):
        _add(win, 2 + idx * 2, 1, f"{reason:<38.38} {count:>7} {count / total * 100:>6.1f}",
             curses.color_pair(_CP_RED))
        _add(win, 3 + idx * 2, 3, describe_reason(reason), curses.A_DIM)
    if not rows:
        _add(win, 2, 1, "No DROP samples retained; this does not establish absence of drops.")
    _add(win, win.getmaxyx()[0] - 1, 2,
         f"{scroll + bool(rows)}-{min(scroll + visible, len(rows))}/{len(rows)} reasons  arrows:scroll  c:cookie / health",
         curses.A_DIM)


def _draw_top_traffic(win: Any, relay: RelayClient, geoip: Any = None) -> None:
    _box(win, "retained event samples by source ip / protocol / port")
    h, w = win.getmaxyx()
    ip_width = min(39, max(20, w - 58))
    _add(win, 1, 1, f"{'source ip':<{ip_width}} {'proto':<5} {'port':>5} {'events':>6} {'A/D':>9} {'bytes*':>9}")
    rows = _collect_top_traffic(relay.events, limit=min(10, max(0, (h - 4) // 2)))
    db_updated = "unknown"
    for idx, row in enumerate(rows):
        loc = geoip.lookup(row.ip) if geoip is not None else {}
        db_updated = str(loc.get("db_updated_at") or db_updated)
        country = str(loc.get("country_code") or "unknown")
        asn = f"AS{loc['asn']}" if loc.get("asn") is not None else "ASN unknown"
        org = str(loc.get("as_org") or loc.get("status") or "GeoIP unavailable")
        tstr = _dt.datetime.fromtimestamp(row.last_seen).strftime("%H:%M:%S") if row.last_seen else "-"
        bytes_text = "unknown" if row.bytes_ is None else human_bytes(row.bytes_)
        attr = curses.color_pair(_CP_RED) if row.drops else curses.color_pair(_CP_GREEN)
        _add(win, 2 + idx * 2, 1,
             f"{row.ip:<{ip_width}.{ip_width}} {row.proto:<5.5} {row.port:>5.5} {row.packets:>6} "
             f"{row.allows}/{row.drops:<7} {bytes_text:>9}", attr)
        evidence = "cookie verified" if row.cookie_verified else "unverified source"
        _add(win, 3 + idx * 2, 2,
             f"{country} {asn} | {tstr} | len {row.bytes_events}/{row.packets} | {evidence} | {org}", curses.A_DIM)
    _add(win, h - 2, 2, f"{len(relay.events)} retained; A/D=ALLOW/DROP; bytes* recorded only; len=coverage", curses.A_DIM)
    _add(win, h - 1, 2,
         f"GeoIP: {getattr(geoip, 'status', 'unavailable')}; DB updated: {db_updated}", curses.A_DIM)


def _draw_cookie(win: Any, snap: Any, relay: RelayClient, scroll: int = 0,
                 geoip: Any = None) -> None:
    """Counters are cumulative diagnostics, not packet totals or accept counts."""
    _box(win, "SYN cookie / observation health")
    h, _ = win.getmaxyx()
    configured = getattr(snap, "cookie_configured", None)
    configured_text = "unknown" if configured is None else "enabled" if configured else "disabled"
    runtime = getattr(snap, "cookie_runtime", None)
    actual = "unknown" if runtime is None else "enabled" if runtime[0] else "disabled"
    _add(win, 1, 1, f"Cookie: runtime={actual}; configured={configured_text}; backend={snap.backend}")
    if runtime is None:
        runtime_text = "Runtime map unavailable; configuration does not prove active protection."
    else:
        runtime_text = f"Auto: {runtime[1]}% challenge / {runtime[2]}% shed; ACK {runtime[3]}/s; cooldown {runtime[4] / 1e9:g}s"
    _add(win, 2, 1, runtime_text)
    _add(win, 3, 1, "VALID != application accept; handoff success = request assigned, not accepted.", curses.A_DIM)
    _add(win, 4, 1, f"{'diagnostic counter (overlapping; do not sum)':<48} {'count':>10}  rate")
    rows = cookie_counters(snap.stats)
    visible = max(0, h - 11)
    scroll = max(0, min(scroll, max(0, len(rows) - visible)))
    for idx, (name, count, rate) in enumerate(rows[scroll:scroll + visible], start=5):
        _add(win, idx, 1, f"{name:<48.48} {str(count) if count is not None else 'unknown':>10}  {rate}")
    _add(win, h - 6, 1, "BPF events: " + " / ".join(
        f"{label}={counter_value(snap.stats, name)}" for label, name in (
            ("emitted", "EVENT_EMITTED"), ("lost", "EVENT_LOST"), ("suppressed", "EVENT_SUPPRESSED"))))
    health = relay.telemetry_status
    _add(win, h - 5, 1, "Relay: " + " ".join(
        f"{label}={health.get(name, 'unknown')}" for label, name in (
            ("decoded", "decoded_events"), ("queue loss", "queue_dropped"), ("invalid", "invalid_records"))))
    _add(win, h - 4, 1, "Relay: " + " ".join(
        f"{label}={health.get(name, 'unknown')}" for label, name in (
            ("depth", "queue_depth"), ("retained", "retained_events"), ("port loss", "port_events_dropped"),
            ("disconnects", "client_disconnects"))))
    note = "packet events suppressed (under-attack config)" if snap.under_attack else relay.status
    history = str(relay.history_available) if relay.history_available is not None else "unknown"
    replay = "replay truncated" if relay.history_truncated else "bounded sample"
    _add(win, h - 3, 1, f"{note}; history available={history}; {replay}", curses.A_DIM)
    _add(win, h - 2, 1, f"GeoIP: {getattr(geoip, 'status', 'unavailable')}; location estimates do not identify attackers.", curses.A_DIM)
    _add(win, h - 1, 2,
         f"{scroll + bool(rows)}-{min(scroll + visible, len(rows))}/{len(rows)}  arrows:scroll  v:samples o:overview q:quit",
         curses.A_DIM)
