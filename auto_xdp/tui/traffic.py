"""Traffic, event and cookie views; rendering never reads kernel maps."""
from __future__ import annotations

import curses
import datetime as _dt
from typing import Any

from auto_xdp.admin.formatting import human_bytes
from auto_xdp.telemetry.relay_client import RelayClient
from auto_xdp.telemetry.events import describe_reason
from auto_xdp.telemetry.traffic import _collect_top_traffic, cookie_counters, counter_value, event_time
from auto_xdp.tui.services import EventServices
from auto_xdp.tui.widgets import _add, _box, _color, _CP_MUTED, _CP_GREEN, _CP_RED


def _event_bottom_top(relay: RelayClient, visible: int) -> int:
    return max(relay.events_offset, relay.events_end - visible)


def _clamp_event_top(relay: RelayClient, visible: int, top: int) -> int:
    return max(relay.events_offset, min(top, _event_bottom_top(relay, visible)))


def _resize_event_top(relay: RelayClient, old_visible: int, visible: int, top: int) -> int:
    if top >= _event_bottom_top(relay, old_visible):
        return _event_bottom_top(relay, visible)
    return _clamp_event_top(relay, visible, top)


def _event_window(relay: RelayClient, visible: int, top: int) -> tuple[int, int, list[dict[str, Any]]]:
    top = _clamp_event_top(relay, visible, top)
    start = max(0, top - relay.events_offset)
    return top, start, relay.events[start:start + visible] if visible else []


def _events_suppressed(snap: Any) -> bool:
    enabled = getattr(snap, "packet_events_enabled", None)
    return enabled is False or (enabled is None and snap.under_attack)


def _only_socket_events(relay: RelayClient) -> bool:
    return all(event.get("type") == "port_change" for event in relay.events)


def _event_capacity(height: int, compact: bool = False, *, suppressed: bool = False,
                    port_only: bool = False) -> int:
    notice = (1 if compact else 2) if suppressed else 0
    return max(0, (height - 3 - notice) // (1 if compact or port_only else 2))


def _event_visible(win: Any, compact: bool = False, *, suppressed: bool = False,
                   port_only: bool = False) -> int:
    return _event_capacity(win.getmaxyx()[0], compact, suppressed=suppressed, port_only=port_only)


def _event_columns(width: int, compact: bool) -> tuple[int, int]:
    service_width = (12 if width >= 80 else 8) if compact else (18 if width >= 110 else 12)
    source_width = min(39, max(8 if compact else 12, width - (42 if compact else 47) - service_width))
    return source_width, service_width


def _draw_event_row(win: Any, i: int, ev: dict[str, Any], compact: bool = False,
                    service: str = "unknown") -> None:
    ts = event_time(ev)
    tstr = _dt.datetime.fromtimestamp(ts).strftime("%H:%M:%S") if ts else "--:--:--"
    if ev.get("type") == "port_change":
        _add(win, i, 2 if compact else 1,
             f"{tstr} SOCKET {ev.get('action', 'change')} {str(ev.get('proto', '-')).upper()} "
             f"local:{ev.get('port', '-')} svc={service} (current; notice)")
        return
    verdict = str(ev.get("verdict", "-"))
    attr = curses.color_pair(_CP_GREEN) if verdict == "ALLOW" else curses.color_pair(_CP_RED)
    source = f"{ev.get('src') or '-'}/{ev.get('sport', '-')}"
    source_width, service_width = _event_columns(win.getmaxyx()[1], compact)
    if compact:
        width = win.getmaxyx()[1]
        short_verdict = "PASS" if verdict == "ALLOW" else verdict
        line = (f"{tstr} {short_verdict:<4.4} {str(ev.get('proto', '-')):<4.4} "
                f"{source:<{source_width}.{source_width}} {str(ev.get('dport', '-')):>5} "
                f"{service:<{service_width}.{service_width}}")
        if width >= 88:
            line += "  " + str(ev.get("reason", "unknown"))
        _add(win, i, 2, line, attr)
        return
    reason = str(ev.get("reason", "unknown"))
    line = (f"{tstr:<8} {verdict:<5} {str(ev.get('proto', '-')):<8.8} "
            f"{source:<{source_width}.{source_width}} {str(ev.get('dport', '-')):>5} "
            f"{service:<{service_width}.{service_width}} {reason}")
    _add(win, i, 1, line, attr)
    ifindex = ev.get("ifindex")
    length = ev.get("pkt_len")
    _add(win, i + 1, 2,
         f"if={ifindex if ifindex is not None else '?'} len={length if length is not None else '?'} "
         f"dst={ev.get('dst') or '?'} service(current)={service} | {describe_reason(reason)}",
         _color(_CP_MUTED))


def _draw_events(win: Any, relay: RelayClient, snap: Any, top: int, focused: bool,
                 dport_filter: int | None = None, filter_scroll: int = 0,
                 compact: bool = False) -> None:
    source_width, service_width = _event_columns(win.getmaxyx()[1], compact)
    header = (f"{'time':<8} {'v':<5} {'protocol':<8} {'source':<{source_width}} {'dport':>5} "
              f"{'service':<{service_width}} reason")
    services = EventServices(snap)
    suppressed = _events_suppressed(snap)
    port_only = _only_socket_events(relay)
    visible = _event_visible(win, compact, suppressed=suppressed, port_only=port_only)
    notice = (1 if compact else 2) if suppressed else 0
    title = "Recent events" if compact else "Packet events"
    if dport_filter is not None:
        title += f" / port {dport_filter}"
        if not compact:
            title += " (click to clear)"
    _box(win, title, focused=focused)
    if compact:
        header = (f"{'TIME':<8} {'ACT':<4} {'PROTO':<4} {'SOURCE':<{source_width}} {'PORT':>5} "
                  f"{'SERVICE':<{service_width}}")
    if port_only:
        header = "TIME     SOCKET STATE NOTIFICATIONS · service=current"
    if suppressed:
        reason = "under_attack=true" if snap.under_attack else "runtime flag"
        notice_text = (f"Packet records OFF ({reason})" if getattr(snap, "packet_events_enabled", None) is False
                       else "Config: records OFF; runtime unknown")
        _add(win, 1, 2, notice_text, _color(_CP_MUTED))
        if not compact:
            hint = ("Counters remain live. Enable records: axdp under-attack off" if snap.under_attack
                    else "Counters remain live; packet recording is disabled by the runtime flag.")
            _add(win, 2, 2, hint, _color(_CP_MUTED))
    _add(win, 1 + notice, 2 if compact else 1, header, _color(_CP_MUTED))
    if dport_filter is not None:
        tag = "FILTER"
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
        _draw_event_row(win, 2 + notice + i * (1 if compact or port_only else 2), ev, compact, services.label(ev))
    if not events and visible:
        message = ("No retained packet records match this port." if dport_filter is not None
                   else "No records retained; packet recording is OFF." if suppressed
                   else "No records retained; waiting for relay samples.")
        _add(win, 2 + notice, 2, message, _color(_CP_MUTED))
    if suppressed:
        footer = f"{tag} · packet records OFF · counters live"
    else:
        footer += " · service=current inventory"
    _add(win, win.getmaxyx()[0] - 1, 2, footer, _color(_CP_MUTED))


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
        _add(win, 3 + idx * 2, 3, describe_reason(reason), _color(_CP_MUTED))
    if not rows:
        _add(win, 2, 1, "No DROP samples retained; this does not establish absence of drops.")
    _add(win, win.getmaxyx()[0] - 1, 2,
         f"{scroll + bool(rows)}-{min(scroll + visible, len(rows))}/{len(rows)} reasons  arrows:scroll  c:cookie / health",
         _color(_CP_MUTED))


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
             f"{country} {asn} | {tstr} | len {row.bytes_events}/{row.packets} | {evidence} | {org}", _color(_CP_MUTED))
    _add(win, h - 2, 2, f"{len(relay.events)} retained; A/D=ALLOW/DROP; bytes* recorded only; len=coverage", _color(_CP_MUTED))
    _add(win, h - 1, 2,
         f"GeoIP: {getattr(geoip, 'status', 'unavailable')}; DB updated: {db_updated}", _color(_CP_MUTED))


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
    _add(win, 3, 1, "VALID != application accept; handoff success = request assigned, not accepted.", _color(_CP_MUTED))
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
    note = "packet records OFF; counters remain live" if _events_suppressed(snap) else relay.status
    history = str(relay.history_available) if relay.history_available is not None else "unknown"
    replay = "replay truncated" if relay.history_truncated else "bounded sample"
    _add(win, h - 3, 1, f"{note}; history available={history}; {replay}", _color(_CP_MUTED))
    _add(win, h - 2, 1, f"GeoIP: {getattr(geoip, 'status', 'unavailable')}; location estimates do not identify attackers.", _color(_CP_MUTED))
    _add(win, h - 1, 2,
         f"{scroll + bool(rows)}-{min(scroll + visible, len(rows))}/{len(rows)}  arrows:scroll  v:samples o:overview q:quit",
         _color(_CP_MUTED))
