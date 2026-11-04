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
from auto_xdp.tui.layout import Column, table_columns, table_line
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


def _event_columns(width: int, compact: bool) -> list[tuple[Column, int]]:
    specs = [Column("time", 8, 0), Column("verdict", 4 if compact else 5, 0),
             Column("proto", 4 if compact else 8, 0), Column("source", 8 if compact else 14, 4),
             Column("port", 5, 0, True), Column("service", 6 if compact else 10, 2)]
    if not compact or width >= 88:
        specs.append(Column("reason", 12 if compact else 14, 3))
    return table_columns(width - 4, specs, gap=1 if compact else 2)


def _socket_columns(width: int, compact: bool) -> list[tuple[Column, int]]:
    specs = [Column("time", 8, 0), Column("event", 14, 0), Column("proto", 6, 0),
             Column("port", 11), Column("service", 18, 3)]
    if not compact and width >= 110:
        specs.append(Column("identity", 16, 2))
    return table_columns(width - 4, specs, gap=1 if compact else 2)


def _draw_event_row(win: Any, i: int, ev: dict[str, Any], compact: bool = False,
                    service: str = "unknown") -> None:
    ts = event_time(ev)
    tstr = _dt.datetime.fromtimestamp(ts).strftime("%H:%M:%S") if ts else "--:--:--"
    if ev.get("type") == "port_change":
        family = ev.get("family")
        protocol = str(ev.get("proto", "-")).upper() + (str(family) if family in (4, 6) else "?")
        identity = f"id={str(ev['session_id'])[:6]}:{ev['seq']}" if "seq" in ev and "session_id" in ev else "id=unknown"
        columns = _socket_columns(win.getmaxyx()[1], compact)
        _add(win, i, 2, table_line(columns, dict(time=tstr, event=f"SOCKET {ev.get('action', 'change')}", proto=protocol,
                                                port=f"local:{ev.get('port', '-')}", service=f"svc(current)={service}", identity=identity),
                                   gap=1 if compact else 2))
        return
    verdict = str(ev.get("verdict", "-"))
    attr = curses.color_pair(_CP_GREEN) if verdict == "ALLOW" else curses.color_pair(_CP_RED)
    source = f"{ev.get('src') or '-'}/{ev.get('sport', '-')}"
    columns = _event_columns(win.getmaxyx()[1], compact)
    values = dict(time=tstr, verdict=verdict, proto=str(ev.get("proto", "-")), source=source,
                  port=str(ev.get("dport", "-")), service=service, reason=str(ev.get("reason", "unknown")))
    if compact:
        values["verdict"] = "PASS" if verdict == "ALLOW" else verdict
        line = table_line(columns, values, gap=1)
        _add(win, i, 2, line, attr)
        return
    reason = str(ev.get("reason", "unknown"))
    _add(win, i, 2, table_line(columns, values), attr)
    ifindex = ev.get("ifindex")
    length = ev.get("pkt_len")
    _add(win, i + 1, 2,
         f"if={ifindex if ifindex is not None else '?'} len={length if length is not None else '?'} "
         f"dst={ev.get('dst') or '?'} service(current)={service} | {describe_reason(reason)}",
         _color(_CP_MUTED))


def _draw_events(win: Any, relay: RelayClient, snap: Any, top: int, focused: bool,
                 dport_filter: int | None = None, filter_scroll: int = 0,
                 compact: bool = False) -> None:
    columns = _event_columns(win.getmaxyx()[1], compact)
    header = table_line(columns, dict(time="TIME" if compact else "time", verdict="ACT" if compact else "v",
                                      proto="PROTO" if compact else "protocol", source="SOURCE" if compact else "source",
                                      port="PORT" if compact else "dport", service="SERVICE" if compact else "service", reason="reason"),
                        gap=1 if compact else 2)
    services = EventServices(snap)
    suppressed = _events_suppressed(snap)
    port_only = _only_socket_events(relay)
    visible = _event_visible(win, compact, suppressed=suppressed, port_only=port_only)
    notice = (1 if compact else 2) if suppressed else 0
    title = "Recent events" if compact else "Packet events"
    if port_only:
        title += " / SOCKET EVENTS · global trace"
    if dport_filter is not None:
        title += f" / port {dport_filter}"
        if not compact:
            title += " (click to clear)"
    _box(win, title, focused=focused)
    if port_only:
        header = table_line(_socket_columns(win.getmaxyx()[1], compact),
                            dict(time="TIME", event="SOCKET EVENTS", proto="proto", port="local port",
                                 service="service=current", identity="history id"), gap=1 if compact else 2)
    if suppressed:
        reason = "under_attack=true" if snap.under_attack else "runtime flag"
        notice_text = (f"Packet records OFF ({reason})" if getattr(snap, "packet_events_enabled", None) is False
                       else "Config: records OFF; runtime unknown")
        _add(win, 1, 2, notice_text, _color(_CP_MUTED))
        if not compact:
            hint = ("Counters remain live. Enable records: axdp under-attack off" if snap.under_attack
                    else "Counters remain live; packet recording is disabled by the runtime flag.")
            _add(win, 2, 2, hint, _color(_CP_MUTED))
    _add(win, 1 + notice, 2, header, _color(_CP_MUTED))
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
    columns = table_columns(win.getmaxyx()[1] - 4, (Column("reason", 28, 4), Column("count", 7, 1, True), Column("percent", 6, 1, True)))
    _add(win, 1, 2, table_line(columns, dict(reason="reason / description below", count="events", percent="%")), _color(_CP_MUTED))
    visible = max(0, (win.getmaxyx()[0] - 3) // 2)
    scroll = max(0, min(scroll, max(0, len(rows) - visible)))
    for idx, (reason, count) in enumerate(rows[scroll:scroll + visible]):
        _add(win, 2 + idx * 2, 2, table_line(columns, dict(reason=reason, count=str(count), percent=f"{count / total * 100:.1f}")),
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
    columns = table_columns(w - 4, (Column("ip", 20, 4), Column("proto", 5, 0), Column("port", 5, 0, True),
                                    Column("count", 6, 1, True), Column("verdicts", 9, 1, True), Column("bytes", 9, 1, True)))
    _add(win, 1, 2, table_line(columns, dict(ip="source ip", proto="proto", port="port", count="events", verdicts="A/D", bytes="bytes*")), _color(_CP_MUTED))
    rows = _collect_top_traffic(relay.events, limit=max(0, (h - 4) // 2))
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
        _add(win, 2 + idx * 2, 2, table_line(columns, dict(ip=row.ip, proto=row.proto, port=str(row.port), count=str(row.packets),
                                                        verdicts=f"{row.allows}/{row.drops}", bytes=bytes_text)), attr)
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
    h, w = win.getmaxyx()
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
    columns = table_columns(w - 4, (Column("name", 42, 4), Column("count", 10, 1, True), Column("rate", 12, 1, True)))
    _add(win, 4, 2, table_line(columns, dict(name="diagnostic counter (overlapping; do not sum)", count="count", rate="rate")), _color(_CP_MUTED))
    rows = cookie_counters(snap.stats)
    visible = max(0, h - 11)
    scroll = max(0, min(scroll, max(0, len(rows) - visible)))
    for idx, (name, count, rate) in enumerate(rows[scroll:scroll + visible], start=5):
        _add(win, idx, 2, table_line(columns, dict(name=name, count=str(count) if count is not None else "unknown", rate=rate)))
    def metrics(y: int, prefix: str, items: list[str]) -> None:
        _add(win, y, 1, prefix, _color(_CP_MUTED))
        fields = table_columns(w - len(prefix) - 4, [Column(str(index), len(item)) for index, item in enumerate(items)])
        _add(win, y, len(prefix) + 2, table_line(fields, {str(index): item for index, item in enumerate(items)}))
    metrics(h - 6, "BPF events:", [
        f"{label}={counter_value(snap.stats, name)}" for label, name in (
            ("emitted", "EVENT_EMITTED"), ("lost", "EVENT_LOST"), ("suppressed", "EVENT_SUPPRESSED"))])
    health = relay.telemetry_status
    metrics(h - 5, "Relay:", [
        f"{label}={health.get(name, 'unknown')}" for label, name in (
            ("decoded", "decoded_events"), ("queue loss", "queue_dropped"), ("invalid", "invalid_records"))])
    metrics(h - 4, "Relay:", [
        f"{label}={health.get(name, 'unknown')}" for label, name in (
            ("depth", "queue_depth"), ("retained", "retained_events"), ("port loss", "port_events_dropped"),
            ("disconnects", "client_disconnects"))])
    note = "packet records OFF; counters remain live" if _events_suppressed(snap) else relay.status
    history = str(relay.history_available) if relay.history_available is not None else "unknown"
    replay = "replay truncated" if relay.history_truncated else "bounded sample"
    _add(win, h - 3, 1, f"{note}; history available={history}; {replay}", _color(_CP_MUTED))
    _add(win, h - 2, 1, f"GeoIP: {getattr(geoip, 'status', 'unavailable')}; location estimates do not identify attackers.", _color(_CP_MUTED))
    _add(win, h - 1, 2,
         f"{scroll + bool(rows)}-{min(scroll + visible, len(rows))}/{len(rows)}  arrows:scroll  v:samples o:overview q:quit",
         _color(_CP_MUTED))
