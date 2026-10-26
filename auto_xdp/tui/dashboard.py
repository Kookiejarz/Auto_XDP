"""Dashboard charts and host meters. Drawing uses snapshots only."""
from __future__ import annotations

import curses
from typing import Any

from auto_xdp.admin.formatting import human_bytes
from auto_xdp.tui.metrics import HostMetrics, NetworkMetrics
from auto_xdp.tui.traffic import _events_suppressed
from auto_xdp.tui.widgets import (
    _add, _box, _color, _meter, _CP_BLUE, _CP_CYAN, _CP_GREEN,
    _CP_MUTED, _CP_RED, _CP_YELLOW, _CP_SELECTED, _CP_GRAPH_RX, _CP_GRAPH_TX,
)


def _number(value: float | int | None) -> str:
    if value is None or value < 0:
        return "--"
    for divisor, suffix in ((1e9, "G"), (1e6, "M"), (1e3, "k")):
        if value >= divisor:
            return f"{value / divisor:.2f}{suffix}"
    return f"{value:.0f}"


def _bits(rate: float | None) -> str:
    if rate is None or rate < 0:
        return "--"
    bits = rate * 8
    for divisor, suffix in ((1e9, "Gb/s"), (1e6, "Mb/s"), (1e3, "kb/s")):
        if bits >= divisor:
            return f"{bits / divisor:.2f} {suffix}"
    return f"{bits:.0f} b/s"


def _graph(win: Any, y: int, x: int, width: int, height: int,
           history: tuple[float | None, ...], color: int) -> None:
    if width <= 0 or height <= 0:
        return
    samples = history[-width:]
    values = (None,) * (width - len(samples)) + samples
    peak = max((value for value in samples if value is not None), default=0.0)
    glyphs = " ▁▂▃▄▅▆▇█"
    for row in range(height):
        floor = (height - row - 1) * 8
        line = []
        for value in values:
            if value is None:
                line.append(" ")
            elif peak <= 0:
                line.append("▁" if row == height - 1 else " ")
            else:
                level = max(0, min(8, round(value / peak * height * 8) - floor))
                line.append(glyphs[level])
        _add(win, y + row, x, "".join(line), _color(color))


def _draw_network(win: Any, network: NetworkMetrics, snap: Any) -> None:
    h, w = win.getmaxyx()
    link = f" · {network.speed_mbps / 1000:g} Gb/s link" if network.speed_mbps else ""
    _box(win, f"Network / {network.iface or snap.iface}{link}", accent=_CP_CYAN)
    interior = max(0, h - 3)
    rx_height = max(0, (interior - 2) // 2)
    tx_height = max(0, interior - 2 - rx_height)
    tx_y = 2 + rx_height
    _add(win, 1, 2, f"↓ RX  {_bits(network.rx_bytes_rate):>13}", _color(_CP_CYAN))
    _add(win, tx_y, 2, f"↑ TX  {_bits(network.tx_bytes_rate):>13}", _color(_CP_BLUE))
    if w >= 58:
        _add(win, 1, 25, f"{_number(network.rx_packets_rate):>7} pps", _color(_CP_MUTED))
        _add(win, tx_y, 25, f"{_number(network.tx_packets_rate):>7} pps", _color(_CP_MUTED))
        rx_total = human_bytes(network.rx_bytes) if network.rx_bytes is not None else "--"
        tx_total = human_bytes(network.tx_bytes) if network.tx_bytes is not None else "--"
        _add(win, 1, max(40, w - 22), f"total {rx_total}", _color(_CP_MUTED))
        _add(win, tx_y, max(40, w - 22), f"total {tx_total}", _color(_CP_MUTED))
    _graph(win, 2, 2, w - 4, rx_height, network.rx_history, _CP_GRAPH_RX)
    _graph(win, tx_y + 1, 2, w - 4, tx_height, network.tx_history, _CP_GRAPH_TX)
    rate = snap.rates.get("XDP_TOTAL", (None, None))[0]
    dropped = snap.rates.get("XDP_DROP_TOTAL", (None, None))[0]
    if snap.backend == "xdp":
        text = f" XDP {_number(rate)} pps · drop {_number(dropped)} pps "
    else:
        text = " interface counters · auto-scaled history "
    _add(win, h - 1, 2, text, _color(_CP_MUTED))


def _percent(value: float | None) -> str:
    return "--" if value is None else f"{value:4.1f}%"


def _usage_color(value: float | None) -> int:
    return _CP_RED if value is not None and value >= 90 else _CP_YELLOW if value is not None and value >= 75 else _CP_GREEN


def _draw_system(win: Any, host: HostMetrics) -> None:
    h, w = win.getmaxyx()
    _box(win, "Host resources", accent=_CP_BLUE)
    _add(win, 1, 2, "CPU", _color(_CP_MUTED))
    _meter(win, 1, 7, w - 17, host.cpu_percent, _usage_color(host.cpu_percent))
    _add(win, 1, w - 9, _percent(host.cpu_percent), _color(_usage_color(host.cpu_percent)))
    memory = (100 * host.memory_used / host.memory_total
              if host.memory_used is not None and host.memory_total else None)
    _add(win, 2, 2, "MEM", _color(_CP_MUTED))
    _meter(win, 2, 7, w - 17, memory, _CP_BLUE)
    _add(win, 2, w - 9, _percent(memory), _color(_CP_BLUE))
    if h >= 6:
        used = human_bytes(host.memory_used) if host.memory_used is not None else "--"
        total = human_bytes(host.memory_total) if host.memory_total is not None else "--"
        _add(win, 3, 2, f"Memory {used} / {total}", _color(_CP_MUTED))
    if h >= 7:
        load = " / ".join(f"{value:.2f}" for value in host.load) or "--"
        _add(win, 4, 2, f"Load {load}", _color(_CP_MUTED))
    if h >= 9 and host.cores:
        column_width = max(1, (w - 4) // 2)
        visible_rows = h - 7
        for idx, (name, percent) in enumerate(host.cores[:visible_rows * 2]):
            row, column = divmod(idx, 2)
            x = 2 + column * column_width
            _add(win, 6 + row, x, f"{name:>2}", _color(_CP_MUTED))
            _meter(win, 6 + row, x + 4, column_width - 11, percent, _usage_color(percent))
            _add(win, 6 + row, x + column_width - 6, _percent(percent), _color(_usage_color(percent)))
    uptime = ""
    if host.uptime is not None:
        hours = int(host.uptime) // 3600
        uptime = f" up {hours // 24}d {hours % 24:02}:{int(host.uptime) // 60 % 60:02} "
    _add(win, h - 1, 2, uptime or " /proc · waiting for baseline ", _color(_CP_MUTED))


_PAGES = (
    ("o", "Overview", "overview"), ("v", "Sources", "traffic"),
    ("e", "Events", "events"), ("c", "Health", "cookie"),
    ("m", "Maps", "maps"), ("a", "Audit", "audit"), ("p", "Requests", "approvals"),
)


def _draw_header(stdscr: Any, snap: Any, page: str, clock: str) -> None:
    _, w = stdscr.getmaxyx()
    _add(stdscr, 0, 1, "AUTO XDP", _color(_CP_CYAN) | curses.A_BOLD)
    identity = snap.host.hostname or snap.attach_target or snap.iface
    suppressed = _events_suppressed(snap)
    identity_width = w - 54 if suppressed else w - len(clock) - 17
    _add(stdscr, 0, 12, identity[:max(0, identity_width)], _color(_CP_MUTED))
    if suppressed:
        _add(stdscr, 0, max(24, w - 37), " EVENTS SUPPRESSED ", _color(_CP_RED))
    _add(stdscr, 0, max(0, w - len(clock) - 2), clock, _color(_CP_MUTED))
    x = 1
    for key, label, target in _PAGES:
        text = f" {key} {label} "
        active = target == page
        _add(stdscr, 1, x, text, (_color(_CP_SELECTED) | curses.A_BOLD) if active else _color(_CP_MUTED))
        x += len(text)


def _draw_footer(stdscr: Any, snap: Any, error: str, focus: str, page: str, *,
                 mouse_enabled: bool = False, copy_mode: bool = False) -> None:
    h, w = stdscr.getmaxyx()
    if copy_mode:
        text = " COPY MODE · screen paused · drag to select · F2 resume · q quit"
        _add(stdscr, h - 1, 0, text.ljust(max(0, w - 1)), _color(_CP_SELECTED))
        return
    if error:
        _add(stdscr, h - 1, 1, error, _color(_CP_RED) | curses.A_BOLD)
        return
    if page == "overview":
        text = f" tab focus: {focus}  ↑↓ scroll  enter filter  F2 copy  q quit"
    else:
        text = " ↑↓ scroll  PgUp/PgDn page  F2 copy  o overview  q quit"
    if mouse_enabled:
        text = (f" tab focus: {focus}  click tabs  wheel/↑↓  F2 copy  q quit" if page == "overview"
                else " click tabs  wheel/↑↓  F2 copy  o overview  q quit")
    _add(stdscr, h - 1, 0, text, _color(_CP_MUTED))
    if w >= 110:
        status = snap.status or "collecting"
        _add(stdscr, h - 1, max(0, w - len(status) - 2), status, _color(_CP_MUTED))
