"""Responsive map tables; drawing uses the collected snapshot only."""
from __future__ import annotations

import curses
import unicodedata
from typing import Any, TYPE_CHECKING

from auto_xdp.admin.formatting import human_bytes
from auto_xdp.tui.widgets import (
    _add, _box, _clip, _color, _meter, _CP_MUTED, _CP_RED, _CP_YELLOW, _CP_GRAPH_RX,
)

if TYPE_CHECKING:
    from auto_xdp.tui.app import MapUsage


_FIXED = {"array", "percpu_array", "prog_array"}
_SAMPLED = {"sampled", "cached", "attack cached"}
_TITLES = {"name": "map", "type": "type", "id": "id", "used": "used",
           "max": "max", "usage": "usage", "memory": "memory", "source": "count source"}
_RIGHT = {"id", "used", "max", "memory"}


def _cells(text: str) -> int:
    return sum(0 if unicodedata.combining(c) else 2 if unicodedata.east_asian_width(c) in {"W", "F"} else 1
               for c in text)


def _field(text: str, width: int, right: bool = False) -> str:
    clean = "".join(c for c in text if c.isprintable())
    fitted = _clip(clean, width + 1)
    if fitted != clean and width:
        fitted = _clip(clean, width) + "…"
    padding = " " * max(0, width - _cells(fitted))
    return padding + fitted if right else fitted + padding


def _count_source(row: MapUsage) -> str:
    if row.note == "attack skip":
        return "skipped (attack)"
    if row.note == "attack cached":
        return "cached (attack)"
    if row.note == "deferred":
        return "pending"
    if row.note == "array":
        return "fixed slots"
    if row.current is None:
        return "not counted" if row.kind in _FIXED or row.kind == "ringbuf" else "unavailable"
    return row.note or "-"


def _values(row: MapUsage) -> dict[str, str]:
    used = ("skip" if row.note == "attack skip" else "pending" if row.note == "deferred"
            else "-") if row.current is None else ("~" if row.note in _SAMPLED else "") + str(row.current)
    usage = "fixed" if row.kind in _FIXED else "--" if row.pct is None else f"{row.pct:.1f}%"
    return dict(name=row.name, type=row.kind, id=str(row.map_id) if row.map_id is not None else "-",
                used=used, max=str(row.maximum) if row.maximum is not None else "-", usage=usage,
                memory=human_bytes(row.memlock) if row.memlock is not None else "-", source=_count_source(row))


def _columns(values: list[dict[str, str]], available: int) -> tuple[list[tuple[str, int]], int]:
    keys = ["name", "type"]
    if available >= 116:
        keys.append("id")
    keys.extend(("used", "max", "usage", "memory"))
    if available >= 96:
        keys.append("source")
    gap = 3 if available >= 176 else 2
    minimum = dict(name=18, type=12, id=5, used=7, max=7, usage=6, memory=8, source=12)
    widths = {key: minimum[key] for key in keys}
    spare = max(0, available - sum(widths.values()) - gap * (len(keys) - 1))
    # Exact numeric values and readable types take priority over padding.
    for key in ("used", "max", "memory", "type", "id", "source", "name"):
        if key not in widths:
            continue
        target = max((_cells(row[key]) for row in values), default=len(_TITLES[key]))
        if key == "name":
            target = max(24, target)
        growth = min(spare, max(0, target - widths[key]))
        widths[key] += growth
        spare -= growth
    # Keep a percentage-only column on small screens; add a useful bar when it fits.
    if spare >= 10:
        growth = min(spare, 14)
        widths["usage"] += growth
        spare -= growth
    weights = {key: weight for key, weight in (("name", 3), ("type", 1), ("usage", 1), ("source", 2))
               if key in widths}
    total = sum(weights.values())
    extra = {key: spare * weight // total for key, weight in weights.items()}
    for key, growth in extra.items():
        widths[key] += growth
    widths["name"] += spare - sum(extra.values())
    return [(key, widths[key]) for key in keys], gap


def _short_count(value: int | None) -> str:
    if value is None:
        return "--"
    for divisor, suffix in ((1_000_000_000, "G"), (1_000_000, "M"), (1_000, "k")):
        if value >= divisor:
            return f"{value / divisor:.0f}{suffix}"
    return str(value)


def _draw_maps(win: Any, rows: list[MapUsage], scroll: int, focused: bool, *, expanded: bool = False) -> None:
    h, w = win.getmaxyx()
    _box(win, f"BPF maps / {len(rows)}", focused=focused)
    wide = expanded or w >= 90
    available = max(0, w - 4)
    values = [_values(row) for row in rows]
    if wide:
        columns, gap = _columns(values, available)
        header = (" " * gap).join(_field(_TITLES[key], width, key in _RIGHT) for key, width in columns)
    else:
        name_width = max(1, available - 17)
        header = f"{_field('map', name_width)} {'entries':>10} {'%':>5}"
    _add(win, 1, 2, header, _color(_CP_MUTED))
    visible = max(0, h - 3)
    scroll = max(0, min(scroll, max(0, len(rows) - visible)))
    for idx, row in enumerate(rows[scroll:scroll + visible], start=2):
        value = values[scroll + idx - 2]
        fixed = row.kind in _FIXED
        attr = _color(_CP_RED) | curses.A_BOLD if not fixed and row.pct is not None and row.pct >= 80 else curses.A_NORMAL
        if wide:
            fields = []
            for key, width in columns:
                text = _field(value[key], 6, True).ljust(width) if key == "usage" else _field(value[key], width, key in _RIGHT)
                fields.append(text)
            _add(win, idx, 2, (" " * gap).join(fields), attr)
            x = 2
            for key, width in columns:
                if key == "usage" and width >= 16 and not fixed and row.pct is not None:
                    color = _CP_RED if row.pct >= 80 else _CP_YELLOW if row.pct >= 70 else _CP_GRAPH_RX
                    _meter(win, idx, x + 8, width - 8, row.pct, color)
                x += width + gap
        else:
            capacity = f"{_short_count(row.current)}/{_short_count(row.maximum)}"
            if fixed and row.maximum is not None:
                capacity = f"{row.maximum:,}"
                if len(capacity) > 10:
                    capacity = _short_count(row.maximum)
            if row.note == "attack skip":
                capacity = f"skip/{_short_count(row.maximum)}"
            if row.note in _SAMPLED:
                capacity = "~" + capacity
            usage = "fixed" if fixed else "--" if row.pct is None else f"{row.pct:.1f}"
            _add(win, idx, 2, f"{_field(row.name, name_width)} {_field(capacity, 10, True)} {_field(usage, 5, True)}", attr)
    total_mem = sum(row.memlock for row in rows if row.memlock is not None)
    memory = f" · {human_bytes(total_mem)}" if total_mem and w >= 40 else ""
    action = "m back" if expanded else "m expand"
    footer = f" {scroll + bool(rows)}-{min(scroll + visible, len(rows))}/{len(rows)}{memory} · {action} "
    if wide and w >= 110:
        footer += "· ~ sampled/cached · skip: count paused"
    _add(win, h - 1, 2, footer, _color(_CP_MUTED))
