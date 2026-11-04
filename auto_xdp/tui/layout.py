"""Terminal-width table layout shared by all dashboard pages."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping, Sequence

from auto_xdp.tui.maps import _cells, _field


@dataclass(frozen=True)
class Column:
    key: str
    minimum: int
    weight: int = 1
    right: bool = False


def table_columns(available: int, specs: Sequence[Column], gap: int = 2) -> list[tuple[Column, int]]:
    """Use the entire interior, preserving compact numeric columns where possible."""
    if not specs:
        return []
    room = max(0, available - gap * (len(specs) - 1))
    widths = [max(1, item.minimum) for item in specs]
    while sum(widths) > room:
        widest = max(range(len(widths)), key=widths.__getitem__)
        if widths[widest] == 0:
            break
        widths[widest] -= 1
    spare = max(0, room - sum(widths))
    weights = [max(0, item.weight) for item in specs]
    if not sum(weights):
        weights[-1] = 1
    total = sum(weights)
    extra = [spare * weight // total for weight in weights]
    for index, amount in enumerate(extra):
        widths[index] += amount
    widths[max(range(len(weights)), key=weights.__getitem__)] += spare - sum(extra)
    return list(zip(specs, widths))


def table_line(columns: Sequence[tuple[Column, int]], values: Mapping[str, str], gap: int = 2) -> str:
    return (" " * gap).join(_field(values.get(item.key, ""), width, item.right) for item, width in columns)


def wrap_cells(text: str, width: int) -> list[str]:
    """Wrap diagnostics by terminal cells, preserving indentation and CJK text."""
    lines = []
    for original in text.expandtabs(4).splitlines():
        line, used = "", 0
        for char in original:
            if not char.isprintable():
                continue
            cells = _cells(char)
            if line and used + cells > max(1, width):
                lines.append(line)
                line, used = "", 0
            line += char
            used += cells
        lines.append(line)
    return lines
