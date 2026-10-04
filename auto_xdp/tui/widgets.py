"""Small shared curses primitives; all rendering clips to its own window."""
from __future__ import annotations

import curses
import unicodedata
from typing import Any

_CP_GREEN = 2
_CP_RED = 3
_CP_YELLOW = 4
_CP_BLACK_ON_GREEN = 5
_CP_BLACK_ON_YELLOW = 6
_CP_WHITE_ON_RED = 7
_CP_CYAN = 8
_CP_BLACK_ON_CYAN = 9


def _clip(text: str, width: int) -> str:
    remaining = max(0, width - 1)
    result = []
    for char in text:
        if not char.isprintable():
            continue
        cells = 0 if unicodedata.combining(char) else 2 if unicodedata.east_asian_width(char) in {"W", "F"} else 1
        if cells > remaining:
            break
        result.append(char)
        remaining -= cells
    return "".join(result)


def _add(win: Any, y: int, x: int, text: str, attr: int = 0) -> None:
    h, w = win.getmaxyx()
    if 0 <= y < h and 0 <= x < w:
        try:
            win.addstr(y, x, _clip(text, w - x), attr)
        except curses.error:
            pass


def _box(win: Any, title: str) -> None:
    h, w = win.getmaxyx()
    if h >= 2 and w >= 2:
        win.box()
        _add(win, 0, 2, _clip(f" {title} ", w - 4), curses.A_BOLD)
