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
_CP_BORDER = 10
_CP_MUTED = 11
_CP_BLUE = 12
_CP_TEXT = 13
_CP_SELECTED = 14
_CP_GRAPH_RX = 15
_CP_GRAPH_TX = 16
_CP_FOCUS = 17


def _color(pair: int) -> int:
    try:
        return curses.color_pair(pair)
    except curses.error:
        return curses.A_NORMAL


def _init_colors() -> None:
    if not curses.has_colors():
        return
    curses.start_color()
    rich = curses.COLORS >= 256
    # Explicit backgrounds keep text readable with either light or dark
    # terminal defaults. Large charts use quieter colors than their labels.
    background = 234 if rich else curses.COLOR_BLACK
    text = 252 if rich else curses.COLOR_WHITE
    surface = 238 if rich else curses.COLOR_BLUE
    badge = 236 if rich else curses.COLOR_BLACK
    green, red, yellow, cyan, blue = (108, 174, 180, 109, 110) if rich else (
        curses.COLOR_GREEN, curses.COLOR_RED, curses.COLOR_YELLOW, curses.COLOR_CYAN, curses.COLOR_BLUE,
    )
    pairs = {
        _CP_GREEN: (green, background), _CP_RED: (red, background),
        _CP_YELLOW: (yellow, background), _CP_CYAN: (cyan, background),
        _CP_BLACK_ON_GREEN: (green, badge),
        _CP_BLACK_ON_YELLOW: (yellow, badge),
        _CP_WHITE_ON_RED: (red, badge),
        _CP_BLACK_ON_CYAN: (cyan, badge),
        _CP_BORDER: (240 if rich else curses.COLOR_BLUE, background),
        _CP_MUTED: (248 if rich else curses.COLOR_WHITE, background),
        _CP_BLUE: (blue, background),
        _CP_TEXT: (text, background),
        _CP_SELECTED: (text, surface),
        _CP_GRAPH_RX: (66 if rich else curses.COLOR_CYAN, background),
        _CP_GRAPH_TX: (67 if rich else curses.COLOR_BLUE, background),
        _CP_FOCUS: (244 if rich else curses.COLOR_CYAN, background),
    }
    for pair, (foreground, back) in pairs.items():
        curses.init_pair(pair, foreground, back)


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


def _box(win: Any, title: str, *, focused: bool = False, accent: int = _CP_BORDER) -> None:
    h, w = win.getmaxyx()
    if hasattr(win, "bkgdset"):
        win.bkgdset(" ", _color(_CP_TEXT))
    if h >= 2 and w >= 2:
        color = _color(_CP_FOCUS if focused else _CP_BORDER)
        if not hasattr(win, "border"):
            win.box()
        else:
            try:
                win.addstr(0, 0, "╭" + "─" * (w - 2) + "╮", color)
                for row in range(1, h - 1):
                    win.addstr(row, 0, "│", color)
                    win.addstr(row, w - 1, "│", color)
                # ncurses can report an error after writing this last cell.
                win.addstr(h - 1, 0, "╰" + "─" * (w - 2) + "╯", color)
            except curses.error:
                pass
            except UnicodeError:
                win.box()
        title_color = _color(accent if accent != _CP_BORDER else _CP_TEXT)
        _add(win, 0, 2, _clip(f" {title} ", w - 4), title_color | (curses.A_BOLD if focused else 0))


def _meter(win: Any, y: int, x: int, width: int, value: float | None, color: int = _CP_GREEN) -> None:
    width = max(0, width)
    filled = round(width * max(0.0, min(100.0, value)) / 100) if value is not None else 0
    _add(win, y, x, "━" * filled, _color(color))
    _add(win, y, x + filled, "─" * (width - filled), _color(_CP_BORDER))
