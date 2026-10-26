"""Mouse hit testing; actions only navigate or select, never authorize policy."""
from __future__ import annotations

import curses
from dataclasses import dataclass
from typing import Any

from auto_xdp.tui.dashboard import _PAGES


@dataclass(frozen=True)
class MouseAction:
    kind: str
    target: str = ""
    index: int = -1
    key: int = -1


def _enable_mouse() -> bool:
    try:
        available, _ = curses.mousemask(curses.ALL_MOUSE_EVENTS)
        curses.mouseinterval(150)
        return bool(available)
    except curses.error:
        return False


def _disable_mouse() -> bool:
    try:
        curses.mousemask(0)
        return True
    except curses.error:
        return False


def _port_window_start(cursor: int, count: int, visible: int) -> int:
    return max(0, min(cursor - visible + 1, max(0, count - visible))) if cursor >= 0 else 0


def _mouse_action(screen: Any, wins: Any, page: str, x: int, y: int, state: int) -> MouseAction | None:
    height, width = screen.getmaxyx()
    if height < 20 or width < 80 or not (0 <= x < width and 0 <= y < height):
        return None
    click = bool(state & (curses.BUTTON1_CLICKED | curses.BUTTON1_DOUBLE_CLICKED))
    double = bool(state & curses.BUTTON1_DOUBLE_CLICKED)
    wheel_up = bool(state & curses.BUTTON4_PRESSED)
    wheel_down = bool(state & getattr(curses, "BUTTON5_PRESSED", 0))
    key = curses.KEY_UP if wheel_up else curses.KEY_DOWN
    if y == 1 and click:
        start = 1
        for shortcut, label, target in _PAGES:
            end = start + len(f" {shortcut} {label} ")
            if start <= x < min(end, width - 1):
                return MouseAction("page", target)
            start = end
    if page == "events" and y == 2 and click:
        return MouseAction("clear_filter")
    if page == "overview" and wins is not None:
        for target in ("maps", "events", "ports"):
            win = getattr(wins, target)
            top, left = win.getbegyx()
            h, w = win.getmaxyx()
            if not (left <= x < left + w and top <= y < top + h):
                continue
            if wheel_up or wheel_down:
                return MouseAction("scroll", target, key=key)
            if click:
                row = y - top
                if row == 0 and target in {"maps", "events"}:
                    return MouseAction("page", target)
                if target == "ports" and 2 <= row < h - 1:
                    return MouseAction("port_events" if double else "port", target, row - 2)
                return MouseAction("focus", target)
    elif 2 <= y < height - 1:
        if wheel_up or wheel_down:
            return MouseAction("scroll", page, key=key)
        if click and page == "approvals" and 4 <= y < height - 2:
            return MouseAction("approval", index=y - 4)
    return None
