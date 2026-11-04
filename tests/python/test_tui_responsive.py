"""Fluid columns and terminal resize contracts, including real input state."""
import curses
from unittest import mock

import pytest

from auto_xdp.tui import app
from auto_xdp.tui.dashboard import page_tabs
from auto_xdp.tui.layout import wrap_cells
from auto_xdp.tui.maps import _cells
from auto_xdp.telemetry.relay_client import RelayClient
from test_tui_dashboard import Canvas, _snapshot


@pytest.mark.parametrize("width", [80, 110, 180, 280, 360])
@pytest.mark.parametrize("page,header_y", [("events", 3), ("cookie", 6), ("traffic", 3),
                                         ("audit", 3), ("approvals", 3), ("maps", 3)])
def test_every_table_distributes_columns_across_actual_terminal_width(width, page, header_y):
    screen = Canvas(50, width)
    snap = _snapshot()
    snap.stats = [("SYN_COOKIE_HANDOFF_SUCCESS", 123456, -1, "123 pps")]
    snap.audit_rows = [dict(action="allow", protocol="tcp", bind_scope="exact", address="2001:db8::1", port=443,
                            zone="public", subject="web", attribution="process", reason="reason_" * 80)]
    snap.approval_rows = [dict(id=1234, status="pending", protocol="tcp", subject="web", zone="public",
                               ports=[443, 8443], reason="reason_" * 80)]
    relay = RelayClient("/unused")
    relay._append(dict(src="2001:db8::1234", sport=12345, dport=443, proto="TCP", verdict="DROP", pkt_len=60,
                       reason="reason_" * 80))
    with mock.patch("curses.color_pair", side_effect=lambda pair: pair << 8):
        app._draw(screen, snap, relay, "", 0, 0, "ports", {}, app._make_win_set(screen), "all", page=page)
    header = next(text for y, x, text, _ in screen.calls if y == header_y and x == 2)
    assert _cells(header) == width - 4
    # Numeric / final data fields reach the right side rather than stopping
    # at the former fixed 70-120-column layout.
    data_y = {"events": 4, "cookie": 7, "traffic": 4, "audit": 4, "approvals": 4, "maps": 4}[page]
    data = next(text for y, x, text, _ in screen.calls if y == data_y and x == 2)
    assert _cells(data) == width - 4
    if page != "maps":
        assert _cells(data.rstrip()) >= width - 6


@pytest.mark.parametrize("width", [80, 140, 280, 360])
def test_navigation_stays_compact_and_keeps_all_pages_clickable(width):
    tabs = page_tabs(width)
    assert tabs[0][0] == 1
    assert tabs[-1][0] + len(tabs[-1][1]) <= min(width - 1, 88)
    assert len(tabs) == 8
    assert all(text == f" {text.strip()} " for _, text, _ in tabs)
    for (x, text, _), (next_x, _, _) in zip(tabs, tabs[1:]):
        assert x + len(text) == next_x


@pytest.mark.parametrize("width", [80, 140, 280, 360])
def test_socket_only_event_history_also_uses_terminal_width(width):
    screen = Canvas(30, width)
    relay = RelayClient("/unused")
    relay._append(dict(type="port_change", action="close", proto="tcp", family=6, port=22, session_id="session", seq=1))
    with mock.patch("curses.color_pair", return_value=0):
        app._draw_events(screen, relay, _snapshot(), 0, False)
    header = next(text for y, x, text, _ in screen.calls if y == 1 and x == 2)
    data = next(text for y, x, text, _ in screen.calls if y == 2 and x == 2)
    assert _cells(header) == width - 4 and _cells(data) == width - 4
    assert "TCP6" in data


def test_overview_panels_grow_with_both_dimensions():
    wins = app._make_win_set(Canvas(90, 320))
    assert wins.system.getmaxyx()[1] > 56
    assert wins.network.getmaxyx()[0] > 13
    assert wins.system.getmaxyx()[0] > 13


def test_diagnostic_wrapping_preserves_all_wide_characters_and_indentation():
    value = "    文件编译失败 " * 100 + " END"
    lines = wrap_cells(value, 75)
    assert all(_cells(line) <= 75 for line in lines)
    assert "".join(lines) == value


@pytest.mark.parametrize("home,end", [(curses.KEY_HOME, curses.KEY_END), ("\x01", "\x05")])
def test_input_survives_terminal_resizing_without_losing_unicode_or_long_paths(monkeypatch, home, end):
    initial = "/路径/" + "long-directory/" * 20
    keys = iter([*initial, (80, 20), (280, 70), curses.KEY_LEFT, curses.KEY_BACKSPACE,
                 home, end, "x", (120, 24), "\n"])
    class InputScreen(Canvas):
        def nodelay(self, value):
            pass
        def timeout(self, value):
            self.delay = value
        def getdelay(self):
            return 200
        def move(self, y, x):
            assert 0 <= y < self.h and 0 <= x < self.w
        def clearok(self, value):
            pass
        def get_wch(self):
            key = next(keys)
            if isinstance(key, tuple):
                self.w, self.h = key
                return curses.KEY_RESIZE
            return key
    monkeypatch.setattr(curses, "noecho", lambda: None)
    monkeypatch.setattr(curses, "curs_set", lambda value: None)
    monkeypatch.setattr(curses, "mousemask", lambda value: (0, 0))
    screen = InputScreen(42, 140)
    assert app._tui_prompt(screen, "Source path:") == initial[:-2] + initial[-1] + "x"
    assert screen.delay == 200
