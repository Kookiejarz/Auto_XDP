import curses
from types import SimpleNamespace
import unicodedata
from unittest import mock

import pytest

from auto_xdp.telemetry.relay_client import RelayClient
from auto_xdp.tui.app import (
    MapUsage, TuiSnapshot, _draw, _draw_maps, _draw_ports, _initial_tui_page, _make_win_set,
)
from auto_xdp.tui.metrics import HostMetrics, NetworkMetrics, ResourceSampler
from auto_xdp.tui.traffic import _draw_events, _event_bottom_top, _resize_event_top
from auto_xdp.tui.traffic import _event_capacity, _events_suppressed
from auto_xdp.tui.mouse import _mouse_action, _port_window_start, _enable_mouse, _disable_mouse
from auto_xdp.tui.services import EventServices


class Canvas:
    """A strict terminal grid: unlike curses, clipping errors fail the test."""
    def __init__(self, h, w, *, root=None, y=0, x=0):
        self.h, self.w, self.y, self.x = h, w, y, x
        self.root = root or self
        if root is None:
            self.calls = []
            self.rects = []

    def getmaxyx(self):
        return self.h, self.w

    def getbegyx(self):
        return self.y, self.x

    def derwin(self, h, w, y, x):
        assert h > 0 and w > 0
        assert 0 <= y and y + h <= self.h
        assert 0 <= x and x + w <= self.w
        self.root.rects.append((self.y + y, self.x + x, h, w))
        return Canvas(h, w, root=self.root, y=self.y + y, x=self.x + x)

    def addstr(self, y, x, text, attr=0):
        cells = sum(0 if unicodedata.combining(c) else 2 if unicodedata.east_asian_width(c) in {"W", "F"} else 1 for c in text)
        assert 0 <= y < self.h and 0 <= x < self.w
        assert x + cells <= self.w, (self.h, self.w, y, x, text)
        assert all(c.isprintable() for c in text)
        self.root.calls.append((self.y + y, self.x + x, text, attr))

    def border(self, *args):
        pass

    def box(self):
        pass

    def refresh(self):
        pass

    def erase(self):
        self.root.calls.clear()


def _snapshot():
    return TuiSnapshot(
        backend="xdp", iface="enp1s0", attach_mode="xdp native", attach_target="enp1s0",
        attach_targets=[("enp1s0", "xdp native")], status="updated 12:34:56",
        rates={"XDP_TOTAL": (1500000, None), "XDP_DROP_TOTAL": (1400000, None)},
        host=HostMetrics("perf", 72.5, tuple((str(i), 20 + i * 10) for i in range(8)),
                         8 * 1024**3, 32 * 1024**3, (2.3, 1.9, 1.2), 90000),
        network=NetworkMetrics(
            iface="enp1s0", rx_bytes=10**10, tx_bytes=10**9,
            rx_bytes_rate=10**8, tx_bytes_rate=10**7, rx_packets_rate=1500000,
            tx_packets_rate=12000, speed_mbps=10000,
            rx_history=tuple([None, 10**6, 10**7, 10**8] * 40),
            tx_history=tuple([0, 10**5, 10**6, 10**7] * 40),
        ),
        ports=[("TCP", port, "https", "server", "syn 100/s") for port in range(443, 460)],
        maps=[MapUsage("tcp_port_policies", "hash", 10, 100, 10.0, map_id=4, memlock=4096)],
    )


@pytest.mark.parametrize("width,height", [(80, 20), (80, 24), (100, 30), (140, 42), (200, 50)])
@pytest.mark.parametrize("page", ["overview", "maps", "events", "traffic", "cookie", "audit", "approvals"])
def test_all_pages_fit_supported_terminal_sizes(width, height, page):
    screen = Canvas(height, width)
    snap = _snapshot()
    relay = RelayClient("/unused", max_events=3)
    relay._append({"src": "2001:db8::1", "sport": 12345, "dport": 443,
                   "proto": "TCP", "verdict": "DROP", "reason": "TCP_DROP"})
    wins = _make_win_set(screen)
    with mock.patch("curses.color_pair", side_effect=lambda pair: pair << 8):
        _draw(screen, snap, relay, "", 0, 0, "ports", {}, wins, "all", page=page)
    rendered = "\n".join(call[2] for call in screen.calls)
    assert "AUTO XDP" in rendered
    if page == "maps":
        for column in ("type", "used", "max", "memory"):
            assert column in rendered
    if page == "overview":
        for title in ("Network", "Protection", "Host resources", "Recent events", "BPF maps"):
            assert title in rendered
        assert len(screen.rects) == 6
        for index, (y, x, h, w) in enumerate(screen.rects):
            assert y >= 2 and y + h <= height - 1
            for other_y, other_x, other_h, other_w in screen.rects[index + 1:]:
                assert y + h <= other_y or other_y + other_h <= y or x + w <= other_x or other_x + other_w <= x


def test_small_terminal_shows_resize_message():
    screen = Canvas(12, 45)
    relay = RelayClient("/unused")
    _draw(screen, TuiSnapshot(), relay, "", 0, 0, "ports", {}, None, "all")
    assert any("80x20" in call[2] for call in screen.calls)


def test_map_fixed_capacity_is_not_a_pressure_alarm():
    screen = Canvas(8, 45)
    rows = [MapUsage("pkt_counters", "percpu_array", 66, 66, 100.0)]
    with mock.patch("curses.color_pair", side_effect=lambda pair: pair << 8):
        _draw_maps(screen, rows, 0, False)
    body = [call for call in screen.calls if call[0] == 2 and "pkt_counters" in call[2]]
    assert body and "fixed" in body[0][2]
    assert body[0][3] == curses.A_NORMAL


@pytest.mark.parametrize("width", [80, 96, 99, 100, 119, 120, 140, 179, 180, 200, 280])
def test_maps_table_uses_available_width_without_losing_numeric_columns(width):
    screen = Canvas(12, width)
    rows = [MapUsage("large_connection_tracking_map_v6", "lru_percpu_hash", 2147483647,
                     4294967295, 50.0, "cached", map_id=1234567, memlock=8 * 1024**3)]
    _draw_maps(screen, rows, 0, True, expanded=True)
    line = next(text for y, x, text, _ in screen.calls if y == 2 and x == 2)
    cells = sum(0 if unicodedata.combining(c) else 2 if unicodedata.east_asian_width(c) in {"W", "F"} else 1 for c in line)
    assert cells == width - 4
    assert "~2147483647" in line and "4294967295" in line
    assert "50.0%" in line and "8.00 GiB" in line
    header = next(text for y, x, text, _ in screen.calls if y == 1 and x == 2)
    assert all(column in header.split() for column in ("map", "type", "used", "max", "usage", "memory"))
    if width >= 140:
        assert "large_connection_tracking_map_v6" in line
        assert "lru_percpu_hash" in line
        assert "1234567" in line
        assert "count source" in header and "cached" in line
    if width == 80:
        assert "id" not in header.split() and "count source" not in header


def test_wide_maps_show_usage_bars_and_preserve_skip_and_fixed_meanings():
    screen = Canvas(12, 160)
    rows = [MapUsage("tracked_connections", "hash", 90, 100, 90.0, "sampled"),
            MapUsage("pkt_counters", "percpu_array", 66, 66, 100.0, "array"),
            MapUsage("udp_hv4", "lru_hash", None, 49152, None, "attack skip"),
            MapUsage("pkt_ringbuf", "ringbuf", None, 262144, None)]
    with mock.patch("curses.color_pair", side_effect=lambda pair: pair << 8):
        _draw_maps(screen, rows, 0, True, expanded=True)
    assert any(y == 2 and "━" in text for y, _, text, _ in screen.calls)
    assert not any(y in {3, 4, 5} and "━" in text for y, _, text, _ in screen.calls)
    fixed = next(call for call in screen.calls if call[0] == 3 and "pkt_counters" in call[2])
    skipped = next(call[2] for call in screen.calls if call[0] == 4 and "udp_hv4" in call[2])
    assert "fixed" in fixed[2] and fixed[3] == curses.A_NORMAL
    assert "skip" in skipped and "skipped (attack)" in skipped
    ringbuf = next(call[2] for call in screen.calls if call[0] == 5 and "pkt_ringbuf" in call[2])
    assert "not counted" in ringbuf and "fixed" not in ringbuf


@pytest.mark.parametrize("width", [30, 45, 56])
def test_overview_map_panel_expands_names_and_marks_truncation(width):
    screen = Canvas(8, width)
    name = "connection_tracking_pending_ipv6"
    _draw_maps(screen, [MapUsage(name, "lru_hash", None, 49152, None, "attack skip")], 0, False)
    line = next(text for y, x, text, _ in screen.calls if y == 2 and x == 2)
    assert "skip/49k" in line
    if width == 56:
        assert name in line
    else:
        assert "…" in line


def test_map_names_with_wide_characters_do_not_shift_numeric_columns():
    screen = Canvas(8, 140)
    _draw_maps(screen, [MapUsage("地图_" * 12, "hash", 12, 100, 12.0)], 0, False, expanded=True)
    line = next(text for y, x, text, _ in screen.calls if y == 2 and x == 2)
    cells = sum(0 if unicodedata.combining(c) else 2 if unicodedata.east_asian_width(c) in {"W", "F"} else 1 for c in line)
    assert cells == 136
    assert "12.0%" in line and "100" in line


def test_port_selection_scrolls_into_view_and_filter_is_applied():
    screen = Canvas(7, 80)
    rows = [("TCP", i, "service", "worker", "-") for i in range(20)]
    rows.append(("UDP", 53, "domain", "named", "-"))
    _draw_ports(screen, rows, {}, "TCP", cursor=18, focused=True)
    body = [call[2] for call in screen.calls if 2 <= call[0] < 6]
    assert any("   18" in line for line in body)
    assert not any("UDP" in line for line in body)
    selected = [call for call in screen.calls if 2 <= call[0] < 6 and call[3] & curses.A_BOLD]
    assert selected and "   18" in selected[0][2]


def test_opening_dashboard_does_not_mark_unseen_audit_as_reviewed(tmp_path):
    args = SimpleNamespace(config=str(tmp_path / "missing.toml"), run_state_dir=str(tmp_path))
    assert _initial_tui_page(args) == "overview"
    assert not (tmp_path / "axdp_audit_tui.json").exists()


@pytest.mark.parametrize("old_visible,visible", [(10, 1), (1, 10), (10, 18), (18, 4)])
def test_resizing_or_switching_pages_preserves_live_event_tail(old_visible, visible):
    relay = RelayClient("/unused", max_events=40)
    for index in range(55):
        relay._append({"id": index})
    top = _event_bottom_top(relay, old_visible)
    assert _resize_event_top(relay, old_visible, visible, top) == _event_bottom_top(relay, visible)


def test_resizing_preserves_manual_event_scroll_within_retained_history():
    relay = RelayClient("/unused", max_events=40)
    for index in range(55):
        relay._append({"id": index})
    assert _resize_event_top(relay, 10, 1, 30) == 30
    assert _resize_event_top(relay, 10, 18, 30) == 30
    assert _resize_event_top(relay, 10, 18, 0) == relay.events_offset


@pytest.mark.parametrize("follow,label", [(False, "PAUSED"), (True, "LIVE")])
def test_event_suppression_keeps_live_or_paused_state_visible(follow, label):
    relay = RelayClient("/unused")
    for _ in range(30):
        relay._append({"type": "port_change", "proto": "tcp", "port": 22})
    screen = Canvas(6, 49)
    visible = _event_capacity(6, compact=True, suppressed=True, port_only=True)
    top = _event_bottom_top(relay, visible) if follow else 0
    _draw_events(screen, relay, TuiSnapshot(under_attack=True, packet_events_enabled=False), top, False, compact=True)
    footer = "".join(text for y, _, text, _ in screen.calls if y == 5)
    assert label in footer and "packet records OFF" in footer
    assert any("under_attack=true" in text for y, _, text, _ in screen.calls if y == 1)


@pytest.mark.parametrize("configured,enabled,suppressed", [(True, True, False), (False, False, True), (True, None, True)])
def test_packet_recording_uses_runtime_flag_before_config(configured, enabled, suppressed):
    snap = TuiSnapshot(under_attack=configured, packet_events_enabled=enabled)
    assert _events_suppressed(snap) == suppressed


def test_socket_notices_are_dense_and_packet_recording_reason_is_visible():
    relay = RelayClient("/unused")
    for _ in range(3):
        relay._append({"type": "port_change", "action": "close", "proto": "tcp", "port": 22})
    screen = Canvas(14, 90)
    _draw_events(screen, relay, TuiSnapshot(under_attack=True, packet_events_enabled=False), 0, False)
    rendered = "\n".join(text for _, _, text, _ in screen.calls)
    assert "Packet records OFF" in rendered and "axdp under-attack off" in rendered
    assert "SOCKET STATE NOTIFICATIONS" in rendered
    assert [y for y, _, text, _ in screen.calls if "SOCKET close" in text] == [4, 5, 6]


def _service_snapshot():
    return TuiSnapshot(
        ports=[("TCP", 22, "ssh", "sshd", "-"), ("UDP", 53, "domain", "resolver", "-")],
        audit_rows=[
            dict(protocol="tcp", port=22, address="0.0.0.0", subject="ssh", attribution="exact"),
            dict(protocol="tcp", port=22, address="::", subject="ssh", attribution="exact"),
            dict(protocol="tcp", port=8080, address="192.0.2.1", subject="web-a", attribution="shared"),
            dict(protocol="tcp", port=8080, address="192.0.2.2", subject="web-b", attribution="shared"),
            dict(protocol="tcp", port=8081, address="::1", subject="v6-only", attribution="exact"),
            dict(protocol="tcp", port=8082, address="0.0.0.0", subject="unknown", attribution="ambiguous"),
        ],
    )


@pytest.mark.parametrize("event,label", [
    (dict(proto="TCP", dport=22, dst="192.0.2.100"), "ssh"),
    (dict(proto="tcp", dport="22", dst="2001:db8::100"), "ssh"),
    (dict(proto="TCP", dport=22, dst="::ffff:192.0.2.100"), "ssh"),
    (dict(type="port_change", proto="tcp", port=22), "ssh"),
    (dict(proto="UDP", dport=22), "unknown"),
    (dict(proto="UDP", dport=53), "port:domain"),
    (dict(proto="TCP", dport=8080, dst="192.0.2.1"), "web-a"),
    (dict(proto="TCP", dport=8080, dst="192.0.2.2"), "web-b"),
    (dict(proto="TCP", dport=8080, dst="192.0.2.3"), "unknown"),
    (dict(type="port_change", proto="tcp", port=8080), "ambiguous"),
    (dict(proto="TCP", dport=8081, dst="127.0.0.1"), "unknown"),
    (dict(proto="TCP", dport=8082, dst="192.0.2.1"), "unknown"),
    (dict(proto="TCP", sport=22, dport=54321), "unknown"),
    (dict(proto="ICMP", dport=22), "-"),
    (dict(proto="TCP", dport=True), "-"),
    (dict(proto="TCP", dport=22.5), "-"),
    (dict(proto="TCP", dport=0), "-"),
])
def test_event_service_matches_destination_without_inventing_ownership(event, label):
    assert EventServices(_service_snapshot()).label(event) == label


def test_colliding_wildcard_and_address_specific_owners_are_ambiguous():
    snap = _service_snapshot()
    snap.audit_rows.append(dict(protocol="tcp", port=22, address="192.0.2.1",
                                subject="other-service", attribution="shared"))
    services = EventServices(snap)
    assert services.label(dict(proto="TCP", dport=22, dst="192.0.2.1")) == "ambiguous"
    assert services.label(dict(proto="TCP", dport=22, dst="192.0.2.2")) == "ssh"


@pytest.mark.parametrize("compact,width", [(True, 49), (True, 92), (False, 80), (False, 140)])
def test_packet_recording_on_renders_current_service_in_both_event_views(compact, width):
    relay = RelayClient("/unused")
    relay._append(dict(proto="TCP", src="198.51.100.1", sport=54321, dst="192.0.2.1",
                       dport=22, verdict="ALLOW", reason="TCP_NEW_ALLOW", ifindex=3, pkt_len=60))
    snap = _service_snapshot()
    snap.packet_events_enabled = True
    screen = Canvas(12, width)
    with mock.patch("curses.color_pair", return_value=0):
        _draw_events(screen, relay, snap, 0, False, compact=compact)
    rendered = "\n".join(text for _, _, text, _ in screen.calls)
    assert "SERVICE" in rendered if compact else "service" in rendered
    assert "ssh" in rendered
    assert "records OFF" not in rendered
    if not compact:
        assert "dst=192.0.2.1" in rendered
        assert "service(current)=ssh" in rendered
        assert "if=3 len=60" in rendered


def test_socket_service_inventory_is_visible_even_when_packets_are_suppressed():
    snap = _service_snapshot()
    snap.packet_events_enabled = False
    relay = RelayClient("/unused")
    relay._append(dict(type="port_change", proto="tcp", port=22, action="open"))
    screen = Canvas(12, 90)
    _draw_events(screen, relay, snap, 0, False)
    rendered = "\n".join(text for _, _, text, _ in screen.calls)
    assert "Packet records OFF" in rendered
    assert "svc=ssh" in rendered


@pytest.mark.parametrize("x,target", [(7, "overview"), (18, "traffic"), (29, "events"),
                                      (39, "cookie"), (48, "maps"), (56, "audit"), (67, "approvals")])
@pytest.mark.parametrize("width,height", [(80, 20), (140, 42)])
def test_clickable_tabs_match_visible_header(x, target, width, height):
    screen = Canvas(height, width)
    action = _mouse_action(screen, _make_win_set(screen), target, x, 1, curses.BUTTON1_CLICKED)
    assert action is not None and action.kind == "page" and action.target == target


@pytest.mark.parametrize("target", ["ports", "maps", "events"])
def test_mouse_focus_and_wheel_target_the_panel_under_pointer(target):
    screen = Canvas(42, 140)
    wins = _make_win_set(screen)
    win = getattr(wins, target)
    y, x = win.getbegyx()
    action = _mouse_action(screen, wins, "overview", x + 3, y + 2, curses.BUTTON1_CLICKED)
    assert action is not None and action.target == target
    wheel = _mouse_action(screen, wins, "overview", x + 3, y + 2, curses.BUTTON4_PRESSED)
    assert wheel is not None and wheel.kind == "scroll" and wheel.target == target
    assert wheel.key == curses.KEY_UP


def test_double_click_port_opens_events_and_scrolled_row_offset_is_stable():
    screen = Canvas(24, 80)
    wins = _make_win_set(screen)
    y, x = wins.ports.getbegyx()
    action = _mouse_action(screen, wins, "overview", x + 2, y + 3, curses.BUTTON1_DOUBLE_CLICKED)
    assert action is not None and action.kind == "port_events" and action.index == 1
    assert _port_window_start(18, 20, 4) + action.index == 16


def test_mouse_ignores_releases_outside_content_and_small_terminals():
    screen = Canvas(24, 80)
    wins = _make_win_set(screen)
    assert _mouse_action(screen, wins, "overview", 7, 1, curses.BUTTON1_RELEASED) is None
    assert _mouse_action(screen, wins, "overview", 80, 1, curses.BUTTON1_CLICKED) is None
    assert _mouse_action(Canvas(12, 45), None, "overview", 7, 1, curses.BUTTON1_CLICKED) is None


def test_terminal_without_mouse_keeps_keyboard_available():
    with mock.patch("curses.mousemask", side_effect=curses.error):
        assert _enable_mouse() is False


def test_releasing_mouse_clears_terminal_reporting_and_reports_failure():
    with mock.patch("curses.mousemask", return_value=(0, curses.ALL_MOUSE_EVENTS)) as mask:
        assert _disable_mouse() is True
        mask.assert_called_once_with(0)
    with mock.patch("curses.mousemask", side_effect=curses.error):
        assert _disable_mouse() is False


@pytest.fixture
def mouse_main(monkeypatch, tmp_path):
    from auto_xdp.tui import app

    def run(snap, clicks=(), initial="overview", *, keys_override=None, mouse_available=True,
            poll_callback=None):
        class Screen(Canvas):
            def bkgd(self, *args):
                pass

            def nodelay(self, *args):
                pass

            def timeout(self, *args):
                pass

            def clear(self):
                self.erase()

            def getch(self):
                return next(keys)

        keys = iter((list(keys_override) if keys_override is not None
                     else [curses.KEY_MOUSE] * len(clicks)) + [ord("q")])
        events = iter(clicks)
        worker, resolver, draw = mock.Mock(), mock.Mock(), mock.Mock()
        worker.get.return_value = (snap, "")
        relay = RelayClient("/unused")
        monkeypatch.setattr(relay, "poll", mock.Mock(
            side_effect=(lambda: poll_callback(relay)) if poll_callback is not None else None))
        monkeypatch.setattr(app, "RelayClient", lambda *args, **kwargs: relay)
        monkeypatch.setattr(app, "SnapshotWorker", lambda args: worker)
        monkeypatch.setattr(app.GeoIPResolver, "from_config", lambda config: resolver)
        monkeypatch.setattr(app, "_init_colors", lambda: None)
        enable_mouse = mock.Mock(return_value=mouse_available)
        disable_mouse = mock.Mock(return_value=True)
        monkeypatch.setattr(app, "_enable_mouse", enable_mouse)
        monkeypatch.setattr(app, "_disable_mouse", disable_mouse)
        monkeypatch.setattr(app, "_initial_tui_page", lambda args: initial)
        monkeypatch.setattr(app.curses, "curs_set", lambda value: None)
        monkeypatch.setattr(app.curses, "getmouse", lambda: next(events))
        monkeypatch.setattr(app, "_draw", draw)
        args = SimpleNamespace(config=str(tmp_path / "config.toml"), run_state_dir=str(tmp_path),
                               socket="/unused", tui_max_events=500)
        assert app._curses_main(Screen(42, 140), args) == 0
        draw.worker, draw.relay = worker, relay
        draw.enable_mouse, draw.disable_mouse = enable_mouse, disable_mouse
        return draw

    return run


def test_copy_mode_freezes_display_drains_relay_and_restores_clicks(mouse_main):
    draw = mouse_main(TuiSnapshot(), [(0, 29, 1, 0, curses.BUTTON1_CLICKED)],
                      keys_override=[-1, curses.KEY_F2, -1, ord("e"), curses.KEY_DOWN,
                                     -1, curses.KEY_F2, curses.KEY_MOUSE])
    assert [call.args[10] for call in draw.call_args_list] == ["overview", "overview", "overview", "events"]
    assert [call.args[18] for call in draw.call_args_list] == [True, False, True, True]
    assert draw.relay.poll.call_count == 8
    assert draw.worker.get.call_count == 4
    assert draw.enable_mouse.call_count == 2
    assert draw.disable_mouse.call_count == 2  # enter copy mode, then exit cleanup
    draw.worker.stop.assert_called_once_with()


def test_copy_mode_preserves_mouse_disabled_on_unsupported_terminal(mouse_main):
    draw = mouse_main(TuiSnapshot(), keys_override=[-1, curses.KEY_F2, -1, curses.KEY_F2],
                      mouse_available=False)
    assert [call.args[18] for call in draw.call_args_list] == [False, False, False]
    draw.enable_mouse.assert_called_once_with()


def test_copy_mode_resumes_live_tail_after_events_arrive_while_paused(mouse_main):
    def packets(relay):
        for _ in range(50):
            relay._append(dict(proto="TCP", dport=22, verdict="ALLOW", reason="TCP_NEW_ALLOW"))
    draw = mouse_main(TuiSnapshot(), poll_callback=packets,
                      keys_override=[ord("e"), curses.KEY_F2, -1, -1, curses.KEY_F2])
    assert draw.call_count == 3
    visible = _event_capacity(39)
    assert draw.call_args.args[5] == _event_bottom_top(draw.relay, visible)


def test_copy_mode_keeps_manual_event_scroll_when_resuming(mouse_main):
    def packets(relay):
        for _ in range(50):
            relay._append(dict(proto="TCP", dport=22, verdict="ALLOW", reason="TCP_NEW_ALLOW"))
    draw = mouse_main(TuiSnapshot(), poll_callback=packets,
                      keys_override=[ord("e"), curses.KEY_UP, curses.KEY_F2, -1, curses.KEY_F2])
    assert draw.call_args.args[5] < _event_bottom_top(draw.relay, _event_capacity(39))


def test_copy_mode_ignores_approval_actions_and_quit_still_works(mouse_main, monkeypatch):
    from auto_xdp.admin import approvals
    mutations = []
    for name in ("approve_request", "reject_request", "revoke_request", "create_request", "reload_daemon"):
        action = mock.Mock()
        monkeypatch.setattr(approvals, name, action)
        mutations.append(action)
    draw = mouse_main(TuiSnapshot(approval_rows=[{"id": 7, "status": "pending"}]),
                      initial="approvals",
                      keys_override=[curses.KEY_F2, 10, ord("d"), ord("x"), ord("n"), -1])
    assert draw.call_count == 1
    assert draw.relay.poll.call_count == 6
    for action in mutations:
        action.assert_not_called()
    draw.worker.stop.assert_called_once_with()


@pytest.mark.parametrize("state", [curses.BUTTON1_CLICKED, curses.BUTTON1_DOUBLE_CLICKED])
def test_mouse_can_select_approval_but_never_approve_or_revoke(mouse_main, monkeypatch, state):
    from auto_xdp.admin import approvals
    mutations = []
    for name in ("approve_request", "reject_request", "revoke_request", "create_request", "reload_daemon"):
        action = mock.Mock()
        monkeypatch.setattr(approvals, name, action)
        mutations.append(action)
    snap = TuiSnapshot(approval_rows=[{"id": 7, "status": "pending"}])
    draw = mouse_main(snap, [(0, 5, 4, 0, state)], initial="approvals")
    assert draw.call_args.args[16] == 0
    for action in mutations:
        action.assert_not_called()


def test_clicking_current_tab_does_not_toggle_to_overview(mouse_main):
    clicks = [(0, 29, 1, 0, curses.BUTTON1_CLICKED)] * 2
    draw = mouse_main(TuiSnapshot(), clicks, initial="events")
    assert [call.args[10] for call in draw.call_args_list] == ["events", "events"]


def test_double_click_port_filters_full_events_page(mouse_main):
    screen = Canvas(42, 140)
    wins = _make_win_set(screen)
    y, x = wins.ports.getbegyx()
    draw = mouse_main(_snapshot(), [(0, x + 3, y + 2, 0, curses.BUTTON1_DOUBLE_CLICKED),
                                   (0, 10, 2, 0, curses.BUTTON1_CLICKED)])
    assert [call.args[10] for call in draw.call_args_list] == ["events", "events"]
    assert [call.args[13] for call in draw.call_args_list] == [443, None]


@pytest.mark.skipif(not hasattr(curses, "BUTTON5_PRESSED"), reason="terminal build has no wheel-down constant")
def test_mouse_wheel_scrolls_full_maps_page(mouse_main):
    snap = TuiSnapshot(maps=[MapUsage(str(i), "hash", 0, 10, 0.0) for i in range(100)])
    draw = mouse_main(snap, [(0, 5, 5, 0, curses.BUTTON5_PRESSED)], initial="maps")
    assert draw.call_args.args[4] == 3


def _proc_fixture(root, *, user=100, idle=100, available=256):
    root.mkdir(exist_ok=True)
    (root / "stat").write_text(f"cpu {user} 0 0 {idle} 0 0 0 0 999 999\ncpu0 {user} 0 0 {idle} 0 0 0 0\n")
    (root / "meminfo").write_text(f"MemTotal: 1024 kB\nMemAvailable: {available} kB\n")
    (root / "loadavg").write_text("1.0 2.0 3.0 1/10 123\n")
    (root / "uptime").write_text("90000.0 100000.0\n")


def _network_fixture(root, *, index=2, values=(1000, 2000, 10, 20)):
    path = root / "eth0"
    (path / "statistics").mkdir(parents=True, exist_ok=True)
    (path / "ifindex").write_text(str(index))
    (path / "speed").write_text("10000")
    for name, value in zip(("rx_bytes", "tx_bytes", "rx_packets", "tx_packets"), values):
        (path / "statistics" / name).write_text(str(value))


def test_resource_sampling_uses_deltas_and_memavailable(tmp_path):
    proc, net = tmp_path / "proc", tmp_path / "net"
    _proc_fixture(proc)
    _network_fixture(net)
    sampler = ResourceSampler(proc, net)
    first, network = sampler.sample("eth0", 10)
    assert first.cpu_percent is None and network.rx_bytes_rate is None
    assert first.memory_used == 768 * 1024
    _proc_fixture(proc, user=130, idle=170)
    _network_fixture(net, values=(3000, 2600, 14, 24))
    host, network = sampler.sample("eth0", 12)
    assert host.cpu_percent == 30
    assert host.cores == (("0", 30),)
    assert network.rx_bytes_rate == 1000
    assert network.tx_bytes_rate == 300
    assert network.rx_packets_rate == 2
    assert network.speed_mbps == 10000


def test_counter_reset_and_interface_replacement_do_not_spike_graph(tmp_path):
    proc, net = tmp_path / "proc", tmp_path / "net"
    _proc_fixture(proc)
    _network_fixture(net)
    sampler = ResourceSampler(proc, net)
    sampler.sample("eth0", 1)
    _network_fixture(net, values=(3000, 3000, 30, 30))
    sampler.sample("eth0", 2)
    _network_fixture(net, values=(100, 100, 1, 1))
    _, network = sampler.sample("eth0", 3)
    assert network.rx_bytes_rate is None
    assert network.rx_history == (None,)
    _network_fixture(net, index=3, values=(10000000, 10000000, 1000, 1000))
    _, network = sampler.sample("eth0", 4)
    assert network.rx_bytes_rate is None and network.rx_history == (None,)


def test_unavailable_metrics_are_unknown_and_history_is_bounded(tmp_path):
    sampler = ResourceSampler(tmp_path / "missing", tmp_path / "net")
    host, network = sampler.sample("eth0", 1)
    assert host.cpu_percent is None and host.memory_used is None
    assert network.rx_bytes_rate is None and network.rx_bytes is None
    _network_fixture(tmp_path / "net")
    for tick in range(2, 270):
        _, network = sampler.sample("eth0", tick)
    assert len(network.rx_history) == 240
    assert len(network.tx_history) == 240
