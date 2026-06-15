import subprocess
import unittest
import tempfile
from pathlib import Path
from unittest import mock

from auto_xdp.tui import (
    MapUsageCache,
    RelayClient,
    TuiSnapshot,
    _collect_map_usage,
    _collect_port_rows,
    _collect_top_traffic,
    _draw_events,
    _draw_ports,
    _draw_summary,
    _draw_top_traffic,
    _dump_count,
    _event_bottom_top,
    _event_window,
    _filter_port_rows,
)


class DumpCountTests(unittest.TestCase):
    def _count(self, out: bytes) -> int | None:
        with mock.patch("auto_xdp.tui.subprocess.check_output", return_value=out):
            return _dump_count(Path("/sys/fs/bpf/xdp_fw/some_map"))

    def test_counts_plain_hash_entries(self):
        out = (
            b'[{"key":["0x50","0x00"],"value":["0x01"]},'
            b'{"key":["0x35","0x00"],"value":["0x01"]},'
            b'{"key":["0x16","0x00"],"value":["0x01"]}]'
        )
        self.assertEqual(self._count(out), 3)

    def test_counts_percpu_entries_once_each(self):
        # Per-CPU maps nest {"cpu":N,"value":...} objects under "values"; only
        # the per-entry "key" wrapper must be counted.
        out = (
            b'[{"key":["0x01"],"values":[{"cpu":0,"value":["0x0a"]},'
            b'{"cpu":1,"value":["0x0b"]}]},'
            b'{"key":["0x02"],"values":[{"cpu":0,"value":["0x0c"]},'
            b'{"cpu":1,"value":["0x0d"]}]}]'
        )
        self.assertEqual(self._count(out), 2)

    def test_counts_btf_formatted_entries(self):
        # BTF-formatted dumps render key/value as struct objects; struct field
        # names ("saddr"/"count"/…) never collide with the "key" wrapper.
        out = (
            b'[{"key":{"saddr":1,"dport":80},"value":{"count":3}},'
            b'{"key":{"saddr":2,"dport":443},"value":{"count":7}}]'
        )
        self.assertEqual(self._count(out), 2)

    def test_empty_map_returns_zero(self):
        self.assertEqual(self._count(b"[]"), 0)

    def test_subprocess_failure_returns_none(self):
        with mock.patch(
            "auto_xdp.tui.subprocess.check_output",
            side_effect=subprocess.CalledProcessError(1, "bpftool"),
        ):
            self.assertIsNone(_dump_count(Path("/sys/fs/bpf/xdp_fw/some_map")))

    def test_missing_bpftool_returns_none(self):
        with mock.patch(
            "auto_xdp.tui.subprocess.check_output",
            side_effect=OSError("No such file"),
        ):
            self.assertIsNone(_dump_count(Path("/sys/fs/bpf/xdp_fw/some_map")))

    def test_garbage_output_returns_none(self):
        self.assertIsNone(self._count(b"not json and no marker"))


class FakeWindow:
    def __init__(self, height: int = 8, width: int = 100) -> None:
        self.height = height
        self.width = width
        self.lines: dict[int, str] = {}
        self.calls: list[tuple[int, int, str, int]] = []

    def getmaxyx(self) -> tuple[int, int]:
        return self.height, self.width

    def box(self) -> None:
        pass

    def addstr(self, y: int, x: int, text: str, attr: int = 0) -> None:
        self.calls.append((y, x, text, attr))
        existing = self.lines.get(y, "")
        if len(existing) < x:
            existing = existing + (" " * (x - len(existing)))
        self.lines[y] = existing[:x] + text


class TuiEventScrollTests(unittest.TestCase):
    def _client_with_events(self, count: int, max_events: int = 20) -> RelayClient:
        relay = RelayClient("/tmp/missing.sock", max_events=max_events)
        for idx in range(count):
            relay._append({"id": idx})
        return relay

    def test_event_window_stays_anchored_when_new_events_arrive_above_bottom(self):
        relay = self._client_with_events(10)
        visible = 3
        top = 4

        _, _, before = _event_window(relay, visible, top)
        relay._append({"id": 10})
        _, _, after = _event_window(relay, visible, top)

        self.assertEqual([ev["id"] for ev in before], [4, 5, 6])
        self.assertEqual([ev["id"] for ev in after], [4, 5, 6])

    def test_bottom_follow_uses_latest_events_after_append(self):
        relay = self._client_with_events(10)
        visible = 3
        top = _event_bottom_top(relay, visible)

        relay._append({"id": 10})
        top = _event_bottom_top(relay, visible)
        _, _, events = _event_window(relay, visible, top)

        self.assertEqual([ev["id"] for ev in events], [8, 9, 10])

    def test_event_window_clamps_to_retained_buffer_after_trimming(self):
        relay = self._client_with_events(5, max_events=5)
        visible = 2
        top = 1

        relay._append({"id": 5})
        _, _, events = _event_window(relay, visible, top)

        self.assertEqual(relay.events_offset, 1)
        self.assertEqual([ev["id"] for ev in events], [1, 2])

    def test_history_message_is_trimmed_before_append(self):
        relay = RelayClient("/tmp/missing.sock", max_events=3)
        msg = b'{"type":"history","events":[{"id":0},{"id":1},{"id":2},{"id":3},{"id":4}]}\n'
        fake_sock = mock.Mock()
        fake_sock.recv.side_effect = [msg, BlockingIOError()]
        relay._sock = fake_sock

        with mock.patch("auto_xdp.tui.select.select", return_value=([fake_sock], [], [])):
            relay.poll()

        self.assertEqual([ev["id"] for ev in relay.events], [2, 3, 4])
        self.assertEqual(relay.events_offset, 0)

    def test_events_panel_labels_and_renders_connection_protocol(self):
        relay = RelayClient("/tmp/missing.sock", max_events=3)
        relay.status = "relay: test"
        relay._append({
            "seen_at": 1_700_000_000.0,
            "verdict": "ALLOW",
            "proto": "TCP",
            "src": "198.51.100.10",
            "sport": 44321,
            "dport": 443,
            "reason": "TCP_ALLOWED",
        })
        win = FakeWindow()

        with mock.patch("auto_xdp.tui.curses.color_pair", return_value=0):
            _draw_events(win, relay, TuiSnapshot(), top=0, focused=False)

        self.assertIn("protocol", win.lines[1])
        self.assertIn("TCP", win.lines[2])
        self.assertIn("198.51.100.10/44321", win.lines[2])


class TuiTopTrafficTests(unittest.TestCase):
    def test_collect_top_traffic_groups_by_ip_proto_and_port(self):
        events = [
            {"src": "198.51.100.10", "proto": "TCP", "dport": 443, "seen_at": 100.0, "verdict": "ALLOW"},
            {"src": "198.51.100.10", "proto": "TCP", "dport": 443, "seen_at": 101.0, "verdict": "DROP"},
            {"src": "198.51.100.10", "proto": "UDP", "dport": 53, "seen_at": 102.0, "verdict": "ALLOW"},
            {"type": "port_change", "proto": "TCP", "port": 22},
        ]

        rows = _collect_top_traffic(events)

        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0].ip, "198.51.100.10")
        self.assertEqual(rows[0].proto, "TCP")
        self.assertEqual(rows[0].port, "443")
        self.assertEqual(rows[0].packets, 2)
        self.assertEqual(rows[0].verdict, "DROP")
        self.assertEqual(rows[1].proto, "UDP")

    def test_collect_top_traffic_prefers_byte_totals_when_available(self):
        events = [
            {"src": "198.51.100.10", "proto": "TCP", "dport": 443, "bytes": 100, "seen_at": 100.0},
            {"src": "203.0.113.7", "proto": "UDP", "dport": 53, "bytes": 500, "seen_at": 100.0},
            {"src": "198.51.100.10", "proto": "TCP", "dport": 443, "bytes": 100, "seen_at": 101.0},
        ]

        rows = _collect_top_traffic(events)

        self.assertEqual(rows[0].ip, "203.0.113.7")
        self.assertEqual(rows[0].bytes_, 500)
        self.assertEqual(rows[1].bytes_, 200)

    def test_draw_top_traffic_renders_protocol_and_port(self):
        relay = RelayClient("/tmp/missing.sock", max_events=5)
        relay.status = "relay: test"
        relay._append({
            "src": "198.51.100.10",
            "proto": "TCP",
            "dport": 443,
            "bytes": 1500,
            "seen_at": 1_700_000_000.0,
            "verdict": "ALLOW",
        })
        win = FakeWindow(height=8, width=120)

        with mock.patch("auto_xdp.tui.curses.color_pair", return_value=0):
            _draw_top_traffic(win, relay)

        rendered = "\n".join(win.lines.values())
        self.assertIn("source ip", rendered)
        self.assertIn("TCP", rendered)
        self.assertIn("443", rendered)
        self.assertIn("198.51.100.10", rendered)


class TuiMapUsageTests(unittest.TestCase):
    def test_high_churn_map_is_sampled_outside_under_attack(self):
        with tempfile.TemporaryDirectory() as td:
            Path(td, "tcp_ct4").touch()
            cache = MapUsageCache()

            with mock.patch("auto_xdp.tui._read_xdp_ports", return_value=([], [])), \
                mock.patch("auto_xdp.tui._all_map_info", return_value={"tcp_ct4": {"name": "tcp_ct4", "type": "hash", "max_entries": 100}}), \
                mock.patch("auto_xdp.tui._dump_count", return_value=12) as dump_count:
                rows = _collect_map_usage(td, cache=cache, now=100.0)

        self.assertEqual(rows[0].current, 12)
        self.assertEqual(rows[0].note, "sampled")
        dump_count.assert_called_once()

    def test_high_churn_map_uses_cache_within_sample_interval(self):
        with tempfile.TemporaryDirectory() as td:
            Path(td, "tcp_ct4").touch()
            cache = MapUsageCache(counts={"tcp_ct4": 12}, refreshed_at={"tcp_ct4": 100.0})

            with mock.patch("auto_xdp.tui._read_xdp_ports", return_value=([], [])), \
                mock.patch("auto_xdp.tui._all_map_info", return_value={"tcp_ct4": {"name": "tcp_ct4", "type": "hash", "max_entries": 100}}), \
                mock.patch("auto_xdp.tui._dump_count") as dump_count:
                rows = _collect_map_usage(td, cache=cache, now=110.0)

        self.assertEqual(rows[0].current, 12)
        self.assertEqual(rows[0].note, "cached")
        dump_count.assert_not_called()

    def test_high_churn_map_skips_dump_under_attack(self):
        with tempfile.TemporaryDirectory() as td:
            Path(td, "tcp_ct4").touch()
            cache = MapUsageCache()

            with mock.patch("auto_xdp.tui._read_xdp_ports", return_value=([], [])), \
                mock.patch("auto_xdp.tui._all_map_info", return_value={"tcp_ct4": {"name": "tcp_ct4", "type": "hash", "max_entries": 100}}), \
                mock.patch("auto_xdp.tui._dump_count") as dump_count:
                rows = _collect_map_usage(td, under_attack=True, cache=cache, now=100.0)

        self.assertIsNone(rows[0].current)
        self.assertEqual(rows[0].note, "attack skip")
        dump_count.assert_not_called()

    def test_fast_map_usage_defers_non_whitelist_counts(self):
        with tempfile.TemporaryDirectory() as td:
            Path(td, "tcp_ct4").touch()
            Path(td, "udp_whitelist").touch()

            with mock.patch("auto_xdp.tui._read_xdp_ports", return_value=([22], [53])), \
                mock.patch("auto_xdp.tui._all_map_info", return_value={
                    "tcp_ct4": {"name": "tcp_ct4", "type": "hash", "max_entries": 100},
                    "udp_whitelist": {"name": "udp_whitelist", "type": "hash", "max_entries": 100},
                }), \
                mock.patch("auto_xdp.tui._dump_count") as dump_count:
                rows = _collect_map_usage(td, sample_counts=False)

        by_name = {row.name: row for row in rows}
        self.assertIsNone(by_name["tcp_ct4"].current)
        self.assertEqual(by_name["tcp_ct4"].note, "deferred")
        self.assertEqual(by_name["udp_whitelist"].current, 1)
        dump_count.assert_not_called()

    def test_non_churn_map_uses_cache_within_sample_interval(self):
        with tempfile.TemporaryDirectory() as td:
            Path(td, "tcp_acl_v4").touch()
            cache = MapUsageCache(counts={"tcp_acl_v4": 7}, refreshed_at={"tcp_acl_v4": 100.0})

            with mock.patch("auto_xdp.tui._read_xdp_ports", return_value=([], [])), \
                mock.patch("auto_xdp.tui._all_map_info", return_value={"tcp_acl_v4": {"name": "tcp_acl_v4", "type": "hash", "max_entries": 100}}), \
                mock.patch("auto_xdp.tui._dump_count") as dump_count:
                rows = _collect_map_usage(td, cache=cache, now=105.0)

        self.assertEqual(rows[0].current, 7)
        self.assertEqual(rows[0].note, "cached")
        dump_count.assert_not_called()

    def test_array_map_uses_max_entries_without_dump(self):
        # Array maps are dense: live count == max_entries, so no per-map
        # `bpftool map dump` subprocess is needed (tsc_port is 65536 entries).
        with tempfile.TemporaryDirectory() as td:
            Path(td, "tsc_port").touch()

            with mock.patch("auto_xdp.tui._read_xdp_ports", return_value=([], [])), \
                mock.patch("auto_xdp.tui._all_map_info", return_value={"tsc_port": {"name": "tsc_port", "type": "array", "max_entries": 65536}}), \
                mock.patch("auto_xdp.tui._dump_count") as dump_count:
                rows = _collect_map_usage(td, now=100.0)

        self.assertEqual(rows[0].current, 65536)
        self.assertEqual(rows[0].maximum, 65536)
        self.assertEqual(rows[0].note, "array")
        dump_count.assert_not_called()

    def test_array_map_without_max_entries_falls_back_to_dump(self):
        with tempfile.TemporaryDirectory() as td:
            Path(td, "weird_array").touch()

            with mock.patch("auto_xdp.tui._read_xdp_ports", return_value=([], [])), \
                mock.patch("auto_xdp.tui._all_map_info", return_value={"weird_array": {"name": "weird_array", "type": "percpu_array"}}), \
                mock.patch("auto_xdp.tui._dump_count", return_value=5) as dump_count:
                rows = _collect_map_usage(td, now=100.0)

        self.assertEqual(rows[0].current, 5)
        dump_count.assert_called_once()

    def test_map_info_uses_cache_within_metadata_interval(self):
        with tempfile.TemporaryDirectory() as td:
            Path(td, "tcp_acl_v4").touch()
            cache = MapUsageCache(
                map_info={"tcp_acl_v4": {"name": "tcp_acl_v4", "type": "hash", "max_entries": 100}},
                map_info_refreshed_at=100.0,
            )

            with mock.patch("auto_xdp.tui._read_xdp_ports", return_value=([], [])), \
                mock.patch("auto_xdp.tui._all_map_info") as all_map_info, \
                mock.patch("auto_xdp.tui._dump_count", return_value=3):
                rows = _collect_map_usage(td, cache=cache, now=105.0)

        self.assertEqual(rows[0].maximum, 100)
        all_map_info.assert_not_called()

    def test_fast_port_rows_skip_process_lookup(self):
        with mock.patch("auto_xdp.tui._collect_ports", return_value=([22], [53])), \
            mock.patch("auto_xdp.tui._lookup_port_procs") as lookup_procs, \
            mock.patch("auto_xdp.tui._read_policy", return_value={}), \
            mock.patch("auto_xdp.tui._read_global_udp_rate", return_value=0), \
            mock.patch("auto_xdp.tui._safe_service", return_value="-"):
            rows = _collect_port_rows("xdp", "/sys/fs/bpf/xdp_fw", "inet", "auto_xdp", include_processes=False)

        self.assertEqual(rows[0][3], "-")
        self.assertEqual(rows[1][3], "-")
        lookup_procs.assert_not_called()


class TuiSummaryTests(unittest.TestCase):
    def test_attach_target_uses_mode_highlight(self):
        win = FakeWindow()
        snap = TuiSnapshot(
            attach_mode="auto",
            attach_target="eth0 eth1",
            attach_targets=[("eth0", "xdp native"), ("eth1", "xdp generic")],
        )

        with mock.patch("auto_xdp.tui.curses.color_pair", side_effect=lambda idx: idx * 10), \
            mock.patch("auto_xdp.tui.curses.A_BOLD", 1):
            _draw_summary(win, snap)

        attrs = {text: attr for _, _, text, attr in win.calls if text in {"eth0", "eth1"}}
        self.assertEqual(attrs["eth0"], 51)
        self.assertEqual(attrs["eth1"], 61)


class TuiPortFilterTests(unittest.TestCase):
    def test_port_filter_rows_selects_protocol(self):
        rows = [
            ("TCP", 22, "ssh", "sshd", "-"),
            ("UDP", 53, "domain", "named", "-"),
        ]

        self.assertEqual(_filter_port_rows(rows, "TCP"), [rows[0]])
        self.assertEqual(_filter_port_rows(rows, "UDP"), [rows[1]])
        self.assertEqual(_filter_port_rows(rows, "all"), rows)

    def test_draw_ports_filters_display_rows_and_title(self):
        win = FakeWindow()
        rows = [
            ("TCP", 22, "ssh", "sshd", "-"),
            ("UDP", 53, "domain", "named", "-"),
        ]

        _draw_ports(win, rows, {}, proto_filter="UDP")

        rendered = "\n".join(win.lines.values())
        title_calls = [text for _, _, text, _ in win.calls if "ports / services" in text]
        self.assertIn("[UDP]", title_calls[0])
        self.assertIn("UDP", rendered)
        self.assertIn("domain", rendered)
        self.assertNotIn("TCP", rendered)
        self.assertNotIn("ssh", rendered)


if __name__ == "__main__":
    unittest.main()
