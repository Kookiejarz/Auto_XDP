import subprocess
import unittest
import tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from auto_xdp.tui.app import (
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
    _draw_cookie,
    _draw_drop_reasons,
    _read_cookie_runtime,
    _clip,
    _dump_count,
    _event_bottom_top,
    _event_window,
    _filter_port_rows,
    _actionable_approval_rows,
    _approve_tui_request,
    _audit_fingerprint,
    _audit_needs_review,
    _mark_audit_reviewed,
)


class DumpCountTests(unittest.TestCase):
    def _count(self, out: bytes) -> int | None:
        with mock.patch("auto_xdp.tui.app.subprocess.check_output", return_value=out):
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

    def test_raw_and_formatted_keys_are_one_entry(self):
        out = b'[{"key":["0x01"],"value":["0x02"],"formatted":{"key":1,"value":{"key":2}}}]'
        self.assertEqual(self._count(out), 1)

    def test_whitespace_and_nested_keys_do_not_inflate_count(self):
        out = b'[ { "key" : {"key": 1}, "value": {"key": 2}}, {"key":2,"value":3} ]'
        self.assertEqual(self._count(out), 2)

    def test_invalid_array_is_not_reported_as_an_entry_count(self):
        for out in (b'[{"key":1},]', b'[{"key":1}', b'[{"value":1}]', b'[{"key":1}] trailing'):
            with self.subTest(out=out):
                self.assertIsNone(self._count(out))

    def test_empty_map_returns_zero(self):
        self.assertEqual(self._count(b"[]"), 0)

    def test_subprocess_failure_returns_none(self):
        with mock.patch(
            "auto_xdp.tui.app.subprocess.check_output",
            side_effect=subprocess.CalledProcessError(1, "bpftool"),
        ):
            self.assertIsNone(_dump_count(Path("/sys/fs/bpf/xdp_fw/some_map")))

    def test_missing_bpftool_returns_none(self):
        with mock.patch(
            "auto_xdp.tui.app.subprocess.check_output",
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

        with mock.patch("auto_xdp.telemetry.relay_client.select.select", return_value=([fake_sock], [], [])):
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

        with mock.patch("auto_xdp.tui.app.curses.color_pair", return_value=0):
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

        with mock.patch("auto_xdp.tui.app.curses.color_pair", return_value=0):
            _draw_top_traffic(win, relay)

        rendered = "\n".join(win.lines.values())
        self.assertIn("source ip", rendered)
        self.assertIn("TCP", rendered)
        self.assertIn("443", rendered)
        self.assertIn("198.51.100.10", rendered)


class TuiMapUsageTests(unittest.TestCase):
    def test_metadata_matches_full_pin_paths_not_truncated_or_duplicate_names(self):
        with tempfile.TemporaryDirectory() as td:
            policy = Path(td, "tcp_port_policies")
            array = Path(td, "tcp_synck_policy")
            for path in (policy, array, Path(td, "sock_state_prog")):
                path.touch()
            entries = [
                {"id": 10, "name": "tcp_port_polici", "type": "hash", "max_entries": 1024,
                 "pinned": [str(policy)]},
                {"id": 20, "name": "tcp_port_polici", "type": "hash", "max_entries": 999,
                 "pinned": [str(Path(td, "other", "tcp_port_policies"))]},
                {"id": 30, "name": "tcp_synck_polic", "type": "array", "max_entries": 65536,
                 "pinned": [str(array)]},
            ]
            with mock.patch("auto_xdp.tui.app.read_xdp_ports", return_value=([], [])), \
                 mock.patch("auto_xdp.tui.app.shutil.which", return_value="/sbin/bpftool"), \
                 mock.patch("auto_xdp.tui.app._run_json", return_value=entries) as batch, \
                 mock.patch("auto_xdp.tui.app._dump_count", return_value=1) as dump:
                rows = {row.name: row for row in _collect_map_usage(td, now=100)}
            self.assertEqual(set(rows), {"tcp_port_policies", "tcp_synck_policy"})
            self.assertEqual((rows[policy.name].map_id, rows[policy.name].maximum), (10, 1024))
            self.assertEqual(rows[policy.name].current, 1)
            self.assertEqual(rows[array.name].current, 65536)
            self.assertEqual(rows[array.name].kind, "array")
            batch.assert_called_once_with(["bpftool", "-j", "-f", "map"])
            dump.assert_called_once_with(policy)

    def test_high_churn_map_is_sampled_outside_under_attack(self):
        with tempfile.TemporaryDirectory() as td:
            Path(td, "hblk4").touch()
            cache = MapUsageCache()

            with mock.patch("auto_xdp.tui.app.read_xdp_ports", return_value=([], [])), \
                mock.patch("auto_xdp.tui.app._all_map_info", return_value={"hblk4": {"name": "hblk4", "type": "hash", "max_entries": 100}}), \
                mock.patch("auto_xdp.tui.app._dump_count", return_value=12) as dump_count:
                rows = _collect_map_usage(td, cache=cache, now=100.0)

        self.assertEqual(rows[0].current, 12)
        self.assertEqual(rows[0].note, "sampled")
        dump_count.assert_called_once()

    def test_high_churn_map_uses_cache_within_sample_interval(self):
        with tempfile.TemporaryDirectory() as td:
            Path(td, "hblk4").touch()
            cache = MapUsageCache(counts={"hblk4": 12}, refreshed_at={"hblk4": 100.0})

            with mock.patch("auto_xdp.tui.app.read_xdp_ports", return_value=([], [])), \
                mock.patch("auto_xdp.tui.app._all_map_info", return_value={"hblk4": {"name": "hblk4", "type": "hash", "max_entries": 100}}), \
                mock.patch("auto_xdp.tui.app._dump_count") as dump_count:
                rows = _collect_map_usage(td, cache=cache, now=110.0)

        self.assertEqual(rows[0].current, 12)
        self.assertEqual(rows[0].note, "cached")
        dump_count.assert_not_called()

    def test_high_churn_map_skips_dump_under_attack(self):
        with tempfile.TemporaryDirectory() as td:
            Path(td, "hblk4").touch()
            cache = MapUsageCache()

            with mock.patch("auto_xdp.tui.app.read_xdp_ports", return_value=([], [])), \
                mock.patch("auto_xdp.tui.app._all_map_info", return_value={"hblk4": {"name": "hblk4", "type": "hash", "max_entries": 100}}), \
                mock.patch("auto_xdp.tui.app._dump_count") as dump_count:
                rows = _collect_map_usage(td, under_attack=True, cache=cache, now=100.0)

        self.assertIsNone(rows[0].current)
        self.assertEqual(rows[0].note, "attack skip")
        dump_count.assert_not_called()

    def test_fast_map_usage_defers_non_whitelist_counts(self):
        with tempfile.TemporaryDirectory() as td:
            Path(td, "hblk4").touch()
            Path(td, "udp_whitelist").touch()

            with mock.patch("auto_xdp.tui.app.read_xdp_ports", return_value=([22], [53])), \
                mock.patch("auto_xdp.tui.app._all_map_info", return_value={
                    "hblk4": {"name": "hblk4", "type": "hash", "max_entries": 100},
                    "udp_whitelist": {"name": "udp_whitelist", "type": "hash", "max_entries": 100},
                }), \
                mock.patch("auto_xdp.tui.app._dump_count") as dump_count:
                rows = _collect_map_usage(td, sample_counts=False)

        by_name = {row.name: row for row in rows}
        self.assertIsNone(by_name["hblk4"].current)
        self.assertEqual(by_name["hblk4"].note, "deferred")
        self.assertEqual(by_name["udp_whitelist"].current, 1)
        dump_count.assert_not_called()

    def test_non_churn_map_uses_cache_within_sample_interval(self):
        with tempfile.TemporaryDirectory() as td:
            Path(td, "tcp_acl_v4").touch()
            cache = MapUsageCache(counts={"tcp_acl_v4": 7}, refreshed_at={"tcp_acl_v4": 100.0})

            with mock.patch("auto_xdp.tui.app.read_xdp_ports", return_value=([], [])), \
                mock.patch("auto_xdp.tui.app._all_map_info", return_value={"tcp_acl_v4": {"name": "tcp_acl_v4", "type": "hash", "max_entries": 100}}), \
                mock.patch("auto_xdp.tui.app._dump_count") as dump_count:
                rows = _collect_map_usage(td, cache=cache, now=105.0)

        self.assertEqual(rows[0].current, 7)
        self.assertEqual(rows[0].note, "cached")
        dump_count.assert_not_called()

    def test_array_map_uses_max_entries_without_dump(self):
        # Array maps are dense: live count == max_entries, so no per-map
        # `bpftool map dump` subprocess is needed.
        with tempfile.TemporaryDirectory() as td:
            Path(td, "weird_array").touch()

            with mock.patch("auto_xdp.tui.app.read_xdp_ports", return_value=([], [])), \
                mock.patch("auto_xdp.tui.app._all_map_info", return_value={"weird_array": {"name": "weird_array", "type": "array", "max_entries": 65536}}), \
                mock.patch("auto_xdp.tui.app._dump_count") as dump_count:
                rows = _collect_map_usage(td, now=100.0)

        self.assertEqual(rows[0].current, 65536)
        self.assertEqual(rows[0].maximum, 65536)
        self.assertEqual(rows[0].note, "array")
        dump_count.assert_not_called()

    def test_array_map_without_max_entries_falls_back_to_dump(self):
        with tempfile.TemporaryDirectory() as td:
            Path(td, "weird_array").touch()

            with mock.patch("auto_xdp.tui.app.read_xdp_ports", return_value=([], [])), \
                mock.patch("auto_xdp.tui.app._all_map_info", return_value={"weird_array": {"name": "weird_array", "type": "percpu_array"}}), \
                mock.patch("auto_xdp.tui.app._dump_count", return_value=5) as dump_count:
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

            with mock.patch("auto_xdp.tui.app.read_xdp_ports", return_value=([], [])), \
                mock.patch("auto_xdp.tui.app._all_map_info") as all_map_info, \
                mock.patch("auto_xdp.tui.app._dump_count", return_value=3):
                rows = _collect_map_usage(td, cache=cache, now=105.0)

        self.assertEqual(rows[0].maximum, 100)
        all_map_info.assert_not_called()

    def test_fast_port_rows_skip_process_lookup(self):
        with mock.patch("auto_xdp.tui.app.collect_ports", return_value=([22], [53])), \
            mock.patch("auto_xdp.tui.app.lookup_port_procs") as lookup_procs, \
            mock.patch("auto_xdp.tui.app._read_policy", return_value={}), \
            mock.patch("auto_xdp.tui.app._read_global_udp_rate", return_value=0), \
            mock.patch("auto_xdp.tui.app._safe_service", return_value="-"):
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

        with mock.patch("auto_xdp.tui.app.curses.color_pair", side_effect=lambda idx: idx * 10), \
            mock.patch("auto_xdp.tui.app.curses.A_BOLD", 1):
            _draw_summary(win, snap)

        attrs = {text: attr for _, _, text, attr in win.calls if text in {"eth0", "eth1"}}
        self.assertEqual(attrs["eth0"], 51)
        self.assertEqual(attrs["eth1"], 61)


class TuiObservationTests(unittest.TestCase):
    def test_cookie_page_uses_unknown_for_missing_counters_and_config_is_not_runtime(self):
        win = FakeWindow(height=19, width=80)
        relay = RelayClient("unused")
        relay.telemetry_status = dict(queue_dropped=7, invalid_records=3)
        snapshot = TuiSnapshot(cookie_configured=True, stats=[("EVENT_SUPPRESSED", 8, -1, "-")])
        _draw_cookie(win, snapshot, relay)
        rendered = "\n".join(win.lines.values())
        self.assertIn("runtime=unknown; configured=enabled", rendered)
        self.assertIn("VALID != application accept", rendered)
        self.assertIn("suppressed=8", rendered)
        self.assertIn("queue loss=7", rendered)
        self.assertIn("unknown", rendered)
        for y, x, text, _ in win.calls:
            self.assertTrue(0 <= y < 19)
            self.assertTrue(0 <= x < 80)
            self.assertLess(x + len(text), 80)

    def test_cookie_page_scroll_reaches_handoff_result(self):
        win = FakeWindow(height=19, width=80)
        snapshot = TuiSnapshot(stats=[("SYN_COOKIE_HANDOFF_SUCCESS", 9, -1, "1 pps")])
        _draw_cookie(win, snapshot, RelayClient("unused"), scroll=100)
        rendered = "\n".join(win.lines.values())
        self.assertIn("SYN_COOKIE_HANDOFF_SUCCESS", rendered)
        self.assertIn("9", rendered)

    def test_reason_panel_explains_only_retained_drop_events(self):
        relay = RelayClient("unused", max_events=1)
        relay._append(dict(verdict="DROP", reason="TCP_DROP"))
        relay._append(dict(verdict="DROP", reason="PORT_NOT_AUTHORIZED"))
        win = FakeWindow(height=8, width=100)
        with mock.patch("auto_xdp.tui.app.curses.color_pair", return_value=0):
            _draw_drop_reasons(win, relay)
        rendered = "\n".join(win.lines.values())
        self.assertIn("1 retained events", rendered)
        self.assertIn("not authorized on this ingress interface", rendered)
        self.assertNotIn("TCP_DROP", rendered)

    def test_source_geo_lookup_is_bounded_and_sample_coverage_is_visible(self):
        relay = RelayClient("unused")
        for index in range(20):
            relay._append(dict(src=f"2001:4860::{index}", verdict="DROP", proto="TCP", dport=443, pkt_len=60))
        geo = SimpleNamespace(status="ready", lookup=mock.Mock(return_value=dict(
            country_code="US", asn=15169, as_org="Organization " * 100, db_updated_at="2026-09-01")))
        win = FakeWindow(height=30, width=80)
        with mock.patch("auto_xdp.tui.app.curses.color_pair", return_value=0):
            _draw_top_traffic(win, relay, geo)
        rendered = "\n".join(win.lines.values())
        self.assertEqual(geo.lookup.call_count, 10)
        self.assertIn("retained event samples", rendered)
        self.assertIn("US AS15169", rendered)
        self.assertIn("bytes* recorded only", rendered)
        self.assertIn("2026-09-01", rendered)
        self.assertIn("unverified source", rendered)
        self.assertTrue(all(x + len(text) < 80 for _, x, text, _ in win.calls))

    def test_event_metadata_and_unknown_old_metadata_are_visible(self):
        relay = RelayClient("unused")
        relay._append(dict(verdict="DROP", src="1.1.1.1", reason="SYN_RATE_DROP", ifindex=3, pkt_len=60))
        relay._append(dict(verdict="DROP", src="1.1.1.1", reason="TCP_DROP"))
        win = FakeWindow(height=8, width=120)
        with mock.patch("auto_xdp.tui.app.curses.color_pair", return_value=0):
            _draw_events(win, relay, TuiSnapshot(), top=0, focused=False)
        rendered = "\n".join(win.lines.values())
        self.assertIn("if=3 len=60", rendered)
        self.assertIn("SYN_RATE_DROP", rendered)
        self.assertIn("if=? len=?", rendered)
        self.assertIn("TCP_DROP", rendered)

    def test_runtime_reader_gets_one_value_and_closes_map(self):
        runtime = mock.Mock()
        runtime.get.return_value = (1, 90, 200, 1000, 5000000000)
        with mock.patch("auto_xdp.tui.app.Path.exists", return_value=True), \
             mock.patch("auto_xdp.tui.app.BpfSyncookieRuntimeMap", return_value=runtime):
            self.assertEqual(_read_cookie_runtime("/sys/fs/bpf/xdp_fw/sync_run_cfg"), runtime.get.return_value)
        runtime.get.assert_called_once_with()
        runtime.close.assert_called_once_with()

    def test_clipping_handles_wide_characters_and_control_text(self):
        self.assertEqual(_clip("中中", 4), "中")
        self.assertEqual(_clip("ab\nc", 4), "abc")
        self.assertEqual(_clip("abc", 1), "")


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
        body = "\n".join(text for y, text in win.lines.items() if 2 <= y < win.height - 1)
        self.assertNotIn("TCP", body)
        self.assertNotIn("ssh", body)


class TuiAuditMarkerTests(unittest.TestCase):
    def test_approval_workflow_hides_history_and_selects_pending_first(self):
        rows = [
            {"id": 1, "status": "approved"},
            {"id": 2, "status": "rejected"},
            {"id": 3, "status": "pending"},
            {"id": 4, "status": "revoked"},
            {"id": 5, "status": "pending"},
        ]

        self.assertEqual(
            [row["id"] for row in _actionable_approval_rows(rows)],
            [3, 5, 1],
        )

    def test_enter_approves_selected_pending_request(self):
        args = SimpleNamespace(run_state_dir="/run/auto_xdp", config="/etc/auto_xdp/config.toml")
        with mock.patch("auto_xdp.tui.app.approvals.approve_request") as approve, \
             mock.patch("auto_xdp.tui.app.approvals.store_path", return_value=Path("/run/auto_xdp/approval_requests.json")), \
             mock.patch("auto_xdp.tui.app.approvals.reload_daemon") as reload_daemon:
            message = _approve_tui_request(args, {"id": 7, "status": "pending"})

        approve.assert_called_once_with(
            Path("/run/auto_xdp/approval_requests.json"),
            "/etc/auto_xdp/config.toml",
            7,
            actor="tui",
        )
        reload_daemon.assert_called_once_with()
        self.assertEqual(message, "approved request #7")

    def test_enter_explains_non_pending_request(self):
        args = SimpleNamespace(run_state_dir="/run/auto_xdp", config="/etc/auto_xdp/config.toml")
        with mock.patch("auto_xdp.tui.app.approvals.approve_request") as approve:
            message = _approve_tui_request(args, {"id": 8, "status": "approved"})

        approve.assert_not_called()
        self.assertIn("Enter only approves pending requests", message)

    def test_audit_marker_only_requests_first_or_changed_snapshot(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            marker = Path(tmpdir) / "audit.json"
            rows = [{"action": "drop", "port": 443, "subject": "unknown"}]
            fingerprint = _audit_fingerprint(rows)
            self.assertTrue(_audit_needs_review(marker, fingerprint))
            _mark_audit_reviewed(marker, fingerprint)
            self.assertFalse(_audit_needs_review(marker, fingerprint))
            changed = _audit_fingerprint(rows + [{"action": "allow", "port": 22, "subject": "ssh"}])
            self.assertTrue(_audit_needs_review(marker, changed))


if __name__ == "__main__":
    unittest.main()
