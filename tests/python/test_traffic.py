import unittest

from auto_xdp.telemetry.traffic import _collect_top_traffic, cookie_counters, counter_value, event_time


class TrafficTests(unittest.TestCase):
    def test_mixed_versions_keep_recorded_bytes_and_coverage_separate(self):
        rows = _collect_top_traffic([
            dict(src="1.1.1.1", proto="TCP", dport=443, verdict="ALLOW", pkt_len=60, seen_at=10),
            dict(src="1.1.1.1", proto="TCP", dport=443, verdict="DROP", pkt_len=None, seen_at=11),
            dict(type="port_change", port=443),
        ])
        row = rows[0]
        self.assertEqual((row.packets, row.allows, row.drops, row.bytes_, row.bytes_events), (2, 1, 1, 60, 1))

    def test_passed_packet_does_not_imply_verified_source(self):
        row = _collect_top_traffic([dict(src="1.1.1.1", verdict="ALLOW", reason="TCP_PASS")])[0]
        self.assertFalse(row.cookie_verified)
        row = _collect_top_traffic([dict(src="1.1.1.1", verdict="ALLOW", reason="SYN_COOKIE_VALID")])[0]
        self.assertTrue(row.cookie_verified)

    def test_missing_and_negative_counters_are_unknown(self):
        stats = [("SYN_COOKIE_SENT", 10, 600, "1 pps"), ("SYN_COOKIE_HANDOFF_SUCCESS", -1, -1, "-")]
        rows = {name: value for name, value, _ in cookie_counters(stats)}
        self.assertEqual(rows["SYN_COOKIE_SENT"], 10)
        self.assertIsNone(rows["SYN_COOKIE_HANDOFF_SUCCESS"])
        self.assertIsNone(rows["SYN_COOKIE_VALID"])
        self.assertEqual(counter_value(stats, "SYN_COOKIE_HANDOFF_SUCCESS"), "unknown")
        self.assertEqual(counter_value(stats, "EVENT_LOST"), "unknown")

    def test_invalid_event_time_is_safe_to_render(self):
        for value in (float("nan"), float("inf"), -1, "bad", {}, 10**1000):
            self.assertEqual(event_time({"seen_at": value}), 0)


if __name__ == "__main__":
    unittest.main()
