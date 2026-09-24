import json
import unittest
from unittest import mock

from auto_xdp.telemetry.relay_client import MAX_READS_PER_POLL, RelayClient


def event(seq, session="run-a", **fields):
    return dict(type="event", session_id=session, seq=seq, src="198.51.100.10",
                proto="TCP", dport=443, verdict="DROP", reason="SYN_RATE_DROP", **fields)


class RelayClientTests(unittest.TestCase):
    def poll_chunks(self, relay, chunks):
        sock = mock.Mock()
        sock.recv.side_effect = [*chunks, BlockingIOError()]
        relay._sock = sock
        with mock.patch("auto_xdp.telemetry.relay_client.select.select", return_value=([sock], [], [])):
            relay.poll()
        return sock

    def test_reconnect_history_deduplicates_by_identity_not_tuple(self):
        relay = RelayClient("unused", max_events=3)
        relay._message(dict(type="history", session_id="run-a", events=[event(1), event(2)]))
        relay.close()
        relay._message(dict(type="history", session_id="run-a", events=[event(1), event(2), event(3)]))
        relay._message(event(4))
        self.assertEqual([row["seq"] for row in relay.events], [2, 3, 4])
        self.assertEqual(relay.events_offset, 1)
        self.assertEqual(relay.reason_totals, {"SYN_RATE_DROP": 3})

    def test_restart_resets_sequence_without_merging_distinct_packets(self):
        relay = RelayClient("unused")
        relay._message(event(100))
        relay.telemetry_status = {"queue_dropped": 9}
        relay._message(dict(type="history", session_id="run-b", events=[event(1, "run-b")]))
        self.assertEqual([(row["session_id"], row["seq"]) for row in relay.events], [("run-a", 100), ("run-b", 1)])
        self.assertEqual(relay.telemetry_status, {})

    def test_reason_counts_expire_with_retained_window(self):
        relay = RelayClient("unused", max_events=2)
        relay._append({"verdict": "DROP", "reason": "TCP_DROP"})
        relay._append({"verdict": "DROP", "reason": "SYN_RATE_DROP"})
        relay._append({"verdict": "ALLOW", "reason": "TCP_PASS"})
        self.assertEqual(relay.reason_totals, {"SYN_RATE_DROP": 1})

    def test_live_port_change_and_health_are_handled_separately(self):
        relay = RelayClient("unused")
        messages = [dict(type="port_change", session_id="run-a", seq=1, port=22),
                    dict(type="telemetry_status", session_id="run-a", queue_dropped=7)]
        self.poll_chunks(relay, [("\n".join(json.dumps(msg) for msg in messages) + "\n").encode()])
        self.assertTrue(relay.ports_dirty)
        self.assertEqual(len(relay.events), 1)
        self.assertEqual(relay.telemetry_status["queue_dropped"], 7)

    def test_complete_messages_survive_eof_but_partial_bytes_do_not(self):
        relay = RelayClient("unused")
        self.poll_chunks(relay, [(json.dumps(event(1)) + '\n{"type":').encode(), b""])
        self.assertEqual(len(relay.events), 1)
        self.assertEqual(relay._buf, b"")
        self.poll_chunks(relay, [(json.dumps(event(2)) + "\n").encode()])
        self.assertEqual([row["seq"] for row in relay.events], [1, 2])

    def test_partial_message_limit_closes_socket(self):
        relay = RelayClient("unused")
        with mock.patch("auto_xdp.telemetry.relay_client.MAX_MESSAGE_BYTES", 64):
            sock = self.poll_chunks(relay, [b"x" * 65])
        sock.close.assert_called_once()
        self.assertIsNone(relay._sock)
        self.assertFalse(relay._buf)
        self.assertIn("buffer limit", relay.status)

    def test_busy_stream_yields_to_caller(self):
        relay = RelayClient("unused")
        chunks = [(json.dumps(event(seq)) + "\n").encode() for seq in range(20)]
        sock = self.poll_chunks(relay, chunks)
        self.assertEqual(sock.recv.call_count, MAX_READS_PER_POLL)
        self.assertEqual(len(relay.events), MAX_READS_PER_POLL)

    def test_legacy_history_replaces_previous_history(self):
        relay = RelayClient("unused")
        history = dict(type="history", events=[dict(reason="TCP_DROP", verdict="DROP")])
        relay._message(history)
        relay._message(history)
        self.assertEqual(len(relay.events), 1)
        self.assertEqual(relay.reason_totals, {"TCP_DROP": 1})

    def test_history_reports_bounded_replay_without_counting_it_as_packet_loss(self):
        relay = RelayClient("unused", max_events=2)
        relay._message(dict(type="history", session_id="run-a", available_events=50,
                            truncated=True, events=[event(1), event(2), event(3)]))
        self.assertEqual(relay.history_available, 50)
        self.assertTrue(relay.history_truncated)
        self.assertEqual(len(relay.events), 2)
        self.assertEqual(relay.telemetry_status, {})

    def test_malformed_messages_do_not_break_following_event(self):
        relay = RelayClient("unused")
        bad = b'[]\n{"type":[]}\n{"type":"history","events":null}\n{"type":"history","events":[null,3]}\n'
        self.poll_chunks(relay, [bad + (json.dumps(event(1)) + "\n").encode()])
        self.assertEqual(len(relay.events), 1)

    def test_failed_connect_closes_created_socket(self):
        relay = RelayClient("unused")
        sock = mock.Mock()
        sock.connect.side_effect = FileNotFoundError(2, "missing")
        with mock.patch("auto_xdp.telemetry.relay_client.socket.socket", return_value=sock):
            relay.poll()
        sock.close.assert_called_once()


if __name__ == "__main__":
    unittest.main()
