import struct
import time
import unittest

from auto_xdp.sock_state import SockStateReader, SOCK_STATE_EVENT_SIZE

_STRUCT = struct.Struct("<QHBBB3x")
_AF_INET  = 2
_AF_INET6 = 10
_TCP      = 6


def _make_raw(ts_ns=1000, port=8080, proto=_TCP, action=1, family=_AF_INET):
    return _STRUCT.pack(ts_ns, port, proto, action, family)


class TestSockStateReader(unittest.TestCase):

    def test_event_size_constant(self):
        self.assertEqual(SOCK_STATE_EVENT_SIZE, 16)

    def test_decode_open_ipv4(self):
        raw = _make_raw(ts_ns=123456789, port=443, action=1, family=_AF_INET)
        ev = SockStateReader.decode_raw(raw)
        self.assertIsNotNone(ev)
        self.assertEqual(ev["type"],   "port_change")
        self.assertEqual(ev["port"],   443)
        self.assertEqual(ev["proto"],  "tcp")
        self.assertEqual(ev["action"], "open")
        self.assertEqual(ev["family"], 4)
        self.assertEqual(ev["ts_ns"],  123456789)

    def test_decode_close_ipv6(self):
        raw = _make_raw(port=22, action=0, family=_AF_INET6)
        ev = SockStateReader.decode_raw(raw)
        self.assertEqual(ev["action"], "close")
        self.assertEqual(ev["family"], 6)

    def test_decode_returns_none_for_short_buffer(self):
        ev = SockStateReader.decode_raw(b"\x00" * 15)
        self.assertIsNone(ev)

    def test_decode_unknown_proto_uses_string(self):
        raw = _make_raw(proto=132)  # SCTP
        ev = SockStateReader.decode_raw(raw)
        self.assertEqual(ev["proto"], "sctp")

    def test_seen_at_is_recent(self):
        raw = _make_raw()
        before = time.time()
        ev = SockStateReader.decode_raw(raw)
        after = time.time()
        self.assertGreaterEqual(ev["seen_at"], before)
        self.assertLessEqual(ev["seen_at"],    after)


import json
from unittest import mock
import pkt_relay as relay_mod


class TestRelayBroadcastPortChange(unittest.TestCase):

    def _make_relay(self):
        rb = mock.MagicMock()
        rb.drain.return_value = iter([])
        rb.fileno.return_value = 99
        return relay_mod.RelayServer(
            rb,
            sock_path="/tmp/_test_relay_t5.sock",
            retention_seconds=5,
            max_events=100,
            max_history_send=10,
        )

    def test_broadcast_port_change_preserves_type(self):
        server = self._make_relay()
        sent = []

        class FakeConn:
            def sendall(self, data):
                sent.append(data)

        server._clients[1] = FakeConn()
        ev = {"type": "port_change", "port": 8080, "action": "open",
              "proto": "tcp", "ts_ns": 1, "seen_at": 1.0, "family": 4}
        server._broadcast(ev)
        self.assertEqual(len(sent), 1)
        decoded = json.loads(sent[0].decode().strip())
        self.assertEqual(decoded["type"], "port_change")
        self.assertEqual(decoded["port"], 8080)

    def test_broadcast_packet_event_wraps_with_event_type(self):
        server = self._make_relay()
        sent = []

        class FakeConn:
            def sendall(self, data):
                sent.append(data)

        server._clients[1] = FakeConn()
        ev = {"src": "1.2.3.4", "dport": 80, "verdict": "DROP", "seen_at": 1.0}
        server._broadcast(ev)
        decoded = json.loads(sent[0].decode().strip())
        self.assertEqual(decoded["type"], "event")


import auto_xdp.syncer as syncer_mod


class TestSyncerDrainRelayLines(unittest.TestCase):

    def test_port_change_line_returns_true(self):
        line = json.dumps({
            "type": "port_change", "port": 9999, "action": "open",
            "proto": "tcp", "ts_ns": 1, "seen_at": 1.0, "family": 4,
        }).encode() + b"\n"
        fake_sock = mock.MagicMock()
        fake_sock.recv.side_effect = [line, BlockingIOError()]
        triggered = syncer_mod._drain_relay_lines(fake_sock)
        self.assertTrue(triggered)

    def test_non_port_change_line_returns_false(self):
        line = json.dumps({"type": "event", "verdict": "DROP"}).encode() + b"\n"
        fake_sock = mock.MagicMock()
        fake_sock.recv.side_effect = [line, BlockingIOError()]
        triggered = syncer_mod._drain_relay_lines(fake_sock)
        self.assertFalse(triggered)

    def test_empty_recv_raises_connection_reset(self):
        fake_sock = mock.MagicMock()
        fake_sock.recv.return_value = b""
        with self.assertRaises(ConnectionResetError):
            syncer_mod._drain_relay_lines(fake_sock)


import auto_xdp.tui as tui_mod
import threading


class TestTuiPortsDirty(unittest.TestCase):

    def _make_relay(self):
        relay = tui_mod.RelayClient.__new__(tui_mod.RelayClient)
        relay.events = []
        relay.events_offset = 0
        relay.max_events = 100
        relay.status = ""
        relay.ports_dirty = False
        relay.reason_totals = {}
        relay.path = ""
        relay._sock = None
        relay._buf = ""
        return relay

    def test_port_change_sets_ports_dirty(self):
        relay = self._make_relay()
        relay._append({"type": "port_change", "port": 443, "action": "open",
                       "proto": "tcp", "ts_ns": 1, "seen_at": 1.0, "family": 4})
        self.assertTrue(relay.ports_dirty)

    def test_packet_event_does_not_set_ports_dirty(self):
        relay = self._make_relay()
        relay._append({"type": "event", "verdict": "DROP", "seen_at": 1.0})
        self.assertFalse(relay.ports_dirty)


class TestSnapshotWorkerWakeup(unittest.TestCase):

    def _make_worker(self):
        worker = tui_mod.SnapshotWorker.__new__(tui_mod.SnapshotWorker)
        worker._stop = threading.Event()
        worker._wakeup = threading.Event()
        return worker

    def test_wakeup_sets_event(self):
        worker = self._make_worker()
        self.assertFalse(worker._wakeup.is_set())
        worker.wakeup()
        self.assertTrue(worker._wakeup.is_set())

    def test_stop_also_sets_wakeup(self):
        worker = tui_mod.SnapshotWorker.__new__(tui_mod.SnapshotWorker)
        worker._stop = threading.Event()
        worker._wakeup = threading.Event()
        worker._thread = mock.MagicMock()
        worker.stop()
        self.assertTrue(worker._wakeup.is_set())
        self.assertTrue(worker._stop.is_set())


if __name__ == "__main__":
    unittest.main()
