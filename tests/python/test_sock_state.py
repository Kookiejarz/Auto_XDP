import struct
import socket
import unittest

import pytest

import auto_xdp.sock_state as sock_state_mod
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
        with mock.patch.object(sock_state_mod.time, "time", return_value=1234.5):
            ev = SockStateReader.decode_raw(raw)
        self.assertEqual(ev["seen_at"], 1234.5)


import json
import os
import stat
import tempfile
from pathlib import Path
from unittest import mock
import pkt_relay as relay_mod


class TestRelayBroadcastPortChange(unittest.TestCase):

    def test_tracepoint_attach_passes_program_fd_by_value(self):
        with (
            mock.patch.object(relay_mod, "_tp_id", return_value=123),
            mock.patch.object(relay_mod, "obj_get", return_value=41),
            mock.patch.object(relay_mod.platform, "machine", return_value="x86_64"),
            mock.patch.object(relay_mod.os, "cpu_count", return_value=1),
            mock.patch.object(relay_mod, "_libc") as libc,
            mock.patch.object(relay_mod.fcntl, "ioctl") as ioctl,
            mock.patch.object(relay_mod.os, "close"),
        ):
            libc.syscall.return_value = 42
            self.assertEqual(relay_mod.attach_tracepoint("/prog", "sock/tp"), [42])

            attr = bytes(libc.syscall.call_args.args[1]._obj)
            self.assertEqual(struct.unpack_from("<IIQ", attr), (2, 128, 123))
            ioctl.assert_any_call(42, relay_mod._PERF_EVENT_IOC_SET_BPF, 41)

    def test_ringbuf_reader_accepts_sock_state_record_size(self):
        raw = _make_raw(port=45683)
        reader = relay_mod.RingBufReader.__new__(relay_mod.RingBufReader)
        reader._mask = 63
        reader._event_size = SOCK_STATE_EVENT_SIZE
        reader._consumer = bytearray(8)
        reader._producer = bytearray(struct.pack("<Q", 24))
        reader._data = bytearray(struct.pack("<II", len(raw), 0) + raw + b"\0" * 40)

        self.assertEqual(list(reader.drain()), [raw])

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

    def test_history_retention_uses_relay_wall_clock_not_bpf_timestamp(self):
        server = self._make_relay()
        server._history.extend(
            [
                {"ts_ns": 1, "seen_at": 994.0},
                {"ts_ns": 2, "seen_at": 996.0},
            ]
        )
        with mock.patch.object(relay_mod.time, "time", return_value=1000.0):
            server._trim_history()
        self.assertEqual(len(server._history), 1)
        self.assertEqual(server._history[0]["seen_at"], 996.0)


@pytest.mark.component
class TestRelaySecurity(unittest.TestCase):
    def _relay(self, directory: str) -> relay_mod.RelayServer:
        rb = mock.MagicMock()
        rb.drain.return_value = iter([])
        rb.fileno.return_value = 99
        return relay_mod.RelayServer(
            rb,
            sock_path=str(Path(directory) / "pkt_events.sock"),
            retention_seconds=5,
            max_events=10,
            max_history_send=2,
        )

    def test_socket_directory_and_node_are_restricted(self):
        with tempfile.TemporaryDirectory() as directory:
            server = self._relay(directory)
            server._open_server()
            try:
                parent_mode = stat.S_IMODE(os.stat(directory).st_mode)
                socket_mode = stat.S_IMODE(os.stat(server._sock_path).st_mode)
                self.assertEqual(parent_mode, 0o750)
                self.assertEqual(socket_mode, relay_mod.SOCKET_MODE)
            finally:
                server._cleanup()

    def test_socket_path_symlink_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "target"
            target.write_text("not a socket")
            socket_path = Path(directory) / "pkt_events.sock"
            socket_path.symlink_to(target)
            server = self._relay(directory)
            with self.assertRaises(RuntimeError):
                server._open_server()
            self.assertEqual(target.read_text(), "not a socket")

    def test_unauthorized_client_is_rejected_before_history(self):
        with tempfile.TemporaryDirectory() as directory:
            server = self._relay(directory)
            server._open_server()
            client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            try:
                client.connect(server._sock_path)
                with mock.patch.object(relay_mod, "_peer_is_authorized", return_value=False):
                    server._accept_client()
                self.assertEqual(server._clients, {})
            finally:
                client.close()
                server._cleanup()

    @unittest.skipUnless(hasattr(socket, "SO_PEERCRED"), "Linux SO_PEERCRED is required")
    def test_peer_credentials_authorize_same_process(self):
        left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            self.assertTrue(relay_mod._peer_is_authorized(left))
            self.assertTrue(relay_mod._peer_is_authorized(right))
        finally:
            left.close()
            right.close()

    def test_pid_file_is_locked_and_removed_only_by_owner(self):
        with tempfile.TemporaryDirectory() as directory:
            pid_path = str(Path(directory) / "relay.pid")
            fd = relay_mod._write_pid(pid_path)
            try:
                self.assertEqual(
                    stat.S_IMODE(os.stat(pid_path).st_mode),
                    relay_mod.PID_FILE_MODE,
                )
                self.assertEqual(Path(pid_path).read_text(), f"{os.getpid()}\n")
                with self.assertRaises(OSError):
                    relay_mod._write_pid(pid_path)
            finally:
                relay_mod._remove_pid(pid_path, fd)
            self.assertFalse(os.path.exists(pid_path))

    def test_pid_symlink_is_rejected_without_touching_target(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "target"
            target.write_text("protected")
            pid_path = Path(directory) / "relay.pid"
            pid_path.symlink_to(target)
            with self.assertRaises(OSError):
                relay_mod._write_pid(str(pid_path))
            self.assertEqual(target.read_text(), "protected")


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

    def test_port_change_split_across_reads_is_preserved(self):
        line = json.dumps({
            "type": "port_change", "port": 9999, "action": "open",
            "proto": "tcp", "ts_ns": 1, "seen_at": 1.0, "family": 4,
        }).encode() + b"\n"
        split_at = len(line) // 2
        pending = bytearray()
        fake_sock = mock.MagicMock()
        fake_sock.recv.side_effect = [line[:split_at], BlockingIOError()]

        self.assertFalse(syncer_mod._drain_relay_lines(fake_sock, pending))
        self.assertEqual(bytes(pending), line[:split_at])

        fake_sock.recv.side_effect = [line[split_at:], BlockingIOError()]
        self.assertTrue(syncer_mod._drain_relay_lines(fake_sock, pending))
        self.assertEqual(pending, bytearray())


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
