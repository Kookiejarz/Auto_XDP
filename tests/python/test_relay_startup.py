"""Relay IPC stays available while packet telemetry waits for XDP."""
from contextlib import contextmanager
import errno
import json
import logging
import os
import socket
import struct
import tempfile
import threading
import time
from unittest.mock import Mock

import pytest

import pkt_relay


pytestmark = pytest.mark.component


@pytest.fixture
def startup(tmp_path, monkeypatch):
    config = tmp_path / "config.toml"
    config.write_text('[policy]\nmode = "audit"\n')
    reader = Mock()
    open_ring = Mock(return_value=reader)
    monkeypatch.setattr(pkt_relay, "RingBufReader", open_ring)
    server = pkt_relay.RelayServer(None, packet_pin_path="/missing/packet-ring",
                                  config_path=str(config), retry_interval=0.1)
    return config, reader, open_ring, server


def relay_records(caplog):
    return [record for record in caplog.records if record.name == pkt_relay.log.name]


@pytest.mark.parametrize("mode", ["audit", "observe"])
def test_inactive_relay_reports_wait_once_then_opens_available_ring(startup, caplog, mode):
    config, reader, open_ring, server = startup
    config.write_text(f'[policy]\nmode = "{mode}"\n')
    open_ring.side_effect = [FileNotFoundError(errno.ENOENT, "missing")] * 3 + [reader]
    caplog.set_level(logging.INFO, logger=pkt_relay.log.name)
    for _ in range(3):
        server._connect_packet_ring()
        assert server._health_status()["packet_state"] == "inactive"
    waiting = [r for r in relay_records(caplog) if "Waiting" in r.getMessage()]
    assert len(waiting) == 1 and waiting[0].levelno == logging.INFO
    assert f"policy.mode={mode}" in waiting[0].getMessage()

    server._connect_packet_ring()
    server._connect_packet_ring()
    assert open_ring.call_count == 4
    assert server._health_status()["packet_state"] == "ready"
    assert server._health_status()["packet_error"] == ""
    server.close_packet_ring()
    server.close_packet_ring()
    reader.close.assert_called_once()


@pytest.mark.parametrize("mode,error", [
    ("enforce", errno.ENOENT), ("audit", errno.EPERM),
    ("observe", errno.EACCES), ("audit", errno.EINVAL), ("invalid", errno.ENOENT),
])
def test_real_ring_failures_still_warn_and_report_error(startup, caplog, mode, error):
    config, _reader, open_ring, server = startup
    config.write_text(f'[policy]\nmode = "{mode}"\n')
    open_ring.side_effect = OSError(error, "cannot open")
    server._connect_packet_ring()
    assert server._health_status()["packet_state"] == "error"
    assert "cannot open" in server._health_status()["packet_error"]
    assert any(record.levelno == logging.WARNING for record in relay_records(caplog))


def test_waiting_relay_notices_enforcement_change(startup, caplog):
    config, _reader, open_ring, server = startup
    open_ring.side_effect = FileNotFoundError(errno.ENOENT, "missing")
    caplog.set_level(logging.INFO, logger=pkt_relay.log.name)
    server._connect_packet_ring()
    assert server._health_status()["policy_mode"] == "audit"
    config.write_text('[policy]\nmode = "enforce"\n')
    server._connect_packet_ring()
    assert server._health_status()["packet_state"] == "error"
    assert [record.levelno for record in relay_records(caplog)] == [logging.INFO, logging.WARNING]


@pytest.mark.parametrize("change", ["missing", "invalid", "wrong_policy_type"])
def test_unreadable_policy_does_not_suppress_missing_ring_warning(startup, caplog, change):
    config, _reader, open_ring, server = startup
    open_ring.side_effect = FileNotFoundError(errno.ENOENT, "missing")
    caplog.set_level(logging.INFO, logger=pkt_relay.log.name)
    server._connect_packet_ring()
    if change == "missing":
        config.unlink()
    elif change == "invalid":
        config.write_text("[invalid")
    else:
        config.write_text('policy = "audit"\n')
    server._connect_packet_ring()
    assert server._health_status()["packet_state"] == "error"
    assert [record.levelno for record in relay_records(caplog)] == [logging.INFO, logging.WARNING]


@contextmanager
def running_relay(server, monkeypatch):
    # Socket authorization has separate SO_PEERCRED tests; allow this transport
    # test to exercise the same lifecycle on macOS as well as Linux.
    monkeypatch.setattr(pkt_relay, "_peer_is_authorized", lambda _conn: True)
    errors = []

    def serve():
        try:
            server.run()
        except Exception as exc:
            errors.append(exc)

    with tempfile.TemporaryDirectory(prefix="relay-") as directory:
        server._sock_path = directory + "/events.sock"
        worker = threading.Thread(target=serve, daemon=True)
        client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        client.settimeout(3)
        worker.start()
        try:
            deadline = time.monotonic() + 3
            while True:
                try:
                    client.connect(server._sock_path)
                    break
                except (FileNotFoundError, ConnectionRefusedError):
                    assert time.monotonic() < deadline and not errors, errors
                    time.sleep(0.01)
            with client.makefile("rb") as stream:
                yield stream
        finally:
            server.stop()
            worker.join(3)
            client.close()
        assert not worker.is_alive()
        assert not errors
        assert not os.path.exists(server._sock_path)
        assert server._wakeup_reader is server._wakeup_writer is None


def receive_until(stream, predicate):
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline:
        raw = stream.readline()
        assert raw, "relay disconnected"
        message = json.loads(raw)
        if predicate(message):
            return message
    pytest.fail("relay did not publish the expected message")


@pytest.mark.parametrize("error,state", [(errno.ENOENT, "inactive"), (errno.EPERM, "error")])
def test_socket_serves_health_and_stops_without_a_packet_ring(startup, monkeypatch, error, state):
    _config, _reader, open_ring, server = startup
    open_ring.side_effect = OSError(error, "not available")
    server._retry_interval = 60  # Waiting must not delay socket startup or shutdown.
    with running_relay(server, monkeypatch) as stream:
        health = receive_until(stream, lambda msg: msg.get("packet_state") == state)
        assert health["type"] == "telemetry_status"
        assert health["decoded_events"] == 0
        assert server._rb is None


class PipeRing:
    invalid_records = 0

    def __init__(self):
        self.read_fd, self.write_fd = os.pipe()
        os.set_blocking(self.read_fd, False)
        self.closed = 0

    def fileno(self):
        return self.read_fd

    def drain(self):
        try:
            os.read(self.read_fd, 1)
        except BlockingIOError:
            return []
        return [struct.pack("<Q16s16sHHBBBB", 1234, socket.inet_aton("198.51.100.2"),
                            socket.inet_aton("192.0.2.1"), socket.htons(12345), socket.htons(443),
                            6, 2, 1, 46)]

    def close(self):
        self.closed += 1
        os.close(self.read_fd)
        os.close(self.write_fd)


def test_waiting_client_receives_packets_after_ring_appears_without_restarting(startup, monkeypatch):
    config, _reader, open_ring, server = startup
    available = threading.Event()
    ring = PipeRing()

    def open_later(_path):
        if not available.is_set():
            raise FileNotFoundError(errno.ENOENT, "missing")
        return ring

    open_ring.side_effect = open_later
    try:
        with running_relay(server, monkeypatch) as stream:
            initial = receive_until(stream, lambda msg: msg.get("packet_state") == "inactive")
            config.write_text('[policy]\nmode = "enforce"\n')
            available.set()
            ready = receive_until(stream, lambda msg: msg.get("packet_state") == "ready")
            assert ready["session_id"] == initial["session_id"]
            assert ready["packet_error"] == ""
            os.write(ring.write_fd, b"x")
            event = receive_until(stream, lambda msg: msg.get("type") == "event")
            assert event["dport"] == 443 and event["verdict"] == "DROP"
            assert event["session_id"] == initial["session_id"]
        assert ring.closed == 1
    finally:
        if not ring.closed:
            ring.close()


@pytest.mark.parametrize("wait", [False, True])
def test_main_defers_ring_open_only_when_wait_requested(startup, monkeypatch, wait):
    config, reader, open_ring, _server = startup
    server = Mock()
    factory = Mock(return_value=server)
    monkeypatch.setattr(pkt_relay, "RelayServer", factory)
    monkeypatch.setattr(pkt_relay.signal, "signal", Mock())
    monkeypatch.setattr(pkt_relay, "_write_pid", Mock(return_value=123))
    monkeypatch.setattr(pkt_relay, "_remove_pid", Mock())
    monkeypatch.setattr(pkt_relay.sys, "argv", ["pkt_relay.py", "--config", str(config)]
                        + (["--wait-for-ringbuf"] if wait else []))
    pkt_relay.main()
    assert factory.call_args.args[0] is (None if wait else reader)
    assert open_ring.call_count == (0 if wait else 1)
    server.run.assert_called_once()
    server.close_packet_ring.assert_called_once()


def test_nonwaiting_relay_keeps_fatal_startup_error(startup, monkeypatch, caplog):
    config, _reader, open_ring, _server = startup
    monkeypatch.setattr(pkt_relay.sys, "argv", ["pkt_relay.py", "--config", str(config)])
    open_ring.side_effect = FileNotFoundError(errno.ENOENT, "missing")
    with pytest.raises(SystemExit) as exc:
        pkt_relay.main()
    assert exc.value.code == 1
    assert any(record.levelno == logging.ERROR for record in relay_records(caplog))
