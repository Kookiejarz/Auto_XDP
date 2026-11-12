"""Production event decoding and relay-pressure contracts; no Linux required."""
import json
from pathlib import Path
import queue
import socket
import struct
import tempfile
import threading
from unittest.mock import Mock

import pytest

import pkt_relay
from auto_xdp.admin import cli as admin_cli
from auto_xdp.admin import stats
from auto_xdp.telemetry.events import decode_event, describe_reason, reason_info


def packet(*, family=2, reason=46, verdict=1, version=1):
    source = socket.inet_pton(socket.AF_INET6, "2001:db8::1234") if family == 10 else socket.inet_aton("198.51.100.27")
    destination = socket.inet_pton(socket.AF_INET6, "2001:db8::80") if family == 10 else socket.inet_aton("203.0.113.80")
    data = struct.pack("<Q16s16sHHBBBB", 123456789, source, destination,
                       socket.htons(51234), socket.htons(443), 6, family, verdict, reason)
    if version != 1:
        data += struct.pack("<IIB7x", 7, 74, version)
    return data


@pytest.mark.parametrize("family,source", [(2, "198.51.100.27"), (10, "2001:db8::1234")])
@pytest.mark.parametrize("version", [1, 2])
def test_decodes_real_wire_layout_and_preserves_unknown_metadata(family, source, version):
    event = decode_event(packet(family=family, version=version))
    assert event is not None
    assert (event["src"], event["sport"], event["dport"]) == (source, 51234, 443)
    assert event["reason"] == "PORT_NOT_AUTHORIZED"
    assert event["reason_category"] == "policy"
    assert event["source_evidence"] == "unverified"
    assert event["event_version"] == version
    assert event["ifindex"] == (7 if version == 2 else None)
    assert event["pkt_len"] == (74 if version == 2 else None)


def test_unknown_layout_is_rejected_but_unknown_reason_is_preserved():
    for raw in (b"", packet()[:-1], packet() + b"\0", packet(version=3),
                packet(verdict=3), packet(family=99)):
        assert decode_event(raw) is None
    event = decode_event(packet(reason=255))
    assert event["reason_id"] == 255
    assert event["reason_category"] == "unknown"
    assert "Unknown reason" in event["reason_detail"]
    event = decode_event(packet(family=0))
    assert event["src"] is None and event["dst"] is None and event["family"] == 0


def test_reason_aliases_are_shared_and_cookie_validation_is_not_acceptance():
    assert reason_info("UDP_GBL_DROP") == reason_info(13)
    assert "legacy" in describe_reason("TCP_DROP")
    assert reason_info(47) != reason_info(48)
    event = decode_event(packet(reason=40, verdict=2))
    assert event["source_evidence"] == "cookie_validated"
    assert "not prove application" in event["reason_detail"]


def relay():
    reader = Mock(invalid_records=0)
    return pkt_relay.RelayServer(reader, max_events=10)


@pytest.fixture
def relay_path():
    # Keep Unix socket paths below the platform limit, including on macOS.
    with tempfile.TemporaryDirectory(prefix="relay-") as directory:
        yield Path(directory) / "relay.sock"


def test_relay_counts_pressure_and_keeps_sequence_gaps_visible():
    server = relay()
    server._queue = queue.Queue(maxsize=1)
    server._enqueue({"reason": "PORT_NOT_AUTHORIZED"})
    server._enqueue({"reason": "PORT_NOT_AUTHORIZED"})
    server._enqueue({"type": "port_change"})
    first = server._queue.get_nowait()
    server._enqueue({"reason": "PORT_NOT_AUTHORIZED"})
    last = server._queue.get_nowait()
    assert first["session_id"] == last["session_id"]
    assert (first["seq"], last["seq"]) == (1, 4)
    health = server._health_status()
    assert (health["decoded_events"], health["queue_dropped"], health["port_events_dropped"]) == (4, 1, 1)
    assert health["type"] == "telemetry_status"


def test_relay_flush_is_bounded_and_history_retains_wire_identity(monkeypatch):
    server = relay()
    monkeypatch.setattr(pkt_relay, "EVENT_BROADCAST_BATCH", 2)
    for _ in range(3):
        server._enqueue({"verdict": "DROP"})
    assert server._flush_batch() == 2
    assert server._queue.qsize() == 1
    assert [event["seq"] for event in server._history] == [1, 2]
    assert server._health_status()["retained_events"] == 2


@pytest.mark.component
@pytest.mark.parametrize("event_count", [0, 1, 5])
def test_relay_wakes_idle_broadcaster_for_events_and_stop(relay_path, monkeypatch, event_count):
    server = pkt_relay.RelayServer(Mock(), sock_path=str(relay_path))
    sender, client = socket.socketpair()
    sender.setblocking(False)
    client.settimeout(3)
    server._clients[sender.fileno()] = sender
    idle = threading.Event()
    idle_ready = []
    errors = []
    select = pkt_relay.select.select

    def wait_for_work(readers, writers, errors, timeout):
        if timeout and not idle.is_set():
            idle.set()
            # Require FD readiness, not success from the polling timeout.
            ready = select(readers, writers, errors, 1.0)
            idle_ready.extend(ready[0])
            return ready
        return select(readers, writers, errors, timeout)

    def produce():
        if idle.wait(3):
            if not event_count:
                server.stop()
            for index in range(event_count):
                server._enqueue({"type": "port_change", "port": 8000 + index})

    def serve():
        try:
            server.run()
        except Exception as exc:
            errors.append(exc)

    monkeypatch.setattr(pkt_relay.select, "select", wait_for_work)
    monkeypatch.setattr(pkt_relay, "EVENT_BROADCAST_BATCH", 2)
    monkeypatch.setattr(server, "_reader_loop", produce)
    worker = threading.Thread(target=serve, daemon=True)
    worker.start()
    try:
        assert idle.wait(3), errors
        if not event_count:
            worker.join(3)
        events = []
        with client.makefile("rb") as stream:
            while len(events) < event_count:
                event = json.loads(stream.readline())
                if event["type"] == "port_change":
                    events.append(event)
        assert [event["port"] for event in events] == list(range(8000, 8000 + event_count))
        assert [event["seq"] for event in events] == list(range(1, event_count + 1))
    finally:
        server.stop()
        worker.join(3)
        client.close()
    assert not worker.is_alive()
    assert not errors
    assert idle_ready
    assert sender.fileno() == -1
    assert not relay_path.exists()
    assert server._wakeup_reader is server._wakeup_writer is None


@pytest.mark.component
def test_relay_full_wakeup_socket_keeps_events_queued(relay_path):
    server = pkt_relay.RelayServer(Mock(), sock_path=str(relay_path))
    wake_reader, wake_writer = socket.socketpair()
    server._wakeup_reader, server._wakeup_writer = wake_reader, wake_writer
    wake_reader.setblocking(False)
    wake_writer.setblocking(False)
    try:
        while True:
            try:
                wake_writer.send(b"\0" * 65536)
            except BlockingIOError:
                break
        server._enqueue({"type": "port_change", "port": 443})
        assert server._queue.get_nowait()["port"] == 443
        assert server._port_events_dropped == 0
        assert pkt_relay.select.select([wake_reader], [], [], 0)[0] == [wake_reader]
    finally:
        server._cleanup()
    assert wake_reader.fileno() == wake_writer.fileno() == -1


@pytest.mark.component
@pytest.mark.parametrize("failure", ["socketpair", "thread"])
def test_relay_startup_failure_closes_owned_sockets(relay_path, monkeypatch, failure):
    server = pkt_relay.RelayServer(Mock(), sock_path=str(relay_path))
    socketpair = socket.socketpair
    opened = []

    def open_wakeup():
        if failure == "socketpair":
            raise OSError("cannot allocate wakeup sockets")
        pair = socketpair()
        opened.extend(pair)
        return pair

    monkeypatch.setattr(pkt_relay.socket, "socketpair", open_wakeup)
    monkeypatch.setattr(threading.Thread, "start", Mock(side_effect=RuntimeError("cannot start reader")))
    with pytest.raises((OSError, RuntimeError)):
        server.run()
    assert not server._running
    assert server._server.fileno() == -1
    assert all(sock.fileno() == -1 for sock in opened)
    assert server._wakeup_reader is server._wakeup_writer is None
    assert not relay_path.exists()


def test_ring_reader_accepts_mixed_versions_and_counts_unsupported_records():
    records = [packet(), packet(version=2), b"invalid!"]
    wire = b"".join(struct.pack("<II", len(raw), 0) + raw + b"\0" * (-len(raw) % 8)
                    for raw in records)
    reader = pkt_relay.RingBufReader.__new__(pkt_relay.RingBufReader)
    reader._mask = 255
    reader._event_size = (48, 64)
    reader._consumer = bytearray(8)
    reader._producer = bytearray(struct.pack("<Q", len(wire)))
    reader._data = wire + bytes(512 - len(wire))
    assert list(reader.drain()) == records[:2]
    assert reader.invalid_records == 1
    assert reader._cpos() == len(wire)


def test_history_replay_has_wire_byte_limit_and_zero_means_no_history():
    server = pkt_relay.RelayServer(Mock(), max_events=30000, max_history_send=20000)
    for seq in range(20000):
        server._history.append(dict(decode_event(packet(family=10, version=2)), seq=seq))
    message = server._history_message()
    assert len((json.dumps(message, separators=(",", ":")) + "\n").encode()) <= pkt_relay.MAX_HISTORY_BYTES
    assert message["truncated"] and message["available_events"] == 20000
    assert message["events"][-1]["seq"] == 19999
    assert message["events"][0]["seq"] > 0
    server._max_history_send = 0
    assert server._history_message()["events"] == []
    with pytest.raises(ValueError):
        pkt_relay.RelayServer(Mock(), max_history_send=-1)


def test_unknown_totals_do_not_modify_accumulator_or_report_a_reset(tmp_path, capsys):
    state = tmp_path / "stats.json"
    known = [("XDP_TOTAL", 100, 10000), ("XDP_DROP_TOTAL", 20, 2000)]
    stats._apply_xdp_accumulator(known, "xdp", "eth0", "1", state)
    baseline = state.read_bytes()
    unknown = [("XDP_TOTAL", -1, -1), ("XDP_DROP_TOTAL", -1, -1)]
    assert stats._apply_xdp_accumulator(unknown, "xdp", "eth0", "1", state) == unknown
    assert state.read_bytes() == baseline
    admin_cli._render_stats(unknown, {"XDP_TOTAL": (100, 10000)}, "xdp", "eth0", "1", True, 1)
    rendered = capsys.readouterr().out
    assert "unknown" in rendered and "ResetHint" not in rendered
