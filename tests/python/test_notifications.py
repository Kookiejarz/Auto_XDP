"""Notification delivery and single-owner reconciliation under backpressure."""
import errno
import signal
import socket
import threading
import time
from unittest import mock

import pytest

from auto_xdp import config as cfg, syncer
from auto_xdp.discovery import notifications as events, proc_events
from auto_xdp.state import ApplyResult, DesiredState, ObservedState
from test_xdp_port_sync import make_proc_event_message


pytestmark = pytest.mark.component
PORT_CHANGE = b'{"type":"port_change","port":8080}\n'


def test_notifications_coalesce_and_consume_before_the_next_round():
    clock = iter([0.0, 0.5, 0.8, 1.0])
    receiver = events.NotificationReceiver("unused", monotonic=lambda: next(clock))
    receiver._notify(immediate=False)
    receiver._notify(immediate=True)
    receiver._notify(immediate=False)
    assert receiver.wait(0) == events.Notification(0.0, 0.8, True)
    assert receiver.wait(0) is None
    receiver._notify(immediate=False)
    assert receiver.wait(0) == events.Notification(1.0, 1.0, False)
    receiver.close()


@pytest.mark.parametrize("when", ["before_start", "during_wait_registration"])
def test_explicit_wake_is_retained_without_event_sources(monkeypatch, when):
    monkeypatch.setattr(events, "open_proc_connector", lambda: None)
    monkeypatch.setattr(events, "_open_relay_client", lambda path: None)
    receiver = events.NotificationReceiver("unused")
    if when == "before_start":
        receiver.wake()
    else:
        original_wait = receiver._condition.wait
        def register(timeout):
            # The condition predicate was checked, but no waiter exists yet.
            receiver.wake()
            return original_wait(timeout)
        monkeypatch.setattr(receiver._condition, "wait", register)
    receiver.start()
    try:
        notification = receiver.wait(2)
        assert notification is not None and notification.immediate
        assert receiver.wait(0) is None
    finally:
        receiver.close()
    assert not receiver._thread.is_alive()
    assert receiver._wake_reader.fileno() == receiver._wake_writer.fileno() == -1


def test_busy_relay_yields_and_ignores_malformed_messages():
    sock = mock.Mock()
    sock.recv.return_value = b'[]\nnull\n\xff\n{broken}\n' + PORT_CHANGE
    pending = bytearray()
    assert events._drain_relay_lines(sock, pending)
    assert 0 < sock.recv.call_count < 32
    assert pending == bytearray()


def test_relay_rejects_unbounded_partial_lines(monkeypatch):
    monkeypatch.setattr(events, "MAX_MESSAGE_BYTES", 32)
    sock = mock.Mock()
    sock.recv.return_value = b"x" * 33
    with pytest.raises(OSError, match="buffer limit"):
        events._drain_relay_lines(sock, bytearray())


def test_failed_relay_connect_closes_the_socket(monkeypatch):
    sock = mock.Mock()
    sock.connect.side_effect = FileNotFoundError()
    monkeypatch.setattr(events.socket, "socket", mock.Mock(return_value=sock))
    assert events._open_relay_client("missing") is None
    sock.close.assert_called_once()


def test_proc_storm_yields_and_overflow_is_reported(monkeypatch):
    sock = mock.Mock()
    sock.recv.return_value = make_proc_event_message(proc_events._PROC_EVENT_EXEC)
    monkeypatch.setattr(proc_events.select, "select", lambda *args: ([sock], [], []))
    assert proc_events.drain_proc_events(sock)
    assert 0 < sock.recv.call_count < 32
    sock.recv.side_effect = OSError(errno.ENOBUFS, "lost netlink messages")
    with pytest.raises(OSError) as exc:
        proc_events.drain_proc_events(sock)
    assert exc.value.errno == errno.ENOBUFS


def test_socket_exhaustion_keeps_relay_optional(monkeypatch):
    monkeypatch.setattr(events.socket, "socket", mock.Mock(side_effect=OSError(errno.EMFILE, "no descriptors")))
    assert events._open_relay_client("unused") is None


def test_receiver_failure_reaches_the_worker(monkeypatch):
    monkeypatch.setattr(events, "open_proc_connector", mock.Mock(side_effect=RuntimeError("broken reader")))
    receiver = events.NotificationReceiver("unused")
    receiver.start()
    try:
        with pytest.raises(RuntimeError, match="notification receiver failed"):
            receiver.wait(2)
    finally:
        receiver.close()
    assert not receiver._thread.is_alive()


def test_reconnect_discards_partial_frames_and_requests_reconciliation(monkeypatch):
    first, first_writer = socket.socketpair()
    second, second_writer = socket.socketpair()
    first.setblocking(False)
    second.setblocking(False)
    reconnected, delivered = threading.Event(), threading.Event()
    connections = iter([first, second])

    def connect(path):
        sock = next(connections, None)
        if sock is second:
            reconnected.set()
        return sock

    drain = events._drain_relay_lines

    def receive(sock, pending):
        changed = drain(sock, pending)
        if changed:
            delivered.set()
        return changed

    monkeypatch.setattr(events, "open_proc_connector", lambda: None)
    monkeypatch.setattr(events, "_open_relay_client", connect)
    monkeypatch.setattr(events, "_drain_relay_lines", receive)
    monkeypatch.setattr(events, "EVENT_SOURCE_RETRY_INTERVAL_SECONDS", 0.0)
    receiver = events.NotificationReceiver("unused")
    receiver.start()
    try:
        assert receiver.wait(2).immediate
        first_writer.sendall(b'{"type":"port_')
        first_writer.close()
        assert reconnected.wait(2)
        assert receiver.wait(2).immediate
        second_writer.sendall(PORT_CHANGE)
        assert delivered.wait(2)
    finally:
        receiver.close()
        first_writer.close()
        second_writer.close()
    assert first.fileno() == second.fileno() == -1
    assert not receiver._thread.is_alive()


@pytest.mark.parametrize("blocked_operation", ["initialize", "reconcile", "verify"])
def test_slow_backend_does_not_block_notifications_or_lose_the_followup(monkeypatch, blocked_operation):
    reader, writer = socket.socketpair()
    reader.setblocking(False)
    writer.settimeout(2)
    receiver = events.NotificationReceiver("unused", monotonic=lambda: 100.0)
    owner = threading.get_ident()
    operations, observed_generations, reader_threads = [], [], []
    received, decoded = threading.Event(), threading.Event()
    generation = 0
    slow_done = False
    rounds = 0
    drain, notify, wait = events._drain_relay_lines, receiver._notify, receiver.wait
    deadline = time.monotonic() + 10

    def receive(sock, pending):
        changed = drain(sock, pending)
        if changed:
            reader_threads.append(threading.get_ident())
            decoded.set()
        return changed

    def mark(**kwargs):
        notify(**kwargs)
        if decoded.is_set():
            received.set()

    def bounded_wait(timeout):
        assert time.monotonic() < deadline, "worker lost the follow-up notification"
        return wait(min(timeout, 0.1))

    def slow_operation():
        nonlocal generation, slow_done
        generation = 1
        writer.sendall(PORT_CHANGE * 4096)
        assert received.wait(2), "socket notifications stalled behind backend work"
        slow_done = True

    def observe(**kwargs):
        operations.append(("discovery", threading.get_ident()))
        observed_generations.append(generation)
        return ObservedState()

    def reconcile(*args):
        nonlocal rounds
        operations.append(("reconcile", threading.get_ident()))
        rounds += 1
        if slow_done and (blocked_operation != "initialize" or rounds > 1):
            assert observed_generations[-1] == 1
            raise KeyboardInterrupt()
        if blocked_operation == "reconcile" and rounds == 2:
            slow_operation()
        return ApplyResult()

    def verify():
        operations.append(("verify", threading.get_ident()))
        if blocked_operation == "verify" and not slow_done:
            slow_operation()
        return 0

    backend = mock.Mock()
    backend.reconcile.side_effect = reconcile
    backend.verify_kernel_state.side_effect = verify
    backend.is_stale.return_value = False
    backend.close.side_effect = lambda: operations.append(("close", threading.get_ident()))

    def open_backend(name):
        operations.append(("initialize", threading.get_ident()))
        if blocked_operation == "initialize":
            slow_operation()
        return backend

    monkeypatch.setattr(events, "open_proc_connector", lambda: None)
    monkeypatch.setattr(events, "_open_relay_client", lambda path: reader)
    monkeypatch.setattr(events, "_drain_relay_lines", receive)
    monkeypatch.setattr(receiver, "_notify", mark)
    monkeypatch.setattr(receiver, "wait", bounded_wait)
    monkeypatch.setattr(syncer, "NotificationReceiver", lambda *args, **kwargs: receiver)
    monkeypatch.setattr(syncer, "open_backend", open_backend)
    monkeypatch.setattr(syncer, "observe_system_state", observe)
    monkeypatch.setattr(syncer, "resolve_desired_state", lambda *args, **kwargs: DesiredState())
    try:
        syncer.watch(False, "xdp", mode="enforce", monotonic=lambda: 100.0)
    finally:
        receiver.close()
        writer.close()
    assert slow_done and rounds >= 2
    assert reader_threads and all(ident != owner for ident in reader_threads)
    assert all(ident == owner for _, ident in operations)
    assert not receiver._thread.is_alive()
    backend.close.assert_called_once()


@pytest.mark.parametrize("new_mode", ["audit", "enforce"])
def test_reload_changes_mode_on_the_worker_without_restarting_receiver(monkeypatch, new_mode):
    original_mode = "enforce" if new_mode == "audit" else "audit"
    monkeypatch.setattr(cfg, "POLICY_MODE", original_mode)
    receiver, backend = mock.Mock(), mock.Mock()
    backend.is_stale.return_value = False
    backend.verify_kernel_state.return_value = 0
    backend.last_apply_failures = 0
    calls = []
    waits = 0

    def wait(timeout):
        nonlocal waits
        waits += 1
        if waits == 1:
            signal.getsignal(signal.SIGHUP)(signal.SIGHUP, None)
        elif waits > 2:
            raise KeyboardInterrupt()
        return None

    def reload(path):
        cfg.POLICY_MODE = new_mode
        return True

    def sync(active_backend, *args, **kwargs):
        calls.append((cfg.POLICY_MODE, active_backend))

    receiver.wait.side_effect = wait
    monkeypatch.setattr(syncer, "NotificationReceiver", lambda *args, **kwargs: receiver)
    monkeypatch.setattr(syncer, "open_backend", lambda name: backend)
    monkeypatch.setattr(syncer, "_reload_config", reload)
    monkeypatch.setattr(syncer, "sync_once", sync)
    previous_sighup = signal.getsignal(signal.SIGHUP)
    syncer.watch(False, "xdp", monotonic=lambda: 100.0)
    assert calls[0][0] == original_mode and calls[-1][0] == new_mode
    assert all(active_backend is None for mode, active_backend in calls if mode == "audit")
    assert all(active_backend is backend for mode, active_backend in calls if mode == "enforce")
    receiver.start.assert_called_once()
    receiver.wake.assert_called_once()
    receiver.close.assert_called_once()
    backend.close.assert_called_once()
    assert signal.getsignal(signal.SIGHUP) is previous_sighup


def _watch_config_reloads(monkeypatch, backend_name, backends, updates):
    receiver = mock.Mock()
    opener = mock.Mock(side_effect=backends)
    calls = []
    waits = reloads = 0

    def wait(timeout):
        nonlocal waits
        waits += 1
        if waits > len(updates) * 2:
            raise KeyboardInterrupt()
        if waits % 2:
            signal.getsignal(signal.SIGHUP)(signal.SIGHUP, None)
        return None

    def reload(path):
        nonlocal reloads
        for name, value in updates[reloads].items():
            monkeypatch.setattr(cfg, name, value)
        reloads += 1
        return True

    for backend in backends:
        backend.is_stale.return_value = False
        backend.verify_kernel_state.return_value = 0
        backend.last_apply_failures = 0
    receiver.wait.side_effect = wait
    monkeypatch.setattr(syncer, "NotificationReceiver", lambda *args, **kwargs: receiver)
    monkeypatch.setattr(syncer, "open_backend", opener)
    monkeypatch.setattr(syncer, "_reload_config", reload)
    monkeypatch.setattr(syncer, "sync_once", lambda backend, *args, **kwargs:
                        calls.append((backend, cfg.snapshot_config())))
    syncer.watch(False, backend_name, mode="enforce", monotonic=lambda: 100.0)
    assert reloads == len(updates)
    receiver.start.assert_called_once()
    receiver.close.assert_called_once()
    return opener, calls


@pytest.mark.parametrize("backend_name", ["xdp", "auto"])
@pytest.mark.parametrize("enabled", [False, True])
def test_icmp_toggles_reconcile_on_the_same_active_xdp_backend(monkeypatch, backend_name, enabled):
    monkeypatch.setattr(cfg, "ICMP_REPLY_ENABLED", enabled)
    backend = mock.Mock()
    backend.name = "xdp"
    opener, calls = _watch_config_reloads(monkeypatch, backend_name, [backend], [
        {"ICMP_REPLY_ENABLED": not enabled}, {"ICMP_REPLY_ENABLED": enabled},
    ])
    opener.assert_called_once_with(backend_name)
    assert [snapshot.ICMP_REPLY_ENABLED for _, snapshot in calls] == [enabled, not enabled, enabled]
    assert all(active is backend for active, _ in calls)
    backend.close.assert_called_once()  # Only watch shutdown owns the final close.


@pytest.mark.parametrize("setting,new_value", [
    ("BPF_PIN_DIR", "/sys/fs/bpf/other_generation"),
    ("NFT_FAMILY", "ip"),
    ("NFT_TABLE", "another_firewall"),
    ("NFT_TCP_SET", "another_tcp_set"),
    ("ABUSEIPDB_ENABLED", True),
    ("ABUSEIPDB_REFRESH_SECONDS", 17.0),
    ("PREFERRED_BACKEND", "nftables"),
])
def test_icmp_toggle_keeps_resource_and_backend_rebuilds(monkeypatch, setting, new_value):
    monkeypatch.setattr(cfg, "ICMP_REPLY_ENABLED", True)
    monkeypatch.setattr(cfg, "PREFERRED_BACKEND", "xdp")
    assert getattr(cfg, setting) != new_value
    original, replacement = mock.Mock(), mock.Mock()
    original.name = "xdp"
    replacement.name = "nftables" if setting == "PREFERRED_BACKEND" else "xdp"
    opener, calls = _watch_config_reloads(monkeypatch, "xdp", [original, replacement], [
        {"ICMP_REPLY_ENABLED": False, setting: new_value},
    ])
    assert opener.call_args_list == [mock.call("xdp"), mock.call(replacement.name)]
    assert calls[0][0] is original
    assert all(active is replacement for active, _ in calls[1:])
    assert calls[-1][1].values[setting] == new_value
    original.close.assert_called_once()
    replacement.close.assert_called_once()


def test_icmp_enable_reselects_an_auto_backend_currently_using_nftables(monkeypatch):
    monkeypatch.setattr(cfg, "ICMP_REPLY_ENABLED", False)
    original, replacement = mock.Mock(), mock.Mock()
    original.name, replacement.name = "nftables", "xdp"
    opener, calls = _watch_config_reloads(monkeypatch, "auto", [original, replacement], [
        {"ICMP_REPLY_ENABLED": True},
    ])
    assert opener.call_args_list == [mock.call("auto"), mock.call("auto")]
    assert calls[0][0] is original
    assert all(active is replacement for active, _ in calls[1:])
    assert calls[-1][1].ICMP_REPLY_ENABLED
    original.close.assert_called_once()
    replacement.close.assert_called_once()


def test_icmp_toggle_keeps_recovery_for_replaced_kernel_maps(monkeypatch):
    monkeypatch.setattr(cfg, "ICMP_REPLY_ENABLED", False)
    original, replacement = mock.Mock(), mock.Mock()
    original.name = replacement.name = "xdp"
    original.is_stale.side_effect = [True]
    opener, calls = _watch_config_reloads(monkeypatch, "xdp", [original, replacement], [
        {"ICMP_REPLY_ENABLED": True},
    ])
    assert opener.call_count == 2
    assert calls[0][0] is original
    assert all(active is replacement for active, _ in calls[1:])
    assert calls[-1][1].ICMP_REPLY_ENABLED
    original.is_stale.assert_called_once()
    original.close.assert_called_once()
    replacement.close.assert_called_once()
