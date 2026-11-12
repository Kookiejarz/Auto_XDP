"""Receive listener-change hints without running discovery or touching maps."""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
import json
import logging
import select
import socket
import threading
import time

from auto_xdp.discovery.proc_events import drain_proc_events, open_proc_connector
from auto_xdp.telemetry.relay_client import MAX_MESSAGE_BYTES, MAX_READS_PER_POLL

log = logging.getLogger(__name__)
EVENT_SOURCE_RETRY_INTERVAL_SECONDS = 5.0


def _open_relay_client(sock_path: str) -> socket.socket | None:
    sock = None
    try:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.setblocking(False)
        sock.connect(sock_path)
    except BlockingIOError:
        pass
    except OSError:
        if sock is not None:
            sock.close()
        return None
    return sock


def _drain_relay_lines(sock: socket.socket, pending: bytearray | None = None) -> bool:
    """Read a bounded batch, retaining incomplete lines between polls."""
    if pending is None:
        pending = bytearray()
    found = False
    for _ in range(MAX_READS_PER_POLL):
        try:
            chunk = sock.recv(65536)
        except BlockingIOError:
            break
        if not chunk:
            raise ConnectionResetError("relay disconnected")
        pending.extend(chunk)
        if len(pending) > MAX_MESSAGE_BYTES:
            raise OSError("relay message exceeds buffer limit")
        while (line_end := pending.find(b"\n")) >= 0:
            raw_line = bytes(pending[:line_end])
            del pending[:line_end + 1]
            try:
                message = json.loads(raw_line)
            except (ValueError, UnicodeDecodeError, RecursionError):
                continue
            if isinstance(message, dict) and message.get("type") == "port_change":
                found = True
    return found


@dataclass(frozen=True)
class Notification:
    first_seen: float
    last_seen: float
    immediate: bool


class NotificationReceiver:
    def __init__(self, relay_path: str, *, monotonic: Callable[[], float] = time.monotonic) -> None:
        self._relay_path = relay_path
        self._monotonic = monotonic
        self._condition = threading.Condition()
        self._pending: Notification | None = None
        self._error: Exception | None = None
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, name="auto-xdp-notifications", daemon=True)

    def start(self) -> None:
        self._thread.start()

    def close(self) -> None:
        self._stop.set()
        if self._thread.ident is not None:
            self._thread.join()

    def _notify(self, *, immediate: bool) -> None:
        with self._condition:
            now = self._monotonic()
            previous = self._pending
            self._pending = Notification(
                previous.first_seen if previous is not None else now,
                now, immediate or (previous.immediate if previous is not None else False),
            )
            self._condition.notify()

    def wait(self, timeout: float) -> Notification | None:
        with self._condition:
            if self._pending is None and self._error is None:
                self._condition.wait(timeout)
            if self._error is not None:
                raise RuntimeError("listener notification receiver failed") from self._error
            pending, self._pending = self._pending, None
            return pending

    def _run(self) -> None:
        nl = relay = None
        relay_pending = bytearray()
        next_netlink = next_relay = 0.0
        try:
            while not self._stop.is_set():
                now = self._monotonic()
                if nl is None and now >= next_netlink:
                    next_netlink = now + EVENT_SOURCE_RETRY_INTERVAL_SECONDS
                    nl = open_proc_connector()
                    if nl is not None:
                        self._notify(immediate=True)
                if relay is None and now >= next_relay:
                    next_relay = now + EVENT_SOURCE_RETRY_INTERVAL_SECONDS
                    relay = _open_relay_client(self._relay_path)
                    if relay is not None:
                        log.info("Connected to pkt_relay for port_change events.")
                        # A reconnect can hide changes made during the gap.
                        self._notify(immediate=True)

                readers = [sock for sock in (nl, relay) if sock is not None]
                if not readers:
                    self._stop.wait(0.2)
                    continue
                try:
                    ready, _, _ = select.select(readers, [], [], 0.2)
                except OSError as exc:
                    log.warning("Notification polling failed (%s); reconnecting.", exc)
                    for sock in readers:
                        sock.close()
                    nl = relay = None
                    relay_pending.clear()
                    next_netlink = next_relay = self._monotonic() + EVENT_SOURCE_RETRY_INTERVAL_SECONDS
                    self._notify(immediate=True)
                    continue

                if nl is not None and nl in ready:
                    try:
                        if drain_proc_events(nl):
                            self._notify(immediate=False)
                    except OSError as exc:
                        log.warning("Netlink event error (%s); reconnecting proc connector.", exc)
                        nl.close()
                        nl = None
                        next_netlink = self._monotonic() + EVENT_SOURCE_RETRY_INTERVAL_SECONDS
                        self._notify(immediate=True)
                if relay is not None and relay in ready:
                    try:
                        if _drain_relay_lines(relay, relay_pending):
                            self._notify(immediate=True)
                    except OSError:
                        log.info("pkt_relay disconnected; retaining proc and periodic reconciliation.")
                        relay.close()
                        relay = None
                        relay_pending.clear()
                        next_relay = self._monotonic() + EVENT_SOURCE_RETRY_INTERVAL_SECONDS
                        self._notify(immediate=True)
        except Exception as exc:
            log.exception("Listener notification receiver failed.")
            with self._condition:
                self._error = exc
                self._condition.notify()
        finally:
            for owned_socket in (nl, relay):
                if owned_socket is not None:
                    owned_socket.close()
