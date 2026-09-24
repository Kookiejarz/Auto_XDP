"""Bounded Unix-socket event client, independent of curses and BPF access."""
from __future__ import annotations

import json
import select
import socket
import time
from collections import Counter
from typing import Any


MAX_MESSAGE_BYTES = 8 * 1024 * 1024
MAX_READS_PER_POLL = 8


class RelayClient:
    def __init__(self, path: str, max_events: int = 500) -> None:
        if isinstance(max_events, bool) or not isinstance(max_events, int) or max_events < 1:
            raise ValueError("max_events must be a positive integer")
        self.path = path
        self.max_events = max_events
        self.events: list[dict[str, Any]] = []
        self.events_offset = 0
        self.status = "relay: disconnected"
        self.ports_dirty = False
        self.telemetry_status: dict[str, Any] = {}
        self.history_available: int | None = None
        self.history_truncated = False
        self.session_id: str | None = None
        self._last_seq = -1
        self._sock: socket.socket | None = None
        self._buf = bytearray()
        self._next_retry = 0.0

    @property
    def events_end(self) -> int:
        return self.events_offset + len(self.events)

    @property
    def reason_totals(self) -> dict[str, int]:
        """DROP distribution for exactly the retained event window."""
        return dict(Counter(str(ev.get("reason") or "unknown") for ev in self.events
                            if ev.get("verdict") == "DROP"))

    def close(self) -> None:
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
        self._sock = None
        self._buf.clear()

    def _session(self, value: Any) -> None:
        if isinstance(value, str) and value and value != self.session_id:
            self.session_id = value
            self._last_seq = -1
            self.telemetry_status = {}

    def _message(self, msg: Any) -> None:
        if not isinstance(msg, dict):
            return
        kind = msg.get("type")
        if not isinstance(kind, str):
            return
        if kind == "history":
            history = msg.get("events")
            if not isinstance(history, list):
                return
            session = msg.get("session_id")
            self._session(session)
            available = msg.get("available_events")
            self.history_available = available if type(available) is int and available >= 0 else len(history)
            self.history_truncated = msg.get("truncated") is True or len(history) > self.max_events
            if not session:
                # Old relays lack packet identity. Their history is a replacement
                # snapshot, never an additional batch to count a second time.
                self.events_offset += len(self.events)
                self.events.clear()
            for event in history[-self.max_events:]:
                if isinstance(event, dict):
                    self._append(dict(event, session_id=event.get("session_id", session)))
        elif kind in {"event", "port_change"}:
            self._append(msg)
        elif kind == "telemetry_status":
            self._session(msg.get("session_id"))
            self.telemetry_status = dict(msg)

    def _consume(self) -> None:
        while True:
            nl = self._buf.find(b"\n")
            if nl < 0:
                return
            line = bytes(self._buf[:nl])
            del self._buf[:nl + 1]
            if not line:
                continue
            try:
                self._message(json.loads(line))
            except (ValueError, UnicodeDecodeError, RecursionError):
                continue

    def poll(self) -> None:
        now = time.monotonic()
        if self._sock is None:
            if now < self._next_retry:
                return
            self._next_retry = now + 2.0
            pending: socket.socket | None = None
            try:
                pending = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                pending.setblocking(False)
                pending.connect(self.path)
            except BlockingIOError:
                self._sock = pending
                self.status = "relay: connecting"
            except OSError as exc:
                if pending is not None:
                    pending.close()
                self.status = ("relay: socket missing; run `sudo systemctl restart auto-xdp-relay`"
                               if exc.errno == 2 else f"relay: {exc.strerror or exc}")
                return
            else:
                self._sock = pending
                self.status = "relay: connected"

        sock = self._sock
        if sock is None:
            return
        try:
            readable, _, _ = select.select([sock], [], [], 0)
        except (OSError, ValueError):
            self.close()
            self.status = "relay: disconnected"
            return
        if not readable:
            return
        # A continuously busy relay must yield to keyboard handling and redraws.
        for _ in range(MAX_READS_PER_POLL):
            try:
                chunk = sock.recv(65536)
            except BlockingIOError:
                break
            except OSError:
                self.close()
                self.status = "relay: disconnected"
                break
            if not chunk:
                self.close()
                self.status = "relay: disconnected"
                break
            self._buf.extend(chunk)
            if len(self._buf) > MAX_MESSAGE_BYTES:
                self.close()
                self.status = "relay: message exceeds buffer limit"
                break
            self._consume()
            self.status = "relay: connected"

    def _append(self, event: dict[str, Any]) -> None:
        if not isinstance(event, dict):
            return
        session, seq = event.get("session_id"), event.get("seq")
        if session is not None:
            if not isinstance(session, str) or not session or type(seq) is not int or seq < 0:
                return
            self._session(session)
            if seq <= self._last_seq:
                return
            self._last_seq = seq
        event = dict(event)
        event.setdefault("seen_at", time.time())
        if event.get("type") == "port_change":
            self.ports_dirty = True
        self.events.append(event)
        if len(self.events) > self.max_events:
            drop_count = len(self.events) - self.max_events
            del self.events[:drop_count]
            self.events_offset += drop_count
