"""Decoder for sock_state_rb ring buffer records.

Binary layout (must match bpf/sock_state_track.c struct sock_state_event):
  u64 ts_ns   — ktime_get_ns() timestamp
  u16 port    — local port, host byte order
  u8  proto   — IPPROTO_TCP=6, etc.
  u8  action  — 1=opened (entered LISTEN), 0=closed
  u8  family  — AF_INET=2, AF_INET6=10
  u8[3] pad
Total: 16 bytes.
"""
from __future__ import annotations

import struct
import time
from typing import Any

SOCK_STATE_EVENT_SIZE = 16

_STRUCT = struct.Struct("<QHBBB3x")

_PROTO_NAMES: dict[int, str] = {6: "tcp", 17: "udp", 132: "sctp"}
_AF_INET  = 2


class SockStateReader:
    """Thin wrapper around a RingBufReader that yields port_change dicts."""

    @staticmethod
    def decode_raw(raw: bytes) -> dict[str, Any] | None:
        if len(raw) < SOCK_STATE_EVENT_SIZE:
            return None
        ts_ns, port, proto, action, family = _STRUCT.unpack_from(raw)
        return {
            "type":    "port_change",
            "ts_ns":   ts_ns,
            "port":    port,
            "proto":   _PROTO_NAMES.get(proto, str(proto)),
            "action":  "open" if action == 1 else "close",
            "family":  4 if family == _AF_INET else 6,
            "seen_at": time.time(),
        }

    def __init__(self, rb: Any) -> None:
        """rb must be a RingBufReader (or duck-typed equivalent)."""
        self._rb = rb

    def drain(self):
        """Yield decoded port_change dicts from the ring buffer."""
        for raw in self._rb.drain():
            ev = self.decode_raw(raw)
            if ev is not None:
                yield ev

    def fileno(self) -> int:
        return self._rb.fileno()

    def close(self) -> None:
        self._rb.close()
