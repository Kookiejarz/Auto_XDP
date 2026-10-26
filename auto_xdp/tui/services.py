"""Match event destinations to the current, already collected service inventory."""
from __future__ import annotations

import ipaddress
from typing import Any


_Address = ipaddress.IPv4Address | ipaddress.IPv6Address


def _address(value: Any) -> _Address | None:
    try:
        address = ipaddress.ip_address(str(value))
    except ValueError:
        return None
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        return address.ipv4_mapped
    return address


def _service_key(proto: Any, port: Any) -> tuple[str, int] | None:
    protocol = str(proto).upper()
    if isinstance(port, bool) or not isinstance(port, (int, str)):
        return None
    try:
        number = int(port)
    except (ValueError, TypeError):
        return None
    if protocol not in {"TCP", "UDP"} or not 1 <= number <= 65535:
        return None
    return protocol, number


class EventServices:
    """A per-frame index; no socket, process, filesystem or BPF reads here.

    Labels describe the current inventory, not ownership at the event's timestamp.
    A services database name alone is explicitly marked ``port:name``.
    """

    def __init__(self, snap: Any) -> None:
        self._port_names: dict[tuple[str, int], str] = {}
        self._endpoints: dict[tuple[str, int], list[tuple[_Address | None, str]]] = {}
        for proto, port, name, _, _ in getattr(snap, "ports", []):
            key = _service_key(proto, port)
            if key is not None and name not in {"", "-", "unknown"}:
                self._port_names[key] = str(name)
        for row in getattr(snap, "audit_rows", []):
            key = _service_key(row.get("protocol"), row.get("port"))
            if key is None:
                continue
            subject = str(row.get("subject") or "unknown")
            if row.get("attribution") == "ambiguous" or subject in {"", "-", "unknown"}:
                subject = "unknown"
            self._endpoints.setdefault(key, []).append((_address(row.get("address")), subject))

    def label(self, event: dict[str, Any]) -> str:
        port = event.get("port") if event.get("type") == "port_change" else event.get("dport")
        key = _service_key(event.get("proto"), port)
        if key is None:
            return "-"
        rows = self._endpoints.get(key)
        if not rows:
            name = self._port_names.get(key)
            return f"port:{name}" if name else "unknown"
        destination = _address(event.get("dst"))
        if destination is not None:
            rows = [(address, subject) for address, subject in rows
                    if address is not None and
                    (address == destination or (address.is_unspecified and address.version == destination.version))]
        subjects = {subject for _, subject in rows}
        if not subjects:
            return "unknown"
        if len(subjects) > 1:
            return "ambiguous"
        return subjects.pop()
