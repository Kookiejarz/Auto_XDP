"""Explicit, versioned state compatibility for live service-handler replacement."""
from __future__ import annotations

import hashlib
import json
import re
import struct
from pathlib import Path
from typing import NamedTuple
from collections.abc import Mapping


class StateContract(NamedTuple):
    schema: str
    maps: tuple[str, ...]


def object_contract(path: Path) -> StateContract | None:
    """Read a bounded opt-in section without loading or executing an ELF object."""
    data = path.read_bytes()
    if not data.startswith(b"\x7fELF"):
        return None  # libbpf remains responsible for ordinary object validation.
    try:
        if len(data) < 64 or data[4:6] not in (b"\x02\x01", b"\x02\x02"):
            raise ValueError("expected a 64-bit BPF ELF")
        order = "<" if data[5] == 1 else ">"
        offset = struct.unpack_from(order + "Q", data, 40)[0]
        size, count, names_index = struct.unpack_from(order + "HHH", data, 58)
        if size < 64 or not count or names_index >= count or offset + size * count > len(data):
            raise ValueError("invalid section table")

        def section(index: int) -> tuple[int, bytes]:
            header = offset + size * index
            name = struct.unpack_from(order + "I", data, header)[0]
            start, length = struct.unpack_from(order + "QQ", data, header + 24)
            if start + length > len(data):
                # NOBITS sections have no payload and cannot carry our contract.
                if struct.unpack_from(order + "I", data, header + 4)[0] == 8:
                    return name, b""
                raise ValueError("section exceeds object")
            return name, data[start:start + length]

        _, names = section(names_index)
        payloads = []
        for index in range(count):
            name, payload = section(index)
            if name >= len(names):
                raise ValueError("invalid section name")
            if names[name:].split(b"\0", 1)[0] == b".axdp_state":
                payloads.append(payload)
        if not payloads:
            return None
        if len(payloads) != 1 or len(payloads[0]) > 4096:
            raise ValueError("invalid state section length/count")
        contract = json.loads(payloads[0].rstrip(b"\0"))
        if not isinstance(contract, dict) or set(contract) != {"version", "schema", "maps"}:
            raise ValueError("invalid state contract fields")
        schema, maps = contract["schema"], contract["maps"]
        if contract["version"] != 1 or not isinstance(schema, str) or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", schema):
            raise ValueError("unsupported state contract/schema")
        if not isinstance(maps, list) or len(maps) > 64 or any(
            not isinstance(name, str) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,63}", name)
            for name in maps
        ) or len(set(maps)) != len(maps):
            raise ValueError("invalid persistent map list")
        return StateContract(schema, tuple(sorted(maps)))
    except (ValueError, KeyError, IndexError, struct.error, UnicodeError) as exc:
        raise RuntimeError(f"Invalid handler state contract in {path}: {exc}") from exc


def fingerprint(contract: StateContract, maps: Mapping[str, tuple[int, ...]]) -> bytes:
    missing = set(contract.maps) - maps.keys()
    if missing:
        raise RuntimeError(f"State contract references missing maps: {', '.join(sorted(missing))}")
    # Plain data maps only. Program arrays, map-in-map and kernel-object storage
    # require a different lifetime/ownership protocol and are intentionally denied.
    for name in contract.maps:
        if maps[name][0] not in {1, 2, 5, 6, 9, 10}:
            raise RuntimeError(f"Unsupported persistent state map type: {name}")
    material = [1, contract.schema, [(name, maps[name]) for name in contract.maps]]
    return hashlib.sha256(json.dumps(material, separators=(",", ":")).encode()).digest()
