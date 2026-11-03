"""Read-only dispatch inventory and a handler/slot view built from snapshots."""
from __future__ import annotations

import json
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from auto_xdp.tui.maps import _field
from auto_xdp.tui.widgets import _add, _box, _color, _CP_GREEN, _CP_MUTED, _CP_YELLOW


HANDLER_REFRESH_INTERVAL = 5.0
_TABLES = (
    ("proto_handlers", "SLOT"), ("tcp_port_handlers", "TCP"),
    ("udp_port_handlers", "UDP"), ("tcp_profile_handlers", "PROFILE"),
    ("tc_tcp_handlers", "TC_TCP"), ("tc_udp_handlers", "TC_UDP"), ("tc_proto_handlers", "TC_SLOT"),
    ("tc_profile_handlers", "TC_PROFILE"),
    ("syncookie_prog_array", "SYNCOOKIE"),
)
_BUILTINS = {"gre": 47, "esp": 50, "sctp": 132}
_PROTOCOLS = {1: "ICMP", 6: "TCP", 17: "UDP", 41: "IPv6", 47: "GRE", 50: "ESP", 58: "ICMPv6", 132: "SCTP"}


@dataclass(frozen=True)
class HandlerRow:
    kind: str
    key: int
    program_id: int | None
    name: str
    state: str
    pin: str = ""
    source: str = ""
    detail: str = ""


@dataclass
class HandlerInventory:
    rows: list[HandlerRow] = field(default_factory=list)
    tables: list[tuple[str, str, int | None]] = field(default_factory=list)
    status: str = "Waiting for dispatch inventory"


@dataclass
class HandlerCache:
    inventory: HandlerInventory = field(default_factory=HandlerInventory)
    refreshed_at: float | None = None
    generation: str = ""


def _query(*args: str) -> Any:
    return json.loads(subprocess.check_output(["bpftool", "-j", *args], stderr=subprocess.DEVNULL, timeout=2))


def _u32(value: Any) -> int:
    if isinstance(value, list) and len(value) == 4:
        value = int.from_bytes(bytes(int(v, 0) if isinstance(v, str) else v for v in value), sys.byteorder)
    elif isinstance(value, dict):
        value = _u32(value["id"] if "id" in value else value["value"])
    elif isinstance(value, str):
        value = int(value, 0)
    if type(value) is not int or not 0 <= value <= 0xFFFFFFFF:
        raise ValueError("invalid dispatch key or program ID")
    return value


def _dispatch_entries(data: Any) -> dict[int, int]:
    if not isinstance(data, list):
        raise ValueError("dispatch dump is not an array")
    entries = {}
    for row in data:
        if not isinstance(row, dict) or "error" in row:
            raise ValueError("unreadable dispatch entry")
        row = row if "key" in row else row["formatted"]
        key, program_id = _u32(row["key"]), _u32(row["value"])
        if program_id:
            entries[key] = program_id
    return entries


def _configured(config: dict[str, Any]) -> dict[tuple[str, int], str]:
    result = {}
    slots = config.get("slots", {})
    enabled = slots.get("enabled", []) if isinstance(slots, dict) else []
    for entry in enabled if isinstance(enabled, list) else []:
        if isinstance(entry, str) and entry in _BUILTINS:
            result[("SLOT", _BUILTINS[entry])] = f"builtin:{entry}"
        elif isinstance(entry, dict):
            try:
                number = int(entry["proto"])
                if 0 <= number <= 255:
                    result[("SLOT", number)] = str(entry.get("path") or "configured")
            except (KeyError, TypeError, ValueError):
                pass
    handlers = config.get("port_handlers", {})
    for proto in ("tcp", "udp"):
        table = handlers.get(proto, {}) if isinstance(handlers, dict) else {}
        if not isinstance(table, dict):
            continue
        for port, path in table.items():
            try:
                number = int(port)
                if 1 <= number <= 65535 and path:
                    result[(proto.upper(), number)] = str(path)
            except (TypeError, ValueError):
                pass
    return result


def _expected_pin(kind: str, key: int) -> str:
    if kind.startswith("TC_"):
        return _expected_pin(kind.removeprefix("TC_"), key).removesuffix("prog") + "egress"
    if kind == "SLOT":
        return f"protocol_handlers/{key}/prog"
    if kind in {"TCP", "UDP"}:
        return f"port_handlers/{kind.lower()}/{key}/prog"
    if kind == "PROFILE":
        return f"profile_handlers/tcp/{key}/prog"
    return "syncookie_prog"


def _pin_key(pin: str) -> tuple[str, int] | None:
    parts = Path(pin).parts
    try:
        if len(parts) == 2 and parts[0] == "handlers" and parts[1].startswith("proto_"):
            return "SLOT", int(parts[1].removeprefix("proto_"))
        if len(parts) == 3 and parts[0] == "protocol_handlers" and parts[2] in {"prog", "egress"}:
            return "TC_SLOT" if parts[2] == "egress" else "SLOT", int(parts[1])
        if len(parts) == 4 and parts[3] in {"prog", "egress"}:
            prefix = "TC_" if parts[3] == "egress" else ""
            if parts[0] == "port_handlers" and parts[1] in {"tcp", "udp"}:
                return prefix + parts[1].upper(), int(parts[2])
            if parts[:2] == ("profile_handlers", "tcp"):
                return prefix + "PROFILE", int(parts[2])
        if pin == "syncookie_prog":
            return "SYNCOOKIE", 0
    except ValueError:
        pass
    return None


def collect_handlers(bpf_pin_dir: str, config: dict[str, Any], cache: HandlerCache,
                     *, generation: str = "", now: float | None = None) -> HandlerInventory:
    now = time.monotonic() if now is None else now
    token = str(Path(bpf_pin_dir).resolve()) + ":" + generation
    if cache.refreshed_at is not None and cache.generation == token and now - cache.refreshed_at < HANDLER_REFRESH_INTERVAL:
        return cache.inventory
    root = Path(bpf_pin_dir).resolve()
    programs: dict[int, dict[str, Any]] = {}
    pins: dict[str, int] = {}
    errors = []
    try:
        data = _query("-f", "prog", "show")
        if not isinstance(data, list):
            raise ValueError("program inventory is not an array")
        for program in data:
            if not isinstance(program, dict) or type(program.get("id")) is not int:
                continue
            programs[program["id"]] = program
            program_pins = program.get("pinned", [])
            for pin in program_pins if isinstance(program_pins, list) else []:
                try:
                    relative = str(Path(pin).relative_to(root))
                except (TypeError, ValueError):
                    continue
                pins[relative] = program["id"]
    except (OSError, ValueError, subprocess.SubprocessError):
        errors.append("program metadata unavailable")
    configured = _configured(config)
    candidates = set(configured)
    for pin in pins:
        entry_key = _pin_key(pin)
        if entry_key is not None:
            candidates.add(entry_key)
    active: dict[tuple[str, int], int] = {}
    tables = []
    state_by_kind = {}
    for name, kind in _TABLES:
        path = root / name
        status = "missing"
        count = None
        if path.exists():
            try:
                entries = _dispatch_entries(_query("map", "dump", "pinned", str(path)))
                active.update(((kind, key), value) for key, value in entries.items())
                candidates.update((kind, key) for key in entries)
                status, count = "ready", len(entries)
            except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
                status = "unreadable"
                errors.append(f"{name} unreadable")
        state_by_kind[kind] = status
        tables.append((kind, status, count))
    rows = []
    order = {kind: index for index, (_, kind) in enumerate(_TABLES)}
    for kind, key in sorted(candidates, key=lambda item: (order[item[0]], item[1])):
        program_id = active.get((kind, key))
        pin = _expected_pin(kind, key)
        if kind == "SLOT":
            options = [pin, f"handlers/proto_{key}"]
            pin = next((item for item in options if program_id and pins.get(item) == program_id),
                       next((item for item in options if item in pins), pin))
        pinned_id = pins.get(pin)
        info = programs.get(program_id or pinned_id or -1, {})
        state = "loaded" if program_id else ("pin only" if pinned_id else "configured")
        if program_id is None and state_by_kind[kind] != "ready":
            state = "unknown" if state_by_kind[kind] == "unreadable" else "no map"
        detail = f"pin refers to program {pinned_id}" if program_id and pinned_id and program_id != pinned_id else ""
        rows.append(HandlerRow(kind, key, program_id or pinned_id, str(info.get("name") or "-"), state,
                               pin if pinned_id else "", configured.get((kind, key), ""), detail))
    inventory = HandlerInventory(rows, tables, "; ".join(errors) or "Kernel dispatch tables · read only")
    cache.inventory, cache.refreshed_at, cache.generation = inventory, now, token
    return inventory


def handler_capacity(height: int) -> int:
    return max(0, (height - 5) // 2)


def draw_handlers(win: Any, inventory: HandlerInventory, scroll: int) -> None:
    height, width = win.getmaxyx()
    active = sum(row.state == "loaded" for row in inventory.rows)
    _box(win, f"Handlers & slots / {active} loaded", focused=True)
    _add(win, 1, 2, inventory.status, _color(_CP_MUTED))
    _add(win, 2, 2, f"{'TYPE':<10} {'TARGET':<12} {'STATE':<11} {'PROG ID':>8}  PROGRAM", _color(_CP_MUTED))
    visible = handler_capacity(height)
    scroll = max(0, min(scroll, max(0, len(inventory.rows) - visible)))
    for index, row in enumerate(inventory.rows[scroll:scroll + visible]):
        y = 3 + index * 2
        target = f"{row.key}/{_PROTOCOLS[row.key]}" if row.kind == "SLOT" and row.key in _PROTOCOLS else str(row.key)
        color = _CP_GREEN if row.state == "loaded" else _CP_YELLOW
        _add(win, y, 2, f"{row.kind:<10} {target:<12} {row.state:<11} {str(row.program_id or '-'):>8}  "
             + _field(row.name, max(1, width - 49)), _color(color))
        details = [f"config={row.source}" if row.source else "", f"pin={row.pin}" if row.pin else "", row.detail]
        _add(win, y + 1, 4, " · ".join(item for item in details if item) or "active dispatch entry; no ownership pin/config path", _color(_CP_MUTED))
    if not inventory.rows and visible:
        _add(win, 3, 2, "No loaded handlers, pinned candidates or configured slots.", _color(_CP_MUTED))
    summary = " · ".join(f"{kind.lower()} {count if count is not None else status}" for kind, status, count in inventory.tables)
    _add(win, height - 2, 2, summary, _color(_CP_MUTED))
    _add(win, height - 1, 2, f" {scroll + bool(inventory.rows)}-{min(scroll + visible, len(inventory.rows))}/{len(inventory.rows)} · h back · loaded=dispatch entry · pin only=not dispatched ", _color(_CP_MUTED))
