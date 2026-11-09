"""Kernel program inventory, available modules, and their handler view."""
from __future__ import annotations

import json
import subprocess
import sys
import time
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

from auto_xdp import config as configuration
from auto_xdp.admin import handler_catalog, module_runtime
from auto_xdp.tui.layout import Column, table_columns, table_line
from auto_xdp.tui.widgets import _add, _box, _color, _CP_GREEN, _CP_MUTED, _CP_YELLOW, _CP_SELECTED


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
_INTERNAL_PROGRAM_PINS = {"prog", "sock_state_prog", "tc_egress_dispatch_prog",
                          "modules/syncookie/ingress"}


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
    module: handler_catalog.Module | None = None
    binding_kind: str = ""


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
    modules = configuration.module_configs(config)
    if modules.get("syncookie", {}).get("enabled", False):
        result[("SYNCOOKIE", 0)] = "builtin:syncookie"
    if modules.get("icmp", {}).get("enabled", False):
        result.update({("SLOT", key): "builtin:icmp" for key in (1, 58)})
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
        if key in (1, 58):
            return "modules/icmp/prog"
        return f"protocol_handlers/{key}/prog"
    if kind in {"TCP", "UDP"}:
        return f"port_handlers/{kind.lower()}/{key}/prog"
    if kind == "PROFILE":
        return f"profile_handlers/tcp/{key}/prog"
    return "modules/syncookie/prog"


def _pin_key(pin: str) -> tuple[str, int] | None:
    parts = Path(pin).parts
    try:
        if len(parts) == 3 and parts[0] == "protocol_handlers" and parts[2] in {"prog", "egress"}:
            return "TC_SLOT" if parts[2] == "egress" else "SLOT", int(parts[1])
        if len(parts) == 4 and parts[3] in {"prog", "egress"}:
            prefix = "TC_" if parts[3] == "egress" else ""
            if parts[0] == "port_handlers" and parts[1] in {"tcp", "udp"}:
                return prefix + parts[1].upper(), int(parts[2])
            if parts[:2] == ("profile_handlers", "tcp"):
                return prefix + "PROFILE", int(parts[2])
        if pin == "modules/syncookie/prog":
            return "SYNCOOKIE", 0
        if pin == "modules/icmp/prog":
            return "SLOT", 1
    except ValueError:
        pass
    return None


def collect_handlers(bpf_pin_dir: str, config: dict[str, Any], cache: HandlerCache,
                     *, generation: str = "", now: float | None = None,
                     context: handler_catalog.Context | None = None) -> HandlerInventory:
    now = time.monotonic() if now is None else now
    token = str(Path(bpf_pin_dir).resolve()) + ":" + generation + ":" + str(context)
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
        pinned_id = pins.get(pin)
        info = programs.get(program_id or pinned_id or -1, {})
        state = "loaded" if program_id else ("pin only" if pinned_id else "configured")
        if program_id is None and state_by_kind[kind] != "ready":
            state = "unknown" if state_by_kind[kind] == "unreadable" else "no map"
        detail = f"pin refers to program {pinned_id}" if program_id and pinned_id and program_id != pinned_id else ""
        if kind == "SYNCOOKIE" and program_id:
            tc_id = pins.get("modules/syncookie/ingress")
            interfaces = []
            if context is not None:
                from auto_xdp.admin.runtime import _load_env_file
                env = _load_env_file(context.config.parent / "auto_xdp.env")
                interfaces = env.get("IFACES", env.get("IFACE", context.iface)).split()
            if not tc_id:
                state, detail = "incomplete", "TC ingress companion is missing"
            elif not interfaces:
                state, detail = "unverified", f"TC ingress program {tc_id}; interfaces unavailable for attachment check"
            else:
                try:
                    attached = all(module_runtime.tc_program_id(iface) == tc_id for iface in interfaces)
                    if not attached or program_id != pinned_id:
                        state, detail = "incomplete", "Module hook does not match its ownership pin"
                    else:
                        detail = f"TC ingress program {tc_id} · {', '.join(interfaces)}"
                except (OSError, RuntimeError, subprocess.SubprocessError) as exc:
                    state, detail = "unknown", str(exc)
        rows.append(HandlerRow(kind, key, program_id or pinned_id, str(info.get("name") or "-"), state,
                               pin if pinned_id else "", configured.get((kind, key), ""), detail))
    # Runtime infrastructure is not an installable handler. Exclude every pin
    # alias of those programs while retaining actual dispatch entries/modules.
    represented = {row.program_id for row in rows} | {pins[pin] for pin in _INTERNAL_PROGRAM_PINS if pin in pins}
    for pin, program_id in sorted(pins.items()):
        if program_id in represented:
            continue
        info = programs.get(program_id, {})
        rows.append(HandlerRow("PROGRAM", program_id, program_id, str(info.get("name") or "-"), "pin only", pin,
                               detail="Program under this application's pin root; no module binding detected"))
        represented.add(program_id)
    inventory = HandlerInventory(rows, tables, "; ".join(errors) or "Kernel dispatch tables · read only")
    if context is not None:
        _include_catalog(inventory, context, config)
    cache.inventory, cache.refreshed_at, cache.generation = inventory, now, token
    return inventory


def _include_catalog(inventory: HandlerInventory, context: handler_catalog.Context, config: dict[str, Any]) -> None:
    modules = handler_catalog.discover(context, config)
    by_id = {module.id: module for module in modules if not module.error}
    by_path = {str(Path(module.path).resolve()): module for module in modules}
    configured = _configured(config)
    represented: set[str] = set()
    for index, row in enumerate(inventory.rows):
        kind = row.kind.removeprefix("TC_")
        binding_kind = "slot" if kind == "SLOT" else kind.lower()
        binding = config.get("handler_bindings", {}).get(binding_kind, {}).get(str(row.key), {})
        source = row.source or configured.get((kind, row.key), "")
        binding_matches = bool(source) and bool(binding.get("path")) and Path(source).resolve() == Path(str(binding["path"])).resolve()
        module = by_id.get(binding.get("module", "")) if binding_matches else None
        if module is None and source:
            module = by_id.get(source.removeprefix("builtin:")) if source.startswith("builtin:") else by_path.get(str(Path(source).resolve()))
        if module is None and kind == "PROFILE" and row.key == 1 and "minecraft" in row.name:
            module = by_id.get("minecraft")
        if module is None and kind == "SYNCOOKIE":
            module = by_id.get("syncookie")
        if module is None and row.pin == "modules/icmp/prog":
            module = by_id.get("icmp")
        if module is not None:
            inventory.rows[index] = replace(row, module=module)
            represented.add(module.id)
    icmp_rows = [row for row in inventory.rows if row.module is not None and row.module.id == "icmp"]
    if icmp_rows:
        first = next((row for row in icmp_rows if row.program_id is not None), icmp_rows[0])
        state, detail = first.state, first.detail
        if any(row.program_id is not None for row in icmp_rows):
            try:
                module_runtime.verify_icmp(context.bpf_pin_dir)
                state, detail = "loaded", "IPv4 + IPv6 Echo Reply protection · kernel dependency axdp_icmp"
            except (OSError, RuntimeError, subprocess.SubprocessError) as exc:
                state, detail = "incomplete", str(exc)
        inventory.rows = [row for row in inventory.rows if row not in icmp_rows]
        inventory.rows.append(replace(first, kind="ICMP", state=state, detail=detail, name="ICMP"))
    for module in modules:
        if module.id in represented:
            continue
        values = handler_catalog.settings(module, config)
        present = all(Path(path).is_file() for path in (module.path, *module.companions))
        state = "invalid" if module.error else ("build fail" if module.build_error else ("available" if present else "missing"))
        inventory.rows.append(HandlerRow("AVAILABLE", int(values.get("target", module.target)), None, module.name,
                                         state, source=module.path,
                                         detail=module.error or f"{module.id} · {module.hooks}", module=module,
                                         binding_kind=str(values.get("kind", module.kind))))
    inventory.status = inventory.status.replace("Kernel dispatch tables · read only", "Live dispatch + local module catalog")


def handler_capacity(height: int) -> int:
    return max(0, (height - 5) // 2)


def handler_labels(row: HandlerRow) -> tuple[str, str]:
    """Present program purpose and binding independently of observed state."""
    if row.kind == "PROGRAM":
        return {
            "prog": ("Firewall", "XDP ingress"),
            "sock_state_prog": ("Socket trace", "Tracepoint"),
            "tc_egress_dispatch_prog": ("TC dispatch", "TC egress"),
        }.get(row.pin, ("Pinned prog", "-"))
    if row.kind == "TC_SYNCOOKIE":
        return "SYN handoff", "TC in / SYN"
    if row.kind == "SYNCOOKIE":
        return "SYN cookie", "XDP + TC in / SYN"
    if row.kind == "ICMP":
        return "ICMP", "XDP / IPv4 + IPv6"
    kind = row.kind.removeprefix("TC_")
    hook = "TC out" if row.kind.startswith("TC_") else "XDP"
    if row.kind == "AVAILABLE":
        kind = (row.binding_kind or row.module.kind).upper() if row.module else "CUSTOM"
        kind = {"MINECRAFT": "PROFILE", "SYNCOOKIE": "SYNCOOKIE"}.get(kind, kind)
        hook = ""  # Catalog candidates have no observed dispatch hook yet.
    prefix = f"{hook} / " if hook else ""
    if kind == "SYNCOOKIE":
        return "SYN cookie", "SYN"
    if kind == "ICMP":
        return "ICMP", "IPv4 + IPv6 Echo Reply"
    if kind == "SLOT":
        protocol = f"/{_PROTOCOLS[row.key]}" if row.key in _PROTOCOLS else ""
        return "Protocol", f"{prefix}IP {row.key}{protocol}"
    if kind in {"TCP", "UDP"}:
        target = str(row.key) if row.key else "unset"
        return "Port handler", f"{prefix}{kind} {target}"
    if kind == "PROFILE":
        return "App profile", f"{prefix}TCP #{row.key}"
    return "Handler", "Not selected"


def draw_handlers(win: Any, inventory: HandlerInventory, scroll: int, cursor: int = -1) -> None:
    height, width = win.getmaxyx()
    active = sum(row.state == "loaded" for row in inventory.rows)
    _box(win, f"Handlers & slots / {active} loaded", focused=True)
    _add(win, 1, 2, inventory.status, _color(_CP_MUTED))
    columns = table_columns(width - 4, (
        Column("name", 18, 3), Column("state", 10, 0), Column("binding", 21, 2),
        Column("id", 8, 0, True)))
    _add(win, 2, 2, table_line(columns, dict(name="PROGRAM", state="STATE", binding="HOOK / TARGET", id="PROG ID")), _color(_CP_MUTED))
    visible = handler_capacity(height)
    scroll = max(0, min(scroll, max(0, len(inventory.rows) - visible)))
    for index, row in enumerate(inventory.rows[scroll:scroll + visible]):
        y = 3 + index * 2
        _, binding = handler_labels(row)
        warning = row.module.error or row.module.build_error if row.module else ""
        color = _CP_GREEN if row.state == "loaded" and not warning else _CP_YELLOW
        if warning:
            _add(win, y, 1, "⚠", _color(_CP_YELLOW))
        _add(win, y, 2, table_line(columns, dict(binding=binding, state=row.state,
                                              id=str(row.program_id or "-"), name=row.name)),
             _color(_CP_SELECTED if scroll + index == cursor else color))
        details = (["Last build/check failed · Enter configure, e errors"] if row.module and row.module.build_error else [])
        details += [f"config={row.source}" if row.source else "", f"pin={row.pin}" if row.pin else "", row.detail]
        _add(win, y + 1, 4, " · ".join(item for item in details if item) or "active dispatch entry; no ownership pin/config path", _color(_CP_MUTED))
    if not inventory.rows and visible:
        _add(win, 3, 2, "No loaded handlers, pinned candidates or configured slots.", _color(_CP_MUTED))
    summary = " · ".join(f"{kind.lower()} {count if count is not None else status}" for kind, status, count in inventory.tables)
    _add(win, height - 2, 2, summary, _color(_CP_MUTED))
    _add(win, height - 1, 2, f" {scroll + bool(inventory.rows)}-{min(scroll + visible, len(inventory.rows))}/{len(inventory.rows)} · ↑↓ select · Enter configure · i install · r refresh · h back ", _color(_CP_MUTED))
