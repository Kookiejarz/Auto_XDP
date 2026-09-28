from __future__ import annotations

import argparse
import ctypes
import datetime as _dt
import errno
from importlib import resources
import json
import math
import os
import re
import secrets
import socket
import struct
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

from auto_xdp import config as cfg
from auto_xdp.admin import stats
from auto_xdp.admin import handlers
from auto_xdp.admin import ports
from auto_xdp.admin import formatting
from auto_xdp.admin import config_file
from auto_xdp import approvals
from auto_xdp import policy
from auto_xdp.discovery import listeners as discovery
from auto_xdp.admin.detect import detect_backend as _detect_backend
from auto_xdp.bpf.syscall import (
    BPF_MAP_DELETE_ELEM,
    BPF_MAP_GET_NEXT_KEY,
    BPF_MAP_LOOKUP_BATCH,
    BPF_MAP_LOOKUP_ELEM,
    bpf,
    map_max_entries,
    map_value_size,
    obj_get,
)
from auto_xdp.discovery.listeners import _build_systemd_socket_map

try:
    import tomllib  # Python 3.11+
except ImportError:
    try:
        import tomli as tomllib
    except ImportError:
        tomllib = None


_LOG_LEVELS = {"debug", "info", "warning", "error"}


def _write_stdout(text: str) -> None:
    sys.stdout.write(text)
    if not text.endswith("\n"):
        sys.stdout.write("\n")


def _normalize_cidr(value: str) -> str:
    try:
        return cfg.normalize_cidr(value)
    except ValueError as exc:
        raise ValueError(f"invalid IPv4/IPv6 address or CIDR: {value}") from exc


def _normalize_ports(values: list[int]) -> list[int]:
    ports = sorted({int(port) for port in values})
    for port in ports:
        if port <= 0 or port > 65535:
            raise ValueError(f"invalid port: {port}")
    return ports


def _slot_paths(args: argparse.Namespace) -> tuple[Path, Path, Path]:
    bpf_pin_dir = Path(args.bpf_pin_dir)
    install_dir = Path(args.install_dir)
    if args.handlers_dir:
        handlers_dir = Path(args.handlers_dir)
    else:
        handlers_dir = install_dir / "handlers"
    return bpf_pin_dir, install_dir, handlers_dir


def _builtin_handlers_dir(args: argparse.Namespace) -> Path:
    return Path(args.install_dir) / "handlers"


def _cmd_config_show(args: argparse.Namespace) -> int:
    path = Path(args.config)
    if not path.exists():
        print(f"(no config file at {path} — run: axdp config init)")
        return 0
    _write_stdout(path.read_text())
    return 0


def _cmd_config_init(args: argparse.Namespace) -> int:
    path = Path(args.config)
    if path.exists():
        print(f"Config already exists: {path}  (use 'axdp config show' to view)")
        return 0
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(config_file.default_config_template())
    path.chmod(0o600)
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        os.chown(path, 0, 0)
    print(f"Created: {path}")
    return 0


def _cmd_log_level(args: argparse.Namespace) -> int:
    path, data = config_file.load_config(args.config)
    if not args.level:
        print(str(data.get("daemon", {}).get("log_level", "warning")).lower())
        return 0

    level = args.level.lower()
    if level not in _LOG_LEVELS:
        print(f"Invalid log level: {level}", file=sys.stderr)
        print("Valid values: debug, info, warning, error", file=sys.stderr)
        return 1

    daemon = data.setdefault("daemon", {})
    daemon["log_level"] = level
    config_file.write_toml(path, data)
    print(f"daemon.log_level={level}")
    return 0


def _cmd_under_attack(args: argparse.Namespace) -> int:
    path, data = config_file.load_config(args.config)
    under_attack = data.setdefault("under_attack", {})

    if not args.mode:
        enabled = bool(under_attack.get("enabled", False))
        print("on" if enabled else "off")
        return 0

    mode = args.mode.lower()
    if mode not in {"on", "off"}:
        print(f"Invalid under_attack mode: {mode}", file=sys.stderr)
        print("Valid values: on, off", file=sys.stderr)
        return 1

    enabled = mode == "on"
    under_attack["enabled"] = enabled
    config_file.write_toml(path, data)
    print(f"under_attack.enabled={'true' if enabled else 'false'}")
    return 0


def _cmd_trust_list(args: argparse.Namespace) -> int:
    _, data = config_file.load_config(args.config)
    trusted = data.get("trusted_ips", {})
    if not trusted:
        print("  (none)")
        return 0
    rows = sorted((_normalize_cidr(cidr), str(label)) for cidr, label in trusted.items())
    for cidr, label in rows:
        print(f"  {cidr:<20}  {label}")
    return 0


def _cmd_trust_add(args: argparse.Namespace) -> int:
    path, data = config_file.load_config(args.config)
    cidr = _normalize_cidr(args.cidr)
    data.setdefault("trusted_ips", {})[cidr] = args.label
    config_file.write_toml(path, data)
    print(f"Added trusted: {cidr} ({args.label})")
    return 0


def _cmd_trust_del(args: argparse.Namespace) -> int:
    path, data = config_file.load_config(args.config)
    cidr = _normalize_cidr(args.cidr)
    data.setdefault("trusted_ips", {}).pop(cidr, None)
    config_file.write_toml(path, data)
    print(f"Removed trusted: {cidr}")
    return 0


def _cmd_acl_list(args: argparse.Namespace) -> int:
    _, data = config_file.load_config(args.config)
    rules = data.get("acl", [])
    if not rules:
        print("  (none)")
        return 0
    normalized: list[tuple[str, str, list[int]]] = []
    for rule in rules:
        proto = str(rule["proto"]).lower()
        cidr = _normalize_cidr(str(rule["cidr"]))
        ports = _normalize_ports([int(port) for port in rule.get("ports", [])])
        normalized.append((proto, cidr, ports))
    for proto, cidr, ports in sorted(normalized, key=lambda item: (item[0], item[1])):
        joined = " ".join(str(port) for port in ports)
        print(f"  {proto.upper():<4}  {cidr:<22}  ports: {joined}")
    return 0


def _cmd_acl_add(args: argparse.Namespace) -> int:
    path, data = config_file.load_config(args.config)
    cidr = _normalize_cidr(args.cidr)
    ports = _normalize_ports(args.ports)
    rules = data.setdefault("acl", [])
    rules = [
        rule
        for rule in rules
        if not (
            str(rule.get("proto", "")).lower() == args.proto
            and _normalize_cidr(str(rule.get("cidr"))) == cidr
        )
    ]
    rules.append({"proto": args.proto, "cidr": cidr, "ports": ports})
    data["acl"] = rules
    config_file.write_toml(path, data)
    print(f"Added ACL: {args.proto} {cidr} ports {' '.join(str(port) for port in ports)}")
    return 0


def _cmd_acl_del(args: argparse.Namespace) -> int:
    path, data = config_file.load_config(args.config)
    cidr = _normalize_cidr(args.cidr)
    data["acl"] = [
        rule
        for rule in data.get("acl", [])
        if not (
            str(rule.get("proto", "")).lower() == args.proto
            and _normalize_cidr(str(rule.get("cidr"))) == cidr
        )
    ]
    config_file.write_toml(path, data)
    print(f"Removed ACL: {args.proto} {cidr}")
    return 0


def _cmd_slot_enable_builtin(args: argparse.Namespace) -> int:
    path, data = config_file.load_config(args.config)
    slots = data.setdefault("slots", {})
    enabled = slots.setdefault("enabled", [])
    if args.name not in enabled:
        enabled.append(args.name)
    config_file.write_toml(path, data)
    return 0


def _cmd_slot_enable_custom(args: argparse.Namespace) -> int:
    path, data = config_file.load_config(args.config)
    slots = data.setdefault("slots", {})
    enabled = slots.setdefault("enabled", [])
    enabled = [entry for entry in enabled if not (isinstance(entry, dict) and entry.get("proto") == args.proto)]
    enabled.append({"proto": args.proto, "path": args.path})
    slots["enabled"] = enabled
    config_file.write_toml(path, data)
    return 0


def _cmd_slot_disable(args: argparse.Namespace) -> int:
    path, data = config_file.load_config(args.config)
    builtin_name = handlers.BUILTIN_SLOT_PROTO.get(args.proto)
    slots = data.setdefault("slots", {})
    enabled = slots.get("enabled", [])
    slots["enabled"] = [
        entry
        for entry in enabled
        if not (isinstance(entry, str) and entry == builtin_name)
        and not (isinstance(entry, dict) and int(entry.get("proto", -1)) == args.proto)
    ]
    config_file.write_toml(path, data)
    return 0


def _cmd_slot_list(args: argparse.Namespace) -> int:
    bpf_pin_dir, _, _ = _slot_paths(args)
    handlers_dir = _builtin_handlers_dir(args)
    slot_pin_dir = bpf_pin_dir / "handlers"
    proto_handlers = bpf_pin_dir / "proto_handlers"

    if not proto_handlers.exists():
        print("Loaded handlers:\n  XDP not running (proto_handlers map not found).\n")
    else:
        print("Loaded handlers:")
        found = False
        for pin in sorted(slot_pin_dir.glob("proto_*")):
            if not pin.is_file():
                continue
            proto = pin.name.removeprefix("proto_")
            name = handlers.slot_prog_name(pin)
            print(f"  proto {proto:<5} {name}")
            found = True
        if not found:
            print("  (none)")
        print("")
    print("Available handlers:")
    for name in handlers.BUILTIN_SLOT_INFO:
        proto_num, obj_name = handlers.BUILTIN_SLOT_INFO[name]
        obj_path = handlers_dir / obj_name
        pin_path = slot_pin_dir / f"proto_{proto_num}"
        if obj_path.exists():
            if pin_path.exists():
                print(f"  {name:<6} (proto {proto_num})  [loaded]")
            else:
                print(f"  {name:<6} (proto {proto_num})")
        else:
            print(f"  {name:<6} (proto {proto_num})  [.o not found: {obj_path}]")
    return 0


def _cmd_slot_load(args: argparse.Namespace) -> int:
    path = Path(args.config)
    bpf_pin_dir, _, handlers_dir = _slot_paths(args)
    builtin_handlers_dir = _builtin_handlers_dir(args)
    slot_ctx_map = bpf_pin_dir / "slot_ctx_map"
    proto_handlers = bpf_pin_dir / "proto_handlers"
    slot_pin_dir = bpf_pin_dir / "handlers"

    builtin_name = ""
    if args.name_or_proto in handlers.BUILTIN_SLOT_INFO:
        builtin_name = args.name_or_proto
        proto, obj_name = handlers.BUILTIN_SLOT_INFO[builtin_name]
        obj_path = builtin_handlers_dir / obj_name
    elif args.name_or_proto.isdigit():
        proto = int(args.name_or_proto)
        if not args.path:
            print("Custom handler requires a .o or .c path: axdp slot load PROTO /path/to/handler.o", file=sys.stderr)
            return 1
        custom_path = Path(args.path)
        if custom_path.suffix == ".c":
            try:
                obj_path = handlers.compile_handler_source(
                    custom_path, proto, handlers_dir, sdk_dir=builtin_handlers_dir
                )
            except RuntimeError as exc:
                print(str(exc), file=sys.stderr)
                return 1
        else:
            obj_path = custom_path
    else:
        print(f"Unknown handler: {args.name_or_proto} (built-in: gre, esp, sctp)", file=sys.stderr)
        return 1

    if not obj_path.is_file():
        print(f"Handler object not found: {obj_path}", file=sys.stderr)
        return 1
    if not slot_ctx_map.exists():
        print("XDP not loaded (slot_ctx_map not found). Run setup first.", file=sys.stderr)
        return 1
    if not proto_handlers.exists():
        print("XDP not loaded (proto_handlers map not found).", file=sys.stderr)
        return 1

    slot_pin_dir.mkdir(parents=True, exist_ok=True)
    pin_path = slot_pin_dir / f"proto_{proto}"
    candidate_pin = slot_pin_dir / f"proto_{proto}_next_{secrets.token_hex(4)}"

    load_cmd = [
        "bpftool",
        "prog",
        "load",
        str(obj_path),
        str(candidate_pin),
        "type",
        "xdp",
        "map",
        "name",
        "slot_ctx_map",
        "pinned",
        str(slot_ctx_map),
    ]

    if proto == 132 and builtin_name == "sctp":
        sctp_whitelist = bpf_pin_dir / "sctp_whitelist"
        if not sctp_whitelist.exists():
            print("XDP not loaded completely (sctp_whitelist map not found).", file=sys.stderr)
            return 1
        load_cmd.extend(
            [
                "map",
                "name",
                "sctp_whitelist",
                "pinned",
                str(sctp_whitelist),
            ]
        )

    try:
        handlers.run_checked(load_cmd, f"Failed to load {obj_path}")
    except RuntimeError as exc:
        if candidate_pin.exists():
            candidate_pin.unlink()
        print(str(exc), file=sys.stderr)
        return 1

    try:
        handlers.transactional_file_prog_swap(proto_handlers, proto, candidate_pin, pin_path)
    except RuntimeError as exc:
        print(str(exc), file=sys.stderr)
        return 1

    print(f"Loaded handler for proto {proto} from {obj_path}")
    config_file.ensure_config_exists(path)
    if builtin_name:
        _cmd_slot_enable_builtin(argparse.Namespace(config=str(path), name=builtin_name))
    else:
        _cmd_slot_enable_custom(argparse.Namespace(config=str(path), proto=proto, path=str(obj_path)))
    print(f"  config: {path}")
    return 0


def _cmd_slot_unload(args: argparse.Namespace) -> int:
    path = Path(args.config)
    bpf_pin_dir, _, _ = _slot_paths(args)
    slot_pin_dir = bpf_pin_dir / "handlers"
    proto_handlers = bpf_pin_dir / "proto_handlers"
    target = args.name_or_proto

    if target.isdigit():
        proto = int(target)
    else:
        proto = None
        for pin in sorted(slot_pin_dir.glob("proto_*")):
            if not pin.is_file():
                continue
            name = handlers.slot_prog_name(pin)
            if name == target or f"_{target}_" in name or name.endswith(f"_{target}"):
                proto = int(pin.name.removeprefix("proto_"))
                break
        if proto is None:
            print(f"No loaded handler matches: {target}", file=sys.stderr)
            return 1

    subprocess.run(
        [
            "bpftool",
            "map",
            "delete",
            "pinned",
            str(proto_handlers),
            "key",
            str(proto),
            "0",
            "0",
            "0",
        ],
        capture_output=True,
        text=True,
    )
    pin_path = slot_pin_dir / f"proto_{proto}"
    if pin_path.exists():
        pin_path.unlink()

    print(f"Unloaded handler for proto {proto}")
    if path.exists():
        _cmd_slot_disable(argparse.Namespace(config=str(path), proto=proto))
        print(f"  config: {path}")
    return 0


def _cmd_port_handler_list(args: argparse.Namespace) -> int:
    bpf_pin_dir, _, handlers_dir = _slot_paths(args)
    base_dir = bpf_pin_dir / "port_handlers"
    configured = handlers.iter_configured_port_handlers(Path(args.config))
    available_by_path = {
        str(path): path
        for directory in (_builtin_handlers_dir(args), handlers_dir)
        for path in handlers.iter_available_port_handler_files(directory)
    }
    available = [available_by_path[key] for key in sorted(available_by_path)]

    print("Loaded per-port handlers:")
    found = False
    for proto in ("tcp", "udp"):
        proto_dir = base_dir / proto
        if not proto_dir.is_dir():
            continue
        port_dirs = [item for item in proto_dir.iterdir() if item.is_dir() and item.name.isdigit()]
        for port_dir in sorted(port_dirs, key=lambda item: int(item.name)):
            if not port_dir.is_dir():
                continue
            prog_pin = port_dir / "prog"
            if not prog_pin.exists():
                continue
            name = handlers.slot_prog_name(prog_pin)
            print(f"  {proto.upper():<3}  {port_dir.name:<5}  {name}")
            found = True
    if not found:
        print("  (none)")

    print("")
    print("Configured per-port handlers:")
    if not configured:
        print("  (none)")
    else:
        for proto, port, path in configured:
            print(f"  {proto.upper():<3}  {port:<5}  {path}")

    print("")
    print("Available local port handler files:")
    if not available:
        print("  (none)")
        return 0
    for handler_path in available:
        print(f"  {handler_path.stem:<20} {handler_path}")
    return 0


def _cmd_port_handler_load(args: argparse.Namespace) -> int:
    path = Path(args.config)
    bpf_pin_dir, _, handlers_dir = _slot_paths(args)
    proto = str(args.proto).lower()
    port = handlers.normalize_handler_port(int(args.port))
    slot_ctx_map = bpf_pin_dir / "slot_ctx_map"
    handler_map = handlers.port_handler_map_path(bpf_pin_dir, proto)

    source_path = Path(args.path)
    if source_path.suffix == ".c":
        try:
            obj_path = handlers.compile_handler_source(
                source_path,
                proto,
                handlers_dir,
                port=port,
                sdk_dir=_builtin_handlers_dir(args),
            )
        except RuntimeError as exc:
            print(str(exc), file=sys.stderr)
            return 1
    else:
        obj_path = source_path

    if not obj_path.is_file():
        print(f"Handler object not found: {obj_path}", file=sys.stderr)
        return 1
    obj_path = obj_path.resolve()
    if not slot_ctx_map.exists():
        print("XDP not loaded (slot_ctx_map not found). Run setup first.", file=sys.stderr)
        return 1
    if not handler_map.exists():
        print(f"XDP not loaded ({handler_map.name} map not found).", file=sys.stderr)
        return 1

    shared_maps = [
        ("slot_ctx_map", slot_ctx_map),
        ("hblk4", bpf_pin_dir / "hblk4"),
        ("hblk6", bpf_pin_dir / "hblk6"),
    ]
    if proto == "udp":
        shared_maps.extend(
            [
                ("udp_hv4", bpf_pin_dir / "udp_hv4"),
                ("udp_hv6", bpf_pin_dir / "udp_hv6"),
            ]
        )

    missing = [name for name, map_path in shared_maps if not map_path.exists()]
    if missing:
        print(f"XDP not loaded completely (missing pinned maps: {', '.join(missing)}).", file=sys.stderr)
        return 1

    pin_dir = handlers.port_handler_dir(bpf_pin_dir, proto, port)
    try:
        handlers.load_handler_object(handler_map, port, obj_path, pin_dir, shared_maps)
    except RuntimeError as exc:
        print(str(exc), file=sys.stderr)
        return 1

    # Handler-specific validation caches must not survive a successful handler
    # replacement. Flush only after the new program is committed so a failed
    # candidate never mutates the active handler's state.
    if proto == "udp":
        handlers.flush_udp_validated_for_port(bpf_pin_dir, port)

    if not args.no_config_update:
        config_file.ensure_config_exists(path)
        handlers.port_handler_config_update(path, proto, port, str(obj_path))
    print(f"Loaded {proto.upper()} handler for port {port} from {obj_path}")
    if not args.no_config_update:
        print(f"  config: {path}")
    return 0


def _cmd_profile_handler_load(args: argparse.Namespace) -> int:
    bpf_pin_dir, _, _ = _slot_paths(args)
    profile_id = handlers.normalize_profile_id(int(args.profile_id))
    handler_map = bpf_pin_dir / "tcp_profile_handlers"
    shared_maps = [
        (name, bpf_pin_dir / name)
        for name in (
            "slot_ctx_map", "profile_ctx_map", "mc_l7_pending",
            "pkt_counters", "byte_counters",
        )
    ]

    obj_path = Path(args.path)
    if not obj_path.is_file():
        print(f"Handler object not found: {obj_path}", file=sys.stderr)
        return 1
    obj_path = obj_path.resolve()
    missing = [name for name, path in shared_maps if not path.exists()]
    if not handler_map.exists():
        missing.insert(0, handler_map.name)
    if missing:
        print(
            f"XDP not loaded completely (missing pinned maps: {', '.join(missing)}).",
            file=sys.stderr,
        )
        return 1

    pin_dir = bpf_pin_dir / "profile_handlers" / "tcp" / str(profile_id)
    try:
        handlers.load_handler_object(handler_map, profile_id, obj_path, pin_dir, shared_maps)
    except RuntimeError as exc:
        print(str(exc), file=sys.stderr)
        return 1

    print(f"Loaded TCP profile handler {profile_id} from {obj_path}")
    return 0


def _cmd_profile_handler_unload(args: argparse.Namespace) -> int:
    bpf_pin_dir, _, _ = _slot_paths(args)
    profile_id = handlers.normalize_profile_id(int(args.profile_id))
    handler_map = bpf_pin_dir / "tcp_profile_handlers"
    pin_dir = bpf_pin_dir / "profile_handlers" / "tcp" / str(profile_id)
    live_pin = pin_dir / "prog"

    if not handler_map.exists():
        print(f"XDP not loaded ({handler_map.name} map not found).", file=sys.stderr)
        return 1

    active_id = handlers.prog_array_entry_id(handler_map, profile_id)
    if not live_pin.exists():
        if active_id is not None:
            print(
                f"Profile handler {profile_id} is active but its ownership pin is missing.",
                file=sys.stderr,
            )
            return 1
        print(f"TCP profile handler {profile_id} is not loaded")
        return 0

    try:
        pinned_id = handlers.pinned_program_id(live_pin)
    except RuntimeError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    if active_id != pinned_id:
        print(
            f"Profile handler {profile_id} does not match its program-array entry; "
            "retaining its pins.",
            file=sys.stderr,
        )
        return 1
    if not handlers.prog_array_delete(handler_map, profile_id):
        print(
            f"Failed to remove profile handler {profile_id}; retaining its pins.",
            file=sys.stderr,
        )
        return 1
    if handlers.prog_array_entry_id(handler_map, profile_id) is not None:
        print(
            f"Profile handler {profile_id} deletion could not be verified; retaining its pins.",
            file=sys.stderr,
        )
        return 1

    shutil.rmtree(pin_dir)
    print(f"Unloaded TCP profile handler {profile_id}")
    return 0


def _autodetect_iface() -> str:
    """Return the default-route interface name, or raise RuntimeError."""
    try:
        out = subprocess.check_output(
            ["ip", "route", "show", "default"], stderr=subprocess.DEVNULL, text=True
        )
    except (subprocess.CalledProcessError, OSError):
        out = ""
    for line in out.splitlines():
        parts = line.split()
        # format: default via ... dev IFACE ...
        if "dev" in parts:
            idx = parts.index("dev")
            if idx + 1 < len(parts):
                return parts[idx + 1]
    raise RuntimeError("Could not detect interface. Use --iface IFACE.")


def _print_port_lines(
    proto: str,
    ports: list[int],
    proc_map: dict[int, set[str]],
    port_rates: dict[int, int],
) -> None:
    """Prints the port table rows."""
    import socket as _socket

    if not ports:
        print("  (none)")
        return
    for p in sorted(set(ports)):
        try:
            svc = _socket.getservbyport(p, proto)
        except OSError:
            svc = "-"
        procs = ",".join(sorted(proc_map.get(p, set()))) or "-"
        rate = port_rates.get(p)
        rate_str = f"{rate}/s" if rate else "-"
        print(f"  {p:5d}  {svc:<14}  {procs:<14}  {rate_str}")


def _diff_port_lists(old: list[int], new: list[int]) -> tuple[list[int], list[int]]:
    old_set = set(old)
    new_set = set(new)
    added = sorted(new_set - old_set)
    removed = sorted(old_set - new_set)
    return added, removed


def _cmd_ports(args: argparse.Namespace) -> int:
    """Handler for the ports subcommand."""
    bpf_pin_dir: str = args.bpf_pin_dir
    run_state_dir: str = args.run_state_dir
    nft_family: str = args.nft_family
    nft_table: str = args.nft_table
    ifaces: list[str] = (args.iface or "").split() or []

    # Auto-detect interface if not provided
    if not ifaces:
        try:
            ifaces = [_autodetect_iface()]
        except RuntimeError as exc:
            print(str(exc), file=sys.stderr)
            return 1

    iface = ifaces[0]

    # Detect backend
    try:
        backend = _detect_backend(Path(bpf_pin_dir), Path(run_state_dir), ifaces, nft_family, nft_table)
    except RuntimeError as exc:
        print(str(exc), file=sys.stderr)
        return 1

    # Initial port read
    try:
        tcp_ports, udp_ports = ports.collect_ports(backend, bpf_pin_dir, nft_family, nft_table)
    except RuntimeError as exc:
        print(str(exc), file=sys.stderr)
        return 1

    syn_rate_map = str(Path(bpf_pin_dir) / "tcp_port_policies")
    udp_rate_map = str(Path(bpf_pin_dir) / "udp_port_policies")

    def _render_current(tcp: list[int], udp: list[int]) -> None:
        tcp_procs = ports.lookup_port_procs("tcp", tcp)
        udp_procs = ports.lookup_port_procs("udp", udp)
        tcp_rates = ports.read_rate_map(syn_rate_map)
        udp_rates = ports.read_rate_map(udp_rate_map)
        print(f"Backend   : {backend}")
        print(f"Interface : {iface}")
        print("TCP allow :")
        _print_port_lines("tcp", tcp, tcp_procs, tcp_rates)
        print("UDP allow :")
        _print_port_lines("udp", udp, udp_procs, udp_rates)

    _render_current(tcp_ports, udp_ports)

    if not args.watch:
        return 0

    import time as _time
    import datetime as _datetime

    prev_tcp = tcp_ports
    prev_udp = udp_ports

    try:
        while True:
            _time.sleep(args.interval)
            try:
                new_backend = _detect_backend(Path(bpf_pin_dir), Path(run_state_dir), ifaces, nft_family, nft_table)
                new_tcp, new_udp = ports.collect_ports(new_backend, bpf_pin_dir, nft_family, nft_table)
            except RuntimeError:
                continue

            if new_tcp == prev_tcp and new_udp == prev_udp:
                continue

            now_ts = _datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            added_tcp, removed_tcp = _diff_port_lists(prev_tcp, new_tcp)
            added_udp, removed_udp = _diff_port_lists(prev_udp, new_udp)

            print("")
            print(f"[{now_ts}] Port whitelist updated")
            if added_tcp:
                print(f"  TCP + {' '.join(str(p) for p in added_tcp)}")
            if removed_tcp:
                print(f"  TCP - {' '.join(str(p) for p in removed_tcp)}")
            if added_udp:
                print(f"  UDP + {' '.join(str(p) for p in added_udp)}")
            if removed_udp:
                print(f"  UDP - {' '.join(str(p) for p in removed_udp)}")
            print("")

            tcp_procs = ports.lookup_port_procs("tcp", new_tcp)
            udp_procs = ports.lookup_port_procs("udp", new_udp)
            tcp_rates = ports.read_rate_map(syn_rate_map)
            udp_rates = ports.read_rate_map(udp_rate_map)
            print("TCP allow :")
            _print_port_lines("tcp", new_tcp, tcp_procs, tcp_rates)
            print("UDP allow :")
            _print_port_lines("udp", new_udp, udp_procs, udp_rates)

            prev_tcp = new_tcp
            prev_udp = new_udp
    except KeyboardInterrupt:
        return 0

    return 0


def _policy_snapshot(args: argparse.Namespace):
    cfg.apply_toml_config(config_file.load_toml(Path(args.config)))
    observed = discovery.get_listening_ports()
    return observed, policy.resolve_desired_state(observed)


def _active_backend_name(args: argparse.Namespace) -> str:
    ifaces = (args.iface or "").split()
    if not ifaces:
        try:
            ifaces = [_autodetect_iface()]
        except RuntimeError:
            ifaces = []
    try:
        return _detect_backend(
            Path(args.bpf_pin_dir), Path(args.run_state_dir), ifaces,
            args.nft_family, args.nft_table,
        )
    except RuntimeError:
        return "unavailable"


def _owner_text(endpoint: Any) -> str:
    if endpoint.container_runtime:
        return f"{endpoint.container_runtime}:{endpoint.container_name or endpoint.container_id[:12]}"
    owner = endpoint.subject or "unknown"
    if endpoint.attribution_source.startswith("systemd") and not owner.endswith(".service"):
        owner += ".service"
    return owner


def _service_label(protocol: str, port: int) -> str:
    try:
        return socket.getservbyport(port, protocol)
    except OSError:
        return f"{protocol}{port}"


def _grant_label(decision: Any) -> str:
    return f"{decision.subject}.{decision.endpoint.ingress_zone}_{_service_label(decision.endpoint.protocol, decision.endpoint.host_port)}"


def _endpoint_text(endpoint: Any) -> str:
    address = f"[{endpoint.host_address}]" if ":" in endpoint.host_address else endpoint.host_address
    return f"{address}:{endpoint.host_port}"


def _cmd_exposure(args: argparse.Namespace) -> int:
    try:
        _observed, desired = _policy_snapshot(args)
    except (OSError, RuntimeError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    backend = _active_backend_name(args)
    decisions = sorted(
        desired.exposure_decisions,
        key=lambda item: (
            item.endpoint.ingress_zone, item.endpoint.host_port,
            item.endpoint.protocol, item.endpoint.host_address,
        ),
    )
    if not decisions:
        print("No externally reachable runtime endpoints.")
        return 0
    current_zone = None
    for decision in decisions:
        zone = decision.endpoint.ingress_zone.upper()
        if zone != current_zone:
            if current_zone is not None:
                print("")
            print(zone)
            print("")
            current_zone = zone
        endpoint = decision.endpoint
        print(f"{endpoint.host_port}/{endpoint.protocol}")
        print(f"  subject: {decision.subject or 'unknown'}")
        print(f"  owner: {_owner_text(endpoint)}")
        if decision.action == "allow":
            print(f"  grant: {_grant_label(decision)}")
            print(f"  backend: {backend}")
            print("  status: allowed")
        else:
            print("  status: blocked")
            print(f"  reason: {decision.reason}")
        print("")
    return 0


def _render_explanation(decision: Any, backend: str) -> None:
    endpoint = decision.endpoint
    print("ALLOW" if decision.action == "allow" else "BLOCK")
    print("")
    print("runtime endpoint:")
    print(f"  {_endpoint_text(endpoint)}")
    print("")
    print("owner:")
    print(f"  {_owner_text(endpoint)}")
    print("")
    print("subject:")
    print(f"  {decision.subject or 'unknown'}")
    print("")
    if decision.action == "allow":
        print("matched grant:")
        print(f"  {endpoint.ingress_zone}/{endpoint.protocol}/{endpoint.host_port}")
    else:
        print("reason:")
        print(f"  {decision.reason}")
    print("")
    print("backend:")
    print(f"  {backend.upper()}")


def _cmd_explain(args: argparse.Namespace) -> int:
    try:
        protocol, raw_port = args.endpoint.lower().split("/", 1)
        port = int(raw_port)
    except (AttributeError, ValueError):
        print("endpoint must be PROTOCOL/PORT, for example tcp/443", file=sys.stderr)
        return 1
    if protocol not in {"tcp", "udp", "sctp"} or not 1 <= port <= 65535:
        print("endpoint must use tcp, udp, or sctp and a port from 1 to 65535", file=sys.stderr)
        return 1
    try:
        _observed, desired = _policy_snapshot(args)
    except (OSError, RuntimeError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    backend = _active_backend_name(args)
    matches = [
        item for item in desired.exposure_decisions
        if item.endpoint.protocol == protocol and item.endpoint.host_port == port
    ]
    if not matches:
        print("BLOCK")
        print("\nruntime endpoint:\n  not listening")
        print("\nreason:\n  no live runtime endpoint")
        print(f"\nbackend:\n  {backend.upper()}")
        return 0
    for index, decision in enumerate(matches):
        if index:
            print("\n---\n")
        _render_explanation(decision, backend)
    return 0


def _cmd_exclude_list(args: argparse.Namespace) -> int:
    _, data = config_file.load_config(args.config)
    discovery = data.get("discovery", {})
    ports = sorted({int(p) for p in discovery.get("exclude_ports", [])})
    cidrs = sorted(_normalize_cidr(c) for c in discovery.get("exclude_bind_cidrs", []))
    if not ports and not cidrs:
        print("  (none)")
        return 0
    for port in ports:
        print(f"  port  {port}")
    for cidr in cidrs:
        print(f"  src   {cidr}")
    return 0


def _cmd_exclude_port_add(args: argparse.Namespace) -> int:
    path, data = config_file.load_config(args.config)
    new_ports = _normalize_ports(args.ports)
    discovery = data.setdefault("discovery", {})
    existing = sorted({int(p) for p in discovery.get("exclude_ports", [])} | set(new_ports))
    discovery["exclude_ports"] = existing
    config_file.write_toml(path, data)
    for port in new_ports:
        print(f"Excluded port: {port}")
    return 0


def _cmd_exclude_port_del(args: argparse.Namespace) -> int:
    path, data = config_file.load_config(args.config)
    del_ports = set(_normalize_ports(args.ports))
    discovery = data.setdefault("discovery", {})
    existing = sorted({int(p) for p in discovery.get("exclude_ports", [])} - del_ports)
    discovery["exclude_ports"] = existing
    config_file.write_toml(path, data)
    for port in sorted(del_ports):
        print(f"Un-excluded port: {port}")
    return 0


def _cmd_exclude_src_add(args: argparse.Namespace) -> int:
    path, data = config_file.load_config(args.config)
    new_cidrs = [_normalize_cidr(c) for c in args.cidrs]
    discovery = data.setdefault("discovery", {})
    existing = sorted(
        set(_normalize_cidr(c) for c in discovery.get("exclude_bind_cidrs", [])) | set(new_cidrs)
    )
    discovery["exclude_bind_cidrs"] = existing
    config_file.write_toml(path, data)
    for cidr in new_cidrs:
        print(f"Excluded src: {cidr}")
    return 0


def _cmd_exclude_src_del(args: argparse.Namespace) -> int:
    path, data = config_file.load_config(args.config)
    del_cidrs = {_normalize_cidr(c) for c in args.cidrs}
    discovery = data.setdefault("discovery", {})
    existing = sorted(
        _normalize_cidr(c)
        for c in discovery.get("exclude_bind_cidrs", [])
        if _normalize_cidr(c) not in del_cidrs
    )
    discovery["exclude_bind_cidrs"] = existing
    config_file.write_toml(path, data)
    for cidr in sorted(del_cidrs):
        print(f"Un-excluded src: {cidr}")
    return 0


def _approval_store(args: argparse.Namespace) -> Path:
    return approvals.store_path(args.run_state_dir)


def _render_approval(request: dict[str, Any]) -> None:
    ports = " ".join(str(port) for port in request.get("ports", []))
    print(
        f"  #{request['id']} {request['status']:<8} "
        f"{request['subject']} {request['zone']} {str(request['protocol']).upper()} "
        f"ports: {ports}  reason: {request.get('reason', '-') }"
    )


def _cmd_approval_list(args: argparse.Namespace) -> int:
    requests = approvals.list_requests(_approval_store(args), args.status)
    if args.json:
        print(json.dumps(requests, indent=2, sort_keys=True))
    elif not requests:
        print("  (none)")
    else:
        for request in requests:
            _render_approval(request)
    return 0


def _cmd_approval_history(args: argparse.Namespace) -> int:
    revision, history = approvals.list_history(_approval_store(args))
    if args.json:
        print(json.dumps({"revision": revision, "history": history}, indent=2, sort_keys=True))
    elif not history:
        print(f"revision {revision}: (none)")
    else:
        for item in history:
            when = _dt.datetime.fromtimestamp(float(item["at"])).isoformat(timespec="seconds")
            print(f"  r{item['revision']} #{item['request_id']} {item['action']:<7} {item['status']:<8} {item['actor']} {when}")
    return 0


def _cmd_approval_request(args: argparse.Namespace) -> int:
    request = approvals.create_request(
        _approval_store(args),
        args.config,
        subject=args.subject,
        zone=args.zone,
        protocol=args.protocol,
        ports=args.ports,
        reason=args.reason,
        systemd_unit=args.systemd_unit,
        process_name=args.process_name,
        container_runtime=args.container_runtime,
        container_id=args.container_id,
        container_name=args.container_name,
        container_label=args.container_label,
        protection_profile=args.profile,
        actor=args.actor,
    )
    print(f"Created approval request #{request['id']}")
    return 0


def _cmd_approval_approve(args: argparse.Namespace) -> int:
    request = approvals.approve_request(_approval_store(args), args.config, args.request_id, actor=args.actor)
    approvals.reload_daemon()
    print(f"Approved request #{request['id']} and updated exposure grant")
    return 0


def _cmd_approval_reject(args: argparse.Namespace) -> int:
    request = approvals.reject_request(_approval_store(args), args.request_id, reason=args.reason, actor=args.actor)
    print(f"Rejected request #{request['id']}")
    return 0


def _cmd_approval_revoke(args: argparse.Namespace) -> int:
    request = approvals.revoke_request(_approval_store(args), args.config, args.request_id, actor=args.actor)
    approvals.reload_daemon()
    print(f"Revoked request #{request['id']} exposure contribution")
    return 0


def _cmd_policy_grants(args: argparse.Namespace) -> int:
    grants = approvals.list_grants(args.config)
    if args.json:
        print(json.dumps(grants, indent=2, sort_keys=True))
    elif not grants:
        print("  (none)")
    else:
        for grant in grants:
            ports = " ".join(str(port) for port in grant["ports"])
            resolver = (
                grant["resolve"].get("systemd_unit")
                or grant["resolve"].get("process_name")
                or grant["resolve"].get("container_name")
                or grant["resolve"].get("container_id")
                or grant["resolve"].get("container_label")
                or "-"
            )
            profile = grant.get("protection_profile") or "-"
            print(f"  {grant['subject']:<20} {grant['zone']:<10} {grant['protocol'].upper():<5} ports: {ports} resolver: {resolver} profile: {profile}")
    return 0


def _cmd_policy_mode(args: argparse.Namespace) -> int:
    path, data = config_file.load_config(args.config)
    policy_config = data.setdefault("policy", {})
    current = str(policy_config.get("mode", "audit")).lower()
    if args.mode is None:
        print(current)
        return 0
    policy_config["mode"] = args.mode
    config_file.write_toml(path, data)
    print(f"policy.mode={args.mode}")
    return 0


def _service_subject(unit: str, explicit: str) -> tuple[str, str]:
    unit = unit.strip()
    if not unit:
        raise ValueError("systemd service name is required")
    if not unit.endswith(".service"):
        unit += ".service"
    subject = explicit.strip() or unit.removesuffix(".service").replace("@", "-")
    if not re.fullmatch(r"[A-Za-z0-9_.-]+", subject):
        raise ValueError("subject must contain only letters, digits, _, ., or -")
    return unit, subject


def _allow_target(target: str, explicit_subject: str) -> tuple[str, dict[str, str]]:
    if ":" not in target:
        unit, subject = _service_subject(target, explicit_subject)
        return subject, {"systemd_unit": unit}
    runtime, identity = target.split(":", 1)
    runtime = runtime.lower()
    identity = identity.strip().lower()
    if runtime not in {"docker", "podman"} or not re.fullmatch(r"[0-9a-f]{12,64}", identity):
        raise ValueError("target must be a systemd service or docker:<12-64 hex id>")
    subject = explicit_subject.strip() or f"{runtime}-{identity[:12]}"
    if not re.fullmatch(r"[A-Za-z0-9_.-]+", subject):
        raise ValueError("subject must contain only letters, digits, _, ., or -")
    return subject, {"container_runtime": runtime, "container_id": identity}


def _allow_args(args: argparse.Namespace) -> tuple[str, str, str]:
    target, endpoint, subject = args.service, args.endpoint, args.subject
    if endpoint is None and target and subject.startswith(("docker:", "podman:")):
        target, endpoint, subject = subject, target, ""
    if not target or not endpoint:
        raise ValueError(f"usage: axdp {args.command} TARGET PROTO/PORT")
    return target, endpoint, subject


def _service_endpoint(value: str) -> tuple[str, int]:
    try:
        protocol, raw_port = value.lower().split("/", 1)
        port = int(raw_port)
    except (AttributeError, ValueError):
        raise ValueError("endpoint must be PROTO/PORT, for example tcp/25565") from None
    if protocol not in {"tcp", "udp", "sctp"} or not 1 <= port <= 65535:
        raise ValueError("endpoint must use tcp, udp, or sctp and a port from 1 to 65535")
    return protocol, port


def _cmd_allow(args: argparse.Namespace) -> int:
    target, endpoint, explicit_subject = _allow_args(args)
    subject, resolve = _allow_target(target, explicit_subject)
    protocol, port = _service_endpoint(endpoint)
    profile = args.profile.strip().lower()
    if profile and profile != "minecraft":
        raise ValueError(f"unsupported protection profile: {profile}")
    if profile == "minecraft" and protocol != "tcp":
        raise ValueError("the minecraft profile requires a TCP endpoint")
    request = approvals.create_request(
        _approval_store(args),
        args.config,
        subject=subject,
        zone=args.zone,
        protocol=protocol,
        ports=[port],
        reason=args.reason,
        resolve=resolve,
        protection_profile=profile,
        actor=args.actor,
    )
    approved = approvals.approve_request(
        _approval_store(args), args.config, request["id"], actor=args.actor
    )
    approvals.reload_daemon()
    profile_text = f" profile={profile}" if profile else ""
    print(f"Allowed {target} {protocol}/{port} zone={args.zone}{profile_text} (approval #{approved['id']})")
    return 0


def _cmd_deny(args: argparse.Namespace) -> int:
    target, endpoint, explicit_subject = _allow_args(args)
    subject, _resolve = _allow_target(target, explicit_subject)
    protocol, port = _service_endpoint(endpoint)
    denied = approvals.deny_grant(
        _approval_store(args),
        args.config,
        subject=subject,
        zone=args.zone,
        protocol=protocol,
        ports=[port],
        reason=args.reason,
        actor=args.actor,
    )
    approvals.reload_daemon()
    print(f"Denied {subject} {protocol}/{port} zone={args.zone} (audit #{denied['id']})")
    return 0


def _cmd_port_handler_unload(args: argparse.Namespace) -> int:
    path = Path(args.config)
    bpf_pin_dir, _, _ = _slot_paths(args)
    proto = str(args.proto).lower()
    port = handlers.normalize_handler_port(int(args.port))

    handlers.cleanup_existing_port_handler(bpf_pin_dir, proto, port)
    print(f"Unloaded {proto.upper()} handler for port {port}")
    if not args.no_config_update and path.exists():
        handlers.port_handler_config_update(path, proto, port, None)
        print(f"  config: {path}")
    return 0


def _render_stats(
    rows: list[tuple[str, int, int]],
    prev: dict[str, tuple[int, int]],
    backend: str,
    iface: str,
    map_id: str,
    show_rates: bool,
    elapsed: float,
) -> None:
    import datetime as _datetime

    print(f"Backend   : {backend}")
    print(f"Interface : {iface}")
    if backend == "xdp":
        print(f"Map ID    : {map_id}")
    print(f"Updated   : {_datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]}")
    print("")

    # Header
    header = f"{'Metric':<12}  {'Packets':<15}  {'Bytes':<12}"
    sep = f"{'------------':<12}  {'---------------':<15}  {'------------':<12}"
    if show_rates:
        header += f"  {'Rate':<24}"
        sep += f"  {'------------------------':<24}"
    print(header)
    print(sep)

    reset_hints: list[str] = []
    for name, packets, b in rows:
        prev_packets, prev_bytes = prev.get(name, (-1, -1))

        # Detect reset
        if 0 <= packets < prev_packets:
            reset_hints.append(f"{name}:{prev_packets}->{packets}")

        packet_text = str(packets) if packets >= 0 else "unknown"
        line = f"{name:<12}  {packet_text:<15}  {formatting.human_bytes(b):<12}"

        if show_rates:
            if prev_packets >= 0 and packets >= 0:
                packet_delta = packets - prev_packets
                if packet_delta < 0:
                    packet_delta = -1
                if b == -1 or prev_bytes == -1:
                    byte_delta = -1
                else:
                    byte_delta = b - prev_bytes
                    if byte_delta < 0:
                        byte_delta = -1
                rate = formatting.format_rate(packet_delta, byte_delta, elapsed)
            else:
                rate = "-"
            line += f"  {rate:<24}"

        print(line)

    if reset_hints:
        print(f"\nResetHint : {', '.join(reset_hints)}")


def _cmd_stats(args: argparse.Namespace) -> int:
    import time as _time

    ifaces: list[str] = (args.iface or "").split() or []
    if not ifaces:
        try:
            ifaces = [_autodetect_iface()]
        except RuntimeError as exc:
            print(str(exc), file=sys.stderr)
            return 1

    iface = ifaces[0]

    try:
        backend = _detect_backend(Path(args.bpf_pin_dir), Path(args.run_state_dir), ifaces, args.nft_family, args.nft_table)
    except RuntimeError as exc:
        print(str(exc), file=sys.stderr)
        return 1

    state_file = Path(args.run_state_dir) / "axdp_stats.json"
    interval: float = args.interval
    show_rates: bool = args.rates
    watch: bool = args.watch
    render_mode: str = args.render  # "append" or "screen"

    def collect() -> tuple[list[tuple[str, int, int]], str]:
        return stats.collect_stats_rows(backend, args.bpf_pin_dir, iface, args.nft_family, args.nft_table, state_file)

    def rows_to_prev(rows: list[tuple[str, int, int]]) -> dict[str, tuple[int, int]]:
        return {name: (packets, b) for name, packets, b in rows}

    if watch:
        try:
            rows, map_id = collect()
            prev = rows_to_prev(rows)
            prev_ts = _time.monotonic()

            if render_mode == "screen":
                print("\033[H\033[2J", end="", flush=True)

            while True:
                _time.sleep(interval)
                cur_ts = _time.monotonic()
                elapsed = cur_ts - prev_ts if show_rates else 0.0
                try:
                    rows, map_id = collect()
                except RuntimeError as exc:
                    print(str(exc), file=sys.stderr)
                    _time.sleep(interval)
                    continue

                if render_mode == "screen":
                    print("\033[H", end="", flush=True)
                else:
                    import datetime as _dt
                    print(f"===== {_dt.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]} =====")

                _render_stats(rows, prev if show_rates else {}, backend, iface, map_id, show_rates, elapsed)

                if render_mode == "screen":
                    print("\033[J", end="", flush=True)
                else:
                    print("")

                prev = rows_to_prev(rows)
                prev_ts = cur_ts
        except KeyboardInterrupt:
            return 0
        return 0

    if show_rates:
        try:
            rows, map_id = collect()
        except RuntimeError as exc:
            print(str(exc), file=sys.stderr)
            return 1
        prev = rows_to_prev(rows)
        prev_ts = _time.monotonic()
        _time.sleep(interval)
        cur_ts = _time.monotonic()
        elapsed = cur_ts - prev_ts
        try:
            rows, map_id = collect()
        except RuntimeError as exc:
            print(str(exc), file=sys.stderr)
            return 1
        _render_stats(rows, prev, backend, iface, map_id, show_rates, elapsed)
        return 0

    try:
        rows, map_id = collect()
    except RuntimeError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    _render_stats(rows, {}, backend, iface, map_id, show_rates=False, elapsed=0.0)
    return 0


def _cmd_tui(args: argparse.Namespace) -> int:
    from auto_xdp.tui import run_tui

    try:
        return run_tui(args)
    except RuntimeError as exc:
        print(str(exc), file=sys.stderr)
        return 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="axdp")
    parser.add_argument("--config", required=True)
    parser.add_argument("--bpf-pin-dir", default="/sys/fs/bpf/xdp_fw")
    parser.add_argument("--install-dir", default="/usr/local/lib/auto_xdp/current")
    parser.add_argument("--handlers-dir", default="/etc/auto_xdp/handlers")
    parser.add_argument("--run-state-dir", default="/run/auto_xdp")
    parser.add_argument("--nft-family", default="inet")
    parser.add_argument("--nft-table", default="auto_xdp")
    parser.add_argument("--iface", default="")
    subparsers = parser.add_subparsers(dest="command", required=True)

    config_cmd = subparsers.add_parser("config")
    config_sub = config_cmd.add_subparsers(dest="subcommand", required=True)
    config_show = config_sub.add_parser("show")
    config_show.set_defaults(func=_cmd_config_show)
    config_init = config_sub.add_parser("init")
    config_init.set_defaults(func=_cmd_config_init)

    log_level = subparsers.add_parser("log-level")
    log_level.add_argument("level", nargs="?")
    log_level.set_defaults(func=_cmd_log_level)

    under_attack = subparsers.add_parser("under-attack")
    under_attack.add_argument("mode", nargs="?")
    under_attack.set_defaults(func=_cmd_under_attack)

    trust = subparsers.add_parser("trust")
    trust_sub = trust.add_subparsers(dest="subcommand", required=True)
    trust_list = trust_sub.add_parser("list")
    trust_list.set_defaults(func=_cmd_trust_list)
    trust_add = trust_sub.add_parser("add")
    trust_add.add_argument("cidr")
    trust_add.add_argument("label", nargs="?", default="manual")
    trust_add.set_defaults(func=_cmd_trust_add)
    trust_del = trust_sub.add_parser("del")
    trust_del.add_argument("cidr")
    trust_del.set_defaults(func=_cmd_trust_del)

    acl = subparsers.add_parser("acl")
    acl_sub = acl.add_subparsers(dest="subcommand", required=True)
    acl_list = acl_sub.add_parser("list")
    acl_list.set_defaults(func=_cmd_acl_list)
    acl_add = acl_sub.add_parser("add")
    acl_add.add_argument("proto", choices=["tcp", "udp"])
    acl_add.add_argument("cidr")
    acl_add.add_argument("ports", nargs="+", type=int)
    acl_add.set_defaults(func=_cmd_acl_add)
    acl_del = acl_sub.add_parser("del")
    acl_del.add_argument("proto", choices=["tcp", "udp"])
    acl_del.add_argument("cidr")
    acl_del.set_defaults(func=_cmd_acl_del)

    slot = subparsers.add_parser("slot")
    slot_sub = slot.add_subparsers(dest="subcommand", required=True)
    slot_list = slot_sub.add_parser("list")
    slot_list.set_defaults(func=_cmd_slot_list)
    slot_load = slot_sub.add_parser("load")
    slot_load.add_argument("name_or_proto")
    slot_load.add_argument("path", nargs="?")
    slot_load.set_defaults(func=_cmd_slot_load)
    slot_unload = slot_sub.add_parser("unload")
    slot_unload.add_argument("name_or_proto")
    slot_unload.set_defaults(func=_cmd_slot_unload)

    slot_builtin = subparsers.add_parser("slot-enable-builtin")
    slot_builtin.add_argument("name", choices=["gre", "esp", "sctp"])
    slot_builtin.set_defaults(func=_cmd_slot_enable_builtin)

    slot_custom = subparsers.add_parser("slot-enable-custom")
    slot_custom.add_argument("proto", type=int)
    slot_custom.add_argument("path")
    slot_custom.set_defaults(func=_cmd_slot_enable_custom)

    slot_disable = subparsers.add_parser("slot-disable")
    slot_disable.add_argument("proto", type=int)
    slot_disable.set_defaults(func=_cmd_slot_disable)

    port_handler = subparsers.add_parser("port-handler")
    port_handler_sub = port_handler.add_subparsers(dest="subcommand", required=True)
    port_handler_list = port_handler_sub.add_parser("list")
    port_handler_list.set_defaults(func=_cmd_port_handler_list)
    port_handler_load = port_handler_sub.add_parser("load")
    port_handler_load.add_argument("proto", choices=["tcp", "udp"])
    port_handler_load.add_argument("port", type=int)
    port_handler_load.add_argument("path")
    port_handler_load.add_argument("--no-config-update", action="store_true")
    port_handler_load.set_defaults(func=_cmd_port_handler_load)
    port_handler_unload = port_handler_sub.add_parser("unload")
    port_handler_unload.add_argument("proto", choices=["tcp", "udp"])
    port_handler_unload.add_argument("port", type=int)
    port_handler_unload.add_argument("--no-config-update", action="store_true")
    port_handler_unload.set_defaults(func=_cmd_port_handler_unload)

    profile_handler = subparsers.add_parser("profile-handler")
    profile_handler_sub = profile_handler.add_subparsers(dest="subcommand", required=True)
    profile_handler_load = profile_handler_sub.add_parser("load")
    profile_handler_load.add_argument("profile_id", type=int)
    profile_handler_load.add_argument("path")
    profile_handler_load.set_defaults(func=_cmd_profile_handler_load)
    profile_handler_unload = profile_handler_sub.add_parser("unload")
    profile_handler_unload.add_argument("profile_id", type=int)
    profile_handler_unload.set_defaults(func=_cmd_profile_handler_unload)

    exclude = subparsers.add_parser("exclude")
    exclude_sub = exclude.add_subparsers(dest="subcommand", required=True)
    exclude_list = exclude_sub.add_parser("list")
    exclude_list.set_defaults(func=_cmd_exclude_list)
    exclude_port = exclude_sub.add_parser("port")
    exclude_port_sub = exclude_port.add_subparsers(dest="subsubcommand", required=True)
    exclude_port_add = exclude_port_sub.add_parser("add")
    exclude_port_add.add_argument("ports", nargs="+", type=int)
    exclude_port_add.set_defaults(func=_cmd_exclude_port_add)
    exclude_port_del = exclude_port_sub.add_parser("del")
    exclude_port_del.add_argument("ports", nargs="+", type=int)
    exclude_port_del.set_defaults(func=_cmd_exclude_port_del)
    exclude_src = exclude_sub.add_parser("src")
    exclude_src_sub = exclude_src.add_subparsers(dest="subsubcommand", required=True)
    exclude_src_add = exclude_src_sub.add_parser("add")
    exclude_src_add.add_argument("cidrs", nargs="+")
    exclude_src_add.set_defaults(func=_cmd_exclude_src_add)
    exclude_src_del = exclude_src_sub.add_parser("del")
    exclude_src_del.add_argument("cidrs", nargs="+")
    exclude_src_del.set_defaults(func=_cmd_exclude_src_del)

    approval = subparsers.add_parser("approval")
    approval_sub = approval.add_subparsers(dest="subcommand", required=True)
    approval_list = approval_sub.add_parser("list")
    approval_list.add_argument("--status", choices=["all", "pending", "approved", "rejected", "revoked"], default="all")
    approval_list.add_argument("--json", action="store_true")
    approval_list.set_defaults(func=_cmd_approval_list)
    approval_history = approval_sub.add_parser("history")
    approval_history.add_argument("--json", action="store_true")
    approval_history.set_defaults(func=_cmd_approval_history)
    approval_request = approval_sub.add_parser("request")
    approval_request.add_argument("subject")
    approval_request.add_argument("zone")
    approval_request.add_argument("protocol", choices=["tcp", "udp", "sctp"])
    approval_request.add_argument("ports", nargs="+", type=int)
    approval_request.add_argument("--reason", required=True)
    approval_request.add_argument("--systemd-unit", default="")
    approval_request.add_argument("--process-name", default="")
    approval_request.add_argument("--container-runtime", choices=["docker", "podman"], default="")
    approval_request.add_argument("--container-id", default="")
    approval_request.add_argument("--container-name", default="")
    approval_request.add_argument("--container-label", default="")
    approval_request.add_argument("--profile", default="")
    approval_request.add_argument("--actor")
    approval_request.set_defaults(func=_cmd_approval_request)
    approval_approve = approval_sub.add_parser("approve")
    approval_approve.add_argument("request_id", type=int)
    approval_approve.add_argument("--actor")
    approval_approve.set_defaults(func=_cmd_approval_approve)
    approval_reject = approval_sub.add_parser("reject")
    approval_reject.add_argument("request_id", type=int)
    approval_reject.add_argument("--reason", required=True)
    approval_reject.add_argument("--actor")
    approval_reject.set_defaults(func=_cmd_approval_reject)
    approval_revoke = approval_sub.add_parser("revoke")
    approval_revoke.add_argument("request_id", type=int)
    approval_revoke.add_argument("--actor")
    approval_revoke.set_defaults(func=_cmd_approval_revoke)

    policy = subparsers.add_parser("policy")
    policy_sub = policy.add_subparsers(dest="subcommand", required=True)
    grants = policy_sub.add_parser("grants")
    grants.add_argument("--json", action="store_true")
    grants.set_defaults(func=_cmd_policy_grants)
    policy_mode = policy_sub.add_parser("mode")
    policy_mode.add_argument("mode", nargs="?", choices=["observe", "audit", "enforce"])
    policy_mode.set_defaults(func=_cmd_policy_mode)

    allow = subparsers.add_parser("allow")
    allow.add_argument("service", metavar="TARGET", nargs="?", help="systemd unit or docker:<container-id>")
    allow.add_argument("endpoint", nargs="?", help="PROTO/PORT, for example tcp/25565")
    allow.add_argument("--zone", default="public")
    allow.add_argument("--profile", default="")
    allow.add_argument("--subject", default="")
    allow.add_argument("--reason", default="local administrator grant")
    allow.add_argument("--actor")
    allow.set_defaults(func=_cmd_allow)

    deny = subparsers.add_parser("deny")
    deny.add_argument("service", metavar="TARGET", nargs="?", help="systemd unit or docker:<container-id>")
    deny.add_argument("endpoint", nargs="?", help="PROTO/PORT, for example tcp/25565")
    deny.add_argument("--zone", default="public")
    deny.add_argument("--subject", default="")
    deny.add_argument("--reason", default="local administrator denial")
    deny.add_argument("--actor")
    deny.set_defaults(func=_cmd_deny)

    ports_cmd = subparsers.add_parser("ports")
    ports_cmd.add_argument("--watch", action="store_true")
    ports_cmd.add_argument("--interval", type=float, default=2.0)
    ports_cmd.set_defaults(func=_cmd_ports)

    exposure_cmd = subparsers.add_parser("exposure")
    exposure_cmd.set_defaults(func=_cmd_exposure)

    explain_cmd = subparsers.add_parser("explain")
    explain_cmd.add_argument("endpoint", help="runtime endpoint, for example tcp/443")
    explain_cmd.set_defaults(func=_cmd_explain)

    stats_cmd = subparsers.add_parser("stats")
    stats_cmd.add_argument("--watch", action="store_true")
    stats_cmd.add_argument("--rates", action="store_true")
    stats_cmd.add_argument("--interval", type=float, default=1.0)
    stats_cmd.add_argument("--render", choices=["append", "screen"], default="append")
    stats_cmd.add_argument("--interface", dest="iface")
    stats_cmd.set_defaults(func=_cmd_stats)

    tui_cmd = subparsers.add_parser("tui")
    tui_cmd.add_argument("--interval", type=float, default=2.0)
    tui_cmd.add_argument("--socket")
    tui_cmd.add_argument("--max-events", dest="tui_max_events", type=int)
    tui_cmd.add_argument("--interface", dest="iface")
    tui_cmd.set_defaults(func=_cmd_tui)

    approval_api = subparsers.add_parser("approval-api")
    approval_api.add_argument("--socket-path")
    approval_api.set_defaults(func=lambda args: approvals.run_api(
        args.config,
        args.run_state_dir,
        args.socket_path or str(Path(args.run_state_dir) / "approval.sock"),
    ))

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command in {"allow", "deny", "approval", "approval-api"} and os.geteuid() != 0:
        print("policy changes require root; try re-running with sudo", file=sys.stderr)
        return 77
    if args.command == "policy" and args.subcommand == "mode" and args.mode is not None and os.geteuid() != 0:
        print("policy changes require root; try re-running with sudo", file=sys.stderr)
        return 77
    try:
        return int(args.func(args))
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    except PermissionError as exc:
        print(f"Permission denied: {exc}", file=sys.stderr)
        print("This command needs root; try re-running with sudo.", file=sys.stderr)
        return 77


if __name__ == "__main__":
    sys.exit(main())
