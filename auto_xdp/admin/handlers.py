"""Handler compilation, pinned program transactions and handler configuration."""
from __future__ import annotations

import ctypes
import ctypes.util
import errno
import fcntl
import hashlib
import json
import os
import re
import secrets
import shutil
import struct
import subprocess
import sys
import tempfile
from pathlib import Path
from contextlib import contextmanager
from functools import lru_cache
from typing import NamedTuple

from auto_xdp.admin import config_file, handler_state
from auto_xdp.bpf.syscall import (
    BPF_MAP_DELETE_ELEM, BPF_MAP_GET_NEXT_KEY, BPF_MAP_LOOKUP_ELEM, BPF_OBJ_GET_INFO_BY_FD,
    bpf, map_id, obj_get,
)


_IPPROTO_BY_NAME = {
    "gre": 47,
    "esp": 50,
    "sctp": 132,
}


def _slot_handler_name(path: Path) -> str:
    return path.name.removesuffix("_handler.c")


def _discover_builtin_slot_info() -> dict[str, tuple[int, str]]:
    info: dict[str, tuple[int, str]] = {}
    handlers_dir = Path(__file__).resolve().parents[2] / "handlers"
    if not handlers_dir.is_dir():
        return {
            name: (proto, f"{name}_handler.o")
            for name, proto in _IPPROTO_BY_NAME.items()
        }
    for source in sorted(handlers_dir.glob("*_handler.c")):
        text = source.read_text(encoding="utf-8", errors="ignore")
        if 'SEC("xdp")' not in text and 'SEC("xdp/' not in text:
            continue
        name = _slot_handler_name(source)
        proto = _IPPROTO_BY_NAME.get(name)
        if proto is None:
            continue
        info[name] = (proto, f"{name}_handler.o")
    return info


BUILTIN_SLOT_INFO = _discover_builtin_slot_info()
BUILTIN_SLOT_PROTO = {proto: name for name, (proto, _obj) in BUILTIN_SLOT_INFO.items()}
_BUILTIN_SLOT_ARTIFACTS = {
    artifact
    for name, (_proto, obj_name) in BUILTIN_SLOT_INFO.items()
    for artifact in (f"{name}_handler.c", obj_name)
}
_CUSTOM_SLOT_ARTIFACT_RE = re.compile(r"^custom_\d+_.+\.(?:c|o)$")
_CUSTOM_PORT_ARTIFACT_RE = re.compile(r"^custom_(?:tcp|udp)_\d+_.+\.(?:c|o)$")
_PORT_HANDLER_MARKERS = ("udp_hv4", "udp_hv6", "hblk4", "hblk6")
_HANDLER_SHARED_MAPS = (
    "slot_ctx_map", "hblk4", "hblk6", "udp_hv4", "udp_hv6",
    "pkt_counters", "byte_counters", "pkt_ringbuf", "xdp_runtime_cfg",
    "profile_ctx_map", "tc_handler_ctx", "sctp_whitelist",
)


def handler_object_programs(obj_path: Path) -> tuple[str, str | None]:
    """Require one XDP entry and at most one optional TC classifier entry."""
    try:
        lib = ctypes.CDLL(ctypes.util.find_library("bpf") or "libbpf.so.1")
        for name, args, result in (
            ("bpf_object__open_file", [ctypes.c_char_p, ctypes.c_void_p], ctypes.c_void_p),
            ("libbpf_get_error", [ctypes.c_void_p], ctypes.c_long),
            ("bpf_object__next_program", [ctypes.c_void_p, ctypes.c_void_p], ctypes.c_void_p),
            ("bpf_program__type", [ctypes.c_void_p], ctypes.c_uint),
            ("bpf_program__name", [ctypes.c_void_p], ctypes.c_char_p),
            ("bpf_program__section_name", [ctypes.c_void_p], ctypes.c_char_p),
            ("bpf_object__close", [ctypes.c_void_p], None),
        ):
            fn = getattr(lib, name)
            fn.argtypes, fn.restype = args, result
    except (OSError, AttributeError) as exc:
        raise RuntimeError(f"Cannot inspect handler programs: {exc}") from exc
    obj = lib.bpf_object__open_file(os.fsencode(obj_path), None)
    if not obj or lib.libbpf_get_error(obj):
        raise RuntimeError(f"Cannot inspect handler object {obj_path}")
    entries: dict[int, list[str]] = {6: [], 3: []}  # XDP, SCHED_CLS
    try:
        program = lib.bpf_object__next_program(obj, None)
        while program:
            kind = lib.bpf_program__type(program)
            name = lib.bpf_program__name(program)
            section = lib.bpf_program__section_name(program) or b""
            if kind == 0 and section.startswith(b"xdp/"):
                kind = 6  # Legacy single-entry objects use a global XDP type override.
            if kind not in entries or not name:
                raise RuntimeError("Handlers support only XDP and TC classifier entries")
            entries[kind].append(os.fsdecode(name))
            program = lib.bpf_object__next_program(obj, program)
        if len(entries[6]) != 1 or len(entries[3]) > 1:
            raise RuntimeError("Handler must contain exactly one XDP entry and at most one TC entry")
        return entries[6][0], entries[3][0] if entries[3] else None
    finally:
        lib.bpf_object__close(obj)


class HandlerMapAbi(NamedTuple):
    map_type: int
    key_size: int
    value_size: int
    max_entries: int
    map_flags: int


def handler_object_maps(obj_path: Path) -> dict[str, HandlerMapAbi]:
    """Inspect declarations with libbpf without creating or loading kernel objects."""
    try:
        lib = ctypes.CDLL(ctypes.util.find_library("bpf") or "libbpf.so.1", use_errno=True)
        lib.bpf_object__open_file.argtypes = [ctypes.c_char_p, ctypes.c_void_p]
        lib.bpf_object__open_file.restype = ctypes.c_void_p
        lib.libbpf_get_error.argtypes = [ctypes.c_void_p]
        lib.libbpf_get_error.restype = ctypes.c_long
        lib.bpf_object__next_map.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
        lib.bpf_object__next_map.restype = ctypes.c_void_p
        lib.bpf_map__name.argtypes = [ctypes.c_void_p]
        lib.bpf_map__name.restype = ctypes.c_char_p
        getters = [getattr(lib, f"bpf_map__{field}") for field in
                   ("type", "key_size", "value_size", "max_entries", "map_flags")]
        for getter in getters:
            getter.argtypes = [ctypes.c_void_p]
            getter.restype = ctypes.c_uint
        lib.bpf_object__close.argtypes = [ctypes.c_void_p]
        lib.bpf_object__close.restype = None
    except (OSError, AttributeError) as exc:
        raise RuntimeError(f"Cannot inspect handler maps with libbpf: {exc}") from exc

    ctypes.set_errno(0)
    obj = lib.bpf_object__open_file(os.fsencode(obj_path), None)
    error = lib.libbpf_get_error(obj)
    if not obj or error:
        code = -error if error < 0 else ctypes.get_errno()
        detail = os.strerror(code) if code else "invalid BPF object"
        raise RuntimeError(f"Cannot inspect handler object {obj_path}: {detail}")
    try:
        maps: dict[str, HandlerMapAbi] = {}
        current = lib.bpf_object__next_map(obj, None)
        while current:
            name = lib.bpf_map__name(current)
            if not name:
                raise RuntimeError(f"Unnamed map in handler object {obj_path}")
            maps[os.fsdecode(name)] = HandlerMapAbi(*(getter(current) for getter in getters))
            current = lib.bpf_object__next_map(obj, current)
        return maps
    finally:
        lib.bpf_object__close(obj)


def pinned_handler_map_abi(path: Path) -> HandlerMapAbi:
    try:
        fd = obj_get(str(path))
        try:
            info = ctypes.create_string_buffer(128)
            attr = ctypes.create_string_buffer(16)
            struct.pack_into("=IIQ", attr, 0, fd, len(info), ctypes.addressof(info))
            bpf(BPF_OBJ_GET_INFO_BY_FD, attr)
            map_type, _, key_size, value_size, max_entries, flags = struct.unpack_from("=6I", info)
            return HandlerMapAbi(map_type, key_size, value_size, max_entries, flags)
        finally:
            os.close(fd)
    except OSError as exc:
        raise RuntimeError(f"Cannot inspect pinned handler map {path}: {exc}") from exc


def handler_shared_maps(obj_path: Path, bpf_pin_dir: Path) -> list[tuple[str, Path]]:
    """Bind declared public maps; private maps stay owned by the handler.

    A declared public map must reuse the main program's pinned instance. Never
    fall back to creating a private copy when that pin is missing. Explicitly
    check the declared ABI: bpftool/libbpf reuse may adopt the pinned map's
    attributes rather than rejecting incompatible object declarations.
    """
    maps = handler_object_maps(obj_path)
    shared = [(name, bpf_pin_dir / name) for name in _HANDLER_SHARED_MAPS if name in maps]
    missing = [name for name, path in shared if not path.exists()]
    if missing:
        raise RuntimeError(f"Handler requires missing pinned maps: {', '.join(missing)}")
    for name, path in shared:
        actual = pinned_handler_map_abi(path)
        if maps[name] != actual:
            raise RuntimeError(
                f"Incompatible shared map {name}: handler declares {maps[name]}, pinned map has {actual}"
            )
    return shared


def handler_state_fingerprint(obj_path: Path) -> bytes | None:
    contract = handler_state.object_contract(obj_path)
    if contract is None:
        return None
    if set(contract.maps) & set(_HANDLER_SHARED_MAPS):
        raise RuntimeError("Persistent state must not include public SDK maps")
    return handler_state.fingerprint(contract, handler_object_maps(obj_path))


def profile_state_generation(obj_path: Path) -> int:
    object_digest = hashlib.sha256(obj_path.read_bytes()).digest()
    return _profile_state_generation(obj_path.resolve(), object_digest)


@lru_cache(maxsize=32)
def _profile_state_generation(obj_path: Path, object_digest: bytes) -> int:
    # The daemon reconciles frequently. Inspect libbpf declarations once per
    # content hash, rather than reopening/logging the ELF on every sync tick.
    digest = handler_state_fingerprint(obj_path) or object_digest
    if hashlib.sha256(obj_path.read_bytes()).digest() != object_digest:
        raise RuntimeError("Handler object changed while inspecting its state contract; retry the update")
    return int.from_bytes(digest[:8], "little") or 1


def _state_marker(pin: Path) -> bytes:
    if pinned_handler_map_abi(pin) != HandlerMapAbi(2, 4, 32, 1, 0):
        raise RuntimeError("Invalid handler state compatibility marker")
    fd = obj_get(str(pin))
    try:
        key, value = ctypes.c_uint32(), ctypes.create_string_buffer(32)
        attr = ctypes.create_string_buffer(128)
        struct.pack_into("=I4xQQ", attr, 0, fd, ctypes.addressof(key), ctypes.addressof(value))
        bpf(BPF_MAP_LOOKUP_ELEM, attr)
        return value.raw
    finally:
        os.close(fd)


def _pinned_map_id(path: Path) -> int:
    fd = obj_get(str(path))
    try:
        return map_id(fd)
    finally:
        os.close(fd)


def _preserved_state_maps(
    obj_path: Path, live_dir: Path,
) -> tuple[bytes | None, list[tuple[str, Path]]]:
    contract = handler_state.object_contract(obj_path)
    digest = handler_state_fingerprint(obj_path) if contract else None
    marker = live_dir / "state_contract"
    if not (live_dir / "prog").exists():
        return digest, []
    if digest is None and not marker.exists():
        return None, []  # Unversioned legacy objects keep their original behavior.
    if digest is None or not marker.exists() or _state_marker(marker) != digest:
        raise RuntimeError(
            "Handler state is not compatible with the active generation; "
            "previous handler retained. Explicitly unload first to discard sessions."
        )
    assert contract is not None
    declarations = handler_object_maps(obj_path)
    preserved = []
    for name in contract.maps:
        path = live_dir / "maps" / name if (live_dir / "egress").exists() else live_dir / name
        if not path.exists() or pinned_handler_map_abi(path) != declarations[name]:
            raise RuntimeError(f"Persistent state map is missing or incompatible: {name}")
        preserved.append((name, path))
    return digest, preserved


def _pin_state_marker(candidate: Path, digest: bytes) -> None:
    pin = candidate / "state_contract"
    run_checked(["bpftool", "map", "create", str(pin), "type", "array", "key", "4",
                 "value", "32", "entries", "1", "name", "axdp_state"],
                "Failed to create handler state marker")
    run_checked(["bpftool", "map", "update", "pinned", str(pin), "key", "0", "0", "0", "0",
                 "value", "hex", *digest.hex(" ").split()], "Failed to publish handler state marker")
    if _state_marker(pin) != digest:
        raise RuntimeError("Handler state marker verification failed")


@contextmanager
def _handler_lock(root: Path):
    # bpffs cannot hold regular lock files. Lock its stable directory inode so
    # loads and unloads cannot race state-map pin reuse or rollback ownership.
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        os.close(fd)


def run_checked(cmd: list[str], fail_msg: str, *, include_detail: bool = False) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip()
        if detail and include_detail:
            raise RuntimeError(f"{fail_msg}\n{detail}")
        if detail:
            print(detail, file=sys.stderr)
        raise RuntimeError(fail_msg)
    return result


def _bpf_key_u32(value: int) -> list[str]:
    return [str((value >> shift) & 0xFF) for shift in (0, 8, 16, 24)]


def _json_u32(value: object) -> int:
    if isinstance(value, int):
        return value
    if isinstance(value, list) and len(value) >= 4:
        raw = bytes(int(item, 0) if isinstance(item, str) else int(item) for item in value[:4])
        return int.from_bytes(raw, byteorder="little")
    if isinstance(value, dict):
        for key in ("id", "value"):
            if key in value:
                return _json_u32(value[key])
    if isinstance(value, str):
        return int(value, 0)
    raise ValueError(f"cannot decode BPF u32 value: {value!r}")


def pinned_program_id(pin_path: Path) -> int:
    result = run_checked(
        ["bpftool", "-j", "prog", "show", "pinned", str(pin_path)],
        f"Failed to inspect candidate program pin {pin_path}",
    )
    try:
        payload = json.loads(result.stdout)
        if isinstance(payload, list):
            payload = payload[0]
        if not isinstance(payload, dict):
            raise ValueError("program JSON is not an object")
        return int(payload["id"])
    except (IndexError, KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"Could not read program ID from {pin_path}") from exc


def _pinned_u32_lookup(map_path: Path, key: bytes) -> int | None:
    """Distinguish an empty entry from an unreadable map before removing pins."""
    try:
        fd = obj_get(str(map_path))
        try:
            key_buf = ctypes.create_string_buffer(key)
            value = ctypes.c_uint32()
            attr = ctypes.create_string_buffer(128)
            struct.pack_into("=I4xQQ", attr, 0, fd, ctypes.addressof(key_buf), ctypes.addressof(value))
            try:
                bpf(BPF_MAP_LOOKUP_ELEM, attr)
            except OSError as exc:
                if exc.errno == errno.ENOENT:
                    return None
                raise
            return value.value
        finally:
            os.close(fd)
    except OSError as exc:
        raise RuntimeError(f"Cannot inspect handler map {map_path}: {exc}") from exc


def prog_array_entry_id(map_path: Path, key: int) -> int | None:
    result = subprocess.run(
        [
            "bpftool",
            "-j",
            "map",
            "lookup",
            "pinned",
            str(map_path),
            "key",
            *_bpf_key_u32(key),
        ],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        return None
    try:
        payload = json.loads(result.stdout)
        if not isinstance(payload, dict):
            return None
        return _json_u32(payload["value"])
    except (KeyError, TypeError, ValueError, json.JSONDecodeError):
        return None


def prog_array_update(map_path: Path, key: int, prog_pin: Path) -> None:
    run_checked(
        [
            "bpftool",
            "map",
            "update",
            "pinned",
            str(map_path),
            "key",
            *_bpf_key_u32(key),
            "value",
            "pinned",
            str(prog_pin),
        ],
        f"Failed to update program-array entry {key}",
    )


def prog_array_delete(map_path: Path, key: int) -> bool:
    result = subprocess.run(
        [
            "bpftool",
            "map",
            "delete",
            "pinned",
            str(map_path),
            "key",
            *_bpf_key_u32(key),
        ],
        capture_output=True,
        text=True,
    )
    return result.returncode == 0


def slot_prog_name(pin_path: Path) -> str:
    result = subprocess.run(
        ["bpftool", "prog", "show", "pinned", str(pin_path)],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        return "custom"
    match = re.search(r"\bname\s+(\S+)", result.stdout)
    return match.group(1) if match else "custom"


def _resolve_target_arch() -> tuple[str, str]:
    machine = os.uname().machine
    if machine == "x86_64":
        return "x86", "-D__x86_64__"
    if machine in {"aarch64", "arm64"}:
        return "arm64", "-D__aarch64__"
    if machine.startswith("armv7") or machine.startswith("armv6") or machine == "arm":
        return "arm", "-D__arm__"
    return machine, ""


def _resolve_asm_include(target_arch: str) -> str | None:
    candidates: list[str] = []
    result = subprocess.run(["gcc", "-print-multiarch"], capture_output=True, text=True)
    multiarch = result.stdout.strip() if result.returncode == 0 else ""
    if multiarch:
        candidates.append(f"/usr/include/{multiarch}")

    if target_arch == "x86":
        candidates.append("/usr/include/x86_64-linux-gnu")
    elif target_arch == "arm64":
        candidates.append("/usr/include/aarch64-linux-gnu")
    elif target_arch == "arm":
        candidates.append("/usr/include/arm-linux-gnueabihf")

    candidates.extend(
        [
            f"/usr/src/linux-headers-{os.uname().release}/arch/{target_arch}/include/generated",
            "/usr/include",
        ]
    )
    for candidate in candidates:
        if os.path.isdir(candidate) and (os.path.isdir(os.path.join(candidate, "asm")) or candidate == "/usr/include"):
            return candidate
    return "/usr/include"


def compile_handler_source(
    source_path: Path,
    proto: int | str,
    handlers_dir: Path,
    port: int | None = None,
    *,
    sdk_dir: Path | None = None,
    defines: dict[str, int] | None = None,
) -> Path:
    if not source_path.is_file():
        raise RuntimeError(f"Handler source not found: {source_path}")
    if source_path.suffix != ".c":
        raise RuntimeError(f"Unsupported handler source type: {source_path}")

    handlers_dir.mkdir(parents=True, exist_ok=True)
    stem = f"custom_{proto}_{port}_{source_path.stem}.o" if port is not None else f"custom_{proto}_{source_path.stem}.o"
    output_path = handlers_dir / stem
    target_arch, host_arch_flag = _resolve_target_arch()
    asm_inc = _resolve_asm_include(target_arch)
    if asm_inc is None:
        raise RuntimeError("ASM headers not found; cannot compile handler source.")

    cmd = [
        "clang",
        "-O3",
        "-g",
        "-target",
        "bpf",
        "-mcpu=v3",
        f"-D__TARGET_ARCH_{target_arch}",
    ]
    if host_arch_flag:
        cmd.append(host_arch_flag)
    for name, value in sorted((defines or {}).items()):
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name) or type(value) is not int:
            raise ValueError("Handler compiler definitions must be named integer constants")
        cmd.append(f"-D{name}={value}")
    cmd.extend(
        [
            "-fno-stack-protector",
            "-Wall",
            "-Wno-unused-value",
            "-I/usr/include",
            f"-I{asm_inc}",
            "-I/usr/include/bpf",
            f"-I{handlers_dir}",
            *([f"-I{sdk_dir}", f"-I{sdk_dir.parent / 'bpf' / 'include'}"]
              if sdk_dir is not None else []),
            f"-I{source_path.parent}",
            "-c",
            str(source_path),
            "-o",
            str(output_path),
        ]
    )
    run_checked(cmd, f"Failed to compile {source_path}", include_detail=True)
    return output_path


def normalize_handler_port(value: int) -> int:
    if value <= 0 or value > 65535:
        raise ValueError(f"invalid port: {value}")
    return value


def normalize_handler_protocol(value: int) -> int:
    if value < 0 or value > 255:
        raise ValueError(f"invalid IP protocol: {value}")
    return value


def protocol_handler_dir(root: Path, proto: int) -> Path:
    return root / "protocol_handlers" / str(normalize_handler_protocol(proto))


def protocol_handler_pin(root: Path, proto: int) -> Path:
    pin = protocol_handler_dir(root, proto) / "prog"
    return pin if pin.exists() else root / "handlers" / f"proto_{proto}"


def _adopt_protocol_pin(root: Path, proto: int) -> Path | None:
    """Retain the legacy pin until the new generation has been verified."""
    legacy = root / "handlers" / f"proto_{proto}"
    live = protocol_handler_dir(root, proto)
    if not legacy.exists():
        return None
    legacy_id = pinned_program_id(legacy)
    active = _pinned_u32_lookup(root / "proto_handlers", struct.pack("=I", proto))
    if (live / "prog").exists():
        canonical_id = pinned_program_id(live / "prog")
        if canonical_id != legacy_id and active != canonical_id:
            raise RuntimeError(f"Conflicting legacy protocol pin: {legacy}")
    elif active not in {None, legacy_id}:
        raise RuntimeError(f"Protocol {proto} has no matching legacy ownership pin")
    else:
        live.mkdir(parents=True, exist_ok=True)
        run_checked(["bpftool", "prog", "pin", "pinned", str(legacy), str(live / "prog")],
                    "Failed to adopt legacy protocol handler")
        if pinned_program_id(live / "prog") != legacy_id:
            raise RuntimeError("Legacy protocol ownership verification failed")
    return legacy


def _retire_protocol_pins(root: Path, proto: int) -> None:
    """After verified publication/removal, retire only known old pin names."""
    directory = root / "handlers"
    if not directory.is_dir():
        return
    pattern = re.compile(rf"proto_{proto}(?:_(?:next|rollback)_[0-9a-f]{{8}})?")
    for pin in directory.iterdir():
        if pin.is_symlink() or not pin.is_file() or not pattern.fullmatch(pin.name):
            continue
        try:
            pin.unlink()
        except OSError as exc:
            print(f"Warning: obsolete protocol pin retained at {pin}: {exc}", file=sys.stderr)
    try:
        directory.rmdir()  # Other protocols and unrelated files are left intact.
    except OSError as exc:
        if exc.errno not in {errno.ENOTEMPTY, errno.EEXIST}:
            print(f"Warning: obsolete protocol directory retained at {directory}: {exc}", file=sys.stderr)


def _adopt_stateless_contract(root: Path, live: Path, obj: Path) -> None:
    """Only a proven public-map-only legacy program can adopt an empty schema."""
    if not (live / "prog").exists() or (live / "state_contract").exists():
        return
    contract = handler_state.object_contract(obj)
    if contract is None or contract.maps or (live / "egress").exists():
        return
    active = _pinned_u32_lookup(root / "proto_handlers", struct.pack("=I", int(live.name)))
    if active is not None and pinned_program_id(live / "prog") != active:
        raise RuntimeError("Active protocol handler does not match its ownership pin")
    result = run_checked(["bpftool", "-j", "prog", "show", "pinned", str(live / "prog")],
                         "Failed to inspect legacy state ownership")
    try:
        info = json.loads(result.stdout)
        if isinstance(info, list):
            info = info[0]
        old_maps = set(info["map_ids"])
    except (ValueError, KeyError, TypeError, IndexError) as exc:
        raise RuntimeError("Cannot establish legacy state ownership") from exc
    public = {_pinned_map_id(root / name) for name in _HANDLER_SHARED_MAPS if (root / name).exists()}
    if old_maps - public:
        raise RuntimeError("Legacy protocol handler has private state; explicitly unload before replacing it")
    digest = handler_state_fingerprint(obj)
    assert digest is not None
    try:
        _pin_state_marker(live, digest)
    except (OSError, RuntimeError):
        # This marker did not exist before adoption. A partially initialized
        # marker must not make a retry look like an incompatible schema.
        (live / "state_contract").unlink(missing_ok=True)
        raise


def load_protocol_handler(root: Path, proto: int, obj: Path) -> bool:
    live = protocol_handler_dir(root, proto)
    shared = handler_shared_maps(obj, root)
    try:
        with _handler_lock(root):
            _adopt_protocol_pin(root, proto)
            _adopt_stateless_contract(root, live, obj)
            preserved = _load_handler_object(root / "proto_handlers", proto, obj, live, shared)
            _retire_protocol_pins(root, proto)
            return preserved
    except OSError as exc:
        raise RuntimeError(f"Protocol handler replacement failed: {exc}") from exc


def unload_protocol_handler(root: Path, proto: int) -> None:
    live = protocol_handler_dir(root, proto)
    table = root / "proto_handlers"
    try:
        with _handler_lock(root):
            _adopt_protocol_pin(root, proto)
            _transactional_handler_pair(table, proto, None, live)
            _retire_protocol_pins(root, proto)
    except OSError as exc:
        raise RuntimeError(f"Protocol handler removal failed: {exc}") from exc


def normalize_profile_id(value: int) -> int:
    if value <= 0 or value > 255:
        raise ValueError(f"invalid profile ID: {value}")
    return value


def port_handler_map_path(bpf_pin_dir: Path, proto: str) -> Path:
    return bpf_pin_dir / ("tcp_port_handlers" if proto == "tcp" else "udp_port_handlers")


def port_handler_dir(bpf_pin_dir: Path, proto: str, port: int) -> Path:
    return bpf_pin_dir / "port_handlers" / proto / str(port)


def handler_egress_table(handler_map: Path) -> tuple[Path, int]:
    name, kind = {
        "tcp_profile_handlers": ("tc_profile_handlers", 1),
        "tcp_port_handlers": ("tc_tcp_handlers", 2),
        "udp_port_handlers": ("tc_udp_handlers", 3),
        "proto_handlers": ("tc_proto_handlers", 4),
    }[handler_map.name]
    return handler_map.with_name(name), kind


def handler_egress_id(root: Path, kind: int, key: int) -> int | None:
    return _pinned_u32_lookup(root / "handler_egress", struct.pack("=II", kind, key))


def set_handler_egress(root: Path, kind: int, key: int, program_id: int | None) -> None:
    cmd = ["bpftool", "map", "update" if program_id is not None else "delete",
           "pinned", str(root / "handler_egress"),
           "key", *_bpf_key_u32(kind), *_bpf_key_u32(key)]
    if program_id is not None:
        cmd.extend(["value", *_bpf_key_u32(program_id)])
        run_checked(cmd, "Failed to publish handler egress capability")
    else:
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode and handler_egress_id(root, kind, key) is not None:
            raise RuntimeError("Failed to remove handler egress capability")
    if handler_egress_id(root, kind, key) != program_id:
        raise RuntimeError("Handler egress capability verification failed")


def transactional_handler_pair(
    handler_map: Path, key: int, candidate_dir: Path | None, live_dir: Path,
) -> None:
    with _handler_lock(handler_map.parent):
        _transactional_handler_pair(handler_map, key, candidate_dir, live_dir)


def _retire_handler_generations(live_dir: Path, key: int) -> None:
    """A verified canonical generation supersedes prior interrupted staging."""
    patterns = (
        re.compile(rf"{key}_next_[a-z0-9_]{{8}}"),
        re.compile(rf"{re.escape(live_dir.name)}_rollback_[0-9a-f]{{8}}"),
    )
    if not live_dir.parent.is_dir():
        return
    for path in live_dir.parent.iterdir():
        if path == live_dir or path.is_symlink() or not path.is_dir():
            continue
        if not any(pattern.fullmatch(path.name) for pattern in patterns):
            continue
        try:
            shutil.rmtree(path)
        except OSError as exc:
            print(f"Warning: obsolete handler generation retained at {path}: {exc}", file=sys.stderr)


def _transactional_handler_pair(
    handler_map: Path, key: int, candidate_dir: Path | None, live_dir: Path,
) -> None:
    """Publish or remove a complete generation; retain pins if rollback fails.

    Cross-hook switching is not atomic. Compatible generations share explicitly
    versioned state; unversioned generations retain their independent maps.
    """
    tc_map, kind = handler_egress_table(handler_map)
    root = handler_map.parent
    single_entry_only = not (tc_map.exists() and (root / "handler_egress").exists())
    tables = [(handler_map, "prog")] if single_entry_only else [(handler_map, "prog"), (tc_map, "egress")]
    def entry(table: Path) -> int | None:
        return _pinned_u32_lookup(table, struct.pack("=I", key))

    def restore(table: Path, pin: Path | None, program_id: int | None) -> None:
        if program_id is None:
            prog_array_delete(table, key)
        else:
            assert pin is not None
            prog_array_update(table, key, pin)
        if entry(table) != program_id:
            raise RuntimeError(f"Handler table verification failed: {table.name}[{key}]")

    old_ids: dict[str, int | None] = {"egress": None}
    new_ids: dict[str, int | None] = {"egress": None}
    try:
        if single_entry_only and (
            tc_map.exists() or (live_dir / "egress").exists() or
            (candidate_dir is not None and (candidate_dir / "egress").exists()) or
            ((root / "handler_egress").exists() and handler_egress_id(root, kind, key) is not None)
        ):
            raise RuntimeError("Handler egress maps are incomplete; active pins retained")
        for table, name in tables:
            pin = live_dir / name
            old_ids[name] = entry(table)
            if old_ids[name] is not None and (
                not pin.exists() or pinned_program_id(pin) != old_ids[name]
            ):
                raise RuntimeError(f"Active entry in {table.name} has no matching ownership pin {pin}")
            new_pin = candidate_dir / name if candidate_dir is not None else None
            new_ids[name] = pinned_program_id(new_pin) if new_pin and new_pin.exists() else None
        if candidate_dir is not None and new_ids["prog"] is None:
            raise RuntimeError("Candidate generation is missing its XDP entry")
        old_capability = None if single_entry_only else handler_egress_id(root, kind, key)
    except (OSError, RuntimeError):
        if candidate_dir is not None:
            shutil.rmtree(candidate_dir, ignore_errors=True)
        raise

    backup = live_dir.with_name(f"{live_dir.name}_rollback_{secrets.token_hex(4)}")
    moved_old = moved_candidate = False
    try:
        # On removal stop ingress first; on replacement prepare egress first.
        order = tables if candidate_dir is None else list(reversed(tables))
        for table, name in order:
            new_id = new_ids[name]
            if new_id is None:
                restore(table, None, None)
            else:
                assert candidate_dir is not None
                restore(table, candidate_dir / name, new_id)
            if not single_entry_only and ((candidate_dir is None and name == "prog") or name == "egress"):
                set_handler_egress(root, kind, key, new_ids["egress"])
        if live_dir.exists():
            live_dir.rename(backup)
            moved_old = True
        if candidate_dir is not None:
            candidate_dir.rename(live_dir)
            moved_candidate = True
        for table, name in tables:
            if entry(table) != new_ids[name]:
                raise RuntimeError(f"Committed {table.name} entry changed during publication")
            if new_ids[name] is not None and pinned_program_id(live_dir / name) != new_ids[name]:
                raise RuntimeError(f"Committed {name} pin does not match the active entry")
    except (OSError, RuntimeError) as exc:
        errors: list[str] = []
        previous = backup if moved_old else live_dir
        for table, name in reversed(tables):
            try:
                restore(
                    table, previous / name if old_ids[name] is not None else None, old_ids[name],
                )
            except (OSError, RuntimeError) as error:
                errors.append(str(error))
        if not single_entry_only:
            try:
                set_handler_egress(root, kind, key, old_capability)
            except (OSError, RuntimeError) as error:
                errors.append(str(error))
        if errors:
            raise RuntimeError(
                f"Handler switch failed ({exc}); rollback failed ({'; '.join(errors)}). "
                "Candidate and rollback pins were retained."
            ) from exc
        if moved_candidate:
            assert candidate_dir is not None
            live_dir.rename(candidate_dir)
        if moved_old:
            backup.rename(live_dir)
        if candidate_dir is not None:
            shutil.rmtree(candidate_dir, ignore_errors=True)
        raise RuntimeError(f"Handler switch failed; previous generation restored: {exc}") from exc
    # This is reached only after both dispatch entries/pins are verified. A
    # failed switch or rollback keeps every recovery generation untouched.
    _retire_handler_generations(live_dir, key)


def load_handler_object(
    handler_map: Path,
    key: int,
    obj_path: Path,
    pin_dir: Path,
    shared_maps: list[tuple[str, Path]],
) -> bool:
    try:
        with _handler_lock(handler_map.parent):
            preserved = _load_handler_object(handler_map, key, obj_path, pin_dir, shared_maps)
            if handler_map.name == "udp_port_handlers" and not preserved:
                flush_udp_validated_for_port(handler_map.parent, key)
            return preserved
    except OSError as exc:
        raise RuntimeError(f"Handler replacement failed: {exc}") from exc


def _load_handler_object(
    handler_map: Path, key: int, obj_path: Path, pin_dir: Path,
    shared_maps: list[tuple[str, Path]],
) -> bool:
    ingress, egress = handler_object_programs(obj_path)
    digest, preserved = _preserved_state_maps(obj_path, pin_dir)
    state_preserved = digest is not None and (pin_dir / "prog").exists()
    preserved_ids = {name: _pinned_map_id(path) for name, path in preserved}
    tc_map, _ = handler_egress_table(handler_map)
    routing_ready = tc_map.exists() and (handler_map.parent / "handler_egress").exists()
    if not routing_ready and (pin_dir / "egress").exists():
        raise RuntimeError("Active dual-entry handler has missing dispatcher maps; previous handler retained")
    if egress is not None and not routing_ready:
        raise RuntimeError("Dual-entry handler requires the generic TC dispatcher maps; upgrade XDP first")
    pin_dir.parent.mkdir(parents=True, exist_ok=True)
    candidate_dir = Path(
        tempfile.mkdtemp(prefix=f"{key}_next_", dir=str(pin_dir.parent))
    )
    load_cmd = [
        "bpftool", "prog", "load", str(obj_path), str(candidate_dir / "prog"),
        "type", "xdp", "pinmaps", str(candidate_dir),
    ]
    if egress is not None:
        # Let libbpf infer each program's type from its section. A global type
        # override would incorrectly turn the TC entry into an XDP program.
        load_cmd = ["bpftool", "prog", "loadall", str(obj_path), str(candidate_dir / "programs"),
                    "pinmaps", str(candidate_dir / "maps")]
    for name, map_path in shared_maps + preserved:
        load_cmd.extend(["map", "name", name, "pinned", str(map_path)])
    try:
        run_checked(load_cmd, f"Failed to load {obj_path}")
        if egress is not None:
            (candidate_dir / "programs" / ingress).rename(candidate_dir / "prog")
            (candidate_dir / "programs" / egress).rename(candidate_dir / "egress")
            (candidate_dir / "programs").rmdir()
        state_dir = candidate_dir / "maps" if egress else candidate_dir
        for name, _ in preserved:
            if _pinned_map_id(state_dir / name) != preserved_ids[name]:
                raise RuntimeError(f"Persistent map was not reused: {name}")
        if digest is not None:
            _pin_state_marker(candidate_dir, digest)
    except (OSError, RuntimeError) as exc:
        shutil.rmtree(candidate_dir, ignore_errors=True)
        raise RuntimeError(f"Failed to prepare handler generation: {exc}") from exc
    _transactional_handler_pair(handler_map, key, candidate_dir, pin_dir)
    return state_preserved


class _BpfUdpValidationMap:
    """Small iterator used only to purge handler-specific UDP validation state."""

    def __init__(self, path: Path, key_len: int) -> None:
        self.path = path
        self.fd = obj_get(str(path))
        self._key = bytearray(key_len)
        self._next_key = bytearray(key_len)
        self._value = bytearray(4)
        self._lookup_attr = bytearray(128)
        self._delete_attr = bytearray(128)
        self._next_attr = bytearray(128)
        self._key_buf = memoryview(self._key)
        self._next_key_buf = memoryview(self._next_key)
        key_ptr = ctypes.addressof(ctypes.c_char.from_buffer(self._key))
        next_key_ptr = ctypes.addressof(ctypes.c_char.from_buffer(self._next_key))
        value_ptr = ctypes.addressof(ctypes.c_char.from_buffer(self._value))
        struct.pack_into("=I4xQQ", self._lookup_attr, 0, self.fd, key_ptr, value_ptr)
        struct.pack_into("=I4xQ", self._delete_attr, 0, self.fd, key_ptr)
        struct.pack_into("=I4xQQ", self._next_attr, 0, self.fd, 0, next_key_ptr)

    def close(self) -> None:
        if self.fd >= 0:
            os.close(self.fd)
            self.fd = -1

    def __enter__(self) -> _BpfUdpValidationMap:
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    def _iter_keys(self) -> list[bytes]:
        result: list[bytes] = []
        current_ptr = 0
        while True:
            next_key_ptr = ctypes.addressof(ctypes.c_char.from_buffer(self._next_key))
            struct.pack_into("=I4xQQ", self._next_attr, 0, self.fd, current_ptr, next_key_ptr)
            try:
                bpf(BPF_MAP_GET_NEXT_KEY, self._next_attr)
            except OSError as exc:
                if exc.errno == errno.ENOENT:
                    break
                raise
            key_raw = bytes(self._next_key_buf)
            result.append(key_raw)
            self._key_buf[:] = key_raw
            current_ptr = ctypes.addressof(ctypes.c_char.from_buffer(self._key))
        return result

    def delete_key_port(self, dest_port: int, dport_offset: int = 2) -> int:
        deleted = 0
        for key_raw in self._iter_keys():
            if struct.unpack_from("!H", key_raw, dport_offset)[0] != dest_port:
                continue
            self._key_buf[:] = key_raw
            try:
                bpf(BPF_MAP_DELETE_ELEM, self._delete_attr)
                deleted += 1
            except OSError as exc:
                if exc.errno != errno.ENOENT:
                    raise
        return deleted


def flush_udp_validated_for_port(bpf_pin_dir: Path, port: int) -> int:
    deleted = 0
    for name, key_len in (("udp_hv4", 12), ("udp_hv6", 36)):
        map_path = bpf_pin_dir / name
        if not map_path.exists():
            continue
        with _BpfUdpValidationMap(map_path, key_len) as validated:
            deleted += validated.delete_key_port(port)
    return deleted


def cleanup_existing_port_handler(bpf_pin_dir: Path, proto: str, port: int) -> None:
    with _handler_lock(bpf_pin_dir):
        _cleanup_existing_port_handler(bpf_pin_dir, proto, port)


def _cleanup_existing_port_handler(bpf_pin_dir: Path, proto: str, port: int) -> None:
    map_path = port_handler_map_path(bpf_pin_dir, proto)
    pin_dir = port_handler_dir(bpf_pin_dir, proto, port)
    _transactional_handler_pair(map_path, port, None, pin_dir)
    if proto == "udp":
        flush_udp_validated_for_port(bpf_pin_dir, port)


def port_handler_config_update(config_path: Path, proto: str, port: int, path: str | None) -> None:
    cfg_path, data = config_file.load_config(str(config_path))
    port_handlers = data.setdefault("port_handlers", {})
    table = port_handlers.setdefault(proto, {})
    if path is None:
        table.pop(str(port), None)
    else:
        table[str(port)] = path
    config_file.write_toml(cfg_path, data)


def iter_configured_port_handlers(config_path: Path) -> list[tuple[str, int, str]]:
    _, data = config_file.load_config(str(config_path))
    port_handlers = data.get("port_handlers", {})
    results: list[tuple[str, int, str]] = []
    for proto in ("tcp", "udp"):
        table = port_handlers.get(proto, {})
        if not isinstance(table, dict):
            continue
        for raw_port, raw_path in table.items():
            port = normalize_handler_port(int(raw_port))
            path = str(raw_path)
            if path:
                results.append((proto, port, path))
    return sorted(results, key=lambda item: (item[0], item[1]))


def _looks_like_port_handler_source(path: Path) -> bool:
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return False
    return any(marker in text for marker in _PORT_HANDLER_MARKERS)


def iter_available_port_handler_files(handlers_dir: Path) -> list[Path]:
    if not handlers_dir.is_dir():
        return []

    candidates: dict[str, Path] = {}
    for path in handlers_dir.iterdir():
        if not path.is_file() or path.suffix not in {".c", ".o"}:
            continue
        if (
            path.name in _BUILTIN_SLOT_ARTIFACTS
            or path.stem == "minecraft_handler"
            or _CUSTOM_SLOT_ARTIFACT_RE.match(path.name)
        ):
            continue

        include = False
        if _CUSTOM_PORT_ARTIFACT_RE.match(path.name):
            include = True
        elif path.suffix == ".c":
            include = _looks_like_port_handler_source(path)
        else:
            source_peer = path.with_suffix(".c")
            include = source_peer.is_file() and _looks_like_port_handler_source(source_peer)

        if not include:
            continue

        key = path.stem
        current = candidates.get(key)
        if current is None or (current.suffix != ".o" and path.suffix == ".o"):
            candidates[key] = path

    return [candidates[key] for key in sorted(candidates)]
