"""Handler compilation, pinned program transactions and handler configuration."""
from __future__ import annotations

import ctypes
import errno
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

from auto_xdp.admin import config_file
from auto_xdp.bpf.syscall import (
    BPF_MAP_DELETE_ELEM, BPF_MAP_GET_NEXT_KEY, bpf, obj_get,
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
        if "SEC(\"xdp/" not in text:
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


def run_checked(cmd: list[str], fail_msg: str) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip()
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


def verify_prog_array_entry(map_path: Path, key: int, expected_id: int) -> None:
    actual_id = prog_array_entry_id(map_path, key)
    if actual_id != expected_id:
        raise RuntimeError(
            f"Program-array verification failed for entry {key}: "
            f"expected program ID {expected_id}, got {actual_id!r}"
        )


def _rollback_prog_array_entry(
    map_path: Path,
    key: int,
    old_pin: Path | None,
    old_id: int | None,
) -> None:
    if old_pin is None or old_id is None:
        if not prog_array_delete(map_path, key) and prog_array_entry_id(map_path, key) is not None:
            raise RuntimeError(f"Failed to remove candidate program-array entry {key}")
        return
    prog_array_update(map_path, key, old_pin)
    verify_prog_array_entry(map_path, key, old_id)


def transactional_file_prog_swap(
    map_path: Path,
    key: int,
    candidate_pin: Path,
    live_pin: Path,
) -> None:
    """Atomically switch a PROG_ARRAY entry, then commit its canonical pin.

    The old program remains pinned until the kernel lookup confirms the new
    program ID.  Any failure before the final cleanup restores the old entry
    and pin name.
    """
    try:
        candidate_id = pinned_program_id(candidate_pin)
        old_exists = live_pin.exists()
        old_id = pinned_program_id(live_pin) if old_exists else None
        active_id = prog_array_entry_id(map_path, key)
        if old_id is None and active_id is not None:
            raise RuntimeError(
                f"Program-array entry {key} is active but its rollback pin {live_pin} is missing"
            )
        if old_id is not None and active_id not in {None, old_id}:
            raise RuntimeError(
                f"Program-array entry {key} does not match its rollback pin {live_pin}"
            )
    except (OSError, RuntimeError):
        if candidate_pin.exists():
            try:
                candidate_pin.unlink()
            except OSError:
                pass
        raise
    backup_pin = live_pin.with_name(f"{live_pin.name}_rollback_{secrets.token_hex(4)}")
    old_pin_for_rollback: Path | None = live_pin if old_exists else None
    switched = False
    moved_old = False
    moved_candidate = False
    try:
        prog_array_update(map_path, key, candidate_pin)
        switched = True
        verify_prog_array_entry(map_path, key, candidate_id)

        if old_exists:
            live_pin.rename(backup_pin)
            moved_old = True
            old_pin_for_rollback = backup_pin
        candidate_pin.rename(live_pin)
        moved_candidate = True
        verify_prog_array_entry(map_path, key, candidate_id)
        if pinned_program_id(live_pin) != candidate_id:
            raise RuntimeError(f"Committed pin {live_pin} does not reference the candidate program")

        if moved_old:
            backup_pin.unlink()
    except (OSError, RuntimeError) as exc:
        rollback_error: Exception | None = None
        if switched:
            try:
                _rollback_prog_array_entry(map_path, key, old_pin_for_rollback, old_id)
            except (OSError, RuntimeError) as rollback_exc:
                rollback_error = rollback_exc

        if moved_candidate and live_pin.exists():
            try:
                live_pin.rename(candidate_pin)
            except OSError:
                pass
        if moved_old and backup_pin.exists() and not live_pin.exists():
            try:
                backup_pin.rename(live_pin)
            except OSError:
                pass

        if rollback_error is not None:
            raise RuntimeError(
                f"Handler switch failed ({exc}); rollback also failed ({rollback_error}). "
                "Candidate and rollback pins were retained."
            ) from exc
        if candidate_pin.exists():
            try:
                candidate_pin.unlink()
            except OSError:
                pass
        raise RuntimeError(f"Handler switch failed; previous program restored: {exc}") from exc


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
    run_checked(cmd, f"Failed to compile {source_path}")
    return output_path


def normalize_handler_port(value: int) -> int:
    if value <= 0 or value > 65535:
        raise ValueError(f"invalid port: {value}")
    return value


def normalize_profile_id(value: int) -> int:
    if value <= 0 or value > 255:
        raise ValueError(f"invalid profile ID: {value}")
    return value


def port_handler_map_path(bpf_pin_dir: Path, proto: str) -> Path:
    return bpf_pin_dir / ("tcp_port_handlers" if proto == "tcp" else "udp_port_handlers")


def port_handler_dir(bpf_pin_dir: Path, proto: str, port: int) -> Path:
    return bpf_pin_dir / "port_handlers" / proto / str(port)


def transactional_dir_prog_swap(
    map_path: Path,
    key: int,
    candidate_dir: Path,
    live_dir: Path,
) -> None:
    candidate_pin = candidate_dir / "prog"
    live_pin = live_dir / "prog"
    try:
        candidate_id = pinned_program_id(candidate_pin)
        old_exists = live_pin.exists()
        old_id = pinned_program_id(live_pin) if old_exists else None
        active_id = prog_array_entry_id(map_path, key)
        if old_id is None and active_id is not None:
            raise RuntimeError(
                f"Program-array entry {key} is active but its rollback pin {live_pin} is missing"
            )
        if old_id is not None and active_id not in {None, old_id}:
            raise RuntimeError(
                f"Program-array entry {key} does not match its rollback pin {live_pin}"
            )
    except (OSError, RuntimeError):
        shutil.rmtree(candidate_dir, ignore_errors=True)
        raise

    backup_dir = live_dir.with_name(f"{live_dir.name}_rollback_{secrets.token_hex(4)}")
    old_pin_for_rollback: Path | None = live_pin if old_exists else None
    switched = False
    moved_old = False
    moved_candidate = False
    try:
        prog_array_update(map_path, key, candidate_pin)
        switched = True
        verify_prog_array_entry(map_path, key, candidate_id)

        if live_dir.exists():
            live_dir.rename(backup_dir)
            moved_old = True
            old_pin_for_rollback = backup_dir / "prog" if old_exists else None
        candidate_dir.rename(live_dir)
        moved_candidate = True
        verify_prog_array_entry(map_path, key, candidate_id)
        if pinned_program_id(live_dir / "prog") != candidate_id:
            raise RuntimeError(f"Committed pin {live_dir / 'prog'} does not reference the candidate program")
    except (OSError, RuntimeError) as exc:
        rollback_error: Exception | None = None
        if switched:
            try:
                _rollback_prog_array_entry(map_path, key, old_pin_for_rollback, old_id)
            except (OSError, RuntimeError) as rollback_exc:
                rollback_error = rollback_exc

        if moved_candidate and live_dir.exists():
            try:
                live_dir.rename(candidate_dir)
            except OSError:
                pass
        if moved_old and backup_dir.exists() and not live_dir.exists():
            try:
                backup_dir.rename(live_dir)
            except OSError:
                pass

        if rollback_error is not None:
            raise RuntimeError(
                f"Handler switch failed ({exc}); rollback also failed ({rollback_error}). "
                "Candidate and rollback generations were retained."
            ) from exc
        if candidate_dir.exists():
            shutil.rmtree(candidate_dir, ignore_errors=True)
        raise RuntimeError(f"Handler switch failed; previous program restored: {exc}") from exc

    if moved_old:
        try:
            shutil.rmtree(backup_dir)
        except OSError as exc:
            # Traffic already uses the verified candidate. Retaining the old
            # generation is safer than treating cleanup as a failed switch.
            print(f"Warning: old handler generation retained at {backup_dir}: {exc}", file=sys.stderr)


def load_handler_object(
    handler_map: Path,
    key: int,
    obj_path: Path,
    pin_dir: Path,
    shared_maps: list[tuple[str, Path]],
) -> None:
    pin_dir.parent.mkdir(parents=True, exist_ok=True)
    candidate_dir = Path(
        tempfile.mkdtemp(prefix=f"{key}_next_", dir=str(pin_dir.parent))
    )
    load_cmd = [
        "bpftool", "prog", "load", str(obj_path), str(candidate_dir / "prog"),
        "type", "xdp", "pinmaps", str(candidate_dir),
    ]
    for name, map_path in shared_maps:
        load_cmd.extend(["map", "name", name, "pinned", str(map_path)])
    try:
        run_checked(load_cmd, f"Failed to load {obj_path}")
    except RuntimeError:
        shutil.rmtree(candidate_dir, ignore_errors=True)
        raise
    transactional_dir_prog_swap(handler_map, key, candidate_dir, pin_dir)


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
    map_path = port_handler_map_path(bpf_pin_dir, proto)
    subprocess.run(
        [
            "bpftool",
            "map",
            "delete",
            "pinned",
            str(map_path),
            "key",
            str(port),
            "0",
            "0",
            "0",
        ],
        capture_output=True,
        text=True,
    )
    if proto == "udp":
        flush_udp_validated_for_port(bpf_pin_dir, port)
    pin_dir = port_handler_dir(bpf_pin_dir, proto, port)
    shutil.rmtree(pin_dir, ignore_errors=True)


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
