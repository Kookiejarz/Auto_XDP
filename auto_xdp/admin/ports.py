"""Read active XDP/nftables ports, process attribution and configured rates."""
from __future__ import annotations

import ctypes
import errno
import json
import os
import shutil
import struct
import subprocess
from pathlib import Path
from typing import Any

from auto_xdp.bpf.syscall import (
    BPF_MAP_LOOKUP_BATCH, BPF_MAP_LOOKUP_ELEM,
    bpf, map_max_entries, map_value_size, obj_get,
)
from auto_xdp.discovery.listeners import _build_systemd_socket_map


def read_xdp_ports(bpf_pin_dir: str) -> tuple[list[int], list[int]]:
    """Returns (tcp_ports, udp_ports) from BPF whitelist maps via direct BPF syscalls."""
    tcp_path = str(Path(bpf_pin_dir) / "tcp_whitelist")
    udp_path = str(Path(bpf_pin_dir) / "udp_whitelist")

    for p in (tcp_path, udp_path):
        if not Path(p).exists():
            raise RuntimeError(f"XDP whitelist maps not found under {bpf_pin_dir}")

    def _read_array_ports(path: str) -> list[int]:
        try:
            fd = obj_get(path)
        except OSError as exc:
            raise RuntimeError(f"Cannot open BPF map {path}: {exc}") from exc
        try:
            n = map_max_entries(fd)
            value_size = map_value_size(fd)
            if value_size < 4:
                raise RuntimeError(f"Invalid BPF map value size {value_size} for {path}")
            keys_buf = ctypes.create_string_buffer(4 * n)
            vals_buf = ctypes.create_string_buffer(value_size * n)
            out_batch = ctypes.create_string_buffer(4)
            attr = ctypes.create_string_buffer(56)
            struct.pack_into(
                "=QQQQIIQQ", attr, 0,
                0,
                ctypes.cast(out_batch, ctypes.c_void_p).value or 0,
                ctypes.cast(keys_buf, ctypes.c_void_p).value or 0,
                ctypes.cast(vals_buf, ctypes.c_void_p).value or 0,
                n, fd, 0, 0,
            )
            try:
                bpf(BPF_MAP_LOOKUP_BATCH, attr)
            except OSError as exc:
                if exc.errno != errno.ENOENT:
                    # Sequential fallback for kernels without batch support
                    k = ctypes.create_string_buffer(4)
                    v = ctypes.create_string_buffer(value_size)
                    la = ctypes.create_string_buffer(128)
                    struct.pack_into(
                        "=I4xQQ", la, 0, fd,
                        ctypes.cast(k, ctypes.c_void_p).value or 0,
                        ctypes.cast(v, ctypes.c_void_p).value or 0,
                    )
                    ports: list[int] = []
                    for port in range(1, min(n, 65536)):
                        try:
                            struct.pack_into("=I", k, 0, port)
                            bpf(BPF_MAP_LOOKUP_ELEM, la)
                            if struct.unpack_from("=I", v, 0)[0]:
                                ports.append(port)
                        except OSError:
                            continue
                    return ports
                # ENOENT means end-of-map; count in attr is updated.
            fetched = struct.unpack_from("=I", attr, 32)[0]
            return sorted({
                struct.unpack_from("=I", keys_buf, i * 4)[0]
                for i in range(fetched)
                if struct.unpack_from("=I", vals_buf, i * value_size)[0]
                and 0 < struct.unpack_from("=I", keys_buf, i * 4)[0] <= 65535
            })
        finally:
            os.close(fd)

    return _read_array_ports(tcp_path), _read_array_ports(udp_path)


def read_nft_ports(nft_family: str, nft_table: str) -> tuple[list[int], list[int]]:
    """Returns (tcp_ports, udp_ports) from nft sets."""
    if not shutil.which("nft"):
        raise RuntimeError("nft command not found")

    def _read_set(set_name: str) -> list[int]:
        try:
            out = subprocess.check_output(
                ["nft", "-j", "list", "set", nft_family, nft_table, set_name],
                stderr=subprocess.DEVNULL,
            )
            data = json.loads(out)
        except (subprocess.CalledProcessError, json.JSONDecodeError, OSError):
            return []
        ports: set[int] = set()
        for item in data.get("nftables", []):
            e = item.get("element")
            if not e:
                continue
            for v in e.get("elem", []):
                if isinstance(v, int) and 0 < v <= 65535:
                    ports.add(v)
        return sorted(ports)

    return _read_set("tcp_ports"), _read_set("udp_ports")


def _display_proc_name(
    proc_name: str,
    port: int,
    systemd_socket_map: dict[int, str] | None,
) -> tuple[str, dict[int, str] | None]:
    if proc_name != "systemd":
        return proc_name, systemd_socket_map
    if systemd_socket_map is None:
        systemd_socket_map = _build_systemd_socket_map()
    return systemd_socket_map.get(port, proc_name), systemd_socket_map


def lookup_port_procs(proto: str, ports: list[int]) -> dict[int, set[str]]:
    """Returns {port: set_of_process_names} by scanning /proc/net/{tcp,udp}."""
    proc_by_port: dict[int, set[str]] = {p: set() for p in ports}
    systemd_socket_map: dict[int, str] | None = None

    def _parse_proc_net(path: str, state_filter: str, check_no_remote: bool = False) -> dict[int, int]:
        result: dict[int, int] = {}
        try:
            with open(path) as f:
                next(f)
                for line in f:
                    parts = line.split()
                    if len(parts) < 10:
                        continue
                    local, remote, st, inode_str = parts[1], parts[2], parts[3], parts[9]
                    if st != state_filter:
                        continue
                    if check_no_remote and not remote.endswith(":0000"):
                        continue
                    port = int(local.split(":")[1], 16)
                    if port > 0:
                        result[port] = int(inode_str)
        except OSError:
            pass
        return result

    if proto == "tcp":
        port_to_inode: dict[int, int] = {}
        port_to_inode.update(_parse_proc_net("/proc/net/tcp", "0A"))
        port_to_inode.update(_parse_proc_net("/proc/net/tcp6", "0A"))
    else:
        port_to_inode = {}
        port_to_inode.update(_parse_proc_net("/proc/net/udp", "07", check_no_remote=True))
        port_to_inode.update(_parse_proc_net("/proc/net/udp6", "07", check_no_remote=True))

    wanted_inodes = {inode for port, inode in port_to_inode.items() if port in proc_by_port}
    inode_map: dict[int, str] = {}
    if wanted_inodes:
        try:
            for entry in os.scandir("/proc"):
                if not entry.name.isdigit():
                    continue
                pid = entry.name
                try:
                    for fd_entry in os.scandir(f"/proc/{pid}/fd"):
                        try:
                            link = os.readlink(fd_entry.path)
                            if link.startswith("socket:["):
                                inode = int(link[8:-1])
                                if inode in wanted_inodes:
                                    with open(f"/proc/{pid}/comm") as cf:
                                        proc_name = cf.read().strip()
                                    prev = inode_map.get(inode)
                                    if prev is None or prev == "systemd":
                                        inode_map[inode] = proc_name
                                    if proc_name != "systemd":
                                        wanted_inodes.discard(inode)
                        except OSError:
                            pass
                except OSError:
                    pass
                if not wanted_inodes:
                    break
        except OSError:
            pass

    for port, inode in port_to_inode.items():
        if port in proc_by_port and inode in inode_map:
            proc_name, systemd_socket_map = _display_proc_name(inode_map[inode], port, systemd_socket_map)
            proc_by_port[port].add(proc_name)

    return proc_by_port


def read_rate_map(map_path: str) -> dict[int, int]:
    """Returns {port: rate_per_sec} from a BPF rate map."""
    rates: dict[int, int] = {}
    if not map_path or not Path(map_path).exists():
        return rates

    def _b(v: Any) -> int:
        if isinstance(v, int):
            return v & 0xFF
        if isinstance(v, str):
            try:
                return int(v, 0) & 0xFF
            except ValueError:
                return 0
        return 0

    try:
        out = subprocess.check_output(
            ["bpftool", "-j", "map", "dump", "pinned", map_path],
            stderr=subprocess.DEVNULL,
        )
        for row in json.loads(out):
            key = row.get("key", [])
            val = row.get("value", [])
            if isinstance(key, list) and len(key) >= 4:
                port = _b(key[0]) | (_b(key[1]) << 8) | (_b(key[2]) << 16) | (_b(key[3]) << 24)
                if isinstance(val, list) and len(val) >= 4:
                    rate = _b(val[0]) | (_b(val[1]) << 8) | (_b(val[2]) << 16) | (_b(val[3]) << 24)
                    if rate > 0:
                        rates[port] = rate
    except (subprocess.CalledProcessError, json.JSONDecodeError, OSError, ValueError):
        pass
    return rates


def collect_ports(
    backend: str,
    bpf_pin_dir: str,
    nft_family: str,
    nft_table: str,
) -> tuple[list[int], list[int]]:
    if backend == "xdp":
        return read_xdp_ports(bpf_pin_dir)
    if backend == "nftables":
        return read_nft_ports(nft_family, nft_table)
    raise RuntimeError("No active backend detected.")
