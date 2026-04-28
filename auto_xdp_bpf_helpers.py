#!/usr/bin/env python3
"""Helpers for Auto XDP BPF map operations."""

from __future__ import annotations

import argparse
import ctypes
import ctypes.util
import json
import os
import platform
import socket
import struct
import subprocess
import time

try:
    import psutil
except ImportError:
    psutil = None


NR_BPF = {
    "x86_64": 321,
    "aarch64": 280,
    "armv7l": 386,
    "armv6l": 386,
}.get(platform.machine(), 321)
BPF_MAP_UPDATE_ELEM = 2
BPF_OBJ_GET = 7

libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)


def bpf(cmd: int, attr: ctypes.Array) -> int:
    ret = libc.syscall(NR_BPF, ctypes.c_int(cmd), attr, ctypes.c_uint(len(attr)))
    if ret < 0:
        err = ctypes.get_errno()
        raise OSError(err, os.strerror(err))
    return ret


def obj_get(path: str) -> int:
    path_b = ctypes.create_string_buffer(path.encode() + b"\x00")
    attr = ctypes.create_string_buffer(128)
    struct.pack_into("=Q", attr, 0, ctypes.cast(path_b, ctypes.c_void_p).value or 0)
    return bpf(BPF_OBJ_GET, attr)


def cmd_pin_maps(prog_id: int, pin_dir: str) -> int:
    try:
        prog = json.loads(
            subprocess.check_output(["bpftool", "-j", "prog", "show", "id", str(prog_id)], text=True)
        )
        map_ids = prog.get("map_ids") or []
        if not map_ids and isinstance(prog.get("maps"), list):
            for m in prog["maps"]:
                if isinstance(m, dict) and "id" in m:
                    map_ids.append(m["id"])

        for map_id in map_ids:
            info = json.loads(
                subprocess.check_output(["bpftool", "-j", "map", "show", "id", str(map_id)], text=True)
            )
            name = info.get("name", f"map_{map_id}")
            pin_path = f"{pin_dir}/{name}"
            subprocess.check_call(["bpftool", "map", "pin", "id", str(map_id), pin_path])
        if not map_ids:
            print("pin-maps failed: no map ids found in bpftool prog json", file=os.sys.stderr)
            return 1
        return 0
    except Exception as exc:
        print(f"pin-maps failed: {exc}", file=os.sys.stderr)
        return 1


def iter_established_tcp():
    if psutil is None:
        return
    getter = getattr(psutil, "connections", psutil.net_connections)
    for conn in getter(kind="inet"):
        if getattr(conn, "family", None) not in (socket.AF_INET, socket.AF_INET6):
            continue
        if getattr(conn, "type", None) != socket.SOCK_STREAM:
            continue
        if conn.status != psutil.CONN_ESTABLISHED:
            continue
        if not conn.laddr or not conn.raddr:
            continue
        yield conn


def pack_ct_key_v4(conn) -> bytes:
    remote_ip = socket.inet_aton(conn.raddr.ip)
    local_ip = socket.inet_aton(conn.laddr.ip)
    return struct.pack("!HH4s4s", conn.raddr.port, conn.laddr.port, remote_ip, local_ip)


def pack_ct_key_v6(conn) -> bytes:
    remote_ip = socket.inet_pton(socket.AF_INET6, conn.raddr.ip)
    local_ip = socket.inet_pton(socket.AF_INET6, conn.laddr.ip)
    return struct.pack("!HH16s16s", conn.raddr.port, conn.laddr.port, remote_ip, local_ip)


def pack_ct_key(conn) -> bytes:
    if conn.family == socket.AF_INET:
        return pack_ct_key_v4(conn)
    return pack_ct_key_v6(conn)


def _open_optional_map(path: str) -> tuple[int, ctypes.Array, ctypes.Array] | None:
    if not path or not os.path.exists(path):
        return None
    fd = obj_get(path)
    return fd, ctypes.create_string_buffer(8), ctypes.create_string_buffer(128)


def cmd_seed_tcp_conntrack(map_path_v4: str, map_path_v6: str) -> int:
    if psutil is None:
        print(0)
        return 0

    try:
        map_v4 = _open_optional_map(map_path_v4)
        map_v6 = _open_optional_map(map_path_v6)
    except OSError as exc:
        print(f"seed-tcp-conntrack failed to open map: {exc}", file=os.sys.stderr)
        return 1

    if map_v4 is None and map_v6 is None:
        print(0)
        return 0

    key_v4 = ctypes.create_string_buffer(12)
    key_v6 = ctypes.create_string_buffer(36)
    attr_v4 = ctypes.create_string_buffer(128)
    attr_v6 = ctypes.create_string_buffer(128)
    value_v4 = map_v4[1] if map_v4 is not None else None
    value_v6 = map_v6[1] if map_v6 is not None else None
    if map_v4 is not None:
        struct.pack_into(
            "=I4xQQQ",
            attr_v4,
            0,
            map_v4[0],
            ctypes.cast(key_v4, ctypes.c_void_p).value or 0,
            ctypes.cast(value_v4, ctypes.c_void_p).value or 0,
            0,
        )
    if map_v6 is not None:
        struct.pack_into(
            "=I4xQQQ",
            attr_v6,
            0,
            map_v6[0],
            ctypes.cast(key_v6, ctypes.c_void_p).value or 0,
            ctypes.cast(value_v6, ctypes.c_void_p).value or 0,
            0,
        )

    seeded = 0
    stamp = time.monotonic_ns()
    for conn in iter_established_tcp():
        try:
            if conn.family == socket.AF_INET and map_v4 is not None:
                packed = pack_ct_key_v4(conn)
                ctypes.memmove(key_v4, packed, len(packed))
                struct.pack_into("=Q", value_v4, 0, stamp)
                bpf(BPF_MAP_UPDATE_ELEM, attr_v4)
            elif conn.family == socket.AF_INET6 and map_v6 is not None:
                packed = pack_ct_key_v6(conn)
                ctypes.memmove(key_v6, packed, len(packed))
                struct.pack_into("=Q", value_v6, 0, stamp)
                bpf(BPF_MAP_UPDATE_ELEM, attr_v6)
            else:
                continue
            seeded += 1
        except OSError:
            continue

    if map_v4 is not None:
        os.close(map_v4[0])
    if map_v6 is not None:
        os.close(map_v6[0])
    print(seeded)
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Auto XDP BPF helper")
    sub = parser.add_subparsers(dest="cmd", required=True)

    pin = sub.add_parser("pin-maps", help="Pin all maps referenced by a program id")
    pin.add_argument("--prog-id", type=int, required=True)
    pin.add_argument("--pin-dir", required=True)

    seed = sub.add_parser("seed-tcp-conntrack", help="Seed established TCP flows into conntrack map")
    seed.add_argument("--map-path-v4", default="")
    seed.add_argument("--map-path-v6", default="")

    args = parser.parse_args()
    if args.cmd == "pin-maps":
        return cmd_pin_maps(args.prog_id, args.pin_dir)
    if args.cmd == "seed-tcp-conntrack":
        return cmd_seed_tcp_conntrack(args.map_path_v4, args.map_path_v6)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
