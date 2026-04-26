from __future__ import annotations

import ctypes
import ctypes.util
import os
import platform
import struct


_libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
NR_BPF: int = {
    "x86_64": 321,
    "aarch64": 280,
    "armv7l": 386,
    "armv6l": 386,
}.get(platform.machine(), 321)

BPF_MAP_LOOKUP_ELEM = 1
BPF_MAP_UPDATE_ELEM = 2
BPF_MAP_DELETE_ELEM = 3
BPF_MAP_GET_NEXT_KEY = 4
BPF_OBJ_GET = 7
BPF_OBJ_GET_INFO_BY_FD = 15
BPF_MAP_LOOKUP_BATCH = 24


def bpf(cmd: int, attr: ctypes.Array) -> int:
    ret = _libc.syscall(NR_BPF, ctypes.c_int(cmd), attr, ctypes.c_uint(len(attr)))
    if ret < 0:
        err = ctypes.get_errno()
        raise OSError(err, os.strerror(err))
    return ret


def obj_get(path: str) -> int:
    path_b = ctypes.create_string_buffer(path.encode() + b"\x00")
    attr = ctypes.create_string_buffer(128)
    struct.pack_into("=Q", attr, 0, ctypes.cast(path_b, ctypes.c_void_p).value or 0)
    return bpf(BPF_OBJ_GET, attr)


def map_max_entries(fd: int) -> int:
    """Return the max_entries of an open BPF map fd via BPF_OBJ_GET_INFO_BY_FD."""
    info = ctypes.create_string_buffer(128)
    attr = ctypes.create_string_buffer(16)
    info_ptr = ctypes.cast(info, ctypes.c_void_p).value or 0
    # bpf_attr.info: bpf_fd(u32), info_len(u32), info(u64 ptr)
    struct.pack_into("=IIQ", attr, 0, fd, len(info), info_ptr)
    bpf(BPF_OBJ_GET_INFO_BY_FD, attr)
    # bpf_map_info.max_entries is at offset 16 (after type, id, key_size, value_size)
    return struct.unpack_from("=I", info, 16)[0]
