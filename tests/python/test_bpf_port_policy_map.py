"""Value-layout contracts for the per-port TCP and UDP policy maps."""
import ctypes
import errno
import struct
import unittest
from unittest import mock

import pytest

from auto_xdp.bpf import maps as maps_mod
from auto_xdp.bpf.maps import BpfPortPolicyMap, BpfPortPolicyViewMap, BpfUdpPortPolicyMap


pytestmark = pytest.mark.component

PATH = "/sys/fs/bpf/xdp_fw/port_policies"

# Field order of struct udp_port_policy_cfg and struct tcp_port_policy_cfg
# in bpf/include/keys.h.
UDP_FIELDS = ("rate_max", "agg_rate_max", "source_prefix_v4", "source_prefix_v6", "_pad0", "_pad1")
TCP_FIELDS = (
    "syn_rate_max", "syn_agg_rate_max", "_reserved2", "source_prefix_v4",
    "source_prefix_v6", "_reserved5", "_reserved6", "_pad",
)


class FakeKernelHashMap:
    """BPF hash map that keeps exactly value_size bytes per key, like the kernel."""

    def __init__(self, value_size: int, max_entries: int = 1024) -> None:
        self.value_size = value_size
        self.max_entries = max_entries
        self.values: dict[int, bytes] = {}

    def decode(self, port: int, fields: tuple[str, ...]) -> dict[str, int]:
        raw = self.values[port]
        return dict(zip(fields, struct.unpack(f"={len(raw) // 4}I", raw)))

    def bpf(self, cmd, attr):
        if cmd == maps_mod.BPF_MAP_UPDATE_ELEM:
            _fd, key_ptr, value_ptr, _flags = struct.unpack_from("=I4xQQQ", attr, 0)
            port = struct.unpack("=I", ctypes.string_at(key_ptr, 4))[0]
            self.values[port] = ctypes.string_at(value_ptr, self.value_size)
            return 0
        if cmd == maps_mod.BPF_MAP_DELETE_ELEM:
            _fd, key_ptr = struct.unpack_from("=I4xQ", attr, 0)
            port = struct.unpack("=I", ctypes.string_at(key_ptr, 4))[0]
            if self.values.pop(port, None) is None:
                raise OSError(errno.ENOENT, "no such entry")
            return 0
        if cmd == maps_mod.BPF_MAP_LOOKUP_BATCH:
            _in, _out, keys_ptr, values_ptr, count, _fd, _elem, _flags = struct.unpack_from(
                "=QQQQIIQQ", attr, 0,
            )
            items = sorted(self.values.items())[:count]
            for i, (port, value) in enumerate(items):
                ctypes.memmove(keys_ptr + 4 * i, struct.pack("=I", port), 4)
                ctypes.memmove(values_ptr + self.value_size * i, value, self.value_size)
            struct.pack_into("=I", attr, 32, len(items))
            # The kernel reports a fully drained map with ENOENT.
            raise OSError(errno.ENOENT, "end of map")
        raise AssertionError(f"unexpected bpf command {cmd}")


class PortPolicyMapLayoutTests(unittest.TestCase):
    def _open(self, cls, kernel):
        for patch in (
            mock.patch.object(maps_mod, "obj_get", return_value=9),
            mock.patch.object(maps_mod, "map_max_entries", return_value=kernel.max_entries),
            mock.patch.object(maps_mod, "map_value_size", return_value=kernel.value_size),
            mock.patch.object(maps_mod, "bpf", side_effect=kernel.bpf),
        ):
            patch.start()
            self.addCleanup(patch.stop)
        policy_map = cls(PATH)
        # No real descriptor backs fd 9; keep __del__ from closing one.
        self.addCleanup(setattr, policy_map, "fd", -1)
        return policy_map

    def test_udp_rate_limits_use_udp_struct_layout(self):
        kernel = FakeKernelHashMap(value_size=24)
        policy_map = self._open(BpfUdpPortPolicyMap, kernel)
        rate = BpfPortPolicyViewMap(policy_map, 0, PATH)
        agg = BpfPortPolicyViewMap(policy_map, 1, PATH)

        self.assertTrue(rate.set(53, 5000))
        self.assertEqual(
            kernel.decode(53, UDP_FIELDS),
            {"rate_max": 5000, "agg_rate_max": 0, "source_prefix_v4": 32,
             "source_prefix_v6": 128, "_pad0": 0, "_pad1": 0},
        )

        self.assertTrue(agg.set(53, 1_000_000))
        policy_map.ensure_prefixes({53}, 24, 64)
        self.assertEqual(
            kernel.decode(53, UDP_FIELDS),
            {"rate_max": 5000, "agg_rate_max": 1_000_000, "source_prefix_v4": 24,
             "source_prefix_v6": 64, "_pad0": 0, "_pad1": 0},
        )
        self.assertEqual(rate.active(), {53: 5000})
        self.assertEqual(agg.active(), {53: 1_000_000})

    def test_udp_entry_is_deleted_when_both_rates_are_cleared(self):
        kernel = FakeKernelHashMap(value_size=24)
        policy_map = self._open(BpfUdpPortPolicyMap, kernel)
        rate = BpfPortPolicyViewMap(policy_map, 0, PATH)
        agg = BpfPortPolicyViewMap(policy_map, 1, PATH)
        rate.set(123, 500)
        agg.set(123, 4096)

        self.assertTrue(rate.delete(123))
        self.assertEqual(kernel.decode(123, UDP_FIELDS)["agg_rate_max"], 4096)
        self.assertEqual(kernel.decode(123, UDP_FIELDS)["rate_max"], 0)

        self.assertTrue(agg.delete(123))
        self.assertNotIn(123, kernel.values)

    def test_udp_entries_written_with_tcp_layout_are_repaired(self):
        kernel = FakeKernelHashMap(value_size=24)
        # Older releases wrote (rate, agg, 0, 32, 128, 0, 0, 0); the kernel kept 24 bytes.
        kernel.values = {
            53: struct.pack("=6I", 5000, 0, 0, 32, 128, 0),
            123: struct.pack("=6I", 500, 0, 0, 32, 128, 0),
        }
        policy_map = self._open(BpfUdpPortPolicyMap, kernel)
        self.assertEqual(BpfPortPolicyViewMap(policy_map, 0, PATH).active(), {53: 5000, 123: 500})

        policy_map.ensure_prefixes({53, 123}, 32, 128)

        for port, rate_max in ((53, 5000), (123, 500)):
            self.assertEqual(
                kernel.decode(port, UDP_FIELDS),
                {"rate_max": rate_max, "agg_rate_max": 0, "source_prefix_v4": 32,
                 "source_prefix_v6": 128, "_pad0": 0, "_pad1": 0},
            )
        self.assertEqual(policy_map.verify(), 0)

    def test_tcp_policy_layout_is_unchanged(self):
        kernel = FakeKernelHashMap(value_size=32)
        policy_map = self._open(BpfPortPolicyMap, kernel)
        BpfPortPolicyViewMap(policy_map, 0, PATH).set(443, 100)
        BpfPortPolicyViewMap(policy_map, 1, PATH).set(443, 2000)
        policy_map.ensure_prefixes({443}, 24, 64)

        self.assertEqual(
            kernel.decode(443, TCP_FIELDS),
            {"syn_rate_max": 100, "syn_agg_rate_max": 2000, "_reserved2": 0,
             "source_prefix_v4": 24, "source_prefix_v6": 64,
             "_reserved5": 0, "_reserved6": 0, "_pad": 0},
        )

    def test_policy_maps_reject_kernel_value_size_mismatch(self):
        for cls, kernel_size, expected_size in (
            (BpfPortPolicyMap, 24, 32),
            (BpfUdpPortPolicyMap, 32, 24),
        ):
            with self.subTest(cls=cls.__name__), \
                 mock.patch.object(maps_mod, "obj_get", return_value=9), \
                 mock.patch.object(maps_mod, "map_max_entries", return_value=1024), \
                 mock.patch.object(maps_mod, "map_value_size", return_value=kernel_size), \
                 mock.patch.object(maps_mod, "bpf") as bpf, \
                 mock.patch.object(maps_mod.os, "close") as close:
                with self.assertRaisesRegex(
                    OSError, f"value_size={kernel_size}, expected {expected_size}",
                ):
                    cls(PATH)
                close.assert_called_once_with(9)
                bpf.assert_not_called()
