"""Attr-packing tests for BPF_MAP_CREATE / BPF_MAP_GET_FD_BY_ID helpers."""
import struct
import unittest
from unittest import mock

from auto_xdp.bpf import syscall as sc


class MapCreateAttrTests(unittest.TestCase):
    def test_map_create_packs_attr_and_returns_fd(self):
        captured = {}

        def fake_bpf(cmd, attr):
            captured["cmd"] = cmd
            captured["raw"] = bytes(attr)
            return 42

        with mock.patch.object(sc, "bpf", fake_bpf):
            fd = sc.map_create(sc.BPF_MAP_TYPE_LRU_HASH, 4, 16, 1024,
                               0x1000, name=b"s4_443")
        self.assertEqual(fd, 42)
        self.assertEqual(captured["cmd"], sc.BPF_MAP_CREATE)
        mt, ks, vs, me, fl, inner = struct.unpack_from("=IIIIII", captured["raw"], 0)
        self.assertEqual((mt, ks, vs, me, fl, inner), (9, 4, 16, 1024, 0x1000, 0))
        name = struct.unpack_from("16s", captured["raw"], 28)[0]
        self.assertEqual(name.rstrip(b"\x00"), b"s4_443")

    def test_map_create_truncates_long_name(self):
        captured = {}

        def fake_bpf(cmd, attr):
            captured["raw"] = bytes(attr)
            return 3

        with mock.patch.object(sc, "bpf", fake_bpf):
            sc.map_create(9, 4, 16, 64, name=b"x" * 40)
        name = struct.unpack_from("16s", captured["raw"], 28)[0]
        self.assertEqual(name.rstrip(b"\x00"), b"x" * 15)

    def test_map_get_fd_by_id_packs_id(self):
        captured = {}

        def fake_bpf(cmd, attr):
            captured["cmd"] = cmd
            captured["raw"] = bytes(attr)
            return 7

        with mock.patch.object(sc, "bpf", fake_bpf):
            fd = sc.map_get_fd_by_id(1234)
        self.assertEqual(fd, 7)
        self.assertEqual(captured["cmd"], sc.BPF_MAP_GET_FD_BY_ID)
        self.assertEqual(struct.unpack_from("=I", captured["raw"], 0)[0], 1234)


class ProbeInnerMapSupportTests(unittest.TestCase):
    def test_probe_true_when_both_creates_succeed(self):
        fds = iter([10, 11])
        with mock.patch.object(sc, "map_create", lambda *a, **k: next(fds)), \
             mock.patch.object(sc.os, "close") as closer:
            self.assertTrue(sc.probe_inner_map_support())
        self.assertEqual(closer.call_count, 2)

    def test_probe_false_on_einval(self):
        with mock.patch.object(sc, "map_create",
                               mock.Mock(side_effect=OSError(22, "EINVAL"))):
            self.assertFalse(sc.probe_inner_map_support())

    def test_probe_raises_on_eperm(self):
        with mock.patch.object(sc, "map_create",
                               mock.Mock(side_effect=PermissionError(1, "EPERM"))):
            with self.assertRaises(PermissionError):
                sc.probe_inner_map_support()


if __name__ == "__main__":
    unittest.main()
