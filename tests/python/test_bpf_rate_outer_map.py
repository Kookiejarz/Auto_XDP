"""Unit tests for BpfRateOuterMap (per-port ARRAY_OF_MAPS wrapper)."""
import unittest
from unittest import mock

from auto_xdp.bpf import maps as maps_mod


class FakeInnerRegistry:
    """Tracks map_create calls; fd == map id for test simplicity."""

    def __init__(self):
        self.caps: dict[int, int] = {}   # fd/id -> max_entries
        self.created: list[tuple] = []   # (key_size, value_size, capacity, flags, name)
        self.next_fd = 100
        self.fail_create = False

    def map_create(self, map_type, key_size, value_size, max_entries,
                   map_flags=0, inner_map_fd=0, name=b""):
        if self.fail_create:
            raise OSError(12, "ENOMEM")
        self.created.append((key_size, value_size, max_entries, map_flags, name))
        self.next_fd += 1
        self.caps[self.next_fd] = max_entries
        return self.next_fd


def _make_map(reg, key_size=4):
    m = object.__new__(maps_mod.BpfRateOuterMap)
    m.path = "/sys/fs/bpf/xdp_fw/syn4"
    m.fd = 9
    m._inner_key_size = key_size
    m._inner_value_size = 16
    m._name_prefix = "s4_"
    m._max_entries = 65536
    m._cache = {}
    return m


class RateOuterMapTests(unittest.TestCase):
    def setUp(self):
        self.reg = FakeInnerRegistry()
        for p in (
            mock.patch.object(maps_mod, "map_create", self.reg.map_create),
            mock.patch.object(maps_mod, "map_get_fd_by_id", lambda i: i),
            mock.patch.object(maps_mod, "map_max_entries",
                              lambda fd: self.reg.caps[fd]),
            mock.patch.object(maps_mod.os, "close", lambda fd: None),
        ):
            p.start()
            self.addCleanup(p.stop)

    def test_set_creates_inner_and_updates_slot(self):
        m = _make_map(self.reg)
        with mock.patch.object(m, "_update_slot", return_value=True) as upd:
            self.assertTrue(m.set(443, 8192))
        upd.assert_called_once()
        self.assertEqual(self.reg.created[0][:4],
                         (4, 16, 8192, 0))
        self.assertEqual(m.active(), {443: 8192})

    def test_set_same_capacity_is_noop(self):
        m = _make_map(self.reg)
        m._cache = {443: 8192}
        self.assertTrue(m.set(443, 8192))
        self.assertEqual(self.reg.created, [])

    def test_set_capacity_change_rebuilds_inner(self):
        m = _make_map(self.reg)
        m._cache = {443: 8192}
        with mock.patch.object(m, "_update_slot", return_value=True):
            self.assertTrue(m.set(443, 16384))
        self.assertEqual(self.reg.created[0][2], 16384)
        self.assertEqual(m.active(), {443: 16384})

    def test_set_dry_run_touches_nothing(self):
        m = _make_map(self.reg)
        self.assertTrue(m.set(443, 8192, dry_run=True))
        self.assertEqual(self.reg.created, [])
        self.assertEqual(m.active(), {})

    def test_set_returns_false_on_create_failure(self):
        m = _make_map(self.reg)
        self.reg.fail_create = True
        self.assertFalse(m.set(443, 8192))
        self.assertEqual(m.active(), {})

    def test_set_returns_false_on_slot_update_failure(self):
        m = _make_map(self.reg)
        with mock.patch.object(m, "_update_slot", return_value=False):
            self.assertFalse(m.set(443, 8192))
        self.assertEqual(m.active(), {})

    def test_delete_removes_slot_and_cache(self):
        m = _make_map(self.reg)
        m._cache = {443: 8192}
        with mock.patch.object(m, "_delete_slot", return_value=True):
            self.assertTrue(m.delete(443))
        self.assertEqual(m.active(), {})

    def test_delete_unknown_port_is_noop_true(self):
        m = _make_map(self.reg)
        self.assertTrue(m.delete(9999))

    def test_verify_repairs_cache_from_kernel(self):
        m = _make_map(self.reg)
        m._cache = {22: 4096}
        with mock.patch.object(m, "_read_kernel",
                               return_value={22: 4096, 443: 8192}):
            self.assertEqual(m.verify(), 1)
        self.assertEqual(m.active(), {22: 4096, 443: 8192})

    def test_verify_clean_returns_zero(self):
        m = _make_map(self.reg)
        m._cache = {22: 4096}
        with mock.patch.object(m, "_read_kernel", return_value={22: 4096}):
            self.assertEqual(m.verify(), 0)


if __name__ == "__main__":
    unittest.main()
