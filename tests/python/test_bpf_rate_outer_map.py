"""Unit tests for BpfRateOuterMap (per-port ARRAY_OF_MAPS wrapper)."""
import ctypes
import errno
import struct
import unittest
from unittest import mock

import pytest

from auto_xdp.bpf import maps as maps_mod


pytestmark = pytest.mark.component


def test_port_policy_value_abi_is_eight_u32_fields():
    assert maps_mod.BpfPortPolicyMap._STRUCT_FMT == "=IIIIIIII"
    assert struct.calcsize(maps_mod.BpfPortPolicyMap._STRUCT_FMT) == 32


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
    # No real map fd belongs to this source-only fixture.  Keeping a positive
    # dummy fd lets __del__ close an unrelated pytest descriptor at teardown.
    m.fd = -1
    m._inner_key_size = key_size
    m._inner_value_size = 8
    m._inner_max_entries = 8192
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
                         (4, 8, 8192, 0))
        self.assertEqual(m.active(), {443: 8192})

    def test_set_same_capacity_is_noop(self):
        m = _make_map(self.reg)
        m._cache = {443: 8192}
        self.assertTrue(m.set(443, 8192))
        self.assertEqual(self.reg.created, [])

    def test_set_rejects_capacity_that_cannot_match_template(self):
        m = _make_map(self.reg)
        m._cache = {443: 8192}
        with mock.patch.object(m, "_update_slot", return_value=True):
            self.assertFalse(m.set(443, 16384))
        self.assertEqual(self.reg.created, [])
        self.assertEqual(m.active(), {443: 8192})

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


@pytest.fixture
def readable_map():
    outer = _make_map(None)
    outer.fd = 42
    yield outer
    outer.fd = -1


def batch_page(attr, entries):
    incoming, cursor, keys, values, count, fd, elem_flags, flags = struct.unpack_from("=QQQQIIQQ", attr)
    assert fd == 42 and elem_flags == flags == 0
    assert len(entries) <= count
    for index, (port, inner_id) in enumerate(entries):
        ctypes.c_uint32.from_address(keys + index * 4).value = port
        ctypes.c_uint32.from_address(values + index * 4).value = inner_id
    struct.pack_into("=I", attr, 32, len(entries))
    if entries:
        ctypes.c_uint32.from_address(cursor).value = entries[-1][0]


def test_empty_batch_repairs_stale_cache_without_single_lookups(readable_map, monkeypatch):
    readable_map._cache = {443: 8192}
    calls = []

    def syscall(cmd, attr):
        calls.append(cmd)
        batch_page(attr, [])
        raise OSError(errno.ENOENT, "end of map")

    monkeypatch.setattr(maps_mod, "bpf", syscall)
    assert readable_map.verify() == 1
    assert readable_map.active() == {}
    assert calls == [maps_mod.BPF_MAP_LOOKUP_BATCH]


def test_sparse_batches_resume_and_keep_entries_returned_with_enoent(readable_map, monkeypatch):
    calls = []
    opened = []
    closed = []

    def syscall(cmd, attr):
        assert cmd == maps_mod.BPF_MAP_LOOKUP_BATCH
        incoming = struct.unpack_from("=Q", attr)[0]
        calls.append(None if not incoming else ctypes.c_uint32.from_address(incoming).value)
        assert struct.unpack_from("=I", attr, 32)[0] == 1024
        if len(calls) == 1:
            batch_page(attr, [(0, 100), (443, 101)])
        else:
            batch_page(attr, [(65535, 102)])
            raise OSError(errno.ENOENT, "last page")

    def open_inner(inner_id):
        opened.append(inner_id)
        return inner_id + 1000

    monkeypatch.setattr(maps_mod, "bpf", syscall)
    monkeypatch.setattr(maps_mod, "map_get_fd_by_id", open_inner)
    monkeypatch.setattr(maps_mod, "map_max_entries", lambda fd: {1100: 8, 1101: 16, 1102: 32}[fd])
    monkeypatch.setattr(maps_mod.os, "close", closed.append)
    assert readable_map._read_kernel() == {0: 8, 443: 16, 65535: 32}
    assert calls == [None, 443]
    assert opened == [100, 101, 102]
    assert closed == [1100, 1101, 1102]


@pytest.mark.parametrize("unsupported", [errno.EINVAL, errno.EOPNOTSUPP, errno.ENOSYS])
def test_unsupported_batch_falls_back_to_single_slot_reads(readable_map, monkeypatch, unsupported):
    readable_map._max_entries = 4
    commands = []

    def syscall(cmd, attr):
        commands.append(cmd)
        if cmd == maps_mod.BPF_MAP_LOOKUP_BATCH:
            raise OSError(unsupported, "unsupported batch")
        assert cmd == maps_mod.BPF_MAP_LOOKUP_ELEM
        fd, key, value = struct.unpack_from("=I4xQQ", attr)
        assert fd == 42
        port = ctypes.c_uint32.from_address(key).value
        if port != 3:
            raise OSError(errno.ENOENT, "empty slot")
        ctypes.c_uint32.from_address(value).value = 123

    monkeypatch.setattr(maps_mod, "bpf", syscall)
    monkeypatch.setattr(maps_mod, "map_get_fd_by_id", lambda inner_id: inner_id)
    monkeypatch.setattr(maps_mod, "map_max_entries", lambda fd: 8192)
    with mock.patch.object(maps_mod.os, "close") as close:
        assert readable_map._read_kernel() == {3: 8192}
    close.assert_called_once_with(123)
    assert commands == [maps_mod.BPF_MAP_LOOKUP_BATCH] + [maps_mod.BPF_MAP_LOOKUP_ELEM] * 4


@pytest.mark.parametrize("failure", [errno.EPERM, errno.EFAULT, errno.EIO])
def test_batch_read_errors_preserve_cache(readable_map, monkeypatch, failure):
    readable_map._cache = {443: 8192}
    syscall = mock.Mock(side_effect=OSError(failure, "read failed"))
    monkeypatch.setattr(maps_mod, "bpf", syscall)
    with pytest.raises(OSError) as exc:
        readable_map.verify()
    assert exc.value.errno == failure
    assert readable_map.active() == {443: 8192}
    assert syscall.call_count == 1


def test_inner_metadata_failure_closes_fd_and_preserves_cache(readable_map, monkeypatch):
    readable_map._cache = {443: 8192}

    def syscall(cmd, attr):
        batch_page(attr, [(443, 100)])
        raise OSError(errno.ENOENT, "last page")

    monkeypatch.setattr(maps_mod, "bpf", syscall)
    monkeypatch.setattr(maps_mod, "map_get_fd_by_id", lambda inner_id: 123)
    monkeypatch.setattr(maps_mod, "map_max_entries", mock.Mock(side_effect=OSError(errno.EIO, "metadata failed")))
    with mock.patch.object(maps_mod.os, "close") as close, pytest.raises(OSError):
        readable_map.verify()
    close.assert_called_once_with(123)
    assert readable_map.active() == {443: 8192}


@pytest.mark.parametrize("failure", [errno.EIO, errno.EOPNOTSUPP])
def test_error_after_first_batch_does_not_publish_partial_cache(readable_map, monkeypatch, failure):
    readable_map._cache = {443: 8192}
    calls = []

    def syscall(cmd, attr):
        calls.append(cmd)
        if len(calls) == 1:
            batch_page(attr, [(22, 100)])
        else:
            raise OSError(failure, "next page failed")

    monkeypatch.setattr(maps_mod, "bpf", syscall)
    monkeypatch.setattr(maps_mod, "map_get_fd_by_id", lambda inner_id: 123)
    monkeypatch.setattr(maps_mod, "map_max_entries", lambda fd: 8192)
    with mock.patch.object(maps_mod.os, "close"), pytest.raises(OSError):
        readable_map.verify()
    assert calls == [maps_mod.BPF_MAP_LOOKUP_BATCH] * 2
    assert readable_map.active() == {443: 8192}


def test_disappearing_inner_map_is_not_treated_as_end_of_batch(readable_map, monkeypatch):
    readable_map._cache = {443: 8192}

    def syscall(cmd, attr):
        batch_page(attr, [(443, 100)])
        raise OSError(errno.ENOENT, "last page")

    monkeypatch.setattr(maps_mod, "bpf", syscall)
    monkeypatch.setattr(maps_mod, "map_get_fd_by_id", mock.Mock(side_effect=OSError(errno.ENOENT, "inner disappeared")))
    with pytest.raises(OSError):
        readable_map.verify()
    assert readable_map.active() == {443: 8192}


@pytest.mark.parametrize("count", [0, 1025])
def test_invalid_batch_count_cannot_confirm_or_loop_forever(readable_map, monkeypatch, count):
    readable_map._cache = {443: 8192}

    def syscall(cmd, attr):
        struct.pack_into("=I", attr, 32, count)

    monkeypatch.setattr(maps_mod, "bpf", syscall)
    with pytest.raises(OSError) as exc:
        readable_map.verify()
    assert exc.value.errno == errno.EIO
    assert readable_map.active() == {443: 8192}


if __name__ == "__main__":
    unittest.main()
