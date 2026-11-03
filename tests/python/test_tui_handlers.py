import json
import subprocess
from unittest import mock

import pytest

from auto_xdp.tui import handlers
from auto_xdp.tui.app import MapUsageCache, _collect_map_usage


def prepare(root):
    for name, _ in handlers._TABLES:
        (root / name).touch()


def test_inventory_uses_dispatch_entries_instead_of_configuration_or_pin_presence(tmp_path):
    prepare(tmp_path)
    config = dict(slots=dict(enabled=["gre"]), port_handlers=dict(tcp={"8080": "/tcp.c"}, udp={"30120": "/udp.c"}))
    programs = [
        dict(id=11, name="actual_gre"),
        dict(id=12, name="custom_udp"),
        dict(id=13, name="tcp_profile", pinned=[str(tmp_path / "profile_handlers/tcp/1/prog")]),
        dict(id=14, name="tc_profile", pinned=[str(tmp_path / "profile_handlers/tcp/1/egress")]),
        dict(id=34, name="tc_orphan", pinned=[str(tmp_path / "port_handlers/tcp/8443/egress")]),
        dict(id=33, name="orphan", pinned=[str(tmp_path / "port_handlers/tcp/8443/prog")]),
        dict(id=99, name="stale_gre", pinned=[str(tmp_path / "handlers/proto_47")]),
        dict(id=100, name="unrelated", pinned=[str(tmp_path.parent / "other/handlers/proto_50")]),
    ]
    entries = {"proto_handlers": [{"key": ["0x2f", "0x00", "0x00", "0x00"], "value": ["0x0b", "0x00", "0x00", "0x00"]}],
               "udp_port_handlers": [{"key": 30120, "value": {"id": 12}}],
               "tcp_profile_handlers": [{"key": 1, "value": 13}],
               "tc_profile_handlers": [{"key": 1, "value": 14}]}

    def query(*args):
        return programs if args[0] == "-f" else entries.get(args[-1].split("/")[-1], [])

    with mock.patch.object(handlers, "_query", side_effect=query):
        inventory = handlers.collect_handlers(str(tmp_path), config, handlers.HandlerCache())
    rows = {(row.kind, row.key): row for row in inventory.rows}
    assert rows["SLOT", 47].state == "loaded" and rows["SLOT", 47].program_id == 11
    assert rows["SLOT", 47].name == "actual_gre" and "99" in rows["SLOT", 47].detail
    assert rows["TCP", 8080].state == "configured" and rows["TCP", 8080].program_id is None
    assert rows["TCP", 8443].state == "pin only" and rows["TCP", 8443].program_id == 33
    assert rows["UDP", 30120].state == "loaded" and rows["UDP", 30120].source == "/udp.c"
    assert rows["PROFILE", 1].state == "loaded" and rows["PROFILE", 1].program_id == 13
    assert rows["TC_PROFILE", 1].state == "loaded" and rows["TC_PROFILE", 1].program_id == 14
    assert rows["TC_TCP", 8443].state == "pin only" and rows["TC_TCP", 8443].program_id == 34
    assert ("SLOT", 50) not in rows
    assert inventory.tables == [("SLOT", "ready", 1), ("TCP", "ready", 0), ("UDP", "ready", 1),
                                ("PROFILE", "ready", 1), ("TC_TCP", "ready", 0), ("TC_UDP", "ready", 0),
                                ("TC_SLOT", "ready", 0), ("TC_PROFILE", "ready", 1), ("SYNCOOKIE", "ready", 0)]


def test_query_failure_is_unknown_and_does_not_claim_an_empty_dispatch_table(tmp_path):
    prepare(tmp_path)

    def query(*args):
        if args[0] == "-f":
            return []
        if args[-1].endswith("tcp_port_handlers"):
            raise subprocess.TimeoutExpired("bpftool", 2)
        return []

    with mock.patch.object(handlers, "_query", side_effect=query):
        inventory = handlers.collect_handlers(str(tmp_path), {"port_handlers": {"tcp": {"8080": "/test.c"}}}, handlers.HandlerCache())
    assert inventory.rows[0].state == "unknown"
    assert ("TCP", "unreadable", None) in inventory.tables
    assert "tcp_port_handlers unreadable" in inventory.status


def test_missing_dispatch_map_does_not_make_a_configured_slot_loaded(tmp_path):
    with mock.patch.object(handlers, "_query", return_value=[]):
        inventory = handlers.collect_handlers(str(tmp_path), {"slots": {"enabled": ["gre"]}}, handlers.HandlerCache())
    assert inventory.rows[0].state == "no map"
    assert inventory.rows[0].program_id is None


def test_inventory_cache_is_bounded_and_invalidated_when_generation_changes(tmp_path):
    prepare(tmp_path)
    cache = handlers.HandlerCache()
    with mock.patch.object(handlers, "_query", return_value=[]) as query:
        first = handlers.collect_handlers(str(tmp_path), {}, cache, generation="a", now=0)
        calls = query.call_count
        assert handlers.collect_handlers(str(tmp_path), {}, cache, generation="a", now=1) is first
        assert query.call_count == calls
        handlers.collect_handlers(str(tmp_path), {}, cache, generation="b", now=2)
        assert query.call_count == calls * 2
        handlers.collect_handlers(str(tmp_path), {}, cache, generation="b", now=8)
        assert query.call_count == calls * 3


@pytest.mark.parametrize("data", [None, {}, [{"key": 1, "value": -1}], [{"key": True, "value": 5}], [{"key": 0, "error": "lookup failed"}]])
def test_unreadable_dispatch_dump_is_rejected(data):
    with pytest.raises(ValueError):
        handlers._dispatch_entries(data)


def test_nested_private_map_pins_have_independent_counts_and_shared_aliases_count_once(tmp_path):
    paths = [tmp_path / "private_state", tmp_path / "port_handlers/udp/30120/private_state", tmp_path / "alias"]
    for path in paths:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.touch()
    root_info = dict(id=7, name="private_state", type="hash", max_entries=20, bytes_memlock=4096)
    child_info = dict(id=8, name="private_state", type="hash", max_entries=20, bytes_memlock=8192)
    metadata = {str(paths[0]): root_info, str(paths[1]): child_info, str(paths[2]): root_info}

    def dump(path):
        return 2 if path.parent == tmp_path else 9

    cache = MapUsageCache()
    with mock.patch("auto_xdp.tui.app._all_map_info", return_value=metadata), \
         mock.patch("auto_xdp.tui.app.read_xdp_ports", return_value=([], [])), \
         mock.patch("auto_xdp.tui.app._dump_count", side_effect=dump) as read:
        rows = _collect_map_usage(str(tmp_path), cache=cache, now=100)
    assert len(rows) == 2 and read.call_count == 2
    assert sum(row.memlock for row in rows) == 12288
    assert next(row for row in rows if row.map_id == 8).name == "port_handlers/udp/30120/private_state"
    assert {row.map_id: row.current for row in rows} == {7: 2, 8: 9}


def test_program_inventory_command_is_read_only_and_bounded():
    with mock.patch.object(handlers.subprocess, "check_output", return_value=b"[]") as query:
        assert handlers._query("-f", "prog", "show") == []
    assert query.call_args.args[0] == ["bpftool", "-j", "-f", "prog", "show"]
    assert query.call_args.kwargs["timeout"] == 2
