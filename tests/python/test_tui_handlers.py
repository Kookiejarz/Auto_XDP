import json
import subprocess
from unittest import mock

import pytest

from auto_xdp.tui import handlers
from auto_xdp.tui.app import MapUsageCache, _collect_map_usage


def prepare(root):
    for name, _ in handlers._TABLES:
        (root / name).touch()


@pytest.mark.parametrize("broken", [False, True])
def test_icmp_has_one_row_and_checks_both_families(tmp_path, broken):
    prepare(tmp_path)
    context = handlers.handler_catalog.Context(tmp_path / "config.toml", tmp_path, tmp_path / "custom", tmp_path, tmp_path / "run")
    programs = [dict(id=11, name="xdp_icmp_handler", pinned=[str(tmp_path / "modules/icmp/prog")])]
    def query(*args):
        return programs if args[0] == "-f" else ([{"key": key, "value": 11} for key in (1, 58)]
                                                 if args[-1].endswith("proto_handlers") else [])
    with mock.patch.object(handlers, "_query", side_effect=query), \
            mock.patch.object(handlers.module_runtime, "verify_icmp", side_effect=RuntimeError("IPv6 missing") if broken else None, return_value=11):
        inventory = handlers.collect_handlers(str(tmp_path), {"modules": {"icmp": {"enabled": True}}}, handlers.HandlerCache(), context=context)
    rows = [row for row in inventory.rows if row.module and row.module.id == "icmp"]
    assert len(rows) == 1 and rows[0].kind == "ICMP"
    assert rows[0].state == ("incomplete" if broken else "loaded")
    assert handlers.handler_labels(rows[0]) == ("ICMP", "XDP / IPv4 + IPv6")


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
        dict(id=99, name="stale_gre", pinned=[str(tmp_path / "protocol_handlers/47/prog")]),
        dict(id=100, name="unrelated", pinned=[str(tmp_path.parent / "other/handlers/proto_50")]),
        dict(id=101, name="xdp_port_whitelist", pinned=[str(tmp_path / "prog"), str(tmp_path / "core_alias")]),
        dict(id=102, name="trace_inet_sock_set_state", pinned=[str(tmp_path / "sock_state_prog")]),
        dict(id=103, name="tc_egress_dispatch", pinned=[str(tmp_path / "tc_egress_dispatch_prog")]),
        dict(id=104, name="tc_syncookie_handoff", pinned=[str(tmp_path / "modules/syncookie/ingress")]),
        # Program names alone must not hide a separately installed candidate.
        dict(id=105, name="xdp_port_whitelist", pinned=[str(tmp_path / "custom_candidate")]),
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
    assert not {101, 102, 103, 104} & {row.program_id for row in inventory.rows}
    assert rows["PROGRAM", 105].pin == "custom_candidate"
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


@pytest.mark.parametrize("tc_id,state", [(12, "loaded"), (99, "incomplete"), (None, "incomplete")])
def test_syncookie_is_one_module_and_status_includes_real_tc_attachment(tmp_path, tc_id, state):
    prepare(tmp_path)
    context = handlers.handler_catalog.Context(tmp_path / "config.toml", tmp_path, tmp_path / "custom", tmp_path, tmp_path / "run", "eth0")
    xdp_pin = "modules/syncookie/prog"
    tc_pin = "modules/syncookie/ingress"
    programs = [dict(id=11, name="xdp_syncookie", pinned=[str(tmp_path / xdp_pin)]),
                dict(id=12, name="handoff", pinned=[str(tmp_path / tc_pin), str(tmp_path / "handoff_alias")])]
    def query(*args):
        return programs if args[0] == "-f" else ([{"key": 0, "value": 11}] if args[-1].endswith("syncookie_prog_array") else [])
    with mock.patch.object(handlers, "_query", side_effect=query), \
            mock.patch.object(handlers.module_runtime, "tc_program_id", return_value=tc_id):
        inventory = handlers.collect_handlers(str(tmp_path), {}, handlers.HandlerCache(), context=context)
    rows = [row for row in inventory.rows if row.module and row.module.id == "syncookie"]
    assert len(rows) == 1 and rows[0].state == state
    assert rows[0].program_id == 11 and rows[0].pin == xdp_pin
    assert all(row.program_id != 12 for row in inventory.rows)


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


def test_role_labels_separate_purpose_binding_and_observed_state():
    from auto_xdp.admin.handler_catalog import Module

    cases = [
        (handlers.HandlerRow("SYNCOOKIE", 0, 11, "xdp_syncookie", "loaded"), ("SYN cookie", "XDP + TC in / SYN")),
        (handlers.HandlerRow("TC_SYNCOOKIE", 0, 12, "handoff", "pin only"), ("SYN handoff", "TC in / SYN")),
        (handlers.HandlerRow("SLOT", 47, 13, "gre", "loaded"), ("Protocol", "XDP / IP 47/GRE")),
        (handlers.HandlerRow("TC_SLOT", 132, 14, "sctp", "loaded"), ("Protocol", "TC out / IP 132/SCTP")),
        (handlers.HandlerRow("TCP", 8443, 15, "tcp", "loaded"), ("Port handler", "XDP / TCP 8443")),
        (handlers.HandlerRow("TC_UDP", 30120, 16, "udp", "pin only"), ("Port handler", "TC out / UDP 30120")),
        (handlers.HandlerRow("PROFILE", 1, 17, "minecraft", "loaded"), ("App profile", "XDP / TCP #1")),
        (handlers.HandlerRow("PROGRAM", 18, 18, "main", "pin only", "prog"), ("Firewall", "XDP ingress")),
        (handlers.HandlerRow("PROGRAM", 19, 19, "socket", "pin only", "sock_state_prog"), ("Socket trace", "Tracepoint")),
        (handlers.HandlerRow("PROGRAM", 20, 20, "dispatch", "pin only", "tc_egress_dispatch_prog"), ("TC dispatch", "TC egress")),
        (handlers.HandlerRow("PROGRAM", 21, 21, "unknown", "pin only", "custom_pin"), ("Pinned prog", "-")),
        (handlers.HandlerRow("AVAILABLE", 47, None, "GRE", "available", module=Module("gre", "GRE", "/gre.o", "slot", 47)),
         ("Protocol", "IP 47/GRE")),
        (handlers.HandlerRow("AVAILABLE", 53, None, "Demo", "build fail", module=Module("demo", "Demo", "/demo.c"), binding_kind="udp"),
         ("Port handler", "UDP 53")),
        (handlers.HandlerRow("AVAILABLE", 0, None, "Demo", "available", module=Module("demo", "Demo", "/demo.c")),
         ("Handler", "Not selected")),
    ]
    for row, labels in cases:
        state = row.state
        assert handlers.handler_labels(row) == labels
        assert row.state == state
