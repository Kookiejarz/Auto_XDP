"""Regression guards for shared BPF counter synchronization."""

from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[2]


def _source(relative: str) -> str:
    return (ROOT / relative).read_text()


def test_window_rate_updates_are_atomic_and_insert_without_overwrite():
    source = _source("bpf/include/rate_limit.h")
    keys = _source("bpf/include/keys.h")

    assert "BPF_NOEXIST" in source
    assert "__sync_fetch_and_add" in source
    assert "__sync_val_compare_and_swap" in source
    assert "__sync_val_compare_and_swap(&_rv->state, _current, _next)" in source
    for name in ("syn_rate_val", "prefix_rate_val"):
        struct_body = keys.split(f"struct {name} {{", 1)[1].split("};", 1)[0]
        assert "__u64 state;" in struct_body
        assert "window_start_ns;" not in struct_body


def test_rate_outer_maps_create_values_matching_packed_bpf_state():
    source = _source("auto_xdp/backends/xdp.py")

    for map_path in ("SYN4_MAP_PATH", "SYN6_MAP_PATH", "UDPRT4_MAP_PATH", "UDPRT6_MAP_PATH"):
        constructor = source.split(f"cfg.{map_path}", 1)[1].split(")", 1)[0]
        assert ", 8," in constructor


def test_connection_counter_values_use_one_atomic_state_word():
    source = _source("bpf/include/keys.h")

    for name in ("tcp_src_conn_val", "tcp_pfx_conn_val", "tcp_port_conn_val"):
        struct_body = source.split(f"struct {name} {{", 1)[1].split("};", 1)[0]
        assert "__u64 state;" in struct_body
        assert "count;" not in struct_body
        assert "last_seen_ns;" not in struct_body


def test_shared_conntrack_map_capacities_match_all_bpf_objects():
    sizes = _source("bpf/include/map_sizes.h")
    maps = _source("bpf/include/maps.h")
    tc = _source("tc_flow_track.c")
    minecraft = _source("handlers/minecraft_handler.c")

    assert "CT_MAP_MAX_ENTRIES_V4 196608" in sizes
    assert "CT_MAP_MAX_ENTRIES_V6 196608" in sizes
    assert "RATE_MAP_MAX_ENTRIES_V4 49152" in sizes
    assert "RATE_MAP_MAX_ENTRIES_V6 16384" in sizes
    for source in (maps, tc, minecraft):
        assert "CT_MAP_MAX_ENTRIES_V4" in source
        assert "CT_MAP_MAX_ENTRIES_V6" in source
    for source in (tc, minecraft):
        assert re.search(
            r"__uint\(max_entries,\s*65536\).*?\}\s*(?:tcp_ct6|udp_ct6)",
            source,
            re.S,
        ) is None


def test_ipv6_bogon_filter_admits_ndp_before_source_filter():
    source = _source("bpf/xdp_firewall.c")
    assert "ndp_control = icmp6_type >= 133 && icmp6_type <= 137" in source
    assert "!ndp_control && is_bogon_v6" in source
    assert source.index("ndp_control =") < source.index("!ndp_control && is_bogon_v6")


def test_minecraft_large_offsets_fail_closed():
    source = _source("handlers/minecraft_handler.c")
    guard = source.split("if (l3_off > 255 || inner_off_u32 > 255)", 1)[1]
    assert "return XDP_DROP;" in guard.split("\n", 2)[1]


def test_tc_uses_runtime_conntrack_timers_and_shared_runtime_map():
    source = _source("tc_flow_track.c")
    loader = _source("runtime/auto_xdp_runtime_common.sh")
    assert "} xdp_runtime_cfg SEC(\".maps\");" in source
    assert "tc_tcp_timeout_ns()" in source
    assert "tc_refresh_ns()" in source
    assert "TCP_TIMEOUT_NS" not in source
    assert "CT_REFRESH_INTERVAL" not in source
    assert 'map name xdp_runtime_cfg pinned "${BPF_PIN_DIR}/xdp_runtime_cfg"' in loader


def test_activity_refreshes_prefix_and_port_connection_counters():
    source = _source("bpf/include/rate_limit.h")
    activity = source.split("tcp_src_conn_record_activity", 1)[1].split(
        "tcp_src_conn_record_close", 1
    )[0]
    assert "tsc_pfx4" in activity
    assert "tsc_pfx6" in activity
    assert "tsc_port" in activity
    assert activity.count("shared_conn_count_activity") == 5


def test_connection_counter_mutations_happen_under_shared_helpers():
    source = _source("bpf/include/rate_limit.h")

    assert "shared_conn_count_record" in source
    assert "shared_conn_count_close" in source
    assert "__sync_val_compare_and_swap(state, current, next)" in source
    assert "__sync_lock_test_and_set(state, conn_state_pack(now_tick, 0xFFFFFFFFU))" in source
    assert source.count("shared_conn_count_fail_closed(state, now_tick);") == 3
    assert "sv->count++" not in source
    assert "sv->count--" not in source
    assert "pv->count++" not in source
    assert "pv->count--" not in source


def test_minecraft_rate_counter_uses_atomic_window_updates():
    source = _source("handlers/minecraft_handler.c")
    struct_body = source.split("struct mc_rate_val {", 1)[1].split("};", 1)[0]

    assert "__u64 state;" in struct_body
    assert "BPF_NOEXIST" in source
    assert "__sync_val_compare_and_swap" in source
    assert "_v->count++" not in source
