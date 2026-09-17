from pathlib import Path


ROOT = Path(__file__).parents[2]
COOKIE = (ROOT / "bpf/xdp_syncookie.c").read_text()
MAIN = (ROOT / "bpf/xdp_firewall.c").read_text()
RUNTIME = (ROOT / "runtime/auto_xdp_runtime_common.sh").read_text()


def test_optional_program_isolated_from_raw_helpers() -> None:
    assert "bpf_tcp_raw_gen_syncookie_ipv4" not in MAIN
    assert "bpf_tcp_raw_check_syncookie_ipv4" not in MAIN
    assert "bpf_tcp_raw_gen_syncookie_ipv4" in COOKIE
    assert "bpf_tcp_raw_check_syncookie_ipv6" in COOKIE
    assert "bpf_tail_call(ctx, &syncookie_prog_array, 0)" in MAIN or \
        "bpf_tail_call(ctx, &syncookie_prog_array, 0)" in (ROOT / "bpf/include/port_dispatch.h").read_text()


def test_cookie_path_handles_vlan_options_and_extension_offsets() -> None:
    assert "sc->l3_offset" in COOKIE
    assert "sc->inner_offset" in COOKIE
    assert "ip->ihl > 5" in COOKIE
    assert "inner_offset != l3_offset + sizeof(*ip)" in COOKIE


def test_runtime_does_not_require_optional_private_maps() -> None:
    assert "map name sync_invalid4" not in RUNTIME
    assert "map name sync_invalid6" not in RUNTIME


def test_invalid_ack_budget_is_bounded_cas() -> None:
    assert "__sync_val_compare_and_swap" in COOKIE
    assert "bounded CAS" in COOKIE
