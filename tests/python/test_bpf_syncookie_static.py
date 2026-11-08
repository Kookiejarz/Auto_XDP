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


DISPATCH = (ROOT / "bpf/include/port_dispatch.h").read_text()
RATE = (ROOT / "bpf/include/rate_limit.h").read_text()
CONNTRACK = (ROOT / "bpf/include/linux_conntrack.h").read_text()


def _body(source: str, signature: str) -> str:
    start = source.index(signature)
    end = source.index("\n}\n", start)
    return source[start:end]


def test_tcp_policy_classifies_with_one_conntrack_lookup() -> None:
    policy = _body(MAIN, "check_tcp_policy(")
    assert policy.count("linux_ct_classify(") == 1
    assert "linux_ct_reply(" not in policy
    assert "bpf_xdp_ct_lookup" not in policy
    classify = _body(CONNTRACK, "linux_ct_classify(")
    assert classify.count("bpf_xdp_ct_lookup(") == 1 and "bpf_ct_release(ct)" in classify


def test_known_flows_never_reach_the_cookie_validator() -> None:
    policy = _body(MAIN, "check_tcp_policy(")
    assert "pure_ack && ct_class != LINUX_CT_ORIGINAL" in policy
    known = _body(COOKIE, "syncookie_known_flow(")
    assert "linux_ct_established" not in known and "BPF_TCP_ESTABLISHED" not in known
    assert "bpf_skc_lookup_tcp(" in known and "!= BPF_TCP_LISTEN" in known
    assert "bpf_sk_release(skc)" in known


def test_cookie_tail_call_miss_continues_on_the_normal_path() -> None:
    dispatch = _body(DISPATCH, "try_dispatch_syncookie(")
    assert "static __always_inline void try_dispatch_syncookie(" in DISPATCH
    assert "XDP_DROP" not in dispatch and "emit_drop" not in dispatch
    assert "return dispatch_syncookie" not in MAIN


def test_cookie_guard_base_is_port_wide_and_zero_never_drops() -> None:
    guard = _body(RATE, "syncookie_guard_check(")
    assert "syn_rate_max" not in guard and "tcp_port_policies" not in guard
    assert "*mode == 2 ? SYN_GUARD_COOKIE : SYN_GUARD_ALLOW" in guard


def test_ack_validation_follows_issued_cookies_not_momentary_state() -> None:
    ack = _body(RATE, "syncookie_ack_enabled(")
    assert "SYNCOOKIE_ACK_GRACE_NS" in ack and "cooldown_until_ns" in ack
    assert "state->state == 1" not in ack
    assert "(125ULL * 1000000000ULL)" in RATE


COMMON = (ROOT / "bpf/include/common.h").read_text()


def test_pure_ack_ignores_ecn_feedback_psh_and_urg() -> None:
    helper = _body(COMMON, "tcp_pure_ack(")
    assert "(tcp_flags & TCP_CONTROL_FLAGS) == TCP_FLAG_ACK" in helper
    assert "#define TCP_CONTROL_FLAGS (TCP_FLAG_SYN | TCP_FLAG_ACK | TCP_FLAG_RST | TCP_FLAG_FIN)" in COMMON
    assert MAIN.count("bool pure_ack = tcp_pure_ack(tcp_flags, l4_len, tcp->doff);") == 2
    assert "tcp_flags == TCP_FLAG_ACK &&" not in MAIN


def test_cookie_synack_sets_every_flag_and_is_not_ect() -> None:
    flags = _body(COOKIE, "syncookie_synack_flags(")
    assert "bytes[12] &= 0xf0;" in flags
    assert "bytes[13] = TCP_FLAG_SYN | TCP_FLAG_ACK | (ecn_ok ? TCP_FLAG_ECE : 0);" in flags
    assert COOKIE.count("syncookie_synack_flags(tcp, syn_opts.ecn_ok);") == 2
    assert "tcp->ack = 1;" not in COOKIE and "tcp->syn = 1;" not in COOKIE
    assert "ip->tos = 0;" in COOKIE and "ip->ttl = SYNCOOKIE_SYNACK_TTL;" in COOKIE
    assert "ip->priority = 0;" in COOKIE and "ip->hop_limit = SYNCOOKIE_SYNACK_TTL;" in COOKIE
    assert "ip->flow_lbl[0] = 0;" in COOKIE


def test_cookie_ecn_decision_matches_the_listener() -> None:
    decide = _body(COOKIE, "syncookie_ecn_ok(")
    assert "(bytes[13] & 0xc0) != 0xc0" in decide
    assert "XDP_CFG_FLAG_ECN_REFUSED" in decide
    assert "ip_ecn == 0 || (bytes[12] & 0x0f)" in decide
    assert "syn_opts.ecn_ok = syncookie_ecn_ok(tcp, ip->tos & 0x03);" in COOKIE
    assert "syn_opts.ecn_ok = syncookie_ecn_ok(tcp, (ip->flow_lbl[0] >> 4) & 0x03);" in COOKIE
    assert "#define XDP_CFG_FLAG_ECN_REFUSED          (1U << 5)" in COMMON
