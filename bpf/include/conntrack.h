#pragma once
#include "rate_limit.h"

static __always_inline void fill_flow_key_v4(
    struct flow_key *key, __be32 saddr, __be32 daddr,
    __be16 sport, __be16 dport)
{
    __builtin_memset(key, 0, sizeof(*key));
    key->family = CT_FAMILY_IPV4;
    key->sport = sport;
    key->dport = dport;
    key->saddr[0] = (__u32)saddr;
    key->daddr[0] = (__u32)daddr;
}

static __always_inline void fill_flow_key_v6(
    struct flow_key *key, const struct in6_addr *saddr, const struct in6_addr *daddr,
    __be16 sport, __be16 dport)
{
    __builtin_memset(key, 0, sizeof(*key));
    key->family = CT_FAMILY_IPV6;
    key->sport = sport;
    key->dport = dport;
    __builtin_memcpy(key->saddr, saddr, sizeof(*saddr));
    __builtin_memcpy(key->daddr, daddr, sizeof(*daddr));
}

static __always_inline int check_tcp_conntrack(
    struct xdp_md *ctx,
    struct flow_key *key, __u8 tcp_flags, __u32 dest_port,
    __u16 l3_off, __u16 inner_off)
{
    __u64 now = bpf_ktime_get_ns();
    struct xdp_runtime_cfg *cfg = runtime_cfg();
    __u64 *last_seen;
    bool ipv4 = key->family == CT_FAMILY_IPV4;

    if (tcp_flags & TCP_FLAG_RST) {
        if (!(tcp_flags & TCP_FLAG_ACK))
            goto drop;

        struct ct_key_v4 key_v4;
        struct ct_key_v6 key_v6;
        if (ipv4)
            fill_ct_key_v4_map(&key_v4, key);
        else
            fill_ct_key_v6_map(&key_v6, key);

        last_seen = tcp_conntrack_lookup(ipv4, &key_v4, &key_v6);
        if (!last_seen) {
            count(CNT_TCP_CT_MISS);
            count(CNT_TCP_DROP);
            emit_drop(IPPROTO_TCP, key->family, key->saddr, key->daddr,
                      key->sport, key->dport, (__u8)CNT_TCP_CT_MISS, now);
            return XDP_DROP;
        }
        {
            __u64 raw = *last_seen;
            __u64 ts = raw & ~CT_SYN_PENDING;
            __u64 ct_to = (raw & CT_SYN_PENDING) ? cfg_syn_timeout_ns(cfg) : cfg_tcp_timeout_ns(cfg);
            if (now - ts > ct_to) {
                tcp_conntrack_delete(ipv4, &key_v4, &key_v6);
                tcp_src_conn_record_close(key, now, dest_port);
                count(CNT_TCP_CT_MISS);
                count(CNT_TCP_DROP);
                emit_drop(IPPROTO_TCP, key->family, key->saddr, key->daddr,
                          key->sport, key->dport, (__u8)CNT_TCP_CT_MISS, now);
                return XDP_DROP;
            }
        }
        tcp_conntrack_delete(ipv4, &key_v4, &key_v6);
        tcp_src_conn_record_close(key, now, dest_port);
        count(CNT_TCP_ESTABLISHED);
        return XDP_PASS;
    }

    if (tcp_flags & TCP_FLAG_ACK) {
        __u64 ct_refresh = cfg_ct_refresh_ns(cfg);
        struct ct_key_v4 key_v4;
        struct ct_key_v6 key_v6;
        if (ipv4)
            fill_ct_key_v4_map(&key_v4, key);
        else
            fill_ct_key_v6_map(&key_v6, key);

        last_seen = tcp_conntrack_lookup(ipv4, &key_v4, &key_v6);
        if (last_seen) {
            __u64 raw = *last_seen;
            bool is_half_open = raw & CT_SYN_PENDING;
            __u64 ts = raw & ~CT_SYN_PENDING;
            __u64 age = now - ts;
            __u64 ct_timeout = is_half_open ? cfg_syn_timeout_ns(cfg) : cfg_tcp_timeout_ns(cfg);
            if (age > ct_timeout) {
                tcp_conntrack_delete(ipv4, &key_v4, &key_v6);
                tcp_src_conn_record_close(key, now, dest_port);
                count(CNT_TCP_CT_MISS);
                count(CNT_TCP_DROP);
                emit_drop(IPPROTO_TCP, key->family, key->saddr, key->daddr,
                          key->sport, key->dport, (__u8)CNT_TCP_CT_MISS, now);
                return XDP_DROP;
            }

            if (tcp_flags & TCP_FLAG_FIN) {
                tcp_conntrack_delete(ipv4, &key_v4, &key_v6);
                tcp_src_conn_record_close(key, now, dest_port);
                count(CNT_TCP_ESTABLISHED);
                return XDP_PASS;
            }

            if (is_half_open || age > ct_refresh) {
                // Half-open: promote to established immediately on first ACK.
                // Established: refresh timestamp after ct_refresh interval.
                tcp_conntrack_update(ipv4, &key_v4, &key_v6, now, BPF_EXIST);
                tcp_src_conn_record_activity(key, now, dest_port);
            }

            count(CNT_TCP_ESTABLISHED);
            return XDP_PASS;
        }

        {
            __u32 *pending_port = tcp_pending_lookup(ipv4, &key_v4, &key_v6);
            if (pending_port)
                try_tcp_port_dispatch(ctx, key, l3_off, inner_off, *pending_port);
        }

        count(CNT_TCP_CT_MISS);
        count(CNT_TCP_DROP);
        emit_drop(IPPROTO_TCP, key->family, key->saddr, key->daddr,
                  key->sport, key->dport, (__u8)CNT_TCP_CT_MISS, now);
        return XDP_DROP;
    }

    if (tcp_flags & TCP_FLAG_FIN) {
        struct ct_key_v4 key_v4;
        struct ct_key_v6 key_v6;
        if (ipv4)
            fill_ct_key_v4_map(&key_v4, key);
        else
            fill_ct_key_v6_map(&key_v6, key);
        last_seen = tcp_conntrack_lookup(ipv4, &key_v4, &key_v6);
        if (last_seen) {
            tcp_conntrack_delete(ipv4, &key_v4, &key_v6);
            tcp_src_conn_record_close(key, now, dest_port);
            count(CNT_TCP_ESTABLISHED);
            return XDP_PASS;
        }
        goto drop;
    }

    if ((tcp_flags & TCP_FLAG_SYN) && !(tcp_flags & TCP_FLAG_ACK)) {
        __u32 *allow = bpf_map_lookup_elem(&tcp_whitelist, &dest_port);
        if (!allow || !*allow)
            goto drop;
        if (is_handler_blocked(key)) {
            count(CNT_HANDLER_BLOCK_DROP);
            count(CNT_TCP_DROP);
            emit_drop(IPPROTO_TCP, key->family, key->saddr, key->daddr,
                      key->sport, key->dport, (__u8)CNT_HANDLER_BLOCK_DROP, now);
            return XDP_DROP;
        }
        if (precheck_new_tcp_syn(key, dest_port, false, now) == XDP_DROP)
            return XDP_DROP;
        try_tcp_port_dispatch(ctx, key, l3_off, inner_off, dest_port);
        return allow_new_tcp_syn(key, dest_port, false, true, now);
    }

drop:
    count(CNT_TCP_DROP);
    emit_drop(IPPROTO_TCP, key->family, key->saddr, key->daddr,
              key->sport, key->dport, (__u8)CNT_TCP_DROP, now);
    return XDP_DROP;
}
