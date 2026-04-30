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

static __always_inline void fill_ct_key_v4_map(struct ct_key_v4 *out, const struct flow_key *key)
{
    out->sport = key->sport;
    out->dport = key->dport;
    out->saddr = (__be32)key->saddr[0];
    out->daddr = (__be32)key->daddr[0];
}

static __always_inline void fill_ct_key_v6_map(struct ct_key_v6 *out, const struct flow_key *key)
{
    out->sport = key->sport;
    out->dport = key->dport;
    __builtin_memcpy(out->saddr, key->saddr, sizeof(out->saddr));
    __builtin_memcpy(out->daddr, key->daddr, sizeof(out->daddr));
}

static __always_inline __u64 *tcp_conntrack_lookup(
    bool ipv4, const struct ct_key_v4 *key_v4, const struct ct_key_v6 *key_v6)
{
    if (ipv4)
        return bpf_map_lookup_elem(&tcp_ct4, key_v4);
    return bpf_map_lookup_elem(&tcp_ct6, key_v6);
}

static __always_inline void tcp_conntrack_delete(
    bool ipv4, const struct ct_key_v4 *key_v4, const struct ct_key_v6 *key_v6)
{
    if (ipv4)
        bpf_map_delete_elem(&tcp_ct4, key_v4);
    else
        bpf_map_delete_elem(&tcp_ct6, key_v6);
}

static __always_inline void tcp_conntrack_update(
    bool ipv4, const struct ct_key_v4 *key_v4, const struct ct_key_v6 *key_v6,
    __u64 now, __u64 flags)
{
    if (ipv4)
        bpf_map_update_elem(&tcp_ct4, key_v4, &now, flags);
    else
        bpf_map_update_elem(&tcp_ct6, key_v6, &now, flags);
}

static __always_inline __u32 *tcp_pending_lookup(
    bool ipv4, const struct ct_key_v4 *key_v4, const struct ct_key_v6 *key_v6)
{
    if (ipv4)
        return bpf_map_lookup_elem(&tcp_pd4, key_v4);
    return bpf_map_lookup_elem(&tcp_pd6, key_v6);
}

static __always_inline int check_tcp_conntrack(
    struct xdp_md *ctx,
    struct flow_key *key, __u8 tcp_flags, __u32 dest_port,
    __u16 l3_off, __u16 inner_off)
{
    __u64 now = bpf_ktime_get_ns();
    __u64 *last_seen;
    bool ipv4 = key->family == CT_FAMILY_IPV4;
    struct ct_key_v4 key_v4;
    struct ct_key_v6 key_v6;

    if (ipv4)
        fill_ct_key_v4_map(&key_v4, key);
    else
        fill_ct_key_v6_map(&key_v6, key);

    if (tcp_flags & 0x04) {
        if (!(tcp_flags & 0x10))
            goto drop;

        last_seen = tcp_conntrack_lookup(ipv4, &key_v4, &key_v6);
        if (!last_seen) {
            count(CNT_TCP_CT_MISS);
            count(CNT_TCP_DROP);
            emit_drop(IPPROTO_TCP, key->family, key->saddr, key->daddr,
                      key->sport, key->dport, (__u8)CNT_TCP_CT_MISS);
            return XDP_DROP;
        }
        {
            __u64 raw = *last_seen;
            __u64 ts = raw & ~CT_SYN_PENDING;
            __u64 ct_to = (raw & CT_SYN_PENDING) ? runtime_syn_timeout_ns() : runtime_tcp_timeout_ns();
            if (now - ts > ct_to) {
                tcp_conntrack_delete(ipv4, &key_v4, &key_v6);
                tcp_src_conn_record_close(key, now, dest_port);
                count(CNT_TCP_CT_MISS);
                count(CNT_TCP_DROP);
                emit_drop(IPPROTO_TCP, key->family, key->saddr, key->daddr,
                          key->sport, key->dport, (__u8)CNT_TCP_CT_MISS);
                return XDP_DROP;
            }
        }
        tcp_conntrack_delete(ipv4, &key_v4, &key_v6);
        tcp_src_conn_record_close(key, now, dest_port);
        count(CNT_TCP_ESTABLISHED);
        return XDP_PASS;
    }

    if (tcp_flags & 0x10) {
        __u64 ct_refresh = runtime_ct_refresh_ns();

        last_seen = tcp_conntrack_lookup(ipv4, &key_v4, &key_v6);
        if (last_seen) {
            __u64 raw = *last_seen;
            bool is_half_open = raw & CT_SYN_PENDING;
            __u64 ts = raw & ~CT_SYN_PENDING;
            __u64 age = now - ts;
            __u64 ct_timeout = is_half_open ? runtime_syn_timeout_ns() : runtime_tcp_timeout_ns();
            if (age > ct_timeout) {
                tcp_conntrack_delete(ipv4, &key_v4, &key_v6);
                tcp_src_conn_record_close(key, now, dest_port);
                count(CNT_TCP_CT_MISS);
                count(CNT_TCP_DROP);
                emit_drop(IPPROTO_TCP, key->family, key->saddr, key->daddr,
                          key->sport, key->dport, (__u8)CNT_TCP_CT_MISS);
                return XDP_DROP;
            }

            if (tcp_flags & 0x01) {
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
                  key->sport, key->dport, (__u8)CNT_TCP_CT_MISS);
        return XDP_DROP;
    }

    if (tcp_flags & 0x01) {
        last_seen = tcp_conntrack_lookup(ipv4, &key_v4, &key_v6);
        if (last_seen) {
            tcp_conntrack_delete(ipv4, &key_v4, &key_v6);
            tcp_src_conn_record_close(key, now, dest_port);
            count(CNT_TCP_ESTABLISHED);
            return XDP_PASS;
        }
        goto drop;
    }

    if ((tcp_flags & 0x02) && !(tcp_flags & 0x10)) {
        __u32 *allow = bpf_map_lookup_elem(&tcp_whitelist, &dest_port);
        if (!allow || !*allow)
            goto drop;
        if (is_handler_blocked(key)) {
            count(CNT_HANDLER_BLOCK_DROP);
            count(CNT_TCP_DROP);
            emit_drop(IPPROTO_TCP, key->family, key->saddr, key->daddr,
                      key->sport, key->dport, (__u8)CNT_HANDLER_BLOCK_DROP);
            return XDP_DROP;
        }
        if (precheck_new_tcp_syn(key, dest_port, false, now) == XDP_DROP)
            return XDP_DROP;
        try_tcp_port_dispatch(ctx, key, l3_off, inner_off, dest_port);
        return allow_new_tcp_syn(key, dest_port, false, true);
    }

drop:
    count(CNT_TCP_DROP);
    emit_drop(IPPROTO_TCP, key->family, key->saddr, key->daddr,
              key->sport, key->dport, (__u8)CNT_TCP_DROP);
    return XDP_DROP;
}
