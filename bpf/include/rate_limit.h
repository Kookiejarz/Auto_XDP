#pragma once
#include "maps.h"

static __always_inline __u32 mask_source_word(__u32 word, __u32 prefix_bits)
{
    if (prefix_bits >= 32)
        return word;
    if (prefix_bits == 0)
        return 0;

    __u32 mask = 0xFFFFFFFFU << (32 - prefix_bits);
    return word & bpf_htonl(mask);
}

static __always_inline void fill_masked_source_words(
    __u32 out[4], const __u32 in[4], __u8 family, __u32 prefix_v4, __u32 prefix_v6)
{
    out[0] = 0;
    out[1] = 0;
    out[2] = 0;
    out[3] = 0;

    if (family == CT_FAMILY_IPV4) {
        if (prefix_v4 > 32)
            prefix_v4 = 32;
        out[0] = mask_source_word(in[0], prefix_v4);
        return;
    }

    if (prefix_v6 > 128)
        prefix_v6 = 128;

    if (prefix_v6 >= 32) {
        out[0] = in[0];
        prefix_v6 -= 32;
    } else {
        out[0] = mask_source_word(in[0], prefix_v6);
        return;
    }

    if (prefix_v6 >= 32) {
        out[1] = in[1];
        prefix_v6 -= 32;
    } else {
        out[1] = mask_source_word(in[1], prefix_v6);
        return;
    }

    if (prefix_v6 >= 32) {
        out[2] = in[2];
        prefix_v6 -= 32;
    } else {
        out[2] = mask_source_word(in[2], prefix_v6);
        return;
    }

    out[3] = mask_source_word(in[3], prefix_v6);
}

static __always_inline void fill_source_rate_key_v4(
    struct syn_rate_key_v4 *rkey, const struct flow_key *key, __u32 prefix_v4)
{
    if (prefix_v4 > 32)
        prefix_v4 = 32;
    rkey->addr = (__be32)mask_source_word(key->saddr[0], prefix_v4);
}

static __always_inline void fill_source_rate_key_v6(
    struct syn_rate_key_v6 *rkey, const struct flow_key *key, __u32 prefix_v6)
{
    fill_masked_source_words(rkey->addr, key->saddr, CT_FAMILY_IPV6, 0, prefix_v6);
}

static __always_inline void fill_prefix_rate_key_v4(
    struct prefix_rate_key_v4 *rkey, const struct flow_key *key,
    __u32 dest_port, __u32 prefix_v4)
{
    if (prefix_v4 > 32)
        prefix_v4 = 32;
    rkey->addr = (__be32)mask_source_word(key->saddr[0], prefix_v4);
    rkey->dest_port = dest_port;
}

static __always_inline void fill_prefix_rate_key_v6(
    struct prefix_rate_key_v6 *rkey, const struct flow_key *key,
    __u32 dest_port, __u32 prefix_v6)
{
    fill_masked_source_words(rkey->addr, key->saddr, CT_FAMILY_IPV6, 0, prefix_v6);
    rkey->dest_port = dest_port;
}

static __always_inline void fill_tcp_src_conn_key_v4(
    struct tcp_src_conn_key_v4 *skey, const struct flow_key *key, __u32 dest_port)
{
    skey->addr = (__be32)key->saddr[0];
    skey->dest_port = dest_port;
}

static __always_inline void fill_tcp_src_conn_key_v6(
    struct tcp_src_conn_key_v6 *skey, const struct flow_key *key, __u32 dest_port)
{
    __builtin_memcpy(skey->addr, key->saddr, sizeof(skey->addr));
    skey->dest_port = dest_port;
}

static __always_inline void rl_fill_ct_key_v4_map(struct ct_key_v4 *out, const struct flow_key *key)
{
    out->sport = key->sport;
    out->dport = key->dport;
    out->saddr = (__be32)key->saddr[0];
    out->daddr = (__be32)key->daddr[0];
}

static __always_inline void rl_fill_ct_key_v6_map(struct ct_key_v6 *out, const struct flow_key *key)
{
    out->sport = key->sport;
    out->dport = key->dport;
    __builtin_memcpy(out->saddr, key->saddr, sizeof(out->saddr));
    __builtin_memcpy(out->daddr, key->daddr, sizeof(out->daddr));
}

static __always_inline __u64 *rl_tcp_conntrack_lookup(
    bool ipv4, const struct ct_key_v4 *key_v4, const struct ct_key_v6 *key_v6)
{
    if (ipv4)
        return bpf_map_lookup_elem(&tcp_ct4, key_v4);
    return bpf_map_lookup_elem(&tcp_ct6, key_v6);
}

static __always_inline void rl_tcp_conntrack_delete(
    bool ipv4, const struct ct_key_v4 *key_v4, const struct ct_key_v6 *key_v6)
{
    if (ipv4)
        bpf_map_delete_elem(&tcp_ct4, key_v4);
    else
        bpf_map_delete_elem(&tcp_ct6, key_v6);
}

static __always_inline void rl_tcp_conntrack_update(
    bool ipv4, const struct ct_key_v4 *key_v4, const struct ct_key_v6 *key_v6,
    __u64 now, __u64 flags)
{
    if (ipv4)
        bpf_map_update_elem(&tcp_ct4, key_v4, &now, flags);
    else
        bpf_map_update_elem(&tcp_ct6, key_v6, &now, flags);
}

static __always_inline int syn_rate_check(struct flow_key *key, __u64 now,
                                          __u32 rate_max,
                                          __u32 prefix_v4, __u32 prefix_v6)
{
    if (rate_max == 0)
        return XDP_PASS;

    if (key->family == CT_FAMILY_IPV4) {
        struct syn_rate_key_v4 rkey;
        struct syn_rate_val *rv;

        fill_source_rate_key_v4(&rkey, key, prefix_v4);
        rv = bpf_map_lookup_elem(&syn4, &rkey);
        if (!rv) {
            struct syn_rate_val new_rv;
            __builtin_memset(&new_rv, 0, sizeof(new_rv));
            new_rv.window_start_ns = now;
            new_rv.count = 1;
            bpf_map_update_elem(&syn4, &rkey, &new_rv, BPF_ANY);
            return XDP_PASS;
        }

        if (now - rv->window_start_ns >= runtime_rate_window_ns()) {
            rv->window_start_ns = now;
            rv->count = 1;
            return XDP_PASS;
        }

        if (rv->count >= rate_max)
            return XDP_DROP;

        rv->count++;
        return XDP_PASS;
    }

    {
        struct syn_rate_key_v6 rkey;
        struct syn_rate_val *rv;

        fill_source_rate_key_v6(&rkey, key, prefix_v6);
        rv = bpf_map_lookup_elem(&syn6, &rkey);
        if (!rv) {
            struct syn_rate_val new_rv;
            __builtin_memset(&new_rv, 0, sizeof(new_rv));
            new_rv.window_start_ns = now;
            new_rv.count = 1;
            bpf_map_update_elem(&syn6, &rkey, &new_rv, BPF_ANY);
            return XDP_PASS;
        }

        if (now - rv->window_start_ns >= runtime_rate_window_ns()) {
            rv->window_start_ns = now;
            rv->count = 1;
            return XDP_PASS;
        }

        if (rv->count >= rate_max)
            return XDP_DROP;

        rv->count++;
        return XDP_PASS;
    }
}

static __always_inline int syn_agg_rate_check(struct flow_key *key, __u64 now,
                                              __u32 dest_port, __u32 rate_max,
                                              __u32 prefix_v4, __u32 prefix_v6)
{
    if (rate_max == 0)
        return XDP_PASS;

    if (key->family == CT_FAMILY_IPV4) {
        struct prefix_rate_key_v4 rkey;
        struct prefix_rate_val *rv;

        fill_prefix_rate_key_v4(&rkey, key, dest_port, prefix_v4);
        rv = bpf_map_lookup_elem(&synag4, &rkey);
        if (!rv) {
            struct prefix_rate_val new_rv;
            __builtin_memset(&new_rv, 0, sizeof(new_rv));
            new_rv.window_start_ns = now;
            new_rv.units = 1;
            bpf_map_update_elem(&synag4, &rkey, &new_rv, BPF_ANY);
            return XDP_PASS;
        }

        if (now - rv->window_start_ns >= runtime_rate_window_ns()) {
            rv->window_start_ns = now;
            rv->units = 1;
            return XDP_PASS;
        }

        if (rv->units >= rate_max)
            return XDP_DROP;

        rv->units++;
        return XDP_PASS;
    }

    {
        struct prefix_rate_key_v6 rkey;
        struct prefix_rate_val *rv;

        fill_prefix_rate_key_v6(&rkey, key, dest_port, prefix_v6);
        rv = bpf_map_lookup_elem(&synag6, &rkey);
        if (!rv) {
            struct prefix_rate_val new_rv;
            __builtin_memset(&new_rv, 0, sizeof(new_rv));
            new_rv.window_start_ns = now;
            new_rv.units = 1;
            bpf_map_update_elem(&synag6, &rkey, &new_rv, BPF_ANY);
            return XDP_PASS;
        }

        if (now - rv->window_start_ns >= runtime_rate_window_ns()) {
            rv->window_start_ns = now;
            rv->units = 1;
            return XDP_PASS;
        }

        if (rv->units >= rate_max)
            return XDP_DROP;

        rv->units++;
        return XDP_PASS;
    }
}

static __always_inline int udp_rate_check(struct flow_key *key, __u64 now,
                                          __u32 rate_max,
                                          __u32 prefix_v4, __u32 prefix_v6)
{
    if (rate_max == 0)
        return XDP_PASS;

    if (key->family == CT_FAMILY_IPV4) {
        struct syn_rate_key_v4 rkey;
        struct syn_rate_val *rv;

        fill_source_rate_key_v4(&rkey, key, prefix_v4);
        rv = bpf_map_lookup_elem(&udprt4, &rkey);
        if (!rv) {
            struct syn_rate_val new_rv;
            __builtin_memset(&new_rv, 0, sizeof(new_rv));
            new_rv.window_start_ns = now;
            new_rv.count = 1;
            bpf_map_update_elem(&udprt4, &rkey, &new_rv, BPF_ANY);
            return XDP_PASS;
        }

        if (now - rv->window_start_ns >= runtime_rate_window_ns()) {
            rv->window_start_ns = now;
            rv->count = 1;
            return XDP_PASS;
        }

        if (rv->count >= rate_max)
            return XDP_DROP;

        rv->count++;
        return XDP_PASS;
    }

    {
        struct syn_rate_key_v6 rkey;
        struct syn_rate_val *rv;

        fill_source_rate_key_v6(&rkey, key, prefix_v6);
        rv = bpf_map_lookup_elem(&udprt6, &rkey);
        if (!rv) {
            struct syn_rate_val new_rv;
            __builtin_memset(&new_rv, 0, sizeof(new_rv));
            new_rv.window_start_ns = now;
            new_rv.count = 1;
            bpf_map_update_elem(&udprt6, &rkey, &new_rv, BPF_ANY);
            return XDP_PASS;
        }

        if (now - rv->window_start_ns >= runtime_rate_window_ns()) {
            rv->window_start_ns = now;
            rv->count = 1;
            return XDP_PASS;
        }

        if (rv->count >= rate_max)
            return XDP_DROP;

        rv->count++;
        return XDP_PASS;
    }
}

static __always_inline int udp_agg_rate_check(struct flow_key *key, __u64 now,
                                              __u32 dest_port, __u64 pkt_bytes,
                                              __u32 rate_max,
                                              __u32 prefix_v4, __u32 prefix_v6)
{
    if (rate_max == 0)
        return XDP_PASS;

    if (key->family == CT_FAMILY_IPV4) {
        struct prefix_rate_key_v4 rkey;
        struct prefix_rate_val *rv;

        fill_prefix_rate_key_v4(&rkey, key, dest_port, prefix_v4);
        rv = bpf_map_lookup_elem(&udpag4, &rkey);
        if (!rv) {
            struct prefix_rate_val new_rv;
            __builtin_memset(&new_rv, 0, sizeof(new_rv));
            new_rv.window_start_ns = now;
            new_rv.units = pkt_bytes;
            bpf_map_update_elem(&udpag4, &rkey, &new_rv, BPF_ANY);
            return XDP_PASS;
        }

        if (now - rv->window_start_ns >= runtime_rate_window_ns()) {
            rv->window_start_ns = now;
            rv->units = pkt_bytes;
            return XDP_PASS;
        }

        if (rv->units + pkt_bytes > (__u64)rate_max)
            return XDP_DROP;

        rv->units += pkt_bytes;
        return XDP_PASS;
    }

    {
        struct prefix_rate_key_v6 rkey;
        struct prefix_rate_val *rv;

        fill_prefix_rate_key_v6(&rkey, key, dest_port, prefix_v6);
        rv = bpf_map_lookup_elem(&udpag6, &rkey);
        if (!rv) {
            struct prefix_rate_val new_rv;
            __builtin_memset(&new_rv, 0, sizeof(new_rv));
            new_rv.window_start_ns = now;
            new_rv.units = pkt_bytes;
            bpf_map_update_elem(&udpag6, &rkey, &new_rv, BPF_ANY);
            return XDP_PASS;
        }

        if (now - rv->window_start_ns >= runtime_rate_window_ns()) {
            rv->window_start_ns = now;
            rv->units = pkt_bytes;
            return XDP_PASS;
        }

        if (rv->units + pkt_bytes > (__u64)rate_max)
            return XDP_DROP;

        rv->units += pkt_bytes;
        return XDP_PASS;
    }
}

static __always_inline int tcp_conn_limit_check(struct flow_key *key, __u64 now,
                                                __u32 dest_port, __u32 conn_max)
{
    if (conn_max == 0)
        return XDP_PASS;

    if (key->family == CT_FAMILY_IPV4) {
        struct tcp_src_conn_key_v4 skey;
        struct tcp_src_conn_val *sv;

        fill_tcp_src_conn_key_v4(&skey, key, dest_port);
        sv = bpf_map_lookup_elem(&tsc4, &skey);
        if (!sv)
            return XDP_PASS;

        if (now - sv->last_seen_ns > runtime_tcp_timeout_ns()) {
            sv->count = 0;
            sv->last_seen_ns = now;
            return XDP_PASS;
        }

        if (sv->count >= conn_max)
            return XDP_DROP;

        return XDP_PASS;
    }

    {
        struct tcp_src_conn_key_v6 skey;
        struct tcp_src_conn_val *sv;

        fill_tcp_src_conn_key_v6(&skey, key, dest_port);
        sv = bpf_map_lookup_elem(&tsc6, &skey);
        if (!sv)
            return XDP_PASS;

        if (now - sv->last_seen_ns > runtime_tcp_timeout_ns()) {
            sv->count = 0;
            sv->last_seen_ns = now;
            return XDP_PASS;
        }

        if (sv->count >= conn_max)
            return XDP_DROP;

        return XDP_PASS;
    }
}

static __always_inline void tcp_src_conn_record_new(struct flow_key *key, __u64 now,
                                                    __u32 dest_port)
{
    if (key->family == CT_FAMILY_IPV4) {
        struct tcp_src_conn_key_v4 skey;
        struct tcp_src_conn_val *sv;

        fill_tcp_src_conn_key_v4(&skey, key, dest_port);
        sv = bpf_map_lookup_elem(&tsc4, &skey);
        if (!sv) {
            struct tcp_src_conn_val new_sv;
            __builtin_memset(&new_sv, 0, sizeof(new_sv));
            new_sv.last_seen_ns = now;
            new_sv.count = 1;
            bpf_map_update_elem(&tsc4, &skey, &new_sv, BPF_ANY);
            return;
        }

        if (now - sv->last_seen_ns > runtime_tcp_timeout_ns())
            sv->count = 0;
        if (sv->count < 0xFFFFFFFF)
            sv->count++;
        sv->last_seen_ns = now;
        return;
    }

    {
        struct tcp_src_conn_key_v6 skey;
        struct tcp_src_conn_val *sv;

        fill_tcp_src_conn_key_v6(&skey, key, dest_port);
        sv = bpf_map_lookup_elem(&tsc6, &skey);
        if (!sv) {
            struct tcp_src_conn_val new_sv;
            __builtin_memset(&new_sv, 0, sizeof(new_sv));
            new_sv.last_seen_ns = now;
            new_sv.count = 1;
            bpf_map_update_elem(&tsc6, &skey, &new_sv, BPF_ANY);
            return;
        }

        if (now - sv->last_seen_ns > runtime_tcp_timeout_ns())
            sv->count = 0;
        if (sv->count < 0xFFFFFFFF)
            sv->count++;
        sv->last_seen_ns = now;
    }
}

static __always_inline void tcp_src_conn_record_activity(struct flow_key *key, __u64 now,
                                                         __u32 dest_port)
{
    if (key->family == CT_FAMILY_IPV4) {
        struct tcp_src_conn_key_v4 skey;
        struct tcp_src_conn_val *sv;

        fill_tcp_src_conn_key_v4(&skey, key, dest_port);
        sv = bpf_map_lookup_elem(&tsc4, &skey);
        if (!sv)
            return;
        if (sv->count == 0)
            sv->count = 1;
        sv->last_seen_ns = now;
        return;
    }

    {
        struct tcp_src_conn_key_v6 skey;
        struct tcp_src_conn_val *sv;

        fill_tcp_src_conn_key_v6(&skey, key, dest_port);
        sv = bpf_map_lookup_elem(&tsc6, &skey);
        if (!sv)
            return;
        if (sv->count == 0)
            sv->count = 1;
        sv->last_seen_ns = now;
    }
}

static __always_inline void tcp_src_conn_record_close(struct flow_key *key, __u64 now,
                                                      __u32 dest_port)
{
    if (key->family == CT_FAMILY_IPV4) {
        struct tcp_src_conn_key_v4 skey;
        struct tcp_src_conn_val *sv;

        fill_tcp_src_conn_key_v4(&skey, key, dest_port);
        sv = bpf_map_lookup_elem(&tsc4, &skey);
        if (!sv)
            return;
        if (sv->count <= 1) {
            bpf_map_delete_elem(&tsc4, &skey);
            return;
        }
        sv->count--;
        sv->last_seen_ns = now;
        return;
    }

    {
        struct tcp_src_conn_key_v6 skey;
        struct tcp_src_conn_val *sv;

        fill_tcp_src_conn_key_v6(&skey, key, dest_port);
        sv = bpf_map_lookup_elem(&tsc6, &skey);
        if (!sv)
            return;
        if (sv->count <= 1) {
            bpf_map_delete_elem(&tsc6, &skey);
            return;
        }
        sv->count--;
        sv->last_seen_ns = now;
    }
}

static __always_inline int precheck_new_tcp_syn(struct flow_key *key, __u32 dest_port,
                                                bool bypass_rate, __u64 now)
{
    struct tcp_port_policy_cfg *policy = bpf_map_lookup_elem(&tcp_port_policies, &dest_port);
    __u32 syn_rate_max = policy ? policy->syn_rate_max : 0;
    __u32 syn_agg_rate_max = policy ? policy->syn_agg_rate_max : 0;
    __u32 conn_limit_max = policy ? policy->conn_limit_max : 0;
    __u32 source_prefix_v4 = policy ? policy->source_prefix_v4 : 32;
    __u32 source_prefix_v6 = policy ? policy->source_prefix_v6 : 128;

    if (!bypass_rate) {
        if (syn_rate_check(key, now, syn_rate_max, source_prefix_v4, source_prefix_v6) == XDP_DROP) {
            count(CNT_SYN_RATE_DROP);
            count(CNT_TCP_DROP);
            emit_drop(IPPROTO_TCP, key->family, key->saddr, key->daddr,
                      key->sport, key->dport, (__u8)CNT_SYN_RATE_DROP);
            return XDP_DROP;
        }

        if (syn_agg_rate_check(key, now, dest_port, syn_agg_rate_max, source_prefix_v4, source_prefix_v6) == XDP_DROP) {
            count(CNT_SYN_AGG_RATE_DROP);
            count(CNT_TCP_DROP);
            emit_drop(IPPROTO_TCP, key->family, key->saddr, key->daddr,
                      key->sport, key->dport, (__u8)CNT_SYN_AGG_RATE_DROP);
            return XDP_DROP;
        }
    }

    if (tcp_conn_limit_check(key, now, dest_port, conn_limit_max) == XDP_DROP) {
        count(CNT_TCP_CONN_LIMIT_DROP);
        count(CNT_TCP_DROP);
        emit_drop(IPPROTO_TCP, key->family, key->saddr, key->daddr,
                  key->sport, key->dport, (__u8)CNT_TCP_CONN_LIMIT_DROP);
        return XDP_DROP;
    }

    return XDP_PASS;
}

static __always_inline int allow_new_tcp_syn(struct flow_key *key, __u32 dest_port,
                                             bool bypass_rate, bool prechecked)
{
    __u64 now = bpf_ktime_get_ns();
    __u64 *last_seen;
    bool ipv4 = key->family == CT_FAMILY_IPV4;
    struct ct_key_v4 key_v4;
    struct ct_key_v6 key_v6;

    if (ipv4)
        rl_fill_ct_key_v4_map(&key_v4, key);
    else
        rl_fill_ct_key_v6_map(&key_v6, key);

    last_seen = rl_tcp_conntrack_lookup(ipv4, &key_v4, &key_v6);
    if (last_seen) {
        __u64 age = now - *last_seen;
        if (age > runtime_tcp_timeout_ns()) {
            rl_tcp_conntrack_delete(ipv4, &key_v4, &key_v6);
            tcp_src_conn_record_close(key, now, dest_port);
        } else {
            if (age > runtime_ct_refresh_ns()) {
                rl_tcp_conntrack_update(ipv4, &key_v4, &key_v6, now, BPF_EXIST);
                tcp_src_conn_record_activity(key, now, dest_port);
            }
            count(CNT_TCP_NEW_ALLOW);
            return XDP_PASS;
        }
    }

    if (!prechecked && precheck_new_tcp_syn(key, dest_port, bypass_rate, now) == XDP_DROP)
        return XDP_DROP;

    rl_tcp_conntrack_update(ipv4, &key_v4, &key_v6, now, BPF_ANY);
    tcp_src_conn_record_new(key, now, dest_port);
    count(CNT_TCP_NEW_ALLOW);
    return XDP_PASS;
}

// Two-level global UDP rate limiter.
//
// Problem with the naive PERCPU_ARRAY approach: each CPU independently enforces
// byte_rate_max, so the effective global limit is byte_rate_max × N_CPUs.
//
// This design separates accumulation (per-CPU, lock-free) from enforcement
// (single shared state, spinlock-protected):
//
//   Fast path (per packet, no lock):
//     Accumulate pkt_bytes in the current CPU's local counter.
//     Return XDP_PASS immediately if the batch threshold is not yet reached.
//
//   Slow path (every UDP_GLOBAL_BATCH_BYTES per CPU, one spinlock acquisition):
//     Flush the local batch to the shared two-bucket sliding window.
//     Return XDP_DROP if the global byte rate is exceeded.
//
// Overshoot at any instant is bounded by N_CPUs × UDP_GLOBAL_BATCH_BYTES.
// For 32 CPUs and a 64 KiB batch that is 2 MiB — acceptable for a DDoS limiter.
// Lock contention is proportional to (global_rate / BATCH) × N_CPUs, not per packet.
//
// Avoids integer division using scaled comparisons:
//   prev*(W-elapsed) + curr*W  vs  byte_rate_max*W

#define UDP_GLOBAL_BATCH_BYTES (65536ULL)

static __always_inline int udp_global_rate_check(__u64 now, __u64 pkt_bytes)
{
    __u32 key = 0;

    struct udp_percpu_local *local = bpf_map_lookup_elem(&udp_percpu_acc, &key);
    if (!local)
        return XDP_PASS;

    local->local_bytes += pkt_bytes;
    if (local->local_bytes < UDP_GLOBAL_BATCH_BYTES)
        return XDP_PASS;

    __u64 to_flush = local->local_bytes;
    local->local_bytes = 0;

    struct udp_global_state *g = bpf_map_lookup_elem(&udp_global_rl, &key);
    if (!g || g->byte_rate_max == 0)
        return XDP_PASS;

    __u64 window_ns = runtime_udp_global_window_ns();
    int ret = XDP_PASS;

    bpf_spin_lock(&g->lock);

    if (g->window_start_ns == 0) {
        g->window_start_ns = now;
        g->prev_bytes = 0;
        g->curr_bytes = to_flush;
    } else {
        __u64 elapsed = now - g->window_start_ns;

        if (elapsed >= 2 * window_ns) {
            g->window_start_ns = now;
            g->prev_bytes = 0;
            g->curr_bytes = to_flush;
        } else {
            if (elapsed >= window_ns) {
                g->prev_bytes = g->curr_bytes;
                g->curr_bytes = 0;
                g->window_start_ns += window_ns;
                elapsed -= window_ns;
            }
            __u64 weighted = g->prev_bytes * (window_ns - elapsed)
                           + g->curr_bytes * window_ns;
            __u64 threshold = (__u64)g->byte_rate_max * window_ns;
            if (weighted + to_flush * window_ns > threshold) {
                ret = XDP_DROP;
            } else {
                g->curr_bytes += to_flush;
            }
        }
    }

    bpf_spin_unlock(&g->lock);
    return ret;
}
