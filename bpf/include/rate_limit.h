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


/* Sliding-window limiter: reset on expiry, drop if unit_field + increment > max.
 * `map` is a map pointer expression (e.g. &synag4 or an inner map from
 * a per-port ARRAY_OF_MAPS lookup).
 *
 * These value structs live in shared (non-percpu) LRU_HASH maps and are hit
 * from every RX CPU concurrently. The whole "check window expiry -> maybe
 * reset -> compare against max -> increment" sequence has to execute as one
 * atomic unit, or two CPUs landing in the same window both read the old
 * unit_field, both pass the max check, and both write back their own
 * increment - the last writer's value wins and the other CPU's increment is
 * silently lost (undercounting the rate under load). A single atomic add on
 * unit_field is not sufficient by itself because the reset-on-expiry branch
 * still needs to be race-free against the increment branch. bpf_spin_lock
 * protects the full sequence, matching the pattern already used by
 * struct udp_global_state's lock. */
#define WINDOW_RATE_CHECK(map, rkey, val_type, unit_field, now, window_ns, increment, max) \
    do {                                                                                    \
        val_type *_rv = bpf_map_lookup_elem((map), &(rkey));                              \
        if (!_rv) {                                                                         \
            val_type _new;                                                                  \
            __builtin_memset(&_new, 0, sizeof(_new));                                      \
            _new.window_start_ns = (now);                                                   \
            _new.unit_field = (increment);                                                  \
            bpf_map_update_elem((map), &(rkey), &_new, BPF_ANY);                          \
            return XDP_PASS;                                                                \
        }                                                                                   \
        int _verdict;                                                                       \
        bpf_spin_lock(&_rv->lock);                                                          \
        if ((now) - _rv->window_start_ns >= (window_ns)) {                                 \
            _rv->window_start_ns = (now);                                                   \
            _rv->unit_field = (increment);                                                  \
            _verdict = XDP_PASS;                                                            \
        } else if ((__u64)_rv->unit_field + (__u64)(increment) > (__u64)(max)) {           \
            _verdict = XDP_DROP;                                                            \
        } else {                                                                            \
            _rv->unit_field += (increment);                                                 \
            _verdict = XDP_PASS;                                                            \
        }                                                                                    \
        bpf_spin_unlock(&_rv->lock);                                                        \
        return _verdict;                                                                    \
    } while (0)

static __always_inline int syn_rate_check(struct flow_key *key, __u64 now,
                                          __u32 dest_port, __u32 rate_max,
                                          __u32 prefix_v4, __u32 prefix_v6,
                                          struct xdp_runtime_cfg *cfg)
{
    if (rate_max == 0)
        return XDP_PASS;

    __u64 window_ns = cfg_rate_window_ns(cfg);

    if (key->family == CT_FAMILY_IPV4) {
        void *inner = bpf_map_lookup_elem(&syn4, &dest_port);
        if (!inner)
            return XDP_PASS; /* no per-port map yet: pass, syncer will create it */
        struct syn_rate_key_v4 rkey;
        fill_source_rate_key_v4(&rkey, key, prefix_v4);
        WINDOW_RATE_CHECK(inner, rkey, struct syn_rate_val, count, now, window_ns, 1U, rate_max);
    }

    {
        void *inner = bpf_map_lookup_elem(&syn6, &dest_port);
        if (!inner)
            return XDP_PASS;
        struct syn_rate_key_v6 rkey;
        fill_source_rate_key_v6(&rkey, key, prefix_v6);
        WINDOW_RATE_CHECK(inner, rkey, struct syn_rate_val, count, now, window_ns, 1U, rate_max);
    }
}

static __always_inline int syn_agg_rate_check(struct flow_key *key, __u64 now,
                                              __u32 dest_port, __u32 rate_max,
                                              __u32 prefix_v4, __u32 prefix_v6,
                                              struct xdp_runtime_cfg *cfg)
{
    if (rate_max == 0)
        return XDP_PASS;

    __u64 window_ns = cfg_rate_window_ns(cfg);

    if (key->family == CT_FAMILY_IPV4) {
        struct prefix_rate_key_v4 rkey;
        fill_prefix_rate_key_v4(&rkey, key, dest_port, prefix_v4);
        WINDOW_RATE_CHECK(&synag4, rkey, struct prefix_rate_val, units, now, window_ns, 1ULL, rate_max);
    }

    struct prefix_rate_key_v6 rkey;
    fill_prefix_rate_key_v6(&rkey, key, dest_port, prefix_v6);
    WINDOW_RATE_CHECK(&synag6, rkey, struct prefix_rate_val, units, now, window_ns, 1ULL, rate_max);
}

static __always_inline int udp_rate_check(struct flow_key *key, __u64 now,
                                          __u32 dest_port, __u32 rate_max,
                                          __u32 prefix_v4, __u32 prefix_v6,
                                          struct xdp_runtime_cfg *cfg)
{
    if (rate_max == 0)
        return XDP_PASS;

    __u64 window_ns = cfg_rate_window_ns(cfg);

    if (key->family == CT_FAMILY_IPV4) {
        void *inner = bpf_map_lookup_elem(&udprt4, &dest_port);
        if (!inner)
            return XDP_PASS; /* no per-port map yet: pass, syncer will create it */
        struct syn_rate_key_v4 rkey;
        fill_source_rate_key_v4(&rkey, key, prefix_v4);
        WINDOW_RATE_CHECK(inner, rkey, struct syn_rate_val, count, now, window_ns, 1U, rate_max);
    }

    {
        void *inner = bpf_map_lookup_elem(&udprt6, &dest_port);
        if (!inner)
            return XDP_PASS;
        struct syn_rate_key_v6 rkey;
        fill_source_rate_key_v6(&rkey, key, prefix_v6);
        WINDOW_RATE_CHECK(inner, rkey, struct syn_rate_val, count, now, window_ns, 1U, rate_max);
    }
}

static __always_inline int udp_agg_rate_check(struct flow_key *key, __u64 now,
                                              __u32 dest_port, __u64 pkt_bytes,
                                              __u32 rate_max,
                                              __u32 prefix_v4, __u32 prefix_v6,
                                              struct xdp_runtime_cfg *cfg)
{
    if (rate_max == 0)
        return XDP_PASS;

    __u64 window_ns = cfg_rate_window_ns(cfg);

    if (key->family == CT_FAMILY_IPV4) {
        struct prefix_rate_key_v4 rkey;
        fill_prefix_rate_key_v4(&rkey, key, dest_port, prefix_v4);
        WINDOW_RATE_CHECK(&udpag4, rkey, struct prefix_rate_val, units, now, window_ns, pkt_bytes, (__u64)rate_max);
    }

    struct prefix_rate_key_v6 rkey;
    fill_prefix_rate_key_v6(&rkey, key, dest_port, prefix_v6);
    WINDOW_RATE_CHECK(&udpag6, rkey, struct prefix_rate_val, units, now, window_ns, pkt_bytes, (__u64)rate_max);
}

static __always_inline int tcp_conn_limit_check(struct flow_key *key, __u64 now,
                                                __u32 dest_port, __u32 conn_max,
                                                struct xdp_runtime_cfg *cfg)
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

        int verdict;
        bpf_spin_lock(&sv->lock);
        if (now - sv->last_seen_ns > cfg_tcp_timeout_ns(cfg)) {
            sv->count = 0;
            sv->last_seen_ns = now;
            verdict = XDP_PASS;
        } else {
            verdict = (sv->count >= conn_max) ? XDP_DROP : XDP_PASS;
        }
        bpf_spin_unlock(&sv->lock);
        return verdict;
    }

    {
        struct tcp_src_conn_key_v6 skey;
        struct tcp_src_conn_val *sv;

        fill_tcp_src_conn_key_v6(&skey, key, dest_port);
        sv = bpf_map_lookup_elem(&tsc6, &skey);
        if (!sv)
            return XDP_PASS;

        int verdict;
        bpf_spin_lock(&sv->lock);
        if (now - sv->last_seen_ns > cfg_tcp_timeout_ns(cfg)) {
            sv->count = 0;
            sv->last_seen_ns = now;
            verdict = XDP_PASS;
        } else {
            verdict = (sv->count >= conn_max) ? XDP_DROP : XDP_PASS;
        }
        bpf_spin_unlock(&sv->lock);
        return verdict;
    }
}

static __always_inline void tcp_src_conn_record_established(
    struct flow_key *key, __u64 now, __u32 dest_port,
    struct xdp_runtime_cfg *cfg)
{
    __u64 tcp_timeout_ns = cfg_tcp_timeout_ns(cfg);

    /* L3 — per-source counter (tsc4/tsc6). */
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
        } else {
            bpf_spin_lock(&sv->lock);
            if (now - sv->last_seen_ns > tcp_timeout_ns)
                sv->count = 0;
            if (sv->count < 0xFFFFFFFF)
                sv->count++;
            sv->last_seen_ns = now;
            bpf_spin_unlock(&sv->lock);
        }
    } else {
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
        } else {
            bpf_spin_lock(&sv->lock);
            if (now - sv->last_seen_ns > tcp_timeout_ns)
                sv->count = 0;
            if (sv->count < 0xFFFFFFFF)
                sv->count++;
            sv->last_seen_ns = now;
            bpf_spin_unlock(&sv->lock);
        }
    }

    /* L4 — per-prefix counter (tsc_pfx4/tsc_pfx6). */
    {
        struct tcp_port_policy_cfg *policy =
            bpf_map_lookup_elem(&tcp_port_policies, &dest_port);
        __u32 prefix_v4 = policy ? policy->source_prefix_v4 : 32;
        __u32 prefix_v6 = policy ? policy->source_prefix_v6 : 128;

        if (key->family == CT_FAMILY_IPV4) {
            struct prefix_rate_key_v4 pkey;
            struct tcp_pfx_conn_val *pv;
            fill_prefix_rate_key_v4(&pkey, key, dest_port, prefix_v4);
            pv = bpf_map_lookup_elem(&tsc_pfx4, &pkey);
            if (!pv) {
                struct tcp_pfx_conn_val new_pv;
                __builtin_memset(&new_pv, 0, sizeof(new_pv));
                new_pv.last_seen_ns = now;
                new_pv.count = 1;
                bpf_map_update_elem(&tsc_pfx4, &pkey, &new_pv, BPF_ANY);
            } else {
                bpf_spin_lock(&pv->lock);
                if (now - pv->last_seen_ns > tcp_timeout_ns)
                    pv->count = 0;
                if (pv->count < 0xFFFFFFFF)
                    pv->count++;
                pv->last_seen_ns = now;
                bpf_spin_unlock(&pv->lock);
            }
        } else {
            struct prefix_rate_key_v6 pkey;
            struct tcp_pfx_conn_val *pv;
            fill_prefix_rate_key_v6(&pkey, key, dest_port, prefix_v6);
            pv = bpf_map_lookup_elem(&tsc_pfx6, &pkey);
            if (!pv) {
                struct tcp_pfx_conn_val new_pv;
                __builtin_memset(&new_pv, 0, sizeof(new_pv));
                new_pv.last_seen_ns = now;
                new_pv.count = 1;
                bpf_map_update_elem(&tsc_pfx6, &pkey, &new_pv, BPF_ANY);
            } else {
                bpf_spin_lock(&pv->lock);
                if (now - pv->last_seen_ns > tcp_timeout_ns)
                    pv->count = 0;
                if (pv->count < 0xFFFFFFFF)
                    pv->count++;
                pv->last_seen_ns = now;
                bpf_spin_unlock(&pv->lock);
            }
        }
    }

    /* L5 — per-port total counter (tsc_port ARRAY). Shared across every RX
     * CPU (ARRAY maps have no per-cpu variant selected here), so this needs
     * the same lock as the LRU-backed counters above. */
    {
        struct tcp_port_conn_val *pv =
            bpf_map_lookup_elem(&tsc_port, &dest_port);
        if (pv) {
            bpf_spin_lock(&pv->lock);
            if (now - pv->last_seen_ns > tcp_timeout_ns)
                pv->count = 0;
            if (pv->count < 0xFFFFFFFF)
                pv->count++;
            pv->last_seen_ns = now;
            bpf_spin_unlock(&pv->lock);
        }
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
        bpf_spin_lock(&sv->lock);
        if (sv->count == 0)
            sv->count = 1;
        sv->last_seen_ns = now;
        bpf_spin_unlock(&sv->lock);
        return;
    }

    {
        struct tcp_src_conn_key_v6 skey;
        struct tcp_src_conn_val *sv;

        fill_tcp_src_conn_key_v6(&skey, key, dest_port);
        sv = bpf_map_lookup_elem(&tsc6, &skey);
        if (!sv)
            return;
        bpf_spin_lock(&sv->lock);
        if (sv->count == 0)
            sv->count = 1;
        sv->last_seen_ns = now;
        bpf_spin_unlock(&sv->lock);
    }
}

static __always_inline void tcp_src_conn_record_close(struct flow_key *key, __u64 now,
                                                      __u32 dest_port)
{
    /* L3 — per-source decrement (tsc4/tsc6). */
    if (key->family == CT_FAMILY_IPV4) {
        struct tcp_src_conn_key_v4 skey;
        struct tcp_src_conn_val *sv;

        fill_tcp_src_conn_key_v4(&skey, key, dest_port);
        sv = bpf_map_lookup_elem(&tsc4, &skey);
        if (sv) {
            bool should_delete;
            bpf_spin_lock(&sv->lock);
            should_delete = sv->count <= 1;
            if (!should_delete) {
                sv->count--;
                sv->last_seen_ns = now;
            }
            bpf_spin_unlock(&sv->lock);
            /* Delete only after unlocking: the lock lives inside the map
             * value, so unlocking a slot bpf_map_delete_elem() has already
             * freed would touch released memory. */
            if (should_delete)
                bpf_map_delete_elem(&tsc4, &skey);
        }
    } else {
        struct tcp_src_conn_key_v6 skey;
        struct tcp_src_conn_val *sv;

        fill_tcp_src_conn_key_v6(&skey, key, dest_port);
        sv = bpf_map_lookup_elem(&tsc6, &skey);
        if (sv) {
            bool should_delete;
            bpf_spin_lock(&sv->lock);
            should_delete = sv->count <= 1;
            if (!should_delete) {
                sv->count--;
                sv->last_seen_ns = now;
            }
            bpf_spin_unlock(&sv->lock);
            if (should_delete)
                bpf_map_delete_elem(&tsc6, &skey);
        }
    }

    /* L4 — per-prefix decrement. */
    {
        struct tcp_port_policy_cfg *policy =
            bpf_map_lookup_elem(&tcp_port_policies, &dest_port);
        __u32 prefix_v4 = policy ? policy->source_prefix_v4 : 32;
        __u32 prefix_v6 = policy ? policy->source_prefix_v6 : 128;

        if (key->family == CT_FAMILY_IPV4) {
            struct prefix_rate_key_v4 pkey;
            struct tcp_pfx_conn_val *pv;
            fill_prefix_rate_key_v4(&pkey, key, dest_port, prefix_v4);
            pv = bpf_map_lookup_elem(&tsc_pfx4, &pkey);
            if (pv) {
                bool should_delete;
                bpf_spin_lock(&pv->lock);
                should_delete = pv->count <= 1;
                if (!should_delete) {
                    pv->count--;
                    pv->last_seen_ns = now;
                }
                bpf_spin_unlock(&pv->lock);
                if (should_delete)
                    bpf_map_delete_elem(&tsc_pfx4, &pkey);
            }
        } else {
            struct prefix_rate_key_v6 pkey;
            struct tcp_pfx_conn_val *pv;
            fill_prefix_rate_key_v6(&pkey, key, dest_port, prefix_v6);
            pv = bpf_map_lookup_elem(&tsc_pfx6, &pkey);
            if (pv) {
                bool should_delete;
                bpf_spin_lock(&pv->lock);
                should_delete = pv->count <= 1;
                if (!should_delete) {
                    pv->count--;
                    pv->last_seen_ns = now;
                }
                bpf_spin_unlock(&pv->lock);
                if (should_delete)
                    bpf_map_delete_elem(&tsc_pfx6, &pkey);
            }
        }
    }

    /* L5 — per-port total decrement (ARRAY stays, saturate at 0). */
    {
        struct tcp_port_conn_val *pv =
            bpf_map_lookup_elem(&tsc_port, &dest_port);
        if (pv) {
            bpf_spin_lock(&pv->lock);
            if (pv->count > 0) {
                pv->count--;
                pv->last_seen_ns = now;
            }
            bpf_spin_unlock(&pv->lock);
        }
    }
}

static __always_inline int tcp_conn_prefix_limit_check(
    struct flow_key *key, __u64 now, __u32 dest_port,
    __u32 prefix_v4, __u32 prefix_v6, __u32 conn_max,
    struct xdp_runtime_cfg *cfg)
{
    if (conn_max == 0)
        return XDP_PASS;

    if (key->family == CT_FAMILY_IPV4) {
        struct prefix_rate_key_v4 pkey;
        struct tcp_pfx_conn_val *pv;
        fill_prefix_rate_key_v4(&pkey, key, dest_port, prefix_v4);
        pv = bpf_map_lookup_elem(&tsc_pfx4, &pkey);
        if (!pv)
            return XDP_PASS;
        if (now - pv->last_seen_ns > cfg_tcp_timeout_ns(cfg))
            return XDP_PASS;
        if (pv->count >= conn_max)
            return XDP_DROP;
        return XDP_PASS;
    }
    {
        struct prefix_rate_key_v6 pkey;
        struct tcp_pfx_conn_val *pv;
        fill_prefix_rate_key_v6(&pkey, key, dest_port, prefix_v6);
        pv = bpf_map_lookup_elem(&tsc_pfx6, &pkey);
        if (!pv)
            return XDP_PASS;
        if (now - pv->last_seen_ns > cfg_tcp_timeout_ns(cfg))
            return XDP_PASS;
        if (pv->count >= conn_max)
            return XDP_DROP;
        return XDP_PASS;
    }
}

static __always_inline int tcp_conn_port_limit_check(
    __u32 dest_port, __u64 now, __u32 conn_max,
    struct xdp_runtime_cfg *cfg)
{
    if (conn_max == 0)
        return XDP_PASS;
    struct tcp_port_conn_val *pv =
        bpf_map_lookup_elem(&tsc_port, &dest_port);
    if (!pv)
        return XDP_PASS;
    if (now - pv->last_seen_ns > cfg_tcp_timeout_ns(cfg))
        return XDP_PASS;
    if (pv->count >= conn_max)
        return XDP_DROP;
    return XDP_PASS;
}

static __always_inline int precheck_new_tcp_syn(struct flow_key *key, __u32 dest_port,
                                                bool bypass_rate, __u64 now,
                                                struct xdp_runtime_cfg *cfg)
{
    struct tcp_port_policy_cfg *policy = bpf_map_lookup_elem(&tcp_port_policies, &dest_port);
    __u32 syn_rate_max = policy ? policy->syn_rate_max : 0;
    __u32 syn_agg_rate_max = policy ? policy->syn_agg_rate_max : 0;
    __u32 conn_limit_max = policy ? policy->conn_limit_max : 0;
    __u32 source_prefix_v4 = policy ? policy->source_prefix_v4 : 32;
    __u32 source_prefix_v6 = policy ? policy->source_prefix_v6 : 128;
    __u32 conn_prefix_limit_max = policy ? policy->conn_prefix_limit_max : 0;
    __u32 conn_port_limit_max   = policy ? policy->conn_port_limit_max   : 0;

    if (!bypass_rate) {
        if (syn_rate_check(key, now, dest_port, syn_rate_max, source_prefix_v4, source_prefix_v6, cfg) == XDP_DROP) {
            count(CNT_SYN_RATE_DROP);
            count(CNT_TCP_DROP);
            emit_drop(IPPROTO_TCP, key->family, key->saddr, key->daddr,
                      key->sport, key->dport, (__u8)CNT_SYN_RATE_DROP, now);
            return XDP_DROP;
        }

        if (syn_agg_rate_check(key, now, dest_port, syn_agg_rate_max, source_prefix_v4, source_prefix_v6, cfg) == XDP_DROP) {
            count(CNT_SYN_AGG_RATE_DROP);
            count(CNT_TCP_DROP);
            emit_drop(IPPROTO_TCP, key->family, key->saddr, key->daddr,
                      key->sport, key->dport, (__u8)CNT_SYN_AGG_RATE_DROP, now);
            return XDP_DROP;
        }
    }

    if (tcp_conn_limit_check(key, now, dest_port, conn_limit_max, cfg) == XDP_DROP) {
        count(CNT_TCP_CONN_LIMIT_DROP);
        count(CNT_TCP_DROP);
        emit_drop(IPPROTO_TCP, key->family, key->saddr, key->daddr,
                  key->sport, key->dport, (__u8)CNT_TCP_CONN_LIMIT_DROP, now);
        return XDP_DROP;
    }

    if (tcp_conn_prefix_limit_check(key, now, dest_port,
                                    source_prefix_v4, source_prefix_v6,
                                    conn_prefix_limit_max, cfg) == XDP_DROP) {
        count(CNT_TCP_CONN_PREFIX_LIMIT_DROP);
        count(CNT_TCP_DROP);
        emit_drop(IPPROTO_TCP, key->family, key->saddr, key->daddr,
                  key->sport, key->dport, (__u8)CNT_TCP_CONN_PREFIX_LIMIT_DROP, now);
        return XDP_DROP;
    }

    if (tcp_conn_port_limit_check(dest_port, now, conn_port_limit_max, cfg) == XDP_DROP) {
        count(CNT_TCP_CONN_PORT_LIMIT_DROP);
        count(CNT_TCP_DROP);
        emit_drop(IPPROTO_TCP, key->family, key->saddr, key->daddr,
                  key->sport, key->dport, (__u8)CNT_TCP_CONN_PORT_LIMIT_DROP, now);
        return XDP_DROP;
    }

    return XDP_PASS;
}

static __always_inline int allow_new_tcp_syn(struct flow_key *key, __u32 dest_port,
                                             bool bypass_rate, bool prechecked,
                                             __u64 now, struct xdp_runtime_cfg *cfg)
{
    __u64 *last_seen;
    bool ipv4 = key->family == CT_FAMILY_IPV4;
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
            if (!is_half_open)
                tcp_src_conn_record_close(key, now, dest_port);
        } else {
            if (age > cfg_ct_refresh_ns(cfg)) {
                __u64 new_val = is_half_open ? (now | CT_SYN_PENDING) : now;
                tcp_conntrack_update(ipv4, &key_v4, &key_v6, new_val, BPF_EXIST);
                tcp_src_conn_record_activity(key, now, dest_port);
            }
            count(CNT_TCP_NEW_ALLOW);
            emit_allow(IPPROTO_TCP, key->family, key->saddr, key->daddr,
                       key->sport, key->dport, (__u8)CNT_TCP_NEW_ALLOW, now);
            return XDP_PASS;
        }
    }

    if (!prechecked && precheck_new_tcp_syn(key, dest_port, bypass_rate, now, cfg) == XDP_DROP)
        return XDP_DROP;

    tcp_conntrack_update(ipv4, &key_v4, &key_v6, now | CT_SYN_PENDING, BPF_ANY);
    count(CNT_TCP_NEW_ALLOW);
    emit_allow(IPPROTO_TCP, key->family, key->saddr, key->daddr,
               key->sport, key->dport, (__u8)CNT_TCP_NEW_ALLOW, now);
    return XDP_PASS;
}

// Two-level global UDP rate limiter with blocked_until_ns fast path.
//
// Problem with the naive PERCPU_ARRAY approach: each CPU independently enforces
// byte_rate_max, so the effective global limit is byte_rate_max × N_CPUs.
//
// This design separates accumulation (per-CPU, lock-free) from enforcement
// (single shared state, spinlock-protected):
//
//   Fast path (per packet, no lock):
//     If local->blocked_until_ns is set and unexpired, drop immediately and
//     clear local_bytes to prevent a burst on unblock.
//     Otherwise accumulate pkt_bytes; pass if batch threshold not yet reached.
//
//   Slow path (every UDP_GLOBAL_BATCH_BYTES per CPU, one spinlock acquisition):
//     Check g->blocked_until_ns (under lock): if the global block is active,
//     save the deadline, propagate it to local->blocked_until_ns, and drop.
//     If the block just expired, reset the sliding-window state for a clean
//     slate.  Otherwise run the two-bucket sliding window; if the rate is
//     exceeded, set g->blocked_until_ns = now + window_ns and drop.
//
// Overshoot at any instant is bounded by N_CPUs × UDP_GLOBAL_BATCH_BYTES.
// For 32 CPUs and a 64 KiB batch that is 2 MiB — acceptable for a DDoS limiter.
// Lock contention is proportional to (global_rate / BATCH) × N_CPUs, not per packet.
//
// Avoids integer division using scaled comparisons:
//   prev*(W-elapsed) + curr*W  vs  byte_rate_max*W

#define UDP_GLOBAL_BATCH_BYTES (65536ULL)

// Per-CPU fast path of the global UDP block: returns XDP_DROP while a block
// verdict is active, clearing it once expired. Shared by the early pre-checks
// in the UDP handlers and by udp_global_rate_check().
static __always_inline int udp_global_block_fast_path(struct udp_percpu_local *local,
                                                      __u64 now)
{
    if (local->blocked_until_ns != 0) {
        if (now < local->blocked_until_ns) {
            local->local_bytes = 0;
            return XDP_DROP;
        }
        local->blocked_until_ns = 0;
    }
    return XDP_PASS;
}

static __always_inline int udp_global_rate_check(__u64 now, __u64 pkt_bytes,
                                                 struct xdp_runtime_cfg *cfg)
{
    __u32 key = 0;

    struct udp_global_state *g = bpf_map_lookup_elem(&udp_global_rl, &key);
    if (!g || g->byte_rate_max == 0)
        return XDP_PASS;

    struct udp_percpu_local *local = bpf_map_lookup_elem(&udp_percpu_acc, &key);
    if (!local)
        return XDP_PASS;

    // Per-CPU fast path: check block verdict without any spinlock.
    if (udp_global_block_fast_path(local, now) == XDP_DROP)
        return XDP_DROP;

    local->local_bytes += pkt_bytes;
    if (local->local_bytes < UDP_GLOBAL_BATCH_BYTES)
        return XDP_PASS;

    __u64 to_flush = local->local_bytes;
    local->local_bytes = 0;

    __u64 window_ns = cfg_udp_global_window_ns(cfg);
    __u64 block_until = 0;
    int ret = XDP_PASS;

    bpf_spin_lock(&g->lock);

    if (g->blocked_until_ns != 0) {
        if (now < g->blocked_until_ns) {
            // Global block still active: save deadline for propagation after unlock.
            block_until = g->blocked_until_ns;
        } else {
            // Block expired: reset sliding-window state for a clean slate.
            g->blocked_until_ns = 0;
            g->window_start_ns = 0;
            g->prev_bytes = 0;
            g->curr_bytes = 0;
        }
    }

    if (block_until == 0) {
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
                    block_until = now + window_ns;
                    g->blocked_until_ns = block_until;
                    ret = XDP_DROP;
                } else {
                    g->curr_bytes += to_flush;
                }
            }
        }
    }

    bpf_spin_unlock(&g->lock);

    if (block_until != 0) {
        local->blocked_until_ns = block_until;
        ret = XDP_DROP;
    }

    return ret;
}
