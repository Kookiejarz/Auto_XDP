#pragma once
#include "maps.h"

static __always_inline void fill_prefix_rate_key(
    struct prefix_rate_key *rkey, struct ct_key *key, __u32 dest_port)
{
    __builtin_memset(rkey, 0, sizeof(*rkey));
    rkey->family = key->family;
    rkey->dest_port = dest_port;
    if (key->family == CT_FAMILY_IPV4) {
        rkey->addr[0] = key->saddr[0] & bpf_htonl(0xFFFFFF00);
    } else {
        rkey->addr[0] = key->saddr[0];
        rkey->addr[1] = key->saddr[1];
    }
}

static __always_inline void fill_tcp_src_conn_key(
    struct tcp_src_conn_key *skey, struct ct_key *key, __u32 dest_port)
{
    __builtin_memset(skey, 0, sizeof(*skey));
    skey->family = key->family;
    skey->addr[0] = key->saddr[0];
    skey->addr[1] = key->saddr[1];
    skey->addr[2] = key->saddr[2];
    skey->addr[3] = key->saddr[3];
    skey->dest_port = dest_port;
}

// Per-IP SYN rate limiter: returns XDP_PASS or XDP_DROP.
// Looks up per-port config from syn_rate_ports; skips limiting entirely if
// the port is absent (e.g. HTTP/HTTPS). Races on multi-core are tolerated —
// a few extra SYNs slipping through is acceptable; spin locking every SYN
// would be far too costly.
static __always_inline int syn_rate_check(struct ct_key *key, __u64 now,
                                           __u32 dest_port)
{
    // Per-port config: rate_max=0 or missing entry → no rate limit for this port.
    struct syn_rate_port_cfg *cfg = bpf_map_lookup_elem(&syn_rate_ports, &dest_port);
    if (!cfg || cfg->rate_max == 0)
        return XDP_PASS;

    __u32 rate_max = cfg->rate_max;

    struct syn_rate_key rkey;
    __builtin_memset(&rkey, 0, sizeof(rkey));
    rkey.family   = key->family;
    rkey.addr[0]  = key->saddr[0];
    rkey.addr[1]  = key->saddr[1];
    rkey.addr[2]  = key->saddr[2];
    rkey.addr[3]  = key->saddr[3];

    struct syn_rate_val *rv = bpf_map_lookup_elem(&syn_rate_map, &rkey);
    if (!rv) {
        // First SYN from this source IP — create a fresh entry.
        struct syn_rate_val new_rv;
        __builtin_memset(&new_rv, 0, sizeof(new_rv));
        new_rv.window_start_ns = now;
        new_rv.count = 1;
        bpf_map_update_elem(&syn_rate_map, &rkey, &new_rv, BPF_ANY);
        return XDP_PASS;
    }

    if (now - rv->window_start_ns >= cfg_syn_window_ns) {
        // Window has elapsed — start a fresh one.
        rv->window_start_ns = now;
        rv->count = 1;
        return XDP_PASS;
    }

    if (rv->count >= rate_max)
        return XDP_DROP;

    rv->count++;
    return XDP_PASS;
}

static __always_inline int syn_agg_rate_check(struct ct_key *key, __u64 now,
                                              __u32 dest_port)
{
    struct syn_rate_port_cfg *cfg = bpf_map_lookup_elem(&syn_agg_rate_ports, &dest_port);
    if (!cfg || cfg->rate_max == 0)
        return XDP_PASS;

    struct prefix_rate_key rkey;
    fill_prefix_rate_key(&rkey, key, dest_port);

    struct prefix_rate_val *rv = bpf_map_lookup_elem(&syn_agg_rate_map, &rkey);
    if (!rv) {
        struct prefix_rate_val new_rv;
        __builtin_memset(&new_rv, 0, sizeof(new_rv));
        new_rv.window_start_ns = now;
        new_rv.units = 1;
        bpf_map_update_elem(&syn_agg_rate_map, &rkey, &new_rv, BPF_ANY);
        return XDP_PASS;
    }

    if (now - rv->window_start_ns >= cfg_syn_window_ns) {
        rv->window_start_ns = now;
        rv->units = 1;
        return XDP_PASS;
    }

    if (rv->units >= cfg->rate_max)
        return XDP_DROP;

    rv->units++;
    return XDP_PASS;
}

static __always_inline int udp_rate_check(struct ct_key *key, __u64 now,
                                           __u32 dest_port)
{
    struct syn_rate_port_cfg *cfg = bpf_map_lookup_elem(&udp_rate_ports, &dest_port);
    if (!cfg || cfg->rate_max == 0)
        return XDP_PASS;

    __u32 rate_max = cfg->rate_max;

    struct syn_rate_key rkey;
    __builtin_memset(&rkey, 0, sizeof(rkey));
    rkey.family  = key->family;
    rkey.addr[0] = key->saddr[0];
    rkey.addr[1] = key->saddr[1];
    rkey.addr[2] = key->saddr[2];
    rkey.addr[3] = key->saddr[3];

    struct syn_rate_val *rv = bpf_map_lookup_elem(&udp_rate_map, &rkey);
    if (!rv) {
        struct syn_rate_val new_rv;
        __builtin_memset(&new_rv, 0, sizeof(new_rv));
        new_rv.window_start_ns = now;
        new_rv.count = 1;
        bpf_map_update_elem(&udp_rate_map, &rkey, &new_rv, BPF_ANY);
        return XDP_PASS;
    }

    if (now - rv->window_start_ns >= cfg_syn_window_ns) {
        rv->window_start_ns = now;
        rv->count = 1;
        return XDP_PASS;
    }

    if (rv->count >= rate_max)
        return XDP_DROP;

    rv->count++;
    return XDP_PASS;
}

static __always_inline int udp_agg_rate_check(struct ct_key *key, __u64 now,
                                              __u32 dest_port, __u64 pkt_bytes)
{
    struct syn_rate_port_cfg *cfg = bpf_map_lookup_elem(&udp_agg_rate_ports, &dest_port);
    if (!cfg || cfg->rate_max == 0)
        return XDP_PASS;

    struct prefix_rate_key rkey;
    fill_prefix_rate_key(&rkey, key, dest_port);

    struct prefix_rate_val *rv = bpf_map_lookup_elem(&udp_agg_rate_map, &rkey);
    if (!rv) {
        struct prefix_rate_val new_rv;
        __builtin_memset(&new_rv, 0, sizeof(new_rv));
        new_rv.window_start_ns = now;
        new_rv.units = pkt_bytes;
        bpf_map_update_elem(&udp_agg_rate_map, &rkey, &new_rv, BPF_ANY);
        return XDP_PASS;
    }

    if (now - rv->window_start_ns >= cfg_syn_window_ns) {
        rv->window_start_ns = now;
        rv->units = pkt_bytes;
        return XDP_PASS;
    }

    if (rv->units + pkt_bytes > (__u64)cfg->rate_max)
        return XDP_DROP;

    rv->units += pkt_bytes;
    return XDP_PASS;
}

static __always_inline int tcp_conn_limit_check(struct ct_key *key, __u64 now,
                                                __u32 dest_port)
{
    struct syn_rate_port_cfg *cfg = bpf_map_lookup_elem(&tcp_conn_limit_ports, &dest_port);
    if (!cfg || cfg->rate_max == 0)
        return XDP_PASS;

    struct tcp_src_conn_key skey;
    fill_tcp_src_conn_key(&skey, key, dest_port);

    struct tcp_src_conn_val *sv = bpf_map_lookup_elem(&tcp_src_conn_map, &skey);
    if (!sv)
        return XDP_PASS;

    if (now - sv->last_seen_ns > cfg_tcp_timeout_ns) {
        sv->count = 0;
        sv->last_seen_ns = now;
        return XDP_PASS;
    }

    if (sv->count >= cfg->rate_max)
        return XDP_DROP;

    return XDP_PASS;
}

static __always_inline void tcp_src_conn_record_new(struct ct_key *key, __u64 now,
                                                    __u32 dest_port)
{
    struct tcp_src_conn_key skey;
    fill_tcp_src_conn_key(&skey, key, dest_port);

    struct tcp_src_conn_val *sv = bpf_map_lookup_elem(&tcp_src_conn_map, &skey);
    if (!sv) {
        struct tcp_src_conn_val new_sv;
        __builtin_memset(&new_sv, 0, sizeof(new_sv));
        new_sv.last_seen_ns = now;
        new_sv.count = 1;
        bpf_map_update_elem(&tcp_src_conn_map, &skey, &new_sv, BPF_ANY);
        return;
    }

    if (now - sv->last_seen_ns > cfg_tcp_timeout_ns)
        sv->count = 0;
    if (sv->count < 0xFFFFFFFF)
        sv->count++;
    sv->last_seen_ns = now;
}

static __always_inline void tcp_src_conn_record_activity(struct ct_key *key, __u64 now,
                                                         __u32 dest_port)
{
    struct tcp_src_conn_key skey;
    fill_tcp_src_conn_key(&skey, key, dest_port);

    struct tcp_src_conn_val *sv = bpf_map_lookup_elem(&tcp_src_conn_map, &skey);
    if (!sv)
        return;
    if (sv->count == 0)
        sv->count = 1;
    sv->last_seen_ns = now;
}

static __always_inline void tcp_src_conn_record_close(struct ct_key *key, __u64 now,
                                                      __u32 dest_port)
{
    struct tcp_src_conn_key skey;
    fill_tcp_src_conn_key(&skey, key, dest_port);

    struct tcp_src_conn_val *sv = bpf_map_lookup_elem(&tcp_src_conn_map, &skey);
    if (!sv)
        return;
    if (sv->count <= 1) {
        bpf_map_delete_elem(&tcp_src_conn_map, &skey);
        return;
    }
    sv->count--;
    sv->last_seen_ns = now;
}

static __always_inline int allow_new_tcp_syn(struct ct_key *key, __u32 dest_port,
                                             bool bypass_rate)
{
    __u64 now = bpf_ktime_get_ns();
    __u64 *last_seen = bpf_map_lookup_elem(&tcp_conntrack, key);

    if (last_seen) {
        __u64 age = now - *last_seen;
        if (age > cfg_tcp_timeout_ns) {
            bpf_map_delete_elem(&tcp_conntrack, key);
            tcp_src_conn_record_close(key, now, dest_port);
        } else {
            if (age > cfg_ct_refresh_ns) {
                bpf_map_update_elem(&tcp_conntrack, key, &now, BPF_EXIST);
                tcp_src_conn_record_activity(key, now, dest_port);
            }
            count(CNT_TCP_NEW_ALLOW);
            return XDP_PASS;
        }
    }

    if (!bypass_rate) {
        if (syn_rate_check(key, now, dest_port) == XDP_DROP) {
            count(CNT_SYN_RATE_DROP);
            count(CNT_TCP_DROP);
            emit_drop(IPPROTO_TCP, key->family, key->saddr, key->daddr,
                      key->sport, key->dport, (__u8)CNT_SYN_RATE_DROP);
            return XDP_DROP;
        }

        if (syn_agg_rate_check(key, now, dest_port) == XDP_DROP) {
            count(CNT_SYN_AGG_RATE_DROP);
            count(CNT_TCP_DROP);
            emit_drop(IPPROTO_TCP, key->family, key->saddr, key->daddr,
                      key->sport, key->dport, (__u8)CNT_SYN_AGG_RATE_DROP);
            return XDP_DROP;
        }
    }

    if (tcp_conn_limit_check(key, now, dest_port) == XDP_DROP) {
        count(CNT_TCP_CONN_LIMIT_DROP);
        count(CNT_TCP_DROP);
        emit_drop(IPPROTO_TCP, key->family, key->saddr, key->daddr,
                  key->sport, key->dport, (__u8)CNT_TCP_CONN_LIMIT_DROP);
        return XDP_DROP;
    }

    bpf_map_update_elem(&tcp_conntrack, key, &now, BPF_ANY);
    tcp_src_conn_record_new(key, now, dest_port);
    count(CNT_TCP_NEW_ALLOW);
    return XDP_PASS;
}

// Global UDP sliding-window rate limiter.
// Uses a two-bucket approximation: maintains current and previous 1-second
// buckets and computes a weighted estimate of the last 1 second's byte count.
// Avoids integer division by comparing scaled values:
//   prev_bytes*(WINDOW-elapsed) + curr_bytes*WINDOW  vs  byte_rate_max*WINDOW
static __always_inline int udp_global_rate_check(__u64 now, __u64 pkt_bytes)
{
    __u32 key = 0;
    struct udp_global_tb *tb = bpf_map_lookup_elem(&udp_global_rl, &key);
    if (!tb)
        return XDP_PASS;

    bpf_spin_lock(&tb->lock);

    if (tb->byte_rate_max == 0) {
        bpf_spin_unlock(&tb->lock);
        return XDP_PASS;
    }

    if (tb->window_start_ns == 0) {
        tb->window_start_ns = now;
        tb->prev_bytes = 0;
        tb->curr_bytes = pkt_bytes;
        bpf_spin_unlock(&tb->lock);
        return XDP_PASS;
    }

    // Hoist the rodata load once; used four times below.
    __u64 window_ns = cfg_udp_global_window_ns;
    __u64 elapsed   = now - tb->window_start_ns;

    if (elapsed >= 2 * window_ns) {
        // Both buckets expired; start fresh.
        tb->window_start_ns = now;
        tb->prev_bytes = 0;
        tb->curr_bytes = pkt_bytes;
        bpf_spin_unlock(&tb->lock);
        return XDP_PASS;
    }

    if (elapsed >= window_ns) {
        tb->prev_bytes = tb->curr_bytes;
        tb->curr_bytes = 0;
        tb->window_start_ns += window_ns;
        elapsed -= window_ns;
    }

    // Weighted sliding-window estimate (multiplication avoids division):
    //   (prev_bytes*(W-elapsed) + curr_bytes*W) >= byte_rate_max*W  →  DROP
    __u64 weighted   = tb->prev_bytes * (window_ns - elapsed)
                     + tb->curr_bytes * window_ns;
    __u64 threshold  = (__u64)tb->byte_rate_max * window_ns;

    int ret;
    if (weighted + (pkt_bytes * window_ns) > threshold) {
        ret = XDP_DROP;
    } else {
        tb->curr_bytes += pkt_bytes;
        ret = XDP_PASS;
    }

    bpf_spin_unlock(&tb->lock);
    return ret;
}
