#pragma once
#include "rate_limit.h"

static __always_inline void fill_ct_key_v4(
    struct ct_key *key, __be32 saddr, __be32 daddr,
    __be16 sport, __be16 dport)
{
    // Zero the full key so the verifier never sees uninitialized padding.
    __builtin_memset(key, 0, sizeof(*key));
    key->family = CT_FAMILY_IPV4;
    key->sport = sport;
    key->dport = dport;
    key->saddr[0] = (__u32)saddr;
    key->daddr[0] = (__u32)daddr;
}

static __always_inline void fill_ct_key_v6(
    struct ct_key *key, const struct in6_addr *saddr, const struct in6_addr *daddr,
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
    struct ct_key *key, __u8 tcp_flags, __u32 dest_port)
{
    __u64 now = bpf_ktime_get_ns();
    __u64 *last_seen;

    // 1. RST: bare RST (no ACK) is a common reset-injection vector — drop it.
    // RST+ACK is only valid for an established connection; without a matching
    // conntrack entry it is a spoofed or stale reset and must be dropped.
    if (tcp_flags & 0x04) {
        if (!(tcp_flags & 0x10))
            goto drop; // bare RST, no ACK

        // RST+ACK: require an existing, non-expired conntrack entry
        last_seen = bpf_map_lookup_elem(&tcp_conntrack, key);
        if (!last_seen) {
            count(CNT_TCP_CT_MISS);
            count(CNT_TCP_DROP);
            emit_drop(IPPROTO_TCP, key->family, key->saddr, key->daddr,
                      key->sport, key->dport, (__u8)CNT_TCP_CT_MISS);
            return XDP_DROP;
        }
        if (now - *last_seen > cfg_tcp_timeout_ns) {
            bpf_map_delete_elem(&tcp_conntrack, key);
            tcp_src_conn_record_close(key, now, dest_port);
            count(CNT_TCP_CT_MISS);
            count(CNT_TCP_DROP);
            emit_drop(IPPROTO_TCP, key->family, key->saddr, key->daddr,
                      key->sport, key->dport, (__u8)CNT_TCP_CT_MISS);
            return XDP_DROP;
        }
        bpf_map_delete_elem(&tcp_conntrack, key);
        tcp_src_conn_record_close(key, now, dest_port);
        count(CNT_TCP_ESTABLISHED);
        return XDP_PASS;
    }

    // 2. ACK / FIN+ACK / SYN-ACK (established traffic)
    if (tcp_flags & 0x10) {
        __u64 tcp_timeout = cfg_tcp_timeout_ns;
        __u64 ct_refresh  = cfg_ct_refresh_ns;
        last_seen = bpf_map_lookup_elem(&tcp_conntrack, key);
        if (last_seen) {
            __u64 age = now - *last_seen;
            if (age > tcp_timeout) {
                bpf_map_delete_elem(&tcp_conntrack, key);
                tcp_src_conn_record_close(key, now, dest_port);
                count(CNT_TCP_CT_MISS);
                count(CNT_TCP_DROP);
                emit_drop(IPPROTO_TCP, key->family, key->saddr, key->daddr,
                          key->sport, key->dport, (__u8)CNT_TCP_CT_MISS);
                return XDP_DROP;
            }

            // FIN+ACK: connection is closing — evict immediately so the map
            // slot is available for new connections rather than waiting for
            // the full TCP timeout.  The remaining FIN/ACK exchange will
            // miss conntrack but those packets are benign on a closing conn.
            if (tcp_flags & 0x01) {
                bpf_map_delete_elem(&tcp_conntrack, key);
                tcp_src_conn_record_close(key, now, dest_port);
                count(CNT_TCP_ESTABLISHED);
                return XDP_PASS;
            }

            // Periodic refresh for long-lived connections
            if (age > ct_refresh) {
                bpf_map_update_elem(&tcp_conntrack, key, &now, BPF_EXIST);
                tcp_src_conn_record_activity(key, now, dest_port);
            }

            count(CNT_TCP_ESTABLISHED);
            return XDP_PASS;
        }

        count(CNT_TCP_CT_MISS);
        count(CNT_TCP_DROP);
        emit_drop(IPPROTO_TCP, key->family, key->saddr, key->daddr,
                  key->sport, key->dport, (__u8)CNT_TCP_CT_MISS);
        return XDP_DROP;
    }

    // 2b. Standalone FIN (no ACK, rare but valid per RFC 793 §3.5)
    if (tcp_flags & 0x01) {
        last_seen = bpf_map_lookup_elem(&tcp_conntrack, key);
        if (last_seen) {
            bpf_map_delete_elem(&tcp_conntrack, key);
            tcp_src_conn_record_close(key, now, dest_port);
            count(CNT_TCP_ESTABLISHED);
            return XDP_PASS;
        }
        goto drop;
    }

    // 3. SYN (new inbound connection)
    // TC egress only fires on outbound, so any inbound SYN on a new tuple
    // will always miss conntrack — no pre-check needed or useful here.
    // Use (flags & SYN) && !(flags & ACK) instead of == 0x02 so that
    // ECN-negotiating SYNs (SYN+ECE=0x42, SYN+ECE+CWR=0xC2) are accepted.
    if ((tcp_flags & 0x02) && !(tcp_flags & 0x10)) {
        // Whitelist check: port not open → DROP, one map lookup and done.
        __u32 *allow = bpf_map_lookup_elem(&tcp_whitelist, &dest_port);
        if (!allow || !*allow)
            goto drop;
        return allow_new_tcp_syn(key, dest_port, false);
    }

drop:
    count(CNT_TCP_DROP);
    emit_drop(IPPROTO_TCP, key->family, key->saddr, key->daddr,
              key->sport, key->dport, (__u8)CNT_TCP_DROP);
    return XDP_DROP;
}
