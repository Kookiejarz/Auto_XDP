/* bpf/xdp_firewall.c — XDP entry point.
 * All helpers live under bpf/include/ as one translation unit. */

#include "include/common.h"
#include "include/keys.h"
#include "include/maps.h"
#include "include/trust_acl.h"
#include "include/rate_limit.h"
#include "include/port_dispatch.h"
#include "include/conntrack.h"
#include "include/parse.h"
#include "include/slots.h"

/* --- Protocol dispatch functions --- */

static __always_inline int check_tcp_ipv4(
    struct xdp_md *ctx,
    struct iphdr *ip, void *trans_data, void *data_end,
    __u16 l3_off, __u16 inner_off)
{
    struct tcphdr *tcp = trans_data;
    struct flow_key key;

    if ((void *)(tcp + 1) > data_end)
        return XDP_DROP;

    __u8 malform = tcp_malformed_reason(tcp, data_end);
    if (malform) {
        count(malform);
        count(CNT_TCP_DROP);
        __u32 s[4] = { (__u32)ip->saddr, 0, 0, 0 };
        __u32 d[4] = { (__u32)ip->daddr, 0, 0, 0 };
        emit_drop(IPPROTO_TCP, CT_FAMILY_IPV4, s, d,
                  tcp->source, tcp->dest, malform);
        return XDP_DROP;
    }

    __u8  tcp_flags = ((__u8 *)tcp)[13];
    __u32 dest_port = (__u32)bpf_ntohs(tcp->dest);
    fill_flow_key_v4(&key, ip->saddr, ip->daddr, tcp->source, tcp->dest);

    // Trusted source: bypass whitelist + SYN rate limit for new connections.
    // Malformed-packet check already ran above; fragments dropped before we arrive.
    if ((tcp_flags & 0x02) && !(tcp_flags & 0x10) && is_trusted_v4(ip->saddr)) {
        return allow_new_tcp_syn(&key, dest_port, true, false);
    }

    if ((tcp_flags & 0x02) && !(tcp_flags & 0x10)) {
        struct trusted_v4_key tk = { .prefixlen = 32, .addr = ip->saddr };
        struct acl_val *av = bpf_map_lookup_elem(&tcp_acl_v4, &tk);
        if (av && acl_port_match(av, dest_port)) {
            return allow_new_tcp_syn(&key, dest_port, true, false);
        }
    }

    return check_tcp_conntrack(ctx, &key, tcp_flags, dest_port, l3_off, inner_off);
}

static __always_inline int check_tcp_ipv6(
    struct xdp_md *ctx,
    struct ipv6hdr *ipv6, void *trans_data, void *data_end,
    __u16 l3_off, __u16 inner_off)
{
    struct tcphdr *tcp = trans_data;
    struct flow_key key;

    if ((void *)(tcp + 1) > data_end)
        return XDP_DROP;

    __u8 malform = tcp_malformed_reason(tcp, data_end);
    if (malform) {
        count(malform);
        count(CNT_TCP_DROP);
        __u32 s[4], d[4];
        __builtin_memcpy(s, &ipv6->saddr, 16);
        __builtin_memcpy(d, &ipv6->daddr, 16);
        emit_drop(IPPROTO_TCP, CT_FAMILY_IPV6, s, d,
                  tcp->source, tcp->dest, malform);
        return XDP_DROP;
    }

    __u8 tcp_flags = ((__u8 *)tcp)[13];
    __u32 dest_port = (__u32)bpf_ntohs(tcp->dest);
    fill_flow_key_v6(&key, &ipv6->saddr, &ipv6->daddr, tcp->source, tcp->dest);

    if ((tcp_flags & 0x02) && !(tcp_flags & 0x10) && is_trusted_v6(&ipv6->saddr)) {
        return allow_new_tcp_syn(&key, dest_port, true, false);
    }

    if ((tcp_flags & 0x02) && !(tcp_flags & 0x10)) {
        struct trusted_v6_key tk;
        tk.prefixlen = 128;
        __builtin_memcpy(tk.addr, &ipv6->saddr, 16);
        struct acl_val *av = bpf_map_lookup_elem(&tcp_acl_v6, &tk);
        if (av && acl_port_match(av, dest_port)) {
            return allow_new_tcp_syn(&key, dest_port, true, false);
        }
    }

    return check_tcp_conntrack(ctx, &key, tcp_flags, dest_port, l3_off, inner_off);
}

static __always_inline int check_udp_ipv4(
    struct xdp_md *ctx,
    struct iphdr *ip, void *trans_data, void *data_end,
    __u16 l3_off, __u16 inner_off)
{
    struct udphdr *udp = trans_data;
    struct flow_key key;
    __u64 now = bpf_ktime_get_ns();
    __u64 *last_seen;

    if ((void *)(udp + 1) > data_end)
        return XDP_DROP;

    __u8 malform = udp_malformed_reason(udp, data_end);
    if (malform) {
        count(malform);
        count(CNT_UDP_DROP);
        __u32 s[4] = { (__u32)ip->saddr, 0, 0, 0 };
        __u32 d[4] = { (__u32)ip->daddr, 0, 0, 0 };
        emit_drop(IPPROTO_UDP, CT_FAMILY_IPV4, s, d,
                  udp->source, udp->dest, malform);
        return XDP_DROP;
    }

    __u32 dest_port = (__u32)bpf_ntohs(udp->dest);
    __u64 pkt_bytes = (__u64)bpf_ntohs(ip->tot_len);
    struct udp_port_policy_cfg *policy;

    // UDP replies are stateful now: tc egress records outbound packets as the
    // reverse tuple, and XDP ingress looks up the current inbound tuple here.
    fill_flow_key_v4(&key, ip->saddr, ip->daddr, udp->source, udp->dest);
    {
        struct ct_key_v4 map_key;
        fill_ct_key_v4_map(&map_key, &key);
        last_seen = bpf_map_lookup_elem(&udp_ct4, &map_key);
        if (last_seen) {
            __u64 age = now - *last_seen;
            if (age > runtime_udp_timeout_ns()) {
                bpf_map_delete_elem(&udp_ct4, &map_key);
            } else {
                if (age > runtime_ct_refresh_ns())
                    bpf_map_update_elem(&udp_ct4, &map_key, &now, BPF_EXIST);
                count(CNT_UDP_PASS);
                return XDP_PASS;
            }
        }

        {
            __u64 *valid_until = bpf_map_lookup_elem(&udp_hv4, &map_key);
            if (valid_until && now < *valid_until) {
                count(CNT_UDP_PASS);
                return XDP_PASS;
            }
        }
    }

    if (is_trusted_v4(ip->saddr)) {
        count(CNT_UDP_PASS);
        return XDP_PASS;
    }

    {
        struct trusted_v4_key tk = { .prefixlen = 32, .addr = ip->saddr };
        struct acl_val *av = bpf_map_lookup_elem(&udp_acl_v4, &tk);
        if (av && acl_port_match(av, dest_port)) {
            count(CNT_UDP_PASS);
            return XDP_PASS;
        }
    }

    __u32 *allow = bpf_map_lookup_elem(&udp_whitelist, &dest_port);
    if (allow && *allow) {
        policy = bpf_map_lookup_elem(&udp_port_policies, &dest_port);
        if (is_handler_blocked(&key)) {
            count(CNT_HANDLER_BLOCK_DROP);
            count(CNT_UDP_DROP);
            emit_drop(IPPROTO_UDP, CT_FAMILY_IPV4, key.saddr, key.daddr,
                      key.sport, key.dport, (__u8)CNT_HANDLER_BLOCK_DROP);
            return XDP_DROP;
        }
        if (udp_rate_check(
                &key, now,
                policy ? policy->rate_max : 0,
                policy ? policy->source_prefix_v4 : 32,
                policy ? policy->source_prefix_v6 : 128) == XDP_DROP) {
            count(CNT_UDP_RATE_DROP);
            count(CNT_UDP_DROP);
            emit_drop(IPPROTO_UDP, CT_FAMILY_IPV4, key.saddr, key.daddr,
                      key.sport, key.dport, (__u8)CNT_UDP_RATE_DROP);
            return XDP_DROP;
        }
        if (udp_agg_rate_check(
                &key, now, dest_port, pkt_bytes,
                policy ? policy->agg_rate_max : 0,
                policy ? policy->source_prefix_v4 : 32,
                policy ? policy->source_prefix_v6 : 128) == XDP_DROP) {
            count(CNT_UDP_AGG_RATE_DROP);
            count(CNT_UDP_DROP);
            emit_drop(IPPROTO_UDP, CT_FAMILY_IPV4, key.saddr, key.daddr,
                      key.sport, key.dport, (__u8)CNT_UDP_AGG_RATE_DROP);
            return XDP_DROP;
        }
        if (udp_global_rate_check(now, pkt_bytes) == XDP_DROP) {
            count(CNT_UDP_GLOBAL_RATE_DROP);
            count(CNT_UDP_DROP);
            emit_drop(IPPROTO_UDP, CT_FAMILY_IPV4, key.saddr, key.daddr,
                      key.sport, key.dport, (__u8)CNT_UDP_GLOBAL_RATE_DROP);
            return XDP_DROP;
        }
        // Only after rate gates pass do we dispatch into an optional handler.
        try_udp_port_dispatch(ctx, &key, l3_off, inner_off, dest_port);
        count(CNT_UDP_PASS);
        return XDP_PASS;
    }

    count(CNT_UDP_DROP);
    emit_drop(IPPROTO_UDP, CT_FAMILY_IPV4, key.saddr, key.daddr,
              key.sport, key.dport, (__u8)CNT_UDP_DROP);
    return XDP_DROP;
}

static __always_inline int check_udp_ipv6(
    struct xdp_md *ctx,
    struct ipv6hdr *ipv6, void *trans_data, void *data_end,
    __u16 l3_off, __u16 inner_off)
{
    struct udphdr *udp = trans_data;
    struct flow_key key;
    __u64 now = bpf_ktime_get_ns();
    __u64 *last_seen;
    struct udp_port_policy_cfg *policy;

    if ((void *)(udp + 1) > data_end)
        return XDP_DROP;

    __u8 malform = udp_malformed_reason(udp, data_end);
    if (malform) {
        count(malform);
        count(CNT_UDP_DROP);
        __u32 s[4], d[4];
        __builtin_memcpy(s, &ipv6->saddr, 16);
        __builtin_memcpy(d, &ipv6->daddr, 16);
        emit_drop(IPPROTO_UDP, CT_FAMILY_IPV6, s, d,
                  udp->source, udp->dest, malform);
        return XDP_DROP;
    }

    __u32 dest_port = (__u32)bpf_ntohs(udp->dest);
    __u64 pkt_bytes = (__u64)sizeof(*ipv6) + (__u64)bpf_ntohs(ipv6->payload_len);

    // IPv6 UDP replies are matched by the same shared conntrack map shape.
    fill_flow_key_v6(&key, &ipv6->saddr, &ipv6->daddr, udp->source, udp->dest);
    {
        struct ct_key_v6 map_key;
        fill_ct_key_v6_map(&map_key, &key);
        last_seen = bpf_map_lookup_elem(&udp_ct6, &map_key);
        if (last_seen) {
            __u64 age = now - *last_seen;
            if (age > runtime_udp_timeout_ns()) {
                bpf_map_delete_elem(&udp_ct6, &map_key);
            } else {
                if (age > runtime_ct_refresh_ns())
                    bpf_map_update_elem(&udp_ct6, &map_key, &now, BPF_EXIST);
                count(CNT_UDP_PASS);
                return XDP_PASS;
            }
        }

        {
            __u64 *valid_until = bpf_map_lookup_elem(&udp_hv6, &map_key);
            if (valid_until && now < *valid_until) {
                count(CNT_UDP_PASS);
                return XDP_PASS;
            }
        }
    }

    if (is_trusted_v6(&ipv6->saddr)) {
        count(CNT_UDP_PASS);
        return XDP_PASS;
    }

    {
        struct trusted_v6_key tk;
        tk.prefixlen = 128;
        __builtin_memcpy(tk.addr, &ipv6->saddr, 16);
        struct acl_val *av = bpf_map_lookup_elem(&udp_acl_v6, &tk);
        if (av && acl_port_match(av, dest_port)) {
            count(CNT_UDP_PASS);
            return XDP_PASS;
        }
    }

    __u32 *allow = bpf_map_lookup_elem(&udp_whitelist, &dest_port);
    if (allow && *allow) {
        policy = bpf_map_lookup_elem(&udp_port_policies, &dest_port);
        if (is_handler_blocked(&key)) {
            count(CNT_HANDLER_BLOCK_DROP);
            count(CNT_UDP_DROP);
            emit_drop(IPPROTO_UDP, CT_FAMILY_IPV6, key.saddr, key.daddr,
                      key.sport, key.dport, (__u8)CNT_HANDLER_BLOCK_DROP);
            return XDP_DROP;
        }
        if (udp_rate_check(
                &key, now,
                policy ? policy->rate_max : 0,
                policy ? policy->source_prefix_v4 : 32,
                policy ? policy->source_prefix_v6 : 128) == XDP_DROP) {
            count(CNT_UDP_RATE_DROP);
            count(CNT_UDP_DROP);
            emit_drop(IPPROTO_UDP, CT_FAMILY_IPV6, key.saddr, key.daddr,
                      key.sport, key.dport, (__u8)CNT_UDP_RATE_DROP);
            return XDP_DROP;
        }
        if (udp_agg_rate_check(
                &key, now, dest_port, pkt_bytes,
                policy ? policy->agg_rate_max : 0,
                policy ? policy->source_prefix_v4 : 32,
                policy ? policy->source_prefix_v6 : 128) == XDP_DROP) {
            count(CNT_UDP_AGG_RATE_DROP);
            count(CNT_UDP_DROP);
            emit_drop(IPPROTO_UDP, CT_FAMILY_IPV6, key.saddr, key.daddr,
                      key.sport, key.dport, (__u8)CNT_UDP_AGG_RATE_DROP);
            return XDP_DROP;
        }
        if (udp_global_rate_check(now, pkt_bytes) == XDP_DROP) {
            count(CNT_UDP_GLOBAL_RATE_DROP);
            count(CNT_UDP_DROP);
            emit_drop(IPPROTO_UDP, CT_FAMILY_IPV6, key.saddr, key.daddr,
                      key.sport, key.dport, (__u8)CNT_UDP_GLOBAL_RATE_DROP);
            return XDP_DROP;
        }
        // Only after rate gates pass do we dispatch into an optional handler.
        try_udp_port_dispatch(ctx, &key, l3_off, inner_off, dest_port);
        count(CNT_UDP_PASS);
        return XDP_PASS;
    }

    count(CNT_UDP_DROP);
    emit_drop(IPPROTO_UDP, CT_FAMILY_IPV6, key.saddr, key.daddr,
              key.sport, key.dport, (__u8)CNT_UDP_DROP);
    return XDP_DROP;
}

// ICMP token-bucket rate limiter: returns XDP_PASS or XDP_DROP.
// Tokens refill at (1e9/runtime_icmp_ns_per_token()) per second up to runtime_icmp_token_max().
static __always_inline int icmp_rate_limit(void)
{
    __u32 key = 0;
    struct icmp_token_bucket *tb = bpf_map_lookup_elem(&icmp_tb, &key);
    if (!tb)
        return XDP_PASS; // fail-open: never block because of a map miss

    __u64 now = bpf_ktime_get_ns();
    struct xdp_runtime_cfg *cfg = runtime_cfg();
    __u64 token_max = (cfg && cfg->icmp_token_max) ? cfg->icmp_token_max : 100ULL;
    __u64 ns_per_token = (cfg && cfg->icmp_ns_per_token)
                       ? cfg->icmp_ns_per_token
                       : NS_PER_SEC / 100ULL;
    int ret;

    bpf_spin_lock(&tb->lock);

    if (tb->last_refill_ns == 0) {
        // First ICMP packet ever: start with a full bucket.
        tb->tokens = token_max;
        tb->last_refill_ns = now;
    } else {
        // Add whole tokens for elapsed time; advance the refill clock by the
        // consumed intervals only (prevents credit accumulation across idle gaps).
        __u64 elapsed = now - tb->last_refill_ns;
        __u64 new_tokens = elapsed / ns_per_token;
        if (new_tokens > 0) {
            tb->tokens += new_tokens;
            if (tb->tokens > token_max)
                tb->tokens = token_max;
            tb->last_refill_ns += new_tokens * ns_per_token;
        }
    }

    if (tb->tokens > 0) {
        tb->tokens--;
        ret = XDP_PASS;
    } else {
        ret = XDP_DROP;
    }

    bpf_spin_unlock(&tb->lock);
    return ret;
}

// Main XDP program

static __always_inline int _xdp_fw(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;

    // --- 1. Parse Ethernet layer ---
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    // Strip 802.1Q / QinQ VLAN tags so firewall rules apply to the inner
    // EtherType.  Without this, VLAN-tagged IP packets arrive with
    // h_proto=0x8100 and bypass all port/conntrack checks via CNT_NON_IP.
    __be16 eth_proto = eth->h_proto;
    void  *l3_data   = (void *)(eth + 1);

    if (!strip_vlan_tags(&eth_proto, &l3_data, data_end))
        return XDP_PASS; // truncated VLAN header: let the kernel handle it

    // Drop packets with more VLAN layers than VLAN_MAX_DEPTH — no legitimate
    // traffic uses such deep nesting; deeper tags are a known bypass technique.
    if (eth_proto == bpf_htons(ETH_P_8021Q) ||
        eth_proto == bpf_htons(ETH_P_8021AD)) {
        count(CNT_VLAN_DROP);
        { __u32 z[4]; __builtin_memset(z, 0, 16);
          emit_drop(0, 0, z, z, 0, 0, (__u8)CNT_VLAN_DROP); }
        return XDP_DROP;
    }

    // 2. IPv4
    if (eth_proto == bpf_htons(ETH_P_IP)) {
        struct iphdr *ip = l3_data;
        if ((void *)(ip + 1) > data_end)
            return XDP_PASS;

        // Validate ihl before reading frag_off
        __u32 ip_hlen = ip->ihl * 4;
        if (ip_hlen < sizeof(*ip))
            return XDP_PASS;

        // Drop IPv4 fragmented packets (rarely needed on personal servers, and fragments can bypass port filtering)
        if (ip->frag_off & bpf_htons(IP_MF | IP_OFFSET)) {
            count(CNT_FRAG_DROP);
            { __u32 s[4] = { (__u32)ip->saddr, 0, 0, 0 };
              __u32 d[4] = { (__u32)ip->daddr, 0, 0, 0 };
              emit_drop(ip->protocol, CT_FAMILY_IPV4, s, d, 0, 0, (__u8)CNT_FRAG_DROP); }
            return XDP_DROP;
        }

        void *trans_data = (void *)ip + ip_hlen;

        if (bogon_filter_active() && is_bogon_v4(ip->saddr)) {
            count(CNT_BOGON_DROP);
            { __u32 s[4] = { (__u32)ip->saddr, 0, 0, 0 };
              __u32 d[4] = { (__u32)ip->daddr, 0, 0, 0 };
              emit_drop(ip->protocol, CT_FAMILY_IPV4, s, d, 0, 0, (__u8)CNT_BOGON_DROP); }
            return XDP_DROP;
        }

        __u16 l3_off    = (__u16)((void *)ip - data);
        __u16 inner_off = (__u16)(trans_data - data);

        switch (ip->protocol) {
        case IPPROTO_TCP:
            return check_tcp_ipv4(ctx, ip, trans_data, data_end, l3_off, inner_off);
        case IPPROTO_UDP:
            return check_udp_ipv4(ctx, ip, trans_data, data_end, l3_off, inner_off);
        case IPPROTO_ICMP: {
            struct icmphdr *icmp = trans_data;
            if ((void *)(icmp + 1) > data_end) {
                count(CNT_IPV4_OTHER);
                return XDP_PASS;
            }
            __u8 icmp_type = icmp->type;
            // Control-plane messages required for PMTU discovery, traceroute,
            // and error feedback — never rate-limit these.
            if (icmp_type == ICMP_DEST_UNREACH  ||
                icmp_type == ICMP_TIME_EXCEEDED  ||
                icmp_type == ICMP_PARAMETERPROB) {
                count(CNT_IPV4_OTHER);
                return XDP_PASS;
            }
            // Echo request from untrusted source: token-bucket rate limit.
            if (icmp_type == ICMP_ECHO &&
                !is_trusted_v4(ip->saddr) &&
                icmp_rate_limit() == XDP_DROP) {
                count(CNT_ICMP_DROP);
                { __u32 s[4] = { (__u32)ip->saddr, 0, 0, 0 };
                  __u32 d[4] = { (__u32)ip->daddr, 0, 0, 0 };
                  emit_drop(IPPROTO_ICMP, CT_FAMILY_IPV4, s, d, 0, 0, (__u8)CNT_ICMP_DROP); }
                return XDP_DROP;
            }
            count(CNT_IPV4_OTHER);
            return XDP_PASS;
        }
        case IPPROTO_IPV6: {
            /* 6in4 tunnel (RFC 4213, proto 41): only pass packets whose outer
             * source IP is an explicitly configured tunnel endpoint.  Dropping
             * everything else at XDP speed prevents attackers from forging
             * proto-41 packets to exhaust kernel SIT-decapsulation CPU. */
            __be32 sit_key = ip->saddr;
            __u32 *sit_allow = bpf_map_lookup_elem(&sit4_endpoints, &sit_key);
            if (sit_allow && *sit_allow) {
                count(CNT_IPV4_OTHER);
                return XDP_PASS;
            }
            count(CNT_SLOT_DROP);
            { __u32 s[4] = { (__u32)ip->saddr, 0, 0, 0 };
              __u32 d[4] = { (__u32)ip->daddr, 0, 0, 0 };
              emit_drop(IPPROTO_IPV6, CT_FAMILY_IPV4, s, d, 0, 0, (__u8)CNT_SLOT_DROP); }
            return XDP_DROP;
        }
        default: {
            __u32 s[4] = { (__u32)ip->saddr, 0, 0, 0 };
            __u32 d[4] = { (__u32)ip->daddr, 0, 0, 0 };
            return dispatch_to_slot(ctx, CT_FAMILY_IPV4, ip->protocol,
                                    l3_off, inner_off, s, d);
        }
        }
    }

    // 3. IPv6
    if (eth_proto == bpf_htons(ETH_P_IPV6)) {
        struct ipv6hdr *ipv6 = l3_data;
        if ((void *)(ipv6 + 1) > data_end)
            return XDP_PASS;

        void *trans_data = (void *)(ipv6 + 1);

        __u8 nexthdr = skip_ipv6_exthdr(&trans_data, data_end, ipv6->nexthdr);
        // 0xFF is our dedicated sentinel for non-initial IPv6 fragments.
        if (nexthdr == IPV6_FRAG_DROP_SENTINEL) {
            count(CNT_FRAG_DROP);
            { __u32 s[4], d[4];
              __builtin_memcpy(s, &ipv6->saddr, 16);
              __builtin_memcpy(d, &ipv6->daddr, 16);
              emit_drop(0, CT_FAMILY_IPV6, s, d, 0, 0, (__u8)CNT_FRAG_DROP); }
            return XDP_DROP;
        }
        if (nexthdr == IPPROTO_NONE)
            return XDP_PASS;

        if (bogon_filter_active() && is_bogon_v6(&ipv6->saddr)) {
            count(CNT_BOGON_DROP);
            { __u32 s[4], d[4];
              __builtin_memcpy(s, &ipv6->saddr, 16);
              __builtin_memcpy(d, &ipv6->daddr, 16);
              emit_drop(nexthdr, CT_FAMILY_IPV6, s, d, 0, 0, (__u8)CNT_BOGON_DROP); }
            return XDP_DROP;
        }

        __u16 l3_off    = (__u16)((void *)ipv6 - data);
        __u16 inner_off = (__u16)(trans_data - data);

        switch (nexthdr) {
        case IPPROTO_TCP:
            return check_tcp_ipv6(ctx, ipv6, trans_data, data_end, l3_off, inner_off);
        case IPPROTO_UDP:
            return check_udp_ipv6(ctx, ipv6, trans_data, data_end, l3_off, inner_off);
        case IPPROTO_ICMPV6: {
            // NDP (RS/RA/NS/NA/Redirect, types 133-137) must always pass —
            // dropping them breaks IPv6 neighbour discovery and routing.
            // Only echo requests (type 128) go through the shared token bucket.
            struct icmp6hdr *icmp6 = trans_data;
            if ((void *)(icmp6 + 1) > data_end) {
                count(CNT_IPV6_OTHER);
                return XDP_PASS;
            }
            if (icmp6->icmp6_type == ICMPV6_ECHO_REQUEST &&
                !is_trusted_v6(&ipv6->saddr) &&
                icmp_rate_limit() == XDP_DROP) {
                count(CNT_ICMP_DROP);
                { __u32 s[4], d[4];
                  __builtin_memcpy(s, &ipv6->saddr, 16);
                  __builtin_memcpy(d, &ipv6->daddr, 16);
                  emit_drop(IPPROTO_ICMPV6, CT_FAMILY_IPV6, s, d, 0, 0, (__u8)CNT_ICMP_DROP); }
                return XDP_DROP;
            }
            count(CNT_IPV6_OTHER);
            return XDP_PASS;
        }
        default: {
            __u32 s[4], d[4];
            __builtin_memcpy(s, &ipv6->saddr, 16);
            __builtin_memcpy(d, &ipv6->daddr, 16);
            return dispatch_to_slot(ctx, CT_FAMILY_IPV6, nexthdr,
                                    l3_off, inner_off, s, d);
        }
        }
    }

    // 4. Pass non-IP traffic (ARP, etc.)
    count(CNT_NON_IP);
    return XDP_PASS;
}

SEC("xdp")
int xdp_port_whitelist(struct xdp_md *ctx) {
    int verdict = _xdp_fw(ctx);
    __u32 pkt_len = (__u32)((char *)(long)ctx->data_end - (char *)(long)ctx->data);
    count_bytes(verdict == XDP_DROP, pkt_len);
    return verdict;
}

char _license[] SEC("license") = "GPL";
