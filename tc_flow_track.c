#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#ifndef bool
typedef _Bool bool;
#define true  1
#define false 0
#endif

#ifndef IP_MF
#define IP_MF     0x2000
#endif
#ifndef IP_OFFSET
#define IP_OFFSET 0x1FFF
#endif

/* struct vlan_hdr is not reliably defined in BPF compilation headers on all
 * distros. Define it locally so tc egress can mirror the XDP VLAN parser.
 */
struct vlan_hdr {
    __be16  h_vlan_TCI;
    __be16  h_vlan_encapsulated_proto;
};

#define IPV6_FRAG_DROP_SENTINEL 0xFF
#define CT_FAMILY_IPV4 2
#define CT_FAMILY_IPV6 10
#define VLAN_MAX_DEPTH 4

#define TCP_FLAG_SYN 0x02
#define TCP_FLAG_ACK 0x10
#define TCP_FLAG_RST 0x04

// Shared conntrack flag constants (CT_SYN_PENDING).  Also included by the XDP
// ingress program via bpf/include/common.h — single source of truth for the
// bit encoding used in the tcp_ct4/tcp_ct6 maps.
#include "ct_flags.h"
#include "map_sizes.h"

// Conntrack timeouts and refresh intervals (must match XDP)
#define NS_PER_SEC 1000000000ULL

struct xdp_runtime_cfg {
    __u64 tcp_timeout_ns;
    __u64 udp_timeout_ns;
    __u64 ct_refresh_ns;
    __u64 icmp_token_max;
    __u64 icmp_ns_per_token;
    __u64 udp_global_window_ns;
    __u64 rate_window_ns;
    __u64 syn_timeout_ns;
    __u32 cfg_flags;
    __u32 _pad;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct xdp_runtime_cfg);
} xdp_runtime_cfg SEC(".maps");

static __always_inline struct xdp_runtime_cfg *tc_runtime_cfg(void)
{
    __u32 key = 0;
    return bpf_map_lookup_elem(&xdp_runtime_cfg, &key);
}

static __always_inline __u64 tc_tcp_timeout_ns(void)
{
    struct xdp_runtime_cfg *cfg = tc_runtime_cfg();
    return cfg && cfg->tcp_timeout_ns ? cfg->tcp_timeout_ns : 300ULL * NS_PER_SEC;
}

static __always_inline __u64 tc_refresh_ns(void)
{
    struct xdp_runtime_cfg *cfg = tc_runtime_cfg();
    return cfg && cfg->ct_refresh_ns ? cfg->ct_refresh_ns : 30ULL * NS_PER_SEC;
}

struct flow_key {
    __u8 family;
    __u8 pad[3];
    __be16 sport;
    __be16 dport;
    __u32 saddr[4];
    __u32 daddr[4];
} __attribute__((aligned(8)));

struct ct_key_v4 {
    __be16 sport;
    __be16 dport;
    __be32 saddr;
    __be32 daddr;
};

struct ct_key_v6 {
    __be16 sport;
    __be16 dport;
    __u32 saddr[4];
    __u32 daddr[4];
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, CT_MAP_MAX_ENTRIES_V4);
    __type(key, struct ct_key_v4);
    __type(value, __u64);
} tcp_ct4 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, CT_MAP_MAX_ENTRIES_V6);
    __type(key, struct ct_key_v6);
    __type(value, __u64);
} tcp_ct6 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, CT_MAP_MAX_ENTRIES_V4);
    __type(key, struct ct_key_v4);
    __type(value, __u64);
} udp_ct4 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, CT_MAP_MAX_ENTRIES_V6);
    __type(key, struct ct_key_v6);
    __type(value, __u64);
} udp_ct6 SEC(".maps");

struct sctp_hdr {
    __be16 sport;
    __be16 dport;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, struct flow_key);
    __type(value, __u64);
} sctp_conntrack SEC(".maps");

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

static __always_inline __u8 skip_ipv6_exthdr(
    void **trans_data, void *data_end, __u8 nexthdr)
{
    // Mirror the XDP-side IPv6 extension-header walk so tc egress can record
    // reply state even when the local packet carries IPv6 extension headers.
    #pragma unroll
    for (int i = 0; i < 6; i++) {
        switch (nexthdr) {
        case IPPROTO_HOPOPTS:
        case IPPROTO_ROUTING:
        case IPPROTO_DSTOPTS:
        {
            __u8 *hdr = *trans_data;
            __u32 hdrlen;
            if ((void *)(hdr + 2) > data_end)
                return IPPROTO_NONE;
            nexthdr = hdr[0];
            hdrlen = (((__u32)hdr[1] + 1) * 8);
            *trans_data += hdrlen;
            if (*trans_data > data_end)
                return IPPROTO_NONE;
            break;
        }
        case IPPROTO_FRAGMENT:
        {
            __u8 *hdr = *trans_data;
            __u16 frag_off_flags;
            if ((void *)(hdr + 8) > data_end)
                return IPPROTO_NONE;
            frag_off_flags = ((__u16)hdr[2] << 8) | hdr[3];
            if (frag_off_flags & 0xFFF8)
                return IPV6_FRAG_DROP_SENTINEL;
            nexthdr = hdr[0];
            *trans_data += 8;
            break;
        }
        default:
            return nexthdr;
        }
    }
    return nexthdr;
}

static __always_inline bool strip_vlan_tags(
    __be16 *eth_proto, void **l3_data, void *data_end)
{
    #pragma unroll
    for (int i = 0; i < VLAN_MAX_DEPTH; i++) {
        if (*eth_proto != bpf_htons(ETH_P_8021Q) &&
            *eth_proto != bpf_htons(ETH_P_8021AD))
            return true;
        struct vlan_hdr *vlan = *l3_data;
        if ((void *)(vlan + 1) > data_end)
            return false;
        *eth_proto = vlan->h_vlan_encapsulated_proto;
        *l3_data = (void *)(vlan + 1);
    }
    return true;
}

SEC("classifier")
int tc_egress_track(struct __sk_buff *skb)
{
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;
    struct ethhdr *eth = data;
    struct iphdr *ip;
    struct ipv6hdr *ipv6;
    struct tcphdr *tcp;
    struct udphdr *udp;
    struct sctp_hdr *sctp;
    struct flow_key key;
    __u32 ip_hlen;
    __u64 now;
    __u8 tcp_flags;
    __u8 nexthdr;
    __be16 eth_proto;
    void *l3_data;
    void *trans_data;

    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;

    eth_proto = eth->h_proto;
    l3_data = (void *)(eth + 1);
    if (!strip_vlan_tags(&eth_proto, &l3_data, data_end))
        return TC_ACT_OK;

    if (eth_proto == bpf_htons(ETH_P_IP)) {
        ip = l3_data;
        if ((void *)(ip + 1) > data_end)
            return TC_ACT_OK;

        ip_hlen = ip->ihl * 4;
        if (ip_hlen < sizeof(*ip))
            return TC_ACT_OK;
        if (ip->frag_off & bpf_htons(IP_MF | IP_OFFSET))
            return TC_ACT_OK;

        switch (ip->protocol) {
        case IPPROTO_TCP:
            tcp = (void *)ip + ip_hlen;
            if ((void *)(tcp + 1) > data_end)
                return TC_ACT_OK;

            tcp_flags = ((__u8 *)tcp)[13];
            // Record the reverse tuple so inbound SYN-ACK/ACK packets can match at XDP.
            fill_flow_key_v4(&key, ip->daddr, ip->saddr, tcp->dest, tcp->source);
            now = bpf_ktime_get_ns();

            {
                struct ct_key_v4 map_key;
                fill_ct_key_v4_map(&map_key, &key);
                if ((tcp_flags & TCP_FLAG_SYN) && !(tcp_flags & TCP_FLAG_ACK)) {
                    bpf_map_update_elem(&tcp_ct4, &map_key, &now, BPF_ANY);
                } else {
                    __u64 *last_seen = bpf_map_lookup_elem(&tcp_ct4, &map_key);
                    if (last_seen) {
                        __u64 ts = *last_seen & ~CT_SYN_PENDING;
                        if ((tcp_flags & TCP_FLAG_RST) ||
                            now - ts > tc_tcp_timeout_ns()) {
                            bpf_map_delete_elem(&tcp_ct4, &map_key);
                        } else if (now - ts > tc_refresh_ns()) {
                            __u64 new_val = (*last_seen & CT_SYN_PENDING) | now;
                            bpf_map_update_elem(&tcp_ct4, &map_key, &new_val, BPF_EXIST);
                        }
                    }
                }
            }
            return TC_ACT_OK;
        case IPPROTO_UDP:
            udp = (void *)ip + ip_hlen;
            if ((void *)(udp + 1) > data_end)
                return TC_ACT_OK;

            // Record the reverse tuple so inbound UDP replies can be matched at XDP.
            fill_flow_key_v4(&key, ip->daddr, ip->saddr, udp->dest, udp->source);
            now = bpf_ktime_get_ns();

            {
                struct ct_key_v4 map_key;
                __u64 *last_seen_udp;
                fill_ct_key_v4_map(&map_key, &key);
                last_seen_udp = bpf_map_lookup_elem(&udp_ct4, &map_key);
                if (!last_seen_udp || (now - *last_seen_udp > tc_refresh_ns()))
                    bpf_map_update_elem(&udp_ct4, &map_key, &now, BPF_ANY);
            }
            return TC_ACT_OK;
        case IPPROTO_SCTP:
            sctp = (void *)ip + ip_hlen;
            if ((void *)(sctp + 1) > data_end)
                return TC_ACT_OK;
            fill_flow_key_v4(&key, ip->daddr, ip->saddr, sctp->dport, sctp->sport);
            now = bpf_ktime_get_ns();
            {
                __u64 *last_seen_sctp = bpf_map_lookup_elem(&sctp_conntrack, &key);
                if (!last_seen_sctp || (now - *last_seen_sctp > tc_refresh_ns()))
                    bpf_map_update_elem(&sctp_conntrack, &key, &now, BPF_ANY);
            }
            return TC_ACT_OK;
        default:
            return TC_ACT_OK;
        }
    }

    if (eth_proto != bpf_htons(ETH_P_IPV6))
        return TC_ACT_OK;

    ipv6 = l3_data;
    if ((void *)(ipv6 + 1) > data_end)
        return TC_ACT_OK;

    trans_data = (void *)(ipv6 + 1);
    nexthdr = skip_ipv6_exthdr(&trans_data, data_end, ipv6->nexthdr);
    if (nexthdr == IPPROTO_NONE || nexthdr == IPV6_FRAG_DROP_SENTINEL)
        return TC_ACT_OK;

    switch (nexthdr) {
    case IPPROTO_TCP:
        tcp = trans_data;
        if ((void *)(tcp + 1) > data_end)
            return TC_ACT_OK;

        tcp_flags = ((__u8 *)tcp)[13];
        now = bpf_ktime_get_ns();
        // Record the reverse IPv6 tuple so inbound SYN-ACK/ACK packets can match.
        fill_flow_key_v6(&key, &ipv6->daddr, &ipv6->saddr, tcp->dest, tcp->source);
        {
            struct ct_key_v6 map_key;
            fill_ct_key_v6_map(&map_key, &key);
            if ((tcp_flags & TCP_FLAG_SYN) && !(tcp_flags & TCP_FLAG_ACK)) {
                bpf_map_update_elem(&tcp_ct6, &map_key, &now, BPF_ANY);
            } else {
                __u64 *last_seen = bpf_map_lookup_elem(&tcp_ct6, &map_key);
                if (last_seen) {
                    __u64 ts = *last_seen & ~CT_SYN_PENDING;
                    if ((tcp_flags & TCP_FLAG_RST) ||
                        now - ts > tc_tcp_timeout_ns()) {
                        bpf_map_delete_elem(&tcp_ct6, &map_key);
                    } else if (now - ts > tc_refresh_ns()) {
                        __u64 new_val = (*last_seen & CT_SYN_PENDING) | now;
                        bpf_map_update_elem(&tcp_ct6, &map_key, &new_val, BPF_EXIST);
                    }
                }
            }
        }
        return TC_ACT_OK;
    case IPPROTO_UDP:
        udp = trans_data;
        if ((void *)(udp + 1) > data_end)
            return TC_ACT_OK;

        now = bpf_ktime_get_ns();
        fill_flow_key_v6(&key, &ipv6->daddr, &ipv6->saddr, udp->dest, udp->source);
        {
            struct ct_key_v6 map_key;
            __u64 *last_seen_v6_udp;
            fill_ct_key_v6_map(&map_key, &key);
            last_seen_v6_udp = bpf_map_lookup_elem(&udp_ct6, &map_key);
            if (!last_seen_v6_udp || (now - *last_seen_v6_udp > tc_refresh_ns()))
                bpf_map_update_elem(&udp_ct6, &map_key, &now, BPF_ANY);
        }
        return TC_ACT_OK;
    case IPPROTO_SCTP:
        sctp = trans_data;
        if ((void *)(sctp + 1) > data_end)
            return TC_ACT_OK;
        now = bpf_ktime_get_ns();
        fill_flow_key_v6(&key, &ipv6->daddr, &ipv6->saddr, sctp->dport, sctp->sport);
        {
            __u64 *last_seen_sctp6 = bpf_map_lookup_elem(&sctp_conntrack, &key);
            if (!last_seen_sctp6 || (now - *last_seen_sctp6 > tc_refresh_ns()))
                bpf_map_update_elem(&sctp_conntrack, &key, &now, BPF_ANY);
        }
        return TC_ACT_OK;
    default:
        return TC_ACT_OK;
    }
}

char _license[] SEC("license") = "GPL";
