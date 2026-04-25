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

#ifndef IP_MF
#define IP_MF     0x2000
#endif
#ifndef IP_OFFSET
#define IP_OFFSET 0x1FFF
#endif

#define IPV6_FRAG_DROP_SENTINEL 0xFF
#define CT_FAMILY_IPV4 2
#define CT_FAMILY_IPV6 10

// Conntrack timeouts and refresh intervals (must match XDP)
#define TCP_TIMEOUT_NS       (300ULL * 1000000000ULL)
#define UDP_TIMEOUT_NS       (60ULL  * 1000000000ULL)
#define SCTP_TIMEOUT_NS      (300ULL * 1000000000ULL)
#define CT_REFRESH_INTERVAL  (30ULL  * 1000000000ULL)

struct ct_key {
    __u8 family;
    __u8 pad[3];
    __be16 sport;
    __be16 dport;
    __u32 saddr[4];
    __u32 daddr[4];
} __attribute__((aligned(8)));

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 262144);
    __type(key, struct ct_key);
    __type(value, __u64);
} tcp_conntrack SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 262144);
    __type(key, struct ct_key);
    __type(value, __u64);
} udp_conntrack SEC(".maps");

struct sctp_hdr {
    __be16 sport;
    __be16 dport;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, struct ct_key);
    __type(value, __u64);
} sctp_conntrack SEC(".maps");

static __always_inline void fill_ct_key_v4(
    struct ct_key *key, __be32 saddr, __be32 daddr,
    __be16 sport, __be16 dport)
{
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
    struct ct_key key;
    __u32 ip_hlen;
    __u64 now;
    __u8 tcp_flags;
    __u8 nexthdr;
    void *trans_data;

    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;
    if (eth->h_proto == bpf_htons(ETH_P_IP)) {
        ip = (void *)(eth + 1);
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
            fill_ct_key_v4(&key, ip->daddr, ip->saddr, tcp->dest, tcp->source);
            now = bpf_ktime_get_ns();

            if ((tcp_flags & 0x02) && !(tcp_flags & 0x10)) { // SYN & ECN
                bpf_map_update_elem(&tcp_conntrack, &key, &now, BPF_ANY);
            } else {
                __u64 *last_seen = bpf_map_lookup_elem(&tcp_conntrack, &key);
                if (last_seen) {
                    if (now - *last_seen > TCP_TIMEOUT_NS) {
                        bpf_map_delete_elem(&tcp_conntrack, &key);
                    } else if (now - *last_seen > CT_REFRESH_INTERVAL) {
                        bpf_map_update_elem(&tcp_conntrack, &key, &now, BPF_EXIST);
                    }
                }
            }
            return TC_ACT_OK;
        case IPPROTO_UDP:
            udp = (void *)ip + ip_hlen;
            if ((void *)(udp + 1) > data_end)
                return TC_ACT_OK;

            // Record the reverse tuple so inbound UDP replies can be matched at XDP.
            fill_ct_key_v4(&key, ip->daddr, ip->saddr, udp->dest, udp->source);
            now = bpf_ktime_get_ns();

            __u64 *last_seen_udp = bpf_map_lookup_elem(&udp_conntrack, &key);
            if (!last_seen_udp) {
                bpf_map_update_elem(&udp_conntrack, &key, &now, BPF_ANY);
            } else {
                if (now - *last_seen_udp > UDP_TIMEOUT_NS) {
                    bpf_map_delete_elem(&udp_conntrack, &key);
                } else if (now - *last_seen_udp > CT_REFRESH_INTERVAL) {
                    bpf_map_update_elem(&udp_conntrack, &key, &now, BPF_EXIST);
                }
            }
            return TC_ACT_OK;
        case IPPROTO_SCTP:
            sctp = (void *)ip + ip_hlen;
            if ((void *)(sctp + 1) > data_end)
                return TC_ACT_OK;
            fill_ct_key_v4(&key, ip->daddr, ip->saddr, sctp->dport, sctp->sport);
            now = bpf_ktime_get_ns();
            {
                __u64 *last_seen_sctp = bpf_map_lookup_elem(&sctp_conntrack, &key);
                if (!last_seen_sctp) {
                    bpf_map_update_elem(&sctp_conntrack, &key, &now, BPF_ANY);
                } else if (now - *last_seen_sctp > SCTP_TIMEOUT_NS) {
                    bpf_map_delete_elem(&sctp_conntrack, &key);
                } else if (now - *last_seen_sctp > CT_REFRESH_INTERVAL) {
                    bpf_map_update_elem(&sctp_conntrack, &key, &now, BPF_EXIST);
                }
            }
            return TC_ACT_OK;
        default:
            return TC_ACT_OK;
        }
    }

    if (eth->h_proto != bpf_htons(ETH_P_IPV6))
        return TC_ACT_OK;

    ipv6 = (void *)(eth + 1);
    if ((void *)(ipv6 + 1) > data_end)
        return TC_ACT_OK;

    trans_data = (void *)(ipv6 + 1);
    nexthdr = skip_ipv6_exthdr(&trans_data, data_end, ipv6->nexthdr);
    if (nexthdr == IPPROTO_NONE || nexthdr == IPV6_FRAG_DROP_SENTINEL)
        return TC_ACT_OK;

    now = bpf_ktime_get_ns();
    switch (nexthdr) {
    case IPPROTO_TCP:
        tcp = trans_data;
        if ((void *)(tcp + 1) > data_end)
            return TC_ACT_OK;

        tcp_flags = ((__u8 *)tcp)[13];
        // Record the reverse IPv6 tuple so inbound SYN-ACK/ACK packets can match.
        fill_ct_key_v6(&key, &ipv6->daddr, &ipv6->saddr, tcp->dest, tcp->source);
        if ((tcp_flags & 0x02) && !(tcp_flags & 0x10)) { // SYN & ECN
            bpf_map_update_elem(&tcp_conntrack, &key, &now, BPF_ANY);
        } else {
            __u64 *last_seen = bpf_map_lookup_elem(&tcp_conntrack, &key);
            if (last_seen) {
                if (now - *last_seen > TCP_TIMEOUT_NS) {
                    bpf_map_delete_elem(&tcp_conntrack, &key);
                } else if (now - *last_seen > CT_REFRESH_INTERVAL) {
                    bpf_map_update_elem(&tcp_conntrack, &key, &now, BPF_EXIST);
                }
            }
        }
        return TC_ACT_OK;
    case IPPROTO_UDP:
        udp = trans_data;
        if ((void *)(udp + 1) > data_end)
            return TC_ACT_OK;

        fill_ct_key_v6(&key, &ipv6->daddr, &ipv6->saddr, udp->dest, udp->source);
        __u64 *last_seen_v6_udp = bpf_map_lookup_elem(&udp_conntrack, &key);
        if (!last_seen_v6_udp) {
            bpf_map_update_elem(&udp_conntrack, &key, &now, BPF_ANY);
        } else {
            if (now - *last_seen_v6_udp > UDP_TIMEOUT_NS) {
                bpf_map_delete_elem(&udp_conntrack, &key);
            } else if (now - *last_seen_v6_udp > CT_REFRESH_INTERVAL) {
                bpf_map_update_elem(&udp_conntrack, &key, &now, BPF_EXIST);
            }
        }
        return TC_ACT_OK;
    case IPPROTO_SCTP:
        sctp = trans_data;
        if ((void *)(sctp + 1) > data_end)
            return TC_ACT_OK;
        fill_ct_key_v6(&key, &ipv6->daddr, &ipv6->saddr, sctp->dport, sctp->sport);
        {
            __u64 *last_seen_sctp6 = bpf_map_lookup_elem(&sctp_conntrack, &key);
            if (!last_seen_sctp6) {
                bpf_map_update_elem(&sctp_conntrack, &key, &now, BPF_ANY);
            } else if (now - *last_seen_sctp6 > SCTP_TIMEOUT_NS) {
                bpf_map_delete_elem(&sctp_conntrack, &key);
            } else if (now - *last_seen_sctp6 > CT_REFRESH_INTERVAL) {
                bpf_map_update_elem(&sctp_conntrack, &key, &now, BPF_EXIST);
            }
        }
        return TC_ACT_OK;
    default:
        return TC_ACT_OK;
    }
}

char _license[] SEC("license") = "GPL";
