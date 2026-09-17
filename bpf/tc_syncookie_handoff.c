#ifdef AUTO_XDP_VMLINUX_H
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#ifndef TC_ACT_OK
#define TC_ACT_OK 0
#endif
#define ETH_P_IP 0x0800
#define ETH_P_IPV6 0x86dd
#define ETH_P_8021Q 0x8100
#define ETH_P_8021AD 0x88a8
#define IPPROTO_HOPOPTS 0
#define IPPROTO_ROUTING 43
#define IPPROTO_FRAGMENT 44
#define IPPROTO_NONE 59
#define IPPROTO_DSTOPTS 60

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
    __uint(max_entries, 65536);
    __type(key, struct ct_key_v4);
    __type(value, struct bpf_tcp_req_attrs);
} sync_handoff4 SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, struct ct_key_v6);
    __type(value, struct bpf_tcp_req_attrs);
} sync_handoff6 SEC(".maps");

static __always_inline __u8 skip_ipv6_exthdr(void **p, void *end,
                                              __u8 nexthdr)
{
#pragma unroll
    for (int i = 0; i < 6; i++) {
        if (nexthdr == IPPROTO_HOPOPTS || nexthdr == IPPROTO_ROUTING ||
            nexthdr == IPPROTO_DSTOPTS) {
            __u8 *hdr = *p;
            if ((void *)(hdr + 2) > end)
                return IPPROTO_NONE;
            nexthdr = hdr[0];
            *p += ((__u32)hdr[1] + 1) * 8;
            if (*p > end)
                return IPPROTO_NONE;
        } else if (nexthdr == IPPROTO_FRAGMENT) {
            __u8 *hdr = *p;
            if ((void *)(hdr + 8) > end)
                return IPPROTO_NONE;
            if ((((__u16)hdr[2] << 8) | hdr[3]) & 0xfff8)
                return 0xff;
            nexthdr = hdr[0];
            *p += 8;
        } else {
            return nexthdr;
        }
    }
    return IPPROTO_NONE;
}

#else
#include "common.h"
#include "keys.h"
#include "parse.h"
#include <linux/pkt_cls.h>
#include "syncookie_maps.h"
#endif

#ifndef BPF_TCP_LISTEN
#define BPF_TCP_LISTEN 10
#endif

#ifndef AUTO_XDP_VMLINUX_H
struct sock;
struct tcp_sock;
#endif

/* Linux 6.11+: this declaration is intentionally isolated in the optional
 * object. Older kernels reject the object at load time, leaving main TC alive. */
extern int bpf_sk_assign_tcp_reqsk(struct __sk_buff *skb, struct sock *sk,
                                   struct bpf_tcp_req_attrs *attrs,
                                   int attrs__sz) __ksym;

static __always_inline int handoff_v4(struct __sk_buff *skb,
                                      struct iphdr *ip, struct tcphdr *tcp,
                                      void *data_end)
{
    struct ct_key_v4 key = {
        .sport = tcp->source, .dport = tcp->dest,
        .saddr = ip->saddr, .daddr = ip->daddr,
    };
    struct bpf_tcp_req_attrs *attrs =
        bpf_map_lookup_elem(&sync_handoff4, &key);
    if (!attrs || bpf_tcp_raw_check_syncookie_ipv4(ip, tcp))
        return TC_ACT_OK;

    struct bpf_sock_tuple tuple = {};
    tuple.ipv4.saddr = ip->saddr;
    tuple.ipv4.daddr = ip->daddr;
    tuple.ipv4.sport = tcp->source;
    tuple.ipv4.dport = tcp->dest;
    struct bpf_sock *skc = bpf_skc_lookup_tcp(
        skb, &tuple, sizeof(tuple.ipv4), BPF_F_CURRENT_NETNS, 0);
    if (!skc || skc->state != BPF_TCP_LISTEN) {
        if (skc)
            bpf_sk_release(skc);
        return TC_ACT_OK;
    }
    struct tcp_sock *tcp_sk = bpf_skc_to_tcp_sock(skc);
    if (!tcp_sk) {
        bpf_sk_release(skc);
        return TC_ACT_OK;
    }
    int ret = bpf_sk_assign_tcp_reqsk(
        skb, (struct sock *)tcp_sk, attrs, sizeof(*attrs));
    bpf_sk_release(skc);
    if (!ret)
        bpf_map_delete_elem(&sync_handoff4, &key);
    return TC_ACT_OK;
}

static __always_inline int handoff_v6(struct __sk_buff *skb,
                                      struct ipv6hdr *ip, struct tcphdr *tcp,
                                      void *data_end)
{
    struct ct_key_v6 key = {
        .sport = tcp->source, .dport = tcp->dest,
    };
    __builtin_memcpy(key.saddr, &ip->saddr, sizeof(key.saddr));
    __builtin_memcpy(key.daddr, &ip->daddr, sizeof(key.daddr));
    struct bpf_tcp_req_attrs *attrs =
        bpf_map_lookup_elem(&sync_handoff6, &key);
    if (!attrs || bpf_tcp_raw_check_syncookie_ipv6(ip, tcp))
        return TC_ACT_OK;

    struct bpf_sock_tuple tuple = {};
    __builtin_memcpy(tuple.ipv6.saddr, &ip->saddr, sizeof(tuple.ipv6.saddr));
    __builtin_memcpy(tuple.ipv6.daddr, &ip->daddr, sizeof(tuple.ipv6.daddr));
    tuple.ipv6.sport = tcp->source;
    tuple.ipv6.dport = tcp->dest;
    struct bpf_sock *skc = bpf_skc_lookup_tcp(
        skb, &tuple, sizeof(tuple.ipv6), BPF_F_CURRENT_NETNS, 0);
    if (!skc || skc->state != BPF_TCP_LISTEN) {
        if (skc)
            bpf_sk_release(skc);
        return TC_ACT_OK;
    }
    struct tcp_sock *tcp_sk = bpf_skc_to_tcp_sock(skc);
    if (!tcp_sk) {
        bpf_sk_release(skc);
        return TC_ACT_OK;
    }
    int ret = bpf_sk_assign_tcp_reqsk(
        skb, (struct sock *)tcp_sk, attrs, sizeof(*attrs));
    bpf_sk_release(skc);
    if (!ret)
        bpf_map_delete_elem(&sync_handoff6, &key);
    return TC_ACT_OK;
}

SEC("classifier")
int tc_syncookie_handoff(struct __sk_buff *skb)
{
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;
    __be16 proto = eth->h_proto;
    void *l3 = (void *)(eth + 1);
#pragma unroll
    for (int i = 0; i < 4; i++) {
        if (proto != bpf_htons(ETH_P_8021Q) &&
            proto != bpf_htons(ETH_P_8021AD))
            break;
        struct vlan_hdr *vlan = l3;
        if ((void *)(vlan + 1) > data_end)
            return TC_ACT_OK;
        proto = vlan->h_vlan_encapsulated_proto;
        l3 = (void *)(vlan + 1);
    }
    if (proto == bpf_htons(ETH_P_IP)) {
        struct iphdr *ip = l3;
        if ((void *)(ip + 1) > data_end || ip->ihl < 5)
            return TC_ACT_OK;
        struct tcphdr *tcp = (void *)ip + ip->ihl * 4;
        if ((void *)(tcp + 1) > data_end || ip->protocol != IPPROTO_TCP ||
            !tcp->ack || tcp->syn || tcp->rst || tcp->fin)
            return TC_ACT_OK;
        return handoff_v4(skb, ip, tcp, data_end);
    }
    if (proto == bpf_htons(ETH_P_IPV6)) {
        struct ipv6hdr *ip = l3;
        if ((void *)(ip + 1) > data_end)
            return TC_ACT_OK;
        void *tcp_data = (void *)(ip + 1);
        __u8 nexthdr = skip_ipv6_exthdr(&tcp_data, data_end, ip->nexthdr);
        if (nexthdr != IPPROTO_TCP)
            return TC_ACT_OK;
        struct tcphdr *tcp = tcp_data;
        if ((void *)(tcp + 1) > data_end || !tcp->ack || tcp->syn ||
            tcp->rst || tcp->fin)
            return TC_ACT_OK;
        return handoff_v6(skb, ip, tcp, data_end);
    }
    return TC_ACT_OK;
}

char LICENSE[] SEC("license") = "GPL";
