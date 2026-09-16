// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/pkt_cls.h>
#include <linux/tcp.h>
#include <stdbool.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include "include/linux_conntrack.h"
#include "include/minecraft.h"

#define MC_SERVER_FRAME_MAX 8192U
#define MC_SERVER_VARINT_MAX 5
#define MC_SERVER_PACKET_LEN_MAX 3
#define VLAN_MAX_DEPTH 4
#define IPV6_PARSE_FAILED 0xff
#define IPV4_FRAGMENT_MASK 0x3fff

struct vlan_hdr_local {
    __be16 tci;
    __be16 proto;
};

struct tcp_endpoint_policy {
    __u32 allow;
    __u32 profile_id;
    __u64 policy_generation;
    __u64 profile_generation;
};

struct zone_port_key {
    __u32 ifindex;
    __u32 port;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 65536);
    __type(key, __u32);
    __type(value, struct tcp_endpoint_policy);
} tcp_whitelist SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, struct zone_port_key);
    __type(value, struct tcp_endpoint_policy);
} tcp_zone_whitelist SEC(".maps");

struct tc_mc_varint {
    __s32 value;
    __u8 bytes;
};

static __always_inline struct tc_mc_varint tc_varint(
    __u8 *ptr, const __u8 *end, __u8 max_bytes, const void *data_end)
{
    __s32 value = 0;
#define TC_MC_BYTE(index, shift)                                      \
    do {                                                              \
        if ((index) > max_bytes || ptr >= end)                        \
            return (struct tc_mc_varint){};                           \
        barrier_var(ptr);                                             \
        __u8 *next = ptr + 1;                                         \
        if ((const void *)next > data_end)                            \
            return (struct tc_mc_varint){};                           \
        __u8 byte = *(next - 1);                                      \
        ptr = next;                                                    \
        value |= ((__s32)(byte & 0x7f) << (shift));                  \
        if (!(byte & 0x80))                                           \
            return (struct tc_mc_varint){ .value = value, .bytes = index }; \
    } while (0)
    TC_MC_BYTE(1, 0);
    TC_MC_BYTE(2, 7);
    TC_MC_BYTE(3, 14);
    TC_MC_BYTE(4, 21);
    TC_MC_BYTE(5, 28);
#undef TC_MC_BYTE
    return (struct tc_mc_varint){};
}

static __always_inline bool tc_strip_vlan(
    __be16 *proto, void **cursor, void *data_end)
{
#pragma unroll
    for (int i = 0; i < VLAN_MAX_DEPTH; i++) {
        if (*proto != bpf_htons(ETH_P_8021Q) && *proto != bpf_htons(ETH_P_8021AD))
            return true;
        struct vlan_hdr_local *vlan = *cursor;
        if ((void *)(vlan + 1) > data_end)
            return false;
        *proto = vlan->proto;
        *cursor = vlan + 1;
    }
    return *proto != bpf_htons(ETH_P_8021Q) && *proto != bpf_htons(ETH_P_8021AD);
}

static __always_inline __u8 tc_skip_ipv6(void **cursor, void *data_end, __u8 next)
{
#pragma unroll
    for (int i = 0; i < 6; i++) {
        if (next == IPPROTO_HOPOPTS || next == IPPROTO_ROUTING || next == IPPROTO_DSTOPTS) {
            __u8 *header = *cursor;
            if ((void *)(header + 2) > data_end)
                return IPV6_PARSE_FAILED;
            next = header[0];
            *cursor += ((__u32)header[1] + 1U) * 8U;
            if (*cursor > data_end)
                return IPV6_PARSE_FAILED;
            continue;
        }
        if (next == IPPROTO_FRAGMENT)
            return IPV6_PARSE_FAILED;
        return next;
    }
    return IPV6_PARSE_FAILED;
}

static __always_inline struct tcp_endpoint_policy *mc_service_policy(
    struct __sk_buff *skb, __u32 port)
{
    struct tcp_endpoint_policy *policy = bpf_map_lookup_elem(&tcp_whitelist, &port);
    if (policy && policy->allow && policy->profile_id == MC_PROFILE_ID)
        return policy;
    struct zone_port_key zone_key = { .ifindex = skb->ifindex, .port = port };
    policy = bpf_map_lookup_elem(&tcp_zone_whitelist, &zone_key);
    return policy && policy->allow && policy->profile_id == MC_PROFILE_ID ? policy : NULL;
}

static __always_inline int inspect_server_frame(
    __u8 *payload, const __u8 *payload_end, const void *data_end,
    struct mc_l7_pending_val *pending)
{
    struct tc_mc_varint value = tc_varint(
        payload, payload_end, MC_SERVER_PACKET_LEN_MAX, data_end);
    __u8 *cursor;
    const __u8 *frame_end;
    __u32 frame_len;

    if (!value.bytes || value.value < 1)
        return -1;
    payload += value.bytes;
    frame_len = (__u32)value.value;
    barrier_var(frame_len);
    if (frame_len > MC_SERVER_FRAME_MAX)
        return -1;
    frame_end = payload + frame_len;
    if (frame_end > payload_end || (const void *)frame_end > data_end)
        return -1;
    cursor = payload;

    if (pending->flags & MC_F_COMPRESSION_ENABLED) {
        value = tc_varint(cursor, frame_end, MC_SERVER_VARINT_MAX, data_end);
        if (!value.bytes)
            return -1;
        cursor += value.bytes;
        if (value.value != 0)
            return -1; /* zlib-compressed body is intentionally opaque to BPF */
    }
    value = tc_varint(cursor, frame_end, MC_SERVER_VARINT_MAX, data_end);
    if (!value.bytes)
        return -1;
    return value.value;
}

SEC("classifier/minecraft_egress")
int tc_minecraft_egress(struct __sk_buff *skb)
{
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    struct ethhdr *eth = data;
    struct tcp_endpoint_policy *policy;
    struct mc_l7_pending_val *pending;
    struct linux_ct_snapshot snapshot;
    struct bpf_ct_opts___local opts;
    struct bpf_sock_tuple tuple;
    struct flow_key key = {};
    struct flow_key wire_key = {};
    struct nf_conn *ct;
    struct tcphdr *tcp;
    __be16 eth_proto;
    void *l3, *transport;
    __u32 tcp_len, payload_len, source_port;
    __u8 *payload;
    int packet_id;
    __u64 now;

    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;
    eth_proto = eth->h_proto;
    l3 = eth + 1;
    if (!tc_strip_vlan(&eth_proto, &l3, data_end))
        return TC_ACT_OK;

    if (eth_proto == bpf_htons(ETH_P_IP)) {
        struct iphdr *ip = l3;
        if ((void *)(ip + 1) > data_end || ip->ihl < 5 || ip->protocol != IPPROTO_TCP)
            return TC_ACT_OK;
        if (ip->frag_off & bpf_htons(IPV4_FRAGMENT_MASK))
            return TC_ACT_OK;
        transport = (void *)ip + (__u32)ip->ihl * 4U;
        if (transport > data_end)
            return TC_ACT_OK;
        key.family = CT_FAMILY_IPV4;
        key.saddr[0] = ip->daddr;
        key.daddr[0] = ip->saddr;
    } else if (eth_proto == bpf_htons(ETH_P_IPV6)) {
        struct ipv6hdr *ip6 = l3;
        if ((void *)(ip6 + 1) > data_end)
            return TC_ACT_OK;
        transport = ip6 + 1;
        if (tc_skip_ipv6(&transport, data_end, ip6->nexthdr) != IPPROTO_TCP)
            return TC_ACT_OK;
        key.family = CT_FAMILY_IPV6;
        __builtin_memcpy(key.saddr, &ip6->daddr, sizeof(key.saddr));
        __builtin_memcpy(key.daddr, &ip6->saddr, sizeof(key.daddr));
    } else {
        return TC_ACT_OK;
    }

    tcp = transport;
    if ((void *)(tcp + 1) > data_end || tcp->doff < 5)
        return TC_ACT_OK;
    tcp_len = (__u32)tcp->doff * 4U;
    if ((void *)tcp + tcp_len > data_end)
        return TC_ACT_OK;
    key.sport = tcp->dest;
    key.dport = tcp->source;
    source_port = (__u32)bpf_ntohs(tcp->source);
    policy = mc_service_policy(skb, source_port);
    if (!policy)
        return TC_ACT_OK;
    pending = bpf_map_lookup_elem(&mc_l7_pending, &key);
    if (!pending || pending->policy_generation != policy->policy_generation ||
        pending->profile_generation != policy->profile_generation)
        return TC_ACT_OK;

    payload = (void *)tcp + tcp_len;
    payload_len = (__u32)((__u8 *)data_end - payload);
    if (!payload_len || pending->egress_bytes >= MC_PREVERIFY_BYTES ||
        payload_len > MC_PREVERIFY_BYTES - pending->egress_bytes)
        return TC_ACT_OK;

    wire_key.family = key.family;
    wire_key.sport = key.dport;
    wire_key.dport = key.sport;
    __builtin_memcpy(wire_key.saddr, key.daddr, sizeof(wire_key.saddr));
    __builtin_memcpy(wire_key.daddr, key.saddr, sizeof(wire_key.daddr));
    linux_ct_fill_tuple(&tuple, &wire_key);
    opts = linux_ct_opts();
    ct = bpf_skb_ct_lookup(skb, &tuple, linux_ct_tuple_size(&wire_key), &opts, sizeof(opts));
    if (!ct)
        return TC_ACT_OK;
    linux_ct_snapshot(ct, opts.dir, &snapshot);
    if (snapshot.dir != NF_CT_DIR_REPLY || !linux_ct_established(&snapshot)) {
        bpf_ct_release(ct);
        return TC_ACT_OK;
    }

    now = bpf_ktime_get_ns();
    if (now >= pending->hard_deadline_ns) {
        bpf_ct_release(ct);
        bpf_map_delete_elem(&mc_l7_pending, &key);
        return TC_ACT_OK;
    }
    pending->egress_bytes += payload_len;

    if (pending->state == MC_L7_ENCRYPTED_PROBATION) {
        pending->flags |= MC_F_SERVER_AFTER_CHALLENGE;
        pending->proof_level = MC_PROOF_CHALLENGE_DIALOGUE;
        bpf_ct_release(ct);
        return TC_ACT_OK;
    }

    packet_id = inspect_server_frame(payload, data_end, data_end, pending);
    if (packet_id == 0 && pending->intention != 1) {
        bpf_ct_release(ct);
        bpf_map_delete_elem(&mc_l7_pending, &key);
        return TC_ACT_OK;
    }
    if (packet_id == 1 && pending->intention != 1) {
        pending->state = MC_L7_SERVER_CHALLENGE;
        pending->proof_level = MC_PROOF_SERVER_PROGRESS;
        pending->hard_deadline_ns = pending->first_seen_ns + MC_CHALLENGE_DEADLINE_NS;
    } else if (packet_id == 2 && pending->intention != 1) {
        mc_mark_conn(ct, policy->profile_generation, MC_PROOF_WIRE_VERIFIED);
        bpf_ct_release(ct);
        bpf_map_delete_elem(&mc_l7_pending, &key);
        return TC_ACT_OK;
    } else if (packet_id == 3 && pending->intention != 1) {
        pending->flags |= MC_F_COMPRESSION_ENABLED;
        pending->proof_level = MC_PROOF_SERVER_PROGRESS;
    }
    bpf_ct_release(ct);
    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
