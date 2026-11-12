/* SPDX-License-Identifier: GPL-2.0 */
#pragma once
#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include "../bpf/include/flow_keys.h"

/* Packet-local ABI for a direct TC dispatcher -> handler tail call. This is
 * scratch space, never connection state and never shared with the XDP scratch
 * slot. Both entries in a handler object share their own protocol maps. */
#define TC_HANDLER_ABI_VERSION 1U
#define HANDLER_ROUTE_PROFILE 1U
#define HANDLER_ROUTE_TCP 2U
#define HANDLER_ROUTE_UDP 3U
#define HANDLER_ROUTE_PROTO 4U
#define HANDLER_CT_UNAVAILABLE 255U

struct tc_handler_ctx {
    __u32 abi_version;
    __u32 kind;
    __u32 target;
    __u32 ingress_ifindex;
    /* Service kinds: original client -> service. PROTO: outgoing wire tuple. */
    struct flow_key flow;
    __u64 policy_generation;
    __u64 profile_generation;
    __u32 payload_offset;
    __u32 payload_len; /* IP-declared length, excluding Ethernet padding */
    __u32 l4_offset;
    __u32 packet_len;
    __u32 ct_status;
    __u8 ct_direction;
    __u8 ct_state;
    __u8 tcp_flags;
    __u8 ip_proto;
};

_Static_assert(sizeof(struct tc_handler_ctx) == 96, "TC handler context ABI");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct tc_handler_ctx);
} tc_handler_ctx SEC(".maps");

static __always_inline struct tc_handler_ctx *get_tc_handler_ctx(struct __sk_buff *skb)
{
    __u32 zero = 0;
    struct tc_handler_ctx *ctx = bpf_map_lookup_elem(&tc_handler_ctx, &zero);
    if (!ctx || ctx->abi_version != TC_HANDLER_ABI_VERSION ||
        ctx->packet_len != skb->len || ctx->payload_offset > skb->len ||
        ctx->payload_len > skb->len - ctx->payload_offset)
        return 0;
    return ctx;
}

/* Observation does not terminate another owner's TC filter chain. */
static __always_inline int tc_handler_continue(void)
{
    return TC_ACT_UNSPEC;
}
