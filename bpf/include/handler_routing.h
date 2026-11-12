/* SPDX-License-Identifier: GPL-2.0 */
#pragma once
#include "../../handlers/tc_handler_ctx.h"

struct handler_route_key {
    __u32 kind;
    __u32 target;
};

struct handler_flow_key {
    struct flow_key flow;
    __u32 proto;
    __u32 _pad;
};

struct handler_flow_route {
    __u64 policy_generation;
    __u64 profile_generation;
    __u32 ingress_ifindex;
    __u32 kind;
    __u32 target;
    __u32 _pad;
};

/* Presence means that a complete, loaded handler has an egress entry. */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, struct handler_route_key);
    __type(value, __u32);
} handler_egress SEC(".maps");

/* This cache records only service ownership selected at ingress. It grants
 * no admission and does not create, age or emulate Linux conntrack entries.
 * Egress requires a matching live Linux connection and current policy. The
 * maps and their interfaces must belong to the same network namespace. */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, struct handler_flow_key);
    __type(value, struct handler_flow_route);
} handler_flows SEC(".maps");

#define TC_HANDLER_TABLE(name, capacity)                  \
    struct {                                            \
        __uint(type, BPF_MAP_TYPE_PROG_ARRAY);           \
        __uint(max_entries, capacity);                  \
        __type(key, __u32);                             \
        __type(value, __u32);                           \
    } name SEC(".maps")

TC_HANDLER_TABLE(tc_profile_handlers, 256);
TC_HANDLER_TABLE(tc_tcp_handlers, 65536);
TC_HANDLER_TABLE(tc_udp_handlers, 65536);
TC_HANDLER_TABLE(tc_proto_handlers, 256);
#undef TC_HANDLER_TABLE

enum handler_egress_stat {
    HANDLER_EGRESS_PARSE_MISS,
    HANDLER_EGRESS_ROUTE_MISS,
    HANDLER_EGRESS_POLICY_MISS,
    HANDLER_EGRESS_CT_MISS,
    HANDLER_EGRESS_DISPATCH,
    HANDLER_EGRESS_TAILCALL_MISS,
    HANDLER_EGRESS_STAT_MAX,
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, HANDLER_EGRESS_STAT_MAX);
    __type(key, __u32);
    __type(value, __u64);
} handler_eg_stats SEC(".maps");

static __always_inline void remember_handler_route(
    struct xdp_md *ctx, const struct flow_key *flow, __u32 proto,
    __u32 kind, __u32 target, __u64 policy_generation, __u64 profile_generation)
{
    struct handler_route_key route_key = { .kind = kind, .target = target };
    __u32 *enabled = bpf_map_lookup_elem(&handler_egress, &route_key);
    if (!enabled || !*enabled)
        return;
    struct handler_flow_key key = { .proto = proto };
    __builtin_memcpy(&key.flow, flow, sizeof(*flow));
    struct handler_flow_route *old = bpf_map_lookup_elem(&handler_flows, &key);
    if (old && old->ingress_ifindex == ctx->ingress_ifindex &&
        old->kind == kind && old->target == target &&
        old->policy_generation == policy_generation &&
        old->profile_generation == profile_generation)
        return;
    struct handler_flow_route route = {
        .policy_generation = policy_generation,
        .profile_generation = profile_generation,
        .ingress_ifindex = ctx->ingress_ifindex,
        .kind = kind,
        .target = target,
    };
    bpf_map_update_elem(&handler_flows, &key, &route, BPF_ANY);
}
