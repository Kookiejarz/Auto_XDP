/* Test plugin: the two entries must see the same private map instance. */
#include "xdp_slot_ctx.h"
#include "tc_handler_ctx.h"
#include "handler_state.h"

struct metrics {
    __u64 ingress;
    __u64 egress;
    __u64 shared;
    __u32 kind;
    __u32 target;
    __u32 ifindex;
    __u32 family;
    __u32 proto;
    __u32 pad;
};
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct metrics);
} private_metrics SEC(".maps");

#ifndef CHAIN_ONLY
#ifndef METRIC_STEP
#define METRIC_STEP 1
#endif
AXDP_STATE_SCHEMA("dual-fixture-v1", "[\"private_metrics\"]");
SEC("xdp")
int test_ingress(struct xdp_md *ctx)
{
    __u32 zero = 0;
    struct metrics *m = bpf_map_lookup_elem(&private_metrics, &zero);
    if (m && get_slot_ctx(ctx))
        __sync_fetch_and_add(&m->ingress, METRIC_STEP);
    return XDP_PASS;
}

SEC("tc")
int test_egress(struct __sk_buff *skb)
{
    struct tc_handler_ctx *ctx = get_tc_handler_ctx(skb);
    __u32 zero = 0;
    struct metrics *m = bpf_map_lookup_elem(&private_metrics, &zero);
    if (m && ctx && ctx->payload_len) {
        __sync_fetch_and_add(&m->egress, 1);
        if (m->ingress)
            __sync_fetch_and_add(&m->shared, 1);
        m->kind = ctx->kind;
        m->target = ctx->target;
        m->ifindex = ctx->ingress_ifindex;
        m->family = ctx->flow.family;
        m->proto = ctx->ip_proto;
    }
    return tc_handler_continue();
}
#else
SEC("tc")
int test_chain(struct __sk_buff *skb)
{
    __u32 zero = 0;
    struct metrics *m = bpf_map_lookup_elem(&private_metrics, &zero);
    if (m && skb->len)
        __sync_fetch_and_add(&m->egress, 1);
    return tc_handler_continue();
}
#endif
char LICENSE[] SEC("license") = "GPL";
