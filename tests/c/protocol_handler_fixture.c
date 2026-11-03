/* Protocol module fixture: persistent shared state and exact TC wire context. */
#include "xdp_slot_ctx.h"
#include "tc_handler_ctx.h"
#include "handler_state.h"
#ifndef RAW_SCHEMA
#define RAW_SCHEMA "protocol-fixture-v1"
#endif
AXDP_STATE_SCHEMA(RAW_SCHEMA, "[\"proto_metrics\"]");
struct metrics {
    struct tc_handler_ctx last;
    __u64 ingress;
    __u64 egress;
};
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct metrics);
} proto_metrics SEC(".maps");
SEC("xdp")
int protocol_ingress(struct xdp_md *packet)
{
    __u32 zero = 0;
    struct metrics *m = bpf_map_lookup_elem(&proto_metrics, &zero);
    if (m && get_slot_ctx(packet))
        __sync_fetch_and_add(&m->ingress, 1);
    return XDP_PASS;
}
SEC("tc")
int protocol_egress(struct __sk_buff *packet)
{
    __u32 zero = 0;
    struct metrics *m = bpf_map_lookup_elem(&proto_metrics, &zero);
    struct tc_handler_ctx *ctx = get_tc_handler_ctx(packet);
    if (m && ctx) {
        m->last = *ctx;
        __sync_fetch_and_add(&m->egress, 1);
    }
    return tc_handler_continue();
}
char LICENSE[] SEC("license") = "GPL";
