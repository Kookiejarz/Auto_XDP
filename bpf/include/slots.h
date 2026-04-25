#pragma once
#include "maps.h"
/* struct xdp_slot_ctx and slot_ctx_map arrive via:
 * maps.h -> keys.h -> common.h -> handlers/xdp_slot_ctx.h */

// Write parsed context into XDP metadata (native mode) or slot_ctx_map
// (generic/skb fallback), then tail-call the registered handler.
// If no handler is loaded for ip_proto, bpf_tail_call() returns and we
// apply slot_def_action.  Called only from the main program's default
// branches, after all extension headers have been traversed.
static __always_inline int dispatch_to_slot(
    struct xdp_md *ctx, __u8 family, __u8 ip_proto,
    __u16 l3_offset, __u16 inner_offset,
    __u32 *saddr, __u32 *daddr)
{
    __u32 zero = 0;
    struct xdp_slot_ctx *sc;

    if (bpf_xdp_adjust_meta(ctx, -(int)sizeof(struct xdp_slot_ctx)) == 0) {
        void *meta = (void *)(long)ctx->data_meta;
        void *data = (void *)(long)ctx->data;
        sc = (meta + sizeof(struct xdp_slot_ctx) <= data)
             ? (struct xdp_slot_ctx *)meta : NULL;
    } else {
        sc = bpf_map_lookup_elem(&slot_ctx_map, &zero);
    }

    if (sc) {
        sc->family       = family;
        sc->ip_proto     = ip_proto;
        sc->l3_offset    = l3_offset;
        sc->inner_offset = inner_offset;
        sc->_pad         = 0;
        sc->saddr[0] = saddr[0]; sc->saddr[1] = saddr[1];
        sc->saddr[2] = saddr[2]; sc->saddr[3] = saddr[3];
        sc->daddr[0] = daddr[0]; sc->daddr[1] = daddr[1];
        sc->daddr[2] = daddr[2]; sc->daddr[3] = daddr[3];
    }

    count(CNT_SLOT_CALL);
    bpf_tail_call(ctx, &proto_handlers, (__u32)ip_proto);

    // bpf_tail_call returned: slot is empty or call failed.
    __u32 *action = bpf_map_lookup_elem(&slot_def_action, &zero);
    if (action && *action == 1) {
        count(CNT_SLOT_DROP);
        emit_drop(ip_proto, family, saddr, daddr, 0, 0, (__u8)CNT_SLOT_DROP);
        return XDP_DROP;
    }
    count(CNT_SLOT_PASS);
    return XDP_PASS;
}
