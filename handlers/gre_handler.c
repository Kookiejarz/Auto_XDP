// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "xdp_slot_ctx.h"

struct gre_hdr {
    __be16 flags;
    __be16 proto;
};

#define GRE_FLAG_CSUM (1 << 15)
#define GRE_FLAG_KEY  (1 << 13)
#define GRE_FLAG_SEQ  (1 << 12)

SEC("xdp/gre")
int xdp_gre_handler(struct xdp_md *ctx)
{
    struct xdp_slot_ctx *sc = get_slot_ctx(ctx);
    if (!sc)
        return XDP_PASS;

    /* Save inner_offset before the head adjustment may invalidate the
     * metadata region.  Advance ctx->data to the GRE header so all
     * subsequent accesses use a fixed offset — this kernel's BPF verifier
     * rejects variable-offset packet pointer arithmetic (pkt += u16_var). */
    __u16 inner_off = sc->inner_offset;
    if (bpf_xdp_adjust_head(ctx, (int)inner_off))
        return XDP_PASS;

    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct gre_hdr *gre = data;

    if ((void *)(gre + 1) > data_end) {
        bpf_xdp_adjust_head(ctx, -(int)inner_off);
        return XDP_PASS;
    }

    __u16 flags_host = bpf_ntohs(gre->flags);

    /* Drop non-zero GRE version (version 1 = PPTP, not standard GRE) */
    if ((flags_host & 0x7) != 0)
        return XDP_DROP;

    /* If checksum-present flag is set, need 4 extra bytes */
    if (flags_host & GRE_FLAG_CSUM) {
        if ((void *)((char *)gre + sizeof(struct gre_hdr) + 4) > data_end)
            return XDP_DROP;
    }

    bpf_xdp_adjust_head(ctx, -(int)inner_off);
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
