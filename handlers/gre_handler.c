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

    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    void *gre_ptr  = data + sc->inner_offset;
    if (gre_ptr + sizeof(struct gre_hdr) > data_end)
        return XDP_PASS;
    struct gre_hdr *gre = gre_ptr;

    __u16 flags_host = bpf_ntohs(gre->flags);

    /* Drop non-zero GRE version (version 1 = PPTP, not standard GRE) */
    if ((flags_host & 0x7) != 0)
        return XDP_DROP;

    /* If checksum-present flag is set, need 4 extra bytes */
    if (flags_host & GRE_FLAG_CSUM) {
        if (gre_ptr + sizeof(struct gre_hdr) + 4 > data_end)
            return XDP_DROP;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
