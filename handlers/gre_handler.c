// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "common.h"

struct gre_hdr {
    __be16 flags;
    __be16 proto;
};

static __always_inline int check_gre(struct xdp_md *ctx)
{
    struct xdp_slot_ctx *sc = get_slot_ctx(ctx);
    if (!sc)
        return XDP_PASS;

    __u16 inner_off = sc->inner_offset;
    if (inner_off > 256)
        return XDP_PASS;

    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct gre_hdr *gre = data + inner_off;

    if ((void *)(gre + 1) > data_end)
        return XDP_PASS;

    __u16 flags_host = bpf_ntohs(gre->flags);

    /* Drop non-zero GRE version (version 1 = PPTP, not standard GRE) */
    if ((flags_host & 0x7) != 0) {
        count(CNT_GRE_VERSION_INVALID);
        emit_drop(ctx, IPPROTO_GRE, sc->family, sc->saddr, sc->daddr,
                  0, 0, CNT_GRE_VERSION_INVALID, bpf_ktime_get_ns());
        return XDP_DROP;
    }

    return XDP_PASS;
}

SEC("xdp/gre")
int xdp_gre_handler(struct xdp_md *ctx)
{
    __u32 pkt_len = packet_length(ctx);
    int action = check_gre(ctx);
    count(action == XDP_DROP ? CNT_SLOT_DROP : CNT_SLOT_PASS);
    count_bytes(action == XDP_DROP, pkt_len);
    return action;
}

char _license[] SEC("license") = "GPL";
