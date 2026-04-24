// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "xdp_slot_ctx.h"

struct esp_hdr {
    __be32 spi;
    __be32 seq;
};

SEC("xdp/esp")
int xdp_esp_handler(struct xdp_md *ctx)
{
    struct xdp_slot_ctx *sc = get_slot_ctx(ctx);
    if (!sc)
        return XDP_PASS;

    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    void *esp_ptr  = data + sc->inner_offset;
    if (esp_ptr + sizeof(struct esp_hdr) > data_end)
        return XDP_PASS;
    struct esp_hdr *esp = esp_ptr;

    /* RFC 4303 §2.1: SPI values 0x00–0xFF are reserved */
    if (bpf_ntohl(esp->spi) < 256)
        return XDP_DROP;

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
