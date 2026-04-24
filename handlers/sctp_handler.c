// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "xdp_slot_ctx.h"

struct sctp_hdr {
    __be16 sport;
    __be16 dport;
    __be32 vtag;
    __be32 checksum;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 65536);
    __type(key, __u32);
    __type(value, __u32);
} sctp_whitelist SEC(".maps");

SEC("xdp/sctp")
int xdp_sctp_handler(struct xdp_md *ctx)
{
    struct xdp_slot_ctx *sc = get_slot_ctx(ctx);
    if (!sc)
        return XDP_PASS;

    void *data      = (void *)(long)ctx->data;
    void *data_end  = (void *)(long)ctx->data_end;
    void *sctp_ptr  = data + sc->inner_offset;
    if (sctp_ptr + sizeof(struct sctp_hdr) > data_end)
        return XDP_PASS;
    struct sctp_hdr *sctp = sctp_ptr;

    __u32 dport = bpf_ntohs(sctp->dport);
    __u32 *allowed = bpf_map_lookup_elem(&sctp_whitelist, &dport);
    if (allowed && *allowed == 1)
        return XDP_PASS;

    return XDP_DROP;
}

char _license[] SEC("license") = "GPL";
