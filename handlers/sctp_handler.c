// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "xdp_slot_ctx.h"

#define CT_FAMILY_IPV4 2
#define CT_FAMILY_IPV6 10
#define SCTP_TIMEOUT_NS (300ULL * 1000000000ULL)

struct sctp_hdr {
    __be16 sport;
    __be16 dport;
    __be32 vtag;
    __be32 checksum;
};

struct ct_key {
    __u8  family;
    __u8  pad[3];
    __be16 sport;
    __be16 dport;
    __u32 saddr[4];
    __u32 daddr[4];
} __attribute__((aligned(8)));

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 65536);
    __type(key, __u32);
    __type(value, __u32);
} sctp_whitelist SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, struct ct_key);
    __type(value, __u64);
} sctp_conntrack SEC(".maps");

static __always_inline void fill_ct_key(
    struct ct_key *key, __u8 family,
    __u32 *saddr, __u32 *daddr,
    __be16 sport, __be16 dport)
{
    __builtin_memset(key, 0, sizeof(*key));
    key->family = family;
    key->sport  = sport;
    key->dport  = dport;
    __builtin_memcpy(key->saddr, saddr, 16);
    __builtin_memcpy(key->daddr, daddr, 16);
}

SEC("xdp/sctp")
int xdp_sctp_handler(struct xdp_md *ctx)
{
    struct xdp_slot_ctx *sc = get_slot_ctx(ctx);
    if (!sc)
        return XDP_PASS;

    /* Copy all needed sc fields before bpf_xdp_adjust_head may shrink the
     * metadata region and invalidate the sc pointer. */
    __u16 inner_off = sc->inner_offset;
    __u8  family    = sc->family;
    __u32 saddr[4], daddr[4];
    __builtin_memcpy(saddr, sc->saddr, 16);
    __builtin_memcpy(daddr, sc->daddr, 16);

    /* Advance ctx->data to the SCTP header to avoid variable-offset packet
     * pointer arithmetic that this kernel's BPF verifier rejects. */
    if (bpf_xdp_adjust_head(ctx, (int)inner_off))
        return XDP_PASS;

    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct sctp_hdr *sctp = data;

    if ((void *)(sctp + 1) > data_end) {
        bpf_xdp_adjust_head(ctx, -(int)inner_off);
        return XDP_PASS;
    }

    // 1. Conntrack: reply to an outbound SCTP connection we initiated.
    struct ct_key key;
    fill_ct_key(&key, family, saddr, daddr, sctp->sport, sctp->dport);
    __u64 *last_seen = bpf_map_lookup_elem(&sctp_conntrack, &key);
    if (last_seen) {
        __u64 now = bpf_ktime_get_ns();
        if (now - *last_seen <= SCTP_TIMEOUT_NS) {
            bpf_xdp_adjust_head(ctx, -(int)inner_off);
            return XDP_PASS;
        }
        bpf_map_delete_elem(&sctp_conntrack, &key);
    }

    // 2. Whitelist: inbound SCTP to an open port.
    __u32 dport = bpf_ntohs(sctp->dport);
    __u32 *allowed = bpf_map_lookup_elem(&sctp_whitelist, &dport);
    if (allowed && *allowed == 1) {
        bpf_xdp_adjust_head(ctx, -(int)inner_off);
        return XDP_PASS;
    }

    return XDP_DROP;
}

char _license[] SEC("license") = "GPL";
