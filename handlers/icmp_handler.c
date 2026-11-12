// SPDX-License-Identifier: GPL-2.0
#include "common.h"
#include "handler_state.h"
#include "icmp_ct_tuple.h"

AXDP_STATE_SCHEMA("icmp-conntrack-v1", "[]");
AXDP_KERNEL_MODULES("[\"axdp_icmp\"]");

extern int bpf_axdp_icmp_reply(struct xdp_md *ctx,
                             const struct axdp_icmp_tuple *query) __ksym;

static __always_inline int check_reply(struct xdp_md *ctx)
{
    struct xdp_slot_ctx *sc = get_slot_ctx(ctx);
    // Cover all extension headers accepted by the main IPv6 parser.
    if (!sc || sc->inner_offset > 16383)
        return XDP_DROP;
    void *data = (void *)(long)ctx->data;
    void *end = (void *)(long)ctx->data_end;
    struct icmphdr *icmp = data + sc->inner_offset;
    if ((void *)(icmp + 1) > end)
        return XDP_DROP;
    if (!((sc->family == CT_FAMILY_IPV4 && sc->ip_proto == IPPROTO_ICMP && icmp->type == ICMP_ECHOREPLY) ||
          (sc->family == CT_FAMILY_IPV6 && sc->ip_proto == IPPROTO_ICMPV6 && icmp->type == ICMPV6_ECHO_REPLY)))
        return XDP_DROP;

    struct axdp_icmp_tuple query = { .family = sc->family, .id = icmp->un.echo.id, .code = icmp->code };
    __builtin_memcpy(query.saddr, sc->saddr, sizeof(query.saddr));
    __builtin_memcpy(query.daddr, sc->daddr, sizeof(query.daddr));
    if (bpf_axdp_icmp_reply(ctx, &query) == 1) {
        count(query.family == CT_FAMILY_IPV4 ? CNT_IPV4_OTHER : CNT_IPV6_OTHER);
        return XDP_PASS;
    }
    count(CNT_ICMP_REPLY_UNTRACKED);
    emit_drop(ctx, sc->ip_proto, query.family, query.saddr, query.daddr, 0, 0,
              CNT_ICMP_REPLY_UNTRACKED, bpf_ktime_get_ns());
    return XDP_DROP;
}

SEC("xdp")
int xdp_icmp_handler(struct xdp_md *ctx)
{
    __u32 length = packet_length(ctx);
    int action = check_reply(ctx);
    count(action == XDP_DROP ? CNT_SLOT_DROP : CNT_SLOT_PASS);
    count_bytes(action == XDP_DROP, length);
    return action;
}

char _license[] SEC("license") = "GPL";
