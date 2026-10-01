#pragma once
/* Included by common.h after runtime configuration and counters. */

static __always_inline __u32 packet_length(const struct xdp_md *ctx)
{
    __u64 length = (char *)(long)ctx->data_end - (char *)(long)ctx->data;
    /* Finish the pointer subtraction before narrowing: LLVM can otherwise
     * spill a packet pointer as u32, which the BPF verifier rejects. */
    barrier_var(length);
    return (__u32)length;
}

struct pkt_event {
    __u64 ts_ns;
    __u32 src_ip[4];   // v4: [0] only; v6: all 4 (network byte order)
    __u32 dst_ip[4];
    __u16 src_port;    // network byte order
    __u16 dst_port;
    __u8  proto;       // IPPROTO_TCP / UDP / ICMP / ICMPV6 …
    __u8  family;      // IPv4=2 / IPv6=10 / unknown=0
    __u8  verdict;     // 1=DROP, 2=ALLOW
    __u8  reason;      // xdp_counter_idx value
    __u32 ifindex;     // ingress interface
    __u32 pkt_len;     // original inbound Ethernet frame bytes
    __u8  version;
    __u8  reserved[7];
};

_Static_assert(sizeof(struct pkt_event) == 64, "packet event ABI size");
_Static_assert(__builtin_offsetof(struct pkt_event, ifindex) == 48, "v1 prefix");
_Static_assert(__builtin_offsetof(struct pkt_event, version) == 56, "v2 version");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 22); // 4 MiB
} pkt_ringbuf SEC(".maps");

static __always_inline bool drop_events_enabled(void)
{
    struct xdp_runtime_cfg *cfg = runtime_cfg();
    return !cfg || !(cfg->cfg_flags & XDP_CFG_FLAG_DROP_EVENTS_DISABLED);
}

static __always_inline void emit_packet_event(
    struct xdp_md *ctx, __u32 pkt_len,
    __u8 proto, __u8 family,
    const __u32 *src_ip, const __u32 *dst_ip,
    __be16 sport, __be16 dport,
    __u8 verdict,
    __u8 reason,
    __u64 now)
{
    if (!drop_events_enabled()) {
        count(CNT_EVENT_SUPPRESSED);
        return;
    }
    struct pkt_event *e = bpf_ringbuf_reserve(&pkt_ringbuf, sizeof(*e), 0);
    if (!e) {
        count(CNT_EVENT_LOST);
        return;
    }
    e->ifindex  = ctx->ingress_ifindex;
    e->pkt_len  = pkt_len;
    e->version  = 2;
    __builtin_memset(e->reserved, 0, sizeof(e->reserved));
    e->ts_ns    = now;
    e->proto    = proto;
    e->family   = family == 2 || family == 10 ? family : 0;
    e->verdict  = verdict;
    e->reason   = reason;
    e->src_port = e->family ? sport : 0;
    e->dst_port = e->family ? dport : 0;
    if (e->family) {
        __builtin_memcpy(e->src_ip, src_ip, 16);
        __builtin_memcpy(e->dst_ip, dst_ip, 16);
    } else {
        __builtin_memset(e->src_ip, 0, sizeof(e->src_ip));
        __builtin_memset(e->dst_ip, 0, sizeof(e->dst_ip));
    }
    bpf_ringbuf_submit(e, 0);
    count(CNT_EVENT_EMITTED);
}

static __always_inline void emit_drop(
    struct xdp_md *ctx,
    __u8 proto, __u8 family,
    const __u32 *src_ip, const __u32 *dst_ip,
    __be16 sport, __be16 dport,
    __u8 reason,
    __u64 now)
{
    emit_packet_event(ctx, packet_length(ctx), proto, family, src_ip, dst_ip, sport, dport, 1, reason, now);
}

static __always_inline void emit_allow(
    struct xdp_md *ctx,
    __u8 proto, __u8 family,
    const __u32 *src_ip, const __u32 *dst_ip,
    __be16 sport, __be16 dport,
    __u8 reason,
    __u64 now)
{
    emit_packet_event(ctx, packet_length(ctx), proto, family, src_ip, dst_ip, sport, dport, 2, reason, now);
}

/* Parsing failed before a trustworthy address/port tuple was available. */
static __always_inline int drop_unclassified(struct xdp_md *ctx, __u8 reason)
{
    __u32 zero[4] = {};
    count(reason);
    emit_drop(ctx, 0, 0, zero, zero, 0, 0, reason, bpf_ktime_get_ns());
    return XDP_DROP;
}
