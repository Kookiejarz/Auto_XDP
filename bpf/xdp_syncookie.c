/* Optional XDP SYN-cookie program.  The main firewall reaches this object only
 * through syncookie_prog_array after whitelist/trust/ACL policy checks. */
#include "include/common.h"
#include "include/syncookie_shared.h"
#include "include/syncookie_maps.h"
#include "include/map_sizes.h"
#include "include/linux_conntrack.h"

static __always_inline bool syncookie_linux_established(
    struct xdp_md *ctx, const struct xdp_slot_ctx *sc)
{
    struct flow_key key = {
        .family = sc->family,
        .sport = sc->sport,
        .dport = sc->dport,
    };
    __builtin_memcpy(key.saddr, sc->saddr, sizeof(key.saddr));
    __builtin_memcpy(key.daddr, sc->daddr, sizeof(key.daddr));
    struct bpf_sock_tuple tuple;
    linux_ct_fill_tuple(&tuple, &key);
    struct bpf_ct_opts___local opts = linux_ct_opts();
    struct nf_conn *ct = bpf_xdp_ct_lookup(
        ctx, &tuple, linux_ct_tuple_size(&key), &opts, sizeof(opts));
    if (!ct)
        return false;
    struct linux_ct_snapshot snapshot;
    linux_ct_snapshot(ct, opts.dir, &snapshot);
    bpf_ct_release(ct);
    return snapshot.dir == NF_CT_DIR_ORIGINAL &&
           linux_ct_established(&snapshot);
}

struct syncookie_syn_opts {
    __u32 tsval;
    __u8 wscale;
    __u8 tstamp_ok;
    __u8 wscale_ok;
    __u8 sack_ok;
    __u8 ecn_ok;
};

static __always_inline struct syncookie_syn_opts
syncookie_parse_syn_opts(struct tcphdr *tcp, void *data_end)
{
    struct syncookie_syn_opts out = {};
    __u8 *base = (__u8 *)tcp + sizeof(*tcp);
    __u32 opt_len = ((__u32)tcp->doff * 4) - sizeof(*tcp);
    __u32 off = 0;
#pragma unroll
    for (int i = 0; i < 10; i++) {
        if (off >= opt_len || base + off + 1 > (__u8 *)data_end)
            break;
        __u8 *opt = base + off;
        __u8 kind = *opt;
        if (kind == 0)
            break;
        if (kind == 1) {
            off++;
            continue;
        }
        if (off + 2 > opt_len || opt + 2 > (__u8 *)data_end || opt[1] < 2 ||
            off + opt[1] > opt_len || opt + opt[1] > (__u8 *)data_end)
            break;
        __u8 len = opt[1];
        if (kind == 3 && len == 3) {
            if (opt + 3 > (__u8 *)data_end)
                break;
            out.wscale = opt[2] > 14 ? 14 : opt[2];
            out.wscale_ok = 1;
        } else if (kind == 4 && len == 2) {
            out.sack_ok = 1;
        } else if (kind == 8 && len == 10) {
            if (opt + 10 > (__u8 *)data_end)
                break;
            out.tsval = ((__u32)opt[2] << 24) | ((__u32)opt[3] << 16) |
                        ((__u32)opt[4] << 8) | opt[5];
            out.tstamp_ok = 1;
        }
        off += len;
    }
    __u8 flags = ((__u8 *)tcp)[13];
    out.ecn_ok = (flags & 0xc0) == 0xc0;
    return out;
}

static __always_inline __u16
syncookie_write_synack_opts(struct tcphdr *tcp,
                            const struct axdp_tcp_req_attrs *attrs)
{
    __u8 *opt = (__u8 *)tcp + sizeof(*tcp);
    __u16 len = 0;
    opt[len++] = 2; opt[len++] = 4;
    opt[len++] = (__u8)(attrs->mss >> 8); opt[len++] = (__u8)attrs->mss;
    if (attrs->tstamp_ok) {
        opt[len++] = 1;
        opt[len++] = 1;
        opt[len++] = 8; opt[len++] = 10;
        opt[len++] = (attrs->rcv_tsecr >> 24) & 0xff;
        opt[len++] = (attrs->rcv_tsecr >> 16) & 0xff;
        opt[len++] = (attrs->rcv_tsecr >> 8) & 0xff;
        opt[len++] = attrs->rcv_tsecr & 0xff;
        opt[len++] = (attrs->rcv_tsval >> 24) & 0xff;
        opt[len++] = (attrs->rcv_tsval >> 16) & 0xff;
        opt[len++] = (attrs->rcv_tsval >> 8) & 0xff;
        opt[len++] = attrs->rcv_tsval & 0xff;
    }
    if (attrs->sack_ok) {
        opt[len++] = 4; opt[len++] = 2;
    }
    if (attrs->wscale_ok) {
        opt[len++] = 1; opt[len++] = 3; opt[len++] = 3;
        opt[len++] = attrs->rcv_wscale;
    }
    if (len & 1)
        opt[len++] = 1;
    if (len & 2) {
        opt[len++] = 1;
        opt[len++] = 1;
    }
    return len;
}

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 65536);
    __type(key, __u32);
    __type(value, __u32);
} tcp_synck_policy SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct syncookie_runtime_cfg);
} sync_run_cfg SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, RATE_MAP_MAX_ENTRIES_V4);
    __type(key, struct syncookie_invalid_key_v4);
    __type(value, struct syn_rate_val);
} sync_invalid4 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, RATE_MAP_MAX_ENTRIES_V6);
    __type(key, struct syncookie_invalid_key_v6);
    __type(value, struct syn_rate_val);
} sync_invalid6 SEC(".maps");

static __always_inline __u16 fold_checksum(__u64 sum)
{
    sum = (sum & 0xffff) + (sum >> 16);
    sum = (sum & 0xffff) + (sum >> 16);
    return (__u16)~sum;
}

static __always_inline __u32 cookie_rate_tick(__u64 now)
{
    return (__u32)(now / 1000000ULL);
}

static __always_inline __u64 cookie_rate_pack(__u32 tick, __u32 count_value)
{
    return ((__u64)tick << 32) | count_value;
}

static __always_inline bool invalid_budget_v4(
    struct syncookie_invalid_key_v4 *key, __u64 now, __u32 limit)
{
    struct syn_rate_val *value = bpf_map_lookup_elem(&sync_invalid4, key);
    __u32 tick = cookie_rate_tick(now);
    if (!value) {
        struct syn_rate_val fresh = { .state = cookie_rate_pack(tick, 1) };
        if (!bpf_map_update_elem(&sync_invalid4, key, &fresh, BPF_NOEXIST))
            return false;
        value = bpf_map_lookup_elem(&sync_invalid4, key);
        if (!value)
            return true;
    }
    /* ponytail: bounded CAS retries fail closed under contention; the
     * lock-free update preserves the existing 8-byte value ABI. */
#pragma unroll
    for (int attempt = 0; attempt < 8; attempt++) {
        __u64 old = __sync_fetch_and_add(&value->state, 0);
        __u32 count_value = (__u32)old;
        __u64 next;
        if ((__u32)(tick - (__u32)(old >> 32)) >= 1000)
            next = cookie_rate_pack(tick, 1);
        else {
            if (count_value >= limit)
                return true;
            next = cookie_rate_pack((__u32)(old >> 32), count_value + 1);
        }
        if (__sync_val_compare_and_swap(&value->state, old, next) == old)
            return false;
    }
    return true;
}

static __always_inline bool invalid_budget_v6(
    struct syncookie_invalid_key_v6 *key, __u64 now, __u32 limit)
{
    struct syn_rate_val *value = bpf_map_lookup_elem(&sync_invalid6, key);
    __u32 tick = cookie_rate_tick(now);
    if (!value) {
        struct syn_rate_val fresh = { .state = cookie_rate_pack(tick, 1) };
        if (!bpf_map_update_elem(&sync_invalid6, key, &fresh, BPF_NOEXIST))
            return false;
        value = bpf_map_lookup_elem(&sync_invalid6, key);
        if (!value)
            return true;
    }
    /* See invalid_budget_v4: bounded CAS is fail-closed under contention. */
#pragma unroll
    for (int attempt = 0; attempt < 8; attempt++) {
        __u64 old = __sync_fetch_and_add(&value->state, 0);
        __u32 count_value = (__u32)old;
        __u64 next;
        if ((__u32)(tick - (__u32)(old >> 32)) >= 1000)
            next = cookie_rate_pack(tick, 1);
        else {
            if (count_value >= limit)
                return true;
            next = cookie_rate_pack((__u32)(old >> 32), count_value + 1);
        }
        if (__sync_val_compare_and_swap(&value->state, old, next) == old)
            return false;
    }
    return true;
}

static __always_inline int syncookie_v4(
    struct xdp_md *ctx, struct xdp_slot_ctx *sc,
    void *data, void *data_end)
{
    __u16 l3_offset = sc->l3_offset;
    __u16 inner_offset = sc->inner_offset;
    struct iphdr *ip = data + l3_offset;
    struct tcphdr *tcp = data + inner_offset;
    __u32 old_seq;
    __u16 tcp_len;
    __s64 generated;
    int new_len;

    if ((void *)(ip + 1) > data_end || (void *)(tcp + 1) > data_end)
        return XDP_DROP;
    if (ip->ihl < 5 || (void *)ip + ip->ihl * 4 > data_end)
        return XDP_DROP;
    if (tcp->doff < 5 || (void *)tcp + tcp->doff * 4 > data_end)
        return XDP_DROP;
    if (tcp->ack || !tcp->syn || tcp->rst || tcp->fin) {
        if (tcp->syn || !tcp->ack || tcp->rst || tcp->fin)
            return XDP_DROP;
        if (syncookie_linux_established(ctx, sc))
            return XDP_PASS;
        struct syncookie_runtime_cfg *runtime =
            bpf_map_lookup_elem(&sync_run_cfg, &(__u32){0});
        struct syncookie_invalid_key_v4 invalid_key = {
            .addr = ip->saddr, .dest_port = bpf_ntohs(tcp->dest),
        };
        if (runtime && invalid_budget_v4(&invalid_key, bpf_ktime_get_ns(),
                                         runtime->invalid_ack_pps)) {
            count(CNT_SYN_COOKIE_BUDGET_DROP);
            count_bytes(true, (__u32)(data_end - data));
            return XDP_DROP;
        }
        if (bpf_tcp_raw_check_syncookie_ipv4(ip, tcp)) {
            count(CNT_SYN_COOKIE_INVALID);
            count_bytes(true, (__u32)(data_end - data));
            return XDP_DROP;
        }
        count(CNT_SYN_COOKIE_VALID);
        count_bytes(false, (__u32)(data_end - data));
        return XDP_PASS;
    }

    tcp_len = tcp->doff * 4;
    count(CNT_SYN_COOKIE_CHALLENGE);
    /* The helper requires verifier-visible room for the maximum TCP header. */
    if (bpf_xdp_adjust_tail(ctx, 60 - tcp_len))
        return XDP_DROP;
    data = (void *)(long)ctx->data;
    data_end = (void *)(long)ctx->data_end;
    ip = data + l3_offset;
    tcp = data + inner_offset;
    if ((void *)ip + 60 > data_end || (void *)tcp + 60 > data_end)
        return XDP_DROP;
    generated = bpf_tcp_raw_gen_syncookie_ipv4(ip, tcp, tcp_len);
    if (generated < 0) {
        count(CNT_SYN_COOKIE_HELPER_ERROR);
        count_bytes(true, (__u32)(data_end - data));
        return XDP_DROP;
    }
    old_seq = bpf_ntohl(tcp->seq);
    struct syncookie_syn_opts syn_opts =
        syncookie_parse_syn_opts(tcp, data_end);
    struct axdp_tcp_req_attrs attrs = {
        .rcv_tsval = syn_opts.tsval,
        .rcv_tsecr = (__u32)(bpf_ktime_get_ns() / 1000000ULL),
        .mss = (__u16)(generated >> 32),
        .rcv_wscale = 7,
        .snd_wscale = syn_opts.wscale,
        .ecn_ok = syn_opts.ecn_ok,
        .wscale_ok = syn_opts.wscale_ok,
        .sack_ok = syn_opts.sack_ok,
        .tstamp_ok = syn_opts.tstamp_ok,
    };
    {
        struct syncookie_tuple_v4 handoff_key = {
            .sport = tcp->source, .dport = tcp->dest,
            .saddr = ip->saddr, .daddr = ip->daddr,
        };
        bpf_map_update_elem(&sync_handoff4, &handoff_key, &attrs, BPF_ANY);
    }

    /* Move TCP to a plain IPv4 header when IPv4 options were present. */
    if (ip->ihl > 5) {
        struct tcphdr *new_tcp = (void *)ip + sizeof(*ip);
        __builtin_memmove(new_tcp, tcp, sizeof(*tcp));
        tcp = new_tcp;
        ip->ihl = 5;
    }
    data = (void *)(long)ctx->data;
    data_end = (void *)(long)ctx->data_end;
    ip = data + l3_offset;
    tcp = data + l3_offset + sizeof(*ip);
    if (data + sizeof(struct ethhdr) > data_end ||
        (void *)ip + sizeof(*ip) > data_end ||
        (void *)tcp + 60 > data_end)
        return XDP_DROP;

    {
        struct ethhdr *eth = data;
        __u8 mac[ETH_ALEN];
        __builtin_memcpy(mac, eth->h_source, ETH_ALEN);
        __builtin_memcpy(eth->h_source, eth->h_dest, ETH_ALEN);
        __builtin_memcpy(eth->h_dest, mac, ETH_ALEN);
        __be32 addr = ip->saddr;
        ip->saddr = ip->daddr;
        ip->daddr = addr;
    }
    {
        __be16 port = tcp->source;
        tcp->source = tcp->dest;
        tcp->dest = port;
    }
    tcp->seq = bpf_htonl((__u32)generated);
    tcp->ack_seq = bpf_htonl(old_seq + 1);
    tcp->ack = 1;
    tcp->syn = 1;
    tcp->rst = 0;
    tcp->fin = 0;
    __u16 tcp_opt_len = syncookie_write_synack_opts(tcp, &attrs);
    tcp->doff = 5 + tcp_opt_len / 4;
    tcp->window = 0;
    tcp->urg_ptr = 0;
    tcp_len = sizeof(*tcp) + tcp_opt_len;

    ip->tot_len = bpf_htons(sizeof(*ip) + tcp_len);
    ip->check = 0;
    ip->check = fold_checksum(bpf_csum_diff(0, 0, (__be32 *)ip, sizeof(*ip), 0));
    tcp->check = 0;
    tcp->check = fold_checksum(bpf_csum_diff(
        0, 0, (__be32 *)tcp, tcp_len,
        bpf_csum_diff(0, 0, &ip->saddr, 8,
                      bpf_htons(IPPROTO_TCP) + bpf_htons(tcp_len))));
    new_len = l3_offset + sizeof(*ip) + tcp_len;
    if (bpf_xdp_adjust_tail(ctx, new_len - (int)(data_end - data)))
        return XDP_DROP;
    count(CNT_SYN_COOKIE_SENT);
    count_bytes(false, (__u32)(data_end - data));
    return XDP_TX;
}

static __always_inline int syncookie_v6(
    struct xdp_md *ctx, struct xdp_slot_ctx *sc,
    void *data, void *data_end)
{
    __u16 l3_offset = sc->l3_offset;
    __u16 inner_offset = sc->inner_offset;
    struct ipv6hdr *ip = data + l3_offset;
    struct tcphdr *tcp = data + inner_offset;
    __u16 tcp_len;
    __u32 old_seq;
    __s64 generated;
    int new_len;

    if ((void *)ip + sizeof(*ip) > data_end ||
        (void *)tcp + sizeof(*tcp) > data_end)
        return XDP_DROP;
    if (tcp->doff < 5 || (void *)tcp + tcp->doff * 4 > data_end)
        return XDP_DROP;
    if (tcp->ack || !tcp->syn || tcp->rst || tcp->fin) {
        if (tcp->syn || !tcp->ack || tcp->rst || tcp->fin)
            return XDP_DROP;
        if (syncookie_linux_established(ctx, sc))
            return XDP_PASS;
        struct syncookie_runtime_cfg *runtime =
            bpf_map_lookup_elem(&sync_run_cfg, &(__u32){0});
        struct syncookie_invalid_key_v6 invalid_key = {
            .dest_port = bpf_ntohs(tcp->dest),
        };
        __builtin_memcpy(invalid_key.addr, &ip->saddr, sizeof(invalid_key.addr));
        if (runtime && invalid_budget_v6(&invalid_key, bpf_ktime_get_ns(),
                                         runtime->invalid_ack_pps)) {
            count(CNT_SYN_COOKIE_BUDGET_DROP);
            count_bytes(true, (__u32)(data_end - data));
            return XDP_DROP;
        }
        if (bpf_tcp_raw_check_syncookie_ipv6(ip, tcp)) {
            count(CNT_SYN_COOKIE_INVALID);
            count_bytes(true, (__u32)(data_end - data));
            return XDP_DROP;
        }
        count(CNT_SYN_COOKIE_VALID);
        count_bytes(false, (__u32)(data_end - data));
        return XDP_PASS;
    }

    tcp_len = tcp->doff * 4;
    count(CNT_SYN_COOKIE_CHALLENGE);
    if (bpf_xdp_adjust_tail(ctx, 60 - tcp_len))
        return XDP_DROP;
    data = (void *)(long)ctx->data;
    data_end = (void *)(long)ctx->data_end;
    ip = data + l3_offset;
    tcp = data + inner_offset;
    if ((void *)ip + 60 > data_end || (void *)tcp + 60 > data_end)
        return XDP_DROP;
    generated = bpf_tcp_raw_gen_syncookie_ipv6(ip, tcp, tcp_len);
    if (generated < 0) {
        count(CNT_SYN_COOKIE_HELPER_ERROR);
        count_bytes(true, (__u32)(data_end - data));
        return XDP_DROP;
    }
    old_seq = bpf_ntohl(tcp->seq);
    struct syncookie_syn_opts syn_opts =
        syncookie_parse_syn_opts(tcp, data_end);
    struct axdp_tcp_req_attrs attrs = {
        .rcv_tsval = syn_opts.tsval,
        .rcv_tsecr = (__u32)(bpf_ktime_get_ns() / 1000000ULL),
        .mss = (__u16)(generated >> 32),
        .rcv_wscale = 7,
        .snd_wscale = syn_opts.wscale,
        .ecn_ok = syn_opts.ecn_ok,
        .wscale_ok = syn_opts.wscale_ok,
        .sack_ok = syn_opts.sack_ok,
        .tstamp_ok = syn_opts.tstamp_ok,
    };
    {
        struct syncookie_tuple_v6 handoff_key = {
            .sport = tcp->source, .dport = tcp->dest,
        };
        __builtin_memcpy(handoff_key.saddr, &ip->saddr, sizeof(handoff_key.saddr));
        __builtin_memcpy(handoff_key.daddr, &ip->daddr, sizeof(handoff_key.daddr));
        bpf_map_update_elem(&sync_handoff6, &handoff_key, &attrs, BPF_ANY);
    }
    if (inner_offset != l3_offset + sizeof(*ip)) {
        struct tcphdr *new_tcp = (void *)ip + sizeof(*ip);
        __builtin_memmove(new_tcp, tcp, sizeof(*tcp));
        tcp = new_tcp;
        ip->nexthdr = IPPROTO_TCP;
    }
    data = (void *)(long)ctx->data;
    data_end = (void *)(long)ctx->data_end;
    ip = data + l3_offset;
    tcp = data + l3_offset + sizeof(*ip);
    if (data + sizeof(struct ethhdr) > data_end ||
        (void *)ip + sizeof(*ip) > data_end ||
        (void *)tcp + 60 > data_end)
        return XDP_DROP;
    {
        struct ethhdr *eth = data;
        __u8 mac[ETH_ALEN];
        __builtin_memcpy(mac, eth->h_source, ETH_ALEN);
        __builtin_memcpy(eth->h_source, eth->h_dest, ETH_ALEN);
        __builtin_memcpy(eth->h_dest, mac, ETH_ALEN);
        struct in6_addr addr = ip->saddr;
        ip->saddr = ip->daddr;
        ip->daddr = addr;
    }
    {
        __be16 port = tcp->source;
        tcp->source = tcp->dest;
        tcp->dest = port;
    }
    tcp->seq = bpf_htonl((__u32)generated);
    tcp->ack_seq = bpf_htonl(old_seq + 1);
    tcp->ack = 1;
    tcp->syn = 1;
    tcp->rst = 0;
    tcp->fin = 0;
    __u16 tcp_opt_len = syncookie_write_synack_opts(tcp, &attrs);
    tcp->doff = 5 + tcp_opt_len / 4;
    tcp->window = 0;
    tcp->urg_ptr = 0;
    tcp_len = sizeof(*tcp) + tcp_opt_len;
    ip->payload_len = bpf_htons(tcp_len);
    tcp->check = 0;
    tcp->check = fold_checksum(bpf_csum_diff(
        0, 0, (__be32 *)tcp, tcp_len,
        bpf_csum_diff(0, 0, (__be32 *)&ip->saddr, 32,
                      bpf_htons(IPPROTO_TCP) + bpf_htons(tcp_len))));
    new_len = l3_offset + sizeof(*ip) + tcp_len;
    if (bpf_xdp_adjust_tail(ctx, new_len - (int)(data_end - data)))
        return XDP_DROP;
    count(CNT_SYN_COOKIE_SENT);
    count_bytes(false, (__u32)(data_end - data));
    return XDP_TX;
}

SEC("xdp")
int xdp_syncookie(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    __u32 zero = 0;
    struct xdp_slot_ctx *sc = bpf_map_lookup_elem(&slot_ctx_map, &zero);
    if (!sc)
        return XDP_DROP;
    /* Bound offsets copied from the validated main parser before using them as
     * packet-pointer arithmetic; this is required by the XDP verifier. */
    if (sc->l3_offset > 256 || sc->inner_offset > 512 ||
        sc->inner_offset < sc->l3_offset)
        return XDP_DROP;
    if (sc->family == CT_FAMILY_IPV4)
        return syncookie_v4(ctx, sc, data, data_end);
    if (sc->family == CT_FAMILY_IPV6)
        return syncookie_v6(ctx, sc, data, data_end);
    return XDP_DROP;
}

char LICENSE[] SEC("license") = "GPL";
