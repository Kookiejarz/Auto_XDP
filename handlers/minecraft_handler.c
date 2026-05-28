// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "xdp_slot_ctx.h"

#define CT_FAMILY_IPV4 2
#define CT_FAMILY_IPV6 10

#define MC_TIMEOUT_NS (15ULL * 1000000000ULL)
#define MC_BLOCK_NS   (300ULL * 1000000000ULL)
#define MC_MAX_OUT_OF_ORDER 4

#define MC_AWAIT_ACK            1
#define MC_AWAIT_HANDSHAKE      2
#define MC_AWAIT_STATUS_REQUEST 3
#define MC_AWAIT_LOGIN          4
#define MC_AWAIT_PING           5
#define MC_PING_COMPLETE        6
#define MC_DIRECT_STATUS        7
#define MC_DIRECT_LOGIN         8
#define MC_LEGACY_PING          9

#define MC_MAX_PACKET_ID_BYTES 5
#define MC_MAX_PACKET_LEN_BYTES 3
#define MC_HANDSHAKE_HOST_MAX (255 * 3)
#define MC_LOGIN_NAME_MAX (16 * 3)
#define MC_LOGIN_KEY_MAX 512
#define MC_LOGIN_SIGNATURE_MAX 4096

struct flow_key {
    __u8  family;
    __u8  pad[3];
    __be16 sport;
    __be16 dport;
    __u32 saddr[4];
    __u32 daddr[4];
} __attribute__((aligned(8)));

struct ct_key_v4 {
    __be16 sport;
    __be16 dport;
    __be32 saddr;
    __be32 daddr;
};

struct ct_key_v6 {
    __be16 sport;
    __be16 dport;
    __u32 saddr[4];
    __u32 daddr[4];
};

struct syn_rate_key_v4 {
    __be32 addr;
};

struct syn_rate_key_v6 {
    __u32 addr[4];
};

struct mc_pending_val {
    __u64 last_seen_ns;
    __u32 expected_seq;
    __s32 protocol_version;
    __u16 state;
    __u16 fails;
};

struct mc_varint {
    __s32 value;
    __u32 bytes;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 4096);
    __type(key, struct flow_key);
    __type(value, struct mc_pending_val);
} pending_mc SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 196608);
    __type(key, struct ct_key_v4);
    __type(value, __u64);
} tcp_ct4 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, struct ct_key_v6);
    __type(value, __u64);
} tcp_ct6 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 49152);
    __type(key, struct ct_key_v4);
    __type(value, __u32);
} tcp_pd4 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 16384);
    __type(key, struct ct_key_v6);
    __type(value, __u32);
} tcp_pd6 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 49152);
    __type(key, struct syn_rate_key_v4);
    __type(value, __u64);
} hblk4 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 16384);
    __type(key, struct syn_rate_key_v6);
    __type(value, __u64);
} hblk6 SEC(".maps");

static __always_inline void fill_flow_key(struct flow_key *key, const struct xdp_slot_ctx *sc)
{
    __builtin_memset(key, 0, sizeof(*key));
    key->family = sc->family;
    key->sport = sc->sport;
    key->dport = sc->dport;
    __builtin_memcpy(key->saddr, sc->saddr, sizeof(key->saddr));
    __builtin_memcpy(key->daddr, sc->daddr, sizeof(key->daddr));
}

static __always_inline void fill_ct_key_v4_map(struct ct_key_v4 *key, const struct flow_key *ct)
{
    key->sport = ct->sport;
    key->dport = ct->dport;
    key->saddr = (__be32)ct->saddr[0];
    key->daddr = (__be32)ct->daddr[0];
}

static __always_inline void fill_ct_key_v6_map(struct ct_key_v6 *key, const struct flow_key *ct)
{
    key->sport = ct->sport;
    key->dport = ct->dport;
    __builtin_memcpy(key->saddr, ct->saddr, sizeof(key->saddr));
    __builtin_memcpy(key->daddr, ct->daddr, sizeof(key->daddr));
}

static __always_inline void fill_block_key_v4(struct syn_rate_key_v4 *key, const struct flow_key *ct)
{
    key->addr = (__be32)ct->saddr[0];
}

static __always_inline void fill_block_key_v6(struct syn_rate_key_v6 *key, const struct flow_key *ct)
{
    __builtin_memcpy(key->addr, ct->saddr, sizeof(key->addr));
}

static __always_inline void cleanup_pending(const struct flow_key *ct)
{
    bpf_map_delete_elem(&pending_mc, ct);
    if (ct->family == CT_FAMILY_IPV4) {
        struct ct_key_v4 map_key;
        fill_ct_key_v4_map(&map_key, ct);
        bpf_map_delete_elem(&tcp_pd4, &map_key);
    } else {
        struct ct_key_v6 map_key;
        fill_ct_key_v6_map(&map_key, ct);
        bpf_map_delete_elem(&tcp_pd6, &map_key);
    }
}

static __always_inline int restore_and_return(struct xdp_md *ctx, __u16 inner_off, int action)
{
    if (inner_off && action != XDP_DROP)
        bpf_xdp_adjust_head(ctx, -(int)inner_off);
    return action;
}

static __always_inline int drop_with_cleanup(struct xdp_md *ctx, __u16 inner_off, const struct flow_key *ct)
{
    cleanup_pending(ct);
    return restore_and_return(ctx, inner_off, XDP_DROP);
}

static __always_inline int penalize_and_drop(
    struct xdp_md *ctx, __u16 inner_off, const struct flow_key *ct, __u64 now)
{
    __u64 blocked_until = now + MC_BLOCK_NS;
    if (ct->family == CT_FAMILY_IPV4) {
        struct syn_rate_key_v4 blocked_key;
        fill_block_key_v4(&blocked_key, ct);
        bpf_map_update_elem(&hblk4, &blocked_key, &blocked_until, BPF_ANY);
    } else {
        struct syn_rate_key_v6 blocked_key;
        fill_block_key_v6(&blocked_key, ct);
        bpf_map_update_elem(&hblk6, &blocked_key, &blocked_until, BPF_ANY);
    }
    cleanup_pending(ct);
    return restore_and_return(ctx, inner_off, XDP_DROP);
}

static __always_inline int verify_and_pass(
    struct xdp_md *ctx, __u16 inner_off, const struct flow_key *ct, __u64 now)
{
    if (ct->family == CT_FAMILY_IPV4) {
        struct ct_key_v4 map_key;
        fill_ct_key_v4_map(&map_key, ct);
        bpf_map_update_elem(&tcp_ct4, &map_key, &now, BPF_ANY);
    } else {
        struct ct_key_v6 map_key;
        fill_ct_key_v6_map(&map_key, ct);
        bpf_map_update_elem(&tcp_ct6, &map_key, &now, BPF_ANY);
    }
    cleanup_pending(ct);
    return restore_and_return(ctx, inner_off, XDP_PASS);
}

static __always_inline struct mc_varint mc_varint_fail(void)
{
    struct mc_varint v = { .value = 0, .bytes = 0 };
    return v;
}

static __always_inline struct mc_varint read_varint(
    __u8 *ptr, const __u8 *end, __u8 max_bytes)
{
    __s32 result = 0;

#define MC_VARINT_BYTE(idx, shift)                                                   \
    do {                                                                              \
        if (max_bytes < (idx))                                                        \
            return mc_varint_fail();                                                  \
        if (ptr + 1 > end)                                                            \
            return mc_varint_fail();                                                  \
        {                                                                             \
            __u8 b = *ptr++;                                                          \
            result |= ((__s32)(b & 0x7F) << (shift));                                 \
            if (!(b & 0x80)) {                                                        \
                struct mc_varint out = { .value = result, .bytes = (idx) };           \
                return out;                                                            \
            }                                                                         \
        }                                                                             \
    } while (0)

    MC_VARINT_BYTE(1, 0);
    MC_VARINT_BYTE(2, 7);
    MC_VARINT_BYTE(3, 14);
    MC_VARINT_BYTE(4, 21);
    MC_VARINT_BYTE(5, 28);

#undef MC_VARINT_BYTE
    return mc_varint_fail();
}

static __always_inline bool consume_bytes(__u8 **ptr, const __u8 *end, __u32 n)
{
    if (*ptr + n > end)
        return false;
    *ptr += n;
    return true;
}

static __always_inline bool inspect_status_request(__u8 *start, const __u8 *end)
{
    struct mc_varint v;

    v = read_varint(start, end, 1);
    if (!v.bytes || v.value != 1)
        return false;
    start += v.bytes;

    v = read_varint(start, end, 1);
    if (!v.bytes || v.value != 0)
        return false;
    start += v.bytes;

    return start == end;
}

static __always_inline bool inspect_ping_request(__u8 *start, const __u8 *end)
{
    struct mc_varint v;

    v = read_varint(start, end, 1);
    if (!v.bytes || v.value != 9)
        return false;
    start += v.bytes;

    v = read_varint(start, end, 1);
    if (!v.bytes || v.value != 1)
        return false;
    start += v.bytes;

    if (!consume_bytes(&start, end, 8))
        return false;

    return start == end;
}

static __always_inline bool inspect_login_packet(
    __u8 *start, const __u8 *end, __s32 protocol_version)
{
    struct mc_varint v;

    v = read_varint(start, end, MC_MAX_PACKET_LEN_BYTES);
    if (!v.bytes || v.value < 2 || v.value > (MC_MAX_PACKET_ID_BYTES + MC_LOGIN_NAME_MAX + 4096))
        return false;
    start += v.bytes;

    v = read_varint(start, end, 1);
    if (!v.bytes || v.value != 0)
        return false;
    start += v.bytes;

    v = read_varint(start, end, MC_MAX_PACKET_ID_BYTES);
    if (!v.bytes || v.value < 1 || v.value > MC_LOGIN_NAME_MAX)
        return false;
    start += v.bytes;
    if (!consume_bytes(&start, end, (__u32)v.value))
        return false;

    if (protocol_version >= 759 && protocol_version < 761) {
        __u8 has_public_key;

        if (!consume_bytes(&start, end, 1))
            return false;
        has_public_key = start[-1];
        if (has_public_key) {
            if (!consume_bytes(&start, end, 8))
                return false;

            v = read_varint(start, end, MC_MAX_PACKET_ID_BYTES);
            if (!v.bytes || v.value < 0 || v.value > MC_LOGIN_KEY_MAX)
                return false;
            start += v.bytes;
            if (!consume_bytes(&start, end, (__u32)v.value))
                return false;

            v = read_varint(start, end, MC_MAX_PACKET_ID_BYTES);
            if (!v.bytes || v.value < 0 || v.value > MC_LOGIN_SIGNATURE_MAX)
                return false;
            start += v.bytes;
            if (!consume_bytes(&start, end, (__u32)v.value))
                return false;
        }
    }

    if (protocol_version >= 760) {
        if (protocol_version >= 764) {
            if (!consume_bytes(&start, end, 16))
                return false;
        } else {
            __u8 has_uuid;

            if (!consume_bytes(&start, end, 1))
                return false;
            has_uuid = start[-1];
            if (has_uuid && !consume_bytes(&start, end, 16))
                return false;
        }
    }

    return start == end;
}

static __always_inline __s32 inspect_handshake(
    __u8 *start, const __u8 *end, __s32 *protocol_version, __u8 **next_ptr)
{
    struct mc_varint v;
    __s32 intention;
    __u8 support_transfer;

    if (start >= end)
        return 0;
    if (start[0] == 0xFE)
        return MC_LEGACY_PING;

    v = read_varint(start, end, MC_MAX_PACKET_LEN_BYTES);
    if (!v.bytes || v.value < 4 || v.value > (MC_MAX_PACKET_ID_BYTES + MC_HANDSHAKE_HOST_MAX + 16))
        return 0;
    start += v.bytes;

    v = read_varint(start, end, 1);
    if (!v.bytes || v.value != 0)
        return 0;
    start += v.bytes;

    v = read_varint(start, end, MC_MAX_PACKET_ID_BYTES);
    if (!v.bytes)
        return 0;
    *protocol_version = v.value;
    start += v.bytes;

    v = read_varint(start, end, MC_MAX_PACKET_ID_BYTES);
    if (!v.bytes || v.value < 0 || v.value > MC_HANDSHAKE_HOST_MAX)
        return 0;
    start += v.bytes;
    if (!consume_bytes(&start, end, (__u32)v.value))
        return 0;

    if (!consume_bytes(&start, end, 2))
        return 0;

    v = read_varint(start, end, 1);
    if (!v.bytes)
        return 0;
    intention = v.value;
    support_transfer = *protocol_version >= 766;

    if (!(intention == 1 || intention == 2 || (support_transfer && intention == 3)))
        return 0;
    start += v.bytes;

    if (start == end)
        return intention == 1 ? MC_AWAIT_STATUS_REQUEST : MC_AWAIT_LOGIN;

    *next_ptr = start;
    return intention == 1 ? MC_DIRECT_STATUS : MC_DIRECT_LOGIN;
}

SEC("xdp/minecraft")
int xdp_minecraft_handler(struct xdp_md *ctx)
{
    struct xdp_slot_ctx *sc = get_slot_ctx(ctx);
    struct flow_key key;
    struct tcphdr *tcp;
    struct mc_pending_val *pending;
    void *data;
    void *data_end;
    __u16 inner_off;
    __u8 family;
    __u32 dest_port;
    __u64 now;
    __u8 *payload;
    const __u8 *payload_end;
    __u32 payload_len;
    __u32 tcp_hdr_len;
    __u32 l4_and_payload_len;

    if (!sc || sc->ip_proto != IPPROTO_TCP)
        return XDP_PASS;

    inner_off = sc->inner_offset;
    family = sc->family;
    dest_port = (__u32)bpf_ntohs(sc->dport);
    fill_flow_key(&key, sc);

    if (family != CT_FAMILY_IPV4 && family != CT_FAMILY_IPV6)
        return XDP_PASS;

    /* Compute actual L4+payload length from the IP header *before* adjust_head.
     * data_end points to the physical Ethernet frame end, which may include
     * padding bytes added to meet the 64-byte minimum frame size.  Using
     * data_end directly would inflate payload_len and corrupt expected_seq. */
    {
        void *pre_data = (void *)(long)ctx->data;
        void *pre_data_end = (void *)(long)ctx->data_end;
        if (family == CT_FAMILY_IPV4) {
            struct iphdr *iph = (struct iphdr *)((char *)pre_data + sc->l3_offset);
            if ((void *)(iph + 1) > pre_data_end)
                return XDP_PASS;
            __u32 ip_tot    = (__u32)bpf_ntohs(iph->tot_len);
            __u32 ip_l4_off = (__u32)(sc->inner_offset - sc->l3_offset);
            l4_and_payload_len = ip_tot > ip_l4_off ? ip_tot - ip_l4_off : 0;
        } else {
            struct ipv6hdr *ip6h = (struct ipv6hdr *)((char *)pre_data + sc->l3_offset);
            if ((void *)(ip6h + 1) > pre_data_end)
                return XDP_PASS;
            __u32 ip6_hdr_and_ext = (__u32)(sc->inner_offset - sc->l3_offset);
            if (ip6_hdr_and_ext < 40u)
                return XDP_PASS;
            __u32 ip6_plen = (__u32)bpf_ntohs(ip6h->payload_len);
            __u32 ip6_ext  = ip6_hdr_and_ext - 40u;
            l4_and_payload_len = ip6_plen > ip6_ext ? ip6_plen - ip6_ext : 0;
        }
    }

    if (bpf_xdp_adjust_head(ctx, (int)inner_off))
        return XDP_PASS;

    data = (void *)(long)ctx->data;
    data_end = (void *)(long)ctx->data_end;
    tcp = data;

    if ((void *)(tcp + 1) > data_end)
        return restore_and_return(ctx, inner_off, XDP_DROP);
    if (tcp->doff < 5)
        return restore_and_return(ctx, inner_off, XDP_DROP);

    tcp_hdr_len = (__u32)tcp->doff * 4;
    if ((void *)tcp + tcp_hdr_len > data_end)
        return restore_and_return(ctx, inner_off, XDP_DROP);

    now = bpf_ktime_get_ns();

    if (tcp->syn && !tcp->ack) {
        struct mc_pending_val new_pending = {
            .last_seen_ns = now,
            .expected_seq = bpf_ntohl(tcp->seq) + 1,
            .protocol_version = 0,
            .state = MC_AWAIT_ACK,
            .fails = 0,
        };

        bpf_map_update_elem(&pending_mc, &key, &new_pending, BPF_ANY);
        if (family == CT_FAMILY_IPV4) {
            struct ct_key_v4 map_key;
            fill_ct_key_v4_map(&map_key, &key);
            bpf_map_update_elem(&tcp_pd4, &map_key, &dest_port, BPF_ANY);
        } else {
            struct ct_key_v6 map_key;
            fill_ct_key_v6_map(&map_key, &key);
            bpf_map_update_elem(&tcp_pd6, &map_key, &dest_port, BPF_ANY);
        }
        return restore_and_return(ctx, inner_off, XDP_PASS);
    }

    pending = bpf_map_lookup_elem(&pending_mc, &key);
    if (!pending)
        return restore_and_return(ctx, inner_off, XDP_DROP);

    if (now - pending->last_seen_ns > MC_TIMEOUT_NS)
        return drop_with_cleanup(ctx, inner_off, &key);

    payload = (__u8 *)tcp + tcp_hdr_len;
    if (l4_and_payload_len < tcp_hdr_len)
        return restore_and_return(ctx, inner_off, XDP_DROP);
    payload_len = l4_and_payload_len - tcp_hdr_len;
    payload_end = payload + payload_len;
    if ((void *)payload_end > data_end)
        return restore_and_return(ctx, inner_off, XDP_DROP);

    if (pending->state == MC_AWAIT_ACK) {
        if (!tcp->ack || pending->expected_seq != bpf_ntohl(tcp->seq)) {
            pending->last_seen_ns = now;
            return restore_and_return(ctx, inner_off, XDP_DROP);
        }

        pending->state = MC_AWAIT_HANDSHAKE;
        pending->last_seen_ns = now;

        if (payload_len == 0)
            return restore_and_return(ctx, inner_off, XDP_DROP);
    }

    if (payload_len > 0) {
        __u8 *cursor = payload;

        if (!tcp->ack)
            return penalize_and_drop(ctx, inner_off, &key, now);

        if (pending->expected_seq != bpf_ntohl(tcp->seq)) {
            if (pending->fails < 0xFFFF)
                pending->fails++;
            pending->last_seen_ns = now;
            if (pending->fails > MC_MAX_OUT_OF_ORDER)
                return penalize_and_drop(ctx, inner_off, &key, now);
            return restore_and_return(ctx, inner_off, XDP_DROP);
        }

        if (pending->state == MC_AWAIT_HANDSHAKE) {
            __s32 next_state = inspect_handshake(cursor, payload_end, &pending->protocol_version, &cursor);

            if (!next_state) {
                pending->last_seen_ns = now;
                return restore_and_return(ctx, inner_off, XDP_DROP);
            }
            if (next_state == MC_LEGACY_PING)
                return drop_with_cleanup(ctx, inner_off, &key);
            if (next_state == MC_DIRECT_STATUS)
                pending->state = MC_AWAIT_STATUS_REQUEST;
            else if (next_state == MC_DIRECT_LOGIN)
                pending->state = MC_AWAIT_LOGIN;
            else
                pending->state = (__u16)next_state;
        }

        if (pending->state == MC_AWAIT_STATUS_REQUEST) {
            if (!inspect_status_request(cursor, payload_end)) {
                pending->last_seen_ns = now;
                return restore_and_return(ctx, inner_off, XDP_DROP);
            }
            pending->state = MC_AWAIT_PING;
            pending->expected_seq += payload_len;
            pending->fails = 0;
            pending->last_seen_ns = now;
            return restore_and_return(ctx, inner_off, XDP_PASS);
        }

        if (pending->state == MC_AWAIT_PING) {
            if (!inspect_ping_request(cursor, payload_end)) {
                pending->last_seen_ns = now;
                return restore_and_return(ctx, inner_off, XDP_DROP);
            }
            pending->state = MC_PING_COMPLETE;
            pending->expected_seq += payload_len;
            pending->fails = 0;
            pending->last_seen_ns = now;
            return restore_and_return(ctx, inner_off, XDP_PASS);
        }

        if (pending->state == MC_AWAIT_LOGIN) {
            if (!inspect_login_packet(cursor, payload_end, pending->protocol_version)) {
                pending->last_seen_ns = now;
                return restore_and_return(ctx, inner_off, XDP_DROP);
            }
            return verify_and_pass(ctx, inner_off, &key, now);
        }

        if (pending->state == MC_PING_COMPLETE)
            return drop_with_cleanup(ctx, inner_off, &key);

        pending->expected_seq += payload_len;
        pending->fails = 0;
        pending->last_seen_ns = now;
        return restore_and_return(ctx, inner_off, XDP_PASS);
    }

    if (pending->state == MC_AWAIT_HANDSHAKE) {
        pending->last_seen_ns = now;
        return restore_and_return(ctx, inner_off, XDP_DROP);
    }

    pending->last_seen_ns = now;
    return restore_and_return(ctx, inner_off, XDP_PASS);
}

char _license[] SEC("license") = "GPL";
