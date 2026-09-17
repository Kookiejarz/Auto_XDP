// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/types.h>
#include <stdbool.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include "xdp_slot_ctx.h"
#include "xdp_profile_ctx.h"
#include "counters.h"
#include "flow_keys.h"
#include "map_sizes.h"
#include "minecraft.h"

#define MC_STATUS_RATE_WINDOW_NS (10ULL * 1000000000ULL)
#define MC_STATUS_RATE_MAX 30
#define MC_LOGIN_RATE_WINDOW_NS (60ULL * 1000000000ULL)
#define MC_LOGIN_RATE_MAX 10
#define MC_MAX_PACKET_ID_BYTES 5
#define MC_MAX_PACKET_LEN_BYTES 3
#define MC_HANDSHAKE_HOST_MAX (255 * 3)
#define MC_LOGIN_NAME_MAX (16 * 3)
#define MC_LOGIN_KEY_MAX 512
#define MC_LOGIN_SIGNATURE_MAX 4096

struct mc_rate_key_v4 { __be32 addr; __be16 dport; __u16 pad; };
struct mc_rate_key_v6 { __u32 addr[4]; __be16 dport; __u16 pad; };
struct mc_rate_val { __u64 state; };
struct mc_varint { __s32 value; __u8 bytes; __u8 result; };
struct mc_frame { __u8 *body; const __u8 *end; };

#define MC_RATE_MAP(name, key_type, entries)                     \
    struct {                                                     \
        __uint(type, BPF_MAP_TYPE_LRU_HASH);                    \
        __uint(max_entries, entries);                           \
        __type(key, key_type);                                  \
        __type(value, struct mc_rate_val);                      \
    } name SEC(".maps")

MC_RATE_MAP(mc_status_rate4, struct mc_rate_key_v4, RATE_MAP_MAX_ENTRIES_V4);
MC_RATE_MAP(mc_status_rate6, struct mc_rate_key_v6, RATE_MAP_MAX_ENTRIES_V6);
MC_RATE_MAP(mc_login_rate4, struct mc_rate_key_v4, RATE_MAP_MAX_ENTRIES_V4);
MC_RATE_MAP(mc_login_rate6, struct mc_rate_key_v6, RATE_MAP_MAX_ENTRIES_V6);

static __always_inline int profile_result(struct xdp_md *ctx, __u16 inner_off, int action)
{
    __u32 pkt_len = (__u32)((char *)(long)ctx->data_end -
                            (char *)(long)ctx->data) + inner_off;
    if (inner_off && action != XDP_DROP && bpf_xdp_adjust_head(ctx, -(int)inner_off))
        action = XDP_DROP;
    count(action == XDP_PASS ? CNT_PROFILE_ALLOW : CNT_PROFILE_DROP);
    count_bytes(action == XDP_DROP, pkt_len);
    return action;
}

static __always_inline int profile_drop(struct xdp_md *ctx)
{
    __u32 pkt_len = (__u32)((char *)(long)ctx->data_end -
                            (char *)(long)ctx->data);
    count(CNT_PROFILE_DROP);
    count_bytes(true, pkt_len);
    return XDP_DROP;
}

static __always_inline void fill_flow_key(struct flow_key *key, const struct xdp_slot_ctx *sc)
{
    __builtin_memset(key, 0, sizeof(*key));
    key->family = sc->family;
    key->sport = sc->sport;
    key->dport = sc->dport;
    __builtin_memcpy(key->saddr, sc->saddr, sizeof(key->saddr));
    __builtin_memcpy(key->daddr, sc->daddr, sizeof(key->daddr));
}

static __always_inline void cleanup_pending(const struct flow_key *key)
{
    bpf_map_delete_elem(&mc_l7_pending, key);
}

#define MC_RATE_TICK_NS 1000000ULL
#define MC_RATE_RETRIES 8
#define MC_RATE_CHECK(map, key, now, window_ns, max_count, over_limit)               \
    do {                                                                             \
        (over_limit) = true;                                                         \
        __u32 _now_tick = (__u32)((now) / MC_RATE_TICK_NS);                         \
        __u64 _ticks64 = (window_ns) / MC_RATE_TICK_NS;                             \
        __u32 _window_ticks = _ticks64 > 0x7fffffffULL ? 0x7fffffffU                \
                                                        : (__u32)_ticks64;           \
        if (!_window_ticks) _window_ticks = 1;                                      \
        for (int _attempt = 0; _attempt < MC_RATE_RETRIES; _attempt++) {             \
            struct mc_rate_val *_v = bpf_map_lookup_elem((map), (key));             \
            if (!_v) {                                                               \
                struct mc_rate_val _init = {                                         \
                    .state = ((__u64)_now_tick << 32) | 1ULL,                        \
                };                                                                   \
                if (!bpf_map_update_elem((map), (key), &_init, BPF_NOEXIST)) {       \
                    (over_limit) = false; break;                                     \
                }                                                                    \
                continue;                                                            \
            }                                                                        \
            __u64 _current = __sync_fetch_and_add(&_v->state, 0);                   \
            __u32 _start_tick = (__u32)(_current >> 32);                            \
            __u32 _count = (__u32)_current;                                          \
            __u32 _next_tick = _start_tick, _next_count;                            \
            if ((__u32)(_now_tick - _start_tick) >= _window_ticks) {                \
                _next_tick = _now_tick; _next_count = 1;                            \
            } else {                                                                 \
                if (_count >= (__u32)(max_count)) break;                            \
                _next_count = _count + 1;                                            \
            }                                                                        \
            __u64 _next = ((__u64)_next_tick << 32) | _next_count;                  \
            if (__sync_val_compare_and_swap(&_v->state, _current, _next) == _current) { \
                (over_limit) = false; break;                                         \
            }                                                                        \
        }                                                                            \
    } while (0)

static __always_inline bool mc_rate_exceeded(
    const struct flow_key *key, __u64 now, void *rate4, void *rate6,
    __u64 window_ns, __u32 max_count)
{
    bool over_limit;
    if (key->family == CT_FAMILY_IPV4) {
        struct mc_rate_key_v4 rate_key = {
            .addr = (__be32)key->saddr[0], .dport = key->dport,
        };
        MC_RATE_CHECK(rate4, &rate_key, now, window_ns, max_count, over_limit);
    } else {
        struct mc_rate_key_v6 rate_key = { .dport = key->dport };
        __builtin_memcpy(rate_key.addr, key->saddr, sizeof(rate_key.addr));
        MC_RATE_CHECK(rate6, &rate_key, now, window_ns, max_count, over_limit);
    }
    return over_limit;
}

#define MC_VARINT_BYTE(ptr, end, data_end, max, idx, shift, value)            \
    do {                                                                      \
        if ((idx) > (max))                                                    \
            return (struct mc_varint){ .result = MC_PARSE_NO_MATCH };        \
        if ((ptr) >= (end))                                                   \
            return (struct mc_varint){ .result = MC_PARSE_NEED_MORE };       \
        barrier_var(ptr);                                                     \
        __u8 *_next = (ptr) + 1;                                              \
        if ((const void *)_next > (data_end))                                \
            return (struct mc_varint){ .result = MC_PARSE_NO_MATCH };        \
        __u8 _byte = *(_next - 1);                                            \
        (ptr) = _next;                                                        \
        (value) |= ((__s32)(_byte & 0x7f) << (shift));                       \
        if (!(_byte & 0x80))                                                  \
            return (struct mc_varint){                                        \
                .value = (value), .bytes = (idx), .result = MC_PARSE_MATCH,  \
            };                                                               \
    } while (0)

static __always_inline struct mc_varint read_varint(
    __u8 *ptr, const __u8 *end, __u8 max_bytes, const void *data_end)
{
    __s32 value = 0;
    MC_VARINT_BYTE(ptr, end, data_end, max_bytes, 1, 0, value);
    MC_VARINT_BYTE(ptr, end, data_end, max_bytes, 2, 7, value);
    MC_VARINT_BYTE(ptr, end, data_end, max_bytes, 3, 14, value);
    MC_VARINT_BYTE(ptr, end, data_end, max_bytes, 4, 21, value);
    MC_VARINT_BYTE(ptr, end, data_end, max_bytes, 5, 28, value);
    return (struct mc_varint){ .result = MC_PARSE_NO_MATCH };
}

static __always_inline enum mc_parse_result read_frame(
    __u8 *start, const __u8 *segment_end, __u32 max_len,
    const void *data_end, struct mc_frame *frame)
{
    struct mc_varint length = read_varint(
        start, segment_end, MC_MAX_PACKET_LEN_BYTES, data_end);
    __u32 packet_len;
    if (length.result != MC_PARSE_MATCH) return length.result;
    if (length.value < 1) return MC_PARSE_NO_MATCH;
    start += length.bytes;
    packet_len = (__u32)length.value;
    barrier_var(packet_len);
    if (packet_len > max_len) return MC_PARSE_NO_MATCH;
    if (start + packet_len > segment_end) return MC_PARSE_NEED_MORE;
    if ((const void *)(start + packet_len) > data_end) return MC_PARSE_NO_MATCH;
    frame->body = start;
    frame->end = start + packet_len;
    return MC_PARSE_MATCH;
}

static __always_inline enum mc_parse_result read_required_varint(
    __u8 **ptr, const __u8 *end, __u8 max_bytes, const void *data_end, __s32 *out)
{
    struct mc_varint value = read_varint(*ptr, end, max_bytes, data_end);
    if (value.result != MC_PARSE_MATCH) return MC_PARSE_NO_MATCH;
    *out = value.value;
    *ptr += value.bytes;
    return MC_PARSE_MATCH;
}

static __always_inline bool consume_bytes(
    __u8 **ptr, const __u8 *end, __u32 length, const void *data_end)
{
    __u8 *cursor = *ptr;
    barrier_var(length);
    length &= 0x1fff;
    if (cursor + length > end) return false;
    barrier_var(cursor);
    if ((const void *)(cursor + length) > data_end) return false;
    *ptr = cursor + length;
    return true;
}

static __always_inline enum mc_parse_result parse_handshake(
    __u8 *start, const __u8 *segment_end, __s32 *protocol_version,
    __u8 *intention, __u8 **next, const void *data_end)
{
    struct mc_frame frame;
    __u8 *cursor;
    __s32 value;
    enum mc_parse_result result = read_frame(
        start, segment_end, MC_MAX_PACKET_ID_BYTES + MC_HANDSHAKE_HOST_MAX + 16,
        data_end, &frame);
    if (result != MC_PARSE_MATCH) return result;
    cursor = frame.body;
    if (read_required_varint(&cursor, frame.end, 1, data_end, &value) != MC_PARSE_MATCH || value != 0)
        return MC_PARSE_NO_MATCH;
    if (read_required_varint(&cursor, frame.end, MC_MAX_PACKET_ID_BYTES, data_end, protocol_version) != MC_PARSE_MATCH)
        return MC_PARSE_NO_MATCH;
    if (read_required_varint(&cursor, frame.end, MC_MAX_PACKET_ID_BYTES, data_end, &value) != MC_PARSE_MATCH ||
        value < 0 || value > MC_HANDSHAKE_HOST_MAX ||
        !consume_bytes(&cursor, frame.end, (__u32)value, data_end) ||
        !consume_bytes(&cursor, frame.end, 2, data_end))
        return MC_PARSE_NO_MATCH;
    if (read_required_varint(&cursor, frame.end, 1, data_end, &value) != MC_PARSE_MATCH ||
        !(value == 1 || value == 2 || (*protocol_version >= 766 && value == 3)) ||
        cursor != frame.end)
        return MC_PARSE_NO_MATCH;
    *intention = (__u8)value;
    *next = (__u8 *)frame.end;
    return MC_PARSE_MATCH;
}

static __always_inline enum mc_parse_result parse_empty_packet(
    __u8 *start, const __u8 *segment_end, __s32 packet_id, const void *data_end)
{
    struct mc_frame frame;
    __u8 *cursor;
    __s32 value;
    enum mc_parse_result result = read_frame(start, segment_end, 16, data_end, &frame);
    if (result != MC_PARSE_MATCH) return result;
    cursor = frame.body;
    if (read_required_varint(&cursor, frame.end, 1, data_end, &value) != MC_PARSE_MATCH)
        return MC_PARSE_NO_MATCH;
    return value == packet_id && cursor == frame.end && frame.end == segment_end
        ? MC_PARSE_MATCH : MC_PARSE_NO_MATCH;
}

static __always_inline enum mc_parse_result parse_ping(
    __u8 *start, const __u8 *segment_end, const void *data_end)
{
    struct mc_frame frame;
    __u8 *cursor;
    __s32 packet_id;
    enum mc_parse_result result = read_frame(start, segment_end, 16, data_end, &frame);
    if (result != MC_PARSE_MATCH) return result;
    cursor = frame.body;
    if (read_required_varint(&cursor, frame.end, 1, data_end, &packet_id) != MC_PARSE_MATCH ||
        packet_id != 1 || !consume_bytes(&cursor, frame.end, 8, data_end))
        return MC_PARSE_NO_MATCH;
    return cursor == frame.end && frame.end == segment_end ? MC_PARSE_MATCH : MC_PARSE_NO_MATCH;
}

static __always_inline enum mc_parse_result parse_login_start(
    __u8 *start, const __u8 *segment_end, __s32 protocol_version, const void *data_end)
{
    struct mc_frame frame;
    __u8 *cursor;
    __s32 value;
    __u8 flag;
    enum mc_parse_result result = read_frame(
        start, segment_end, MC_MAX_PACKET_ID_BYTES + MC_LOGIN_NAME_MAX + 4096,
        data_end, &frame);
    if (result != MC_PARSE_MATCH) return result;
    cursor = frame.body;
    if (read_required_varint(&cursor, frame.end, 1, data_end, &value) != MC_PARSE_MATCH || value != 0 ||
        read_required_varint(&cursor, frame.end, MC_MAX_PACKET_ID_BYTES, data_end, &value) != MC_PARSE_MATCH ||
        value < 1 || value > MC_LOGIN_NAME_MAX ||
        !consume_bytes(&cursor, frame.end, (__u32)value, data_end))
        return MC_PARSE_NO_MATCH;
    if (protocol_version >= 759 && protocol_version < 761) {
        if (!consume_bytes(&cursor, frame.end, 1, data_end)) return MC_PARSE_NO_MATCH;
        flag = *(cursor - 1);
        if (flag && (!consume_bytes(&cursor, frame.end, 8, data_end) ||
            read_required_varint(&cursor, frame.end, MC_MAX_PACKET_ID_BYTES, data_end, &value) != MC_PARSE_MATCH ||
            value < 0 || value > MC_LOGIN_KEY_MAX ||
            !consume_bytes(&cursor, frame.end, (__u32)value, data_end) ||
            read_required_varint(&cursor, frame.end, MC_MAX_PACKET_ID_BYTES, data_end, &value) != MC_PARSE_MATCH ||
            value < 0 || value > MC_LOGIN_SIGNATURE_MAX ||
            !consume_bytes(&cursor, frame.end, (__u32)value, data_end)))
            return MC_PARSE_NO_MATCH;
    }
    if (protocol_version >= 760) {
        if (protocol_version >= 764) {
            if (!consume_bytes(&cursor, frame.end, 16, data_end)) return MC_PARSE_NO_MATCH;
        } else {
            if (!consume_bytes(&cursor, frame.end, 1, data_end)) return MC_PARSE_NO_MATCH;
            flag = *(cursor - 1);
            if (flag && !consume_bytes(&cursor, frame.end, 16, data_end)) return MC_PARSE_NO_MATCH;
        }
    }
    return cursor == frame.end && frame.end == segment_end ? MC_PARSE_MATCH : MC_PARSE_NO_MATCH;
}

static __always_inline enum mc_parse_result parse_encryption_response(
    __u8 *start, const __u8 *segment_end, const void *data_end)
{
    struct mc_frame frame;
    __u8 *cursor;
    __s32 value;
    enum mc_parse_result result = read_frame(start, segment_end, 2048, data_end, &frame);
    if (result != MC_PARSE_MATCH) return result;
    cursor = frame.body;
    if (read_required_varint(&cursor, frame.end, 1, data_end, &value) != MC_PARSE_MATCH || value != 1)
        return MC_PARSE_NO_MATCH;
#pragma unroll
    for (int field = 0; field < 2; field++) {
        if (read_required_varint(&cursor, frame.end, MC_MAX_PACKET_ID_BYTES, data_end, &value) != MC_PARSE_MATCH ||
            value < 1 || value > MC_LOGIN_KEY_MAX ||
            !consume_bytes(&cursor, frame.end, (__u32)value, data_end))
            return MC_PARSE_NO_MATCH;
    }
    return cursor == frame.end && frame.end == segment_end ? MC_PARSE_MATCH : MC_PARSE_NO_MATCH;
}

static __always_inline bool pending_budget_ok(
    struct mc_l7_pending_val *pending, __u32 payload_len, __u64 now)
{
    if (now >= pending->hard_deadline_ns || pending->packets >= MC_PREVERIFY_PACKETS ||
        pending->ingress_bytes >= MC_PREVERIFY_BYTES ||
        payload_len > MC_PREVERIFY_BYTES - pending->ingress_bytes)
        return false;
    pending->packets++;
    pending->ingress_bytes += payload_len;
    return true;
}

SEC("xdp/minecraft")
int xdp_minecraft_handler(struct xdp_md *ctx)
{
    struct xdp_slot_ctx *sc = get_slot_ctx(ctx);
    struct xdp_profile_ctx *profile = get_profile_ctx();
    struct linux_ct_snapshot snapshot;
    struct bpf_ct_opts___local opts;
    struct bpf_sock_tuple tuple;
    struct mc_l7_pending_val *pending;
    struct flow_key key;
    struct nf_conn *ct;
    struct tcphdr *tcp;
    void *data, *data_end;
    __u32 l3_off, inner_off_u32, l4_len, tcp_hdr_len, payload_len;
    __u16 inner_off;
    __u8 *payload;
    const __u8 *payload_end;
    __u64 now;

    if (!sc || !profile || sc->ip_proto != IPPROTO_TCP ||
        profile->profile_id != MC_PROFILE_ID || !profile->policy_generation ||
        !profile->profile_generation)
        return profile_drop(ctx);
    l3_off = (__u32)sc->l3_offset;
    inner_off_u32 = (__u32)sc->inner_offset;
    if (l3_off > 255 || inner_off_u32 > 255 ||
        (sc->family != CT_FAMILY_IPV4 && sc->family != CT_FAMILY_IPV6))
        return profile_drop(ctx);
    if ((sc->family == CT_FAMILY_IPV4 && inner_off_u32 < l3_off + 20U) ||
        (sc->family == CT_FAMILY_IPV6 && inner_off_u32 < l3_off + 40U))
        return profile_drop(ctx);

    fill_flow_key(&key, sc);
    inner_off = (__u16)inner_off_u32;
    {
        void *pre_data = (void *)(long)ctx->data;
        void *pre_end = (void *)(long)ctx->data_end;
        if (sc->family == CT_FAMILY_IPV4) {
            struct iphdr *ip = (struct iphdr *)((char *)pre_data + l3_off);
            if ((void *)(ip + 1) > pre_end) return profile_drop(ctx);
            __u32 total = (__u32)bpf_ntohs(ip->tot_len);
            __u32 offset = inner_off_u32 - l3_off;
            l4_len = total > offset ? total - offset : 0;
        } else {
            struct ipv6hdr *ip6 = (struct ipv6hdr *)((char *)pre_data + l3_off);
            if ((void *)(ip6 + 1) > pre_end) return profile_drop(ctx);
            __u32 ext_len = inner_off_u32 - l3_off - 40U;
            __u32 total = (__u32)bpf_ntohs(ip6->payload_len);
            l4_len = total > ext_len ? total - ext_len : 0;
        }
    }
    if (bpf_xdp_adjust_head(ctx, (int)inner_off)) return profile_drop(ctx);
    data = (void *)(long)ctx->data;
    data_end = (void *)(long)ctx->data_end;
    tcp = data;
    if ((void *)(tcp + 1) > data_end || tcp->doff < 5)
        return profile_result(ctx, inner_off, XDP_DROP);
    tcp_hdr_len = (__u32)tcp->doff * 4U;
    if ((void *)tcp + tcp_hdr_len > data_end || l4_len < tcp_hdr_len)
        return profile_result(ctx, inner_off, XDP_DROP);

    now = bpf_ktime_get_ns();
    if (tcp->syn && !tcp->ack) {
        cleanup_pending(&key);
        return profile_result(ctx, inner_off, XDP_PASS);
    }
    linux_ct_fill_tuple(&tuple, &key);
    opts = linux_ct_opts();
    ct = bpf_xdp_ct_lookup(ctx, &tuple, linux_ct_tuple_size(&key), &opts, sizeof(opts));
    if (!ct) return profile_result(ctx, inner_off, XDP_DROP);
    linux_ct_snapshot(ct, opts.dir, &snapshot);
    if (snapshot.dir != NF_CT_DIR_ORIGINAL) {
        bpf_ct_release(ct);
        return profile_result(ctx, inner_off, XDP_DROP);
    }
    if (tcp->fin || tcp->rst) {
        bpf_ct_release(ct);
        cleanup_pending(&key);
        return profile_result(ctx, inner_off, XDP_PASS);
    }
    if (!linux_ct_established(&snapshot)) {
        bool third_handshake_ack =
            (snapshot.status & IPS_CONFIRMED_LOCAL) &&
            snapshot.tcp_state == TCP_CONNTRACK_SYN_RECV_LOCAL && tcp->ack;
        bpf_ct_release(ct);
        if (!third_handshake_ack)
            return profile_result(ctx, inner_off, XDP_DROP);
        if (l4_len == tcp_hdr_len)
            return profile_result(ctx, inner_off, XDP_PASS);
    } else if (mc_mark_valid(snapshot.mark, profile->profile_generation,
                             MC_PROOF_WIRE_VERIFIED)) {
        bpf_ct_release(ct);
        return profile_result(ctx, inner_off, XDP_PASS);
    } else {
        bpf_ct_release(ct);
    }

    payload_len = l4_len - tcp_hdr_len;
    payload = (__u8 *)tcp + tcp_hdr_len;
    payload_end = payload + payload_len;
    if ((void *)payload_end > data_end) return profile_result(ctx, inner_off, XDP_DROP);
    pending = bpf_map_lookup_elem(&mc_l7_pending, &key);
    if (pending && (pending->policy_generation != profile->policy_generation ||
                    pending->profile_generation != profile->profile_generation)) {
        cleanup_pending(&key);
        pending = NULL;
    }
    if (!payload_len)
        return profile_result(ctx, inner_off, pending && now >= pending->hard_deadline_ns
                              ? XDP_DROP : XDP_PASS);
    if (!pending) {
        struct mc_l7_pending_val initial = {
            .first_seen_ns = now,
            .hard_deadline_ns = now + MC_PROTOCOL_DEADLINE_NS,
            .policy_generation = profile->policy_generation,
            .profile_generation = profile->profile_generation,
            .state = MC_L7_HANDSHAKE,
        };
        if (bpf_map_update_elem(&mc_l7_pending, &key, &initial, BPF_NOEXIST))
            return profile_result(ctx, inner_off, XDP_DROP);
        pending = bpf_map_lookup_elem(&mc_l7_pending, &key);
        if (!pending) return profile_result(ctx, inner_off, XDP_DROP);
    }
    if (!pending_budget_ok(pending, payload_len, now)) {
        cleanup_pending(&key);
        return profile_result(ctx, inner_off, XDP_DROP);
    }

    if (pending->state == MC_L7_HANDSHAKE) {
        __u8 *next = payload;
        __u8 intention = 0;
        __u32 consumed;
        enum mc_parse_result result = parse_handshake(
            payload, payload_end, &pending->protocol_version, &intention, &next, data_end);
        if (result == MC_PARSE_NEED_MORE) {
            pending->state = MC_L7_OPAQUE_PROBATION;
            pending->hard_deadline_ns = pending->first_seen_ns + MC_OPAQUE_DEADLINE_NS;
            return profile_result(ctx, inner_off, XDP_PASS);
        }
        if (result != MC_PARSE_MATCH) {
            cleanup_pending(&key);
            return profile_result(ctx, inner_off, XDP_DROP);
        }
        pending->intention = intention;
        pending->proof_level = MC_PROOF_HANDSHAKE;
        pending->state = intention == 1 ? MC_L7_STATUS_REQUEST : MC_L7_LOGIN_START;
        consumed = (__u32)(next - payload);
        barrier_var(consumed);
        if (consumed > MC_MAX_PACKET_LEN_BYTES + MC_MAX_PACKET_ID_BYTES +
                       MC_HANDSHAKE_HOST_MAX + 16 || consumed > payload_len) {
            cleanup_pending(&key);
            return profile_result(ctx, inner_off, XDP_DROP);
        }
        if (consumed == payload_len) return profile_result(ctx, inner_off, XDP_PASS);
        payload += consumed;
        if (intention == 1) goto parse_status_request;
        goto parse_login_start;
    }
    if (pending->state == MC_L7_STATUS_REQUEST) {
parse_status_request: ;
        enum mc_parse_result result = parse_empty_packet(payload, payload_end, 0, data_end);
        if (result == MC_PARSE_NEED_MORE) return profile_result(ctx, inner_off, XDP_PASS);
        if (result != MC_PARSE_MATCH ||
            mc_rate_exceeded(&key, now, &mc_status_rate4, &mc_status_rate6,
                             MC_STATUS_RATE_WINDOW_NS, MC_STATUS_RATE_MAX)) {
            cleanup_pending(&key);
            return profile_result(ctx, inner_off, XDP_DROP);
        }
        pending->state = MC_L7_STATUS_PING;
        return profile_result(ctx, inner_off, XDP_PASS);
    }
    if (pending->state == MC_L7_STATUS_PING) {
        enum mc_parse_result result = parse_ping(payload, payload_end, data_end);
        if (result == MC_PARSE_NEED_MORE) return profile_result(ctx, inner_off, XDP_PASS);
        if (result != MC_PARSE_MATCH) {
            cleanup_pending(&key);
            return profile_result(ctx, inner_off, XDP_DROP);
        }
        pending->state = MC_L7_STATUS_DONE;
        return profile_result(ctx, inner_off, XDP_PASS);
    }
    if (pending->state == MC_L7_STATUS_DONE) {
        cleanup_pending(&key);
        return profile_result(ctx, inner_off, XDP_DROP);
    }
    if (pending->state == MC_L7_LOGIN_START) {
parse_login_start: ;
        enum mc_parse_result result = parse_login_start(
            payload, payload_end, pending->protocol_version, data_end);
        if (result == MC_PARSE_NEED_MORE) {
            pending->state = MC_L7_OPAQUE_PROBATION;
            pending->hard_deadline_ns = pending->first_seen_ns + MC_OPAQUE_DEADLINE_NS;
            return profile_result(ctx, inner_off, XDP_PASS);
        }
        if (result != MC_PARSE_MATCH ||
            mc_rate_exceeded(&key, now, &mc_login_rate4, &mc_login_rate6,
                             MC_LOGIN_RATE_WINDOW_NS, MC_LOGIN_RATE_MAX)) {
            cleanup_pending(&key);
            return profile_result(ctx, inner_off, XDP_DROP);
        }
        pending->proof_level = MC_PROOF_LOGIN_START;
        pending->state = MC_L7_AWAIT_SERVER;
        return profile_result(ctx, inner_off, XDP_PASS);
    }
    if (pending->state == MC_L7_SERVER_CHALLENGE) {
        enum mc_parse_result result = parse_encryption_response(payload, payload_end, data_end);
        if (result == MC_PARSE_NEED_MORE) return profile_result(ctx, inner_off, XDP_PASS);
        if (result != MC_PARSE_MATCH) {
            cleanup_pending(&key);
            return profile_result(ctx, inner_off, XDP_DROP);
        }
        pending->state = MC_L7_ENCRYPTED_PROBATION;
        pending->proof_level = MC_PROOF_SERVER_PROGRESS;
        pending->challenge_at_ns = now;
        pending->hard_deadline_ns = pending->first_seen_ns + MC_CHALLENGE_DEADLINE_NS;
        return profile_result(ctx, inner_off, XDP_PASS);
    }
    if (pending->state == MC_L7_ENCRYPTED_PROBATION &&
        (pending->flags & MC_F_SERVER_AFTER_CHALLENGE) &&
        now - pending->challenge_at_ns >= MC_POST_CHALLENGE_MIN_NS) {
        opts = linux_ct_opts();
        ct = bpf_xdp_ct_lookup(ctx, &tuple, linux_ct_tuple_size(&key), &opts, sizeof(opts));
        if (!ct) return profile_result(ctx, inner_off, XDP_DROP);
        linux_ct_snapshot(ct, opts.dir, &snapshot);
        if (snapshot.dir == NF_CT_DIR_ORIGINAL && linux_ct_established(&snapshot)) {
            mc_mark_conn(ct, profile->profile_generation, MC_PROOF_WIRE_VERIFIED);
            bpf_ct_release(ct);
            cleanup_pending(&key);
            return profile_result(ctx, inner_off, XDP_PASS);
        }
        bpf_ct_release(ct);
        return profile_result(ctx, inner_off, XDP_DROP);
    }
    return profile_result(ctx, inner_off, XDP_PASS);
}

char _license[] SEC("license") = "GPL";
