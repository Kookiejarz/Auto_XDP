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
#include "common.h"
#include "flow_keys.h"
#include "map_sizes.h"
#include "minecraft_state.h"
#include "handler_state.h"

#include "tc_handler_ctx.h"

AXDP_STATE_SCHEMA("minecraft-session-v1",
    "[\"mc_l7_pending\",\"mc_verified\",\"mc_status_rate4\",\"mc_status_rate6\","
    "\"mc_login_rate4\",\"mc_login_rate6\"]");

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

static __always_inline void emit_profile_drop(struct xdp_md *ctx, __u32 pkt_len)
{
    __u32 zero = 0;
    struct xdp_slot_ctx *sc = bpf_map_lookup_elem(&slot_ctx_map, &zero);
    __u32 unknown[4] = {};
    emit_packet_event(ctx, pkt_len, IPPROTO_TCP, sc ? sc->family : 0,
                      sc ? sc->saddr : unknown, sc ? sc->daddr : unknown,
                      sc ? sc->sport : 0, sc ? sc->dport : 0,
                      1, CNT_PROFILE_DROP, bpf_ktime_get_ns());
}

static __always_inline int profile_result(struct xdp_md *ctx, __u16 inner_off, int action)
{
    __u32 pkt_len = (__u32)((char *)(long)ctx->data_end -
                            (char *)(long)ctx->data) + inner_off;
    if (inner_off && action != XDP_DROP && bpf_xdp_adjust_head(ctx, -(int)inner_off))
        action = XDP_DROP;
    count(action == XDP_PASS ? CNT_PROFILE_ALLOW : CNT_PROFILE_DROP);
    count_bytes(action == XDP_DROP, pkt_len);
    if (action == XDP_DROP)
        emit_profile_drop(ctx, pkt_len);
    return action;
}

static __always_inline int profile_drop(struct xdp_md *ctx)
{
    __u32 pkt_len = (__u32)((char *)(long)ctx->data_end -
                            (char *)(long)ctx->data);
    count(CNT_PROFILE_DROP);
    count_bytes(true, pkt_len);
    emit_profile_drop(ctx, pkt_len);
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

SEC("xdp")
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
    linux_ct_fill_tuple(&tuple, &key);
    opts = linux_ct_opts(IPPROTO_TCP);
    ct = bpf_xdp_ct_lookup(ctx, &tuple, linux_ct_tuple_size(&key), &opts, sizeof(opts));
    if (tcp->syn && !tcp->ack) {
        bool live = false;
        if (ct) {
            linux_ct_snapshot(ct, opts.dir, &snapshot);
            live = linux_ct_established(&snapshot);
            bpf_ct_release(ct);
        }
        if (l4_len != tcp_hdr_len)
            return profile_result(ctx, inner_off, XDP_DROP);
        /* A SYN aimed at an existing connection must not erase its proof or
         * revive revoked authorization. Linux owns actual tuple reuse. */
        if (!live) {
            cleanup_pending(&key);
            bpf_map_delete_elem(&mc_verified, &key);
        }
        return profile_result(ctx, inner_off, XDP_PASS);
    }
    if (!ct) return profile_result(ctx, inner_off, XDP_DROP);
    linux_ct_snapshot(ct, opts.dir, &snapshot);
    if (snapshot.dir != NF_CT_DIR_ORIGINAL) {
        bpf_ct_release(ct);
        return profile_result(ctx, inner_off, XDP_DROP);
    }
    if ((tcp->fin || tcp->rst) && l4_len == tcp_hdr_len) {
        bpf_ct_release(ct);
        cleanup_pending(&key);
        bpf_map_delete_elem(&mc_verified, &key);
        return profile_result(ctx, inner_off, XDP_PASS);
    }
    struct mc_verified_val *verified = bpf_map_lookup_elem(&mc_verified, &key);
    if (verified || (snapshot.mark & MC_MARK_MAGIC_MASK) == MC_MARK_MAGIC) {
        bool admitted = linux_ct_established(&snapshot) &&
            mc_verified_matches(verified, snapshot.mark,
                                profile->policy_generation, profile->profile_generation);
        bpf_ct_release(ct);
        /* Lost/revoked proof is not a new handshake or opaque probation. */
        return profile_result(ctx, inner_off, admitted ? XDP_PASS : XDP_DROP);
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
        opts = linux_ct_opts(IPPROTO_TCP);
        ct = bpf_xdp_ct_lookup(ctx, &tuple, linux_ct_tuple_size(&key), &opts, sizeof(opts));
        if (!ct) return profile_result(ctx, inner_off, XDP_DROP);
        linux_ct_snapshot(ct, opts.dir, &snapshot);
        if (snapshot.dir == NF_CT_DIR_ORIGINAL && linux_ct_established(&snapshot)) {
            bool admitted = mc_mark_conn(ct, &key, profile->policy_generation,
                                        profile->profile_generation, MC_PROOF_WIRE_VERIFIED);
            bpf_ct_release(ct);
            if (admitted)
                cleanup_pending(&key);
            return profile_result(ctx, inner_off, admitted ? XDP_PASS : XDP_DROP);
        }
        bpf_ct_release(ct);
        return profile_result(ctx, inner_off, XDP_DROP);
    }
    return profile_result(ctx, inner_off, XDP_PASS);
}


/* The service was selected by the generic TC dispatcher. Only Minecraft
 * framing and dialogue state belong in this entry. */
#define MC_SERVER_FRAME_MAX 8192U
#define MC_SERVER_VARINT_MAX 5
#define MC_SERVER_PACKET_LEN_MAX 3

struct tc_mc_varint {
    __s32 value;
    __u8 bytes;
};

static __always_inline struct tc_mc_varint tc_varint(
    __u8 *ptr, const __u8 *end, __u8 max_bytes, const void *data_end)
{
    __s32 value = 0;
#define TC_MC_BYTE(index, shift)                                      \
    do {                                                              \
        if ((index) > max_bytes || ptr >= end)                        \
            return (struct tc_mc_varint){};                           \
        barrier_var(ptr);                                             \
        __u8 *next = ptr + 1;                                         \
        if ((const void *)next > data_end)                            \
            return (struct tc_mc_varint){};                           \
        __u8 byte = *(next - 1);                                      \
        ptr = next;                                                    \
        value |= ((__s32)(byte & 0x7f) << (shift));                  \
        if (!(byte & 0x80))                                           \
            return (struct tc_mc_varint){ .value = value, .bytes = index }; \
    } while (0)
    TC_MC_BYTE(1, 0);
    TC_MC_BYTE(2, 7);
    TC_MC_BYTE(3, 14);
    TC_MC_BYTE(4, 21);
    TC_MC_BYTE(5, 28);
#undef TC_MC_BYTE
    return (struct tc_mc_varint){};
}

static __always_inline int inspect_server_frame(
    __u8 *payload, const __u8 *payload_end, const void *data_end,
    struct mc_l7_pending_val *pending)
{
    struct tc_mc_varint value = tc_varint(
        payload, payload_end, MC_SERVER_PACKET_LEN_MAX, data_end);
    __u8 *cursor;
    const __u8 *frame_end;
    __u32 frame_len;

    if (!value.bytes || value.value < 1)
        return -1;
    payload += value.bytes;
    frame_len = (__u32)value.value;
    barrier_var(frame_len);
    if (frame_len > MC_SERVER_FRAME_MAX)
        return -1;
    frame_end = payload + frame_len;
    if (frame_end > payload_end || (const void *)frame_end > data_end)
        return -1;
    cursor = payload;

    if (pending->flags & MC_F_COMPRESSION_ENABLED) {
        value = tc_varint(cursor, frame_end, MC_SERVER_VARINT_MAX, data_end);
        if (!value.bytes)
            return -1;
        cursor += value.bytes;
        if (value.value != 0)
            return -1; /* zlib-compressed body is intentionally opaque to BPF */
    }
    value = tc_varint(cursor, frame_end, MC_SERVER_VARINT_MAX, data_end);
    if (!value.bytes)
        return -1;
    return value.value;
}

SEC("tc")
int tc_minecraft_handler(struct __sk_buff *skb)
{
    struct tc_handler_ctx *policy = get_tc_handler_ctx(skb);
    if (!policy || policy->kind != HANDLER_ROUTE_PROFILE ||
        policy->target != MC_PROFILE_ID || policy->ip_proto != IPPROTO_TCP ||
        policy->ct_direction != NF_CT_DIR_REPLY ||
        policy->ct_state != TCP_CONNTRACK_ESTABLISHED_LOCAL)
        return tc_handler_continue();
    struct flow_key key = policy->flow;
    struct flow_key wire_key = {};
    struct mc_l7_pending_val *pending;
    struct linux_ct_snapshot snapshot;
    struct bpf_ct_opts___local opts;
    struct bpf_sock_tuple tuple;
    struct nf_conn *ct;
    __u32 payload_len = policy->payload_len;
    __u32 payload_offset = policy->payload_offset;
    void *data, *data_end;
    __u8 *payload;
    int packet_id;
    __u64 now;
    if (payload_offset > 0x3fff)
        return tc_handler_continue();
    if (!payload_len && (policy->tcp_flags & (TCP_FLAG_FIN | TCP_FLAG_RST))) {
        bpf_map_delete_elem(&mc_l7_pending, &key);
        bpf_map_delete_elem(&mc_verified, &key);
        return tc_handler_continue();
    }
    pending = bpf_map_lookup_elem(&mc_l7_pending, &key);
    if (!pending || pending->policy_generation != policy->policy_generation ||
        pending->profile_generation != policy->profile_generation)
        return tc_handler_continue();
    if (!payload_len || pending->egress_bytes >= MC_PREVERIFY_BYTES ||
        payload_len > MC_PREVERIFY_BYTES - pending->egress_bytes)
        return tc_handler_continue();

    /* TCP sendmsg may place even a two-byte reply in non-linear fragments.
     * Pull only the bounded control frame, not an entire large GSO packet. */
    __u32 inspect_len = payload_len;
    if (inspect_len > MC_SERVER_FRAME_MAX + MC_SERVER_PACKET_LEN_MAX)
        inspect_len = MC_SERVER_FRAME_MAX + MC_SERVER_PACKET_LEN_MAX;
    if (bpf_skb_pull_data(skb, payload_offset + inspect_len))
        return tc_handler_continue();
    data = (void *)(long)skb->data;
    data_end = (void *)(long)skb->data_end;
    payload = data + payload_offset;
    if ((void *)payload > data_end)
        return tc_handler_continue();

    wire_key.family = key.family;
    wire_key.sport = key.dport;
    wire_key.dport = key.sport;
    __builtin_memcpy(wire_key.saddr, key.daddr, sizeof(wire_key.saddr));
    __builtin_memcpy(wire_key.daddr, key.saddr, sizeof(wire_key.daddr));
    linux_ct_fill_tuple(&tuple, &wire_key);
    opts = linux_ct_opts(IPPROTO_TCP);
    ct = bpf_skb_ct_lookup(skb, &tuple, linux_ct_tuple_size(&wire_key), &opts, sizeof(opts));
    if (!ct)
        return tc_handler_continue();
    linux_ct_snapshot(ct, opts.dir, &snapshot);
    if (snapshot.dir != NF_CT_DIR_REPLY || !linux_ct_established(&snapshot)) {
        bpf_ct_release(ct);
        return tc_handler_continue();
    }

    now = bpf_ktime_get_ns();
    if (now >= pending->hard_deadline_ns) {
        bpf_ct_release(ct);
        bpf_map_delete_elem(&mc_l7_pending, &key);
        return tc_handler_continue();
    }
    pending->egress_bytes += payload_len;

    if (pending->state == MC_L7_ENCRYPTED_PROBATION) {
        pending->flags |= MC_F_SERVER_AFTER_CHALLENGE;
        pending->proof_level = MC_PROOF_CHALLENGE_DIALOGUE;
        bpf_ct_release(ct);
        return tc_handler_continue();
    }

    packet_id = inspect_server_frame(payload, payload + inspect_len, data_end, pending);
    if (packet_id == 0 && pending->intention != 1) {
        bpf_ct_release(ct);
        bpf_map_delete_elem(&mc_l7_pending, &key);
        return tc_handler_continue();
    }
    if (packet_id == 1 && pending->intention != 1) {
        pending->state = MC_L7_SERVER_CHALLENGE;
        pending->proof_level = MC_PROOF_SERVER_PROGRESS;
        pending->hard_deadline_ns = pending->first_seen_ns + MC_CHALLENGE_DEADLINE_NS;
    } else if (packet_id == 2 && pending->intention != 1) {
        bool admitted = mc_mark_conn(ct, &key, policy->policy_generation,
                                    policy->profile_generation, MC_PROOF_WIRE_VERIFIED);
        bpf_ct_release(ct);
        if (admitted)
            bpf_map_delete_elem(&mc_l7_pending, &key);
        return tc_handler_continue();
    } else if (packet_id == 3 && pending->intention != 1) {
        pending->flags |= MC_F_COMPRESSION_ENABLED;
        pending->proof_level = MC_PROOF_SERVER_PROGRESS;
    }
    bpf_ct_release(ct);
    return tc_handler_continue();
}

char _license[] SEC("license") = "GPL";
