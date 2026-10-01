/* Native checks execute the production event/counter helpers with fake maps. */
#include <assert.h>
#include <string.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

static void *lookup(void *map, const void *key);
static void *reserve(void *map, __u64 size, __u64 flags);
static void submit(void *record, __u64 flags);
/* Substitute calls after libbpf declares its immutable helper pointers. */
#define bpf_map_lookup_elem lookup
#define bpf_ringbuf_reserve reserve
#define bpf_ringbuf_submit submit
#include "bpf/include/common.h"

static __u64 counts[CNT_MAX];
static __u64 bytes[4];
static struct xdp_runtime_cfg config;
static struct pkt_event event;
static bool full;
static unsigned int reservations;

static void *lookup(void *map, const void *key)
{
    __u32 idx = *(const __u32 *)key;
    if (map == &xdp_runtime_cfg)
        return idx == 0 ? &config : NULL;
    if (map == &pkt_counters)
        return idx < CNT_MAX ? &counts[idx] : NULL;
    if (map == &byte_counters)
        return idx < 4 ? &bytes[idx] : NULL;
    return NULL;
}

static void *reserve(void *map, __u64 size, __u64 flags)
{
    assert(map == &pkt_ringbuf && size == sizeof(event) && flags == 0);
    reservations++;
    memset(&event, 0xff, sizeof(event));
    return full ? NULL : &event;
}

static void submit(void *record, __u64 flags)
{
    assert(record == &event && flags == 0);
}

int main(void)
{
    struct xdp_md ctx = { .data = 1000, .data_end = 1064, .ingress_ifindex = 7 };
    __u32 src[4] = { 1, 2, 3, 4 }, dst[4] = { 5, 6, 7, 8 };
    emit_drop(&ctx, IPPROTO_TCP, 10, src, dst, 123, 456,
              CNT_PORT_NOT_AUTHORIZED, 9000);
    assert(event.version == 2 && event.ifindex == 7 && event.pkt_len == 64);
    assert(event.ts_ns == 9000 && event.family == 10 && event.proto == IPPROTO_TCP);
    assert(event.verdict == 1 && event.reason == CNT_PORT_NOT_AUTHORIZED);
    assert(event.src_port == 123 && event.dst_port == 456);
    assert(memcmp(event.src_ip, src, sizeof(src)) == 0);
    assert(memcmp(event.dst_ip, dst, sizeof(dst)) == 0);
    for (unsigned int i = 0; i < sizeof(event.reserved); i++)
        assert(event.reserved[i] == 0);
    assert(counts[CNT_EVENT_EMITTED] == 1 && reservations == 1);

    config.cfg_flags = XDP_CFG_FLAG_DROP_EVENTS_DISABLED;
    emit_allow(&ctx, 6, 2, src, dst, 0, 0, CNT_TCP_NEW_ALLOW, 9001);
    assert(counts[CNT_EVENT_SUPPRESSED] == 1 && reservations == 1);
    config.cfg_flags = 0;
    full = true;
    emit_drop(&ctx, 0, 0, src, dst, 0, 0, CNT_PACKET_TRUNCATED, 9002);
    assert(counts[CNT_EVENT_LOST] == 1 && counts[CNT_EVENT_EMITTED] == 1);
    full = false;
    emit_packet_event(&ctx, 128, 0, 99, src, dst, 123, 456, 2, CNT_SYN_COOKIE_VALID, 9003);
    assert(event.family == 0 && event.pkt_len == 128 && event.verdict == 2);
    assert(event.src_port == 0 && event.dst_port == 0);
    for (unsigned int i = 0; i < 4; i++)
        assert(event.src_ip[i] == 0 && event.dst_ip[i] == 0);
    assert(counts[CNT_EVENT_EMITTED] == 2);

    count_bytes(false, 100);
    count_bytes(true, 200);
    assert(bytes[0] == 300 && bytes[1] == 200 && bytes[2] == 2 && bytes[3] == 1);
    return 0;
}
