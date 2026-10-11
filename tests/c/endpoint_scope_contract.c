/* Exercise the production admission lookup, including fallback precedence. */
#include <string.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
static void *lookup(const void *map, const void *key);
#define bpf_map_lookup_elem lookup
#include "bpf/include/common.h"
#include "bpf/include/exposure.h"

#define CHECK(value) do { if (!(value)) __builtin_trap(); } while (0)
static struct xdp_runtime_cfg runtime;
static struct endpoint_scope_key keys[4];
static __u32 values[4];
static int entries;

static void *lookup(const void *map, const void *key)
{
    if (map == &xdp_runtime_cfg)
        return &runtime;
    if (map == &endpoint_scopes)
        for (int i = 0; i < entries; i++)
            if (!memcmp(key, &keys[i], sizeof(keys[i])))
                return &values[i];
    return NULL;
}

int main(void)
{
    struct xdp_md ctx = { .ingress_ifindex = 1 };
    __u32 address[4] = { 0x0a6433c6, 0, 0, 0 };
    __u32 other[4] = { 0x0b6433c6, 0, 0, 0 };
    CHECK(endpoint_scope_allowed(&ctx, 2, 6, address, 8080)); /* legacy flag */
    runtime.cfg_flags = XDP_CFG_FLAG_ENDPOINT_POLICY;
    CHECK(!endpoint_scope_allowed(&ctx, 2, 6, address, 8080));
    keys[0] = (struct endpoint_scope_key){ .port = 8080, .proto = 6, .family = 2 };
    memcpy(keys[0].daddr, address, sizeof(address));
    values[0] = 1;
    entries = 1;
    CHECK(endpoint_scope_allowed(&ctx, 2, 6, address, 8080));
    CHECK(!endpoint_scope_allowed(&ctx, 2, 6, other, 8080));
    CHECK(!endpoint_scope_allowed(&ctx, 10, 6, address, 8080));
    CHECK(!endpoint_scope_allowed(&ctx, 2, 17, address, 8080));
    CHECK(!endpoint_scope_allowed(&ctx, 2, 132, address, 8080));
    keys[1] = (struct endpoint_scope_key){ .ifindex = 7, .port = 8080, .proto = 6, .family = 2 };
    values[1] = 0;
    entries = 2;
    ctx.ingress_ifindex = 7;
    CHECK(!endpoint_scope_allowed(&ctx, 2, 6, address, 8080)); /* private tombstone */
    keys[2] = keys[1];
    memcpy(keys[2].daddr, address, sizeof(address));
    values[2] = 1;
    entries = 3;
    CHECK(endpoint_scope_allowed(&ctx, 2, 6, address, 8080)); /* private exact grant */
    CHECK(!endpoint_scope_allowed(&ctx, 2, 6, other, 8080));
    keys[3] = (struct endpoint_scope_key){ .port = 53, .proto = 17, .family = 10 };
    values[3] = 1;
    entries = 4;
    CHECK(endpoint_scope_allowed(&ctx, 10, 17, address, 53)); /* family wildcard */
    CHECK(!endpoint_scope_allowed(&ctx, 2, 17, address, 53));
    return 0;
}
