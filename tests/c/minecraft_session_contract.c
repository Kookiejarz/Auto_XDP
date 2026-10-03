/* Native checks call the production proof helpers with a fake map update. */
#include <assert.h>
#include <stdbool.h>
#include <string.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
static long update(void *map, const void *key, const void *value, __u64 flags);
#define bpf_map_update_elem update
#include "bpf/include/minecraft.h"

static struct mc_verified_val stored;
static struct nf_conn connection;
static bool fail_update;

static long update(void *map, const void *key, const void *value, __u64 flags)
{
    assert(map == &mc_verified && key && flags == BPF_ANY);
    assert(connection.mark == 0x1234); /* Publish proof before its CT hint. */
    if (fail_update)
        return -1;
    stored = *(const struct mc_verified_val *)value;
    return 0;
}

int main(void)
{
    struct flow_key key = { .family = CT_FAMILY_IPV4 };
    struct bpf_ct_opts___local opts = linux_ct_opts(IPPROTO_TCP);
    const unsigned char expected[12] = {255, 255, 255, 255, 0, 0, 0, 0, 6, 0, 0, 0};
    assert(memcmp(&opts, expected, sizeof(opts)) == 0);
    connection.mark = 0x1234;
    fail_update = true;
    assert(!mc_mark_conn(&connection, &key, 11, 22, MC_PROOF_WIRE_VERIFIED));
    assert(connection.mark == 0x1234);
    fail_update = false;
    assert(mc_mark_conn(&connection, &key, 11, 22, MC_PROOF_WIRE_VERIFIED));
    assert((connection.mark & ~MC_MARK_MASK) == 0x1234);
    assert(mc_verified_matches(&stored, connection.mark, 11, 22));
    assert(!mc_verified_matches(NULL, connection.mark, 11, 22));
    assert(!mc_verified_matches(&stored, 0, 11, 22));
    assert(!mc_verified_matches(&stored, connection.mark, 12, 22));
    assert(!mc_verified_matches(&stored, connection.mark, 11, 23));
    /* Same compact epoch is still a different full generation. */
    assert(mc_mark_encode(22, MC_PROOF_WIRE_VERIFIED) ==
           mc_mark_encode(278, MC_PROOF_WIRE_VERIFIED));
    assert(!mc_verified_matches(&stored, connection.mark, 11, 278));
    assert(!mc_verified_matches(&stored, connection.mark, (1ULL << 32) + 11, 22));
    return 0;
}
