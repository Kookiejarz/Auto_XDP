/* Verify the fixed conntrack options ABI, including reserved bytes. */
#include <assert.h>
#include <stdbool.h>
#include <string.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "bpf/include/minecraft.h"
int main(void)
{
    struct bpf_ct_opts___local opts = linux_ct_opts(IPPROTO_TCP);
    const unsigned char expected[12] = {255,255,255,255,0,0,0,0,6,0,0,0};
    assert(memcmp(&opts, expected, sizeof(opts)) == 0);
    return 0;
}
