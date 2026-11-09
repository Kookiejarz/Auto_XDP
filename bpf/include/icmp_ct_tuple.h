/* SPDX-License-Identifier: GPL-2.0 */
#pragma once
#include <linux/types.h>

/* Wire addresses and echo ID, in network byte order. family is AF_INET/6.
 * This scalar-only ABI is shared by the BPF caller and the optional module. */
struct axdp_icmp_tuple {
    __be32 saddr[4];
    __be32 daddr[4];
    __be16 id;
    __u8 family;
    __u8 code;
};
