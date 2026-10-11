#pragma once
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "../../handlers/xdp_slot_ctx.h"
#include "../../handlers/xdp_profile_ctx.h"
#include "counters.h"
#include "flow_keys.h"

#ifndef bool
typedef _Bool bool;
#define true  1
#define false 0
#endif

/* struct vlan_hdr is not reliably defined in BPF compilation headers on all
 * distros (<linux/if_vlan.h> may only forward-declare it).  Define it here
 * directly; ETH_P_8021Q / ETH_P_8021AD come from <linux/if_ether.h>. */
struct vlan_hdr {
    __be16  h_vlan_TCI;
    __be16  h_vlan_encapsulated_proto;
};

// These two macros are not exposed under the BPF compilation path of <linux/ip.h>, so define them manually
#ifndef IP_MF
#define IP_MF     0x2000  // More Fragments bit
#endif
#ifndef IP_OFFSET
#define IP_OFFSET 0x1FFF  // Fragment offset mask
#endif

#define IPV6_FRAG_DROP_SENTINEL 0xFF
#define IPV6_EXTHDR_MALFORMED_SENTINEL 0xFE
#define VLAN_MAX_DEPTH 4
#define NS_PER_SEC 1000000000ULL

#define TCP_FLAG_FIN  0x01
#define TCP_FLAG_SYN  0x02
#define TCP_FLAG_RST  0x04
#define TCP_FLAG_ACK  0x10


// cfg_flags bits for xdp_runtime_cfg.cfg_flags.
// Zero means "all defaults" so old loaders remain compatible.
#define XDP_CFG_FLAG_BOGON_DISABLED       (1U << 0)  // bogon filter off (default: on)
#define XDP_CFG_FLAG_ABUSEIPDB_ENABLED    (1U << 1)  // AbuseIPDB active (default: off)
#define XDP_CFG_FLAG_DROP_EVENTS_DISABLED (1U << 2)  // ring-buf events off (default: on)
#define XDP_CFG_FLAG_SLOT_DROP            (1U << 3)  // unknown proto → drop (default: pass)
#define XDP_CFG_FLAG_ENDPOINT_POLICY      (1U << 4)  // exact address/family/interface admission

// Runtime tunables. Userspace writes this map from config.toml; zero fields
// fall back to defaults so old loaders remain compatible.
struct xdp_runtime_cfg {
    __u64 _reserved0;
    __u64 _reserved1;
    __u64 _reserved2;
    __u64 icmp_token_max;
    __u64 icmp_ns_per_token;
    __u64 udp_global_window_ns;
    __u64 rate_window_ns;
    __u64 _reserved7;
    __u32 cfg_flags;        // XDP_CFG_FLAG_* bits; replaces bogon_cfg/abuseipdb_cfg/observability_cfg/slot_def_action
    __u32 _pad;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct xdp_runtime_cfg);
} xdp_runtime_cfg SEC(".maps");

static __always_inline struct xdp_runtime_cfg *runtime_cfg(void)
{
    __u32 key = 0;
    return bpf_map_lookup_elem(&xdp_runtime_cfg, &key);
}

// cfg_*_ns(): pre-fetched cfg pointer variants — callers that already hold a
// runtime_cfg() pointer use these to avoid redundant map lookups in hot paths.
static __always_inline __u64 cfg_udp_global_window_ns(struct xdp_runtime_cfg *cfg)
{
    return cfg && cfg->udp_global_window_ns ? cfg->udp_global_window_ns : NS_PER_SEC;
}

static __always_inline __u64 cfg_rate_window_ns(struct xdp_runtime_cfg *cfg)
{
    return cfg && cfg->rate_window_ns ? cfg->rate_window_ns : NS_PER_SEC;
}

#include "telemetry.h"
