// SPDX-License-Identifier: GPL-2.0
/* Kernel dependency of icmp_handler.c: read-only Linux conntrack lookup. */
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <linux/module.h>
#include <net/xdp.h>
#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_core.h>
#include <net/netfilter/nf_conntrack_zones.h>
#include "icmp_ct_tuple.h"

__bpf_kfunc_start_defs();

/* Return 1 for a confirmed request's REPLY tuple, 0 for a miss, or -EINVAL.
 * The first reply must pass before Linux sets IPS_SEEN_REPLY. Acquire and
 * release references here so no conntrack pointer escapes to the caller. */
__bpf_kfunc int bpf_axdp_icmp_reply(struct xdp_md *ctx,
                                 const struct axdp_icmp_tuple *query)
{
    struct xdp_buff *xdp = (struct xdp_buff *)ctx;
    struct nf_conntrack_tuple tuple = {};
    struct nf_conntrack_zone zone;
    struct nf_conntrack_tuple_hash *hash;
    struct nf_conn *ct;
    int matched;

    if (query->code)
        return -EINVAL;
    tuple.src.l3num = query->family;
    tuple.src.u.icmp.id = query->id;
    if (query->family == AF_INET) {
        tuple.src.u3.ip = query->saddr[0];
        tuple.dst.u3.ip = query->daddr[0];
        tuple.dst.protonum = IPPROTO_ICMP;
        tuple.dst.u.icmp.type = ICMP_ECHOREPLY;
    } else if (query->family == AF_INET6) {
        memcpy(tuple.src.u3.ip6, query->saddr, sizeof(query->saddr));
        memcpy(tuple.dst.u3.ip6, query->daddr, sizeof(query->daddr));
        tuple.dst.protonum = IPPROTO_ICMPV6;
        tuple.dst.u.icmp.type = ICMPV6_ECHO_REPLY;
    } else {
        return -EINVAL;
    }

    /* Match the main firewall's ingress namespace and zone-0 contract. */
    nf_ct_zone_init(&zone, NF_CT_DEFAULT_ZONE_ID, NF_CT_DEFAULT_ZONE_DIR, 0);
    hash = nf_conntrack_find_get(dev_net(xdp->rxq->dev), &zone, &tuple);
    if (!hash)
        return 0;
    ct = nf_ct_tuplehash_to_ctrack(hash);
    matched = NF_CT_DIRECTION(hash) == IP_CT_DIR_REPLY && nf_ct_is_confirmed(ct);
    nf_ct_put(ct);
    return matched;
}

__bpf_kfunc_end_defs();

/* Some kernel headers predate the explicit kfunc-set tag. */
#ifndef BTF_KFUNCS_START
#define BTF_KFUNCS_START(name) BTF_SET8_START(name)
#define BTF_KFUNCS_END(name) BTF_SET8_END(name)
#endif
BTF_KFUNCS_START(axdp_icmp_kfunc_ids)
BTF_ID_FLAGS(func, bpf_axdp_icmp_reply)
BTF_KFUNCS_END(axdp_icmp_kfunc_ids)

static const struct btf_kfunc_id_set axdp_icmp_kfunc_set = {
    .owner = THIS_MODULE,
    .set = &axdp_icmp_kfunc_ids,
};

static int __init axdp_icmp_init(void)
{
    if (!IS_ENABLED(CONFIG_DEBUG_INFO_BTF_MODULES))
        return -EOPNOTSUPP;
    return register_btf_kfunc_id_set(BPF_PROG_TYPE_XDP, &axdp_icmp_kfunc_set);
}

static void __exit axdp_icmp_exit(void) {}

module_init(axdp_icmp_init);
module_exit(axdp_icmp_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Auto XDP read-only ICMP conntrack query");
MODULE_VERSION("1");
