#pragma once

#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/types.h>
#include "flow_keys.h"

/* The conntrack kfunc ABI is intentionally unstable.  Keep the local types
 * CO-RE relocatable and use the 12-byte options ABI supported since the
 * lookup kfuncs were introduced.  This project currently uses zone 0. */
struct bpf_ct_opts___local {
    __s32 netns_id;
    __s32 error;
    __u8 l4proto;
    __u8 dir;
    __u8 reserved[2]; /* Kernel validates these bytes; padding is not zeroed. */
};

/* This is the fixed 12-byte options ABI, not a relocatable kernel snapshot.
 * New kernels place their extended reserved field at a different offset. */
_Static_assert(sizeof(struct bpf_ct_opts___local) == 12, "conntrack options ABI");

struct ip_ct_tcp___local {
    __u8 state;
} __attribute__((preserve_access_index));

union nf_conntrack_proto___local {
    struct ip_ct_tcp___local tcp;
} __attribute__((preserve_access_index));

struct nf_conn {
    unsigned long status;
    __u32 mark;
    union nf_conntrack_proto___local proto;
} __attribute__((preserve_access_index));

extern struct nf_conn *bpf_xdp_ct_lookup(
    struct xdp_md *ctx, struct bpf_sock_tuple *tuple, __u32 tuple_size,
    struct bpf_ct_opts___local *opts, __u32 opts_size) __ksym;
extern struct nf_conn *bpf_skb_ct_lookup(
    struct __sk_buff *ctx, struct bpf_sock_tuple *tuple, __u32 tuple_size,
    struct bpf_ct_opts___local *opts, __u32 opts_size) __ksym;
extern void bpf_ct_release(struct nf_conn *ct) __ksym;

#define BPF_F_CURRENT_NETNS_LOCAL (-1)
#define NF_CT_DIR_ORIGINAL 0
#define NF_CT_DIR_REPLY 1
#define IPS_SEEN_REPLY_LOCAL (1UL << 1)
#define IPS_CONFIRMED_LOCAL (1UL << 3)
#define TCP_CONNTRACK_SYN_RECV_LOCAL 2
#define TCP_CONNTRACK_ESTABLISHED_LOCAL 3

struct linux_ct_snapshot {
    unsigned long status;
    __u32 mark;
    __u8 tcp_state;
    __u8 dir;
};

static __always_inline void linux_ct_fill_tuple(
    struct bpf_sock_tuple *tuple, const struct flow_key *key)
{
    __builtin_memset(tuple, 0, sizeof(*tuple));
    if (key->family == CT_FAMILY_IPV4) {
        tuple->ipv4.saddr = key->saddr[0];
        tuple->ipv4.daddr = key->daddr[0];
        tuple->ipv4.sport = key->sport;
        tuple->ipv4.dport = key->dport;
        return;
    }
    __builtin_memcpy(tuple->ipv6.saddr, key->saddr, sizeof(tuple->ipv6.saddr));
    __builtin_memcpy(tuple->ipv6.daddr, key->daddr, sizeof(tuple->ipv6.daddr));
    tuple->ipv6.sport = key->sport;
    tuple->ipv6.dport = key->dport;
}

static __always_inline __u32 linux_ct_tuple_size(const struct flow_key *key)
{
    return key->family == CT_FAMILY_IPV4
        ? sizeof(((struct bpf_sock_tuple *)0)->ipv4)
        : sizeof(((struct bpf_sock_tuple *)0)->ipv6);
}

static __always_inline struct bpf_ct_opts___local linux_ct_opts(__u8 l4proto)
{
    return (struct bpf_ct_opts___local) {
        .netns_id = BPF_F_CURRENT_NETNS_LOCAL,
        .l4proto = l4proto,
    };
}

/* The lookup kfunc reports a missing entry as -ENOENT in opts.error. */
#define LINUX_CT_ENOENT 2

enum linux_ct_class {
    LINUX_CT_MISS = 0,     /* no entry for this tuple */
    LINUX_CT_ORIGINAL = 1, /* known flow, packet sent by its initiator */
    LINUX_CT_REPLY = 2,    /* confirmed reply to a flow this host initiated */
    LINUX_CT_ERROR = 3,    /* lookup failed; callers treat it like a miss */
};

/* One read-only lookup classifies the packet; never create state from an
 * unsolicited ingress packet. Directions are relative to the connection
 * initiator, not the interface. REPLY does not require SEEN_REPLY or
 * ESTABLISHED: the first DNS reply/SYN-ACK precedes those transitions.
 * ORIGINAL accepts any TCP state, so half-closed and closing flows stay known.
 * The stack still validates packets after XDP_PASS.
 */
static __always_inline enum linux_ct_class linux_ct_classify(
    struct xdp_md *ctx, const struct flow_key *key, __u8 l4proto)
{
    struct bpf_sock_tuple tuple;
    struct bpf_ct_opts___local opts = linux_ct_opts(l4proto);
    linux_ct_fill_tuple(&tuple, key);
    struct nf_conn *ct = bpf_xdp_ct_lookup(
        ctx, &tuple, linux_ct_tuple_size(key), &opts, sizeof(opts));
    if (!ct)
        return opts.error == -LINUX_CT_ENOENT ? LINUX_CT_MISS : LINUX_CT_ERROR;
    enum linux_ct_class cls = LINUX_CT_MISS;
    if (opts.dir == NF_CT_DIR_REPLY) {
        if (ct->status & IPS_CONFIRMED_LOCAL)
            cls = LINUX_CT_REPLY;
    } else if (opts.dir == NF_CT_DIR_ORIGINAL) {
        cls = LINUX_CT_ORIGINAL;
    }
    bpf_ct_release(ct);
    return cls;
}

static __always_inline bool linux_ct_reply(
    struct xdp_md *ctx, const struct flow_key *key, __u8 l4proto)
{
    return linux_ct_classify(ctx, key, l4proto) == LINUX_CT_REPLY;
}

static __always_inline void linux_ct_snapshot(
    const struct nf_conn *ct, __u8 dir, struct linux_ct_snapshot *snapshot)
{
    snapshot->status = ct->status;
    snapshot->mark = ct->mark;
    snapshot->tcp_state = ct->proto.tcp.state;
    snapshot->dir = dir;
}

static __always_inline bool linux_ct_established(
    const struct linux_ct_snapshot *snapshot)
{
    return (snapshot->status & IPS_CONFIRMED_LOCAL) &&
           snapshot->tcp_state == TCP_CONNTRACK_ESTABLISHED_LOCAL;
}
