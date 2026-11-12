/* SPDX-License-Identifier: GPL-2.0
 * Service observation only. Linux owns connection tracking and TCP state. */
#include "include/common.h"
#include "include/exposure.h"
#include "include/handler_routing.h"
#include "include/linux_conntrack.h"

static __always_inline void egress_count(__u32 index)
{
    __u64 *value = bpf_map_lookup_elem(&handler_eg_stats, &index);
    if (value)
        (*value)++;
}

/* Read headers through skb helpers: outgoing TCP can be non-linear or GSO.
 * We only support complete IP datagrams, with bounded extension traversal.
 * Unsupported traffic continues untouched, without inventing a flow binding. */
static __always_inline bool parse_egress(
    struct __sk_buff *skb, struct handler_flow_key *key, struct tc_handler_ctx *out)
{
    struct ethhdr eth;
    if (bpf_skb_load_bytes(skb, 0, &eth, sizeof(eth)))
        return false;
    __u32 offset = sizeof(eth), end = 0;
    __be16 proto = eth.h_proto;
#pragma unroll
    for (int i = 0; i < VLAN_MAX_DEPTH; i++) {
        if (proto != bpf_htons(ETH_P_8021Q) && proto != bpf_htons(ETH_P_8021AD))
            break;
        struct vlan_hdr vlan;
        if (bpf_skb_load_bytes(skb, offset, &vlan, sizeof(vlan)))
            return false;
        proto = vlan.h_vlan_encapsulated_proto;
        offset += sizeof(vlan);
    }
    __u8 next;
    if (proto == bpf_htons(ETH_P_IP)) {
        struct iphdr ip;
        if (bpf_skb_load_bytes(skb, offset, &ip, sizeof(ip)) || ip.version != 4 ||
            ip.ihl < 5 || (ip.frag_off & bpf_htons(IP_MF | IP_OFFSET)))
            return false;
        __u32 length = bpf_ntohs(ip.tot_len);
        if (length < (__u32)ip.ihl * 4 || offset > skb->len || length > skb->len - offset)
            return false;
        end = offset + length;
        offset += (__u32)ip.ihl * 4;
        next = ip.protocol;
        key->flow.family = CT_FAMILY_IPV4;
        key->flow.saddr[0] = ip.daddr;
        key->flow.daddr[0] = ip.saddr;
    } else if (proto == bpf_htons(ETH_P_IPV6)) {
        struct ipv6hdr ip;
        if (bpf_skb_load_bytes(skb, offset, &ip, sizeof(ip)) || ip.version != 6)
            return false;
        __u32 length = bpf_ntohs(ip.payload_len);
        offset += sizeof(ip);
        if (!length || offset > skb->len || length > skb->len - offset)
            return false;
        end = offset + length;
        next = ip.nexthdr;
        key->flow.family = CT_FAMILY_IPV6;
        __builtin_memcpy(key->flow.saddr, &ip.daddr, sizeof(key->flow.saddr));
        __builtin_memcpy(key->flow.daddr, &ip.saddr, sizeof(key->flow.daddr));
#pragma unroll
        for (int i = 0; i < 6; i++) {
            if (next != IPPROTO_HOPOPTS && next != IPPROTO_ROUTING &&
                next != IPPROTO_DSTOPTS && next != IPPROTO_AH)
                break;
            __u8 header[2];
            if (offset > end || 2 > end - offset ||
                bpf_skb_load_bytes(skb, offset, header, sizeof(header)))
                return false;
            __u32 length = next == IPPROTO_AH ?
                ((__u32)header[1] + 2) * 4 : ((__u32)header[1] + 1) * 8;
            if (length > end - offset)
                return false;
            next = header[0];
            offset += length;
        }
    } else {
        return false;
    }
    out->l4_offset = offset;
    if (offset > end)
        return false;
    if (next == IPPROTO_TCP) {
        struct tcphdr tcp;
        if (sizeof(tcp) > end - offset ||
            bpf_skb_load_bytes(skb, offset, &tcp, sizeof(tcp)) || tcp.doff < 5 ||
            (__u32)tcp.doff * 4 > end - offset)
            return false;
        key->flow.sport = tcp.dest;
        key->flow.dport = tcp.source;
        out->tcp_flags = ((__u8 *)&tcp)[13];
        offset += (__u32)tcp.doff * 4;
    } else if (next == IPPROTO_UDP) {
        struct udphdr udp;
        if (sizeof(udp) > end - offset ||
            bpf_skb_load_bytes(skb, offset, &udp, sizeof(udp)))
            return false;
        __u32 length = bpf_ntohs(udp.len);
        if (length < sizeof(udp) || length > end - offset)
            return false;
        end = offset + length;
        key->flow.sport = udp.dest;
        key->flow.dport = udp.source;
        offset += sizeof(udp);
    } else if (next == IPPROTO_GRE || next == IPPROTO_ESP || next == IPPROTO_SCTP) {
        __u32 minimum = next == IPPROTO_GRE ? 4 : next == IPPROTO_ESP ? 8 : 12;
        if (minimum > end - offset)
            return false;
        if (next == IPPROTO_SCTP) {
            __be16 ports[2];
            if (bpf_skb_load_bytes(skb, offset, ports, sizeof(ports)))
                return false;
            key->flow.sport = ports[1];
            key->flow.dport = ports[0];
            offset += 12;
        }
        /* GRE options and ESP encrypted data are owned by the protocol module;
         * expose the entire protocol header starting at l4_offset. */
        out->kind = HANDLER_ROUTE_PROTO;
    } else {
        return false;
    }
    if (out->kind != HANDLER_ROUTE_PROTO && (!key->flow.sport || !key->flow.dport))
        return false;
    key->proto = next;
    out->ip_proto = next;
    out->payload_offset = offset;
    out->payload_len = end - offset;
    return true;
}

static __always_inline bool route_is_current(
    const struct handler_flow_key *key, const struct handler_flow_route *route)
{
    __u32 port = bpf_ntohs(key->flow.dport);
    if (!endpoint_scope_allowed_on(route->ingress_ifindex, key->flow.family,
                                   key->proto, key->flow.daddr, port))
        return false;
    if (key->proto == IPPROTO_TCP) {
        struct tcp_endpoint_policy policy = {};
        if (!tcp_endpoint_policy_lookup_on(route->ingress_ifindex, port, &policy))
            return false;
        if (route->kind == HANDLER_ROUTE_PROFILE)
            return policy.profile_id == route->target &&
                   policy.policy_generation == route->policy_generation &&
                   policy.profile_generation == route->profile_generation;
        return route->kind == HANDLER_ROUTE_TCP && route->target == port &&
               !policy.profile_id && policy.policy_generation == route->policy_generation;
    }
    return route->kind == HANDLER_ROUTE_UDP && route->target == port &&
           udp_exposure_allowed_on(route->ingress_ifindex, port);
}

SEC("tc")
int tc_egress_dispatch(struct __sk_buff *skb)
{
    struct handler_flow_key key = {};
    struct tc_handler_ctx context = { .abi_version = TC_HANDLER_ABI_VERSION,
                                      .packet_len = skb->len };
    if (!parse_egress(skb, &key, &context)) {
        egress_count(HANDLER_EGRESS_PARSE_MISS);
        return tc_handler_continue();
    }
    if (context.kind == HANDLER_ROUTE_PROTO) {
        struct handler_route_key target = { .kind = HANDLER_ROUTE_PROTO, .target = key.proto };
        __u32 *enabled = bpf_map_lookup_elem(&handler_egress, &target);
        if (!enabled || !*enabled) {
            egress_count(HANDLER_EGRESS_ROUTE_MISS);
            return tc_handler_continue();
        }
        /* These protocols have no service-port/CT reply binding here. Never
         * infer a GRE key, ESP SA, or SCTP association from address pairs. */
        context.target = key.proto;
        context.flow.family = key.flow.family;
        context.flow.sport = key.flow.dport;
        context.flow.dport = key.flow.sport;
        __builtin_memcpy(context.flow.saddr, key.flow.daddr, sizeof(context.flow.saddr));
        __builtin_memcpy(context.flow.daddr, key.flow.saddr, sizeof(context.flow.daddr));
        context.ct_direction = HANDLER_CT_UNAVAILABLE;
        __u32 zero = 0;
        struct tc_handler_ctx *slot = bpf_map_lookup_elem(&tc_handler_ctx, &zero);
        if (!slot)
            return tc_handler_continue();
        *slot = context;
        egress_count(HANDLER_EGRESS_DISPATCH);
        bpf_tail_call(skb, &tc_proto_handlers, key.proto);
        slot->abi_version = 0;
        egress_count(HANDLER_EGRESS_TAILCALL_MISS);
        return tc_handler_continue();
    }
    struct handler_flow_route *saved = bpf_map_lookup_elem(&handler_flows, &key);
    if (!saved) {
        egress_count(HANDLER_EGRESS_ROUTE_MISS);
        return tc_handler_continue();
    }
    struct handler_flow_route route = *saved;
    struct handler_route_key target = { .kind = route.kind, .target = route.target };
    __u32 *enabled = bpf_map_lookup_elem(&handler_egress, &target);
    if (!enabled || !*enabled || !route_is_current(&key, &route)) {
        egress_count(HANDLER_EGRESS_POLICY_MISS);
        return tc_handler_continue();
    }

    struct flow_key wire = { .family = key.flow.family,
                             .sport = key.flow.dport, .dport = key.flow.sport };
    __builtin_memcpy(wire.saddr, key.flow.daddr, sizeof(wire.saddr));
    __builtin_memcpy(wire.daddr, key.flow.saddr, sizeof(wire.daddr));
    struct bpf_sock_tuple tuple;
    linux_ct_fill_tuple(&tuple, &wire);
    struct bpf_ct_opts___local opts = linux_ct_opts(key.proto);
    struct nf_conn *ct = bpf_skb_ct_lookup(skb, &tuple, linux_ct_tuple_size(&wire),
                                          &opts, sizeof(opts));
    if (!ct) {
        egress_count(HANDLER_EGRESS_CT_MISS);
        return tc_handler_continue();
    }
    struct linux_ct_snapshot snapshot;
    linux_ct_snapshot(ct, opts.dir, &snapshot);
    bpf_ct_release(ct); /* References cannot cross a tail call. */
    if (snapshot.dir != NF_CT_DIR_REPLY || !(snapshot.status & IPS_CONFIRMED_LOCAL)) {
        egress_count(HANDLER_EGRESS_CT_MISS);
        return tc_handler_continue();
    }
    context.kind = route.kind;
    context.target = route.target;
    context.ingress_ifindex = route.ingress_ifindex;
    context.policy_generation = route.policy_generation;
    context.profile_generation = route.profile_generation;
    context.flow = key.flow;
    context.ct_status = snapshot.status;
    context.ct_direction = snapshot.dir;
    context.ct_state = snapshot.tcp_state;
    __u32 zero = 0;
    struct tc_handler_ctx *slot = bpf_map_lookup_elem(&tc_handler_ctx, &zero);
    if (!slot)
        return tc_handler_continue();
    *slot = context;
    egress_count(HANDLER_EGRESS_DISPATCH);
    if (route.kind == HANDLER_ROUTE_PROFILE)
        bpf_tail_call(skb, &tc_profile_handlers, route.target);
    else if (route.kind == HANDLER_ROUTE_TCP)
        bpf_tail_call(skb, &tc_tcp_handlers, route.target);
    else if (route.kind == HANDLER_ROUTE_UDP)
        bpf_tail_call(skb, &tc_udp_handlers, route.target);
    slot->abi_version = 0;
    egress_count(HANDLER_EGRESS_TAILCALL_MISS);
    return tc_handler_continue();
}

char LICENSE[] SEC("license") = "GPL";
