#pragma once
#include "keys.h"

#define CT_MAP_MAX_ENTRIES_V4 196608
#define CT_MAP_MAX_ENTRIES_V6 196608
#define RATE_MAP_MAX_ENTRIES_V4 49152
#define RATE_MAP_MAX_ENTRIES_V6 16384

/* Note: pkt_counters (PERCPU_ARRAY) and pkt_ringbuf (RINGBUF) are declared
 * in common.h alongside the count() and emit_drop() helpers that use them.
 * All other SEC(".maps") map definitions are below. */

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, CT_MAP_MAX_ENTRIES_V4);
    __type(key, struct ct_key_v4);
    __type(value, __u64); // ktime_ns at insert for future timeout handling
} tcp_ct4 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, CT_MAP_MAX_ENTRIES_V6);
    __type(key, struct ct_key_v6);
    __type(value, __u64); // ktime_ns at insert for future timeout handling
} tcp_ct6 SEC(".maps");

// Pending TCP validations owned by per-port handlers.
// Key: inbound 5-tuple. Value: handler destination port (host byte order).
// Used when ACK/data misses tcp_conntrack but should still be re-dispatched
// into a multi-packet handler state machine before the final CT_MISS drop.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, RATE_MAP_MAX_ENTRIES_V4);
    __type(key, struct ct_key_v4);
    __type(value, __u32);
} tcp_pd4 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, RATE_MAP_MAX_ENTRIES_V6);
    __type(key, struct ct_key_v6);
    __type(value, __u32);
} tcp_pd6 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 256);
    __type(key, struct trusted_v4_key);
    __type(value, __u32);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} trusted_ipv4 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 256);
    __type(key, struct trusted_v6_key);
    __type(value, __u32);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} trusted_ipv6 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, CT_MAP_MAX_ENTRIES_V4);
    __type(key, struct ct_key_v4);
    __type(value, __u64); // ktime_ns of the most recent outbound UDP packet
} udp_ct4 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, CT_MAP_MAX_ENTRIES_V6);
    __type(key, struct ct_key_v6);
    __type(value, __u64); // ktime_ns of the most recent outbound UDP packet
} udp_ct6 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 65536);
    __type(key, __u32);   // port number (host byte order) as array index
    __type(value, __u32); // 1 = allow
} tcp_whitelist SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 65536);
    __type(key, __u32);   // port number (host byte order) as array index
    __type(value, __u32); // 1 = allow
} udp_whitelist SEC(".maps");

// Shared SCTP whitelist / conntrack maps.
// The main program pins them so the optional slot handler and tc egress tracker
// can reuse the same fds instead of creating private copies.
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 65536);
    __type(key, __u32);
    __type(value, __u32);
} sctp_whitelist SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, struct flow_key);
    __type(value, __u64);
} sctp_conntrack SEC(".maps");

// Global ICMP token-bucket state (single entry, protected by spin lock)
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct icmp_token_bucket);
} icmp_tb SEC(".maps");

// Global UDP rate limiter: single shared entry, spinlock-protected.
// All CPUs write to this after flushing their per-CPU local accumulator.
// Must be BPF_MAP_TYPE_ARRAY (not PERCPU) so the spinlock is truly shared.
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct udp_global_state);
} udp_global_rl SEC(".maps");

// Per-CPU local byte accumulator for the two-level UDP global rate limiter.
// Each CPU accumulates here without locking; flushes to udp_global_rl in batches.
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct udp_percpu_local);
} udp_percpu_acc SEC(".maps");

// Bogon filter toggle: 0 = disabled, non-zero = enabled (default on).
// Written at runtime by xdp_port_sync from config.toml [firewall].bogon_filter.
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} bogon_cfg SEC(".maps");

// Per-port TCP policy config, populated at runtime by xdp_port_sync.
// Key: dest port (host byte order). Value: SYN/per-prefix/conn-limit controls.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);  // dest port (host byte order)
    __type(value, struct tcp_port_policy_cfg);
} tcp_port_policies SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, RATE_MAP_MAX_ENTRIES_V4);
    __type(key, struct syn_rate_key_v4);
    __type(value, struct syn_rate_val);
} syn4 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, RATE_MAP_MAX_ENTRIES_V6);
    __type(key, struct syn_rate_key_v6);
    __type(value, struct syn_rate_val);
} syn6 SEC(".maps");

// Per-port UDP policy config, populated at runtime by xdp_port_sync.
// Key: dest port (host byte order). Value: packet-rate and aggregate-byte-rate controls.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);  // dest port (host byte order)
    __type(value, struct udp_port_policy_cfg);
} udp_port_policies SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, RATE_MAP_MAX_ENTRIES_V4);
    __type(key, struct syn_rate_key_v4);
    __type(value, struct syn_rate_val);
} udprt4 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, RATE_MAP_MAX_ENTRIES_V6);
    __type(key, struct syn_rate_key_v6);
    __type(value, struct syn_rate_val);
} udprt6 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, RATE_MAP_MAX_ENTRIES_V4);
    __type(key, struct prefix_rate_key_v4);
    __type(value, struct prefix_rate_val);
} synag4 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, RATE_MAP_MAX_ENTRIES_V6);
    __type(key, struct prefix_rate_key_v6);
    __type(value, struct prefix_rate_val);
} synag6 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, RATE_MAP_MAX_ENTRIES_V4);
    __type(key, struct prefix_rate_key_v4);
    __type(value, struct prefix_rate_val);
} udpag4 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, RATE_MAP_MAX_ENTRIES_V6);
    __type(key, struct prefix_rate_key_v6);
    __type(value, struct prefix_rate_val);
} udpag6 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, RATE_MAP_MAX_ENTRIES_V4);
    __type(key, struct tcp_src_conn_key_v4);
    __type(value, struct tcp_src_conn_val);
} tsc4 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, RATE_MAP_MAX_ENTRIES_V6);
    __type(key, struct tcp_src_conn_key_v6);
    __type(value, struct tcp_src_conn_val);
} tsc6 SEC(".maps");

// Per-CIDR port ACL: source CIDR → list of allowed destination ports.
// ACL entries bypass rate limiting and take priority over the port whitelist.
// TCP and UDP are configured independently via separate maps.
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 1024);
    __type(key, struct trusted_v4_key);
    __type(value, struct acl_val);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} tcp_acl_v4 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 1024);
    __type(key, struct trusted_v6_key);
    __type(value, struct acl_val);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} tcp_acl_v6 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 1024);
    __type(key, struct trusted_v4_key);
    __type(value, struct acl_val);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} udp_acl_v4 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 1024);
    __type(key, struct trusted_v6_key);
    __type(value, struct acl_val);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} udp_acl_v6 SEC(".maps");

// 256-entry prog_array: index = final IP protocol number (post ext-hdr traversal).
// Userspace loads handler .o files and updates this map to enable per-protocol
// inspection without modifying the main program.
struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 256);
    __type(key, __u32);
    __type(value, __u32);
} proto_handlers SEC(".maps");

// Default action when bpf_tail_call() returns (no handler in slot).
// 0 = XDP_PASS (default, backward-compatible), 1 = XDP_DROP (strict mode).
// Configurable at runtime via bpftool or axdp; mirrors config.toml [slots].default_action.
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} slot_def_action SEC(".maps");

// Per-port TCP/UDP handler prog arrays (key = dest port, host byte order).
// Userspace loads a handler .o and updates the fd at the port's index to enable
// per-service deep inspection without modifying or reloading the main program.
struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 65536);
    __type(key, __u32);
    __type(value, __u32);
} tcp_port_handlers SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 65536);
    __type(key, __u32);
    __type(value, __u32);
} udp_port_handlers SEC(".maps");

// Handler-blocked source IPs: src → blocked_until_ns (ktime).
// Port handlers write here on DROP verdict; the main program checks this after
// whitelist confirms the port is open, before dispatching to the handler again.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, RATE_MAP_MAX_ENTRIES_V4);
    __type(key, struct syn_rate_key_v4);
    __type(value, __u64);  // blocked_until_ns
} hblk4 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, RATE_MAP_MAX_ENTRIES_V6);
    __type(key, struct syn_rate_key_v6);
    __type(value, __u64);  // blocked_until_ns
} hblk6 SEC(".maps");

// Handler-validated UDP sessions: 5-tuple → validated_until_ns.
// UDP port handlers write here on PASS to create a fast path for subsequent
// packets from the same 5-tuple, bypassing the handler until TTL expires.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, RATE_MAP_MAX_ENTRIES_V4);
    __type(key, struct ct_key_v4);
    __type(value, __u64);  // validated_until_ns
} udp_hv4 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, RATE_MAP_MAX_ENTRIES_V6);
    __type(key, struct ct_key_v6);
    __type(value, __u64);  // validated_until_ns
} udp_hv6 SEC(".maps");
