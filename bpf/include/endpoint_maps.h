/* SPDX-License-Identifier: GPL-2.0 */
#pragma once
#include "keys.h"

/* Shared ingress policy; zone entries, including explicit deny, take precedence. */
struct endpoint_scope_key {
    __u32 ifindex;  // zero represents the global public scope
    __u16 port;     // host byte order
    __u8 proto;
    __u8 family;
    __u32 daddr[4]; // network byte order; zero represents a wildcard bind
};

_Static_assert(sizeof(struct endpoint_scope_key) == 24, "endpoint scope key ABI");
_Static_assert(__builtin_offsetof(struct endpoint_scope_key, daddr) == 8, "endpoint address ABI");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, struct endpoint_scope_key);
    __type(value, __u32);
} endpoint_scopes SEC(".maps");


struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 65536);
    __type(key, __u32);   // port number (host byte order) as array index
    __type(value, struct tcp_endpoint_policy);
} tcp_whitelist SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 65536);
    __type(key, __u32);   // port number (host byte order) as array index
    __type(value, __u32); // 1 = allow
} udp_whitelist SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, struct zone_port_key);
    __type(value, struct tcp_endpoint_policy);
} tcp_zone_whitelist SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, struct zone_port_key);
    __type(value, __u32);
} udp_zone_whitelist SEC(".maps");
