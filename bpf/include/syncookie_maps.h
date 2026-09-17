#pragma once

#include "syncookie_shared.h"

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, struct syncookie_tuple_v4);
    __type(value, struct axdp_tcp_req_attrs);
} sync_handoff4 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, struct syncookie_tuple_v6);
    __type(value, struct axdp_tcp_req_attrs);
} sync_handoff6 SEC(".maps");
