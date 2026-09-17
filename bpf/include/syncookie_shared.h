#pragma once

#include "keys.h"

struct syncookie_tuple_v4 {
    __be16 sport;
    __be16 dport;
    __be32 saddr;
    __be32 daddr;
};

struct syncookie_tuple_v6 {
    __be16 sport;
    __be16 dport;
    __u32 saddr[4];
    __u32 daddr[4];
};

struct syncookie_invalid_key_v4 {
    __be32 addr;
    __u32 dest_port;
};

struct syncookie_invalid_key_v6 {
    __u32 addr[4];
    __u32 dest_port;
};

struct axdp_tcp_req_attrs {
    __u32 rcv_tsval;
    __u32 rcv_tsecr;
    __u16 mss;
    __u8 rcv_wscale;
    __u8 snd_wscale;
    __u8 ecn_ok;
    __u8 wscale_ok;
    __u8 sack_ok;
    __u8 tstamp_ok;
    __u8 usec_ts_ok;
    __u8 reserved[3];
};
