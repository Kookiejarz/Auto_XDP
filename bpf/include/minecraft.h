#pragma once

#include "flow_keys.h"
#include "linux_conntrack.h"
#include "map_sizes.h"

#define MC_PROFILE_ID 1

#define MC_PROTOCOL_DEADLINE_NS (10ULL * 1000000000ULL)
#define MC_CHALLENGE_DEADLINE_NS (20ULL * 1000000000ULL)
#define MC_OPAQUE_DEADLINE_NS (15ULL * 1000000000ULL)
#define MC_POST_CHALLENGE_MIN_NS (1000ULL * 1000000ULL)
#define MC_PREVERIFY_BYTES (256U * 1024U)
#define MC_PREVERIFY_PACKETS 256U

#define MC_MARK_MASK 0xffff0000U
#define MC_MARK_MAGIC 0xa0000000U
#define MC_MARK_MAGIC_MASK 0xf0000000U
#define MC_MARK_EPOCH_SHIFT 20
#define MC_MARK_EPOCH_MASK 0x0ff00000U
#define MC_MARK_PROOF_SHIFT 16
#define MC_MARK_PROOF_MASK 0x000f0000U

enum mc_parse_result {
    MC_PARSE_MATCH,
    MC_PARSE_NO_MATCH,
    MC_PARSE_NEED_MORE,
};

enum mc_proof_level {
    MC_PROOF_NONE = 0,
    MC_PROOF_HANDSHAKE = 1,
    MC_PROOF_LOGIN_START = 2,
    MC_PROOF_SERVER_PROGRESS = 3,
    MC_PROOF_CHALLENGE_DIALOGUE = 4,
    MC_PROOF_WIRE_VERIFIED = 5,
    MC_PROOF_EXTERNAL_ATTESTED = 6,
};

enum mc_l7_state {
    MC_L7_HANDSHAKE = 1,
    MC_L7_STATUS_REQUEST,
    MC_L7_STATUS_PING,
    MC_L7_STATUS_DONE,
    MC_L7_LOGIN_START,
    MC_L7_AWAIT_SERVER,
    MC_L7_SERVER_CHALLENGE,
    MC_L7_ENCRYPTED_PROBATION,
    MC_L7_OPAQUE_PROBATION,
};

#define MC_F_SERVER_AFTER_CHALLENGE (1U << 0)
#define MC_F_COMPRESSION_ENABLED (1U << 1)

struct mc_l7_pending_val {
    __u64 first_seen_ns;
    __u64 hard_deadline_ns;
    __u64 challenge_at_ns;
    __u64 policy_generation;
    __u64 profile_generation;
    __u32 ingress_bytes;
    __u32 egress_bytes;
    __u16 packets;
    __s32 protocol_version;
    __u8 state;
    __u8 proof_level;
    __u8 intention;
    __u8 flags;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 4096);
    __type(key, struct flow_key);
    __type(value, struct mc_l7_pending_val);
} mc_l7_pending SEC(".maps");

static __always_inline __u8 mc_epoch(__u64 profile_generation)
{
    __u8 epoch = (__u8)profile_generation;
    return epoch ? epoch : 1;
}

static __always_inline __u32 mc_mark_encode(__u64 profile_generation, __u8 proof)
{
    return MC_MARK_MAGIC |
           ((__u32)mc_epoch(profile_generation) << MC_MARK_EPOCH_SHIFT) |
           (((__u32)proof << MC_MARK_PROOF_SHIFT) & MC_MARK_PROOF_MASK);
}

static __always_inline bool mc_mark_valid(
    __u32 mark, __u64 profile_generation, __u8 minimum_proof)
{
    return (mark & MC_MARK_MAGIC_MASK) == MC_MARK_MAGIC &&
           (mark & MC_MARK_EPOCH_MASK) ==
               ((__u32)mc_epoch(profile_generation) << MC_MARK_EPOCH_SHIFT) &&
           ((mark & MC_MARK_PROOF_MASK) >> MC_MARK_PROOF_SHIFT) >= minimum_proof;
}

static __always_inline void mc_mark_conn(
    struct nf_conn *ct, __u64 profile_generation, __u8 proof)
{
    __u32 old_mark = ct->mark;
    ct->mark = (old_mark & ~MC_MARK_MASK) | mc_mark_encode(profile_generation, proof);
}
