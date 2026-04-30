#pragma once

// Shared conntrack flag constants.
// Included by both the XDP ingress program (via common.h) and the TC egress
// program (tc_flow_track.c).  Keep this header free of any XDP- or TC-specific
// kernel headers so it compiles cleanly in both build environments.

// Bit 63 is set in the conntrack ktime value for half-open (SYN-only) entries.
// XDP ingress writes (ktime_get_ns() | CT_SYN_PENDING) when a whitelisted SYN
// arrives; TC egress must mask this bit before computing ages and preserve it
// when refreshing timestamps.  Linux ktime_get_ns() won't reach 2^63 ns
// (~292 years uptime), so bit 63 is permanently safe as a flag.
#define CT_SYN_PENDING (1ULL << 63)
