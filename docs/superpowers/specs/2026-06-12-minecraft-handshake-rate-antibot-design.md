# Minecraft Handler: Per-Prefix Handshake-Rate Anti-Bot

## Problem

`handlers/minecraft_handler.c` already validates the Minecraft Java handshake
protocol byte-by-byte (handshake → status/ping or login), and drops/penalizes
flows that violate TCP sequencing or send malformed packets. This filters
"speaks invalid Minecraft protocol" bots.

It does **not** currently catch sources that speak *valid* protocol but
complete handshakes too often — e.g. scanner fleets repeatedly issuing status
(server-list) pings, or join-flood bots completing login handshakes with many
different usernames from IPs in the same network block.

## Goal

Add per-`/24` (IPv4) / per-`/64` (IPv6) rate limits on **completed**
handshakes, separately for:

- **status handshakes** (client validated through `MC_AWAIT_STATUS_REQUEST`,
  about to enter `MC_AWAIT_PING`)
- **login handshakes** (client validated through `MC_AWAIT_LOGIN`, about to
  call `verify_and_pass`)

When either threshold is exceeded, ban the **offending source IP** (not the
whole prefix) for `MC_BLOCK_NS` via the existing `hblk4`/`hblk6` mechanism,
using the existing `penalize_and_drop` helper.

## Design

### New maps

```c
struct mc_rate_key_v4 {
    __be32 prefix; // saddr masked to /24
};

struct mc_rate_key_v6 {
    __u32 prefix[2]; // saddr masked to /64 (first 8 bytes)
};

struct mc_rate_val {
    __u64 window_start_ns;
    __u32 count;
};
```

Four new `BPF_MAP_TYPE_LRU_HASH` maps, sized similarly to `hblk4`/`hblk6`:

- `mc_status_rate4` (key `mc_rate_key_v4`, value `mc_rate_val`)
- `mc_status_rate6` (key `mc_rate_key_v6`, value `mc_rate_val`)
- `mc_login_rate4`  (key `mc_rate_key_v4`, value `mc_rate_val`)
- `mc_login_rate6`  (key `mc_rate_key_v6`, value `mc_rate_val`)

### New constants

```c
#define MC_STATUS_RATE_WINDOW_NS (10ULL * 1000000000ULL)
#define MC_STATUS_RATE_MAX       30   // ~3/sec per /24 or /64

#define MC_LOGIN_RATE_WINDOW_NS  (60ULL * 1000000000ULL)
#define MC_LOGIN_RATE_MAX        20   // per minute per /24 or /64
```

These are starting defaults — tune after observing real traffic via the
ringbuf/TUI event stream. They are hardcoded constants (consistent with
`MC_TIMEOUT_NS`, `MC_BLOCK_NS`, `MC_MAX_OUT_OF_ORDER`), not exposed through
`mc-config.toml`, since the handler is compiled as-is without templating.

### Key-fill helpers

Mirror the existing `fill_block_key_v4`/`fill_block_key_v6` style:

```c
static __always_inline void fill_rate_key_v4(struct mc_rate_key_v4 *key, const struct flow_key *ct)
{
    key->prefix = (__be32)ct->saddr[0] & bpf_htonl(0xFFFFFF00u); // /24
}

static __always_inline void fill_rate_key_v6(struct mc_rate_key_v6 *key, const struct flow_key *ct)
{
    // /64 = first 8 bytes of the address (ct->saddr[0], ct->saddr[1])
    key->prefix[0] = ct->saddr[0];
    key->prefix[1] = ct->saddr[1];
}
```

### Rate-check helper

BPF doesn't support a true generic map reference, so provide one
implementation per (family) pair, parameterized over which map to hit via a
small macro to avoid duplicating the window/reset/increment logic four times:

```c
#define MC_RATE_CHECK(map, key, now, window_ns, max_count, over_limit)       \
    do {                                                                     \
        struct mc_rate_val *_v = bpf_map_lookup_elem((map), (key));         \
        if (!_v) {                                                           \
            struct mc_rate_val _init = { .window_start_ns = (now), .count = 1 }; \
            bpf_map_update_elem((map), (key), &_init, BPF_ANY);             \
            (over_limit) = false;                                           \
        } else if ((now) - _v->window_start_ns > (window_ns)) {             \
            _v->window_start_ns = (now);                                    \
            _v->count = 1;                                                  \
            (over_limit) = false;                                           \
        } else {                                                            \
            _v->count++;                                                    \
            (over_limit) = _v->count > (max_count);                         \
        }                                                                    \
    } while (0)
```

This is a fixed-window counter (not sliding-window) — same approximation
tradeoff already accepted by `hblk4/6`'s LRU eviction. Adequate for catching
sustained abuse without per-packet overhead of a sliding window.

### Hook points (minimal diff to existing state machine)

In `xdp_minecraft_handler`, both call sites are inside the existing
`payload_len > 0` block, immediately before the existing state transitions:

1. **Status handshake completion** — where the code currently does:
   ```c
   pending->state = MC_AWAIT_PING;
   pending->expected_seq += payload_len;
   pending->fails = 0;
   pending->last_seen_ns = now;
   return restore_and_return(ctx, inner_off, XDP_PASS);
   ```
   Before this `return`, compute the rate key (v4 or v6 based on `family`),
   call `MC_RATE_CHECK` against `mc_status_rate4`/`mc_status_rate6`. If
   over limit, `return penalize_and_drop(ctx, inner_off, &key, now);` instead.

2. **Login handshake completion** — where the code currently does:
   ```c
   if (pending->state == MC_AWAIT_LOGIN) {
       if (!inspect_login_packet(...))
           ...
       return verify_and_pass(ctx, inner_off, &key, now);
   }
   ```
   Before calling `verify_and_pass`, run the same `MC_RATE_CHECK` against
   `mc_login_rate4`/`mc_login_rate6`. If over limit,
   `return penalize_and_drop(ctx, inner_off, &key, now);` instead of
   `verify_and_pass`.

### Non-goals

- No changes to `mc-config.toml`, `auto_xdp` Python code, or map-loading
  infrastructure — these are plain BPF maps declared with `SEC(".maps")`,
  loaded the same way as the existing `hblk4/6`/`tcp_ct4/6` maps.
- No userspace visibility/tuning of thresholds in this iteration — pure
  in-handler constants.
- No behavioral fingerprinting of login packet fields (protocol_version,
  username patterns) — out of scope per discussion; XDP-level scope is
  limited to handshake-completion rate.

## Testing

- `tests/bash/` already has handler-level tests
  (`test_setup_xdp.sh` references the handler build). Add cases that:
  - Send `MC_STATUS_RATE_MAX + 1` valid status handshakes from the same `/24`
    within `MC_STATUS_RATE_WINDOW_NS` and confirm the last one is dropped and
    the triggering source IP lands in `hblk4`/`hblk6`.
  - Same for `MC_LOGIN_RATE_MAX + 1` valid login handshakes.
  - Confirm traffic from a *different* `/24` is unaffected (prefix isolation).
  - Confirm counters reset correctly after `window_ns` elapses.
