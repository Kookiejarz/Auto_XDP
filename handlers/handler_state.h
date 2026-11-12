#pragma once

/* Required kernel capabilities, loaded before this object's BPF programs.
 * Keep this in the ELF so dependency handling also works for prebuilt objects. */
#define AXDP_KERNEL_MODULES(names_json) \
    static const char axdp_kernel_modules[] \
    __attribute__((section(".axdp_kmods"), used)) = names_json

/* Opt in to preserving protocol state across compatible object replacements.
 * Bump schema whenever layout, meaning, admission rules or old/new concurrent
 * access cease to be compatible. List every persistent private map in JSON.
 * Packet scratch maps should not be listed. */
#define AXDP_STATE_SCHEMA(schema, maps_json) \
    static const char axdp_state_contract[] \
    __attribute__((section(".axdp_state"), used)) = \
        "{\"version\":1,\"schema\":\"" schema "\",\"maps\":" maps_json "}"
