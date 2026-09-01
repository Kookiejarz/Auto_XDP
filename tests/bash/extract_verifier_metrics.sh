#!/usr/bin/env bash

set -euo pipefail

phase="${1:?usage: extract_verifier_metrics.sh PHASE}"

awk -v phase="$phase" '
    /found program .*code size [0-9]+ insns/ {
        for (i = 1; i <= NF; i++)
            if ($i == "size") static_insns = $(i + 1)
    }
    /^verification time [0-9]+ usec$/ { verification_time_usec = $3 }
    /^stack depth [0-9]+(\+[0-9]+)?$/ {
        stack_depth = $3
        sub(/\+.*/, "", stack_depth)
    }
    /^processed [0-9]+ insns / {
        processed_insns = $2
        for (i = 1; i <= NF; i++) {
            if ($i == "max_states_per_insn") max_states_per_insn = $(i + 1)
            if ($i == "total_states") total_states = $(i + 1)
            if ($i == "peak_states") peak_states = $(i + 1)
        }
    }
    END {
        if (!static_insns || !verification_time_usec || !stack_depth ||
            !processed_insns || !max_states_per_insn || !total_states ||
            !peak_states)
            exit 1
        gsub(/[[:space:]]+/, "_", phase)
        printf "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", phase,
               static_insns, processed_insns, max_states_per_insn,
               total_states, peak_states, verification_time_usec, stack_depth
    }
'
