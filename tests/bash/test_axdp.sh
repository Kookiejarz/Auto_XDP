#!/usr/bin/env bash

set -euo pipefail

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]:-}")/../.." && pwd)
BASE_PATH="${PATH:-/usr/bin:/bin:/usr/sbin:/sbin}"
# shellcheck source=tests/bash/testlib.sh
source "$REPO_ROOT/tests/bash/testlib.sh"

test_format_helpers_render_human_output() (
    source "$REPO_ROOT/axdp"
    set +e

    assert_eq "$(human_bytes 1536)" "1.50 KiB" || return 1
    assert_eq "$(human_bytes -1)" "-" || return 1
    assert_eq "$(human_bps 1500)" "1.50 Kbps" || return 1
    assert_eq "$(format_rate 10 125 1)" "10.00 pps / 1.00 Kbps"
)

test_parse_stats_args_sets_expected_flags() (
    source "$REPO_ROOT/axdp"
    set +e

    WATCH_MODE=0
    SHOW_RATES=0
    INTERVAL=1
    IFACE=""

    parse_stats_args --watch --rates --interval 5 --interface eth9 || return 1
    assert_eq "$WATCH_MODE" "1" || return 1
    assert_eq "$SHOW_RATES" "1" || return 1
    assert_eq "$INTERVAL" "5" || return 1
    assert_eq "$IFACE" "eth9"
)

test_parse_ports_args_sets_expected_flags() (
    source "$REPO_ROOT/axdp"
    set +e

    PORTS_WATCH=0
    PORTS_INTERVAL=2

    parse_ports_args --watch --interval 7 || return 1
    assert_eq "$PORTS_WATCH" "1" || return 1
    assert_eq "$PORTS_INTERVAL" "7"
)

test_csv_helpers_sort_and_diff_ports() (
    source "$REPO_ROOT/axdp"
    set +e

    local sorted
    sorted=$(csv_to_sorted_lines "443,22,80")
    assert_eq "$sorted" $'22\n80\n443' || return 1
    assert_eq "$(diff_csv "22,80" "22,443" added)" "443" || return 1
    assert_eq "$(diff_csv "22,80" "22,443" removed)" "80"
)

test_valid_log_level_and_config_updates() (
    source "$REPO_ROOT/axdp"
    set +e

    valid_log_level debug || return 1
    valid_log_level trace >/dev/null 2>&1
    local status=$?
    assert_eq "$status" "1" || return 1

    local tmpdir
    tmpdir=$(mktemp -d)
    CONFIG_FILE="$tmpdir/auto_xdp.env"
    cat >"$CONFIG_FILE" <<'EOF_CFG'
LOG_LEVEL="info"
SYNC_INTERVAL="30"
EOF_CFG

    set_config_var "LOG_LEVEL" "debug" || return 1
    assert_file_contains "$CONFIG_FILE" 'LOG_LEVEL="debug"'
)

test_run_log_level_reads_and_updates_config() (
    source "$REPO_ROOT/axdp"
    set +e

    local tmpdir
    tmpdir=$(mktemp -d)
    CONFIG_FILE="$tmpdir/auto_xdp.env"
    cat >"$CONFIG_FILE" <<'EOF_CFG'
LOG_LEVEL="info"
EOF_CFG

    PATH="$tmpdir/empty-bin:$BASE_PATH"
    mkdir -p "$tmpdir/empty-bin"

    assert_eq "$(run_log_level)" "info" || return 1

    local output
    output=$(run_log_level DEBUG 2>&1) || return 1
    assert_contains "$output" "LOG_LEVEL=debug" || return 1
    assert_file_contains "$CONFIG_FILE" 'LOG_LEVEL="debug"'
)

test_detect_backend_prefers_xdp_runtime_state() (
    source "$REPO_ROOT/axdp"
    set +e

    local tmpdir
    tmpdir=$(mktemp -d)
    RUN_STATE_DIR="$tmpdir/run"
    BPF_PIN_DIR="$tmpdir/bpf"
    mkdir -p "$RUN_STATE_DIR" "$BPF_PIN_DIR"
    printf 'xdp\n' > "$RUN_STATE_DIR/backend"
    touch "$BPF_PIN_DIR/pkt_counters"

    BACKEND=""
    IFACE="eth0"
    detect_backend || return 1
    assert_eq "$BACKEND" "xdp"
)

test_detect_backend_falls_back_to_nftables() (
    source "$REPO_ROOT/axdp"
    set +e

    local tmpdir
    tmpdir=$(mktemp -d)
    RUN_STATE_DIR="$tmpdir/run"
    BPF_PIN_DIR="$tmpdir/bpf"
    mkdir -p "$RUN_STATE_DIR" "$BPF_PIN_DIR" "$tmpdir/bin"
    printf 'nftables\n' > "$RUN_STATE_DIR/backend"

    cat >"$tmpdir/bin/nft" <<'EOF_NFT'
#!/bin/sh
exit 0
EOF_NFT
    chmod +x "$tmpdir/bin/nft"

    PATH="$tmpdir/bin:$BASE_PATH"
    BACKEND=""
    IFACE="eth0"
    detect_backend || return 1
    assert_eq "$BACKEND" "nftables"
)

test_detect_backend_reports_missing_state() (
    source "$REPO_ROOT/axdp"
    set +e

    local tmpdir
    tmpdir=$(mktemp -d)
    RUN_STATE_DIR="$tmpdir/run"
    BPF_PIN_DIR="$tmpdir/bpf"
    mkdir -p "$RUN_STATE_DIR" "$BPF_PIN_DIR" "$tmpdir/bin"

    PATH="$tmpdir/bin:$BASE_PATH"
    IFACE="eth0"

    local output status
    output=$(detect_backend 2>&1)
    status=$?
    assert_eq "$status" "1" || return 1
    assert_contains "$output" "No active Auto XDP backend detected."
)

test_cli_help_runs_without_runtime_state() (
    local output
    output=$(bash "$REPO_ROOT/axdp" help)
    assert_contains "$output" "Usage: axdp"
)

run_test "axdp formats human-readable counters and rates" test_format_helpers_render_human_output
run_test "axdp parses stats flags" test_parse_stats_args_sets_expected_flags
run_test "axdp parses ports flags" test_parse_ports_args_sets_expected_flags
run_test "axdp sorts and diffs csv port lists" test_csv_helpers_sort_and_diff_ports
run_test "axdp validates log levels and rewrites config" test_valid_log_level_and_config_updates
run_test "axdp reads and updates runtime log level" test_run_log_level_reads_and_updates_config
run_test "axdp detects active xdp backend from runtime state" test_detect_backend_prefers_xdp_runtime_state
run_test "axdp detects nftables fallback backend" test_detect_backend_falls_back_to_nftables
run_test "axdp reports when no backend is active" test_detect_backend_reports_missing_state
run_test "axdp help works without installation" test_cli_help_runs_without_runtime_state

finish_tests
