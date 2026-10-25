#!/usr/bin/env bash
# auto-xdp-test-suite: component
set -euo pipefail
REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
# shellcheck source=tests/bash/testlib.sh
source "$REPO_ROOT/tests/bash/testlib.sh"

test_xdp_mode_uses_json_and_ignores_names() (
    source "$REPO_ROOT/runtime/auto_xdp_runtime_common.sh"
    local payload expected actual
    ip() {
        [[ "$*" == '-j -d link show dev xdpgeneric0' ]] || return 1
        printf '%s\n' "$payload"
    }
    while IFS='|' read -r expected payload; do
        actual=$(_auto_xdp_iface_xdp_mode xdpgeneric0)
        assert_eq "$actual" "$expected" "$payload" || return 1
    done <<'EOF'
none|[{"ifname":"xdpgeneric0","ifalias":"prog/xdp native"}]
native|[{"ifname":"xdpgeneric0","xdp":{"mode":1,"prog":{"id":77}}}]
generic|[{"ifname":"xdpgeneric0","xdp":{"mode":2,"prog":{"id":77}}}]
offload|[{"ifname":"xdpgeneric0","xdp":{"mode":3,"id":77}}]
multi|[{"ifname":"xdpgeneric0","xdp":{"mode":4,"attached":[{"mode":1},{"mode":3}]}}]
unknown|[{"ifname":"xdpgeneric0","xdp":{"mode":99}}]
unknown|7: xdpgeneric0: <UP> prog/xdp
EOF
)

test_xdp_mode_query_error_does_not_claim_no_attachment() (
    source "$REPO_ROOT/runtime/auto_xdp_runtime_common.sh"
    ip() { printf 'Operation not permitted\n' >&2; return 1; }
    assert_eq "$(_auto_xdp_iface_xdp_mode eth0)" "unknown" || return 1
    ip() { printf 'Device "eth0" does not exist.\n' >&2; return 1; }
    assert_eq "$(_auto_xdp_iface_xdp_mode eth0)" "none"
)

test_xdp_mode_parser_works_from_installed_layout_outside_source_tree() (
    local tmpdir
    tmpdir=$(mktemp -d)
    trap 'rm -rf "$tmpdir"' EXIT
    mkdir -p "$tmpdir/release/python/auto_xdp"
    cp "$REPO_ROOT/runtime/auto_xdp_runtime_common.sh" "$tmpdir/release/auto_xdp_runtime_common.sh"
    cp "$REPO_ROOT/auto_xdp/"{__init__,xdp_link}.py "$tmpdir/release/python/auto_xdp/"
    source "$tmpdir/release/auto_xdp_runtime_common.sh"
    PYTHON_LIB_DIR="$tmpdir/missing"
    ip() { printf '[{"ifname":"xdpgeneric0","xdp":{"mode":1,"prog":{"id":77}}}]\n'; }
    cd / || return 1
    assert_eq "$(_auto_xdp_iface_xdp_mode xdpgeneric0)" native
)

test_xdp_auto_retries_after_unsupported_and_keeps_first_error() (
    source "$REPO_ROOT/runtime/auto_xdp_runtime_common.sh"
    local tmpdir
    tmpdir=$(mktemp -d)
    trap 'rm -rf "$tmpdir"' EXIT
    _auto_xdp_saved_iface_mode() { printf 'auto:auto\n'; }
    ip() { printf '[{"ifname":"eth0"}]\n'; }
    _auto_xdp_attach_mode() {
        printf '%s\n' "$3" >> "$tmpdir/modes"
        if [[ "$3" == native ]]; then
            printf 'Error: interface xdpdrv attach failed: Operation not supported\n' >&2
            return 1
        fi
    }
    _auto_xdp_attach_candidate eth0 /pins/prog 2> "$tmpdir/errors" || return 1
    assert_eq "$(cat "$tmpdir/modes")" $'native\ngeneric' || return 1
    assert_eq "$AUTO_XDP_LAST_ATTACH_MODE" generic || return 1
    assert_eq "$AUTO_XDP_ATTACH_FATAL" 0 || return 1
    assert_contains "$AUTO_XDP_LAST_ATTACH_ERRORS" 'native [unsupported' || return 1
    assert_file_contains "$tmpdir/errors" 'Operation not supported'
)

test_xdp_auto_does_not_hide_fatal_errors_with_generic() (
    source "$REPO_ROOT/runtime/auto_xdp_runtime_common.sh"
    local tmpdir error expected status
    tmpdir=$(mktemp -d)
    trap 'rm -rf "$tmpdir"' EXIT
    _auto_xdp_saved_iface_mode() { printf 'auto:auto\n'; }
    ip() { printf '[{"ifname":"eth0"}]\n'; }
    _auto_xdp_attach_mode() {
        printf '%s\n' "$3" >> "$tmpdir/modes"
        if [[ "$3" == native ]]; then
            [[ "$LC_ALL" == C ]] || return 99
            printf '%s\n' "$error" >&2
            return 1
        fi
    }
    while IFS='|' read -r expected error; do
        : > "$tmpdir/modes"
        # Exercise the same locale contract as the real bpftool invocation.
        if LC_ALL=C _auto_xdp_attach_candidate eth0 /pins/prog 2> "$tmpdir/errors"; then
            printf 'fatal %s unexpectedly fell back\n' "$expected"
            return 1
        else
            status=$?
        fi
        assert_eq "$status" 1 || return 1
        assert_eq "$(cat "$tmpdir/modes")" native || return 1
        assert_eq "$AUTO_XDP_LAST_ATTACH_MODE" '' || return 1
        assert_eq "$AUTO_XDP_LAST_ATTACH_ERROR_CLASS" "$expected" || return 1
        assert_eq "$AUTO_XDP_ATTACH_FATAL" 1 || return 1
        assert_file_contains "$tmpdir/errors" "$error" || return 1
    done <<'EOF'
permission|Error: interface xdpdrv attach failed: Operation not permitted
permission|Error: interface xdpdrv attach failed: Permission denied
resource|Error: interface xdpdrv attach failed: Cannot allocate memory
resource|Error: interface xdpdrv attach failed: No space left on device
resource|Error: interface xdpdrv attach failed: No buffer space available
configuration|Error: interface xdpdrv attach failed: Invalid argument
busy|Error: interface xdpdrv attach failed: Device or resource busy
device|Error: invalid devname eth0
tooling|bpftool: command not found
unknown|Error: can't get pinned program: Operation not supported
unknown|kernel rejected test candidate
EOF
)

test_xdp_auto_retains_both_errors_when_fallback_fails() (
    source "$REPO_ROOT/runtime/auto_xdp_runtime_common.sh"
    local output
    _auto_xdp_saved_iface_mode() { printf 'auto:auto\n'; }
    ip() { printf '[{"ifname":"eth0"}]\n'; }
    _auto_xdp_attach_mode() {
        if [[ "$3" == native ]]; then
            printf 'Error: interface xdpdrv attach failed: Operation not supported\n' >&2
        else
            printf 'Error: interface xdpgeneric attach failed: Cannot allocate memory\n' >&2
        fi
        return 1
    }
    local tmpdir
    tmpdir=$(mktemp -d)
    trap 'rm -rf "$tmpdir"' EXIT
    if _auto_xdp_attach_candidate eth0 /pins/prog 2> "$tmpdir/errors"; then return 1; fi
    output=$(cat "$tmpdir/errors")
    assert_contains "$output" 'native [unsupported' || return 1
    assert_contains "$output" 'generic [resource' || return 1
    assert_contains "$AUTO_XDP_LAST_ATTACH_ERRORS" 'Operation not supported' || return 1
    assert_contains "$AUTO_XDP_LAST_ATTACH_ERRORS" 'Cannot allocate memory' || return 1
    assert_eq "$AUTO_XDP_ATTACH_FATAL" 1
)

test_xdp_mode_conflict_requires_confirmed_existing_opposite_mode() (
    source "$REPO_ROOT/runtime/auto_xdp_runtime_common.sh"
    local tmpdir active
    tmpdir=$(mktemp -d)
    trap 'rm -rf "$tmpdir"' EXIT
    _auto_xdp_saved_iface_mode() { printf 'auto:auto\n'; }
    ip() { printf '%s\n' "$active"; }
    _auto_xdp_attach_mode() {
        printf '%s\n' "$3" >> "$tmpdir/modes"
        if [[ "$3" == native ]]; then
            printf 'Error: interface xdpdrv attach failed: File exists\n' >&2
            return 1
        fi
    }
    active='[{"ifname":"eth0","xdp":{"mode":2,"prog":{"id":77}}}]'
    _auto_xdp_attach_candidate eth0 /pins/prog 2> "$tmpdir/errors" || return 1
    assert_eq "$AUTO_XDP_LAST_ATTACH_MODE" generic || return 1
    assert_eq "$(cat "$tmpdir/modes")" $'native\ngeneric' || return 1
    : > "$tmpdir/modes"
    active='[{"ifname":"eth0"}]'
    if _auto_xdp_attach_candidate eth0 /pins/prog 2> "$tmpdir/errors"; then return 1; fi
    assert_eq "$(cat "$tmpdir/modes")" native || return 1
    assert_eq "$AUTO_XDP_ATTACH_FATAL" 1
)

test_xdp_explicit_mode_does_not_downgrade_on_unsupported() (
    source "$REPO_ROOT/runtime/auto_xdp_runtime_common.sh"
    local tmpdir
    tmpdir=$(mktemp -d)
    trap 'rm -rf "$tmpdir"' EXIT
    _auto_xdp_saved_iface_mode() { printf 'native:generic\n'; }
    ip() { printf '[{"ifname":"eth0"}]\n'; }
    _auto_xdp_attach_mode() {
        printf '%s\n' "$3" >> "$tmpdir/modes"
        printf 'Error: interface xdpdrv attach failed: Operation not supported\n' >&2
        return 1
    }
    if _auto_xdp_attach_candidate eth0 /pins/prog 2> "$tmpdir/errors"; then return 1; fi
    assert_eq "$(cat "$tmpdir/modes")" native || return 1
    assert_eq "$AUTO_XDP_ATTACH_FATAL" 1
)

test_fatal_attach_error_blocks_runtime_nftables_fallback() (
    source "$REPO_ROOT/runtime/auto_xdp_runtime_common.sh"
    source "$REPO_ROOT/runtime/auto_xdp_start.sh"
    local tmpdir
    tmpdir=$(mktemp -d)
    trap 'rm -rf "$tmpdir"' EXIT
    XDP_OBJ_PATH="$tmpdir/program.o"
    BPF_PIN_DIR="$tmpdir/pins"
    RUN_STATE_DIR="$tmpdir/run"
    _IFACES=(eth0)
    mkdir "$RUN_STATE_DIR"
    touch "$XDP_OBJ_PATH"
    _auto_xdp_resolve_bpftool() { return 0; }
    ensure_bpffs() { return 0; }
    ensure_linux_conntrack() { return 0; }
    _auto_xdp_any_target_has_xdp() { return 1; }
    resolve_preferred_backend() { printf 'auto'; }
    resolve_committed_backend() { return 1; }
    transactional_reload_xdp() { AUTO_XDP_ATTACH_FATAL=1; return 1; }
    activate_nftables_backend() { touch "$tmpdir/nft-started"; }
    if select_backend > "$tmpdir/errors" 2>&1; then return 1; fi
    [[ ! -e "$tmpdir/nft-started" ]] || return 1
    assert_file_contains "$tmpdir/errors" 'automatic backend fallback disabled' || return 1
    # Unsupported modes remain eligible for the existing backend fallback.
    transactional_reload_xdp() { AUTO_XDP_ATTACH_FATAL=0; return 1; }
    select_backend > "$tmpdir/errors" 2>&1 || return 1
    [[ -e "$tmpdir/nft-started" ]]
)

test_unknown_or_multiple_modes_block_reload_before_loading() (
    source "$REPO_ROOT/runtime/auto_xdp_runtime_common.sh"
    local tmpdir current_mode
    tmpdir=$(mktemp -d)
    trap 'rm -rf "$tmpdir"' EXIT
    XDP_OBJ_PATH="$tmpdir/program.o"
    BPF_PIN_DIR="$tmpdir/pins"
    IFACES=(eth0)
    touch "$XDP_OBJ_PATH"
    ensure_linux_conntrack() { return 0; }
    _auto_xdp_iface_xdp_mode() { printf '%s' "$current_mode"; }
    bpftool() { touch "$tmpdir/program-loaded"; return 0; }
    for current_mode in unknown multi; do
        if transactional_reload_xdp > "$tmpdir/errors" 2>&1; then return 1; fi
        [[ ! -e "$tmpdir/program-loaded" && ! -e "${BPF_PIN_DIR}_next" ]] || return 1
        assert_eq "$AUTO_XDP_ATTACH_FATAL" 1 || return 1
        assert_file_contains "$tmpdir/errors" "Cannot confirm a single XDP mode" || return 1
    done
)

test_fatal_attach_error_blocks_installer_nftables_fallback() (
    source "$REPO_ROOT/setup_xdp.sh"
    local tmpdir
    tmpdir=$(mktemp -d)
    trap 'rm -rf "$tmpdir"' EXIT
    XDP_OBJ_INSTALLED="$tmpdir/program.o"
    IFACES=(eth0)
    touch "$XDP_OBJ_INSTALLED"
    ensure_bpffs() { return 0; }
    cleanup_existing_xdp() { return 0; }
    _auto_xdp_any_target_has_xdp() { return 1; }
    _auto_xdp_resolve_preferred_backend() { printf 'auto'; }
    transactional_reload_xdp() {
        AUTO_XDP_ATTACH_FATAL=1
        AUTO_XDP_LAST_ATTACH_ERRORS='native [permission]: Operation not permitted'
        return 1
    }
    ensure_nftables_available() { touch "$tmpdir/nft-started"; }
    if deploy_backend_step > "$tmpdir/errors" 2>&1; then return 1; fi
    [[ ! -e "$tmpdir/nft-started" ]] || return 1
    assert_eq "$XDP_FALLBACK_BLOCKED" 1 || return 1
    assert_contains "$XDP_FALLBACK_REASON" 'Operation not permitted' || return 1
    assert_file_contains "$tmpdir/errors" 'automatic nftables fallback disabled'
)

run_discovered_tests "${BASH_SOURCE[0]}" "xdp modes"
finish_tests
