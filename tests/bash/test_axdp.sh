#!/usr/bin/env bash
# auto-xdp-test-suite: component

set -euo pipefail

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]:-}")/../.." && pwd)
BASE_PATH="${PATH:-/usr/bin:/bin:/usr/sbin:/sbin}"
# shellcheck source=tests/bash/testlib.sh
source "$REPO_ROOT/tests/bash/testlib.sh"

# NOTE: stats/ports formatting, flag parsing, and csv helpers migrated to
# Python (auto_xdp/admin/cli.py); covered by tests/python/test_admin_cli.py.

test_run_log_level_reads_and_updates_config() (
    source "$REPO_ROOT/axdp"
    set +e

    local tmpdir
    tmpdir=$(mktemp -d)
    TOML_CONFIG="$tmpdir/config.toml"
    PYTHON_LIB_DIR="$REPO_ROOT"
    require_root() { :; }
    cat >"$TOML_CONFIG" <<'EOF_CFG'
[daemon]
log_level = "info"
EOF_CFG

    PATH="$tmpdir/empty-bin:$BASE_PATH"
    mkdir -p "$tmpdir/empty-bin"
    reload_daemon() { :; }

    assert_eq "$(run_log_level)" "info" || return 1

    local output
    output=$(run_log_level DEBUG 2>&1) || return 1
    assert_contains "$output" "daemon.log_level=debug" || return 1
    assert_file_contains "$TOML_CONFIG" "[daemon]"
    assert_file_contains "$TOML_CONFIG" 'log_level = "debug"'
)

test_run_under_attack_reads_and_updates_config() (
    source "$REPO_ROOT/axdp"
    set +e

    local tmpdir
    tmpdir=$(mktemp -d)
    TOML_CONFIG="$tmpdir/config.toml"
    PYTHON_LIB_DIR="$REPO_ROOT"
    require_root() { :; }
    cat >"$TOML_CONFIG" <<'EOF_CFG'
[under_attack]
enabled = false
EOF_CFG

    PATH="$tmpdir/empty-bin:$BASE_PATH"
    mkdir -p "$tmpdir/empty-bin"
    reload_daemon() { :; }

    assert_eq "$(run_under_attack)" "off" || return 1

    local output
    output=$(run_under_attack on 2>&1) || return 1
    assert_contains "$output" "under_attack.enabled=true" || return 1
    assert_file_contains "$TOML_CONFIG" "[under_attack]"
    assert_file_contains "$TOML_CONFIG" "enabled = true"
)

test_main_dispatches_under_attack_command() (
    source "$REPO_ROOT/axdp"
    set +e

    local called=""
    run_under_attack() {
        called="yes:$*"
    }

    main under-attack on || return 1
    assert_eq "$called" "yes:on"
)

test_main_dispatches_integrated_policy_commands() (
    source "$REPO_ROOT/axdp"
    set +e

    local calls=""
    run_exposure() { calls+="discover:$*|"; }
    run_allow() { calls+="allow:$*|"; }
    run_deny() { calls+="deny:$*|"; }
    run_mode() { calls+="mode:$*|"; }

    main discover || return 1
    main allow paper.service tcp/25565 --profile minecraft || return 1
    main deny paper.service tcp/25565 || return 1
    main mode enforce || return 1
    assert_eq "$calls" "discover:|allow:paper.service tcp/25565 --profile minecraft|deny:paper.service tcp/25565|mode:enforce|"
)

test_enable_refuses_ungranted_remote_ssh() (
    source "$REPO_ROOT/axdp"
    set +e

    local tmpdir
    tmpdir=$(mktemp -d)
    TOML_CONFIG="$tmpdir/config.toml"
    : > "$TOML_CONFIG"
    require_root() { :; }
    run_admin_config() {
        [[ "$*" == "explain tcp/22" ]] && printf 'BLOCK\n'
    }
    SSH_CONNECTION="198.51.100.4 40000 203.0.113.2 22"
    local output status
    output=$(run_enable 2>&1)
    status=$?
    [[ $status -ne 0 ]] || return 1
    assert_contains "$output" "current SSH listener has no matching grant"
)

test_remote_ssh_guard_rejects_mixed_allow_and_block() (
    source "$REPO_ROOT/axdp"
    set +e

    run_admin_config() { printf 'ALLOW\n---\nBLOCK\n'; }
    SSH_CONNECTION="198.51.100.4 40000 203.0.113.2 22"
    ! remote_access_is_granted
)

test_service_command_propagates_primary_daemon_failure() (
    source "$REPO_ROOT/axdp"
    set +e

    local tmpdir
    tmpdir=$(mktemp -d)
    SYSTEMD_RUN_DIR="$tmpdir"
    systemctl() {
        [[ "$1" == "list-unit-files" ]] && return 0
        [[ "$2" == "$RELAY_SERVICE_NAME" ]]
    }

    run_service_cmd restart
    [[ $? -ne 0 ]]
)

test_enable_failure_restores_audit_discovery() (
    source "$REPO_ROOT/axdp"
    set +e

    local tmpdir calls=""
    tmpdir=$(mktemp -d)
    TOML_CONFIG="$tmpdir/config.toml"
    : > "$TOML_CONFIG"
    require_root() { :; }
    remote_access_is_granted() { return 0; }
    run_admin_config() { calls+="config:$*|"; }
    run_service_cmd() {
        calls+="service:$*|"
        [[ "$1" != "restart" ]]
    }

    run_enable >/dev/null 2>&1
    [[ $? -ne 0 ]] || return 1
    assert_eq "$calls" "config:policy mode enforce|service:restart|config:policy mode audit|service:start|"
)

test_enable_waits_for_health_and_rolls_back_on_timeout() (
    local scenario
    for scenario in xdp nftables timeout; do
        (
            source "$REPO_ROOT/axdp"
            set +e
            local tmpdir attempts=0 output status
            tmpdir=$(mktemp -d)
            trap 'rm -rf "$tmpdir"' EXIT
            TOML_CONFIG="$tmpdir/config.toml"
            touch "$TOML_CONFIG"
            require_root() { :; }
            remote_access_is_granted() { return 0; }
            run_admin_config() {
                printf 'config:%s\n' "$*" >> "$tmpdir/calls"
                [[ "$*" != 'policy mode' ]] || printf 'enforce\n'
            }
            run_service_cmd() { printf 'service:%s\n' "$*" >> "$tmpdir/calls"; }
            run_admin_runtime() { printf 'runtime:%s\n' "$*" >> "$tmpdir/calls"; }
            run_backend() {
                if (( attempts == 0 )); then
                    printf 'No active Auto XDP backend detected.\n' >&2
                    return 1
                fi
                if (( attempts == 1 )) || [[ "$scenario" == timeout ]]; then
                    printf 'Health    : degraded\n'
                    return 1
                fi
                printf 'Backend   : %s\nHealth    : healthy\n' "$scenario"
            }
            sleep() {
                attempts=$((attempts + 1))
                [[ "$scenario" != timeout ]] || SECONDS=$((SECONDS + 40))
            }
            output=$(run_enable --force 2>&1)
            status=$?
            if [[ "$scenario" == timeout ]]; then
                assert_eq "$status" 1 "$output" || exit 1
                [[ "$output" != *'Auto XDP enforcement enabled.'* ]] || exit 1
                assert_contains "$output" 'Health    : degraded' || exit 1
                assert_file_contains "$tmpdir/calls" $'config:policy mode audit\nservice:stop\nruntime:deactivate\nservice:start' || exit 1
            else
                assert_eq "$status" 0 "$output" || exit 1
                assert_contains "$output" "Backend   : $scenario" || exit 1
                assert_contains "$output" 'Auto XDP enforcement enabled.' || exit 1
                [[ "$output" != *'No active'* && "$output" != *degraded* ]] || exit 1
                assert_eq "$(cat "$tmpdir/calls")" $'config:policy mode enforce\nservice:restart' || exit 1
            fi
        ) || { printf 'enable scenario failed: %s\n' "$scenario"; return 1; }
    done
)

test_status_combines_service_and_backend_health() (
    source "$REPO_ROOT/axdp"
    set +e

    run_service_cmd() { printf 'service active\n'; }
    run_backend() { printf 'Backend   : xdp\nHealth    : healthy\n'; }

    local output
    output=$(run_status) || return 1
    assert_contains "$output" "service active" || return 1
    assert_contains "$output" "Auto XDP protection health" || return 1
    assert_contains "$output" "Health    : healthy"
)

test_check_update_propagates_main_ref_to_downloaded_installer() (
    source "$REPO_ROOT/axdp"
    set +e

    local tmpdir
    tmpdir=$(mktemp -d)
    mkdir -p "$tmpdir/bin"
    cat > "$tmpdir/bin/curl" <<'EOF_CURL'
#!/bin/sh
out=""
url=""
while [ "$#" -gt 0 ]; do
    case "$1" in
        -o) out="$2"; shift 2 ;;
        -*) shift ;;
        *) url="$1"; shift ;;
    esac
done
if [ "$url" = "https://api.github.com/repos/Kookiejarz/Auto_XDP/commits/main" ]; then
    printf '{"sha":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}\n'
    exit 0
fi
cat > "$out" <<'EOF_INSTALLER'
#!/bin/bash
printf '%s|%s|%s\n' "$AUTO_XDP_SOURCE_REF" "$AUTO_XDP_FORCE_REMOTE" "$*" > "$AXDP_UPDATE_TEST_LOG"
EOF_INSTALLER
EOF_CURL
    chmod +x "$tmpdir/bin/curl"

    PATH="$tmpdir/bin:$BASE_PATH"
    AXDP_UPDATE_TEST_LOG="$tmpdir/update.log"
    export AXDP_UPDATE_TEST_LOG

    run_check_update --force || return 1
    assert_file_contains "$tmpdir/update.log" "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa|1|--check-update --force"
)

test_main_loads_configured_ifaces_for_tui() (
    source "$REPO_ROOT/axdp"
    set +e

    local tmpdir
    tmpdir=$(mktemp -d)
    CONFIG_FILE="$tmpdir/auto_xdp.env"
    cat >"$CONFIG_FILE" <<'EOF_CFG'
IFACES="eth0 eth1"
IFACE="eth0"
EOF_CFG

    local called=""
    run_tui() {
        called="$IFACES"
    }

    main tui || return 1
    assert_eq "$called" "eth0 eth1"
)

test_main_reports_stale_admin_cli_for_tui() (
    source "$REPO_ROOT/axdp"
    set +e

    local tmpdir output status
    tmpdir=$(mktemp -d)
    PYTHON_LIB_DIR="$tmpdir/python"
    # Keep a real installed /etc/auto_xdp/auto_xdp.env from overriding the fake
    # PYTHON_LIB_DIR when this suite runs on a host with Auto XDP installed.
    CONFIG_FILE="$tmpdir/absent.env"
    mkdir -p "$PYTHON_LIB_DIR/auto_xdp/admin"
    touch "$PYTHON_LIB_DIR/auto_xdp/__init__.py"
    cat >"$PYTHON_LIB_DIR/auto_xdp/admin/cli.py" <<'EOF_PY'
import argparse


def build_parser():
    parser = argparse.ArgumentParser(prog="python -m auto_xdp.admin.cli")
    parser.add_argument("--config", required=True)
    parser.add_argument("--bpf-pin-dir", default="/sys/fs/bpf/xdp_fw")
    parser.add_argument("--install-dir", default="/usr/local/lib/auto_xdp/current")
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("config")
    return parser
EOF_PY

    output=$(main tui 2>&1)
    status=$?

    [[ $status -ne 0 ]] || {
        printf 'expected stale admin_cli guard to fail\n'
        return 1
    }
    assert_contains "$output" "Installed auto_xdp Python support package is too old for: axdp tui" || return 1
    assert_contains "$output" "sudo axdp check-update --force"
)

test_config_updates_preserve_unrelated_sections() (
    source "$REPO_ROOT/axdp"
    set +e

    local tmpdir
    tmpdir=$(mktemp -d)
    TOML_CONFIG="$tmpdir/config.toml"
    PYTHON_LIB_DIR="$REPO_ROOT"
    require_root() { :; }
    reload_daemon() { :; }

    cat >"$TOML_CONFIG" <<'EOF_CFG'
[firewall]
bogon_filter = false

[trusted_ips]
"203.0.113.1/32" = "office"

[slots]
default_action = "drop"
enabled = ["sctp", { proto = 47, path = "/tmp/gre_handler.o" }]
EOF_CFG

    run_trust add "198.51.100.8/32" office >/dev/null || return 1

    assert_file_contains "$TOML_CONFIG" "[firewall]" || return 1
    assert_file_contains "$TOML_CONFIG" "bogon_filter = false" || return 1
    assert_file_contains "$TOML_CONFIG" "[slots]" || return 1
    assert_file_contains "$TOML_CONFIG" 'default_action = "drop"' || return 1
    assert_file_contains "$TOML_CONFIG" 'enabled = ["sctp", { proto = 47, path = "/tmp/gre_handler.o" }]' || return 1
    assert_file_contains "$TOML_CONFIG" '"198.51.100.8/32" = "office"'
)

_setup_reattach_test_env() {
    local tmpdir="$1"
    BPF_PIN_DIR="$tmpdir/bpf"
    RUN_STATE_DIR="$tmpdir/run"
    XDP_OBJ_PATH="$tmpdir/xdp.o"
    mkdir -p "$BPF_PIN_DIR" "$RUN_STATE_DIR" "$tmpdir/bin"

    # satisfy ensure_xdp_loaded preconditions
    touch "$BPF_PIN_DIR/prog" "$XDP_OBJ_PATH"
    for _m in tcp_whitelist udp_whitelist pkt_counters syn_rate; do
        touch "$BPF_PIN_DIR/$_m"
    done

    # bpftool must exist in PATH for ensure_xdp_loaded to proceed
    printf '#!/bin/sh\nexit 0\n' >"$tmpdir/bin/bpftool"
    chmod +x "$tmpdir/bin/bpftool"
    printf '#!/bin/sh\nexit 0\n' >"$tmpdir/bin/tc"
    chmod +x "$tmpdir/bin/tc"

    PATH="$tmpdir/bin:$BASE_PATH"

    # stubs for functions from auto_xdp_runtime_common.sh (not loaded in tests)
    ensure_bpffs() { return 0; }
    ensure_linux_conntrack() { return 0; }
    load_sock_state_tracker() { return 0; }
    load_syncookie_program() { return 0; }
    load_minecraft_egress() { return 0; }
    xdp_maps_ready() { return 0; }
    load_port_handlers() { return 0; }
    auto_tune_interface_parallelism() { return 0; }
    _TEST_XDP_ATTACHED=""
    _auto_xdp_verify_iface_program() {
        [[ " $_TEST_XDP_ATTACHED " == *" $1 "* ]] && return 0
        ip -d link show dev "$1" 2>/dev/null | grep -Eq 'xdp|xdpgeneric'
    }
    _auto_xdp_attach_candidate() {
        if ip link set dev "$1" xdp pinned "$2" 2>/dev/null; then
            AUTO_XDP_LAST_ATTACH_MODE="native"
            _TEST_XDP_ATTACHED="$_TEST_XDP_ATTACHED $1"
            return 0
        fi
        if ip link set dev "$1" xdpgeneric pinned "$2" 2>/dev/null; then
            AUTO_XDP_LAST_ATTACH_MODE="generic"
            _TEST_XDP_ATTACHED="$_TEST_XDP_ATTACHED $1"
            return 0
        fi
        return 1
    }
    _auto_xdp_record_xdp_state() { return 0; }
}

test_ensure_xdp_reattach_records_generic_mode_on_fallback() (
    source "$REPO_ROOT/runtime/auto_xdp_start.sh"
    set +e

    local tmpdir
    tmpdir=$(mktemp -d)
    _setup_reattach_test_env "$tmpdir"

    # eth0 has no xdp (needs re-attach); native fails, generic succeeds
    # eth1 already has native xdp
    cat >"$tmpdir/bin/ip" <<'EOF_IP'
#!/bin/sh
args="$*"
if echo "$args" | grep -q "show.*eth0\b\|show dev eth0"; then
    printf "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP>\n    link/ether\n"
elif echo "$args" | grep -q "show.*eth1\b\|show dev eth1"; then
    printf "3: eth1: <BROADCAST,MULTICAST,UP,LOWER_UP>\n    link/ether xdp\n"
elif echo "$args" | grep -q "set.*eth0.*xdpgeneric"; then
    exit 0
elif echo "$args" | grep -q "set.*eth0.*xdp "; then
    exit 1
fi
exit 0
EOF_IP
    chmod +x "$tmpdir/bin/ip"

    _IFACES=(eth0 eth1)
    ensure_xdp_loaded || return 1
    assert_eq "$(cat "$RUN_STATE_DIR/xdp_mode")" "generic"
)

test_ensure_xdp_reattach_records_native_mode_when_all_native() (
    source "$REPO_ROOT/runtime/auto_xdp_start.sh"
    set +e

    local tmpdir
    tmpdir=$(mktemp -d)
    _setup_reattach_test_env "$tmpdir"

    # eth0 has no xdp; re-attach succeeds native. eth1 already has native xdp.
    cat >"$tmpdir/bin/ip" <<'EOF_IP'
#!/bin/sh
args="$*"
if echo "$args" | grep -q "show.*eth0\b\|show dev eth0"; then
    printf "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP>\n    link/ether\n"
elif echo "$args" | grep -q "show.*eth1\b\|show dev eth1"; then
    printf "3: eth1: <BROADCAST,MULTICAST,UP,LOWER_UP>\n    link/ether xdp\n"
elif echo "$args" | grep -q "set.*eth0.*xdp "; then
    exit 0
fi
exit 0
EOF_IP
    chmod +x "$tmpdir/bin/ip"

    _IFACES=(eth0 eth1)
    ensure_xdp_loaded || return 1
    assert_eq "$(cat "$RUN_STATE_DIR/xdp_mode")" "native"
)

test_ensure_xdp_reattach_records_generic_when_existing_iface_is_generic() (
    source "$REPO_ROOT/runtime/auto_xdp_start.sh"
    set +e

    local tmpdir
    tmpdir=$(mktemp -d)
    _setup_reattach_test_env "$tmpdir"

    # Both interfaces already have xdp attached; eth1 is generic only
    cat >"$tmpdir/bin/ip" <<'EOF_IP'
#!/bin/sh
args="$*"
if echo "$args" | grep -q "show.*eth1\b\|show dev eth1"; then
    printf "3: eth1: <BROADCAST,MULTICAST,UP,LOWER_UP>\n    link/ether xdpgeneric\n"
else
    printf "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP>\n    link/ether xdp\n"
fi
exit 0
EOF_IP
    chmod +x "$tmpdir/bin/ip"

    _IFACES=(eth0 eth1)
    ensure_xdp_loaded || return 1
    assert_eq "$(cat "$RUN_STATE_DIR/xdp_mode")" "generic"
)

test_ensure_xdp_recovers_stable_generation_when_candidate_resume_fails() (
    source "$REPO_ROOT/runtime/auto_xdp_start.sh"
    set +e

    local tmpdir
    tmpdir=$(mktemp -d)
    _setup_reattach_test_env "$tmpdir"
    mkdir -p "${BPF_PIN_DIR}_next"
    touch "${BPF_PIN_DIR}_next/prog"
    _IFACES=(eth0)

    _auto_xdp_finish_interrupted_reload() {
        printf 'resume\n' >> "$tmpdir/recovery.log"
        return 1
    }
    _auto_xdp_restore_interrupted_reload() {
        printf 'restore\n' >> "$tmpdir/recovery.log"
        rm -rf "${BPF_PIN_DIR}_next"
        return 0
    }
    _auto_xdp_verify_iface_program() { return 0; }

    ensure_xdp_loaded >/dev/null 2>&1 || return 1
    assert_eq "$(cat "$tmpdir/recovery.log")" $'resume\nrestore' || return 1
    [[ ! -e "${BPF_PIN_DIR}_next" ]]
)

test_ensure_xdp_blocks_fallback_when_conntrack_is_unavailable() (
    source "$REPO_ROOT/runtime/auto_xdp_start.sh"
    set +e
    local tmpdir status
    tmpdir=$(mktemp -d)
    _setup_reattach_test_env "$tmpdir"
    ensure_linux_conntrack() { return 1; }
    _auto_xdp_any_target_has_xdp() { return 0; }
    ensure_xdp_loaded >/dev/null 2>&1
    status=$?
    assert_eq "$status" 2
)

test_ensure_xdp_blocks_fallback_when_required_syncookie_is_unavailable() (
    source "$REPO_ROOT/runtime/auto_xdp_start.sh"
    set +e

    local tmpdir status
    tmpdir=$(mktemp -d)
    _setup_reattach_test_env "$tmpdir"
    _IFACES=(eth0)
    _auto_xdp_verify_iface_program() { return 0; }
    ip() { printf '\n'; }
    load_syncookie_program() { return 1; }

    ensure_xdp_loaded >/dev/null 2>&1
    status=$?
    assert_eq "$status" "2"
)

test_select_backend_refuses_nftables_while_xdp_remains_attached() (
    source "$REPO_ROOT/runtime/auto_xdp_start.sh"
    set +e

    local tmpdir
    tmpdir=$(mktemp -d)
    RUN_STATE_DIR="$tmpdir/run"
    mkdir -p "$RUN_STATE_DIR"
    resolve_preferred_backend() { printf 'auto\n'; }
    ensure_xdp_loaded() { return 2; }

    select_backend >/dev/null 2>&1
    local status=$?
    assert_eq "$status" "1" || return 1
    [[ ! -e "$RUN_STATE_DIR/backend" ]]
)

test_cli_help_runs_without_runtime_state() (
    local output
    output=$(bash "$REPO_ROOT/axdp" help)
    assert_contains "$output" "Usage: axdp"
)

test_uninstall_removes_all_auto_xdp_artifacts() (
    source "$REPO_ROOT/axdp"
    set +e

    local tmpdir tc_scenario="${1:-success}" iface direction output status
    tmpdir=$(mktemp -d)
    local ops_log="$tmpdir/ops.log"

    BPF_PIN_DIR="$tmpdir/sys/fs/bpf/xdp_fw"
    INSTALL_ROOT="$tmpdir/usr/local/lib/auto_xdp"
    INSTALL_DIR="$INSTALL_ROOT/current"
    CONFIG_DIR="$tmpdir/etc/auto_xdp"
    CONFIG_FILE="$CONFIG_DIR/auto_xdp.env"
    TOML_CONFIG="$CONFIG_DIR/config.toml"
    RELAY_GROUP="auto-xdp"
    RELAY_GROUP_MARKER="$CONFIG_DIR/.relay-group-created"
    RUN_STATE_DIR="$tmpdir/run/auto_xdp"
    SYNC_SCRIPT="$INSTALL_DIR/xdp_port_sync.py"
    RELAY_SCRIPT="$INSTALL_DIR/pkt_relay.py"
    RUNNER_SCRIPT="$INSTALL_DIR/auto_xdp_start.sh"
    AXDP_CMD="$tmpdir/usr/local/bin/axdp"
    SYSTEMD_UNIT_DIR="$tmpdir/etc/systemd/system"
    SYSTEMD_RUN_DIR="$tmpdir/run/systemd/system"
    OPENRC_INIT_DIR="$tmpdir/etc/init.d"
    OPENRC_RUN_DIR="$tmpdir/run"
    AUTO_XDP_PROC_ROOT="$tmpdir/proc"
    IFACES="eth0 eth1"
    IFACE="eth0"

    mkdir -p \
        "$BPF_PIN_DIR" "${BPF_PIN_DIR}_next" "${BPF_PIN_DIR}_rollback" \
        "$INSTALL_ROOT" "$CONFIG_DIR" "$RUN_STATE_DIR" \
        "$(dirname "$SYNC_SCRIPT")" "$(dirname "$AXDP_CMD")" \
        "$SYSTEMD_UNIT_DIR" "$OPENRC_INIT_DIR"
    touch \
        "$SYNC_SCRIPT" "$RELAY_SCRIPT" "$RUNNER_SCRIPT" "$AXDP_CMD" \
        "$SYSTEMD_UNIT_DIR/xdp-port-sync.service" \
        "$SYSTEMD_UNIT_DIR/auto-xdp-relay.service" \
        "$OPENRC_INIT_DIR/xdp-port-sync" \
        "$OPENRC_INIT_DIR/auto-xdp-relay" \
        "$OPENRC_RUN_DIR/xdp-port-sync.pid" \
        "$OPENRC_RUN_DIR/auto-xdp-relay.pid" \
        "$CONFIG_FILE" "$TOML_CONFIG" "$RELAY_GROUP_MARKER"
    if [[ "$tc_scenario" != absent ]]; then
        for iface in eth0 eth1; do
            for direction in ingress egress; do
                touch "$tmpdir/tc-$iface-$direction"
            done
        done
    fi

    require_root() { return 0; }
    getent() {
        case "$1" in
            group) printf 'auto-xdp:x:991:\n'; return 0 ;;
            passwd) return 1 ;;
        esac
        return 1
    }
    groupdel() { printf 'groupdel %s\n' "$1" >>"$ops_log"; return 0; }
    systemctl() { printf 'systemctl %s\n' "$*" >>"$ops_log"; return 0; }
    rc-service() { printf 'rc-service %s\n' "$*" >>"$ops_log"; return 0; }
    rc-update() { printf 'rc-update %s\n' "$*" >>"$ops_log"; return 0; }
    ip() {
        printf 'ip %s\n' "$*" >>"$ops_log"
        case "$*" in
            "link show dev "*) return 0 ;;
            "-d link show dev "*) printf '2: test: <UP>\n'; return 0 ;;
        esac
        return 0
    }
    command() {
        [[ "$tc_scenario:$*" != "missing_tc:-v tc" ]] || return 1
        builtin command "$@"
    }
    tc() {
        printf 'tc %s\n' "$*" >>"$ops_log"
        if [[ "$1" == -j ]]; then
            [[ "$tc_scenario" != query_failure ]] || return 1
            [[ "$tc_scenario" != invalid_json ]] || { printf 'invalid JSON\n'; return 0; }
            [[ "$*" == "-j filter show dev "* ]] || return 1
            if [[ -e "$tmpdir/tc-$5-$6" ]]; then
                printf '[{"kind":"bpf","options":{"handle":"0x2"}}]\n'
            else
                # Another handle at the same preference belongs to someone else.
                printf '[{"kind":"bpf","options":{"handle":"0x3"}}]\n'
            fi
            return 0
        fi
        [[ "$*" == "filter del dev "* && "${6:-}:${7:-}:${8:-}:${10:-}:${11:-}:${12:-}" \
            == "protocol:all:pref:handle:2:bpf" ]] || return 255
        case "$5:$9" in ingress:49151|egress:49153) ;; *) return 1 ;; esac
        [[ "$tc_scenario" != delete_failure ]] || return 2
        [[ "$tc_scenario" != residual_filter ]] || return 0
        [[ -e "$tmpdir/tc-$4-$5" ]] || return 2
        rm "$tmpdir/tc-$4-$5"
    }
    nft() {
        printf 'nft %s\n' "$*" >>"$ops_log"
        case "$*" in
            "list table "*) return 1 ;;
        esac
        return 0
    }
    python3() {
        if [[ "$*" == '-m auto_xdp.bpf.conntrack --remove' ]]; then
            printf 'conntrack remove\n' >> "$ops_log"
            [[ "$tc_scenario" != conntrack_failure ]]
            return
        fi
        command python3 "$@"
    }

    output=$(run_uninstall 2>&1)
    status=$?
    case "$tc_scenario" in
        delete_failure|query_failure|invalid_json|residual_filter|missing_tc|conntrack_failure)
            assert_eq "$status" 1 "$tc_scenario: $output" || return 1
            [[ -f "$AXDP_CMD" && -d "$INSTALL_ROOT" && -d "$BPF_PIN_DIR" && -d "$CONFIG_DIR" ]] \
                || { printf 'TC failure deleted retry assets\n'; return 1; }
            assert_contains "$output" "Uninstall stopped before deleting runtime files" || return 1
            if [[ "$tc_scenario" != conntrack_failure ]]; then
                ! grep -q 'conntrack remove' "$ops_log" || return 1
            fi
            [[ "$output" != *"completely uninstalled"* ]]
            return ;;
        *) assert_eq "$status" 0 "$output" || return 1 ;;
    esac
    for iface in eth0 eth1; do
        for direction in ingress egress; do
            [[ ! -e "$tmpdir/tc-$iface-$direction" ]] \
                || { printf 'TC filter remains on %s %s\n' "$iface" "$direction"; return 1; }
        done
    done

    local path
    for path in \
        "$BPF_PIN_DIR" "${BPF_PIN_DIR}_next" "${BPF_PIN_DIR}_rollback" \
        "$INSTALL_DIR" "$CONFIG_DIR" "$RUN_STATE_DIR" \
        "$SYNC_SCRIPT" "$RELAY_SCRIPT" "$RUNNER_SCRIPT" "$AXDP_CMD" \
        "$SYSTEMD_UNIT_DIR/xdp-port-sync.service" \
        "$SYSTEMD_UNIT_DIR/auto-xdp-relay.service" \
        "$OPENRC_INIT_DIR/xdp-port-sync" \
        "$OPENRC_INIT_DIR/auto-xdp-relay" \
        "$OPENRC_RUN_DIR/xdp-port-sync.pid" \
        "$OPENRC_RUN_DIR/auto-xdp-relay.pid"; do
        [[ ! -e "$path" ]] || {
            printf 'uninstall left artifact: %s\n' "$path"
            return 1
        }
    done

    assert_file_contains "$ops_log" "ip link set dev eth1 xdpgeneric off" || return 1
    assert_file_contains "$ops_log" "groupdel auto-xdp" || return 1
    assert_file_contains "$ops_log" "conntrack remove" || return 1
    if grep -q "qdisc del" "$ops_log"; then
        printf 'uninstall deleted the shared clsact qdisc\n'
        return 1
    fi
)

test_uninstall_verifies_tc_cleanup_before_removing_files() (
    local scenario
    for scenario in absent delete_failure query_failure invalid_json residual_filter missing_tc conntrack_failure; do
        test_uninstall_removes_all_auto_xdp_artifacts "$scenario" || return 1
    done
)

test_uninstall_systemd_lifecycle() (
    local scenario
    for scenario in success failed_unit missing_unit no_manager query_failure stop_failure \
        disable_failure still_running still_enabled reload_failure reload_retry reset_failure residual_unit; do
        (
            source "$REPO_ROOT/axdp"
            set +e
            local tmpdir unit output status
            tmpdir=$(mktemp -d)
            BPF_PIN_DIR="$tmpdir/bpf/xdp_fw"
            INSTALL_ROOT="$tmpdir/lib/auto_xdp"
            INSTALL_DIR="$INSTALL_ROOT/current"
            CONFIG_DIR="$tmpdir/etc/auto_xdp"
            RUN_STATE_DIR="$tmpdir/run/auto_xdp"
            AXDP_CMD="$tmpdir/bin/axdp"
            SYSTEMD_UNIT_DIR="$tmpdir/systemd/system"
            SYSTEMD_RUN_DIR="$tmpdir/run/systemd/system"
            OPENRC_INIT_DIR="$tmpdir/init.d"
            OPENRC_RUN_DIR="$tmpdir/run"
            AUTO_XDP_PROC_ROOT="$tmpdir/proc"
            RELAY_GROUP_MARKER="$CONFIG_DIR/.relay-group-created"
            mkdir -p "$BPF_PIN_DIR" "$INSTALL_ROOT" "$CONFIG_DIR" "$RUN_STATE_DIR" \
                "${AXDP_CMD%/*}" "$SYSTEMD_UNIT_DIR/multi-user.target.wants"
            [[ "$scenario" == no_manager ]] || mkdir -p "$SYSTEMD_RUN_DIR/multi-user.target.wants"
            touch "$AXDP_CMD"
            for unit in "$SERVICE_NAME.service" "$RELAY_SERVICE_NAME.service"; do
                [[ "$scenario:$unit" == "missing_unit:$RELAY_SERVICE_NAME.service" ]] \
                    || touch "$SYSTEMD_UNIT_DIR/$unit"
                ln -s "../$unit" "$SYSTEMD_UNIT_DIR/multi-user.target.wants/$unit"
                [[ "$scenario" == no_manager ]] || ln -s "$SYSTEMD_UNIT_DIR/$unit" \
                    "$SYSTEMD_RUN_DIR/multi-user.target.wants/$unit"
            done
            require_root() { :; }
            python3() {
                [[ "$*" != '-m auto_xdp.bpf.conntrack --remove' ]] || return 0
                command python3 "$@"
            }
            ip() { return 1; } # No real network interface is touched.
            nft() { return 1; }
            rc-service() { :; }
            rc-update() { :; }
            systemctl() {
                printf '%s\n' "$*" >> "$tmpdir/systemctl.log"
                [[ "$scenario" != no_manager ]] || return 1
                local action="$1" name="${*: -1}" links
                [[ "$name" == *.service ]] || name+=.service
                case "$action" in
                    show)
                        [[ "$scenario" != query_failure ]] || return 1
                        case "$*" in
                            *LoadState*)
                                if [[ -e "$SYSTEMD_UNIT_DIR/$name" || "$scenario" == residual_unit ]] \
                                    || { [[ "$scenario" == reload_retry ]] && [[ ! -e "$tmpdir/removed-reloaded" ]]; }; then
                                    printf 'loaded\n'
                                else
                                    printf 'not-found\n'
                                fi ;;
                            *ActiveState*)
                                if [[ "$scenario" == still_running ]]; then
                                    printf 'active\n'
                                elif [[ "$scenario" == failed_unit || "$scenario" == reset_failure ]] \
                                    && [[ ! -e "$tmpdir/reset-$name" ]]; then
                                    # A deleted failed unit must be reset explicitly.
                                    printf 'failed\n'
                                else
                                    printf 'inactive\n'
                                fi ;;
                            *) return 1 ;;
                        esac ;;
                    disable)
                        [[ "$scenario" != disable_failure ]] || return 1
                        [[ "$scenario:$*" != stop_failure:*--now* ]] || return 1
                        links="$SYSTEMD_UNIT_DIR"
                        [[ "$*" != *--runtime* ]] || links="$SYSTEMD_RUN_DIR"
                        shift
                        for name in "$@"; do
                            [[ "$name" != -* ]] || continue
                            [[ "$name" == *.service ]] || name+=.service
                            [[ -e "$SYSTEMD_UNIT_DIR/$name" ]] || return 1
                            [[ "$scenario" == still_enabled ]] \
                                || rm -f "$links/multi-user.target.wants/$name"
                        done ;;
                    stop) [[ "$scenario" != stop_failure ]] ;;
                    is-enabled)
                        if [[ -e "$SYSTEMD_UNIT_DIR/$name" ]]; then
                            if [[ -L "$SYSTEMD_UNIT_DIR/multi-user.target.wants/$name" ]]; then
                                printf 'enabled\n'; return 0
                            fi
                            if [[ -L "$SYSTEMD_RUN_DIR/multi-user.target.wants/$name" ]]; then
                                printf 'enabled-runtime\n'; return 0
                            fi
                            printf 'disabled\n'; return 1
                        fi
                        printf 'not-found\n'; return 4 ;;
                    daemon-reload)
                        if [[ ! -e "$SYSTEMD_UNIT_DIR/$SERVICE_NAME.service" ]]; then
                            [[ "$scenario" != reload_failure ]] || return 1
                            if [[ "$scenario" == reload_retry && ! -e "$tmpdir/reload-failed-once" ]]; then
                                touch "$tmpdir/reload-failed-once"
                                return 1
                            fi
                            touch "$tmpdir/removed-reloaded"
                        fi ;;
                    reset-failed)
                        [[ "$scenario" != reset_failure ]] || return 1
                        [[ ! -e "$SYSTEMD_UNIT_DIR/$name" ]] || return 1
                        touch "$tmpdir/reset-$name" ;;
                    *) return 1 ;;
                esac
            }
            output=$(run_uninstall eth0 2>&1)
            status=$?
            if [[ "$scenario" == reload_retry ]]; then
                [[ $status -ne 0 && -f "$AXDP_CMD" && -d "$BPF_PIN_DIR" ]] || exit 1
                output=$(run_uninstall eth0 2>&1)
                status=$?
            fi
            case "$scenario" in
                success|failed_unit|missing_unit|no_manager|reload_retry)
                    assert_eq "$status" 0 "$scenario: $output" || exit 1
                    for unit in "$SERVICE_NAME.service" "$RELAY_SERVICE_NAME.service"; do
                        [[ ! -e "$SYSTEMD_UNIT_DIR/$unit" && ! -L "$SYSTEMD_UNIT_DIR/$unit" ]] || exit 1
                        [[ ! -L "$SYSTEMD_UNIT_DIR/multi-user.target.wants/$unit" ]] || exit 1
                        [[ ! -L "$SYSTEMD_RUN_DIR/multi-user.target.wants/$unit" ]] || exit 1
                    done
                    [[ ! -e "$AXDP_CMD" ]] || exit 1
                    if [[ "$scenario" == no_manager ]]; then
                        [[ ! -e "$tmpdir/systemctl.log" ]] || exit 1
                    else
                        assert_file_contains "$tmpdir/systemctl.log" "daemon-reload" || exit 1
                        if [[ "$scenario" == failed_unit ]]; then
                            assert_file_contains "$tmpdir/systemctl.log" "reset-failed $SERVICE_NAME.service" || exit 1
                            assert_file_contains "$tmpdir/systemctl.log" "reset-failed $RELAY_SERVICE_NAME.service" || exit 1
                        fi
                    fi ;;
                *)
                    [[ $status -ne 0 ]] || { printf '%s falsely reported success\n' "$scenario"; exit 1; }
                    [[ -f "$AXDP_CMD" && -d "$INSTALL_ROOT" && -d "$BPF_PIN_DIR" && -d "$CONFIG_DIR" ]] \
                        || { printf '%s deleted retry assets\n' "$scenario"; exit 1; } ;;
            esac
        ) || { printf 'systemd uninstall scenario failed: %s\n' "$scenario"; return 1; }
    done
)

test_uninstall_preserves_used_relay_group() (
    source "$REPO_ROOT/axdp"
    set +e

    local tmpdir groupdel_called=0
    tmpdir=$(mktemp -d)
    CONFIG_DIR="$tmpdir/etc/auto_xdp"
    RELAY_GROUP="auto-xdp"
    RELAY_GROUP_MARKER="$CONFIG_DIR/.relay-group-created"
    mkdir -p "$CONFIG_DIR"
    touch "$RELAY_GROUP_MARKER"

    getent() {
        case "$1" in
            group) printf 'auto-xdp:x:991:operator\n'; return 0 ;;
            passwd) return 1 ;;
        esac
        return 1
    }
    groupdel() { groupdel_called=1; return 0; }

    _remove_owned_relay_group || return 1
    [[ $groupdel_called -eq 0 ]] || return 1
    [[ ! -e "$RELAY_GROUP_MARKER" ]] || return 1
)

test_uninstall_keeps_runtime_when_xdp_detach_fails() (
    source "$REPO_ROOT/axdp"
    set +e

    local tmpdir
    tmpdir=$(mktemp -d)
    BPF_PIN_DIR="$tmpdir/sys/fs/bpf/xdp_fw"
    INSTALL_ROOT="$tmpdir/usr/local/lib/auto_xdp"
    INSTALL_DIR="$INSTALL_ROOT/current"
    AUTO_XDP_PROC_ROOT="$tmpdir/proc"
    SYSTEMD_RUN_DIR="$tmpdir/run/systemd/system"
    IFACES="eth0"
    mkdir -p "$BPF_PIN_DIR" "$INSTALL_DIR"

    require_root() { return 0; }
    systemctl() { return 0; }
    ip() {
        case "$*" in
            "link show dev eth0") return 0 ;;
            "-d link show dev eth0") printf '2: eth0: <UP> prog/xdp id 42\n'; return 0 ;;
        esac
        return 0
    }
    tc() { return 0; }
    nft() { return 1; }

    run_uninstall >/dev/null 2>&1
    local status=$?
    assert_eq "$status" "1" || return 1
    [[ -d "$BPF_PIN_DIR" && -d "$INSTALL_DIR" ]] || {
        printf 'uninstall removed retry assets after detach verification failed\n'
        return 1
    }
)

test_uninstall_stops_only_exact_runtime_process_argv() (
    source "$REPO_ROOT/axdp"
    set +e

    local tmpdir
    tmpdir=$(mktemp -d)
    AUTO_XDP_PROC_ROOT="$tmpdir/proc"
    SYNC_SCRIPT="/usr/local/lib/auto_xdp/current/xdp_port_sync.py"
    mkdir -p "$AUTO_XDP_PROC_ROOT/100" "$AUTO_XDP_PROC_ROOT/101"
    printf 'bash\0-lc\0test /usr/local/lib/auto_xdp/current/xdp_port_sync.py\0' \
        >"$AUTO_XDP_PROC_ROOT/100/cmdline"
    printf 'python3\0/usr/local/lib/auto_xdp/current/xdp_port_sync.py\0--watch\0' \
        >"$AUTO_XDP_PROC_ROOT/101/cmdline"

    local killed="$tmpdir/killed"
    kill() { printf '%s\n' "$1" >>"$killed"; rm -rf "$AUTO_XDP_PROC_ROOT/$1"; }

    _stop_runtime_processes

    assert_eq "$(<"$killed")" "101"
)

test_main_dispatches_uninstall_command() (
    source "$REPO_ROOT/axdp"
    set +e

    load_config() { return 0; }
    run_uninstall() { printf 'uninstall %s\n' "$*"; }

    assert_eq "$(main uninstall eth9)" "uninstall eth9"
)

test_slot_load_sctp_reuses_shared_maps() (
    source "$REPO_ROOT/axdp"
    set +e

    local tmpdir
    tmpdir=$(mktemp -d)
    BPF_PIN_DIR="$tmpdir/bpf"
    INSTALL_DIR="$tmpdir/install"
    HANDLERS_DIR="$tmpdir/etc/handlers"
    TOML_CONFIG="$tmpdir/config.toml"
    PYTHON_LIB_DIR="$REPO_ROOT"
    require_root() { :; }
    mkdir -p "$BPF_PIN_DIR/handlers" "$INSTALL_DIR/handlers" "$HANDLERS_DIR" "$tmpdir/bin"
    touch \
        "$BPF_PIN_DIR/slot_ctx_map" \
        "$BPF_PIN_DIR/sctp_whitelist" \
        "$BPF_PIN_DIR/proto_handlers" \
        "$BPF_PIN_DIR/pkt_counters" \
        "$BPF_PIN_DIR/byte_counters" \
        "$BPF_PIN_DIR/pkt_ringbuf" \
        "$BPF_PIN_DIR/xdp_runtime_cfg" \
        "$INSTALL_DIR/handlers/sctp_handler.o"
    cat >"$TOML_CONFIG" <<'EOF_CFG'
[slots]
enabled = []
EOF_CFG

    cat >"$tmpdir/bin/bpftool" <<EOF_BPFSH
#!/bin/sh
printf '%s\n' "\$*" >> "$tmpdir/bpftool.log"
if [ "\$1 \$2" = "prog load" ]; then
    : > "\$4"
elif [ "\$1 \$2 \$3" = "-j prog show" ]; then
    printf '%s\n' '{"id":132}'
elif [ "\$1 \$2" = "map update" ]; then
    printf '%s\n' 132 > "$tmpdir/active-id"
elif [ "\$1 \$2 \$3" = "-j map lookup" ]; then
    [ -f "$tmpdir/active-id" ] || exit 1
    printf '%s\n' '{"key":[132,0,0,0],"value":[132,0,0,0]}'
fi
exit 0
EOF_BPFSH
    chmod +x "$tmpdir/bin/bpftool"

    PATH="$tmpdir/bin:$BASE_PATH"
    run_slot load sctp >/dev/null || return 1

    assert_file_contains "$tmpdir/bpftool.log" "map name slot_ctx_map pinned $BPF_PIN_DIR/slot_ctx_map" || return 1
    assert_file_contains "$tmpdir/bpftool.log" "map name sctp_whitelist pinned $BPF_PIN_DIR/sctp_whitelist" || return 1
    local map_name
    for map_name in pkt_counters byte_counters pkt_ringbuf xdp_runtime_cfg; do
        assert_file_contains "$tmpdir/bpftool.log" "map name $map_name pinned $BPF_PIN_DIR/$map_name" || return 1
    done
)

test_slot_load_custom_c_compiles_and_persists_object_path() (
    source "$REPO_ROOT/axdp"
    set +e

    local tmpdir
    tmpdir=$(mktemp -d)
    BPF_PIN_DIR="$tmpdir/bpf"
    INSTALL_DIR="$tmpdir/install"
    HANDLERS_DIR="$tmpdir/etc/handlers"
    TOML_CONFIG="$tmpdir/config.toml"
    PYTHON_LIB_DIR="$REPO_ROOT"
    require_root() { :; }
    mkdir -p "$BPF_PIN_DIR/handlers" "$INSTALL_DIR/handlers" "$HANDLERS_DIR" "$tmpdir/bin"
    touch \
        "$BPF_PIN_DIR/slot_ctx_map" \
        "$BPF_PIN_DIR/proto_handlers" \
        "$INSTALL_DIR/handlers/xdp_slot_ctx.h"
    cat >"$TOML_CONFIG" <<'EOF_CFG'
[slots]
enabled = []
EOF_CFG
    cat >"$tmpdir/custom_handler.c" <<'EOF_SRC'
// test source
EOF_SRC

    cat >"$tmpdir/bin/clang" <<EOF_CLANG
#!/bin/sh
out=""
prev=""
for arg in "\$@"; do
  if [ "\$prev" = "-o" ]; then
    out="\$arg"
    break
  fi
  prev="\$arg"
done
printf '%s\n' "\$*" >> "$tmpdir/clang.log"
: > "\$out"
exit 0
EOF_CLANG
    cat >"$tmpdir/bin/bpftool" <<EOF_BPFSH
#!/bin/sh
printf '%s\n' "\$*" >> "$tmpdir/bpftool.log"
if [ "\$1 \$2" = "prog load" ]; then
    : > "\$4"
elif [ "\$1 \$2 \$3" = "-j prog show" ]; then
    printf '%s\n' '{"id":99}'
elif [ "\$1 \$2" = "map update" ]; then
    printf '%s\n' 99 > "$tmpdir/active-id"
elif [ "\$1 \$2 \$3" = "-j map lookup" ]; then
    [ -f "$tmpdir/active-id" ] || exit 1
    printf '%s\n' '{"key":[99,0,0,0],"value":[99,0,0,0]}'
fi
exit 0
EOF_BPFSH
    chmod +x "$tmpdir/bin/clang" "$tmpdir/bin/bpftool"

    PATH="$tmpdir/bin:$BASE_PATH"
    run_slot load 99 "$tmpdir/custom_handler.c" >/dev/null || return 1

    assert_file_contains "$tmpdir/clang.log" "$tmpdir/custom_handler.c" || return 1
    assert_file_contains "$tmpdir/bpftool.log" "$HANDLERS_DIR/custom_99_custom_handler.o" || return 1
    assert_file_contains "$TOML_CONFIG" "[[slots.enabled]]" || return 1
    assert_file_contains "$TOML_CONFIG" 'proto = 99' || return 1
    assert_file_contains "$TOML_CONFIG" 'path = "'"$HANDLERS_DIR"'/custom_99_custom_handler.o"'
)

run_discovered_tests "${BASH_SOURCE[0]}" "axdp"
finish_tests
