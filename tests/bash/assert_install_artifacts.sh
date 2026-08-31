#!/usr/bin/env bash

set -Eeuo pipefail

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]:-}")/../.." && pwd)
# shellcheck source=tests/bash/diagnostics.sh
source "$REPO_ROOT/tests/bash/diagnostics.sh"
enable_test_error_diagnostics

install_log=""
reinstall_log=""
expected_status="fresh"
usage="usage: assert_install_artifacts.sh INSTALL_LOG [--replace] [REINSTALL_LOG]"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --replace)
            expected_status="replace"
            shift
            ;;
        -*)
            printf '[ERROR] installer artifact check: %s\n' "$usage" >&2
            exit 1
            ;;
        *)
            if [[ -z "$install_log" ]]; then
                install_log="$1"
            elif [[ -z "$reinstall_log" ]]; then
                reinstall_log="$1"
            else
                printf '[ERROR] installer artifact check: %s\n' "$usage" >&2
                exit 1
            fi
            shift
            ;;
    esac
done

[[ -n "$install_log" ]] || {
    printf '[ERROR] installer artifact check: %s\n' "$usage" >&2
    exit 1
}

require_record() {
    local log="$1" record="$2"
    grep -qx "$record" "$log" || {
        printf '[ERROR] installer artifact check: missing %s in %s\n' "$record" "$log" >&2
        exit 1
    }
}

[[ -f "$install_log" ]] || {
    printf '[ERROR] installer artifact check: missing log %s\n' "$install_log" >&2
    exit 1
}

require_record "$install_log" "install_status=${expected_status}"
require_record "$install_log" "install_result=complete"

test -x /usr/local/bin/axdp
test -L /usr/local/lib/auto_xdp/current
test -x /usr/local/lib/auto_xdp/current/auto_xdp_start.sh
test -f /usr/local/lib/auto_xdp/current/auto_xdp_bpf_helpers.py
test -f /usr/local/lib/auto_xdp/current/release.json
test -s /usr/local/lib/auto_xdp/current/xdp_firewall.o
test -s /usr/local/lib/auto_xdp/current/tc_flow_track.o
test -s /usr/local/lib/auto_xdp/current/xdp_map_abi.txt
test ! -e /usr/local/bin/auto_xdp_start.sh
test ! -e /usr/local/bin/xdp_port_sync.py
test ! -e /usr/local/bin/pkt_relay.py
test -f /etc/auto_xdp/config.toml
test -d /etc/auto_xdp/handlers
command -v clang >/dev/null
command -v bpftool >/dev/null

if [[ -n "$reinstall_log" ]]; then
    [[ -f "$reinstall_log" ]] || {
        printf '[ERROR] installer artifact check: missing reinstall log %s\n' "$reinstall_log" >&2
        exit 1
    }
    require_record "$reinstall_log" "install_status=replace"
    require_record "$reinstall_log" "install_result=complete"
fi

printf '[INFO] installer artifacts: passed\n'
