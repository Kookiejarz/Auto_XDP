#!/usr/bin/env bash
# auto-xdp-test-suite: uninstall

set -Eeuo pipefail

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]:-}")/../.." && pwd)
# shellcheck source=tests/bash/diagnostics.sh
source "$REPO_ROOT/tests/bash/diagnostics.sh"
enable_test_error_diagnostics

CONFIG_FILE="${CONFIG_FILE:-/etc/auto_xdp/auto_xdp.env}"
AXDP_CMD="${AXDP_CMD:-/usr/local/bin/axdp}"
BPF_PIN_DIR="${BPF_PIN_DIR:-/sys/fs/bpf/xdp_fw}"
RUN_STATE_DIR="${RUN_STATE_DIR:-/run/auto_xdp}"

fail() {
    printf '[ERROR] uninstall-e2e: %s\n' "$*" >&2
    exit 1
}

[[ $EUID -eq 0 ]] || fail "must run as root"
[[ -x "$AXDP_CMD" ]] || fail "installed axdp command not found: $AXDP_CMD"
[[ -f "$CONFIG_FILE" ]] || fail "installed environment config not found: $CONFIG_FILE"

# shellcheck disable=SC1090
source "$CONFIG_FILE"
IFS=' ' read -ra interfaces <<< "${IFACES:-}"
[[ ${#interfaces[@]} -gt 0 ]] || fail "no protected interfaces in $CONFIG_FILE"

"$AXDP_CMD" uninstall "${interfaces[@]}"

for iface in "${interfaces[@]}"; do
    if ip -d link show dev "$iface" 2>/dev/null \
            | grep -Eq 'prog/xdp|xdpgeneric|xdpoffload'; then
        fail "XDP is still attached to $iface"
    fi
    if tc filter show dev "$iface" egress pref 49152 handle 1 2>/dev/null | grep -q .; then
        fail "TC egress filter remains on $iface"
    fi
done

if command -v nft >/dev/null 2>&1 \
        && nft list table inet auto_xdp >/dev/null 2>&1; then
    fail "nftables table inet auto_xdp remains"
fi

for path in \
    "$BPF_PIN_DIR" "${BPF_PIN_DIR}_next" "${BPF_PIN_DIR}_rollback" \
    "$RUN_STATE_DIR" /etc/auto_xdp /usr/local/lib/auto_xdp \
    /usr/local/bin/axdp \
    /etc/systemd/system/xdp-port-sync.service \
    /etc/systemd/system/auto-xdp-relay.service \
    /etc/init.d/xdp-port-sync /etc/init.d/auto-xdp-relay \
    /run/xdp-port-sync.pid /run/auto-xdp-relay.pid; do
    [[ ! -e "$path" ]] || fail "artifact remains: $path"
done

printf '[INFO] uninstall: runtime, policy, services, and filesystem residue cleared\n'
