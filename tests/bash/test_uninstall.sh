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
systemd_mode=0
[[ ! -d /run/systemd/system ]] || systemd_mode=1

"$AXDP_CMD" uninstall "${interfaces[@]}"

for iface in "${interfaces[@]}"; do
    if ip -d link show dev "$iface" 2>/dev/null \
            | grep -Eq 'prog/xdp|xdpgeneric|xdpoffload'; then
        fail "XDP is still attached to $iface"
    fi
    ip link show dev "$iface" >/dev/null 2>&1 || continue
    for direction in ingress egress; do
        pref=49151
        [[ "$direction" != egress ]] || pref=49153
        tc_filters=$(tc -j filter show dev "$iface" "$direction" pref "$pref") \
            || fail "cannot inspect TC filters on $iface $direction"
        python3 -c '
import json, sys
assert not any(row.get("kind") == "bpf" and
               str(row.get("options", {}).get("handle", "")) in ("0x2", "2")
               for row in json.load(sys.stdin)), "Auto XDP TC filter remains"
' <<< "$tc_filters" || fail "TC cleanup incomplete on $iface $direction"
    done
done

if command -v nft >/dev/null 2>&1 \
        && nft list table inet auto_xdp >/dev/null 2>&1; then
    fail "nftables table inet auto_xdp remains"
fi
if nft list table inet auto_xdp_conntrack >/dev/null 2>&1; then
    fail "conntrack activation table remains"
fi

for path in \
    "$BPF_PIN_DIR" "${BPF_PIN_DIR}_next" "${BPF_PIN_DIR}_rollback" \
    "$RUN_STATE_DIR" /etc/auto_xdp /usr/local/lib/auto_xdp \
    /usr/local/bin/axdp \
    /etc/systemd/system/xdp-port-sync.service \
    /etc/systemd/system/auto-xdp-relay.service \
    /etc/systemd/system/multi-user.target.wants/xdp-port-sync.service \
    /etc/systemd/system/multi-user.target.wants/auto-xdp-relay.service \
    /run/systemd/system/multi-user.target.wants/xdp-port-sync.service \
    /run/systemd/system/multi-user.target.wants/auto-xdp-relay.service \
    /etc/init.d/xdp-port-sync /etc/init.d/auto-xdp-relay \
    /run/xdp-port-sync.pid /run/auto-xdp-relay.pid; do
    [[ ! -e "$path" && ! -L "$path" ]] || fail "artifact remains: $path"
done

if [[ $systemd_mode -eq 1 ]]; then
    for unit in xdp-port-sync.service auto-xdp-relay.service; do
        load_state=$(systemctl show --property=LoadState --value "$unit") \
            || fail "cannot query $unit load state"
        active_state=$(systemctl show --property=ActiveState --value "$unit") \
            || fail "cannot query $unit active state"
        [[ "$load_state" == not-found && "$active_state" == inactive ]] \
            || fail "$unit remains: $load_state/$active_state"
    done
fi

printf '[INFO] uninstall: runtime, policy, services, and filesystem residue cleared\n'
