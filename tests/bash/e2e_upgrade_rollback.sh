#!/usr/bin/env bash
# Real installed-runtime E2E: in-place upgrade, config retention, rollback.
# This file is intentionally not named test_*.sh: run it explicitly on an
# Ubuntu VM that already has a healthy XDP installation.

set -Eeuo pipefail

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")/../.." && pwd)
INSTALL_ROOT=/usr/local/lib/auto_xdp
CURRENT_LINK=${INSTALL_ROOT}/current
CONFIG_DIR=/etc/auto_xdp
CONFIG_FILE=${CONFIG_DIR}/config.toml
ENV_FILE=${CONFIG_DIR}/auto_xdp.env
TRANSACTION_FILE=${CONFIG_DIR}/install-transaction.json

fail() {
    printf '[ERROR] upgrade-rollback-e2e: %s\n' "$*" >&2
    exit 1
}

require_command() {
    command -v "$1" >/dev/null 2>&1 || fail "missing command: $1"
}

[[ ${EUID:-$(id -u)} -eq 0 ]] || fail 'must run as root'
for command in bash cp date ip python3 sha256sum systemctl; do
    require_command "$command"
done
[[ -L "$CURRENT_LINK" ]] || fail "current release link not found: $CURRENT_LINK"
[[ -f "$CONFIG_FILE" ]] || fail "TOML config not found: $CONFIG_FILE"
[[ -f "$ENV_FILE" ]] || fail "installed environment config not found: $ENV_FILE"

# shellcheck disable=SC1090
source "$ENV_FILE"
IFS=' ' read -ra interfaces <<< "${IFACES:-}"
[[ ${#interfaces[@]} -gt 0 ]] || fail "no protected interfaces in $ENV_FILE"

initial_target=$(readlink "$CURRENT_LINK")
case "$initial_target" in
    releases/*) ;;
    *) fail "current does not point into releases/: $initial_target" ;;
esac
initial_release_dir=${INSTALL_ROOT}/${initial_target}
[[ -d "$initial_release_dir" ]] || fail "current release directory missing: $initial_release_dir"

run_state_dir=${RUN_STATE_DIR:-/run/auto_xdp}
bpf_pin_dir=${BPF_PIN_DIR:-/sys/fs/bpf/xdp_fw}

assert_xdp_runtime() {
    [[ -f "$run_state_dir/backend" ]] || return 1
    [[ "$(<"$run_state_dir/backend")" == xdp ]] || return 1
    [[ -e "$bpf_pin_dir/prog" ]] || return 1
    local iface
    for iface in "${interfaces[@]}"; do
        ip -d link show dev "$iface" 2>/dev/null \
            | grep -Eq '(^|[[:space:]])prog/xdp([[:space:]]|$)|(^|[[:space:]])xdpgeneric([[:space:]]|$)|(^|[[:space:]])xdpoffload([[:space:]]|$)' \
            || return 1
    done
}

assert_services_active() {
    if command -v systemctl >/dev/null 2>&1 \
        && systemctl list-unit-files xdp-port-sync.service >/dev/null 2>&1; then
        systemctl is-active --quiet xdp-port-sync \
            && systemctl is-active --quiet auto-xdp-relay
        return
    fi

    # Ubuntu's VM path is systemd. Keep a useful non-systemd fallback for
    # environments where the installed runtime is launched directly.
    pgrep -af 'auto_xdp_start\.sh' >/dev/null 2>&1 \
        && pgrep -af 'xdp_port_sync\.py' >/dev/null 2>&1
}

wait_for_healthy_runtime() {
    local attempts=0
    while (( attempts < 30 )); do
        if assert_xdp_runtime && assert_services_active; then
            return 0
        fi
        sleep 1
        attempts=$((attempts + 1))
    done
    return 1
}

TMP_ROOT=$(mktemp -d)
original_toml="$TMP_ROOT/config.toml"
cp -p "$CONFIG_FILE" "$original_toml"

cleanup() {
    local status=$?
    if [[ -f "$original_toml" ]]; then
        cp -p "$original_toml" "$CONFIG_FILE" 2>/dev/null || true
    fi
    if [[ -n "${TMP_ROOT:-}" && -d "$TMP_ROOT" ]]; then
        rm -rf "$TMP_ROOT"
    fi
    exit "$status"
}
trap cleanup EXIT

marker="auto-xdp-upgrade-rollback-${BASHPID}-$(date -u +%s)"
printf '\n# temporary E2E marker\n[e2e]\nupgrade_rollback_marker = "%s"\n' "$marker" >> "$CONFIG_FILE"
python3 - "$CONFIG_FILE" "$marker" <<'PY'
import sys
try:
    import tomllib
except ImportError:
    import tomli as tomllib

with open(sys.argv[1], "rb") as handle:
    config = tomllib.load(handle)
assert config["e2e"]["upgrade_rollback_marker"] == sys.argv[2]
PY

upgrade_log="$TMP_ROOT/upgrade.log"
printf '[INFO] running in-place upgrade from %s\n' "$REPO_ROOT"
if ! AUTO_XDP_PRESTAGED_SOURCE_ROOT="$REPO_ROOT" \
    AUTO_XDP_SOURCE_REF=refs/heads/main \
    bash "$REPO_ROOT/setup_xdp.sh" --force "${interfaces[@]}" >"$upgrade_log" 2>&1; then
    tail -n 80 "$upgrade_log" >&2
    fail 'in-place upgrade failed'
fi

new_target=$(readlink "$CURRENT_LINK")
[[ "$new_target" != "$initial_target" ]] \
    || fail "in-place upgrade did not switch current: $new_target"
[[ -d "${INSTALL_ROOT}/${new_target}" ]] \
    || fail "new current release directory missing: $new_target"
python3 - "$CONFIG_FILE" "$marker" <<'PY'
import sys
try:
    import tomllib
except ImportError:
    import tomli as tomllib

with open(sys.argv[1], "rb") as handle:
    config = tomllib.load(handle)
assert config["e2e"]["upgrade_rollback_marker"] == sys.argv[2]
PY
wait_for_healthy_runtime \
    || fail 'runtime is not healthy after in-place upgrade'

# The second installer run sees this successful candidate as PREVIOUS_RELEASE;
# all rollback baselines must therefore be captured after the first upgrade.
baseline_target="$new_target"
baseline_launcher_hash=$(sha256sum "$CURRENT_LINK/auto_xdp_start.sh" | awk '{print $1}')
baseline_env_hash=$(sha256sum "$ENV_FILE" | awk '{print $1}')

printf '[INFO] in-place upgrade active at %s; injecting one failing service restart\n' "$new_target"
# Fail one candidate-only service operation through a temporary PATH wrapper.
# The first relay restart fails after current is switched; subsequent calls
# (including rollback's restart of the old services) pass to real systemctl.
systemctl_real=$(command -v systemctl)
systemctl_wrapper_dir="$TMP_ROOT/systemctl-bin"
systemctl_failure_state="$TMP_ROOT/systemctl-relay-failed"
mkdir -p "$systemctl_wrapper_dir"
cat >"$systemctl_wrapper_dir/systemctl" <<EOF_SYSTEMCTL
#!/bin/sh
if [ "\${1:-}" = restart ] && [ "\${2:-}" = auto-xdp-relay ] && [ ! -e "$systemctl_failure_state" ]; then
    : > "$systemctl_failure_state"
    echo '[e2e] injected one-shot auto-xdp-relay restart failure' >&2
    exit 97
fi
exec "$systemctl_real" "\$@"
EOF_SYSTEMCTL
chmod +x "$systemctl_wrapper_dir/systemctl"

rollback_log="$TMP_ROOT/rollback.log"
rollback_status=0
if PATH="$systemctl_wrapper_dir:$PATH" \
    AUTO_XDP_PRESTAGED_SOURCE_ROOT="$REPO_ROOT" \
    AUTO_XDP_SOURCE_REF=refs/heads/main \
    bash "$REPO_ROOT/setup_xdp.sh" --force "${interfaces[@]}" >"$rollback_log" 2>&1; then
    rollback_status=0
else
    rollback_status=$?
fi
[[ $rollback_status -ne 0 ]] || {
    tail -n 80 "$rollback_log" >&2
    fail 'intentionally failing candidate unexpectedly committed'
}

[[ "$(readlink "$CURRENT_LINK")" == "$baseline_target" ]] \
    || fail "rollback did not restore current: $(readlink "$CURRENT_LINK")"
restored_launcher_hash=$(sha256sum "$CURRENT_LINK/auto_xdp_start.sh" | awk '{print $1}')
[[ "$restored_launcher_hash" == "$baseline_launcher_hash" ]] \
    || fail 'rollback did not restore the old runtime launcher'
python3 - "$CONFIG_FILE" "$marker" <<'PY'
import sys
try:
    import tomllib
except ImportError:
    import tomli as tomllib

with open(sys.argv[1], "rb") as handle:
    config = tomllib.load(handle)
assert config["e2e"]["upgrade_rollback_marker"] == sys.argv[2]
PY
# Contract: rollback must restore generation metadata written during the
# successful upgrade, not the metadata from the first pre-test installation.
[[ "$(sha256sum "$ENV_FILE" | awk '{print $1}')" == "$baseline_env_hash" ]] \
    || fail 'auto_xdp.env was not restored to the successful-upgrade baseline'
wait_for_healthy_runtime \
    || fail 'old service/XDP runtime did not recover after rollback'

python3 - "$TRANSACTION_FILE" "$baseline_target" <<'PY'
import json, sys
with open(sys.argv[1]) as handle:
    transaction = json.load(handle)
assert transaction.get("status") == "rolled_back", transaction
assert transaction.get("phase") == "rolled_back", transaction
assert transaction.get("previous") == sys.argv[2], transaction
PY

printf '[INFO] upgrade: switched release, retained config, and kept XDP healthy\n'
printf '[INFO] rollback: restored current=%s, baseline launcher, config, services, and XDP\n' "$baseline_target"
