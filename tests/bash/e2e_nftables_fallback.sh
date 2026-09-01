#!/usr/bin/env bash
# Real installed nftables fallback E2E.  This is intentionally standalone and
# is not registered in tests/run.sh: the install workflow invokes it after the
# normal XDP install has been removed.

set -Eeuo pipefail

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")/../.." && pwd)

fail() {
    printf '[ERROR] nftables-fallback-e2e: %s\n' "$*" >&2
    exit 1
}

require_command() {
    command -v "$1" >/dev/null 2>&1 || fail "missing command: $1"
}

[[ $EUID -eq 0 ]] || fail "must run as root"
for command_name in ip python3 bash; do
    require_command "$command_name"
done

# Names are overridable for CI, but the script only deletes objects it created.
printf -v suffix '%06d' "$(( ${BASHPID:-$$} % 1000000 ))"
IFACE="${IFACE:-axnft${suffix}}"
PEER_IFACE="${PEER_IFACE:-axnfti${suffix}}"
NETNS="${NETNS:-axdp-nft-${suffix}}"
HOST_IP="${HOST_IP:-198.18.0.1}"
NS_IP="${NS_IP:-198.18.0.2}"
HOST_CIDR="${HOST_IP}/24"
NS_CIDR="${NS_IP}/24"
NFT_FAMILY="${NFT_FAMILY:-inet}"
NFT_TABLE="${NFT_TABLE:-auto_xdp}"
CONFIG_FILE="/etc/auto_xdp/auto_xdp.env"
AXDP_CMD="/usr/local/bin/axdp"
WAIT_SECONDS="${WAIT_SECONDS:-35}"

WORK_DIR=""
SOURCE_ROOT=""
LISTENER_PID=""
LAUNCHER_PID=""
CREATED_NETNS=0
CREATED_IFACE=0
UNINSTALL_ATTEMPTED=0

cleanup() {
    local status=$?
    local cleanup_status=0
    set +e

    if [[ -n "$LISTENER_PID" ]]; then
        kill -TERM "$LISTENER_PID" 2>/dev/null || true
        wait "$LISTENER_PID" 2>/dev/null || true
    fi
    if [[ -n "$LAUNCHER_PID" ]]; then
        kill -TERM "$LAUNCHER_PID" 2>/dev/null || true
        wait "$LAUNCHER_PID" 2>/dev/null || true
    fi

    # Keep the existing residue test as the final product cleanup assertion.
    # It also removes the installed nftables table through axdp uninstall.
    if [[ $UNINSTALL_ATTEMPTED -eq 0 && -x "$AXDP_CMD" && -f "$CONFIG_FILE" ]]; then
        UNINSTALL_ATTEMPTED=1
        if ! bash "$REPO_ROOT/tests/bash/test_uninstall.sh" \
                >"${WORK_DIR:-/tmp}/nftables-fallback-uninstall.log" 2>&1; then
            cat "${WORK_DIR:-/tmp}/nftables-fallback-uninstall.log" >&2
            cleanup_status=1
        fi
    fi

    if [[ $CREATED_NETNS -eq 1 ]]; then
        ip netns del "$NETNS" 2>/dev/null || cleanup_status=1
    fi
    if [[ $CREATED_IFACE -eq 1 ]]; then
        ip link del "$IFACE" 2>/dev/null || cleanup_status=1
    fi
    [[ -z "$WORK_DIR" ]] || rm -rf "$WORK_DIR"

    # Do not hide the original assertion/installer failure behind teardown.
    if [[ $status -eq 0 && $cleanup_status -ne 0 ]]; then
        status=$cleanup_status
    fi
    exit "$status"
}
trap cleanup EXIT

WORK_DIR=$(mktemp -d /tmp/auto-xdp-nft-e2e.XXXXXX)

for existing in "$IFACE" "$PEER_IFACE"; do
    ip link show "$existing" >/dev/null 2>&1 \
        && fail "test interface already exists: $existing"
done
ip netns list | awk '{print $1}' | grep -Fx "$NETNS" >/dev/null 2>&1 \
    && fail "test network namespace already exists: $NETNS"

printf '[INFO] creating veth topology: %s <-> %s (%s)\n' "$IFACE" "$PEER_IFACE" "$NETNS"
ip netns add "$NETNS"
CREATED_NETNS=1
ip link add "$IFACE" type veth peer name "$PEER_IFACE"
CREATED_IFACE=1
ip link set "$PEER_IFACE" netns "$NETNS"
ip addr add "$HOST_CIDR" dev "$IFACE"
ip link set dev "$IFACE" up
ip netns exec "$NETNS" ip addr add "$NS_CIDR" dev "$PEER_IFACE"
ip netns exec "$NETNS" ip link set dev "$PEER_IFACE" up
ip netns exec "$NETNS" ip link set dev lo up

# Stage the same local source tree the installer would consume, changing only
# the supported TOML preference.  This exercises setup_xdp.sh's real install
# and backend path; no nftables rule is created by this test.
SOURCE_ROOT="$WORK_DIR/source"
mkdir -p "$SOURCE_ROOT"
for source_path in \
    setup_xdp.sh axdp config.toml xdp_port_sync.py pkt_relay.py \
    auto_xdp_bpf_helpers.py tc_flow_track.c auto_xdp bpf handlers lib runtime; do
    cp -a "$REPO_ROOT/$source_path" "$SOURCE_ROOT/"
done
sed -i \
    -e 's/^preferred_backend = "[^"]*"/preferred_backend = "nftables"/' \
    -e 's/^bogon_filter = true$/bogon_filter = false/' \
    "$SOURCE_ROOT/config.toml"

printf '[INFO] installing product with daemon.preferred_backend=nftables\n'
if ! AUTO_XDP_PRESTAGED_SOURCE_ROOT="$SOURCE_ROOT" \
        AUTO_XDP_RELEASE_NAME="nftables-fallback-e2e" \
        bash "$SOURCE_ROOT/setup_xdp.sh" --force \
        --allow-container-interfaces "$IFACE" \
        >"$WORK_DIR/install.log" 2>&1; then
    cat "$WORK_DIR/install.log" >&2
    fail "installer failed"
fi

[[ -f "$CONFIG_FILE" ]] || fail "installer did not write $CONFIG_FILE"
[[ -x "$AXDP_CMD" ]] || fail "installer did not write $AXDP_CMD"
require_command nft
# shellcheck disable=SC1090
source "$CONFIG_FILE"
grep -q '^PREFERRED_BACKEND="nftables"$' "$CONFIG_FILE" \
    || fail "installed environment did not select nftables"

if [[ -d /run/systemd/system ]] && command -v systemctl >/dev/null 2>&1; then
    systemctl is-active --quiet xdp-port-sync \
        || fail "xdp-port-sync service is not active"
    printf '[INFO] xdp-port-sync service is active\n'
else
    # Ubuntu's VM job normally uses systemd.  This fallback keeps the script
    # useful in a minimal Ubuntu root environment while still running the
    # installed launcher and daemon, not a test double.
    launcher="${SYNC_SCRIPT%/*}/auto_xdp_start.sh"
    [[ -x "$launcher" ]] || fail "installed launcher not found: $launcher"
    "$launcher" >"$WORK_DIR/launcher.log" 2>&1 &
    LAUNCHER_PID=$!
    printf '[INFO] no systemd PID 1; running installed launcher directly\n'
fi

nft_policy_schema_present() {
    local table_dump
    table_dump=$(nft list table "$NFT_FAMILY" "$NFT_TABLE" 2>/dev/null) || return 1
    [[ "$table_dump" == *"set tcp_ports"* && "$table_dump" == *"chain input"* ]]
}

deadline=$((SECONDS + WAIT_SECONDS))
while [[ ! -f /run/auto_xdp/backend ]] && (( SECONDS < deadline )); do sleep 0.2; done
[[ -f /run/auto_xdp/backend ]] || fail "backend state file missing"
grep -qx nftables /run/auto_xdp/backend \
    || fail "installed backend is not nftables"
deadline=$((SECONDS + WAIT_SECONDS))
while (( SECONDS < deadline )); do
    if nft_policy_schema_present; then
        break
    fi
    sleep 0.2
done
if ! nft_policy_schema_present; then
    nft list ruleset >&2 || true
    [[ -z "$LAUNCHER_PID" ]] || cat "$WORK_DIR/launcher.log" >&2
    fail "installed nftables policy schema is missing"
fi

set_contains_port() {
    local port="$1"
    nft list set "$NFT_FAMILY" "$NFT_TABLE" tcp_ports 2>/dev/null \
        | grep -E "(^|[{},[:space:]])${port}([},[:space:]]|$)" >/dev/null
}

wait_for_port_state() {
    local port="$1" expected="$2" deadline=$((SECONDS + WAIT_SECONDS))
    while (( SECONDS < deadline )); do
        if set_contains_port "$port"; then
            [[ "$expected" == present ]] && return 0
        elif [[ "$expected" == absent ]]; then
            return 0
        fi
        sleep 0.2
    done
    fail "timed out waiting for tcp_ports port $port to become $expected"
}

tcp_probe() {
    local port="$1" expected="$2"
    ip netns exec "$NETNS" python3 - "$HOST_IP" "$port" "$expected" <<'PY'
import socket
import sys

host, port, expected = sys.argv[1], int(sys.argv[2]), sys.argv[3]
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.settimeout(1.2)
try:
    sock.connect((host, port))
    if expected != "allowed":
        raise SystemExit("blocked probe unexpectedly connected")
    if sock.recv(2) != b"ok":
        raise SystemExit("allowed probe did not receive listener response")
except socket.timeout:
    if expected == "allowed":
        raise SystemExit("allowed probe timed out")
except ConnectionRefusedError:
    raise SystemExit("probe received RST; nftables did not drop closed-port traffic")
except OSError as exc:
    if expected == "allowed":
        raise SystemExit(f"allowed probe failed: {exc}")
else:
    if expected != "allowed":
        raise SystemExit("blocked probe unexpectedly succeeded")
finally:
    sock.close()
PY
}

LISTENER_READY="$WORK_DIR/listener.port"
python3 - "$HOST_IP" "$LISTENER_READY" <<'PY' &
import pathlib
import socket
import sys

host, ready_path = sys.argv[1], pathlib.Path(sys.argv[2])
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind((host, 0))
server.listen(8)
ready_path.write_text(str(server.getsockname()[1]), encoding="ascii")
while True:
    client, _ = server.accept()
    try:
        client.sendall(b"ok")
    finally:
        client.close()
PY
LISTENER_PID=$!

deadline=$((SECONDS + 5))
while [[ ! -s "$LISTENER_READY" ]] && (( SECONDS < deadline )); do sleep 0.1; done
[[ -s "$LISTENER_READY" ]] || fail "listener failed to start"
LISTENER_PORT=$(<"$LISTENER_READY")
[[ "$LISTENER_PORT" =~ ^[0-9]+$ ]] || fail "listener returned an invalid port"

printf '[INFO] listener port %s opened; waiting for daemon discovery\n' "$LISTENER_PORT"
wait_for_port_state "$LISTENER_PORT" present
tcp_probe "$LISTENER_PORT" allowed
printf '[INFO] veth/netns TCP traffic allowed for discovered listener\n'

kill -TERM "$LISTENER_PID" 2>/dev/null || true
wait "$LISTENER_PID" 2>/dev/null || true
LISTENER_PID=""
printf '[INFO] listener closed; waiting for daemon policy removal\n'
wait_for_port_state "$LISTENER_PORT" absent
tcp_probe "$LISTENER_PORT" blocked
printf '[INFO] nftables policy removed listener port and blocked new traffic\n'

printf '[INFO] nftables fallback E2E passed; teardown will run test_uninstall.sh\n'
