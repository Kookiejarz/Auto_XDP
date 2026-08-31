#!/usr/bin/env bash
# auto-xdp-test-suite: installed

set -Eeuo pipefail

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]:-}")/../.." && pwd)
# shellcheck source=tests/bash/diagnostics.sh
source "$REPO_ROOT/tests/bash/diagnostics.sh"
enable_test_error_diagnostics

CONFIG_FILE="${CONFIG_FILE:-/etc/auto_xdp/auto_xdp.env}"
AXDP_CMD="${AXDP_CMD:-/usr/local/bin/axdp}"
RUN_STATE_DIR="${RUN_STATE_DIR:-/run/auto_xdp}"
BPF_PIN_DIR="${BPF_PIN_DIR:-/sys/fs/bpf/xdp_fw}"
TOML_CONFIG="${TOML_CONFIG:-/etc/auto_xdp/config.toml}"
RUNTIME_E2E_WAIT_SECONDS="${RUNTIME_E2E_WAIT_SECONDS:-40}"

fail() {
    printf '[ERROR] runtime-e2e: %s\n' "$*" >&2
    exit 1
}

require_command() {
    command -v "$1" >/dev/null 2>&1 || fail "missing command: $1"
}

wait_for_path() {
    local path="$1"
    local attempts=0
    while [[ ! -e "$path" && $attempts -lt 50 ]]; do
        sleep 0.2
        attempts=$((attempts + 1))
    done
    [[ -e "$path" ]] || fail "timed out waiting for $path"
}

wait_for_socket() {
    local path="$1"
    local attempts=0
    while [[ ! -S "$path" && $attempts -lt 50 ]]; do
        sleep 0.2
        attempts=$((attempts + 1))
    done
    [[ -S "$path" ]] || fail "timed out waiting for Unix socket $path"
}

[[ $EUID -eq 0 ]] || fail "must run as root"
require_command ip
require_command tc
require_command python3
require_command bpftool
[[ -x "$AXDP_CMD" ]] || fail "installed axdp command not found: $AXDP_CMD"
[[ -f "$CONFIG_FILE" ]] || fail "installed environment config not found: $CONFIG_FILE"

# shellcheck disable=SC1090
source "$CONFIG_FILE"
IFS=' ' read -ra interfaces <<< "${IFACES:-}"
[[ ${#interfaces[@]} -gt 0 ]] || fail "no protected interface in $CONFIG_FILE"
iface="${interfaces[0]}"
[[ -n "$TOML_CONFIG" && -f "$TOML_CONFIG" ]] || fail "TOML config not found: $TOML_CONFIG"

socket_path=$(python3 - "$TOML_CONFIG" <<'PY'
import sys
try:
    import tomllib
except ImportError:
    import tomli as tomllib

with open(sys.argv[1], "rb") as handle:
    value = tomllib.load(handle)
print(value.get("ringbuf", {}).get("socket_path", "/var/run/auto_xdp/pkt_events.sock"))
PY
)

launcher="${SYNC_SCRIPT%/*}/auto_xdp_start.sh"
relay="${SYNC_SCRIPT%/*}/pkt_relay.py"
[[ -x "$launcher" ]] || fail "installed launcher not found: $launcher"
[[ -f "$relay" ]] || fail "installed relay not found: $relay"

loader_pid=""
relay_pid=""
listener_pid=""
event_monitor_pid=""
e2e_ns="auto-xdp-runtime-e2e-$$"
e2e_peer=""
e2e_peer_moved=0
e2e_host_addr_added=0
e2e_host_ip="192.0.2.1"
e2e_peer_ip="192.0.2.2"
e2e_listener_info=""
cleanup() {
    if [[ -n "$event_monitor_pid" ]]; then
        kill -TERM "$event_monitor_pid" 2>/dev/null || true
        wait "$event_monitor_pid" 2>/dev/null || true
    fi
    if [[ -n "$listener_pid" ]]; then
        kill -TERM "$listener_pid" 2>/dev/null || true
        wait "$listener_pid" 2>/dev/null || true
    fi
    if [[ $e2e_peer_moved -eq 1 ]]; then
        ip netns exec "$e2e_ns" ip link set "$e2e_peer" netns 1 2>/dev/null || true
        e2e_peer_moved=0
    fi
    ip netns del "$e2e_ns" 2>/dev/null || true
    if [[ $e2e_host_addr_added -eq 1 ]]; then
        ip addr del "$e2e_host_ip/24" dev "$iface" 2>/dev/null || true
        e2e_host_addr_added=0
    fi
    rm -f "$e2e_listener_info"
    if [[ -n "$relay_pid" ]]; then
        kill -TERM "$relay_pid" 2>/dev/null || true
        wait "$relay_pid" 2>/dev/null || true
    fi
    if [[ -n "$loader_pid" ]]; then
        kill -TERM "$loader_pid" 2>/dev/null || true
        wait "$loader_pid" 2>/dev/null || true
    fi
}
trap cleanup EXIT

_tcp_policy_value() {
    local key_hex="$1" raw value
    # shellcheck disable=SC2086 # bpftool expects one argument per hex byte.
    raw=$(bpftool -j map lookup pinned "$BPF_PIN_DIR/tcp_whitelist" \
        key hex $key_hex 2>/dev/null || true)
    [[ -n "$raw" ]] || { printf '0\n'; return 0; }
    value=$(python3 -c '
import json, sys
try:
    value = json.load(sys.stdin).get("value", 0)
    if isinstance(value, list):
        value = int.from_bytes(bytes(int(v, 0) if isinstance(v, str) else v for v in value), "little")
    elif isinstance(value, str):
        value = int(value, 0)
    print(int(value))
except (ValueError, TypeError, json.JSONDecodeError):
    print(0)
' <<<"$raw" 2>/dev/null || printf '0\n')
    printf '%s\n' "$value"
}

wait_for_tcp_policy() {
    local port="$1" expected="$2" key_hex value
    local deadline=$((SECONDS + RUNTIME_E2E_WAIT_SECONDS))
    key_hex=$(python3 - "$port" <<'PY'
import struct, sys
print(" ".join(f"{byte:02x}" for byte in struct.pack("<I", int(sys.argv[1]))))
PY
)
    while (( SECONDS < deadline )); do
        value=$(_tcp_policy_value "$key_hex")
        [[ "$value" == "$expected" ]] && return 0
        sleep 0.2
    done
    fail "timed out waiting for tcp_whitelist[$port] = $expected (last value: $value)"
}

_tcp_probe_from_netns() {
    local ns="$1" dest="$2" port="$3"
    ip netns exec "$ns" python3 - "$dest" "$port" <<'PY'
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(1.0)
try:
    s.connect((sys.argv[1], int(sys.argv[2])))
except ConnectionRefusedError:
    raise SystemExit(0)  # A real RST proves XDP passed the SYN.
except OSError:
    raise SystemExit(1)  # Timeout/unreachable means XDP dropped the SYN.
else:
    s.close()
    raise SystemExit(0)
PY
}

_find_veth_peer() {
    local peer_index
    peer_index=$(ip -o link show dev "$iface" 2>/dev/null \
        | sed -n 's/.*@if\([0-9][0-9]*\):.*/\1/p')
    [[ -n "$peer_index" ]] || return 1
    ip -o link show 2>/dev/null \
        | awk -v index="$peer_index:" '$1 == index { sub(/@.*/, "", $2); print $2; exit }'
}

test_auto_port_sync_closed_loop() {
    local port key_hex event_log
    local peer_override="${RUNTIME_E2E_PEER_IFACE:-}"
    e2e_peer="$peer_override"
    [[ -n "$e2e_peer" ]] || e2e_peer=$(_find_veth_peer || true)
    if [[ -z "$e2e_peer" ]] || ! ip link show dev "$e2e_peer" >/dev/null 2>&1; then
        printf '[WARNING] runtime-e2e: SKIP automatic port-sync packet loop (protected interface is not a veth; set RUNTIME_E2E_PEER_IFACE to override)\n'
        return 0
    fi
    if ! ip netns add "$e2e_ns" 2>/dev/null; then
        printf '[WARNING] runtime-e2e: SKIP automatic port-sync packet loop (network namespaces unavailable)\n'
        return 0
    fi

    ip addr show dev "$iface" | grep -Eq "[[:space:]]${e2e_host_ip}/24[[:space:]]" \
        || { ip addr add "$e2e_host_ip/24" dev "$iface" || fail "could not add E2E address to $iface"; e2e_host_addr_added=1; }
    ip link set "$e2e_peer" netns "$e2e_ns" \
        || fail "could not move veth peer $e2e_peer into $e2e_ns"
    e2e_peer_moved=1
    ip netns exec "$e2e_ns" ip addr add "$e2e_peer_ip/24" dev "$e2e_peer"
    ip netns exec "$e2e_ns" ip link set "$e2e_peer" up
    ip netns exec "$e2e_ns" ip link set lo up

    e2e_listener_info=$(mktemp)
    python3 - "$e2e_host_ip" <<'PY' >"$e2e_listener_info" 2>/tmp/auto-xdp-runtime-e2e-listener.log &
import socket, sys, time
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind((sys.argv[1], 0))
s.listen(8)
print(s.getsockname()[1], flush=True)
try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    pass
finally:
    s.close()
PY
    listener_pid=$!
    local attempts=0
    while [[ ! -s "$e2e_listener_info" && $attempts -lt 50 ]]; do
        kill -0 "$listener_pid" 2>/dev/null || fail "E2E TCP listener exited before binding"
        sleep 0.2
        attempts=$((attempts + 1))
    done
    [[ -s "$e2e_listener_info" ]] || fail "timed out waiting for E2E TCP listener"
    port=$(<"$e2e_listener_info")
    [[ "$port" =~ ^[0-9]+$ ]] || fail "invalid E2E listener port: $port"
    key_hex=$(python3 - "$port" <<'PY'
import struct, sys
print(" ".join(f"{byte:02x}" for byte in struct.pack("<I", int(sys.argv[1]))))
PY
)

    if [[ "${REQUIRE_SOCK_STATE_EVENT:-0}" == "1" ]]; then
        event_log=$(mktemp)
        python3 - "$socket_path" "$port" "$event_log" <<'PY' &
import json, socket, sys, time
path, wanted, log_path = sys.argv[1], int(sys.argv[2]), sys.argv[3]
deadline = time.monotonic() + 20
seen = set()
client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
client.settimeout(0.5)
try:
    client.connect(path)
    pending = b""
    while time.monotonic() < deadline and "close" not in seen:
        try:
            chunk = client.recv(65536)
        except socket.timeout:
            continue
        if not chunk:
            break
        pending += chunk
        while b"\n" in pending:
            raw, pending = pending.split(b"\n", 1)
            if not raw:
                continue
            try:
                message = json.loads(raw)
            except json.JSONDecodeError:
                continue
            events = message.get("events", []) if message.get("type") == "history" else [message]
            for event in events:
                if (event.get("type") == "port_change"
                        and event.get("proto") == "tcp"
                        and event.get("port") == wanted):
                    seen.add(event.get("action"))
                    with open(log_path, "w", encoding="ascii") as out:
                        out.write(" ".join(sorted(seen)))
finally:
    client.close()
raise SystemExit(0 if {"open", "close"} <= seen else 1)
PY
        event_monitor_pid=$!
    fi

    wait_for_tcp_policy "$port" 1
    _tcp_probe_from_netns "$e2e_ns" "$e2e_host_ip" "$port" \
        || fail "SYN to automatically opened TCP listener was dropped"
    if [[ "${REQUIRE_SOCK_STATE_EVENT:-0}" == "1" ]]; then
        local event_attempts=0
        while [[ ! -f "$event_log" || "$(<"$event_log")" != *open* ]]; do
            (( event_attempts < 50 )) || fail "sock_state open event was not relayed for port $port"
            sleep 0.2
            event_attempts=$((event_attempts + 1))
        done
    fi

    kill -TERM "$listener_pid" 2>/dev/null || true
    wait "$listener_pid" 2>/dev/null || true
    listener_pid=""
    wait_for_tcp_policy "$port" 0
    _tcp_probe_from_netns "$e2e_ns" "$e2e_host_ip" "$port" \
        && fail "SYN to automatically closed TCP listener was not dropped"
    if [[ "${REQUIRE_SOCK_STATE_EVENT:-0}" == "1" ]]; then
        local close_attempts=0
        while [[ ! -f "$event_log" || "$(<"$event_log")" != *close* ]]; do
            (( close_attempts < 50 )) || fail "sock_state close event was not relayed for port $port"
            sleep 0.2
            close_attempts=$((close_attempts + 1))
        done
        wait "$event_monitor_pid" 2>/dev/null || fail "sock_state event monitor did not observe open and close"
        event_monitor_pid=""
        rm -f "$event_log"
    fi
    printf '[INFO] runtime-e2e: automatic TCP port sync opened and closed port %s\n' "$port"
}

systemd_mode=0
if command -v systemctl >/dev/null 2>&1 \
    && systemctl is-active --quiet xdp-port-sync; then
    systemctl is-enabled --quiet xdp-port-sync \
        || fail "xdp-port-sync is active but not enabled"
    systemctl is-enabled --quiet auto-xdp-relay \
        || fail "auto-xdp-relay is active but not enabled"
    systemctl is-active --quiet auto-xdp-relay \
        || fail "xdp-port-sync is active but auto-xdp-relay is not active"
    "$AXDP_CMD" status >/tmp/auto-xdp-runtime-e2e-status.log 2>&1 \
        || fail "axdp status failed"
    systemd_mode=1
else
    # Containers without an init system still exercise the exact installed
    # launcher and relay processes instead of replacing them with mocks.
    "$launcher" >"/tmp/auto-xdp-runtime-e2e-loader.log" 2>&1 &
    loader_pid=$!
    wait_for_path "$RUN_STATE_DIR/backend"
    grep -qx xdp "$RUN_STATE_DIR/backend" \
        || fail "installed launcher did not select the XDP backend"

    PYTHONPATH="${PYTHON_LIB_DIR:-}" "$relay" \
        --config "$TOML_CONFIG" \
        --pin-path "$BPF_PIN_DIR/pkt_ringbuf" \
        --sock-state-rb "$BPF_PIN_DIR/sock_state_rb" \
        --socket "$socket_path" \
        --pid-file "$RUN_STATE_DIR/runtime-e2e-relay.pid" \
        --wait-for-ringbuf \
        >"/tmp/auto-xdp-runtime-e2e-relay.log" 2>&1 &
    relay_pid=$!
fi

wait_for_path "$BPF_PIN_DIR/prog"
wait_for_path "$BPF_PIN_DIR/sock_state_prog"
wait_for_path "$BPF_PIN_DIR/sock_state_rb"
wait_for_socket "$socket_path"

tc filter show dev "$iface" egress 2>/dev/null \
    | grep -q 'pref 49152' \
    || fail "installed TC egress filter is not active on $iface"

test_auto_port_sync_closed_loop

if [[ $systemd_mode -eq 1 ]]; then
    systemctl is-active --quiet xdp-port-sync
    systemctl is-active --quiet auto-xdp-relay
fi

printf '[INFO] installed runtime: XDP + TC + sock_state + relay passed\n'
