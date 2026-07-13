#!/usr/bin/env bash
# Real-environment XDP integration tests: kernel BPF, network namespaces, veth.
# Requires root, clang, bpftool, iproute2 (with netns support), python3.

set -uo pipefail

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]:-}")/../.." && pwd)
# shellcheck source=tests/bash/testlib.sh
source "$REPO_ROOT/tests/bash/testlib.sh"

readonly _NS="axdp_t"
readonly _VETH="axdp_v0"
readonly _VETH_IN="axdp_v1"
readonly _HOST_IP="10.99.0.1"
readonly _NS_IP="10.99.0.2"
readonly _PIN_DIR="/sys/fs/bpf/axdp_integ"
readonly _RUN_DIR="/run/axdp_integ"
readonly _XDP_OBJ="/tmp/axdp_integ_fw.o"

# ---------------------------------------------------------------------------
# Prerequisites
# ---------------------------------------------------------------------------
if [[ $EUID -ne 0 ]]; then
    echo "skip: must run as root"
    exit 0
fi

for _cmd in clang bpftool ip python3; do
    command -v "$_cmd" &>/dev/null || { echo "skip: $_cmd not found"; exit 0; }
done

ip netns add "${_NS}_chk" 2>/dev/null || true
if ! ip netns exec "${_NS}_chk" true 2>/dev/null; then
    ip netns del "${_NS}_chk" 2>/dev/null || true
    echo "skip: network namespaces not supported"
    exit 0
fi
ip netns del "${_NS}_chk" 2>/dev/null || true

# ---------------------------------------------------------------------------
# Compile XDP object once (cached at _XDP_OBJ)
# ---------------------------------------------------------------------------
if [[ ! -f "$_XDP_OBJ" ]]; then
    _src="$REPO_ROOT/bpf/xdp_firewall.c"
    [[ -f "$_src" ]] || { echo "skip: $_src not found"; exit 0; }
    _asm_inc=$(clang -print-file-name=include 2>/dev/null) || {
        echo "skip: clang include path not found"; exit 0
    }
    clang -O2 -g -target bpf \
        -I "$REPO_ROOT/bpf/include" -I "$_asm_inc" \
        -c "$_src" -o "$_XDP_OBJ" 2>/dev/null || {
        echo "skip: XDP compile failed"; exit 0
    }
fi

# ---------------------------------------------------------------------------
# Runtime common (xdp_required_map_names, xdp_maps_ready, etc.)
# ---------------------------------------------------------------------------
BPF_PIN_DIR="$_PIN_DIR"
export BPF_PIN_DIR
# shellcheck source=runtime/auto_xdp_runtime_common.sh
source "$REPO_ROOT/runtime/auto_xdp_runtime_common.sh"

# ---------------------------------------------------------------------------
# Setup / teardown
# ---------------------------------------------------------------------------
_setup() {
    rm -rf "$_PIN_DIR" "$_RUN_DIR"
    mkdir -p "$_PIN_DIR" "$_RUN_DIR"

    ip netns del "$_NS" 2>/dev/null || true
    ip link del "$_VETH" 2>/dev/null || true

    ip netns add "$_NS"
    ip link add "$_VETH" type veth peer name "$_VETH_IN"
    ip link set "$_VETH_IN" netns "$_NS"
    ip addr add "${_HOST_IP}/24" dev "$_VETH"
    ip link set "$_VETH" up
    ip netns exec "$_NS" ip addr add "${_NS_IP}/24" dev "$_VETH_IN"
    ip netns exec "$_NS" ip link set "$_VETH_IN" up
    ip netns exec "$_NS" ip link set lo up

    bpftool prog load "$_XDP_OBJ" "$_PIN_DIR/prog" type xdp \
        pinmaps "$_PIN_DIR" >/dev/null 2>&1
    ip link set dev "$_VETH" xdp generic pinned "$_PIN_DIR/prog"
    echo "generic" > "$_RUN_DIR/xdp_mode"
}

_teardown() {
    ip link set dev "$_VETH" xdp generic off 2>/dev/null || true
    ip netns del "$_NS" 2>/dev/null || true
    ip link del "$_VETH" 2>/dev/null || true
    rm -rf "$_PIN_DIR" "$_RUN_DIR"
}
trap '_teardown' EXIT

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Encode integer as __u32 little-endian hex bytes for bpftool
_u32le() { python3 -c "import struct; print(' '.join(f'{b:02x}' for b in struct.pack('<I', $1)))"; }
# Encode integer as __u64 little-endian hex bytes
_u64le() { python3 -c "import struct; print(' '.join(f'{b:02x}' for b in struct.pack('<Q', $1)))"; }
# Encode dotted-decimal IPv4 as __be32 (network order) hex bytes
_ip4be() { python3 -c "import socket; print(' '.join(f'{b:02x}' for b in socket.inet_aton('$1')))"; }
# Encode port as __be16 (network order) hex bytes
_u16be() { python3 -c "import struct; print(' '.join(f'{b:02x}' for b in struct.pack('>H', $1)))"; }
# Current kernel monotonic time in ns (same epoch as bpf_ktime_get_ns)
_ktime_ns() { python3 -c "import time; print(time.clock_gettime_ns(time.CLOCK_MONOTONIC))"; }

# Send TCP SYN from inside the namespace to _HOST_IP:PORT.
# Returns 0 if XDP passes (kernel sends RST or accepts), 1 if XDP drops (timeout).
_tcp_probe() {
    local port="$1"
    ip netns exec "$_NS" python3 - "$_HOST_IP" "$port" <<'PYEOF' 2>/dev/null
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(0.8)
try:
    s.connect((sys.argv[1], int(sys.argv[2])))
    s.close()
    sys.exit(0)
except ConnectionRefusedError:
    sys.exit(0)   # RST received → XDP passed
except OSError:
    sys.exit(1)   # timeout → XDP dropped
PYEOF
}

# Listen for one UDP datagram on PORT and write it to stdout.
_udp_listen_py() {
    local port="$1"
    python3 - "$port" <<'PYEOF'
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('', int(sys.argv[1])))
s.settimeout(2)
try:
    data, _ = s.recvfrom(1024)
    sys.stdout.buffer.write(data)
    sys.stdout.flush()
except socket.timeout:
    pass
PYEOF
}

# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

test_attach() {
    [[ -f "$_PIN_DIR/prog" ]] || { echo "prog pin missing after load"; return 1; }

    local map_name
    while IFS= read -r map_name; do
        [[ -n "$map_name" ]] || continue
        [[ -e "$_PIN_DIR/$map_name" ]] || {
            echo "missing required map pin: $map_name"
            return 1
        }
    done < <(xdp_required_map_names)

    ip -d link show "$_VETH" | grep -q "xdp" || {
        echo "XDP not shown in ip link output for $_VETH"
        return 1
    }
}

test_reload() {
    xdp_maps_ready || { echo "xdp_maps_ready failed with full map set"; return 1; }

    rm "$_PIN_DIR/tcp_ct4"
    xdp_maps_ready && { echo "xdp_maps_ready should detect missing tcp_ct4"; return 1; }

    # Re-pin by loading into a temporary prog pin, which repins all maps.
    bpftool prog load "$_XDP_OBJ" "$_PIN_DIR/prog2" type xdp \
        pinmaps "$_PIN_DIR" >/dev/null 2>&1 || true
    rm -f "$_PIN_DIR/prog2"

    xdp_maps_ready || { echo "xdp_maps_ready failed after re-pinning"; return 1; }
}

test_fallback() {
    ip -d link show "$_VETH" | grep -q "xdpgeneric" || {
        echo "expected xdpgeneric on veth; only generic mode is supported"
        return 1
    }
    assert_eq "$(cat "$_RUN_DIR/xdp_mode")" "generic" "xdp_mode file"
}

test_port_sync() {
    local port=7701
    local key_hex lookup_val
    key_hex=$(_u32le "$port")

    # Enable port; SYN should pass and receive RST (no listener on host).
    bpftool map update pinned "$_PIN_DIR/tcp_whitelist" \
        key hex $key_hex value hex 01 00 00 00 >/dev/null 2>&1
    lookup_val=$(bpftool -j map lookup pinned "$_PIN_DIR/tcp_whitelist" \
        key hex $key_hex 2>/dev/null \
        | python3 -c "import json,sys; d=json.load(sys.stdin); v=d.get('value',0); print(int(v,16) if isinstance(v,str) else int(v))" 2>/dev/null)
    assert_eq "$lookup_val" "1" "whitelist enabled" || return 1
    _tcp_probe "$port" || { echo "SYN to whitelisted port was dropped"; return 1; }

    # Disable port; SYN should be dropped (timeout).
    bpftool map update pinned "$_PIN_DIR/tcp_whitelist" \
        key hex $key_hex value hex 00 00 00 00 >/dev/null 2>&1
    lookup_val=$(bpftool -j map lookup pinned "$_PIN_DIR/tcp_whitelist" \
        key hex $key_hex 2>/dev/null \
        | python3 -c "import json,sys; d=json.load(sys.stdin); v=d.get('value',0); print(int(v,16) if isinstance(v,str) else int(v))" 2>/dev/null)
    assert_eq "$lookup_val" "0" "whitelist disabled" || return 1
    _tcp_probe "$port" && { echo "SYN to non-whitelisted port was not dropped"; return 1; }

    return 0
}

test_udp_reply() {
    local sport=5100 dport=9901
    local key_hex val_hex

    # ct_key_v4: sport(__be16) + dport(__be16) + saddr(__be32) + daddr(__be32)
    key_hex="$(_u16be "$sport") $(_u16be "$dport") $(_ip4be "$_NS_IP") $(_ip4be "$_HOST_IP")"
    val_hex=$(_u64le "$(_ktime_ns)")

    bpftool map update pinned "$_PIN_DIR/udp_ct4" \
        key hex $key_hex value hex $val_hex >/dev/null 2>&1

    local recv_file
    recv_file=$(mktemp)

    _udp_listen_py "$dport" >"$recv_file" 2>/dev/null &
    local listen_pid=$!
    sleep 0.15

    # Send UDP from inside ns, bound to the exact source port in the CT entry.
    ip netns exec "$_NS" python3 - "$_NS_IP" "$sport" "$_HOST_IP" "$dport" <<'PYEOF' 2>/dev/null
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind((sys.argv[1], int(sys.argv[2])))
s.sendto(b'axdp-test', (sys.argv[3], int(sys.argv[4])))
PYEOF

    sleep 0.4
    kill "$listen_pid" 2>/dev/null || true
    wait "$listen_pid" 2>/dev/null || true

    local got
    got=$(<"$recv_file")
    rm -f "$recv_file"
    [[ "$got" == *"axdp-test"* ]] || {
        echo "UDP reply packet not received (XDP may have dropped it)"
        return 1
    }
}

test_acl() {
    local port=7702

    # trusted_v4_key for LPM trie: prefixlen(__u32 LE) + addr(__be32) = 8 bytes
    local key_hex
    key_hex="$(_u32le 32) $(_ip4be "$_NS_IP")"

    # acl_val: count(__u32 LE) + ports[64](__u16 LE each) = 4 + 128 = 132 bytes
    local port_le zeros val_hex
    port_le=$(python3 -c "import struct; print(' '.join(f'{b:02x}' for b in struct.pack('<H', $port)))")
    zeros=$(python3 -c "print(' '.join(['00']*126))")
    val_hex="01 00 00 00 $port_le $zeros"

    bpftool map update pinned "$_PIN_DIR/tcp_acl_v4" \
        key hex $key_hex value hex $val_hex >/dev/null 2>&1

    # Explicitly clear the whitelist for this port — ACL must grant access on its own.
    bpftool map update pinned "$_PIN_DIR/tcp_whitelist" \
        key hex $(_u32le "$port") value hex 00 00 00 00 >/dev/null 2>&1

    _tcp_probe "$port" || { echo "SYN from ACL-permitted source was dropped"; return 1; }
}

test_rate_limit() {
    local port=7703 rate_max=2

    # Enable port in whitelist so the packet reaches the rate-limit check.
    bpftool map update pinned "$_PIN_DIR/tcp_whitelist" \
        key hex $(_u32le "$port") value hex 01 00 00 00 >/dev/null 2>&1

    # tcp_port_policy_cfg: syn_rate_max + syn_agg_rate_max + conn_limit_max +
    #                      source_prefix_v4 + source_prefix_v6 + _pad (__u32 × 6)
    local policy_hex
    policy_hex=$(python3 -c "
import struct
print(' '.join(f'{b:02x}' for b in struct.pack('<IIIIII', $rate_max, 0, 0, 32, 128, 0)))
")
    bpftool map update pinned "$_PIN_DIR/tcp_port_policies" \
        key hex $(_u32le "$port") value hex $policy_hex >/dev/null 2>&1

    # syn_rate_val: window_start_ns(__u64 LE) + count(__u32 LE) + _pad(__u32)
    local now_ns rate_val_hex
    now_ns=$(_ktime_ns)
    rate_val_hex=$(python3 -c "
import struct
print(' '.join(f'{b:02x}' for b in struct.pack('<QII', $now_ns, $rate_max, 0)))
")
    # Create a per-port inner LRU (BPF_F_INNER_MAP = 0x1000) and install it
    # into the syn4 outer slot for $port, then pre-fill the source's counter
    # with count=rate_max inside the current window so the next SYN overflows.
    local inner_pin="$_PIN_DIR/it_syn4_$port"
    bpftool map create "$inner_pin" type lru_hash key 4 value 16 \
        entries 1024 name "s4_$port" flags 0x1000 >/dev/null 2>&1 || {
        echo "inner map create failed"; return 1; }
    bpftool map update pinned "$_PIN_DIR/syn4" \
        key hex $(_u32le "$port") value pinned "$inner_pin" >/dev/null 2>&1
    bpftool map update pinned "$inner_pin" \
        key hex $(_ip4be "$_NS_IP") value hex $rate_val_hex >/dev/null 2>&1

    local probe_rc=0
    _tcp_probe "$port" && probe_rc=1
    rm -f "$inner_pin"
    [ "$probe_rc" -eq 1 ] && { echo "rate-limited SYN was not dropped"; return 1; }
    return 0
}

test_service_restart() {
    # Seed a conntrack entry before the reload to confirm prog re-pins cleanly.
    local ct_key ct_val
    ct_key="$(_u16be 6100) $(_u16be 7704) $(_ip4be "$_NS_IP") $(_ip4be "$_HOST_IP")"
    ct_val=$(_u64le "$(_ktime_ns)")
    bpftool map update pinned "$_PIN_DIR/tcp_ct4" \
        key hex $ct_key value hex $ct_val >/dev/null 2>&1

    # Simulate service restart: detach, wipe pins, reload, re-attach.
    ip link set dev "$_VETH" xdp generic off 2>/dev/null || true
    rm -rf "$_PIN_DIR"
    mkdir -p "$_PIN_DIR"
    bpftool prog load "$_XDP_OBJ" "$_PIN_DIR/prog" type xdp \
        pinmaps "$_PIN_DIR" >/dev/null 2>&1
    ip link set dev "$_VETH" xdp generic pinned "$_PIN_DIR/prog"

    [[ -f "$_PIN_DIR/prog" ]] || { echo "prog pin missing after reload"; return 1; }
    xdp_maps_ready || { echo "maps not ready after reload"; return 1; }

    # Verify the newly loaded program passes traffic on a whitelisted port.
    bpftool map update pinned "$_PIN_DIR/tcp_whitelist" \
        key hex $(_u32le 7705) value hex 01 00 00 00 >/dev/null 2>&1
    _tcp_probe 7705 || { echo "traffic not passing after service restart"; return 1; }
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
_setup
run_test "attach: XDP loads and pins all required maps" test_attach
_teardown

_setup
run_test "reload: xdp_maps_ready detects missing map pin" test_reload
_teardown

_setup
run_test "fallback: veth attach uses generic XDP mode" test_fallback
_teardown

_setup
run_test "port sync: tcp_whitelist allows and blocks TCP SYN by port" test_port_sync
_teardown

_setup
run_test "UDP reply: udp_ct4 CT entry passes inbound reply packet" test_udp_reply
_teardown

_setup
run_test "ACL: tcp_acl_v4 entry permits SYN without whitelist" test_acl
_teardown

_setup
run_test "rate limit: excess SYNs from same IP are dropped" test_rate_limit
_teardown

_setup
run_test "service restart: XDP re-attaches and accepts traffic after reload" test_service_restart
_teardown

finish_tests
