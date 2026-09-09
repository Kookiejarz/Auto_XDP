#!/usr/bin/env bash
# auto-xdp-test-suite: kernel
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
readonly _HOST_IP6="2001:db8:99::1"
readonly _NS_IP6="2001:db8:99::2"
readonly _PIN_DIR="/sys/fs/bpf/axdp_integ"
readonly _DEBUG_PIN_DIR="/sys/fs/bpf/axdp_integ_debug"
readonly _RUN_DIR="/run/axdp_integ"
readonly _XDP_OBJ="/tmp/axdp_integ_fw.o"
readonly _TC_OBJ="/tmp/axdp_integ_tc.o"

# ---------------------------------------------------------------------------
# Prerequisites
# ---------------------------------------------------------------------------
_kernel_unavailable() {
    if [[ "${REQUIRE_KERNEL_TESTS:-0}" == 1 ]]; then
        test_log_error "kernel tests required: $*"
        exit 1
    fi
    test_log_warning "SKIP $*"
    exit 0
}

if [[ $EUID -ne 0 ]]; then
    _kernel_unavailable "must run as root"
fi

for _cmd in clang bpftool ip python3; do
    command -v "$_cmd" &>/dev/null || _kernel_unavailable "$_cmd not found"
done

ip netns add "${_NS}_chk" 2>/dev/null || true
if ! ip netns exec "${_NS}_chk" true 2>/dev/null; then
    ip netns del "${_NS}_chk" 2>/dev/null || true
    _kernel_unavailable "network namespaces not supported"
fi
ip netns del "${_NS}_chk" 2>/dev/null || true

# ---------------------------------------------------------------------------
# Compile XDP object from current sources. Never reuse a leftover /tmp object
# after the repository has changed.
# ---------------------------------------------------------------------------
_src="$REPO_ROOT/bpf/xdp_firewall.c"
[[ -f "$_src" ]] || _kernel_unavailable "$_src not found"
_asm_inc=$(clang -print-file-name=include 2>/dev/null) || {
    _kernel_unavailable "clang include path not found"
}
_include_args=(-I "$REPO_ROOT/bpf/include" -I "$_asm_inc")
_multiarch_inc="/usr/include/$(uname -m)-linux-gnu"
[[ ! -d "$_multiarch_inc" ]] || _include_args+=(-I "$_multiarch_inc")
rm -f "$_XDP_OBJ"
if ! clang -O3 -g -target bpf -mcpu=v3 -fno-stack-protector \
    "${_include_args[@]}" \
    -c "$_src" -o "$_XDP_OBJ"; then
    test_log_error "XDP compile failed"
    exit 1
fi
_tc_src="$REPO_ROOT/tc_flow_track.c"
[[ -f "$_tc_src" ]] || _kernel_unavailable "$_tc_src not found"
rm -f "$_TC_OBJ"
if ! clang -O3 -g -target bpf -mcpu=v3 -fno-stack-protector \
    "${_include_args[@]}" \
    -c "$_tc_src" -o "$_TC_OBJ"; then
    test_log_error "tc egress compile failed"
    exit 1
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
_load_xdp_program() {
    local phase="${1:-load}"
    local load_log status debug_status metrics_tmp metrics_status
    local -a pipe_status
    load_log=$(mktemp)

    if [[ -n "${VERIFIER_METRICS_FILE:-}" && ! -s "$VERIFIER_METRICS_FILE" ]]; then
        metrics_tmp=$(mktemp)
        bpftool -d prog load "$_XDP_OBJ" "$_PIN_DIR/prog" type xdp \
            pinmaps "$_PIN_DIR" 2>&1 \
            | bash "$REPO_ROOT/tests/bash/extract_verifier_metrics.sh" "$phase" \
                >"$metrics_tmp"
        pipe_status=("${PIPESTATUS[@]}")
        status=${pipe_status[0]}
        metrics_status=${pipe_status[1]}
        if [[ $status -eq 0 && $metrics_status -eq 0 ]]; then
            {
                printf '# kernel\t%s\n' "$(uname -r)"
                printf '# clang\t%s\n' "$(clang --version | head -n 1)"
                printf '# bpftool\t%s\n' "$(bpftool version | head -n 1)"
                printf 'phase\tstatic_insns\tprocessed_insns\tmax_states_per_insn\ttotal_states\tpeak_states\tverification_time_usec\tstack_depth\n'
                cat "$metrics_tmp"
            } >"$VERIFIER_METRICS_FILE"
        fi
        rm -f "$metrics_tmp"
        if [[ $status -eq 0 && $metrics_status -ne 0 ]]; then
            printf 'error: unable to parse bpftool verifier metrics during %s\n' "$phase" >&2
            rm -f "$load_log"
            return 1
        fi
    else
        bpftool prog load "$_XDP_OBJ" "$_PIN_DIR/prog" type xdp \
            pinmaps "$_PIN_DIR" >"$load_log" 2>&1
        status=$?
    fi
    if [[ $status -eq 0 ]]; then
        rm -f "$load_log"
        return 0
    fi

    printf 'error: XDP program load failed during %s (exit %d)\n' "$phase" "$status" >&2
    printf '%s\n' '--- bpftool load output ---' >&2
    cat "$load_log" >&2
    rm -f "$load_log"

    # Preserve full libbpf map-creation and verifier context in CI. A separate
    # pin directory avoids collisions with anything left by the first load.
    rm -rf "$_DEBUG_PIN_DIR"
    mkdir -p "$_DEBUG_PIN_DIR"
    printf '%s\n' '--- bpftool -d verifier output ---' >&2
    bpftool -d prog load "$_XDP_OBJ" "$_DEBUG_PIN_DIR/prog" type xdp \
        pinmaps "$_DEBUG_PIN_DIR" >&2
    debug_status=$?
    printf '%s\n' "--- bpftool -d exited $debug_status ---" >&2
    rm -rf "$_DEBUG_PIN_DIR"
    return "$status"
}

_setup() {
    rm -rf "$_PIN_DIR" "${_PIN_DIR}_next" "${_PIN_DIR}_rollback" \
        "$_DEBUG_PIN_DIR" "$_RUN_DIR"
    mkdir -p "$_PIN_DIR" "$_RUN_DIR"

    ip netns del "$_NS" 2>/dev/null || true
    ip link del "$_VETH" 2>/dev/null || true

    ip netns add "$_NS"
    ip link add "$_VETH" type veth peer name "$_VETH_IN"
    ip link set "$_VETH_IN" netns "$_NS"
    ip addr add "${_HOST_IP}/24" dev "$_VETH"
    ip -6 addr add "${_HOST_IP6}/64" dev "$_VETH" nodad
    ip link set "$_VETH" up
    ip netns exec "$_NS" ip addr add "${_NS_IP}/24" dev "$_VETH_IN"
    ip netns exec "$_NS" ip -6 addr add "${_NS_IP6}/64" dev "$_VETH_IN" nodad
    ip netns exec "$_NS" ip link set "$_VETH_IN" up
    ip netns exec "$_NS" ip link set lo up

    _load_xdp_program "integration setup" || return 1
    _configure_test_runtime || return 1
    ip link set dev "$_VETH" xdpgeneric pinned "$_PIN_DIR/prog" || return 1
    echo "generic" > "$_RUN_DIR/xdp_mode"
}

_teardown() {
    ip link set dev "$_VETH" xdpgeneric off 2>/dev/null || true
    tc filter del dev "$_VETH" egress pref 49152 handle 1 2>/dev/null || true
    tc qdisc del dev "$_VETH" clsact 2>/dev/null || true
    nft delete table inet axdp_integ 2>/dev/null || true
    ip netns del "$_NS" 2>/dev/null || true
    ip link del "$_VETH" 2>/dev/null || true
    rm -rf "$_PIN_DIR" "${_PIN_DIR}_next" "${_PIN_DIR}_rollback" \
        "$_DEBUG_PIN_DIR" "$_RUN_DIR"
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
_ip6be() { python3 -c "import socket; print(' '.join(f'{b:02x}' for b in socket.inet_pton(socket.AF_INET6, '$1')))"; }
# Encode port as __be16 (network order) hex bytes
_u16be() { python3 -c "import struct; print(' '.join(f'{b:02x}' for b in struct.pack('>H', $1)))"; }
# Current kernel monotonic time in ns (same epoch as bpf_ktime_get_ns)
_ktime_ns() { python3 -c "import time; print(time.clock_gettime_ns(time.CLOCK_MONOTONIC))"; }

_pinned_prog_id() {
    bpftool -j prog show pinned "$1" | python3 -c '
import json, sys
data = json.load(sys.stdin)
if isinstance(data, list):
    data = data[0]
print(data["id"])
'
}

# Read a little-endian __u32 from bpftool's JSON output. Depending on the
# bpftool version, raw values are emitted as an array of hex-byte strings
# rather than as a scalar.
_map_lookup_u32() {
    local map_path="$1" key_hex="$2"
    bpftool -j map lookup pinned "$map_path" key hex $key_hex \
        | python3 -c '
import json, struct, sys

value = json.load(sys.stdin)["value"]
if isinstance(value, list):
    raw = bytes(int(byte, 0) if isinstance(byte, str) else byte for byte in value)
    print(struct.unpack_from("<I", raw)[0])
elif isinstance(value, str):
    print(int(value, 0))
else:
    print(int(value))
'
}

# Assert the ABI exposed by the loaded kernel map, rather than duplicating C
# declarations in a Python model. bpftool has used both bytes_key/bytes_value
# and key_size/value_size field names across releases, so accept either JSON
# spelling while keeping the contract itself exact.
_assert_map_abi() {
    local map_name="$1" expected_type="$2" expected_key="$3"
    local expected_value="$4" expected_entries="$5"

    bpftool -j map show pinned "$_PIN_DIR/$map_name" \
        | python3 -c '
import json, sys

name, expected_type, expected_key, expected_value, expected_entries = sys.argv[1:]
data = json.load(sys.stdin)
if isinstance(data, list):
    data = data[0]

actual = (
    data.get("type"),
    data.get("bytes_key", data.get("key_size")),
    data.get("bytes_value", data.get("value_size")),
    data.get("max_entries"),
)
expected = (expected_type, int(expected_key), int(expected_value), int(expected_entries))
if actual != expected:
    raise SystemExit(f"{name} ABI {actual!r}, expected {expected!r}")
' "$map_name" "$expected_type" "$expected_key" "$expected_value" "$expected_entries"
}

# Integration traffic uses an RFC1918 veth subnet. Production defaults treat
# private source addresses as bogons, so disable that independent policy here;
# otherwise whitelist, ACL, conntrack, and rate-limit assertions never reach
# the code paths they claim to exercise.
_configure_test_runtime() {
    local value_hex value_bytes=72
    value_bytes=$(bpftool -j map show pinned "$_PIN_DIR/xdp_runtime_cfg" | python3 -c '
import json, sys
data = json.load(sys.stdin)
if isinstance(data, list):
    data = data[0]
print(int(data.get("bytes_value", data.get("value_size", 72))))
')
    value_hex=$(python3 -c '
import struct, sys
size = int(sys.argv[1])
# cfg_flags sits after eight u64 fields; set XDP_CFG_FLAG_BOGON_DISABLED.
payload = struct.pack("<QQQQQQQQI", *([0] * 8), 1)
payload = payload.ljust(size, b"\x00")
print(" ".join(f"{byte:02x}" for byte in payload[:size]))
' "$value_bytes")
    bpftool map update pinned "$_PIN_DIR/xdp_runtime_cfg" \
        key hex 00 00 00 00 value hex $value_hex >/dev/null
}

# Send TCP SYN from inside the namespace to _HOST_IP:PORT.
# Returns 0 if XDP passes (kernel sends RST or accepts), 1 if XDP drops (timeout).
_tcp_probe() {
    local port="$1"
    local dest="${2:-$_HOST_IP}"
    local family="${3:-inet}"
    ip netns exec "$_NS" python3 - "$dest" "$port" "$family" <<'PYEOF' 2>/dev/null
import socket, sys
af = socket.AF_INET6 if sys.argv[3] == "inet6" else socket.AF_INET
s = socket.socket(af, socket.SOCK_STREAM)
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
    local family="${2:-inet}"
    python3 - "$port" "$family" <<'PYEOF'
import socket, sys
af = socket.AF_INET6 if sys.argv[2] == "inet6" else socket.AF_INET
s = socket.socket(af, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('::' if af == socket.AF_INET6 else '', int(sys.argv[1])))
s.settimeout(2)
try:
    data, _ = s.recvfrom(1024)
    sys.stdout.buffer.write(data)
    sys.stdout.flush()
except socket.timeout:
    pass
PYEOF
}

_udp_send() {
    local family="$1" src="$2" sport="$3" dest="$4" dport="$5"
    local packets="$6" payload_bytes="$7"
    ip netns exec "$_NS" python3 - "$family" "$src" "$sport" "$dest" "$dport" "$packets" "$payload_bytes" <<'PYEOF'
import socket, sys

family, source, sport, dest, dport, packets, payload_bytes = sys.argv[1:]
af = socket.AF_INET6 if family == "inet6" else socket.AF_INET
s = socket.socket(af, socket.SOCK_DGRAM)
s.bind((source, int(sport)))
payload = b"x" * int(payload_bytes)
for _ in range(int(packets)):
    s.sendto(payload, (dest, int(dport)))
s.close()
PYEOF
}

_map_lookup_u64_offset() {
    local map_path="$1" key_hex="$2" offset="$3"
    bpftool -j map lookup pinned "$map_path" key hex $key_hex \
        | python3 -c '
import json, struct, sys

value = json.load(sys.stdin)["value"]
raw = bytes(int(byte, 0) if isinstance(byte, str) else byte for byte in value)
print(struct.unpack_from("<Q", raw, int(sys.argv[1]))[0])
' "$offset"
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

    ip -d link show "$_VETH" | grep -q "prog/xdp" || {
        echo "XDP not shown in ip link output for $_VETH"
        return 1
    }
}

_header_define() {
    awk -v name="$2" '$1 == "#define" && $2 == name { print $3; exit }' "$1"
}

test_loaded_map_abi() {
    local ct4 ct6 rate4 rate6
    ct4=$(_header_define "$REPO_ROOT/bpf/include/map_sizes.h" CT_MAP_MAX_ENTRIES_V4)
    ct6=$(_header_define "$REPO_ROOT/bpf/include/map_sizes.h" CT_MAP_MAX_ENTRIES_V6)
    rate4=$(_header_define "$REPO_ROOT/bpf/include/map_sizes.h" RATE_MAP_MAX_ENTRIES_V4)
    rate6=$(_header_define "$REPO_ROOT/bpf/include/map_sizes.h" RATE_MAP_MAX_ENTRIES_V6)

    _assert_map_abi tcp_ct4 lru_hash 12 8 "$ct4" || return 1
    _assert_map_abi tcp_ct6 lru_hash 36 8 "$ct6" || return 1
    _assert_map_abi udp_ct4 lru_hash 12 8 "$ct4" || return 1
    _assert_map_abi udp_ct6 lru_hash 36 8 "$ct6" || return 1
    _assert_map_abi syn4 array_of_maps 4 4 65536 || return 1
    _assert_map_abi syn6 array_of_maps 4 4 65536 || return 1

    _assert_map_abi tsc4 lru_hash 8 8 "$rate4" || return 1
    _assert_map_abi tsc6 lru_hash 20 8 "$rate6" || return 1
    _assert_map_abi tsc_pfx4 lru_hash 8 8 "$rate4" || return 1
    _assert_map_abi tsc_pfx6 lru_hash 20 8 "$rate6" || return 1
    _assert_map_abi tsc_port array 4 8 65536 || return 1

    _assert_map_abi tcp_port_policies hash 4 32 1024 || return 1
    _assert_map_abi udp_global_rl array 4 40 1 || return 1
    _assert_map_abi udp_percpu_acc percpu_array 4 16 1 || return 1
}

test_interrupted_candidate_restore() {
    local candidate_dir="${_PIN_DIR}_next"
    local stable_id candidate_id attached_id
    local -a IFACES=("$_VETH")

    mkdir -p "$candidate_dir" || return 1
    bpftool prog load "$_XDP_OBJ" "$candidate_dir/prog" type xdp \
        pinmaps "$candidate_dir" >/dev/null 2>&1 || {
        echo "failed to load interrupted candidate generation"
        return 1
    }
    stable_id=$(_pinned_prog_id "$_PIN_DIR/prog") || return 1
    candidate_id=$(_pinned_prog_id "$candidate_dir/prog") || return 1
    [[ "$candidate_id" != "$stable_id" ]] || {
        echo "candidate generation reused the stable program id"
        return 1
    }

    _auto_xdp_attach_mode "$_VETH" "$candidate_dir/prog" generic || return 1
    attached_id=$(_auto_xdp_iface_prog_id "$_VETH") || {
        echo "could not read candidate program id from the interface"
        return 1
    }
    assert_eq "$attached_id" "$candidate_id" "candidate attached before recovery" || return 1

    _auto_xdp_restore_interrupted_reload || return 1
    attached_id=$(_auto_xdp_iface_prog_id "$_VETH") || return 1
    assert_eq "$attached_id" "$stable_id" "stable program restored" || return 1
    [[ -e "$_PIN_DIR/prog" && ! -e "$candidate_dir" ]] || {
        echo "recovery did not retain stable pins and remove the failed candidate"
        return 1
    }
}

test_handler_transactional_hot_swap() {
    local handler_obj="/tmp/axdp_integ_gre_handler.o"
    local config_path="/tmp/axdp_integ_handler.toml"
    local asm_inc multiarch_inc old_id new_id map_id
    asm_inc=$(clang -print-file-name=include) || return 1
    multiarch_inc="/usr/include/$(uname -m)-linux-gnu"
    local -a include_args=(-I "$REPO_ROOT/handlers" -I /usr/include -I /usr/include/bpf -I "$asm_inc")
    [[ ! -d "$multiarch_inc" ]] || include_args+=(-I "$multiarch_inc")

    clang -O2 -g -target bpf -mcpu=v3 \
        "${include_args[@]}" \
        -c "$REPO_ROOT/handlers/gre_handler.c" -o "$handler_obj" || return 1
    printf '[slots]\nenabled = []\n' > "$config_path"

    PYTHONPATH="$REPO_ROOT" python3 -m auto_xdp.admin_cli \
        --config "$config_path" \
        --bpf-pin-dir "$_PIN_DIR" \
        --handlers-dir /tmp \
        slot load 47 "$handler_obj" >/dev/null || return 1
    old_id=$(_pinned_prog_id "$_PIN_DIR/handlers/proto_47") || return 1

    PYTHONPATH="$REPO_ROOT" python3 -m auto_xdp.admin_cli \
        --config "$config_path" \
        --bpf-pin-dir "$_PIN_DIR" \
        --handlers-dir /tmp \
        slot load 47 "$handler_obj" >/dev/null || return 1
    new_id=$(_pinned_prog_id "$_PIN_DIR/handlers/proto_47") || return 1
    map_id=$(_map_lookup_u32 "$_PIN_DIR/proto_handlers" "$(_u32le 47)") || return 1

    [[ "$new_id" != "$old_id" ]] || {
        echo "handler hot swap did not load a new program generation"
        return 1
    }
    [[ "$map_id" == "$new_id" ]] || {
        echo "proto_handlers entry points to $map_id, expected candidate $new_id"
        return 1
    }
    if find "$_PIN_DIR/handlers" -maxdepth 1 \
            \( -name 'proto_47_next_*' -o -name 'proto_47_rollback_*' \) | grep -q .; then
        echo "handler transaction left candidate or rollback pins after success"
        return 1
    fi
    rm -f "$handler_obj" "$config_path"
}

test_reload() {
    local map_id

    xdp_maps_ready || { echo "xdp_maps_ready failed with full map set"; return 1; }

    map_id=$(bpftool -j map show pinned "$_PIN_DIR/tcp_ct4" \
        | python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])') || {
        echo "failed to resolve tcp_ct4 map id"; return 1;
    }

    rm "$_PIN_DIR/tcp_ct4"
    xdp_maps_ready && { echo "xdp_maps_ready should detect missing tcp_ct4"; return 1; }

    # Removing a pin does not destroy a map still referenced by the attached
    # program. Re-pin that exact map; loading a second program with pinmaps
    # would collide with every map name that remains in this directory.
    bpftool map pin id "$map_id" "$_PIN_DIR/tcp_ct4" >/dev/null || {
        echo "failed to re-pin tcp_ct4 map id $map_id"; return 1;
    }

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
    lookup_val=$(_map_lookup_u32 "$_PIN_DIR/tcp_whitelist" "$key_hex")
    assert_eq "$lookup_val" "1" "whitelist enabled" || return 1
    _tcp_probe "$port" || { echo "SYN to whitelisted port was dropped"; return 1; }

    # Disable port; SYN should be dropped (timeout).
    bpftool map update pinned "$_PIN_DIR/tcp_whitelist" \
        key hex $key_hex value hex 00 00 00 00 >/dev/null 2>&1
    lookup_val=$(_map_lookup_u32 "$_PIN_DIR/tcp_whitelist" "$key_hex")
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

_attach_tc_egress() {
    command -v tc >/dev/null 2>&1 || { echo "tc not found"; return 1; }
    bpftool prog load "$_TC_OBJ" "$_PIN_DIR/tc_egress_prog" type classifier \
        map name tcp_ct4 pinned "$_PIN_DIR/tcp_ct4" \
        map name tcp_ct6 pinned "$_PIN_DIR/tcp_ct6" \
        map name udp_ct4 pinned "$_PIN_DIR/udp_ct4" \
        map name udp_ct6 pinned "$_PIN_DIR/udp_ct6" \
        map name sctp_conntrack pinned "$_PIN_DIR/sctp_conntrack" \
        map name xdp_runtime_cfg pinned "$_PIN_DIR/xdp_runtime_cfg" >/dev/null || {
        echo "failed to load tc egress program against shared maps"
        return 1
    }
    tc qdisc add dev "$_VETH" clsact 2>/dev/null || true
    tc filter replace dev "$_VETH" egress pref 49152 handle 1 \
        bpf direct-action object-pinned "$_PIN_DIR/tc_egress_prog" >/dev/null || {
        echo "failed to attach tc egress filter"
        return 1
    }
}

_map_has_key() {
    local map_path="$1"
    shift
    bpftool map lookup pinned "$map_path" key hex "$@" >/dev/null 2>&1
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

    # tcp_port_policy_cfg: three rate/connection limits, two source prefixes,
    # two additional connection limits, and padding (__u32 x 8).
    local policy_hex
    policy_hex=$(python3 -c "
import struct
print(' '.join(f'{b:02x}' for b in struct.pack('<IIIIIIII', $rate_max, 0, 0, 32, 128, 0, 0, 0)))
")
    bpftool map update pinned "$_PIN_DIR/tcp_port_policies" \
        key hex $(_u32le "$port") value hex $policy_hex >/dev/null 2>&1

    # syn_rate_val.state packs window tick (upper 32) and count (lower 32).
    local now_ns rate_val_hex
    now_ns=$(_ktime_ns)
    rate_val_hex=$(python3 -c "
import struct
tick = ($now_ns // 1_000_000) & 0xffffffff
state = (tick << 32) | $rate_max
print(' '.join(f'{b:02x}' for b in struct.pack('<Q', state)))
")
    # Create a per-port inner LRU and install it into the syn4 outer slot for
    # $port, then pre-fill the source's counter with count=rate_max inside the
    # current window so the next SYN overflows. BPF_F_INNER_MAP is valid for
    # array inner maps, not LRU hash maps; the latter are created with flags 0.
    local inner_pin="$_PIN_DIR/it_syn4_$port" value_bytes=8
    value_bytes=$(python3 -c '
import json, subprocess, sys
data = json.loads(subprocess.check_output(["bpftool", "-j", "map", "show", "pinned", sys.argv[1]]))
if isinstance(data, list):
    data = data[0]
print(int(data.get("bytes_value", data.get("value_size", 8))))
' "$_PIN_DIR/tsc4")
    bpftool map create "$inner_pin" type lru_hash key 4 value "$value_bytes" \
        entries 1024 name "s4_$port" flags 0 >/dev/null 2>&1 || {
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

test_connection_limits() {
    local source_at=7710 prefix_below=7711 prefix_at=7712
    local port_below=7713 port_at=7714 disabled=7715
    local port policy_hex state_hex key_hex

    for port in "$source_at" "$prefix_below" "$prefix_at" \
            "$port_below" "$port_at" "$disabled"; do
        bpftool map update pinned "$_PIN_DIR/tcp_whitelist" \
            key hex $(_u32le "$port") value hex 01 00 00 00 >/dev/null 2>&1 || return 1
    done

    # Use a current 100-ms activity tick so the preloaded counter is live for
    # the real BPF timeout check. The low word is the established count.
    _connection_state_hex() {
        local count="$1"
        python3 -c "
import struct, time
tick = (time.clock_gettime_ns(time.CLOCK_MONOTONIC) // 100_000_000) & 0xffffffff
state = (tick << 32) | ($count & 0xffffffff)
print(' '.join(f'{byte:02x}' for byte in struct.pack('<Q', state)))
"
    }

    _connection_policy_hex() {
        local source_max="$1" prefix_max="$2" port_max="$3"
        python3 -c "
import struct
values = (0, 0, $source_max, 32, 128, $prefix_max, $port_max, 0)
print(' '.join(f'{byte:02x}' for byte in struct.pack('<IIIIIIII', *values)))
"
    }

    # Per-source cap at the limit drops.
    policy_hex=$(_connection_policy_hex 2 0 0)
    bpftool map update pinned "$_PIN_DIR/tcp_port_policies" \
        key hex $(_u32le "$source_at") value hex $policy_hex >/dev/null 2>&1 || return 1
    key_hex="$(_ip4be "$_NS_IP") $(_u32le "$source_at")"
    state_hex=$(_connection_state_hex 2)
    bpftool map update pinned "$_PIN_DIR/tsc4" \
        key hex $key_hex value hex $state_hex >/dev/null 2>&1 || return 1
    _tcp_probe "$source_at" && { echo "SYN at per-source cap was not dropped"; return 1; }

    # Per-prefix cap passes immediately below the limit and drops at it.
    policy_hex=$(_connection_policy_hex 0 2 0)
    for port in "$prefix_below" "$prefix_at"; do
        bpftool map update pinned "$_PIN_DIR/tcp_port_policies" \
            key hex $(_u32le "$port") value hex $policy_hex >/dev/null 2>&1 || return 1
    done
    key_hex="$(_ip4be "$_NS_IP") $(_u32le "$prefix_below")"
    state_hex=$(_connection_state_hex 1)
    bpftool map update pinned "$_PIN_DIR/tsc_pfx4" \
        key hex $key_hex value hex $state_hex >/dev/null 2>&1 || return 1
    _tcp_probe "$prefix_below" || { echo "SYN below per-prefix cap was dropped"; return 1; }

    key_hex="$(_ip4be "$_NS_IP") $(_u32le "$prefix_at")"
    state_hex=$(_connection_state_hex 2)
    bpftool map update pinned "$_PIN_DIR/tsc_pfx4" \
        key hex $key_hex value hex $state_hex >/dev/null 2>&1 || return 1
    _tcp_probe "$prefix_at" && { echo "SYN at per-prefix cap was not dropped"; return 1; }

    # Per-port cap has the same boundary and does not depend on a source key.
    policy_hex=$(_connection_policy_hex 0 0 2)
    for port in "$port_below" "$port_at"; do
        bpftool map update pinned "$_PIN_DIR/tcp_port_policies" \
            key hex $(_u32le "$port") value hex $policy_hex >/dev/null 2>&1 || return 1
    done
    state_hex=$(_connection_state_hex 1)
    bpftool map update pinned "$_PIN_DIR/tsc_port" \
        key hex $(_u32le "$port_below") value hex $state_hex >/dev/null 2>&1 || return 1
    _tcp_probe "$port_below" || { echo "SYN below per-port cap was dropped"; return 1; }

    state_hex=$(_connection_state_hex 2)
    bpftool map update pinned "$_PIN_DIR/tsc_port" \
        key hex $(_u32le "$port_at") value hex $state_hex >/dev/null 2>&1 || return 1
    _tcp_probe "$port_at" && { echo "SYN at per-port cap was not dropped"; return 1; }

    # A populated counter is inert when all connection-limit policy fields are
    # zero, which is the public disabled-state contract.
    policy_hex=$(_connection_policy_hex 0 0 0)
    bpftool map update pinned "$_PIN_DIR/tcp_port_policies" \
        key hex $(_u32le "$disabled") value hex $policy_hex >/dev/null 2>&1 || return 1
    state_hex=$(_connection_state_hex 4294967295)
    bpftool map update pinned "$_PIN_DIR/tsc_port" \
        key hex $(_u32le "$disabled") value hex $state_hex >/dev/null 2>&1 || return 1
    _tcp_probe "$disabled" || { echo "disabled connection cap dropped SYN"; return 1; }
}

test_connection_counter_cas_contention() {
    local port=7716 per_worker=8 workers total
    local ready_file server_pid client_pid state source_count prefix_count port_count
    ready_file=$(mktemp)
    workers=$(ip netns exec "$_NS" python3 -c 'import os; print(min(8, len(os.sched_getaffinity(0))))')
    if [[ "$workers" -lt 2 ]]; then
        test_log_warning "SKIP CAS contention needs at least two available CPUs"
        rm -f "$ready_file"
        return 0
    fi
    total=$((workers * per_worker))

    bpftool map update pinned "$_PIN_DIR/tcp_whitelist" \
        key hex $(_u32le "$port") value hex 01 00 00 00 >/dev/null 2>&1 || return 1

    python3 - "$port" "$total" <<'PYEOF' &
import socket, sys, time

port, total = map(int, sys.argv[1:])
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind(("10.99.0.1", port))
server.listen(total)
connections = [server.accept()[0] for _ in range(total)]
time.sleep(4)
for connection in connections:
    connection.close()
server.close()
PYEOF
    server_pid=$!

    ip netns exec "$_NS" python3 - "$port" "$workers" "$per_worker" "$ready_file" <<'PYEOF' &
import multiprocessing as mp
import os
import socket
import sys
import time

port, workers, per_worker = map(int, sys.argv[1:4])
ready_file = sys.argv[4]
cpus = sorted(os.sched_getaffinity(0))[:workers]
start = mp.Event()
close = mp.Event()
ready = mp.Queue()

def worker(cpu):
    os.sched_setaffinity(0, {cpu})
    start.wait()
    connections = []
    for _ in range(per_worker):
        connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        connection.connect(("10.99.0.1", port))
        connections.append(connection)
    ready.put(len(connections))
    close.wait()
    for connection in connections:
        connection.close()

processes = [mp.Process(target=worker, args=(cpu,)) for cpu in cpus]
for process in processes:
    process.start()
start.set()
connected = sum(ready.get(timeout=8) for _ in processes)
with open(ready_file, "w", encoding="ascii") as output:
    output.write(str(connected))
time.sleep(2)
close.set()
for process in processes:
    process.join(5)
    if process.exitcode != 0:
        raise SystemExit(f"worker exited with {process.exitcode}")
PYEOF
    client_pid=$!

    for ((state = 0; state < 100; state++)); do
        [[ ! -s "$ready_file" ]] || break
        sleep 0.05
    done
    if [[ "$(cat "$ready_file")" != "$total" ]]; then
        echo "concurrent clients did not establish all $total connections"
        kill "$client_pid" "$server_pid" 2>/dev/null || true
        wait "$client_pid" "$server_pid" 2>/dev/null || true
        rm -f "$ready_file"
        return 1
    fi

    state=$(_map_lookup_u64_offset \
        "$_PIN_DIR/tsc4" "$(_ip4be "$_NS_IP") $(_u32le "$port")" 0) || return 1
    source_count=$((state & 0xFFFFFFFF))
    state=$(_map_lookup_u64_offset \
        "$_PIN_DIR/tsc_pfx4" "$(_ip4be "$_NS_IP") $(_u32le "$port")" 0) || return 1
    prefix_count=$((state & 0xFFFFFFFF))
    state=$(_map_lookup_u64_offset "$_PIN_DIR/tsc_port" "$(_u32le "$port")" 0) || return 1
    port_count=$((state & 0xFFFFFFFF))
    if [[ "$source_count" -ne "$total" || "$prefix_count" -ne "$total" ||
          "$port_count" -ne "$total" ]]; then
        echo "CAS record mismatch expected=$total source=$source_count prefix=$prefix_count port=$port_count"
        kill "$client_pid" "$server_pid" 2>/dev/null || true
        wait "$client_pid" "$server_pid" 2>/dev/null || true
        rm -f "$ready_file"
        return 1
    fi

    wait "$client_pid" || return 1
    wait "$server_pid" || return 1
    rm -f "$ready_file"

    for ((state = 0; state < 40; state++)); do
        source_count=$(_map_lookup_u64_offset \
            "$_PIN_DIR/tsc4" "$(_ip4be "$_NS_IP") $(_u32le "$port")" 0)
        prefix_count=$(_map_lookup_u64_offset \
            "$_PIN_DIR/tsc_pfx4" "$(_ip4be "$_NS_IP") $(_u32le "$port")" 0)
        port_count=$(_map_lookup_u64_offset \
            "$_PIN_DIR/tsc_port" "$(_u32le "$port")" 0)
        source_count=$((source_count & 0xFFFFFFFF))
        prefix_count=$((prefix_count & 0xFFFFFFFF))
        port_count=$((port_count & 0xFFFFFFFF))
        [[ "$source_count" -ne 0 || "$prefix_count" -ne 0 || "$port_count" -ne 0 ]] || return 0
        sleep 0.05
    done
    echo "CAS close mismatch source=$source_count prefix=$prefix_count port=$port_count"
    return 1
}

test_service_restart() {
    # Seed a conntrack entry before the reload to confirm prog re-pins cleanly.
    local ct_key ct_val
    ct_key="$(_u16be 6100) $(_u16be 7704) $(_ip4be "$_NS_IP") $(_ip4be "$_HOST_IP")"
    ct_val=$(_u64le "$(_ktime_ns)")
    bpftool map update pinned "$_PIN_DIR/tcp_ct4" \
        key hex $ct_key value hex $ct_val >/dev/null 2>&1

    # Simulate service restart: detach, wipe pins, reload, re-attach.
    ip link set dev "$_VETH" xdpgeneric off 2>/dev/null || true
    rm -rf "$_PIN_DIR"
    mkdir -p "$_PIN_DIR"
    _load_xdp_program "service restart" || return 1
    _configure_test_runtime || return 1
    ip link set dev "$_VETH" xdpgeneric pinned "$_PIN_DIR/prog" || return 1

    [[ -f "$_PIN_DIR/prog" ]] || { echo "prog pin missing after reload"; return 1; }
    xdp_maps_ready || { echo "maps not ready after reload"; return 1; }

    # Verify the newly loaded program passes traffic on a whitelisted port.
    bpftool map update pinned "$_PIN_DIR/tcp_whitelist" \
        key hex $(_u32le 7705) value hex 01 00 00 00 >/dev/null 2>&1
    _tcp_probe 7705 || { echo "traffic not passing after service restart"; return 1; }
}

test_tc_egress_udp_reply() {
    local sport=5200 dport=9902
    local key_hex

    _attach_tc_egress || return 1

    python3 - "$_HOST_IP" "$dport" "$_NS_IP" "$sport" <<'PYEOF' &
import socket, sys, time
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind((sys.argv[1], int(sys.argv[2])))
time.sleep(0.2)
s.sendto(b'axdp-tc', (sys.argv[3], int(sys.argv[4])))
s.close()
PYEOF
    local send_pid=$!
    sleep 0.4
    wait "$send_pid" 2>/dev/null || true

    # Reverse tuple recorded by tc: sport=remote, dport=local, saddr=remote, daddr=local.
    key_hex="$(_u16be "$sport") $(_u16be "$dport") $(_ip4be "$_NS_IP") $(_ip4be "$_HOST_IP")"
    _map_has_key "$_PIN_DIR/udp_ct4" $key_hex || {
        echo "tc egress did not insert udp_ct4 reverse tuple"
        return 1
    }

    local recv_file
    recv_file=$(mktemp)
    _udp_listen_py "$dport" >"$recv_file" 2>/dev/null &
    local listen_pid=$!
    sleep 0.15
    ip netns exec "$_NS" python3 - "$_NS_IP" "$sport" "$_HOST_IP" "$dport" <<'PYEOF' 2>/dev/null
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind((sys.argv[1], int(sys.argv[2])))
s.sendto(b'axdp-tc-reply', (sys.argv[3], int(sys.argv[4])))
PYEOF
    sleep 0.4
    kill "$listen_pid" 2>/dev/null || true
    wait "$listen_pid" 2>/dev/null || true
    local got
    got=$(<"$recv_file")
    rm -f "$recv_file"
    [[ "$got" == *"axdp-tc-reply"* ]] || {
        echo "inbound UDP reply after tc-created conntrack was dropped"
        return 1
    }
}

test_ipv6_whitelist() {
    local port=7706
    ip -6 neigh replace "$_NS_IP6" lladdr "$(ip netns exec "$_NS" cat /sys/class/net/$_VETH_IN/address)" \
        dev "$_VETH" nud permanent 2>/dev/null || true
    ip netns exec "$_NS" ip -6 neigh replace "$_HOST_IP6" \
        lladdr "$(cat /sys/class/net/$_VETH/address)" dev "$_VETH_IN" nud permanent 2>/dev/null || true
    bpftool map update pinned "$_PIN_DIR/tcp_whitelist" \
        key hex $(_u32le "$port") value hex 01 00 00 00 >/dev/null 2>&1
    _tcp_probe "$port" "$_HOST_IP6" inet6 || {
        echo "IPv6 SYN to whitelisted port was dropped"
        return 1
    }
    bpftool map update pinned "$_PIN_DIR/tcp_whitelist" \
        key hex $(_u32le "$port") value hex 00 00 00 00 >/dev/null 2>&1
    _tcp_probe "$port" "$_HOST_IP6" inet6 && {
        echo "IPv6 SYN to non-whitelisted port was not dropped"
        return 1
    }
    return 0
}

test_ipv6_udp_whitelist() {
    local sport=5300 dport=7708 recv_file listen_pid got
    ip -6 neigh replace "$_NS_IP6" lladdr "$(ip netns exec "$_NS" cat /sys/class/net/$_VETH_IN/address)" \
        dev "$_VETH" nud permanent 2>/dev/null || true
    ip netns exec "$_NS" ip -6 neigh replace "$_HOST_IP6" \
        lladdr "$(cat /sys/class/net/$_VETH/address)" dev "$_VETH_IN" nud permanent 2>/dev/null || true

    bpftool map update pinned "$_PIN_DIR/udp_whitelist" \
        key hex $(_u32le "$dport") value hex 01 00 00 00 >/dev/null 2>&1
    recv_file=$(mktemp)
    _udp_listen_py "$dport" inet6 >"$recv_file" 2>/dev/null &
    listen_pid=$!
    sleep 0.15
    _udp_send inet6 "$_NS_IP6" "$sport" "$_HOST_IP6" "$dport" 1 32 || return 1
    sleep 0.2
    kill "$listen_pid" 2>/dev/null || true
    wait "$listen_pid" 2>/dev/null || true
    got=$(<"$recv_file")
    rm -f "$recv_file"
    [[ "$got" == *"xxx"* ]] || {
        echo "IPv6 UDP packet to whitelisted port was dropped"
        return 1
    }

    bpftool map update pinned "$_PIN_DIR/udp_whitelist" \
        key hex $(_u32le "$dport") value hex 00 00 00 00 >/dev/null 2>&1
    recv_file=$(mktemp)
    _udp_listen_py "$dport" inet6 >"$recv_file" 2>/dev/null &
    listen_pid=$!
    sleep 0.15
    _udp_send inet6 "$_NS_IP6" "$sport" "$_HOST_IP6" "$dport" 1 32 || return 1
    sleep 0.2
    kill "$listen_pid" 2>/dev/null || true
    wait "$listen_pid" 2>/dev/null || true
    got=$(<"$recv_file")
    rm -f "$recv_file"
    [[ -z "$got" ]] || {
        echo "IPv6 UDP packet to non-whitelisted port was not dropped"
        return 1
    }
}

test_udp_global_rate_limit() {
    local sport=5400 dport=7709 packets=140 payload_bytes=1200
    local recv_file listen_pid received global_hex blocked_until now_ns

    bpftool map update pinned "$_PIN_DIR/udp_whitelist" \
        key hex $(_u32le "$dport") value hex 01 00 00 00 >/dev/null 2>&1
    global_hex=$(python3 -c '
import struct
print(" ".join(f"{byte:02x}" for byte in struct.pack("<IIQQQQ", 0, 1, 0, 0, 0, 0)))
')
    bpftool map update pinned "$_PIN_DIR/udp_global_rl" \
        key hex 00 00 00 00 value hex $global_hex >/dev/null 2>&1

    recv_file=$(mktemp)
    python3 - "$dport" "$recv_file" <<'PYEOF' &
import socket, sys

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("", int(sys.argv[1])))
s.settimeout(2)
count = 0
try:
    while True:
        s.recvfrom(2048)
        count += 1
except socket.timeout:
    pass
with open(sys.argv[2], "w", encoding="ascii") as handle:
    handle.write(str(count))
PYEOF
    listen_pid=$!
    sleep 0.15
    _udp_send inet "$_NS_IP" "$sport" "$_HOST_IP" "$dport" "$packets" "$payload_bytes" || return 1

    now_ns=$(_ktime_ns)
    blocked_until=$(_map_lookup_u64_offset "$_PIN_DIR/udp_global_rl" "00 00 00 00" 32)
    [[ "$blocked_until" -gt "$now_ns" ]] || {
        echo "UDP global limiter did not enter a blocked window"
        kill "$listen_pid" 2>/dev/null || true
        wait "$listen_pid" 2>/dev/null || true
        rm -f "$recv_file"
        return 1
    }

    wait "$listen_pid" 2>/dev/null || true
    received=$(<"$recv_file")
    rm -f "$recv_file"
    [[ "$received" -gt 0 && "$received" -lt "$packets" ]] || {
        echo "UDP global limiter received=$received packets=$packets"
        return 1
    }
}

test_nftables_packet_path() {
    command -v nft >/dev/null 2>&1 || { echo "nft not found"; return 1; }
    ip link set dev "$_VETH" xdpgeneric off 2>/dev/null || true

    PYTHONPATH="$REPO_ROOT" python3 - <<'PYEOF' || return 1
from auto_xdp import config as cfg
from auto_xdp.backends.nftables import NftablesBackend
from auto_xdp.state import DesiredState

cfg.NFT_FAMILY = "inet"
cfg.NFT_TABLE = "axdp_integ"
cfg.BOGON_FILTER_ENABLED = False
cfg.SLOT_DEFAULT_ACTION = "drop"
backend = NftablesBackend()
try:
    backend.reconcile(
        DesiredState(tcp_ports={7707}, bogon_filter_enabled=False),
        dry_run=False,
    )
finally:
    backend.close()
PYEOF

    _tcp_probe 7707 || { echo "nftables did not accept SYN to allowed TCP port"; return 1; }
    _tcp_probe 7708 && { echo "nftables did not drop SYN to closed TCP port"; return 1; }
    return 0
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
_run_kernel_test() {
    local name="$1"
    shift
    if ! _setup; then
        printf 'fatal: integration setup failed before %s\n' "$name" >&2
        exit 1
    fi
    run_test "$name" "$@"
    _teardown
}

trap - EXIT
while IFS= read -r function_name; do
    [[ -n "$function_name" ]] || continue
    _run_kernel_test "${function_name#test_}" "$function_name"
done < <(
    discover_test_functions "${BASH_SOURCE[0]}"
)
_teardown

finish_tests
