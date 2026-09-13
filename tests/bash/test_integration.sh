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
# otherwise whitelist, ACL, and rate-limit assertions never reach
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
    local rate4 rate6
    rate4=$(_header_define "$REPO_ROOT/bpf/include/map_sizes.h" RATE_MAP_MAX_ENTRIES_V4)
    rate6=$(_header_define "$REPO_ROOT/bpf/include/map_sizes.h" RATE_MAP_MAX_ENTRIES_V6)

    _assert_map_abi syn4 array_of_maps 4 4 65536 || return 1
    _assert_map_abi syn6 array_of_maps 4 4 65536 || return 1

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

test_minecraft_profile_dataplane() {
    local port=25565
    local handler_obj="/tmp/axdp_integ_minecraft_handler.o"
    local result_file="/tmp/axdp_integ_minecraft_result"
    local asm_inc multiarch_inc server_pid
    asm_inc=$(clang -print-file-name=include) || return 1
    multiarch_inc="/usr/include/$(uname -m)-linux-gnu"
    local -a include_args=(
        -I "$REPO_ROOT/handlers"
        -I "$REPO_ROOT/bpf/include"
        -I /usr/include
        -I /usr/include/bpf
        -I "$asm_inc"
    )
    [[ ! -d "$multiarch_inc" ]] || include_args+=(-I "$multiarch_inc")

    clang -O3 -g -target bpf -mcpu=v3 -fno-stack-protector \
        "${include_args[@]}" \
        -c "$REPO_ROOT/handlers/minecraft_handler.c" -o "$handler_obj" || return 1
    PYTHONPATH="$REPO_ROOT" python3 -m auto_xdp.admin_cli \
        --config /tmp/axdp_integ_missing.toml \
        --bpf-pin-dir "$_PIN_DIR" \
        --install-dir "$REPO_ROOT" \
        port-handler load tcp "$port" "$handler_obj" --no-config-update \
        >/dev/null || return 1
    bpftool map update pinned "$_PIN_DIR/tcp_whitelist" \
        key hex $(_u32le "$port") value hex 01 00 00 00 >/dev/null || return 1

    rm -f "$result_file"
    python3 - "$port" "$result_file" <<'PYEOF' &
import socket, sys

port, result_path = int(sys.argv[1]), sys.argv[2]
server = socket.socket()
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind(("0.0.0.0", port))
server.listen(4)
server.settimeout(3)
valid = b""
try:
    conn, _ = server.accept()
    conn.settimeout(2)
    while b"PLAY" not in valid:
        chunk = conn.recv(4096)
        if not chunk:
            break
        valid += chunk
    conn.close()
except OSError:
    pass

server.settimeout(2)
invalid_payload = b""
try:
    conn, _ = server.accept()
    conn.settimeout(1)
    try:
        invalid_payload = conn.recv(4096)
    except OSError:
        pass
    conn.close()
except OSError:
    pass
server.close()
with open(result_path, "w", encoding="ascii") as handle:
    handle.write(f"{valid.hex()}\n{invalid_payload.hex()}\n")
PYEOF
    server_pid=$!
    sleep 0.15

    if ! ip netns exec "$_NS" python3 - "$_HOST_IP" "$port" <<'PYEOF'
import socket, sys, time

s = socket.create_connection((sys.argv[1], int(sys.argv[2])), timeout=2)
s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
s.sendall(b"\x0f\x00\x2f\x09localhost\x63\xdd\x02")
time.sleep(0.1)
s.sendall(b"\x06\x00\x04Test")
time.sleep(0.1)
s.sendall(b"PLAY")
time.sleep(0.1)
s.close()
PYEOF
    then
        kill "$server_pid" 2>/dev/null || true
        wait "$server_pid" 2>/dev/null || true
        return 1
    fi

    if ! ip netns exec "$_NS" python3 - "$_HOST_IP" "$port" <<'PYEOF'
import socket, sys, time

s = socket.create_connection((sys.argv[1], int(sys.argv[2])), timeout=2)
s.sendall(b"GET / HTTP/1.1\r\n\r\n")
time.sleep(0.1)
s.close()
PYEOF
    then
        kill "$server_pid" 2>/dev/null || true
        wait "$server_pid" 2>/dev/null || true
        return 1
    fi

    wait "$server_pid" || return 1
    python3 - "$result_file" <<'PYEOF' || return 1
import sys

lines = open(sys.argv[1], encoding="ascii").read().splitlines()
payload = bytes.fromhex(lines[0])
expected = b"\x0f\x00\x2f\x09localhost\x63\xdd\x02\x06\x00\x04TestPLAY"
if payload != expected:
    raise SystemExit(f"valid Minecraft flow mismatch: {payload!r}")
if lines[1]:
    raise SystemExit("non-Minecraft payload reached the protected listener")
PYEOF
    rm -f "$handler_obj" "$result_file"
}

test_reload() {
    local map_id

    xdp_maps_ready || { echo "xdp_maps_ready failed with full map set"; return 1; }

    map_id=$(bpftool -j map show pinned "$_PIN_DIR/tcp_whitelist" \
        | python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])') || {
        echo "failed to resolve tcp_whitelist map id"; return 1;
    }

    rm "$_PIN_DIR/tcp_whitelist"
    xdp_maps_ready && { echo "xdp_maps_ready should detect missing tcp_whitelist"; return 1; }

    # Removing a pin does not destroy a map still referenced by the attached
    # program. Re-pin that exact map; loading a second program with pinmaps
    # would collide with every map name that remains in this directory.
    bpftool map pin id "$map_id" "$_PIN_DIR/tcp_whitelist" >/dev/null || {
        echo "failed to re-pin tcp_whitelist map id $map_id"; return 1;
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

_map_has_key() {
    local map_path="$1"
    shift
    bpftool map lookup pinned "$map_path" key hex "$@" >/dev/null 2>&1
}

_configure_exhausted_tcp_rate() {
    local port="$1" rate_max="$2"
    local policy_hex now_ns rate_val_hex outer_error
    local inner_pin="$_PIN_DIR/it_syn4_$port"

    policy_hex=$(python3 -c "
import struct
print(' '.join(f'{b:02x}' for b in struct.pack('<IIIIIIII', $rate_max, 0, 0, 32, 128, 0, 0, 0)))
")
    bpftool map update pinned "$_PIN_DIR/tcp_port_policies" \
        key hex $(_u32le "$port") value hex $policy_hex >/dev/null 2>&1 || {
        echo "tcp policy update failed"; return 1;
    }

    now_ns=$(_ktime_ns)
    rate_val_hex=$(python3 -c "
import struct
tick = ($now_ns // 1_000_000) & 0xffffffff
state = (tick << 32) | $rate_max
print(' '.join(f'{b:02x}' for b in struct.pack('<Q', state)))
")
    bpftool map create "$inner_pin" type lru_hash key 4 value 8 \
        entries 16384 name "s4_$port" flags 0 >/dev/null 2>&1 || {
        echo "inner map create failed"; return 1;
    }
    outer_error=$(bpftool map update pinned "$_PIN_DIR/syn4" \
        key hex $(_u32le "$port") value pinned "$inner_pin" 2>&1) || {
        echo "rate outer map update failed: $outer_error"; return 1;
    }
    bpftool map update pinned "$inner_pin" \
        key hex $(_ip4be "$_NS_IP") value hex $rate_val_hex >/dev/null 2>&1 || {
        echo "rate inner map update failed"; return 1;
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

    # Source ACLs constrain/bypass mitigation but never create exposure.
    bpftool map update pinned "$_PIN_DIR/tcp_whitelist" \
        key hex $(_u32le "$port") value hex 00 00 00 00 >/dev/null 2>&1
    _tcp_probe "$port" && { echo "ACL widened a closed port"; return 1; }

    bpftool map update pinned "$_PIN_DIR/tcp_whitelist" \
        key hex $(_u32le "$port") value hex 01 00 00 00 >/dev/null 2>&1
    _configure_exhausted_tcp_rate "$port" 1 || return 1
    _tcp_probe "$port" || { echo "ACL did not bypass mitigation on an exposed port"; return 1; }
}

test_rate_limit() {
    local port=7703 rate_max=2

    # Enable port in whitelist so the packet reaches the rate-limit check.
    bpftool map update pinned "$_PIN_DIR/tcp_whitelist" \
        key hex $(_u32le "$port") value hex 01 00 00 00 >/dev/null 2>&1

    _configure_exhausted_tcp_rate "$port" "$rate_max" || return 1

    local probe_rc=0
    _tcp_probe "$port" && probe_rc=1
    [ "$probe_rc" -eq 1 ] && { echo "rate-limited SYN was not dropped"; return 1; }
    return 0
}

test_service_restart() {
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
