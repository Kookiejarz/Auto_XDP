#!/usr/bin/env bash

set -euo pipefail

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]:-}")/../.." && pwd)
cd "$REPO_ROOT"

if ! command -v clang >/dev/null 2>&1 || ! command -v bpftool >/dev/null 2>&1; then
    echo "skip: clang or bpftool missing"
    exit 0
fi

source "$REPO_ROOT/setup_xdp.sh"
tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT

PREFER_REMOTE_SOURCES=0
CHECK_UPDATES=0

fetch_local_or_remote() {
    local local_path="$1"
    local target_path="$3"
    if [[ -f "$local_path" ]]; then
        mkdir -p "$(dirname "$target_path")"
        [[ "$local_path" == "$target_path" ]] || cp "$local_path" "$target_path"
    fi
    return 0
}

set +e
compile_xdp_program
status=$?
compile_sock_state_program
sock_status=$?
set -e
if [[ $status -ne 0 ]]; then
    echo "compile_xdp_program failed"
    exit 1
fi
if [[ $sock_status -ne 0 ]]; then
    echo "compile_sock_state_program failed"
    exit 1
fi

XDP_OBJ_INSTALLED="$BUILD_STAGING_DIR/$XDP_OBJ"
TC_OBJ_INSTALLED="$BUILD_STAGING_DIR/$TC_OBJ"
[[ -s "$XDP_OBJ_INSTALLED" ]] || {
    echo "missing compiled XDP object: $XDP_OBJ_INSTALLED"
    exit 1
}

[[ -s "$TC_OBJ_INSTALLED" ]] || {
    echo "missing compiled tc object: $TC_OBJ_INSTALLED"
    exit 1
}

[[ -s "$BUILD_STAGING_DIR/xdp_map_abi.txt" ]] || {
    echo "missing staged XDP map ABI manifest"
    exit 1
}

[[ -s "$BUILD_STAGING_DIR/$SOCK_STATE_OBJ" ]] || {
    echo "missing staged sock_state object: $BUILD_STAGING_DIR/$SOCK_STATE_OBJ"
    exit 1
}

resolve_bpf_build_env || {
    echo "failed to resolve native BPF build environment"
    exit 1
}

for handler_obj in \
    "$BUILD_STAGING_DIR/handlers/gre_handler.o" \
    "$BUILD_STAGING_DIR/handlers/esp_handler.o" \
    "$BUILD_STAGING_DIR/handlers/sctp_handler.o" \
    "$BUILD_STAGING_DIR/handlers/minecraft_handler.o"; do
    [[ -s "$handler_obj" ]] || {
        echo "missing compiled handler object: $handler_obj"
        exit 1
    }
done

echo "native distro build succeeded"
