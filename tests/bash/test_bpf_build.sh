#!/usr/bin/env bash
# auto-xdp-test-suite: build

set -euo pipefail

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]:-}")/../.." && pwd)
cd "$REPO_ROOT"
# shellcheck source=tests/bash/diagnostics.sh
source "$REPO_ROOT/tests/bash/diagnostics.sh"
enable_test_error_diagnostics

if ! command -v clang >/dev/null 2>&1 || ! command -v bpftool >/dev/null 2>&1; then
    echo "[WARNING] SKIP clang or bpftool missing"
    exit 0
fi

source "$REPO_ROOT/setup_xdp.sh"

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
    echo "[ERROR] compile_xdp_program failed" >&2
    exit 1
fi
if [[ $sock_status -ne 0 ]]; then
    echo "[ERROR] compile_sock_state_program failed" >&2
    exit 1
fi

XDP_OBJ_INSTALLED="$BUILD_STAGING_DIR/$XDP_OBJ"
TC_OBJ_INSTALLED="$BUILD_STAGING_DIR/$TC_OBJ"
[[ -s "$XDP_OBJ_INSTALLED" ]] || {
    echo "[ERROR] missing staged XDP object: $XDP_OBJ_INSTALLED" >&2
    exit 1
}

[[ -s "$BUILD_STAGING_DIR/$TC_OBJ" ]] || {
    echo "[ERROR] missing staged tc object: $BUILD_STAGING_DIR/$TC_OBJ" >&2
    exit 1
}

[[ -s "$BUILD_STAGING_DIR/xdp_map_abi.txt" ]] || {
    echo "[ERROR] missing staged XDP map ABI manifest" >&2
    exit 1
}

[[ -s "$BUILD_STAGING_DIR/$SOCK_STATE_OBJ" ]] || {
    echo "[ERROR] missing staged sock_state object: $BUILD_STAGING_DIR/$SOCK_STATE_OBJ" >&2
    exit 1
}

resolve_bpf_build_env || {
    echo "[ERROR] failed to resolve native BPF build environment" >&2
    exit 1
}

shopt -s nullglob
handler_objs=("$BUILD_STAGING_DIR"/handlers/*_handler.o)
[[ ${#handler_objs[@]} -gt 0 ]] || {
    echo "[ERROR] no staged handler objects under $BUILD_STAGING_DIR/handlers" >&2
    exit 1
}
for src in "$REPO_ROOT"/handlers/*_handler.c; do
    handler_obj="$BUILD_STAGING_DIR/handlers/$(basename "${src%.c}").o"
    [[ -s "$handler_obj" ]] || {
        echo "[ERROR] missing compiled handler object: $handler_obj" >&2
        exit 1
    }
done

echo "[INFO] native distro build succeeded"
