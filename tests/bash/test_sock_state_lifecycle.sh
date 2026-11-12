#!/usr/bin/env bash
# auto-xdp-test-suite: kernel
# Exercise listener events from the real tracepoint program and ring buffer.

set -euo pipefail
REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
# shellcheck source=tests/bash/diagnostics.sh
source "$REPO_ROOT/tests/bash/diagnostics.sh"
enable_test_error_diagnostics

kernel_unavailable() {
    if [[ "${REQUIRE_KERNEL_TESTS:-0}" == 1 ]]; then
        printf '[ERROR] listener kernel tests required: %s\n' "$*" >&2
        exit 1
    fi
    printf '[WARNING] SKIP listener kernel tests: %s\n' "$*"
    exit 0
}

[[ $(uname -s) == Linux && $EUID -eq 0 ]] || kernel_unavailable "Linux root required"
for command_name in clang bpftool ip python3 unshare mount; do
    command -v "$command_name" >/dev/null || kernel_unavailable "$command_name not found"
done

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    exec unshare --mount --net --propagation private bash -euc '
        mount -t sysfs sysfs /sys
        mount -t bpf bpf /sys/fs/bpf
        mkdir -p /sys/kernel/tracing
        mount -t tracefs tracefs /sys/kernel/tracing
        source "$1"
    ' bash "$REPO_ROOT/tests/bash/test_sock_state_lifecycle.sh"
fi

WORK_DIR=$(mktemp -d /tmp/axdp-sock-state.XXXXXX)
PIN_DIR="/sys/fs/bpf/axdp_sock_state_$$"
trap 'rm -rf "$PIN_DIR" "$WORK_DIR"' EXIT
mkdir "$PIN_DIR"
ip link set lo up

include_args=(-I "$REPO_ROOT/bpf/include")
multiarch_include="/usr/include/$(uname -m)-linux-gnu"
[[ ! -d "$multiarch_include" ]] || include_args+=(-I "$multiarch_include")
clang -O3 -g -target bpf -mcpu=v3 -fno-stack-protector "${include_args[@]}" \
    -c "$REPO_ROOT/bpf/sock_state_track.c" -o "$WORK_DIR/sock_state.o"
bpftool prog load "$WORK_DIR/sock_state.o" "$PIN_DIR/prog" \
    type tracepoint pinmaps "$PIN_DIR"
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH="$REPO_ROOT${PYTHONPATH:+:$PYTHONPATH}" \
    python3 "$REPO_ROOT/tests/python/kernel_sock_state.py" "$PIN_DIR"
