#!/usr/bin/env bash

set -euo pipefail

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]:-}")/../.." && pwd)
cd "$REPO_ROOT"

if ! command -v clang >/dev/null 2>&1 || ! command -v bpftool >/dev/null 2>&1; then
    echo "skip: clang or bpftool missing"
    exit 0
fi

source "$REPO_ROOT/setup_xdp.sh"
set +e

tmpdir=$(mktemp -d)
INSTALL_DIR="$tmpdir/install"
XDP_OBJ_INSTALLED="$INSTALL_DIR/xdp_firewall.o"
TC_OBJ_INSTALLED="$INSTALL_DIR/tc_flow_track.o"
PREFER_REMOTE_SOURCES=0
CHECK_UPDATES=0

fetch_local_or_remote() {
    return 0
}

compile_xdp_program
status=$?
if [[ $status -ne 0 ]]; then
    echo "compile_xdp_program failed"
    exit 1
fi

[[ -s "$XDP_OBJ_INSTALLED" ]] || {
    echo "missing compiled XDP object: $XDP_OBJ_INSTALLED"
    exit 1
}

[[ -s "$TC_OBJ_INSTALLED" ]] || {
    echo "missing compiled tc object: $TC_OBJ_INSTALLED"
    exit 1
}

echo "bpf objects compiled successfully"
