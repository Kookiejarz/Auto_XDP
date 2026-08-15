#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]:-}")/../.." && pwd)
cd "$REPO_ROOT/handlers"

if ! command -v clang >/dev/null 2>&1; then
    echo "skip: clang missing"
    exit 0
fi

make gre_handler.o
test -s gre_handler.o
echo "ok - compiled current gre_handler.c"
