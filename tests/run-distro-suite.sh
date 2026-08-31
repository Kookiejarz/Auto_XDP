#!/usr/bin/env bash

set -euo pipefail

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]:-}")/.." && pwd)
exec bash "$REPO_ROOT/tests/run.sh" distro
