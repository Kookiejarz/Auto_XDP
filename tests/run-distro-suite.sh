#!/usr/bin/env bash

set -euo pipefail

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$REPO_ROOT"

export PYTHONDONTWRITEBYTECODE=1

bash -n ./setup_xdp.sh
bash -n ./axdp

python3 - <<'PY'
import ast
from pathlib import Path

for path in (Path("xdp_port_sync.py"), Path("auto_xdp_bpf_helpers.py")):
    ast.parse(path.read_text(), filename=str(path))
PY

bash ./tests/bash/test_setup_xdp.sh
bash ./tests/bash/test_axdp.sh
python3 -m unittest discover -s tests/python -v

if [[ "$(uname -s)" == "Linux" ]]; then
    bash ./setup_xdp.sh --check-env | tee /tmp/setup_xdp_check_env.log
    grep -q '^distro_id=' /tmp/setup_xdp_check_env.log
    grep -q '^package_manager=' /tmp/setup_xdp_check_env.log
    grep -q '^init_system=' /tmp/setup_xdp_check_env.log

    bash ./setup_xdp.sh --dry-run | tee /tmp/setup_xdp_dry_run.log
    grep -q '^mode=dry-run$' /tmp/setup_xdp_dry_run.log
    grep -q '^package_manager=' /tmp/setup_xdp_dry_run.log
    grep -q '^planned_actions=' /tmp/setup_xdp_dry_run.log
    grep -q '^planned_packages=' /tmp/setup_xdp_dry_run.log
else
    echo "skip: installer smoke checks require Linux"
fi

bash ./setup_xdp.sh --help >/dev/null
bash ./axdp help >/dev/null
python3 ./xdp_port_sync.py --help >/dev/null
python3 ./auto_xdp_bpf_helpers.py --help >/dev/null
