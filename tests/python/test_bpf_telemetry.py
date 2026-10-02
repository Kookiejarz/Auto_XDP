"""Production telemetry ABI, shared-map loading and native helper contracts."""
from pathlib import Path
import json
import re
import shutil
import subprocess
import sys
from unittest import mock

import pytest

from auto_xdp.telemetry.events import COUNTERS


ROOT = Path(__file__).resolve().parents[2]


def test_python_catalogue_matches_every_kernel_counter_id() -> None:
    header = (ROOT / "bpf/include/counters.h").read_text()
    entries = {name: int(value) for name, value in re.findall(r"CNT_(\w+)\s*=\s*(\d+)", header)}
    assert entries.pop("MAX") == len(COUNTERS)
    assert entries == {row[0]: index for index, row in enumerate(COUNTERS)}


def test_counter_abi_manifest_is_generated_from_current_headers(tmp_path: Path) -> None:
    subprocess.run(
        ["bash", "-c", 'source "$1"; BUILD_STAGING_DIR="$2"; generate_xdp_map_abi "$3"',
         "telemetry-test", str(ROOT / "lib/setup/build.sh"), str(tmp_path), str(ROOT)],
        check=True, capture_output=True, text=True,
    )
    assert (tmp_path / "xdp_map_abi.txt").read_text() == (
        ROOT / "auto_xdp/xdp_map_abi.txt"
    ).read_text()






@pytest.mark.skipif(sys.platform != "linux", reason="production BPF headers require Linux")
def test_native_event_helpers(tmp_path: Path) -> None:
    compiler = shutil.which("clang") or shutil.which("cc")
    if compiler is None or not Path("/usr/include/bpf/bpf_helpers.h").exists():
        pytest.skip("native C compiler and libbpf development headers required")
    binary = tmp_path / "telemetry-contract"
    subprocess.run(
        [compiler, "-O2", "-Wall", "-Werror", f"-I{ROOT}",
         str(ROOT / "tests/c/telemetry_contract.c"), "-o", str(binary)],
        check=True, capture_output=True, text=True,
    )
    subprocess.run([str(binary)], check=True, capture_output=True, text=True)

def test_cookie_telemetry_uses_the_main_pinned_maps() -> None:
    runtime = (ROOT / "runtime/auto_xdp_runtime_common.sh").read_text()
    xdp = runtime.split('bpftool prog load "$xdp_obj"', 1)[1].split(
        ">/dev/null 2>&1", 1
    )[0]
    tc = runtime.split('bpftool prog load "$tc_obj"', 1)[1].split(
        ">/dev/null 2>&1", 1
    )[0]
    for name in ("pkt_counters", "byte_counters", "pkt_ringbuf", "xdp_runtime_cfg"):
        assert f'map name {name} pinned "${{BPF_PIN_DIR}}/{name}"' in xdp
    assert 'map name pkt_counters pinned "${BPF_PIN_DIR}/pkt_counters"' in tc
