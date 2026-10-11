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


def test_runtime_builtin_slot_telemetry_map_binding(tmp_path: Path) -> None:
    runtime = (ROOT / "runtime/auto_xdp_runtime_common.sh").read_text()
    script = runtime.split("load_slot_handlers() {", 1)[1].split(
        "<<'PYEOF'\n", 1
    )[1].split("\nPYEOF", 1)[0]
    maps = ("slot_ctx_map", "pkt_counters", "byte_counters", "pkt_ringbuf", "xdp_runtime_cfg")
    for name in (*maps, "gre_handler.o"):
        (tmp_path / name).touch()
    entries = ["gre", {"proto": 47, "path": str(tmp_path / "gre_handler.o")}]
    commands: list[list[str]] = []

    def run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        commands.append(command)
        return subprocess.CompletedProcess(command, 0, "", "")

    argv = ["slot-test", json.dumps(entries), str(tmp_path), str(tmp_path), str(tmp_path), "1"]
    with mock.patch.object(sys, "argv", argv), mock.patch("subprocess.run", run):
        exec(compile(script, "runtime-slot-loader", "exec"), {})
    builtin, custom = [command for command in commands if command[1:3] == ["prog", "load"]]
    for name in maps:
        assert str(tmp_path / name) in builtin
    for name in maps[1:]:
        assert str(tmp_path / name) not in custom


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


@pytest.mark.skipif(sys.platform != "linux", reason="production BPF headers require Linux")
def test_native_endpoint_scope_helpers(tmp_path: Path) -> None:
    compiler = shutil.which("clang") or shutil.which("cc")
    if compiler is None or not Path("/usr/include/bpf/bpf_helpers.h").exists():
        pytest.skip("native C compiler and libbpf development headers required")
    binary = tmp_path / "endpoint-scope-contract"
    subprocess.run(
        [compiler, "-O2", "-Wall", "-Werror", "-Wno-unknown-attributes", f"-I{ROOT}",
         str(ROOT / "tests/c/endpoint_scope_contract.c"), "-o", str(binary)],
        check=True, capture_output=True, text=True,
    )
    subprocess.run([str(binary)], check=True, capture_output=True, text=True)
