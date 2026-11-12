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


@pytest.mark.component
def test_cookie_telemetry_uses_the_main_pinned_maps(tmp_path: Path) -> None:
    from auto_xdp.admin import handlers
    xdp, tc = tmp_path / "xdp.o", tmp_path / "tc.o"
    xdp.touch()
    tc.touch()
    names = ("pkt_counters", "byte_counters", "pkt_ringbuf", "xdp_runtime_cfg")
    abi = handlers.HandlerMapAbi(2, 4, 4, 1, 0)
    for name in names:
        (tmp_path / name).touch()
    def maps(obj):
        return {name: abi for name in (names if obj == xdp else ("pkt_counters",))}
    with mock.patch.object(handlers, "handler_object_programs", return_value=("entry", None)), \
         mock.patch.object(handlers, "handler_object_maps", side_effect=maps), \
         mock.patch.object(handlers, "pinned_handler_map_abi", return_value=abi), \
         mock.patch.object(handlers, "run_checked") as run, \
         mock.patch.object(handlers, "_transactional_handler_bindings"):
        handlers._load_handler_bundle(tmp_path / "syncookie_prog_array", 0,
                                      [("prog", xdp, "xdp"), ("ingress", tc, "classifier")],
                                      tmp_path / "modules/syncookie", [])
    for call, expected in zip(run.call_args_list, (names, ("pkt_counters",))):
        command = call.args[0]
        bindings = {command[i + 2]: command[i + 4] for i, value in enumerate(command) if value == "map"}
        assert bindings == {name: str(tmp_path / name) for name in expected}
    assert run.call_count == 2


def test_runtime_builtin_slot_telemetry_map_binding(tmp_path: Path) -> None:
    runtime = (ROOT / "runtime/auto_xdp_runtime_common.sh").read_text()
    script = runtime.split("load_slot_handlers() {", 1)[1].split(
        "<<'PYEOF'\n", 1
    )[1].split("\nPYEOF", 1)[0]
    maps = ("slot_ctx_map", "pkt_counters", "byte_counters", "pkt_ringbuf", "xdp_runtime_cfg")
    for name in (*maps, "gre_handler.o"):
        (tmp_path / name).touch()
    entries = ["gre", {"proto": 47, "path": str(tmp_path / "gre_handler.o")}]
    from auto_xdp.admin import handlers
    abi = handlers.HandlerMapAbi(2, 4, 4, 1, 0)
    argv = ["slot-test", json.dumps(entries), str(tmp_path), str(tmp_path), "1"]
    with mock.patch.object(sys, "argv", argv), \
         mock.patch.object(handlers, "handler_object_maps", return_value={name: abi for name in maps}), \
         mock.patch.object(handlers, "pinned_handler_map_abi", return_value=abi), \
         mock.patch.object(handlers, "_load_handler_object", return_value=False) as load:
        exec(compile(script, "runtime-slot-loader", "exec"), {})
    assert load.call_count == 2
    for call in load.call_args_list:
        assert call.args[:4] == (tmp_path / "proto_handlers", 47, tmp_path / "gre_handler.o",
                                tmp_path / "protocol_handlers/47")
        assert dict(call.args[4]) == {name: tmp_path / name for name in maps}


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
