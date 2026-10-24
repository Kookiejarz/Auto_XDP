"""Custom port handlers share only the public maps they declare."""
import ctypes
import shutil
import subprocess
import sys
from pathlib import Path
from unittest import mock

import pytest

from auto_xdp.admin import cli, handlers


pytestmark = pytest.mark.component
CONTEXT_ABI = handlers.HandlerMapAbi(6, 4, 44, 1, 0)


@pytest.fixture
def port_handler(tmp_path: Path):
    pins = tmp_path / "bpf"
    pins.mkdir()
    (pins / "udp_port_handlers").touch()
    live = pins / "port_handlers" / "udp" / "30120"
    live.mkdir(parents=True)
    (live / "prog").write_text("old-program")
    obj = tmp_path / "fivem.o"
    obj.touch()
    config = tmp_path / "config.toml"
    config.write_text("[port_handlers.udp]\n")
    args = [
        "--config", str(config), "--bpf-pin-dir", str(pins),
        "port-handler", "load", "udp", "30120", str(obj),
    ]
    return pins, live, obj, config, args


@pytest.mark.parametrize("shared", [(), ("slot_ctx_map",), ("hblk4",),
                                    ("pkt_counters", "pkt_ringbuf", "xdp_runtime_cfg")])
def test_port_load_reuses_only_declared_public_maps(port_handler, shared):
    pins, _, obj, config, args = port_handler
    for name in shared:
        (pins / name).touch()
    with mock.patch.object(handlers, "handler_object_maps",
                           return_value={name: CONTEXT_ABI for name in
                                         ("rate_limit_map", "packet_count_map", *shared)}), \
         mock.patch.object(handlers, "pinned_handler_map_abi", return_value=CONTEXT_ABI), \
         mock.patch.object(handlers, "run_checked") as run, \
         mock.patch.object(handlers, "transactional_dir_prog_swap") as swap, \
         mock.patch.object(handlers, "flush_udp_validated_for_port") as flush:
        assert cli.main(args) == 0
    command = run.call_args.args[0]
    bindings = [command[i + 2] for i, value in enumerate(command) if value == "map"]
    assert set(bindings) == set(shared)
    for name in shared:
        assert str(pins / name) in command
    assert "rate_limit_map" not in bindings
    assert "packet_count_map" not in bindings
    swap.assert_called_once()
    flush.assert_called_once_with(pins, 30120)
    assert str(obj) in config.read_text()


@pytest.mark.parametrize("failure", ["missing-pin", "incompatible-map", "invalid-object", "load-failure"])
def test_failed_candidate_preserves_active_handler_config_and_validation(port_handler, failure):
    pins, live, _, config, args = port_handler
    original_config = config.read_bytes()
    inspect_error = RuntimeError("Cannot inspect handler object") if failure == "invalid-object" else None
    if failure in {"incompatible-map", "load-failure"}:
        (pins / "slot_ctx_map").touch()
    actual = CONTEXT_ABI._replace(value_size=48) if failure == "incompatible-map" else CONTEXT_ABI
    with mock.patch.object(handlers, "handler_object_maps", return_value={"slot_ctx_map": CONTEXT_ABI},
                           side_effect=inspect_error), \
         mock.patch.object(handlers, "pinned_handler_map_abi", return_value=actual), \
         mock.patch.object(handlers, "run_checked",
                           side_effect=RuntimeError("kernel rejected candidate")) as run, \
         mock.patch.object(handlers, "transactional_dir_prog_swap") as swap, \
         mock.patch.object(handlers, "flush_udp_validated_for_port") as flush:
        assert cli.main(args) == 1
    if failure == "load-failure":
        run.assert_called_once()
    else:
        run.assert_not_called()
    swap.assert_not_called()
    flush.assert_not_called()
    assert (live / "prog").read_text() == "old-program"
    assert config.read_bytes() == original_config
    assert not list(live.parent.glob("30120_next_*"))


def test_inspection_does_not_create_kernel_objects_and_closes_libbpf_object():
    lib = mock.Mock()
    lib.bpf_object__open_file.return_value = 100
    lib.libbpf_get_error.return_value = 0
    lib.bpf_object__next_map.side_effect = [200, 300, None]
    lib.bpf_map__name.side_effect = [b"slot_ctx_map", b"private_rate"]
    for field, value in zip(("type", "key_size", "value_size", "max_entries", "map_flags"), CONTEXT_ABI):
        getattr(lib, f"bpf_map__{field}").return_value = value
    with mock.patch.object(ctypes, "CDLL", return_value=lib):
        assert handlers.handler_object_maps(Path("handler.o")) == {
            "slot_ctx_map": CONTEXT_ABI, "private_rate": CONTEXT_ABI,
        }
    lib.bpf_object__close.assert_called_once_with(100)
    lib.bpf_object__load.assert_not_called()


@pytest.mark.parametrize("obj, error", [(None, 0), (None, -22), (123, -22)])
def test_inspection_rejects_null_and_legacy_error_pointers(obj, error):
    lib = mock.Mock()
    lib.bpf_object__open_file.return_value = obj
    lib.libbpf_get_error.return_value = error
    with mock.patch.object(ctypes, "CDLL", return_value=lib), \
         pytest.raises(RuntimeError, match="Cannot inspect handler object"):
        handlers.handler_object_maps(Path("invalid.o"))
    lib.bpf_object__next_map.assert_not_called()
    lib.bpf_object__close.assert_not_called()


@pytest.mark.parametrize("field", handlers.HandlerMapAbi._fields)
def test_shared_map_rejects_each_incompatible_abi_field(tmp_path: Path, field: str):
    (tmp_path / "slot_ctx_map").touch()
    actual = CONTEXT_ABI._replace(**{field: getattr(CONTEXT_ABI, field) + 1})
    with mock.patch.object(handlers, "handler_object_maps", return_value={"slot_ctx_map": CONTEXT_ABI}), \
         mock.patch.object(handlers, "pinned_handler_map_abi", return_value=actual), \
         pytest.raises(RuntimeError, match="Incompatible shared map slot_ctx_map"):
        handlers.port_handler_shared_maps(tmp_path / "handler.o", tmp_path)


def test_failed_pinned_map_inspection_closes_fd():
    with mock.patch.object(handlers, "obj_get", return_value=42), \
         mock.patch.object(handlers, "bpf", side_effect=PermissionError("map info denied")), \
         mock.patch.object(handlers.os, "close") as close, \
         pytest.raises(RuntimeError, match="Cannot inspect pinned handler map"):
        handlers.pinned_handler_map_abi(Path("slot_ctx_map"))
    close.assert_called_once_with(42)


@pytest.mark.skipif(sys.platform != "linux", reason="libbpf object parsing requires Linux")
@pytest.mark.parametrize("with_map", [False, True])
def test_inspect_real_bpf_object_without_root(tmp_path: Path, with_map: bool):
    compiler = shutil.which("clang")
    if compiler is None:
        pytest.skip("clang with BPF target required")
    source = tmp_path / "handler.c"
    obj = source.with_suffix(".o")
    source.write_text(("""
struct {
    int (*type)[2];
    int (*max_entries)[1];
    unsigned int *key;
    unsigned long long *value;
} private_rate __attribute__((section(".maps"), used));
""" if with_map else "") + """
__attribute__((section("xdp"), used)) int handler(void *ctx) { return 2; }
char _license[] __attribute__((section("license"), used)) = "MIT";
""")
    subprocess.run([compiler, "-target", "bpf", "-O2", "-g", "-c", str(source), "-o", str(obj)],
                   check=True, capture_output=True, text=True)
    assert handlers.handler_object_maps(obj) == (
        {"private_rate": handlers.HandlerMapAbi(2, 4, 8, 1, 0)} if with_map else {}
    )
