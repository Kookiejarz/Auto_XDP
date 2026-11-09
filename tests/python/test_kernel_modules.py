"""Kernel dependencies must be ready before any BPF generation is published."""
import json
import struct
import subprocess
from pathlib import Path

import pytest

from auto_xdp.admin import kernel_modules, handlers, module_runtime


def dependency_object(path: Path, names) -> Path:
    strings = b"\0.shstrtab\0.axdp_kmods\0"
    payload = json.dumps(names).encode() + b"\0"
    data = bytearray(256)
    data[:6] = b"\x7fELF\x02\x01"
    struct.pack_into("<Q", data, 40, 64)
    struct.pack_into("<HHH", data, 58, 64, 3, 1)
    struct.pack_into("<IIQQQQ", data, 128, 1, 3, 0, 0, len(data), len(strings))
    struct.pack_into("<IIQQQQ", data, 192, 11, 1, 0, 0, len(data) + len(strings), len(payload))
    path.write_bytes(data + strings + payload)
    return path


@pytest.mark.parametrize("names", [["../bad"], ["--remove"], ["a", "a"], [False], {}, ["x"] * 9])
def test_invalid_dependency_metadata_never_runs_a_command(tmp_path, monkeypatch, names):
    monkeypatch.setattr(kernel_modules, "_run", lambda *args, **kwargs: pytest.fail("executed malformed dependency"))
    with pytest.raises(RuntimeError, match="Invalid kernel dependencies"):
        kernel_modules.ensure(dependency_object(tmp_path / "bad.o", names))


def test_missing_bundled_dependency_builds_then_loads(tmp_path, monkeypatch):
    events = []
    def run(command, **kwargs):
        events.append(command)
        success = command == ["modprobe", "axdp_icmp"] and ["build", "axdp_icmp"] in events
        return subprocess.CompletedProcess(command, 0 if success else 1, "", "module missing")
    monkeypatch.setattr(kernel_modules, "_run", run)
    monkeypatch.setattr(kernel_modules, "_build_install", lambda name: events.append(["build", name]))
    kernel_modules.ensure(dependency_object(tmp_path / "icmp.o", ["axdp_icmp"]))
    assert events == [["modprobe", "axdp_icmp"], ["modinfo", "-n", "axdp_icmp"],
                      ["build", "axdp_icmp"], ["modprobe", "axdp_icmp"]]


def test_existing_module_load_error_is_preserved_without_rebuild(tmp_path, monkeypatch):
    monkeypatch.setattr(kernel_modules, "_build_install", lambda name: pytest.fail("must not rebuild a signature failure"))
    monkeypatch.setattr(kernel_modules, "_run", lambda cmd, **kw: subprocess.CompletedProcess(
        cmd, int(cmd[0] == "modprobe"), "/lib/modules/test/axdp_icmp.ko", "Key was rejected by service"))
    with pytest.raises(RuntimeError, match="Key was rejected"):
        kernel_modules.ensure(dependency_object(tmp_path / "icmp.o", ["axdp_icmp"]))


def test_automatic_build_uses_installed_sdk_and_running_kernel(tmp_path, monkeypatch):
    kernel = kernel_modules.os.uname().release
    build_dir = tmp_path / "modules" / kernel / "build"
    build_dir.mkdir(parents=True)
    (build_dir / "Makefile").touch()
    sdk = tmp_path / "release/handlers"
    sdk.mkdir(parents=True)
    for name in ("axdp_icmp.c", "Kbuild", "Makefile.kmod"):
        (sdk / name).write_text(name)
    header = sdk.parent / "bpf/include/icmp_ct_tuple.h"
    header.parent.mkdir(parents=True)
    header.write_text("shared tuple")
    monkeypatch.setattr(kernel_modules, "KERNEL_MODULES_DIR", tmp_path / "modules")
    monkeypatch.setattr(kernel_modules, "BUILD_LOCK", tmp_path / "run/module.lock")
    monkeypatch.setattr(kernel_modules, "sdk_directory", lambda: sdk)
    built = []
    def run(command, *, cwd=None, **kwargs):
        if command[0] == "modprobe":
            return subprocess.CompletedProcess(command, 1, "", "not found")
        assert command == ["make", "-f", "Makefile.kmod", f"KVER={kernel}", f"KDIR={build_dir}", "install"]
        assert cwd != sdk
        assert (cwd / "icmp_ct_tuple.h").read_text() == "shared tuple"
        assert (cwd / "axdp_icmp.c").read_text() == "axdp_icmp.c"
        built.append(cwd)
        return subprocess.CompletedProcess(command, 0, "", "")
    monkeypatch.setattr(kernel_modules, "_run", run)
    kernel_modules._build_install("axdp_icmp")
    assert len(built) == 1 and not built[0].exists()
    assert sorted(path.name for path in sdk.iterdir()) == ["Kbuild", "Makefile.kmod", "axdp_icmp.c"]


@pytest.fixture
def icmp_generation(tmp_path, monkeypatch):
    root = tmp_path / "pins"
    live = root / "modules/icmp"
    live.mkdir(parents=True)
    (live / "prog").write_text("11")
    (root / "proto_handlers").touch()
    obj = dependency_object(tmp_path / "icmp.o", ["axdp_icmp"])
    state, events = {1: 11, 58: 11}, []
    monkeypatch.setattr(handlers, "pinned_program_id", lambda pin: int(pin.read_text()))
    monkeypatch.setattr(handlers, "_pinned_u32_lookup", lambda table, key: state[struct.unpack("=I", key)[0]])
    def update(table, key, pin):
        state[key] = int(pin.read_text())
        events.append((key, state[key]))
    monkeypatch.setattr(handlers, "prog_array_update", update)
    monkeypatch.setattr(handlers, "prog_array_delete", lambda table, key: state.update({key: None}) or True)
    monkeypatch.setattr(handlers, "handler_object_programs", lambda *args, **kwargs: ("entry", None))
    monkeypatch.setattr(handlers, "handler_shared_maps", lambda *args: [])
    def load(command, *args, **kwargs):
        events.append(("load", command[3]))
        Path(command[4]).write_text("21")
    monkeypatch.setattr(handlers, "run_checked", load)
    def dependency(command, **kwargs):
        events.append(("dependency", command[1]))
        return subprocess.CompletedProcess(command, 0, "", "")
    monkeypatch.setattr(kernel_modules, "_run", dependency)
    return root, obj, state, events


def test_dependency_precedes_load_and_both_family_bindings(icmp_generation):
    root, obj, state, events = icmp_generation
    module_runtime.load_icmp(root, obj)
    assert [event[0] for event in events] == ["dependency", "load", 58, 1]
    assert state == {1: 21, 58: 21}
    assert (root / "modules/icmp/prog").read_text() == "21"


def test_dependency_failure_preserves_both_active_families(icmp_generation, monkeypatch):
    root, obj, state, events = icmp_generation
    monkeypatch.setattr(kernel_modules, "_run", lambda cmd, **kw: subprocess.CompletedProcess(
        cmd, int(cmd[0] == "modprobe"), "existing.ko", "load rejected"))
    with pytest.raises(RuntimeError, match="load rejected"):
        module_runtime.load_icmp(root, obj)
    assert state == {1: 11, 58: 11} and events == []
    assert (root / "modules/icmp/prog").read_text() == "11"
    assert not list((root / "modules").glob("icmp_next_*"))


def test_second_family_publish_failure_rolls_back_both(icmp_generation, monkeypatch):
    root, obj, state, _ = icmp_generation
    original = handlers.prog_array_update
    def fail_once(table, key, pin):
        if key == 1 and pin.read_text() == "21":
            raise RuntimeError("IPv4 publish failed")
        original(table, key, pin)
    monkeypatch.setattr(handlers, "prog_array_update", fail_once)
    with pytest.raises(RuntimeError, match="IPv4 publish failed"):
        module_runtime.load_icmp(root, obj)
    assert state == {1: 11, 58: 11}
    assert (root / "modules/icmp/prog").read_text() == "11"


@pytest.mark.parametrize("fail", [False, True])
def test_disable_clears_requirement_and_restores_it_on_failure(icmp_generation, monkeypatch, fail):
    root, _, state, _ = icmp_generation
    flags = [64 | 4]
    class Runtime:
        def __init__(self, path): pass
        def get_cfg_flags(self): return flags[0]
        def get(self): return {}
        def set(self, values, value): flags[0] = value; return True
        def close(self): pass
    monkeypatch.setattr(module_runtime, "BpfRuntimeConfigMap", Runtime)
    original = handlers.prog_array_delete
    def delete(table, key):
        assert not flags[0] & 64
        if fail and key == 58:
            raise RuntimeError("IPv6 removal failed")
        return original(table, key)
    monkeypatch.setattr(handlers, "prog_array_delete", delete)
    if fail:
        with pytest.raises(RuntimeError, match="IPv6 removal failed"):
            module_runtime.remove_icmp(root)
        assert state == {1: 11, 58: 11} and flags[0] == 68
    else:
        module_runtime.remove_icmp(root)
        assert state == {1: None, 58: None} and flags[0] == 4
        assert not (root / "modules/icmp").exists()


@pytest.mark.parametrize("drift", [False, True])
def test_reload_reuses_ready_handler_and_repairs_missing_binding(icmp_generation, monkeypatch, drift):
    root, obj, state, _ = icmp_generation
    monkeypatch.setattr(module_runtime, "obj_get", lambda path: 123)
    monkeypatch.setattr(module_runtime, "program_id", lambda fd: 11)
    monkeypatch.setattr(module_runtime.os, "close", lambda fd: None)
    monkeypatch.setattr(kernel_modules, "sdk_directory", lambda: obj.parent)
    loads = []
    monkeypatch.setattr(module_runtime, "load_icmp", lambda *args: loads.append(args))
    if drift:
        state[58] = None
    module_runtime.prepare_icmp(root, enabled=True)
    assert loads == ([(root, obj.parent / "icmp_handler.o")] if drift else [])


def test_disable_retains_bindings_if_runtime_values_cannot_be_read(icmp_generation, monkeypatch):
    from unittest.mock import Mock
    root, _, state, events = icmp_generation
    runtime = Mock()
    runtime.get_cfg_flags.return_value = 64
    runtime.get.return_value = None
    monkeypatch.setattr(module_runtime, "BpfRuntimeConfigMap", lambda path: runtime)
    with pytest.raises(RuntimeError, match="Cannot read ICMP runtime state"):
        module_runtime.remove_icmp(root)
    runtime.set.assert_not_called()
    runtime.close.assert_called_once()
    assert state == {1: 11, 58: 11} and events == []


def test_disabled_verification_rejects_leftover_gate(tmp_path, monkeypatch):
    (tmp_path / "xdp_runtime_cfg").touch()
    class Runtime:
        def __init__(self, path): pass
        def get_cfg_flags(self): return 64
        def close(self): pass
    monkeypatch.setattr(module_runtime, "BpfRuntimeConfigMap", Runtime)
    with pytest.raises(RuntimeError, match="runtime gate"):
        module_runtime.verify_icmp(tmp_path, enabled=False)


def test_config_reload_dependency_failure_does_not_publish_gate(tmp_path, monkeypatch):
    from unittest.mock import Mock
    from auto_xdp import config
    from auto_xdp.backends.xdp import XdpBackend
    from auto_xdp.state import BackendProjection, ReconcilePlan

    desired = BackendProjection(config=config.parse_toml_config({
        "modules": {"icmp": {"enabled": True}}, "bpf": {"pin_dir": str(tmp_path)},
    }))
    backend = XdpBackend.__new__(XdpBackend)
    backend.runtime_config_map = Mock()
    backend.runtime_config_map.get_cfg_flags.return_value = 0
    def fail(*args, **kwargs):
        raise RuntimeError("kernel dependency unavailable")
    monkeypatch.setattr(module_runtime, "prepare_icmp", fail)
    with pytest.raises(RuntimeError, match="dependency unavailable"):
        backend.apply_reconcile_plan(ReconcilePlan(), False, desired)
    backend.runtime_config_map.set.assert_not_called()
