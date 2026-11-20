"""Kernel dependencies must be ready before any BPF generation is published."""
import json
import struct
import subprocess
from pathlib import Path

import pytest

from auto_xdp.admin import kernel_modules, handlers, module_runtime


@pytest.fixture(autouse=True)
def private_run_state(tmp_path, monkeypatch):
    # Markers, rebuild stamps, installed modules and loaded-module state are all
    # private: on a host with a real (possibly broken) axdp_icmp.ko the tests
    # must neither read it nor depend on it.
    monkeypatch.setenv("RUN_STATE_DIR", str(tmp_path / "run"))
    monkeypatch.setattr(kernel_modules, "BUILD_LOCK", tmp_path / "run/kernel-modules.lock")
    monkeypatch.setattr(kernel_modules, "KERNEL_MODULES_DIR", tmp_path / "modules")
    monkeypatch.setattr(kernel_modules, "SYS_MODULE_DIR", tmp_path / "sys/module")


def dependency_object(path: Path, names) -> Path:
    return elf_section(path, b".axdp_kmods", json.dumps(names).encode() + b"\0")


def elf_section(path: Path, name: bytes, payload: bytes) -> Path:
    strings = b"\0.shstrtab\0" + name + b"\0"
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
    monkeypatch.setattr(kernel_modules, "_build_install", lambda name, **kw: events.append(["build", name]))
    kernel_modules.ensure(dependency_object(tmp_path / "icmp.o", ["axdp_icmp"]))
    assert events == [["modprobe", "axdp_icmp"], ["modinfo", "-n", "axdp_icmp"],
                      ["build", "axdp_icmp"], ["modprobe", "axdp_icmp"]]


def test_existing_module_load_error_is_preserved_without_rebuild(tmp_path, monkeypatch):
    monkeypatch.setattr(kernel_modules, "_build_install", lambda name, **kw: pytest.fail("must not rebuild a signature failure"))
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


# `.BTF_ids` of axdp_icmp.ko as recorded on a 7.0 host: the build that skipped
# resolve_btfids (count 0, id 0) and the repaired one (count 1, BTF FUNC id).
UNRESOLVED_IDS = bytes.fromhex("00000000010000000000000000000000")
RESOLVED_IDS = bytes.fromhex("01000000010000004a9a020000000000")


@pytest.mark.parametrize("payload, expected", [
    (UNRESOLVED_IDS, True), (bytes(16), True), (RESOLVED_IDS, False), (None, False),
])
def test_unresolved_kfunc_ids_are_read_from_the_module(tmp_path, payload, expected):
    module = tmp_path / "axdp_icmp.ko"
    if payload is None:
        elf_section(module, b".other", b"data")
    else:
        elf_section(module, b".BTF_ids", payload)
    assert kernel_modules.kfunc_ids_unresolved(module) is expected
    assert not kernel_modules.kfunc_ids_unresolved(tmp_path / "missing.ko")


@pytest.fixture
def installed_module(tmp_path, monkeypatch):
    """A bundled module at its install path, with a fake SDK and build."""
    kernel = kernel_modules.os.uname().release
    module = tmp_path / "modules" / kernel / "extra/auto_xdp/axdp_icmp.ko"
    module.parent.mkdir(parents=True)
    sdk = tmp_path / "release/handlers"
    sdk.mkdir(parents=True)
    for name in ("axdp_icmp.c", "Kbuild", "Makefile.kmod"):
        (sdk / name).write_text(name)
    header = sdk.parent / "bpf/include/icmp_ct_tuple.h"
    header.parent.mkdir(parents=True)
    header.write_text("shared tuple")
    loaded = tmp_path / "sys/module/axdp_icmp"
    loaded.mkdir(parents=True)
    (loaded / "refcnt").write_text("0\n")  # loaded, no BPF program uses it
    monkeypatch.setattr(kernel_modules, "sdk_directory", lambda: sdk)
    events = []
    toolchain = ["pahole v1.25"]
    def run(command, **kwargs):
        if command == ["pahole", "--version"]:
            return subprocess.CompletedProcess(command, 0, toolchain[0], "")
        events.append(command)
        if command == ["modprobe", "-r", "axdp_icmp"]:
            (loaded / "refcnt").unlink()
            loaded.rmdir()
        return subprocess.CompletedProcess(command, 0, "", "")
    monkeypatch.setattr(kernel_modules, "_run", run)
    return module, sdk, events, tmp_path / "icmp.o"


def test_module_built_without_kfunc_ids_is_rebuilt_and_reloaded(installed_module, monkeypatch):
    module, _, events, obj = installed_module
    elf_section(module, b".BTF_ids", UNRESOLVED_IDS)
    def build(name):
        events.append(["build", name])
        elf_section(module, b".BTF_ids", RESOLVED_IDS)
    monkeypatch.setattr(kernel_modules, "_make_install", build)
    kernel_modules.ensure(dependency_object(obj, ["axdp_icmp"]))
    # The wrongly built module may be loaded: it is replaced before loading.
    assert events == [["build", "axdp_icmp"], ["modprobe", "-r", "axdp_icmp"], ["modprobe", "axdp_icmp"]]
    events.clear()
    kernel_modules.ensure(obj)
    assert events == [["modprobe", "axdp_icmp"]]


def test_rebuild_that_cannot_resolve_ids_is_reported_and_not_repeated(installed_module, monkeypatch):
    module, sdk, events, obj = installed_module
    elf_section(module, b".BTF_ids", UNRESOLVED_IDS)
    monkeypatch.setattr(kernel_modules, "_make_install", lambda name: events.append(["build", name]))
    dependency_object(obj, ["axdp_icmp"])
    with pytest.raises(RuntimeError, match=r"without resolved kfunc IDs.*did not help: upgrade Auto XDP"):
        kernel_modules.ensure(obj)
    with pytest.raises(RuntimeError, match="already rebuilt it without effect"):
        kernel_modules.ensure(obj)
    # One build per boot and SDK; the broken module is never loaded again.
    assert events == [["build", "axdp_icmp"]]
    # An upgraded SDK (for example a corrected Makefile.kmod) gets its own attempt.
    (sdk / "Makefile.kmod").write_text("corrected")
    with pytest.raises(RuntimeError, match="did not help"):
        kernel_modules.ensure(obj)
    assert events == [["build", "axdp_icmp"]] * 2


def test_failed_rebuild_is_retried_once_its_cause_is_fixed(installed_module, monkeypatch):
    module, _, events, obj = installed_module
    elf_section(module, b".BTF_ids", UNRESOLVED_IDS)
    dependency_object(obj, ["axdp_icmp"])
    def no_headers(name):
        raise RuntimeError("axdp_icmp needs development headers for running kernel")
    monkeypatch.setattr(kernel_modules, "_make_install", no_headers)
    with pytest.raises(RuntimeError, match="needs development headers"):
        kernel_modules.ensure(obj)
    assert events == []  # the broken module is not loaded instead
    # Installing the headers must be enough; no reboot or upgrade is required.
    monkeypatch.setattr(kernel_modules, "_make_install",
                        lambda name: elf_section(module, b".BTF_ids", RESOLVED_IDS))
    kernel_modules.ensure(obj)
    assert events == [["modprobe", "-r", "axdp_icmp"], ["modprobe", "axdp_icmp"]]


def test_replacement_build_ignores_the_loadable_broken_module(installed_module, monkeypatch):
    module, _, events, obj = installed_module
    kernel = kernel_modules.os.uname().release
    build_dir = module.parents[2] / "build"
    build_dir.mkdir()
    (build_dir / "Makefile").touch()
    elf_section(module, b".BTF_ids", UNRESOLVED_IDS)
    with pytest.raises(RuntimeError, match="did not help"):  # the fake make changes nothing
        kernel_modules.ensure(dependency_object(obj, ["axdp_icmp"]))
    # modprobe would succeed for the broken module, so it must not end the build.
    assert [command[0] for command in events] == ["make"]
    assert events[0][2:4] == ["Makefile.kmod", f"KVER={kernel}"]


def test_concurrent_loader_neither_rebuilds_nor_unloads_a_module_in_use(installed_module, monkeypatch):
    module, _, events, obj = installed_module
    elf_section(module, b".BTF_ids", UNRESOLVED_IDS)
    dependency_object(obj, ["axdp_icmp"])
    loaded = kernel_modules.SYS_MODULE_DIR / "axdp_icmp"
    original = kernel_modules._build_lock
    @kernel_modules.contextmanager
    def lock_after_other_loader():
        # While this loader waited for the lock, another one rebuilt, reloaded
        # and loaded a BPF program that now uses the module.
        elf_section(module, b".BTF_ids", RESOLVED_IDS)
        (loaded / "refcnt").write_text("1\n")
        with original():
            yield
    monkeypatch.setattr(kernel_modules, "_build_lock", lock_after_other_loader)
    monkeypatch.setattr(kernel_modules, "_make_install", lambda name: pytest.fail("rebuilt twice"))
    kernel_modules.ensure(obj)
    assert events == [["modprobe", "axdp_icmp"]] and loaded.exists()


def test_upgraded_toolchain_gets_another_rebuild_without_reboot(installed_module, monkeypatch):
    module, _, events, obj = installed_module
    elf_section(module, b".BTF_ids", UNRESOLVED_IDS)
    dependency_object(obj, ["axdp_icmp"])
    monkeypatch.setattr(kernel_modules, "_make_install", lambda name: events.append(["build", name]))
    for expected in ("did not help", "already rebuilt it without effect"):
        with pytest.raises(RuntimeError, match=expected):
            kernel_modules.ensure(obj)
    assert events == [["build", "axdp_icmp"]]
    # The error advises upgrading pahole/resolve_btfids: that alone permits a new attempt.
    pahole = kernel_modules._run(["pahole", "--version"])
    monkeypatch.setattr(kernel_modules, "_run", lambda command, **kw: subprocess.CompletedProcess(
        command, 0, "pahole v1.30", "") if command == ["pahole", "--version"] else (
            events.append(command) or subprocess.CompletedProcess(command, 0, "", "")))
    assert pahole.stdout == "pahole v1.25"
    monkeypatch.setattr(kernel_modules, "_make_install",
                        lambda name: events.append(["build", name]) or elf_section(module, b".BTF_ids", RESOLVED_IDS))
    kernel_modules.ensure(obj)
    assert events[1] == ["build", "axdp_icmp"] and events[-1] == ["modprobe", "axdp_icmp"]


def test_builds_disabled_never_builds(installed_module, monkeypatch):
    module, _, events, obj = installed_module
    dependency_object(obj, ["axdp_icmp"])
    monkeypatch.setattr(kernel_modules, "_make_install", lambda name: pytest.fail("built during a policy update"))
    elf_section(module, b".BTF_ids", UNRESOLVED_IDS)
    with kernel_modules.builds_disabled(), pytest.raises(kernel_modules.BuildRequired, match="must be rebuilt"):
        kernel_modules.ensure(obj)
    module.unlink()
    def missing(command, **kw):
        events.append(command)
        return subprocess.CompletedProcess(command, 1, "", "not found")
    monkeypatch.setattr(kernel_modules, "_run", missing)
    with kernel_modules.builds_disabled(), pytest.raises(kernel_modules.BuildRequired, match="is not installed"):
        kernel_modules.ensure(obj)
    assert ["make"] not in [command[:1] for command in events]


@pytest.mark.parametrize("refcnt, resolved, reloaded", [("0", True, True), ("1", True, False), ("0", False, False)])
def test_stale_loaded_module_is_reloaded_once_after_the_verifier_rejects_the_kfunc(
        installed_module, monkeypatch, refcnt, resolved, reloaded):
    module, _, events, obj = installed_module
    elf_section(module, b".BTF_ids", RESOLVED_IDS if resolved else UNRESOLVED_IDS)
    (kernel_modules.SYS_MODULE_DIR / "axdp_icmp/refcnt").write_text(refcnt)
    dependency_object(obj, ["axdp_icmp"])
    # The disk copy was repaired (manual `make install`, or a loader killed
    # before its unload) while the broken build stayed loaded.
    tokens = kernel_modules.reload_tokens(obj)
    assert kernel_modules.reload_stale(obj, tokens) is reloaded
    assert events == ([["modprobe", "-r", "axdp_icmp"], ["modprobe", "axdp_icmp"]] if reloaded else [])


def test_stale_reload_never_unloads_a_module_another_loader_just_reloaded(installed_module):
    module, _, events, obj = installed_module
    elf_section(module, b".BTF_ids", RESOLVED_IDS)
    dependency_object(obj, ["axdp_icmp"])
    loader_a = kernel_modules.reload_tokens(obj)  # A reads its token, then its load fails
    loader_b = kernel_modules.reload_tokens(obj)  # so does B
    assert kernel_modules.reload_stale(obj, loader_b) is True  # B reloads first
    loaded = kernel_modules.SYS_MODULE_DIR / "axdp_icmp"
    loaded.mkdir(parents=True)
    (loaded / "refcnt").write_text("0\n")  # B's fresh module, not yet used by B's retry
    events.clear()
    # A must not unload it: it only retries.
    assert kernel_modules.reload_stale(obj, loader_a) is True
    assert events == [] and loaded.exists()


def test_handler_load_retries_once_after_reloading_a_stale_module(tmp_path, monkeypatch):
    obj = dependency_object(tmp_path / "icmp.o", ["axdp_icmp"])
    monkeypatch.setattr(kernel_modules, "ensure", lambda path: None)
    attempts, reloads = [], []
    def load(command, *args, **kwargs):
        attempts.append(command)
        if len(attempts) == 1:
            raise RuntimeError("Failed to load icmp.o\ncalling kernel function bpf_axdp_icmp_reply is not allowed")
    monkeypatch.setattr(handlers, "run_checked", load)
    monkeypatch.setattr(kernel_modules, "reload_tokens", lambda path: {"axdp_icmp": str(len(attempts))})
    monkeypatch.setattr(kernel_modules, "reload_stale",
                        lambda path, tokens: reloads.append((path, tokens)) or True)
    handlers.stage_handler_program(obj, tmp_path / "prog", "xdp", [], tmp_path)
    # The token is read before the failed attempt, not after it.
    assert len(attempts) == 2 and reloads == [(obj, {"axdp_icmp": "0"})]
    # Nothing to reload, or another error: the first failure is reported unchanged.
    for error, reloadable in (("is not allowed", False), ("invalid argument", True)):
        attempts.clear()
        monkeypatch.setattr(kernel_modules, "reload_stale", lambda path, tokens, value=reloadable: value)
        def fail(command, *args, error=error, **kwargs):
            attempts.append(command)
            raise RuntimeError(f"Failed to load icmp.o\n{error}")
        monkeypatch.setattr(handlers, "run_checked", fail)
        with pytest.raises(RuntimeError, match=error):
            handlers.stage_handler_program(obj, tmp_path / "prog", "xdp", [], tmp_path)
        assert len(attempts) == 1


class FakeRuntime:
    """xdp_runtime_cfg stand-in; `flags` is shared with the test."""
    flags = [0]
    writable = True
    def __init__(self, path): pass
    def get_cfg_flags(self): return self.flags[0]
    def get(self): return (0,) * 8
    def set(self, values, value):
        if self.writable:
            self.flags[0] = value
        return self.writable
    def close(self): pass


@pytest.fixture
def unloadable_icmp(icmp_generation, tmp_path, monkeypatch):
    """ICMP is enabled, nothing is bound, and the handler cannot be loaded."""
    root, obj, state, events = icmp_generation
    state.update({1: None, 58: None})
    (root / "modules/icmp/prog").unlink()
    (root / "modules/icmp").rmdir()
    config = tmp_path / "config.toml"
    config.write_text("[modules.icmp]\nenabled = true\n")
    def reject(command, *args, **kwargs):
        raise RuntimeError(f"Failed to load {command[3]}\nlibbpf: prog 'xdp_icmp_handler': BPF program load failed\n"
                           "calling kernel function bpf_axdp_icmp_reply is not allowed\n"
                           "libbpf: failed to load object\nError: failed to load object file")
    monkeypatch.setattr(handlers, "run_checked", reject)
    runtime = type("Runtime", (FakeRuntime,), {"flags": [4], "writable": True})
    monkeypatch.setattr(module_runtime, "BpfRuntimeConfigMap", runtime)
    return root, obj, config, state, runtime


def test_unloadable_icmp_handler_degrades_fail_closed_when_allowed(unloadable_icmp, tmp_path, capsys):
    root, obj, config, state, runtime = unloadable_icmp
    marker = tmp_path / "run/icmp_degraded"
    # A caller that could keep a working generation instead gets the error.
    with pytest.raises(RuntimeError, match="is not allowed"):
        module_runtime.reconcile_icmp(root, obj, config)
    assert runtime.flags == [4] and not marker.exists()

    module_runtime.reconcile_icmp(root, obj, config, allow_degraded=True)
    # The gate is published without a handler: slots.h drops Echo Replies.
    assert runtime.flags == [4 | 64] and state == {1: None, 58: None}
    error = capsys.readouterr().err
    assert error.count("\n") == 1 and error.startswith("[auto_xdp] error: ICMP reply protection is degraded")
    assert "calling kernel function bpf_axdp_icmp_reply is not allowed" in error
    assert "rebuild or upgrade it" in error and "axdp handler apply icmp --set enabled=true" in error
    assert "drops inbound Echo Replies" in error and str(marker) in error
    assert module_runtime.icmp_degraded_reason(marker.parent).endswith("rebuild or upgrade it)")
    assert "libbpf: failed to load object" in marker.read_text()  # full detail is kept
    with pytest.raises(RuntimeError, match="has not been loaded: Failed to load .*is not allowed"):
        module_runtime.verify_icmp(root)

    # Each runtime start reports once; the daemon's retries do not repeat it.
    module_runtime.reconcile_icmp(root, obj, config, allow_degraded=True)
    assert capsys.readouterr().err.count("ICMP reply protection is degraded") == 1 and runtime.flags == [4 | 64]
    assert module_runtime.note_icmp_degraded(RuntimeError(marker.read_text().split("\n\n", 1)[1].strip())) is None


def test_degraded_icmp_state_ends_when_the_handler_loads(unloadable_icmp, tmp_path, monkeypatch):
    root, obj, config, state, _ = unloadable_icmp
    module_runtime.reconcile_icmp(root, obj, config, allow_degraded=True)
    assert module_runtime.icmp_degraded_reason(tmp_path / "run")
    monkeypatch.setattr(handlers, "run_checked", lambda command, *a, **k: Path(command[4]).write_text("21"))
    module_runtime.reconcile_icmp(root, obj, config, allow_degraded=True)
    assert state == {1: 21, 58: 21}
    assert module_runtime.icmp_degraded_reason(tmp_path / "run") is None


def test_degraded_icmp_requires_a_published_gate(unloadable_icmp, tmp_path):
    root, obj, config, _, runtime = unloadable_icmp
    runtime.writable = False
    with pytest.raises(RuntimeError, match="Echo Replies could not be closed"):
        module_runtime.reconcile_icmp(root, obj, config, allow_degraded=True)
    assert runtime.flags == [4] and not (tmp_path / "run/icmp_degraded").exists()


def test_failed_reload_keeps_a_loaded_handler_and_is_not_degraded(icmp_generation, tmp_path, monkeypatch, capsys):
    root, obj, state, _ = icmp_generation
    config = tmp_path / "config.toml"
    config.write_text("[modules.icmp]\nenabled = true\n")
    monkeypatch.setattr(module_runtime, "obj_get", lambda path: 123)
    monkeypatch.setattr(module_runtime, "program_id", lambda fd: 11)
    monkeypatch.setattr(module_runtime.os, "close", lambda fd: None)
    monkeypatch.setattr(module_runtime, "BpfRuntimeConfigMap",
                        lambda path: pytest.fail("the gate of a working handler must not be touched"))
    def reject(*args, **kwargs):
        raise RuntimeError("verifier rejected the new object")
    monkeypatch.setattr(handlers, "run_checked", reject)
    module_runtime.reconcile_icmp(root, obj, config, allow_degraded=True)
    assert state == {1: 11, 58: 11}
    assert "the loaded handler stays active: verifier rejected the new object" in capsys.readouterr().err
    assert module_runtime.icmp_degraded_reason(tmp_path / "run") is None


def bare_backend(flags: int, monkeypatch=None, slots_free=True):
    from unittest.mock import Mock
    from auto_xdp.backends.xdp import XdpBackend
    backend = XdpBackend.__new__(XdpBackend)
    backend.runtime_config_map = Mock()
    backend.runtime_config_map.get_cfg_flags.return_value = flags
    if monkeypatch is not None:
        monkeypatch.setattr(module_runtime, "icmp_slots_free", lambda root: slots_free)
    return backend


@pytest.mark.parametrize("gate, cold_start", [(True, False), (False, True)])
def test_policy_sync_continues_while_icmp_is_degraded(tmp_path, monkeypatch, caplog, gate, cold_start):
    from auto_xdp.backends import xdp
    backend = bare_backend(64 if gate else 0, monkeypatch)
    backend.icmp_degrade_ok = cold_start
    attempts = []
    def fail(root, *, enabled):
        attempts.append(root)
        raise RuntimeError("axdp_icmp needs development headers for running kernel 7.0.0-42-generic")
    monkeypatch.setattr(module_runtime, "prepare_icmp", fail)
    clock = [1000.0]
    monkeypatch.setattr(xdp.time, "monotonic", lambda: clock[0])
    with caplog.at_level("ERROR"):
        for _ in range(3):
            backend._prepare_icmp(tmp_path, True, gate)
    # One attempt however often policy is reconciled. The daemon (gate set)
    # reports once; a candidate pre-seed leaves the report to the runtime
    # start's handler step, so a start shows exactly one error.
    assert len(attempts) == 1 and len(caplog.records) == (1 if gate else 0)
    if gate:
        assert "needs development headers for running kernel 7.0.0-42-generic" in caplog.text
    assert module_runtime.icmp_degraded_reason(tmp_path / "run")
    clock[0] += xdp._ICMP_RETRY_SECONDS
    monkeypatch.setattr(module_runtime, "prepare_icmp", lambda root, *, enabled: attempts.append("loaded"))
    backend._prepare_icmp(tmp_path, True, gate)
    assert attempts[-1] == "loaded" and len(caplog.records) == (1 if gate else 0)


def test_retained_backend_can_disable_and_reenable_during_icmp_retry_delay(tmp_path, monkeypatch):
    from auto_xdp.backends import xdp
    backend = bare_backend(64, monkeypatch)
    attempts = []
    def prepare(root, *, enabled):
        attempts.append(enabled)
        if len(attempts) == 1:
            raise handlers.HandlerBusy("another loader owns ICMP")
    monkeypatch.setattr(module_runtime, "prepare_icmp", prepare)
    monkeypatch.setattr(xdp.time, "monotonic", lambda: 1000.0)
    backend._prepare_icmp(tmp_path, True, True)
    assert backend._icmp_retry_at > 1000.0
    backend._prepare_icmp(tmp_path, True, True)
    assert attempts == [True]
    backend._prepare_icmp(tmp_path, False, True)
    assert backend._icmp_retry_at == 0.0
    backend._prepare_icmp(tmp_path, True, False)
    assert attempts == [True, False, True]
    assert backend._icmp_retry_at == 0.0


def test_explicit_candidate_preparation_can_build_the_dependency(tmp_path, monkeypatch):
    backend = bare_backend(0, monkeypatch)
    backend.module_maintenance = True
    attempts = []

    def prepare(root, *, enabled):
        kernel_modules._require_build("axdp_icmp", "is missing")
        assert not handlers._NONBLOCKING_LOCKS.get()
        attempts.append(root)

    monkeypatch.setattr(module_runtime, "prepare_icmp", prepare)
    backend._prepare_icmp(tmp_path, True, False)
    assert attempts == [tmp_path]


def test_daemon_retry_never_builds_and_does_not_report_a_build_as_degraded(tmp_path, monkeypatch, caplog):
    backend = bare_backend(64, monkeypatch)
    seen = []
    def prepare(root, *, enabled):
        seen.append(kernel_modules._BUILDS_ALLOWED.get())
        kernel_modules._require_build("axdp_icmp", "is not installed for kernel 7.0")
    monkeypatch.setattr(module_runtime, "prepare_icmp", prepare)
    with caplog.at_level("INFO"):
        backend._prepare_icmp(tmp_path, True, True)
    assert seen == [False] and kernel_modules._BUILDS_ALLOWED.get()
    assert "built on the next runtime start" in caplog.text
    assert not [record for record in caplog.records if record.levelname == "ERROR"]
    assert module_runtime.degraded_reason("icmp", tmp_path / "run") is None


@pytest.mark.component
def test_daemon_retry_and_profile_cli_return_while_another_loader_holds_lock(tmp_path):
    import fcntl
    import os
    import sys
    # Distinct open file descriptions contend on the actual directory flock.
    # Both child commands must finish before this descriptor is released.
    (tmp_path / "tcp_profile_handlers").touch()
    fd = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        source = """
import logging, sys
from pathlib import Path
from auto_xdp.admin import handlers, kernel_modules, module_runtime
from auto_xdp.backends.xdp import XdpBackend
logging.basicConfig(level=logging.INFO)
root = Path(sys.argv[1])
module_runtime._icmp_bound = lambda root: False
module_runtime.icmp_slots_free = lambda root: True
kernel_modules.sdk_directory = lambda: root
backend = XdpBackend.__new__(XdpBackend)
backend._prepare_icmp(root, True, True)
assert module_runtime.degraded_reason("icmp", root / "run") is None
print("retry returned")
"""
        retry = subprocess.run([sys.executable, "-c", source, str(tmp_path)],
                               capture_output=True, text=True, timeout=10)
        assert retry.returncode == 0 and "retry returned" in retry.stdout, retry.stderr
        assert "holds the handler lock" in retry.stderr
        result = subprocess.run([sys.executable, "-m", "auto_xdp.admin.cli", "--no-wait",
                                 "--config", str(tmp_path / "config.toml"), "--bpf-pin-dir", str(tmp_path),
                                 "profile-handler", "unload", "1"], capture_output=True, text=True, timeout=10)
        assert result.returncode != 0 and "holds the handler lock" in result.stderr
        assert "Traceback" not in result.stderr
    finally:
        os.close(fd)
    with handlers._handler_lock(tmp_path):
        pass


def test_foreign_program_in_an_icmp_slot_is_never_tolerated(tmp_path, monkeypatch):
    backend = bare_backend(64, monkeypatch, slots_free=False)
    def fail(*args, **kwargs):
        raise RuntimeError("Active entry has no matching ownership pin")
    monkeypatch.setattr(module_runtime, "prepare_icmp", fail)
    with pytest.raises(RuntimeError, match="ownership pin"):
        backend._prepare_icmp(tmp_path, True, True)


def test_enabling_icmp_on_a_running_generation_stays_all_or_nothing(tmp_path, monkeypatch):
    backend = bare_backend(0, monkeypatch)
    def fail(*args, **kwargs):
        raise RuntimeError("kernel dependency unavailable")
    monkeypatch.setattr(module_runtime, "prepare_icmp", fail)
    for _ in range(2):  # never throttled into silence
        with pytest.raises(RuntimeError, match="dependency unavailable"):
            backend._prepare_icmp(tmp_path, True, False)
    assert module_runtime.icmp_degraded_reason(tmp_path / "run") is None


def test_status_reports_a_degraded_icmp_module_without_failing_health(tmp_path, monkeypatch):
    from auto_xdp.admin import runtime as admin_runtime
    env, run = tmp_path / "env", tmp_path / "run"
    run.mkdir()
    state = tmp_path / "runtime.json"
    state.write_text(json.dumps({"healthy": True, "interfaces": {"eth0": {"program_id": 10}}}))
    env.write_text(f'IFACES="eth0"\nRUNTIME_STATE="{state}"\nMACHINE_STATE="{tmp_path}/machine.json"\n'
                   f'INSTALL_DIR="{tmp_path}"\nINSTALL_TRANSACTION_FILE="{tmp_path}/transaction.json"\n'
                   f'TOML_CONFIG="{tmp_path}/absent.toml"\n')
    context = admin_runtime.RuntimeContext(env, tmp_path / "bpf", run, "inet", "auto_xdp")
    monkeypatch.setattr(admin_runtime, "_policy_mode", lambda env: "enforce")
    monkeypatch.setattr(admin_runtime, "detect_backend", lambda ctx, interfaces: "xdp")
    monkeypatch.setattr(admin_runtime, "_iface_xdp_state", lambda name: "native")
    monkeypatch.setattr(admin_runtime, "_iface_xdp_program_id", lambda name: 10)
    report = admin_runtime.collect_backend_report(context)
    assert report.healthy and report.degraded == {}
    assert "Degraded" not in admin_runtime.render_backend_text(report)

    (run / "icmp_degraded").write_text("axdp_icmp needs development headers\n\nfull detail\n")
    report = admin_runtime.collect_backend_report(context)  # configuration unreadable: the marker is trusted
    # The core firewall is attached: `axdp status` still exits 0, `axdp enable` is not rolled back.
    assert report.healthy
    text = admin_runtime.render_backend_text(report)
    assert ("Degraded  : icmp (reply handler not loaded, Echo Replies are dropped: "
            "axdp_icmp needs development headers)") in text
    assert json.loads(admin_runtime.render_backend_json(report))["degraded"] == report.degraded

    (run / "syncookie_degraded").write_text("refusing SYN-cookie enablement: NAT LOCAL_IN\n")
    text = admin_runtime.render_backend_text(admin_runtime.collect_backend_report(context))
    assert ("Degraded  : syncookie (module not active, TCP endpoints that use SYN cookies stay closed: "
            "refusing SYN-cookie enablement: NAT LOCAL_IN)") in text and "Degraded  : icmp (" in text


def test_status_reads_degraded_state_from_the_live_generation(tmp_path, monkeypatch):
    from auto_xdp.admin import runtime as admin_runtime
    env, run, bpf = tmp_path / "env", tmp_path / "run", tmp_path / "bpf"
    run.mkdir()
    bpf.mkdir()
    (bpf / "xdp_runtime_cfg").touch()
    config = tmp_path / "config.toml"
    state = tmp_path / "runtime.json"
    state.write_text(json.dumps({"healthy": True, "interfaces": {"eth0": {"program_id": 10}}}))
    env.write_text(f'IFACES="eth0"\nRUNTIME_STATE="{state}"\nMACHINE_STATE="{tmp_path}/machine.json"\n'
                   f'INSTALL_DIR="{tmp_path}"\nINSTALL_TRANSACTION_FILE="{tmp_path}/transaction.json"\n'
                   f'TOML_CONFIG="{config}"\n')
    context = admin_runtime.RuntimeContext(env, bpf, run, "inet", "auto_xdp")
    monkeypatch.setattr(admin_runtime, "_policy_mode", lambda env: "enforce")
    monkeypatch.setattr(admin_runtime, "detect_backend", lambda ctx, interfaces: "xdp")
    monkeypatch.setattr(admin_runtime, "_iface_xdp_state", lambda name: "native")
    monkeypatch.setattr(admin_runtime, "_iface_xdp_program_id", lambda name: 10)
    live = {"icmp": "dropped", "cookie_verified": False, "cookie_dispatched": False}
    monkeypatch.setattr(module_runtime, "icmp_live_degraded", lambda root: live["icmp"])
    def verify(root, interfaces):
        assert interfaces == ["eth0"]
        if not live["cookie_verified"]:
            raise RuntimeError("SYN Cookie TC ingress is not attached on eth0")
    monkeypatch.setattr(module_runtime, "verify_syncookie", verify)
    monkeypatch.setattr(module_runtime, "program_available", lambda root: live["cookie_dispatched"])
    degraded = lambda: admin_runtime.collect_backend_report(context).degraded

    config.write_text("[modules.icmp]\nenabled = true\n[modules.syncookie]\nenabled = true\n")
    # Held closed with no marker at all (lost, or cleared by a discarded candidate).
    assert degraded() == {
        "icmp": "reply handler not loaded, Echo Replies are dropped: no handler is bound",
        "syncookie": "module not active, TCP endpoints that use SYN cookies stay closed: "
                     "SYN Cookie TC ingress is not attached on eth0"}
    (run / "syncookie_degraded").write_text("refusing SYN-cookie enablement: NAT\n")
    live["cookie_dispatched"] = True
    assert degraded()["syncookie"] == ("previous cookie program dispatched but not verified on every "
                                       "interface: refusing SYN-cookie enablement: NAT")
    # Fixed since the marker was written: the stale marker is not reported.
    (run / "icmp_degraded").write_text("old cause\n")
    live.update(icmp=None, cookie_verified=True)
    assert degraded() == {}
    # Another program in an ICMP slot receives Echo Replies: never "dropped".
    live.update(icmp="foreign")
    assert degraded()["icmp"].startswith("reply handler not loaded and protocol slot 1 or 58 holds another program")
    # Disabled (for example by a daemon reload) with the markers still present,
    # or every cookie mode set to "off" as the degrade message suggests.
    live.update(icmp="dropped", cookie_verified=False)
    config.write_text('[modules.icmp]\nenabled = true\n[modules.syncookie]\nenabled = true\ndefault_mode = "off"\n')
    assert list(degraded()) == ["icmp"]
    config.write_text("[modules.icmp]\nenabled = false\n[modules.syncookie]\nenabled = false\n")
    assert degraded() == {}


def test_candidate_root_never_clears_the_live_marker(icmp_generation, tmp_path, monkeypatch):
    root, obj, _, _ = icmp_generation
    marker = tmp_path / "run/icmp_degraded"
    marker.parent.mkdir(parents=True, exist_ok=True)
    candidate = root.with_name(f"{root.name}_next")
    root.rename(candidate)
    marker.write_text("live generation has no handler\n")
    module_runtime.load_icmp(candidate, obj)  # the candidate may still be discarded
    assert marker.exists()
    candidate.rename(root)
    module_runtime.load_icmp(root, obj)
    assert not marker.exists()


def test_degraded_icmp_refuses_a_foreign_program_in_its_slot(unloadable_icmp, tmp_path):
    root, obj, config, state, runtime = unloadable_icmp
    state[1] = 99  # e.g. a raw [slots] entry for protocol 1
    with pytest.raises(RuntimeError, match="slot 1 or 58 holds another program"):
        module_runtime.reconcile_icmp(root, obj, config, allow_degraded=True)
    assert runtime.flags == [4] and not (tmp_path / "run/icmp_degraded").exists()


@pytest.mark.parametrize("bound, gate, expected", [(False, True, 0), (True, True, 1), (True, False, 0)])
def test_unprotected_query_reports_whether_a_handler_is_bound(icmp_generation, monkeypatch, bound, gate, expected):
    root, _, _, _ = icmp_generation
    monkeypatch.setattr(module_runtime, "_icmp_bound", lambda root: bound)
    # A bound handler whose gate was never published protects nothing.
    monkeypatch.setattr(module_runtime, "_icmp_gate", lambda root: gate)
    assert module_runtime.main(["unprotected", "icmp", "--root", str(root)]) == expected
    def unreadable(root):
        raise OSError("EPERM")
    monkeypatch.setattr(module_runtime, "_icmp_bound", unreadable)
    assert module_runtime.main(["unprotected", "icmp", "--root", str(root)]) == 1  # doubt: protected


def test_icmp_slots_are_reserved_while_the_reply_gate_is_set(icmp_generation, tmp_path, monkeypatch):
    root, _, state, _ = icmp_generation
    state.update({1: None, 58: None})  # degraded: gate set, slots empty
    (root / "xdp_runtime_cfg").touch()
    gate = [64]
    monkeypatch.setattr(module_runtime, "_icmp_gate", lambda root: bool(gate[0] & 64))
    for proto in (1, 58):
        with pytest.raises(RuntimeError, match=f"slot {proto} is reserved for the managed ICMP module"):
            handlers.load_protocol_handler(root, proto, tmp_path / "custom.o")
    gate[0] = 0  # ICMP disabled: slots 1 and 58 are never dispatched, nothing to protect
    class ReachedLoader(Exception):
        pass
    def reached(*args):
        raise ReachedLoader
    monkeypatch.setattr(handlers, "handler_shared_maps", reached)
    with pytest.raises(ReachedLoader):
        handlers.load_protocol_handler(root, 1, tmp_path / "custom.o")


def test_status_uses_the_runtime_default_configuration(tmp_path, monkeypatch):
    from auto_xdp.admin import runtime as admin_runtime
    env, run = tmp_path / "env", tmp_path / "run"
    run.mkdir()
    env.write_text('IFACES="eth0"\n')  # legacy env file without TOML_CONFIG
    seen = []
    monkeypatch.setattr(module_runtime, "degraded_modules",
                        lambda root, run_dir, config, interfaces: seen.append(config) or {})
    monkeypatch.setattr(admin_runtime, "_policy_mode", lambda env: "enforce")
    monkeypatch.setattr(admin_runtime, "detect_backend", lambda ctx, interfaces: "xdp")
    monkeypatch.setattr(admin_runtime, "_iface_xdp_state", lambda name: "native")
    admin_runtime.collect_backend_report(admin_runtime.RuntimeContext(env, tmp_path / "bpf", run, "inet", "auto_xdp"))
    assert seen == [Path("/etc/auto_xdp/config.toml")]


def test_damaged_installed_module_is_rebuilt(installed_module, monkeypatch):
    module, _, events, obj = installed_module
    module.write_bytes(b"\x7fELF\x02\x01" + b"\0" * 10)  # truncated by an interrupted install
    assert kernel_modules.module_damaged(module) and not kernel_modules.module_damaged(module.with_name("absent.ko"))
    dependency_object(obj, ["axdp_icmp"])
    def run(command, **kwargs):
        if command == ["pahole", "--version"]:
            return subprocess.CompletedProcess(command, 0, "pahole", "")
        events.append(command)
        if command[0] == "modprobe" and ["build"] not in events:
            return subprocess.CompletedProcess(command, 1, "", "Exec format error")
        return subprocess.CompletedProcess(command, 0, str(module), "")  # modinfo finds the file
    monkeypatch.setattr(kernel_modules, "_run", run)
    monkeypatch.setattr(kernel_modules, "_make_install", lambda name: events.append(["build"]))
    kernel_modules.ensure(obj)
    assert ["build"] in events and events[-1] == ["modprobe", "axdp_icmp"]


def test_dependency_loads_are_serialized_and_daemon_retries_do_not_wait(tmp_path, monkeypatch):
    import fcntl
    obj = dependency_object(tmp_path / "icmp.o", ["axdp_icmp"])
    plain = dependency_object(tmp_path / "plain.o", [])
    held = []
    monkeypatch.setattr(kernel_modules, "ensure", lambda path: held.append(getattr(kernel_modules._LOCK_STATE, "depth", 0)))
    monkeypatch.setattr(handlers, "run_checked", lambda *a, **k: held.append(getattr(kernel_modules._LOCK_STATE, "depth", 0)))
    handlers.stage_handler_program(obj, tmp_path / "prog", "xdp", [], tmp_path)
    handlers.stage_handler_program(plain, tmp_path / "prog", "xdp", [], tmp_path)
    # ensure() and the load that takes the module reference run under one lock;
    # objects without a bundled dependency do not take it.
    assert held == [1, 1, 0, 0]
    # The lock is reentrant within a loader (ensure -> rebuild -> unload).
    with kernel_modules._build_lock(), kernel_modules._build_lock():
        assert kernel_modules._LOCK_STATE.depth == 2
    # Another process holds it (e.g. a build): a daemon retry fails fast.
    kernel_modules.BUILD_LOCK.parent.mkdir(parents=True, exist_ok=True)
    with kernel_modules.BUILD_LOCK.open("a") as other:
        fcntl.flock(other, fcntl.LOCK_EX)
        import subprocess as sp, sys as system
        probe = sp.run([system.executable, "-c", f"""
import sys; sys.path.insert(0, {str(Path(__file__).resolve().parents[2])!r})
from pathlib import Path
from auto_xdp.admin import kernel_modules
kernel_modules.BUILD_LOCK = Path({str(kernel_modules.BUILD_LOCK)!r})
try:
    with kernel_modules.builds_disabled(), kernel_modules._build_lock():
        print("acquired")
except kernel_modules.BuildRequired as exc:
    print("busy:", exc)
"""], capture_output=True, text=True, timeout=20)
    assert probe.stdout.startswith("busy: another loader holds the kernel-module lock"), probe.stderr


def test_slot_check_and_gate_write_share_the_handler_lock(unloadable_icmp, monkeypatch):
    root, obj, config, state, runtime = unloadable_icmp
    order = []
    original = handlers._handler_lock
    @kernel_modules.contextmanager
    def tracking(path):
        order.append("lock")
        with original(path):
            yield
        order.append("unlock")
    monkeypatch.setattr(handlers, "_handler_lock", tracking)
    monkeypatch.setattr(module_runtime, "icmp_slots_free", lambda path: order.append("check") or True)
    real_set = runtime.set
    monkeypatch.setattr(runtime, "set", lambda self, values, value: order.append("gate") or real_set(self, values, value))
    module_runtime.reconcile_icmp(root, obj, config, allow_degraded=True)
    # load_icmp's own lock, then one lock around both check and gate write.
    assert order[-4:] == ["lock", "check", "gate", "unlock"]
