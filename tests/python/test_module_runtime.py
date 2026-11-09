"""SYN Cookie is an owned two-hook module, with explicit generation ownership."""
import json
import shutil
import subprocess
from pathlib import Path
from unittest import mock

import pytest

from auto_xdp.admin import handlers, module_runtime as modules

pytestmark = pytest.mark.component


@pytest.fixture
def generation(tmp_path, monkeypatch):
    root = tmp_path / "pins"
    live = modules.module_dir(root)
    live.mkdir(parents=True)
    for name, value in (("prog", "11"), ("ingress", "12")):
        (live / name).write_text(value)
    (root / "syncookie_prog_array").touch()
    (root / "sync_handoff4").write_text("existing handoff state")
    xdp, tc = tmp_path / "xdp.o", tmp_path / "tc.o"
    xdp.touch()
    tc.touch()
    state = {"xdp": 11, "eth0": 12, "eth1": 12, "eth2": 99}
    events = []
    def program_id(pin):
        return int(pin.read_text())
    def update(table, key, pin):
        state["xdp"] = program_id(pin)
        events.append(("xdp", state["xdp"]))
    def delete(table, key):
        state["xdp"] = None
        events.append(("xdp", None))
        return True
    def run(command, *args, **kwargs):
        if command[:3] == ["bpftool", "prog", "pin"]:
            shutil.copyfile(command[4], command[5])
        elif command[:3] == ["bpftool", "prog", "load"]:
            Path(command[4]).write_text("21" if command[6] == "xdp" else "22")
            events.append(("load", command[6]))
        elif command[:2] == ["tc", "filter"]:
            iface = command[4]
            state[iface] = program_id(Path(command[-1])) if command[2] == "replace" else None
            events.append((iface, state[iface]))
        return subprocess.CompletedProcess(command, 0, "", "")
    monkeypatch.setattr(handlers, "pinned_program_id", program_id)
    monkeypatch.setattr(handlers, "_pinned_u32_lookup", lambda *args: state["xdp"])
    monkeypatch.setattr(handlers, "prog_array_update", update)
    monkeypatch.setattr(handlers, "prog_array_delete", delete)
    monkeypatch.setattr(handlers, "handler_object_programs", lambda *args, **kwargs: ("entry", None))
    monkeypatch.setattr(handlers, "handler_shared_maps", lambda *args: [])
    monkeypatch.setattr(handlers, "run_checked", run)
    monkeypatch.setattr(modules, "tc_program_id", lambda iface: state.get(iface))
    monkeypatch.setattr(modules.socket, "if_nameindex", lambda: [(1, "lo"), (2, "eth0"), (3, "eth1"), (4, "eth2")])
    monkeypatch.setattr(modules.subprocess, "run", lambda command, **kwargs: subprocess.CompletedProcess(command, 0))
    return root, live, xdp, tc, state, events


def test_replace_and_disable_verify_both_hooks_without_losing_shared_state(generation):
    root, live, xdp, tc, state, events = generation
    modules.load_syncookie(root, xdp, tc, ["eth0", "eth1"])
    assert modules.verify_syncookie(root, ["eth0", "eth1"]) == 21
    assert events.index(("eth0", 22)) < events.index(("xdp", 21))
    assert events.index(("eth1", 22)) < events.index(("xdp", 21))
    assert (root / "sync_handoff4").read_text() == "existing handoff state"
    assert not list(live.parent.glob("syncookie_*"))
    events.clear()
    modules.remove_syncookie(root, ["eth0", "eth1"])
    assert events[0] == ("xdp", None)
    assert state == {"xdp": None, "eth0": None, "eth1": None, "eth2": 99}
    assert not live.exists()
    assert modules.verify_syncookie(root, ["eth0", "eth1"], enabled=False) is None


@pytest.mark.parametrize("failure", ["tc-verifier", "second-interface", "dispatch", "rename", "tc-timeout"])
def test_failed_module_replacement_restores_all_hooks_and_pins(generation, monkeypatch, failure):
    root, live, xdp, tc, state, events = generation
    run, update, rename = handlers.run_checked, handlers.prog_array_update, Path.rename
    failed = False
    def fail_run(command, *args, **kwargs):
        nonlocal failed
        run(command, *args, **kwargs)
        if not failed and (failure == "tc-verifier" and command[:3] == ["bpftool", "prog", "load"] and command[6] == "classifier"
                           or failure in {"second-interface", "tc-timeout"} and command[:2] == ["tc", "filter"] and command[4] == "eth0"):
            failed = True
            if failure == "tc-timeout":
                raise subprocess.TimeoutExpired("injected TC query", 5)
            raise RuntimeError("injected module failure")
    def fail_update(*args):
        nonlocal failed
        update(*args)
        if failure == "dispatch" and not failed:
            failed = True
            raise RuntimeError("injected dispatch failure")
    def fail_rename(source, dest):
        nonlocal failed
        if failure == "rename" and "next" in source.name and not failed:
            failed = True
            raise OSError("injected rename failure")
        return rename(source, dest)
    monkeypatch.setattr(handlers, "run_checked", fail_run)
    monkeypatch.setattr(handlers, "prog_array_update", fail_update)
    monkeypatch.setattr(Path, "rename", fail_rename)
    with pytest.raises((OSError, RuntimeError), match="injected"):
        modules.load_syncookie(root, xdp, tc, ["eth0", "eth1"])
    assert failed
    assert state == {"xdp": 11, "eth0": 12, "eth1": 12, "eth2": 99}
    assert (live / "prog").read_text() == "11"
    assert (live / "ingress").read_text() == "12"
    assert not list(live.parent.glob("syncookie_*"))
    if failure == "tc-verifier":
        assert not any(event[0] in {"eth0", "eth1", "xdp"} for event in events)


def test_failed_rollback_retains_candidate_and_previous_ownership(generation, monkeypatch):
    root, live, xdp, tc, state, events = generation
    monkeypatch.setattr(handlers, "prog_array_update", mock.Mock(side_effect=RuntimeError("write denied")))
    with pytest.raises(RuntimeError, match="rollback failed"):
        modules.load_syncookie(root, xdp, tc, ["eth0", "eth1"])
    assert (live / "prog").exists() and (live / "ingress").exists()
    assert list(live.parent.glob("syncookie_next_*/prog"))


def test_foreign_hook_is_never_replaced_or_removed(generation):
    root, live, xdp, tc, state, events = generation
    for action in (lambda: modules.load_syncookie(root, xdp, tc, ["eth0", "eth2"]),
                   lambda: modules.remove_syncookie(root, ["eth0", "eth2"])):
        with pytest.raises(RuntimeError, match="ownership pin"):
            action()
        assert state == {"xdp": 11, "eth0": 12, "eth1": 12, "eth2": 99}


def test_reconfiguration_removes_previously_owned_interface(generation):
    root, live, xdp, tc, state, events = generation
    modules.load_syncookie(root, xdp, tc, ["eth0"])
    assert state == {"xdp": 21, "eth0": 22, "eth1": None, "eth2": 99}


def test_foreign_non_bpf_filter_on_an_unrelated_interface_does_not_block_module(generation, monkeypatch):
    root, live, xdp, tc, state, events = generation
    def query(iface):
        if iface == "eth2":
            raise modules.ForeignHookError("foreign filter")
        return state.get(iface)
    monkeypatch.setattr(modules, "tc_program_id", query)
    modules.load_syncookie(root, xdp, tc, ["eth0", "eth1"])
    assert state["eth2"] == 99 and state["xdp"] == 21


@pytest.mark.parametrize("action", ["load", "remove"])
def test_flat_pins_cannot_authorize_a_module_transaction(generation, action):
    root, live, xdp, tc, state, events = generation
    (live / "prog").rename(root / "syncookie_prog")
    (live / "ingress").rename(root / "tc_syncookie_handoff_prog")
    live.rmdir()
    with pytest.raises(RuntimeError, match="ownership pin"):
        if action == "load":
            modules.load_syncookie(root, xdp, tc, ["eth0", "eth1"])
        else:
            modules.remove_syncookie(root, ["eth0", "eth1"])
    assert state["xdp"] == 11 and state["eth0"] == state["eth1"] == 12
    assert not live.exists()
    assert (root / "syncookie_prog").read_text() == "11"
    assert (root / "tc_syncookie_handoff_prog").read_text() == "12"
    assert all(event[0] == "load" for event in events)


def test_main_reload_retains_old_tc_ownership_without_publishing_old_dispatch(generation, tmp_path, monkeypatch):
    root, live, xdp, tc, state, events = generation
    candidate = tmp_path / "new-main-root"
    candidate.mkdir()
    monkeypatch.setattr(modules, "obj_get", lambda pin: modules.os.open(pin, modules.os.O_RDONLY))
    monkeypatch.setattr(modules, "program_id", lambda fd: int(modules.os.read(fd, 64)))
    (candidate / "syncookie_prog_array").touch()
    modules.retain_syncookie(root, candidate)
    assert (modules.module_dir(candidate) / "ingress").read_text() == "12"
    assert not events
    # The new main has no cookie entry yet. A subsequent load replaces the
    # retained TC companion and publishes a program using this root's maps.
    state["xdp"] = None
    assert not modules.program_available(candidate)
    modules.load_syncookie(candidate, xdp, tc, ["eth0", "eth1"])
    assert modules.program_available(candidate)
    assert state["eth0"] == state["eth1"] == 22


@pytest.mark.parametrize("level,ready,mode,raises", [(1, True, "auto", False), (1, True, "always", True),
                                                      (2, False, "auto", True)])
def test_capability_failure_withdraws_both_hooks(generation, tmp_path, level, ready, mode, raises):
    root, live, xdp, tc, state, events = generation
    config = tmp_path / "config.toml"
    config.write_text(f'[modules.syncookie]\nenabled = true\ndefault_mode = "{mode}"\n')
    args = (root, xdp, tc, ["eth0", "eth1"], config, tmp_path / "sysctl-state", f"{level}\nreason\n{int(ready)}")
    if raises:
        with pytest.raises(RuntimeError):
            modules.reconcile_syncookie(*args)
    else:
        modules.reconcile_syncookie(*args)
    assert state["xdp"] is state["eth0"] is state["eth1"] is None
    assert not live.exists()


@pytest.mark.parametrize("recoverable", [True, False])
def test_sysctl_is_released_after_failed_first_load_only_when_rollback_succeeded(tmp_path, monkeypatch, recoverable):
    root = tmp_path / "pins"
    root.mkdir()
    xdp, tc, config, state = [tmp_path / name for name in ("xdp.o", "tc.o", "config.toml", "sysctl.json")]
    xdp.touch()
    tc.touch()
    config.write_text('[modules.syncookie]\nenabled = true\n')
    monkeypatch.setattr(modules, "acquire_sysctl", lambda path: path.touch())
    release = mock.Mock()
    monkeypatch.setattr(modules, "release_sysctl", release)
    def fail(*args):
        if not recoverable:
            recovery = modules.module_dir(root).parent / "syncookie_next_12345678"
            recovery.mkdir(parents=True)
            (recovery / "prog").touch()
        raise RuntimeError("failed switch")
    monkeypatch.setattr(modules, "load_syncookie", fail)
    with pytest.raises(RuntimeError, match="failed switch"):
        modules.reconcile_syncookie(root, xdp, tc, ["eth0"], config, state, "2\nready\n1")
    assert release.called is recoverable


def test_missing_or_incompatible_shared_map_fails_before_loading_either_object(generation, monkeypatch):
    root, live, xdp, tc, state, events = generation
    monkeypatch.setattr(handlers, "handler_shared_maps", mock.Mock(side_effect=[[], RuntimeError("incompatible handoff map")]))
    with pytest.raises(RuntimeError, match="incompatible handoff map"):
        modules.load_syncookie(root, xdp, tc, ["eth0", "eth1"])
    assert not events
    assert state["xdp"] == 11 and state["eth0"] == state["eth1"] == 12


@pytest.mark.parametrize("status,rows,expected", [
    (0, [{"pref": 49151, "kind": "bpf"}, {"pref": 49151, "kind": "bpf", "options": {"handle": "0x2", "id": 12}}], 12),
    (0, [{"pref": 49151, "kind": "bpf", "options": {"handle": 2, "prog": {"id": 12}}}], 12),
    (0, [{"pref": 49151, "kind": "bpf", "options": {"handle": "0x3", "id": 99}}], None),
    (0, [{"pref": 49151, "kind": "bpf", "options": {"handle": "0x2"}}], "error"),
    (0, [{"pref": 49151, "kind": "flower", "options": {"handle": 2}}], "error"),
    (1, [], "error"),
])
def test_tc_readback_is_strict_and_scoped_to_the_owned_filter(status, rows, expected):
    with mock.patch.object(modules.subprocess, "run", return_value=subprocess.CompletedProcess([], status, json.dumps(rows), "denied")):
        if expected == "error":
            with pytest.raises(RuntimeError, match="Cannot verify"):
                modules.tc_program_id("eth0")
        else:
            assert modules.tc_program_id("eth0") == expected
