"""Transactional publication keeps both hook entries and generation pins recoverable."""
from pathlib import Path
from unittest import mock

import pytest

from auto_xdp.admin import handlers

pytestmark = pytest.mark.component


@pytest.fixture(params=["tcp_port_handlers", "proto_handlers"])
def pair(tmp_path, request):
    xdp = tmp_path / request.param
    tc, _ = handlers.handler_egress_table(xdp)
    tc.touch()
    (tmp_path / "handler_egress").touch()
    live, candidate = tmp_path / "live", tmp_path / "candidate"
    live.mkdir()
    candidate.mkdir()
    for name, old, new in (("prog", 11, 21), ("egress", 12, 22)):
        (live / name).write_text(str(old))
        (candidate / name).write_text(str(new))
    (live / "private-state").write_text("old proof")
    (candidate / "private-state").write_text("fresh proof")
    state = {xdp: 11, tc: 12}
    capability = {"id": 12}
    events = []

    def program_id(pin):
        return int(pin.read_text())

    def update(table, _key, pin):
        state[table] = program_id(pin)
        events.append((table.name, state[table]))

    def delete(table, _key):
        state[table] = None
        events.append((table.name, None))
        return True

    def publish(_root, _kind, _key, value):
        capability["id"] = value
        events.append(("capability", value))

    with mock.patch.object(handlers, "pinned_program_id", side_effect=program_id), \
         mock.patch.object(handlers, "_pinned_u32_lookup", side_effect=lambda table, key: state[table]), \
         mock.patch.object(handlers, "prog_array_update", side_effect=update), \
         mock.patch.object(handlers, "prog_array_delete", side_effect=delete), \
         mock.patch.object(handlers, "handler_egress_id", side_effect=lambda *args: capability["id"]), \
         mock.patch.object(handlers, "set_handler_egress", side_effect=publish):
        yield xdp, tc, live, candidate, state, capability, events


@pytest.mark.parametrize("mode", ["dual-reload", "single-to-dual", "dual-to-single", "unload"])
def test_pair_generation_transition(pair, mode):
    xdp, tc, live, candidate, state, capability, events = pair
    if mode == "single-to-dual":
        (live / "egress").unlink()
        state[tc] = capability["id"] = None
    if mode == "dual-to-single":
        (candidate / "egress").unlink()
    handlers.transactional_handler_pair(xdp, 443, None if mode == "unload" else candidate, live)
    if mode == "unload":
        assert state == {xdp: None, tc: None} and capability["id"] is None
        assert not live.exists()
        assert events[0] == (xdp.name, None)
    else:
        assert state[xdp] == 21
        assert state[tc] == capability["id"] == (None if mode == "dual-to-single" else 22)
        assert (live / "private-state").read_text() == "fresh proof"
        assert events.index(("capability", capability["id"])) < events.index((xdp.name, 21))
    assert not list(live.parent.glob("live_rollback_*"))


@pytest.mark.parametrize("failure", ["tc-update", "capability", "xdp-update", "rename", "post-rename"])
def test_failed_switch_restores_both_programs_capability_and_private_state(pair, failure):
    xdp, tc, live, candidate, state, capability, _ = pair
    update = handlers.prog_array_update.side_effect
    publish = handlers.set_handler_egress.side_effect
    rename = Path.rename
    failed = False

    def maybe_update(table, key, pin):
        nonlocal failed
        if not failed and table == (tc if failure == "tc-update" else xdp) and failure.endswith("update"):
            failed = True
            raise RuntimeError("injected update failure")
        update(table, key, pin)

    def maybe_publish(*args):
        nonlocal failed
        if failure == "capability" and not failed:
            failed = True
            raise RuntimeError("injected capability failure")
        publish(*args)

    def maybe_rename(source, destination):
        nonlocal failed
        if failure == "rename" and source == candidate and not failed:
            failed = True
            raise OSError("injected rename failure")
        return rename(source, destination)

    original_id = handlers.pinned_program_id.side_effect

    def maybe_id(pin):
        nonlocal failed
        if failure == "post-rename" and pin == live / "prog" and pin.read_text() == "21" and not failed:
            failed = True
            raise RuntimeError("injected committed-pin failure")
        return original_id(pin)

    with mock.patch.object(handlers, "prog_array_update", side_effect=maybe_update), \
         mock.patch.object(handlers, "set_handler_egress", side_effect=maybe_publish), \
         mock.patch.object(handlers, "pinned_program_id", side_effect=maybe_id), \
         mock.patch.object(Path, "rename", new=maybe_rename), \
         pytest.raises(RuntimeError, match="previous generation restored"):
        handlers.transactional_handler_pair(xdp, 443, candidate, live)
    assert failed
    assert state == {xdp: 11, tc: 12} and capability["id"] == 12
    assert (live / "prog").read_text() == "11" and (live / "egress").read_text() == "12"
    assert (live / "private-state").read_text() == "old proof"
    assert not candidate.exists()


def test_rollback_failure_retains_recovery_pins(pair):
    xdp, tc, live, candidate, state, capability, _ = pair
    with mock.patch.object(handlers, "prog_array_update", side_effect=RuntimeError("kernel denied")), \
         pytest.raises(RuntimeError, match="rollback failed"):
        handlers.transactional_handler_pair(xdp, 443, candidate, live)
    assert (live / "prog").exists() and (live / "egress").exists()
    assert (candidate / "prog").exists() and (candidate / "egress").exists()


def test_foreign_tc_entry_is_not_overwritten(pair):
    xdp, tc, live, candidate, state, capability, events = pair
    state[tc] = 99
    with pytest.raises(RuntimeError, match="ownership pin"):
        handlers.transactional_handler_pair(xdp, 443, candidate, live)
    assert not events and state == {xdp: 11, tc: 99}
    assert (live / "private-state").read_text() == "old proof"


@pytest.mark.parametrize("types", [[6, 6], [3], [6, 3, 3], [6, 1], []])
def test_object_inspection_rejects_ambiguous_or_unsupported_entries(types):
    lib = mock.Mock()
    lib.bpf_object__open_file.return_value = 100
    lib.libbpf_get_error.return_value = 0
    lib.bpf_object__next_program.side_effect = [*range(200, 200 + len(types)), None]
    lib.bpf_program__type.side_effect = types
    lib.bpf_program__name.return_value = b"handler"
    lib.bpf_program__section_name.return_value = b"xdp"
    with mock.patch.object(handlers.ctypes, "CDLL", return_value=lib), pytest.raises(RuntimeError):
        handlers.handler_object_programs(Path("candidate.o"))
    lib.bpf_object__close.assert_called_once_with(100)
    lib.bpf_object__load.assert_not_called()


@pytest.mark.parametrize("error, expected", [(2, None), (1, "unreadable"), (5, "unreadable")])
def test_lookup_never_confuses_permission_or_io_failure_with_an_empty_entry(error, expected):
    with mock.patch.object(handlers, "obj_get", return_value=42), \
         mock.patch.object(handlers, "bpf", side_effect=OSError(error, "injected failure")), \
         mock.patch.object(handlers.os, "close") as close:
        if expected is None:
            assert handlers._pinned_u32_lookup(Path("table"), bytes(4)) is None
        else:
            with pytest.raises(RuntimeError, match="Cannot inspect handler map"):
                handlers._pinned_u32_lookup(Path("table"), bytes(4))
    close.assert_called_once_with(42)


def test_missing_map_is_not_an_empty_entry():
    with mock.patch.object(handlers, "obj_get", side_effect=FileNotFoundError(2, "no pin")), \
         pytest.raises(RuntimeError, match="Cannot inspect handler map"):
        handlers.handler_egress_id(Path("pins"), 1, 1)


def test_failed_dual_load_never_publishes_one_entry(tmp_path):
    table = tmp_path / "tcp_port_handlers"
    for name in (table.name, "tc_tcp_handlers", "handler_egress"):
        (tmp_path / name).touch()
    live = tmp_path / "port_handlers/tcp/443"
    live.mkdir(parents=True)
    (live / "prog").write_text("old ingress")
    (live / "egress").write_text("old egress")
    (tmp_path / "dual.o").touch()
    with mock.patch.object(handlers, "handler_object_programs", return_value=("incoming", "outgoing")), \
         mock.patch.object(handlers, "run_checked", side_effect=RuntimeError("TC verifier rejected")) as run, \
         mock.patch.object(handlers, "_transactional_handler_pair") as publish, \
         pytest.raises(RuntimeError, match="TC verifier rejected"):
        handlers.load_handler_object(table, 443, tmp_path / "dual.o", live, [])
    command = run.call_args.args[0]
    assert command[:3] == ["bpftool", "prog", "loadall"]
    assert "type" not in command
    publish.assert_not_called()
    assert (live / "prog").read_text() == "old ingress"
    assert (live / "egress").read_text() == "old egress"
    assert not list(live.parent.glob("443_next_*"))


@pytest.mark.parametrize("action", ["replace", "unload", "failed-switch", "failed-rollback"])
def test_obsolete_generations_are_removed_only_after_verified_commit(pair, action):
    xdp, tc, live, candidate, state, capability, _ = pair
    obsolete = [live.parent / "443_next_deadbeef", live.parent / "live_rollback_1234abcd"]
    foreign = live.parent / "443_next_operator_backup"
    for path in [*obsolete, foreign]:
        path.mkdir()
        (path / "prog").write_text("recovery pin")
    if action in {"replace", "unload"}:
        handlers.transactional_handler_pair(xdp, 443, None if action == "unload" else candidate, live)
        assert not any(path.exists() for path in obsolete)
    else:
        update = handlers.prog_array_update.side_effect
        failed = False
        def fail(table, key, pin):
            nonlocal failed
            if action == "failed-rollback" or not failed:
                failed = True
                raise RuntimeError("injected update failure")
            update(table, key, pin)
        with mock.patch.object(handlers, "prog_array_update", side_effect=fail), pytest.raises(RuntimeError):
            handlers.transactional_handler_pair(xdp, 443, candidate, live)
        assert all(path.exists() for path in obsolete)
    assert foreign.exists()


@pytest.mark.parametrize("table_name", ["proto_handlers", "tcp_port_handlers", "udp_port_handlers", "tcp_profile_handlers"])
@pytest.mark.parametrize("action", ["replace", "unload", "unreadable"])
def test_single_entry_modules_use_the_same_strict_transaction(tmp_path, table_name, action):
    table = tmp_path / table_name
    live, candidate = tmp_path / "47", tmp_path / "47_next_deadbeef"
    live.mkdir()
    candidate.mkdir()
    (live / "prog").write_text("11")
    (candidate / "prog").write_text("21")
    state = {"id": 11}
    def update(_table, _key, pin):
        state["id"] = int(pin.read_text())
    def delete(_table, _key):
        state["id"] = None
        return True
    def lookup(_table, key):
        if action == "unreadable":
            raise RuntimeError("lookup denied")
        return state["id"]
    with mock.patch.object(handlers, "_pinned_u32_lookup", side_effect=lookup), \
         mock.patch.object(handlers, "pinned_program_id", side_effect=lambda pin: int(pin.read_text())), \
         mock.patch.object(handlers, "prog_array_update", side_effect=update), \
         mock.patch.object(handlers, "prog_array_delete", side_effect=delete), \
         mock.patch.object(handlers, "set_handler_egress") as capability:
        if action == "unreadable":
            with pytest.raises(RuntimeError, match="lookup denied"):
                handlers.transactional_handler_pair(table, 47, candidate, live)
            assert state["id"] == 11 and (live / "prog").read_text() == "11"
        else:
            handlers.transactional_handler_pair(table, 47, None if action == "unload" else candidate, live)
            assert state["id"] == (None if action == "unload" else 21)
            assert live.exists() is (action != "unload")
            assert not list(tmp_path.glob("47_rollback_*"))
        capability.assert_not_called()
