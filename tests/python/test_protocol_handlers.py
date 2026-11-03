"""Protocol slots use the same ownership/state lifecycle as service modules."""
import json
import subprocess
from unittest import mock

import pytest

from auto_xdp.admin import handlers, handler_state
from test_handler_state import elf

pytestmark = pytest.mark.component


def test_explicit_stateless_contract(tmp_path):
    obj = elf(tmp_path / "gre.o", {"version": 1, "schema": "gre-stateless-v1", "maps": []})
    assert handler_state.object_contract(obj) == handler_state.StateContract("gre-stateless-v1", ())
    assert len(handler_state.fingerprint(handler_state.object_contract(obj), {})) == 32


@pytest.mark.parametrize("proto", [-1, 256, 65536])
def test_protocol_number_out_of_range_rejected_before_io(tmp_path, proto):
    with pytest.raises(ValueError, match="invalid IP protocol"):
        handlers.load_protocol_handler(tmp_path, proto, tmp_path / "missing.o")
    with pytest.raises(ValueError, match="invalid IP protocol"):
        handlers.unload_protocol_handler(tmp_path, proto)


@pytest.mark.parametrize("active", [11, 99])
def test_legacy_ownership_is_verified_before_adoption(tmp_path, active):
    legacy = tmp_path / "handlers/proto_47"
    legacy.parent.mkdir()
    legacy.touch()
    def pin(command, message):
        assert legacy.exists()
        (tmp_path / "protocol_handlers/47/prog").touch()
    with mock.patch.object(handlers, "pinned_program_id", return_value=11), \
         mock.patch.object(handlers, "_pinned_u32_lookup", return_value=active), \
         mock.patch.object(handlers, "run_checked", side_effect=pin) as run:
        if active == 11:
            assert handlers._adopt_protocol_pin(tmp_path, 47) == legacy
            run.assert_called_once()
        else:
            with pytest.raises(RuntimeError, match="ownership"):
                handlers._adopt_protocol_pin(tmp_path, 47)
            run.assert_not_called()
    assert legacy.exists()


@pytest.mark.parametrize("private", [False, True])
def test_stateless_adoption_requires_no_private_legacy_maps(tmp_path, private):
    live = tmp_path / "protocol_handlers/50"
    live.mkdir(parents=True)
    (live / "prog").touch()
    (tmp_path / "slot_ctx_map").touch()
    obj = elf(tmp_path / "esp.o", {"version": 1, "schema": "esp-stateless-v1", "maps": []})
    info = {"map_ids": [1, 99] if private else [1]}
    with mock.patch.object(handlers, "_pinned_u32_lookup", return_value=None), \
         mock.patch.object(handlers, "run_checked", return_value=subprocess.CompletedProcess([], 0, json.dumps(info))), \
         mock.patch.object(handlers, "_pinned_map_id", return_value=1), \
         mock.patch.object(handlers, "handler_object_maps", return_value={}), \
         mock.patch.object(handlers, "_pin_state_marker") as marker:
        if private:
            with pytest.raises(RuntimeError, match="private state"):
                handlers._adopt_stateless_contract(tmp_path, live, obj)
            marker.assert_not_called()
        else:
            handlers._adopt_stateless_contract(tmp_path, live, obj)
            marker.assert_called_once()


@pytest.mark.parametrize("failure", ["delete", "lookup"])
def test_legacy_unload_failure_retains_program_and_pins(tmp_path, failure):
    live = tmp_path / "protocol_handlers/132"
    live.mkdir(parents=True)
    (live / "prog").touch()
    with mock.patch.object(handlers, "_pinned_u32_lookup", side_effect=RuntimeError("unreadable") if failure == "lookup" else None, return_value=11), \
         mock.patch.object(handlers, "pinned_program_id", return_value=11), \
         mock.patch.object(handlers, "prog_array_delete", return_value=False), \
         mock.patch.object(handlers, "prog_array_update"), \
         pytest.raises(RuntimeError):
        handlers.unload_protocol_handler(tmp_path, 132)
    assert (live / "prog").exists()


def test_failed_stateless_marker_does_not_block_retry(tmp_path):
    live = tmp_path / "protocol_handlers/47"
    live.mkdir(parents=True)
    (live / "prog").touch()
    obj = elf(tmp_path / "gre.o", {"version": 1, "schema": "gre-stateless-v1", "maps": []})
    def fail_marker(directory, digest):
        (directory / "state_contract").touch()
        raise RuntimeError("injected marker update failure")
    with mock.patch.object(handlers, "_pinned_u32_lookup", return_value=None), \
         mock.patch.object(handlers, "run_checked", return_value=subprocess.CompletedProcess([], 0, '{"map_ids":[]}')), \
         mock.patch.object(handlers, "handler_object_maps", return_value={}), \
         mock.patch.object(handlers, "_pin_state_marker", side_effect=fail_marker), \
         pytest.raises(RuntimeError, match="marker update"):
        handlers._adopt_stateless_contract(tmp_path, live, obj)
    assert (live / "prog").exists() and not (live / "state_contract").exists()


@pytest.mark.parametrize("missing", ["tc_proto_handlers", "handler_egress", "both"])
def test_incomplete_dual_maps_do_not_turn_unload_into_single_entry_removal(tmp_path, missing):
    live = tmp_path / "protocol_handlers/47"
    live.mkdir(parents=True)
    for name in ("prog", "egress"):
        (live / name).touch()
    for name in ("tc_proto_handlers", "handler_egress"):
        if missing not in {name, "both"}:
            (tmp_path / name).touch()
    with mock.patch.object(handlers, "prog_array_delete") as remove, \
         pytest.raises(RuntimeError, match="incomplete"):
        handlers.unload_protocol_handler(tmp_path, 47)
    remove.assert_not_called()
    assert (live / "prog").exists() and (live / "egress").exists()


def test_flat_protocol_pins_and_empty_directory_are_retired_after_migration(tmp_path):
    directory = tmp_path / "handlers"
    directory.mkdir()
    retired = ["proto_47", "proto_47_next_deadbeef", "proto_47_rollback_1234abcd"]
    retained = ["proto_50", "proto_47_next_operator_backup"]
    for name in retired + retained:
        (directory / name).touch()
    handlers._retire_protocol_pins(tmp_path, 47)
    assert sorted(path.name for path in directory.iterdir()) == sorted(retained)
    (directory / retained[1]).unlink()
    handlers._retire_protocol_pins(tmp_path, 50)
    assert not directory.exists()


def test_committed_canonical_program_can_retire_stale_flat_pin(tmp_path):
    legacy = tmp_path / "handlers/proto_47"
    canonical = tmp_path / "protocol_handlers/47/prog"
    for pin, value in ((legacy, "11"), (canonical, "21")):
        pin.parent.mkdir(parents=True)
        pin.write_text(value)
    with mock.patch.object(handlers, "pinned_program_id", side_effect=lambda pin: int(pin.read_text())), \
         mock.patch.object(handlers, "_pinned_u32_lookup", return_value=21), \
         mock.patch.object(handlers, "run_checked") as pin_command:
        assert handlers._adopt_protocol_pin(tmp_path, 47) == legacy
    pin_command.assert_not_called()
    assert canonical.read_text() == "21" and legacy.exists()
