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


def test_flat_protocol_pin_does_not_authorize_removal(tmp_path):
    legacy = tmp_path / "handlers/proto_47"
    legacy.parent.mkdir()
    legacy.touch()
    with mock.patch.object(handlers, "_pinned_u32_lookup", return_value=11), \
         mock.patch.object(handlers, "prog_array_delete") as remove, \
         pytest.raises(RuntimeError, match="ownership pin"):
        handlers.unload_protocol_handler(tmp_path, 47)
    remove.assert_not_called()
    assert legacy.exists()
    assert not (tmp_path / "protocol_handlers/47").exists()


@pytest.mark.parametrize("failure", ["delete", "lookup"])
def test_unload_failure_retains_program_and_pins(tmp_path, failure):
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
