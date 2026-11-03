"""A state contract must authorize reuse explicitly before anything is published."""
import json
import struct
from pathlib import Path
from unittest import mock

import pytest

from auto_xdp.admin import handler_state, handlers
from auto_xdp.backends.xdp import XdpBackend

pytestmark = pytest.mark.component
ABI = handlers.HandlerMapAbi(9, 40, 24, 4096, 0)
CONTRACT = handler_state.StateContract("protocol-v1", ("sessions",))


def elf(path, contract):
    names = b"\0.shstrtab\0.axdp_state\0"
    payload = json.dumps(contract).encode() + b"\0"
    data = bytearray(64 + 3 * 64)
    data[:6] = b"\x7fELF\x02\x01"
    struct.pack_into("<Q", data, 40, 64)
    struct.pack_into("<HHH", data, 58, 64, 3, 1)
    struct.pack_into("<IIQQQQ", data, 128, 1, 3, 0, 0, len(data), len(names))
    struct.pack_into("<IIQQQQ", data, 192, 11, 1, 0, 0, len(data) + len(names), len(payload))
    path.write_bytes(data + names + payload)
    return path


def test_contract_parsing_and_compatible_generation_ignore_code_only_changes(tmp_path):
    obj = elf(tmp_path / "handler.o", {"version": 1, "schema": "protocol-v1", "maps": ["sessions"]})
    assert handler_state.object_contract(obj) == CONTRACT
    with mock.patch.object(handlers, "handler_object_maps", return_value={"sessions": ABI}):
        before = handlers.profile_state_generation(obj)
        obj.write_bytes(obj.read_bytes() + b"new instructions / compiler metadata")
        assert handlers.profile_state_generation(obj) == before
    assert handler_state.fingerprint(CONTRACT, {"sessions": ABI}) != handler_state.fingerprint(
        CONTRACT, {"sessions": ABI._replace(value_size=32)})


@pytest.mark.parametrize("contract", [
    {"version": 2, "schema": "x", "maps": ["sessions"]},
    {"version": 1, "schema": "x", "maps": ["sessions", "sessions"]},
    {"version": 1, "schema": "../x", "maps": ["sessions"]},
    {"version": 1, "schema": "x", "maps": ["../sessions"]},
    [],
])
def test_bad_contract_rejected(tmp_path, contract):
    with pytest.raises(RuntimeError, match="Invalid handler state contract"):
        handler_state.object_contract(elf(tmp_path / "bad.o", contract))


@pytest.mark.parametrize("failure", ["schema", "size", "capacity", "flags", "missing", "unversioned"])
def test_incompatible_state_rejected_before_load(tmp_path, failure):
    live = tmp_path / "live"
    (live / "maps").mkdir(parents=True)
    for pin in ("prog", "egress", "state_contract", "maps/sessions"):
        (live / pin).touch()
    digest = handler_state.fingerprint(CONTRACT, {"sessions": ABI})
    actual = ABI
    if failure == "size":
        actual = ABI._replace(value_size=32)
    elif failure == "capacity":
        actual = ABI._replace(max_entries=8192)
    elif failure == "flags":
        actual = ABI._replace(map_flags=1)
    elif failure == "missing":
        (live / "maps/sessions").unlink()
    elif failure == "unversioned":
        (live / "state_contract").unlink()
    with mock.patch.object(handler_state, "object_contract", return_value=CONTRACT), \
         mock.patch.object(handlers, "handler_object_maps", return_value={"sessions": ABI}), \
         mock.patch.object(handlers, "_state_marker", return_value=bytes(32) if failure == "schema" else digest), \
         mock.patch.object(handlers, "pinned_handler_map_abi", return_value=actual), \
         mock.patch.object(handlers, "run_checked") as run, \
         pytest.raises(RuntimeError, match="compatible"):
        handlers._preserved_state_maps(Path("candidate.o"), live)
    run.assert_not_called()
    assert (live / "prog").exists()


def test_compatible_maps_are_rebound_without_copying_entries(tmp_path):
    live = tmp_path / "live"
    (live / "maps").mkdir(parents=True)
    for pin in ("prog", "egress", "state_contract", "maps/sessions"):
        (live / pin).touch()
    digest = handler_state.fingerprint(CONTRACT, {"sessions": ABI})
    with mock.patch.object(handler_state, "object_contract", return_value=CONTRACT), \
         mock.patch.object(handlers, "handler_object_maps", return_value={"sessions": ABI}), \
         mock.patch.object(handlers, "_state_marker", return_value=digest), \
         mock.patch.object(handlers, "pinned_handler_map_abi", return_value=ABI):
        assert handlers._preserved_state_maps(Path("candidate.o"), live) == (
            digest, [("sessions", live / "maps/sessions")])


@pytest.mark.parametrize("map_type", [3, 12, 13, 27])
def test_kernel_object_maps_cannot_opt_into_plain_data_migration(map_type):
    with pytest.raises(RuntimeError, match="Unsupported persistent"):
        handler_state.fingerprint(CONTRACT, {"sessions": ABI._replace(map_type=map_type)})


def test_versioned_state_cannot_be_silently_replaced_by_unversioned_object(tmp_path):
    (tmp_path / "prog").touch()
    (tmp_path / "state_contract").touch()
    with mock.patch.object(handler_state, "object_contract", return_value=None), \
         pytest.raises(RuntimeError, match="previous handler retained"):
        handlers._preserved_state_maps(Path("candidate.o"), tmp_path)


def test_public_scratch_map_cannot_be_persistent_state():
    with mock.patch.object(handler_state, "object_contract", return_value=handler_state.StateContract("bad", ("slot_ctx_map",))), \
         pytest.raises(RuntimeError, match="public SDK"):
        handlers.handler_state_fingerprint(Path("candidate.o"))


@pytest.mark.parametrize("preserved", [True, False])
def test_udp_validation_is_only_flushed_when_state_is_replaced(tmp_path, preserved):
    with mock.patch.object(handlers, "_load_handler_object", return_value=preserved), \
         mock.patch.object(handlers, "flush_udp_validated_for_port") as flush:
        assert handlers.load_handler_object(tmp_path / "udp_port_handlers", 30120,
                                            Path("candidate.o"), tmp_path / "live", []) is preserved
    if preserved:
        flush.assert_not_called()
    else:
        flush.assert_called_once_with(tmp_path, 30120)


@pytest.mark.parametrize("outcome", ["success", "rejected", "rollback-failed", "marker-failed", "unchanged", "marker-missing"])
def test_backend_code_reload_keeps_state_epoch_and_only_trusts_verified_rollback(tmp_path, outcome):
    import hashlib
    from types import SimpleNamespace

    obj = tmp_path / "handlers/minecraft_handler.o"
    obj.parent.mkdir()
    obj.write_bytes(b"new code with compatible state")
    marker = tmp_path / "marker.json"
    digest = hashlib.sha256(obj.read_bytes()).hexdigest()
    marker.write_text(json.dumps({"profile": "minecraft", "profile_id": 1,
                                 "program_id": 42, "profile_generation": 123,
                                 "object_digest": digest if outcome == "unchanged" else "old code"}))
    if outcome == "marker-missing":
        marker.unlink()
        pin = tmp_path / "profile_handlers/tcp/1/state_contract"
        pin.parent.mkdir(parents=True)
        pin.touch()
    active = {"id": 42}
    backend = XdpBackend.__new__(XdpBackend)
    backend._config = SimpleNamespace(BPF_PIN_DIR=str(tmp_path))
    backend.tcp_profile_map = mock.Mock()
    backend.tcp_profile_map.value.side_effect = lambda _key: (active["id"],)

    def command(action, *_args):
        assert action == "load", "a failed update must not unload a retained session"
        if outcome in {"rejected", "marker-missing"}:
            return False
        if outcome == "rollback-failed":
            active["id"] = 99
            return False
        active["id"] = 43
        return True

    with mock.patch.object(backend, "_profile_install_dir", return_value=tmp_path), \
         mock.patch.object(backend, "_profile_marker", return_value=marker), \
         mock.patch.object(backend, "_profile_generation", return_value=123), \
         mock.patch.object(backend, "_pinned_program_id", side_effect=lambda _path: 42 if outcome == "rollback-failed" else active["id"]), \
         mock.patch.object(backend, "_profile_egress_ready", return_value=True), \
         mock.patch.object(handlers, "_state_marker", return_value=(123).to_bytes(32, "little")), \
         mock.patch.object(backend, "_profile_command", side_effect=command) as load, \
         mock.patch("auto_xdp.backends.xdp.atomic_write_json", side_effect=OSError("read-only state directory") if outcome == "marker-failed" else None) as write:
        failures, generation = backend._ensure_profile_handlers({("public", 25565): "minecraft"}, 123, False)
    if outcome == "rollback-failed":
        assert failures == {("public", 25565)} and generation == 0
    else:
        assert not failures and generation == 123
    if outcome == "unchanged":
        load.assert_not_called()
    else:
        load.assert_called_once_with("load", 1, obj)
    if outcome in {"success", "marker-failed"}:
        assert active["id"] == 43
        assert write.call_args.args[1]["object_digest"] == digest
        assert write.call_args.args[1]["profile_generation"] == 123
    else:
        write.assert_not_called()
