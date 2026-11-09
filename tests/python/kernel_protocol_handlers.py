"""Real GRE/ESP/SCTP ownership and optional dual-entry protocol dispatch.

Runs exclusively inside the integration suite's private network/mount namespace.
"""
import json
from pathlib import Path
import socket
import struct
import sys
import tempfile
from unittest import mock

from auto_xdp.admin import handlers
from kernel_handler_dispatch import run, update, metrics as chain_metrics
from kernel_packet_telemetry import run_packet, counter
from kernel_packet_lengths import ethernet, ipv4, ipv6, SOURCE4, DEST4, SOURCE6, DEST6


def state(live):
    result = json.loads(run("bpftool", "-j", "map", "lookup", "pinned", live / "maps/proto_metrics",
                            "key", "0", "0", "0", "0").stdout)
    return bytes(int(v, 0) for v in result["value"])


def counts(live):
    return struct.unpack_from("=QQ", state(live), 96)


def tc_packet(pin, packet):
    with tempfile.TemporaryDirectory(prefix="axdp-protocol-packet-") as directory:
        path = Path(directory) / "packet"
        path.write_bytes(packet)
        result = json.loads(run("bpftool", "-j", "prog", "run", "pinned", pin,
                                "data_in", path, "repeat", 1).stdout)
        assert result["retval"] in (-1, 4294967295), result


def main(root, iface, objects):
    ifindex = socket.if_nametoindex(iface)
    update(root, "xdp_runtime_cfg", bytes(4), bytes(64) + struct.pack("=II", 1, 0))
    bodies = {47: bytes.fromhex("00000800"), 50: struct.pack("!II", 256, 1),
              132: struct.pack("!HHII", 40000, 42000, 123, 0)}
    # Both stateful service tests and protocol plugins use this same dispatcher.
    dispatcher = objects / "dispatcher.o"
    command = ["bpftool", "prog", "load", dispatcher, root / "protocol_dispatch", "type", "classifier"]
    for name in handlers.handler_object_maps(dispatcher):
        command += ["map", "name", name, "pinned", root / name]
    run(*command)
    run("bpftool", "prog", "load", objects / "chain.o", root / "protocol_chain", "type", "classifier",
        "pinmaps", root / "protocol_chain_maps")
    run("tc", "qdisc", "add", "dev", iface, "clsact")
    for pref, pin in ((49153, "protocol_dispatch"), (49154, "protocol_chain")):
        run("tc", "filter", "add", "dev", iface, "egress", "pref", pref, "handle", 2,
            "bpf", "direct-action", "object-pinned", root / pin)
    fixture = objects / "fixture.o"
    try:
        for proto, name in ((47, "gre"), (50, "esp"), (132, "sctp")):
            obj = objects / f"{name}.o"
            # Reproduce the old flat pin format with no compatibility marker.
            legacy_obj = objects / f"{name}_legacy.o"
            legacy_obj.write_bytes(obj.read_bytes().replace(b".axdp_state", b".oldp_state"))
            legacy = root / "handlers" / f"proto_{proto}"
            legacy.parent.mkdir(exist_ok=True)
            command = ["bpftool", "prog", "load", legacy_obj, legacy, "type", "xdp"]
            for map_name, pin in handlers.handler_shared_maps(legacy_obj, root):
                command += ["map", "name", map_name, "pinned", pin]
            run(*command)
            handlers.prog_array_update(root / "proto_handlers", proto, legacy)
            for suffix in ("next_deadbeef", "rollback_1234abcd"):
                run("bpftool", "prog", "pin", "pinned", legacy, legacy.with_name(f"proto_{proto}_{suffix}"))
            old_id = handlers.pinned_program_id(legacy)
            live = handlers.protocol_handler_dir(root, proto)
            binding = handlers.program_array_binding(root / "proto_handlers", proto)
            old_pins = list(legacy.parent.iterdir())
            # Flat pins do not authorize takeover or removal. Both operations
            # must preserve the active program and all of its recovery pins.
            for operation in (
                lambda: handlers.load_protocol_handler(root, proto, obj),
                lambda: handlers.unload_protocol_handler(root, proto),
            ):
                try:
                    operation()
                except RuntimeError as exc:
                    assert "ownership pin" in str(exc), str(exc)
                else:
                    raise AssertionError("flat protocol pin authorized a generation change")
                assert binding.read() == old_id
                assert all(handlers.pinned_program_id(pin) == old_id for pin in old_pins)
                assert not (live / "prog").exists()
                assert not list(live.parent.glob(f"{proto}_next_*"))
            # The fixture owns this old installation and explicitly tears it
            # down before exercising a fresh canonical generation.
            assert handlers.prog_array_delete(root / "proto_handlers", proto)
            assert binding.read() is None
            for pin in old_pins:
                pin.unlink()
            legacy.parent.rmdir()
            if proto == 47:
                (root / "tc_proto_handlers").rename(root / "saved_tc_proto")
            handlers.load_protocol_handler(root, proto, obj)
            assert not legacy.parent.exists() and (live / "state_contract").exists()
            assert handlers.pinned_program_id(live / "prog") != old_id
            if proto == 47:
                # Prior framework has service TC maps but no protocol TC table.
                try:
                    handlers.load_protocol_handler(root, proto, fixture)
                except RuntimeError:
                    pass
                else:
                    raise AssertionError("dual protocol loaded without its dispatcher table")
                handlers.unload_protocol_handler(root, proto)
                assert not live.exists()
                handlers.load_protocol_handler(root, proto, obj)
                (root / "saved_tc_proto").rename(root / "tc_proto_handlers")
            before = handlers.pinned_program_id(live / "prog")
            assert handlers.load_protocol_handler(root, proto, obj)
            assert handlers.pinned_program_id(live / "prog") != before
            for family, ip in ((4, ipv4), (6, ipv6)):
                frame = ethernet(ip(proto, bodies[proto]), family)
                if proto == 132:
                    update(root, "sctp_whitelist", struct.pack("=I", 42000), struct.pack("=I", 0))
                    assert run_packet(root, ifindex, frame)[0] == 1
                    update(root, "sctp_whitelist", struct.pack("=I", 42000), struct.pack("=I", 1))
                assert run_packet(root, ifindex, frame)[0] == 2
                if proto in (47, 50):
                    bad = bytes.fromhex("00010800") if proto == 47 else struct.pack("!II", 255, 1)
                    assert run_packet(root, ifindex, ethernet(ip(proto, bad), family))[0] == 1
                else:
                    update(root, "xdp_runtime_cfg", bytes(4), bytes(64) + struct.pack("=II", 1 | 16, 0))
                    assert run_packet(root, ifindex, frame)[0] == 1, "SCTP bypassed exact endpoint scope"
                    address = (DEST4 if family == 4 else DEST6).ljust(16, b"\0")
                    scope = struct.pack("=IHBB", ifindex, 42000, proto, 2 if family == 4 else 10) + address
                    update(root, "endpoint_scopes", scope, struct.pack("=I", 1))
                    assert run_packet(root, ifindex, frame)[0] == 2
                    update(root, "xdp_runtime_cfg", bytes(4), bytes(64) + struct.pack("=II", 1, 0))
            handlers.unload_protocol_handler(root, proto)
            assert not live.exists()
            print(f"PASS {name}: flat ownership rejected, fresh load, compatible replacement, IPv4/IPv6 verdicts and unload", flush=True)

            handlers.load_protocol_handler(root, proto, fixture)
            private_id = handlers._pinned_map_id(live / "maps/proto_metrics")
            for family, ip, src, dst in ((4, ipv4, SOURCE4, DEST4), (6, ipv6, SOURCE6, DEST6)):
                body = bodies[proto] + b"payload"
                packet = ethernet(ip(proto, body), family, padding=128)
                assert run_packet(root, ifindex, packet)[0] == 2
                before_ingress, before_egress = counts(live)
                tc_packet(root / "protocol_dispatch", packet)
                current = state(live)
                assert counts(live) == (before_ingress, before_egress + 1)
                assert struct.unpack_from("=4I", current) == (1, 4, proto, 0)
                assert current[16] == (2 if family == 4 else 10)
                assert struct.unpack_from("!HH", current, 20) == ((40000, 42000) if proto == 132 else (0, 0))
                assert current[24:40] == src.ljust(16, b"\0") and current[40:56] == dst.ljust(16, b"\0")
                assert current[56:72] == bytes(16) and current[88:96] == bytes(4) + bytes((255, 0, 0, proto))
                l4 = 34 if family == 4 else 54
                payload_offset = l4 + 12 if proto == 132 else l4
                assert struct.unpack_from("=4I", current, 72) == (payload_offset, len(body) - (12 if proto == 132 else 0), l4, 128)
                # Real egress hook and a later independent filter both execute.
                previous_chain = chain_metrics(root / "protocol_chain_maps/private_metrics")[1]
                before_egress = counts(live)[1]
                with socket.socket(socket.AF_PACKET, socket.SOCK_RAW) as sock:
                    sock.bind((iface, 0))
                    sock.send(packet)
                assert counts(live)[1] == before_egress + 1
                assert chain_metrics(root / "protocol_chain_maps/private_metrics")[1] > previous_chain
                # VLANs and IPv6 extensions keep the protocol/header boundary.
                extended = ip(proto, body) if family == 4 else ipv6(0, bytes((proto, 0)) + bytes(6) + body)
                tc_packet(root / "protocol_dispatch", ethernet(extended, family, vlan=True))
                extra = 4 + (8 if family == 6 else 0)
                assert struct.unpack_from("=I", state(live), 80)[0] == l4 + extra
                before_egress = counts(live)[1]
                short = ethernet(ip(proto, bodies[proto][:-1]), family, padding=128)
                tc_packet(root / "protocol_dispatch", short)
                fragmented = (ip(proto, body)[:6] + b"\x20\x00" + ip(proto, body)[8:]) if family == 4 else ipv6(44, bytes((proto, 0)) + bytes(6) + body)
                tc_packet(root / "protocol_dispatch", ethernet(fragmented, family))
                assert counts(live)[1] == before_egress, "malformed/padded/fragmented packet dispatched"
                for suffix in ("next_deadbeef", "rollback_1234abcd"):
                    retired = live.with_name(f"{proto}_{suffix}")
                    retired.mkdir()
                    run("bpftool", "prog", "pin", "pinned", live / "prog", retired / "prog")
                before_state = state(live)
                old_program = handlers.pinned_program_id(live / "prog")
                assert handlers.load_protocol_handler(root, proto, fixture)
                assert not list(live.parent.glob(f"{proto}_next_*"))
                assert not list(live.parent.glob(f"{proto}_rollback_*"))
                assert state(live) == before_state and handlers._pinned_map_id(live / "maps/proto_metrics") == private_id
                assert handlers.pinned_program_id(live / "prog") != old_program
                tc_packet(root / "protocol_dispatch", packet)
                assert counts(live)[1] == before_egress + 1
            incompatible = objects / "incompatible.o"
            incompatible.write_bytes(fixture.read_bytes().replace(b"protocol-fixture-v1", b"protocol-fixture-v2"))
            old_ids = [handlers.pinned_program_id(live / pin) for pin in ("prog", "egress")]
            try:
                handlers.load_protocol_handler(root, proto, incompatible)
            except RuntimeError as exc:
                assert "not compatible" in str(exc)
            else:
                raise AssertionError("incompatible protocol schema published")
            assert [handlers.pinned_program_id(live / pin) for pin in ("prog", "egress")] == old_ids
            original_update = handlers.prog_array_update
            failed = False
            before_ingress = counts(live)[0]
            def fail_publish(table, key, pin):
                nonlocal failed
                if table.name == "proto_handlers" and not failed:
                    failed = True
                    assert run_packet(root, ifindex, ethernet(ipv4(proto, bodies[proto]), 4))[0] == 2
                    raise RuntimeError("injected protocol publication failure")
                return original_update(table, key, pin)
            with mock.patch.object(handlers, "prog_array_update", side_effect=fail_publish):
                try:
                    handlers.load_protocol_handler(root, proto, fixture)
                except RuntimeError as exc:
                    assert "previous generation restored" in str(exc)
                else:
                    raise AssertionError("injected publication failure ignored")
            assert failed and counts(live)[0] == before_ingress + 1
            assert [handlers.pinned_program_id(live / pin) for pin in ("prog", "egress")] == old_ids
            assert handlers.handler_egress_id(root, 4, proto) == old_ids[1]
            tc_packet(root / "protocol_dispatch", ethernet(ipv4(proto, bodies[proto]), 4))
            tc_map = root / "tc_proto_handlers"
            handlers.prog_array_delete(tc_map, proto)
            misses = counter(root / "handler_eg_stats", 5)
            before_egress = counts(live)[1]
            tc_packet(root / "protocol_dispatch", ethernet(ipv4(proto, bodies[proto]), 4))
            assert counts(live)[1] == before_egress and counter(root / "handler_eg_stats", 5) == misses + 1
            handlers.prog_array_update(tc_map, proto, live / "egress")
            original_delete = handlers.prog_array_delete
            def fail_delete(table, key):
                return False if table.name == "proto_handlers" else original_delete(table, key)
            with mock.patch.object(handlers, "prog_array_delete", side_effect=fail_delete):
                try:
                    handlers.unload_protocol_handler(root, proto)
                except RuntimeError as exc:
                    assert "previous generation restored" in str(exc)
                else:
                    raise AssertionError("failed removal discarded active pins")
            assert [handlers.pinned_program_id(live / pin) for pin in ("prog", "egress")] == old_ids
            assert handlers._pinned_map_id(live / "maps/proto_metrics") == private_id
            handlers.unload_protocol_handler(root, proto)
            assert handlers.prog_array_entry_id(root / "proto_handlers", proto) is None
            assert handlers.prog_array_entry_id(tc_map, proto) is None
            assert handlers.handler_egress_id(root, 4, proto) is None and not live.exists()
            print(f"PASS {name}: raw TC context, shared state, real TC chain, reload, rollback, schema rejection and unload", flush=True)
    finally:
        run("tc", "qdisc", "del", "dev", iface, "clsact")


if __name__ == "__main__":
    main(Path(sys.argv[1]), sys.argv[2], Path(sys.argv[3]))
