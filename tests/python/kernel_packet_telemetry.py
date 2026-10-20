"""Real BPF_PROG_TEST_RUN telemetry checks; invoked by the kernel Bash suite.

The caller temporarily detaches its private veth so counter deltas are exact.
No BPF helpers, maps, event readers, or verdicts are mocked here.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import socket
import struct
import subprocess
import tempfile

from auto_xdp.telemetry.events import decode_event
from auto_xdp.admin.stats import _read_byte_counters
from pkt_relay import RingBufReader


SOURCE = socket.inet_aton("10.99.0.3")
DESTINATION = socket.inet_aton("10.99.0.1")
SPORT = 40123


def checksum(data: bytes) -> int:
    data += b"\0" * (len(data) % 2)
    value = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while value >> 16:
        value = (value & 65535) + (value >> 16)
    return (~value) & 65535


def frame(protocol: int, segment: bytes, ihl: int = 5) -> bytes:
    ip = struct.pack("!BBHHHBBH4s4s", 0x40 | ihl, 0, 20 + len(segment),
                     123, 0, 64, protocol, 0, SOURCE, DESTINATION)
    ip = ip[:10] + struct.pack("!H", checksum(ip)) + ip[12:]
    return bytes.fromhex("0200000000010200000000020800") + ip + segment


def tcp_frame(port: int, flags: int, payload: bytes = b"", *,
              sequence: int = 12345, acknowledgement: int = 67890,
              options: bytes = b"") -> bytes:
    assert len(options) % 4 == 0
    segment = struct.pack("!HHIIHHHH", SPORT, port, sequence, acknowledgement,
                          ((5 + len(options) // 4) << 12) | flags, 65535, 0, 0) + options + payload
    pseudo = SOURCE + DESTINATION + struct.pack("!BBH", 0, 6, len(segment))
    segment = segment[:16] + struct.pack("!H", checksum(pseudo + segment)) + segment[18:]
    return frame(6, segment)


def counter(pin: Path, key: int) -> int:
    row = json.loads(subprocess.check_output([
        "bpftool", "-j", "map", "lookup", "pinned", str(pin), "key", "hex",
        *struct.pack("<I", key).hex(" ").split(),
    ], text=True))

    def scalar(value: object) -> int:
        if isinstance(value, list):
            return int.from_bytes(bytes(int(v, 0) if isinstance(v, str) else v
                                        for v in value), "little")
        return int(value, 0) if isinstance(value, str) else int(value)

    if "values" in row:
        return sum(scalar(item["value"]) for item in row["values"])
    return scalar(row["value"])


def run_packet(pin: Path, ifindex: int, packet: bytes) -> tuple[int, bytes]:
    with tempfile.TemporaryDirectory(prefix="axdp-telemetry-packet-") as directory:
        root = Path(directory)
        (root / "input").write_bytes(packet)
        # Test-run context uses offsets into data_in, not kernel pointers;
        # data_end=0 would intentionally present an empty packet to XDP.
        # xdp_md: data, data_end, data_meta, ingress_ifindex, rx_queue_index, egress_ifindex.
        (root / "context").write_bytes(struct.pack("<6I", 0, len(packet), 0, ifindex, 0, 0))
        result = json.loads(subprocess.check_output([
            "bpftool", "-j", "prog", "run", "pinned", str(pin / "prog"),
            "data_in", str(root / "input"), "data_out", str(root / "output"),
            "ctx_in", str(root / "context"), "repeat", "1",
        ], text=True))
        return int(result["retval"]), (root / "output").read_bytes()


def byte_counts(pin: Path) -> list[int]:
    totals = _read_byte_counters(str(pin))
    assert all(value >= 0 for value in totals), f"traffic totals unavailable: {totals}"
    return list(totals)


def check_event(raw: bytes, *, reason: int, ifindex: int, packet: bytes,
                protocol: int, family: int, dport: int, verdict: int) -> None:
    assert len(raw) == 64, f"event length {len(raw)}, expected exact v2 size 64"
    assert raw[44:48] == bytes((protocol, family, verdict, reason)), raw.hex()
    assert struct.unpack_from("<IIB", raw, 48) == (ifindex, len(packet), 2), raw.hex()
    assert raw[57:] == bytes(7), f"reserved bytes not zero: {raw.hex()}"
    assert struct.unpack_from("<Q", raw)[0] > 0
    if family == 2:
        assert raw[8:24] == SOURCE + bytes(12)
        assert raw[24:40] == DESTINATION + bytes(12)
        assert struct.unpack_from("!HH", raw, 40) == (SPORT, dport)
    else:
        assert raw[8:44] == bytes(36), "unclassified event invented addresses or ports"
    decoded = decode_event(raw)
    assert decoded is not None and decoded["reason_id"] == reason
    assert decoded["ifindex"] == ifindex and decoded["pkt_len"] == len(packet)
    print(json.dumps(decoded, sort_keys=True))


def check_packet(pin: Path, reader: RingBufReader, ifindex: int, packet: bytes,
                 reason: int, protocol: int, family: int, dport: int = 0,
                 expected_verdict: int = 1) -> None:
    assert not list(reader.drain()), "unexpected event before controlled test run"
    before = byte_counts(pin)
    emitted = counter(pin / "pkt_counters", 56)
    verdict, _ = run_packet(pin, ifindex, packet)
    assert verdict == expected_verdict, f"expected XDP action {expected_verdict}, got {verdict}"
    after = byte_counts(pin)
    dropped = int(verdict == 1)
    delta = [end - start for start, end in zip(before, after)]
    expected = [len(packet), len(packet) * dropped, 1, dropped]
    assert delta == expected, f"byte counter delta {delta}, expected {expected}; before={before}, after={after}"
    records = list(reader.drain())
    assert len(records) == 1, f"expected one event, got {len(records)}"
    check_event(records[0], reason=reason, ifindex=ifindex, packet=packet,
                protocol=protocol, family=family, dport=dport, verdict=expected_verdict)
    assert counter(pin / "pkt_counters", 56) - emitted == 1


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("events", "cookie"))
    parser.add_argument("pin_dir", type=Path)
    parser.add_argument("iface")
    parser.add_argument("--port", type=int, default=7710)
    args = parser.parse_args()
    pin, ifindex = args.pin_dir, socket.if_nametoindex(args.iface)
    reader = RingBufReader(str(pin / "pkt_ringbuf"))
    try:
        list(reader.drain())
        if args.mode == "events":
            udp = struct.pack("!HHHH", SPORT, 7790, 26, 0) + b"telemetry-contract"
            packet = frame(17, udp)
            check_packet(pin, reader, ifindex, packet, 46, 17, 2, 7790)
            check_packet(pin, reader, ifindex, packet[:30], 49, 0, 0)
            check_packet(pin, reader, ifindex, frame(17, udp, ihl=4), 50, 0, 0)
        else:
            packet = tcp_frame(args.port, 0x02)
            before = byte_counts(pin)
            sent = counter(pin / "pkt_counters", 39)
            verdict, reply = run_packet(pin, ifindex, packet)
            assert verdict == 3, f"expected cookie XDP_TX, got {verdict}"
            assert len(reply) != len(packet), "test did not exercise cookie packet resizing"
            after = byte_counts(pin)
            delta = [end - start for start, end in zip(before, after)]
            assert delta == [len(packet), 0, 1, 0], f"cookie byte delta {delta}; input={len(packet)} reply={len(reply)}"
            assert counter(pin / "pkt_counters", 39) - sent == 1
            assert not list(reader.drain()), "SYN challenge unexpectedly emitted an ALLOW event"
            print(f"cookie resize: inbound={len(packet)}, reply={len(reply)}, accounted={after[0] - before[0]}")
            tcp_offset = 14 + (reply[14] & 15) * 4
            server_sequence = struct.unpack_from("!I", reply, tcp_offset + 4)[0]
            ack = tcp_frame(args.port, 0x10, sequence=12346,
                            acknowledgement=(server_sequence + 1) & 0xFFFFFFFF)
            check_packet(pin, reader, ifindex, ack, 40, 6, 2, args.port,
                         expected_verdict=2)
            invalid_ack = tcp_frame(args.port, 0x10, sequence=12346,
                                    acknowledgement=((server_sequence + 1) ^ 0x80000000) & 0xFFFFFFFF,
                                    options=b"\x01" * 8)
            check_packet(pin, reader, ifindex, invalid_ack, 41, 6, 2, args.port)
        assert reader.invalid_records == 0
    finally:
        reader.close()


if __name__ == "__main__":
    main()
