"""Check declared IP boundaries in the real, privately loaded XDP program.

Invoked by test_integration.sh, including with SYN cookies enabled. Ethernet
padding must remain legal without supplying missing transport/header bytes.
"""
from __future__ import annotations

import argparse
from pathlib import Path
import re
import socket
import struct
import subprocess

from kernel_packet_telemetry import checksum, counter, run_packet


ROOT = Path(__file__).resolve().parents[2]
SOURCE4 = socket.inet_aton("10.99.0.3")
DEST4 = socket.inet_aton("10.99.0.1")
SOURCE6 = socket.inet_pton(socket.AF_INET6, "2001:db8:99::3")
DEST6 = socket.inet_pton(socket.AF_INET6, "2001:db8:99::1")


def ethernet(body: bytes, family: int, *, padding: int = 0,
             vlan: bool = False) -> bytes:
    ethertype = 0x0800 if family == 4 else 0x86DD
    header = bytes.fromhex("020000000001020000000002")
    if vlan:
        header += struct.pack("!HH", 0x8100, 7)
    return (header + struct.pack("!H", ethertype) + body).ljust(padding, b"\0")


def ipv4(proto: int, segment: bytes, *, total: int | None = None,
         options: bytes = b"", version: int = 4) -> bytes:
    assert len(options) % 4 == 0
    size = 20 + len(options)
    header = struct.pack("!BBHHHBBH4s4s", version << 4 | size // 4, 0,
                         size + len(segment) if total is None else total,
                         123, 0, 64, proto, 0, SOURCE4, DEST4) + options
    return header[:10] + struct.pack("!H", checksum(header)) + header[12:] + segment


def ipv6(proto: int, segment: bytes, *, payload: int | None = None,
         version: int = 6) -> bytes:
    return struct.pack("!IHBB16s16s", version << 28,
                       len(segment) if payload is None else payload,
                       proto, 64, SOURCE6, DEST6) + segment


def tcp(port: int, family: int, *, options: bytes = b"") -> bytes:
    segment = struct.pack("!HHIIHHHH", 40123, port, 12345, 0,
                          (5 + len(options) // 4) << 12 | 2, 65535, 0, 0) + options
    if family == 4:
        pseudo = SOURCE4 + DEST4 + struct.pack("!BBH", 0, 6, len(segment))
    else:
        pseudo = SOURCE6 + DEST6 + struct.pack("!I3xB", len(segment), 6)
    return segment[:16] + struct.pack("!H", checksum(pseudo + segment)) + segment[18:]


def udp(port: int, family: int, body: bytes = b"", *, length: int | None = None) -> bytes:
    segment = struct.pack("!HHHH", 40123, port,
                          8 + len(body) if length is None else length, 0) + body
    if family == 4:
        pseudo = SOURCE4 + DEST4 + struct.pack("!BBH", 0, 17, len(segment))
    else:
        pseudo = SOURCE6 + DEST6 + struct.pack("!I3xB", len(segment), 17)
    return segment[:6] + struct.pack("!H", checksum(pseudo + segment) or 65535) + segment[8:]


def cases(port: int):
    """Yield (name, Ethernet frame, drop reason or None, cookie candidate)."""
    t4, t6 = tcp(port, 4), tcp(port, 6)
    u4, u6 = udp(port, 4), udp(port, 6)
    icmp4 = b"\0" * 8  # Echo reply, not subject to request rate limiting.
    icmp6 = b"\x81" + b"\0" * 7
    hop = bytes((6, 0)) + b"\0" * 6
    malformed = [
        ("ip_short_total", ipv4(6, t4, total=10), 4, "IP_HEADER_INVALID"),
        ("ip_zero_total", ipv4(6, t4, total=0), 4, "IP_HEADER_INVALID"),
        ("ip_truncated_total", ipv4(6, t4, total=1450), 4, "PACKET_TRUNCATED"),
        ("ip_wrong_version", ipv4(6, t4, version=6), 4, "IP_HEADER_INVALID"),
        ("ip_options_exceed_total", ipv4(6, t4, options=b"\x01" * 4, total=20), 4, "IP_HEADER_INVALID"),
        ("ip_tcp_in_padding", ipv4(6, t4, total=20), 4, "PACKET_TRUNCATED"),
        ("ip_tcp_header_short", ipv4(6, t4, total=39), 4, "PACKET_TRUNCATED"),
        ("ip_tcp_options_in_padding", ipv4(6, tcp(port, 4, options=b"\x01" * 4), total=40), 4, "TCP_MALFORM_DOFF"),
        ("ip_udp_header_short", ipv4(17, u4, total=27), 4, "PACKET_TRUNCATED"),
        ("ip_udp_body_in_padding", ipv4(17, udp(port, 4, b"body"), total=28), 4, "UDP_MALFORM_LEN"),
        ("ip_icmp_in_padding", ipv4(1, icmp4, total=27), 4, "PACKET_TRUNCATED"),
        ("ip_sctp_in_padding", ipv4(132, u4, total=27), 4, "PACKET_TRUNCATED"),
        ("ip6_wrong_version", ipv6(6, t6, version=4), 6, "IP_HEADER_INVALID"),
        ("ip6_truncated_payload", ipv6(6, t6, payload=1450), 6, "PACKET_TRUNCATED"),
        ("ip6_tcp_zero_payload", ipv6(6, t6, payload=0), 6, "PACKET_TRUNCATED"),
        ("ip6_tcp_header_short", ipv6(6, t6, payload=19), 6, "PACKET_TRUNCATED"),
        ("ip6_tcp_options_in_padding", ipv6(6, tcp(port, 6, options=b"\x01" * 4), payload=20), 6, "TCP_MALFORM_DOFF"),
        ("ip6_udp_header_short", ipv6(17, u6, payload=7), 6, "PACKET_TRUNCATED"),
        ("ip6_udp_body_in_padding", ipv6(17, udp(port, 6, b"body"), payload=8), 6, "UDP_MALFORM_LEN"),
        ("ip6_icmp_in_padding", ipv6(58, icmp6, payload=7), 6, "PACKET_TRUNCATED"),
        ("ip6_sctp_in_padding", ipv6(132, u6, payload=7), 6, "PACKET_TRUNCATED"),
        ("ip6_extension_in_padding", ipv6(0, hop + t6, payload=7), 6, "IPV6_EXTENSION_INVALID"),
        ("ip6_extension_tcp_in_padding", ipv6(0, hop + t6, payload=8), 6, "PACKET_TRUNCATED"),
        ("ip6_extension_chain_in_padding", ipv6(0, bytes((60, 0)) + b"\0" * 6 + hop + t6, payload=8), 6, "IPV6_EXTENSION_INVALID"),
        ("ip6_fragment_in_padding", ipv6(44, bytes((6, 0)) + b"\0" * 6 + t6, payload=7), 6, "IPV6_EXTENSION_INVALID"),
    ]
    for name, packet, family, reason in malformed:
        for vlan in (False, True):
            yield name + ("_vlan" if vlan else ""), ethernet(packet, family, padding=128, vlan=vlan), reason, False
    for family, writer, segment, datagram, icmp in (
        (4, ipv4, t4, u4, icmp4), (6, ipv6, t6, u6, icmp6),
    ):
        for vlan in (False, True):
            for padding in (0, 60, 128):
                suffix = f"_v{family}_vlan{int(vlan)}_pad{padding}"
                yield "valid_tcp" + suffix, ethernet(writer(6, segment), family, padding=padding, vlan=vlan), None, True
                yield "valid_udp" + suffix, ethernet(writer(17, datagram), family, padding=padding, vlan=vlan), None, False
                yield "valid_icmp" + suffix, ethernet(writer(1 if family == 4 else 58, icmp), family, padding=padding, vlan=vlan), None, False
    yield "valid_ip_options", ethernet(ipv4(6, t4, options=b"\x01" * 4), 4), None, True
    yield "valid_ip6_extension", ethernet(ipv6(0, hop + t6), 6), None, True
    yield "valid_ip6_no_next_header", ethernet(ipv6(59, b""), 6, padding=128), None, False


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("pin_dir", type=Path)
    parser.add_argument("iface")
    parser.add_argument("--port", type=int, default=7711)
    parser.add_argument("--cookie", action="store_true")
    args = parser.parse_args()
    counters = {name: int(value) for name, value in re.findall(
        r"\bCNT_(\w+)\s*=\s*(\d+)", (ROOT / "bpf/include/counters.h").read_text())}
    for name, value in (("tcp_whitelist", struct.pack("<IIQQ", 1, 0, 0, 0)),
                        ("udp_whitelist", struct.pack("<I", 1))):
        subprocess.run(["bpftool", "map", "update", "pinned", str(args.pin_dir / name),
                        "key", "hex", *struct.pack("<I", args.port).hex(" ").split(),
                        "value", "hex", *value.hex(" ").split()], check=True)
    pin = args.pin_dir / "pkt_counters"
    ifindex = socket.if_nametoindex(args.iface)
    for name, packet, reason, candidate in cases(args.port):
        keys = [counters[k] for k in ("SYN_COOKIE_CHALLENGE", "SYN_COOKIE_SENT")]
        if reason:
            keys.append(counters[reason])
        before = {k: counter(pin, k) for k in keys}
        verdict, _ = run_packet(args.pin_dir, ifindex, packet)
        expected = 1 if reason else 3 if args.cookie and candidate else 2
        assert verdict == expected, f"{name}: action {verdict}, expected {expected}"
        delta = {k: counter(pin, k) - before[k] for k in keys}
        if reason:
            assert delta == {keys[0]: 0, keys[1]: 0, counters[reason]: 1}, (name, delta)
        elif args.cookie and candidate:
            assert delta == {keys[0]: 1, keys[1]: 1}, (name, delta)
        print(f"PASS {name}: action={verdict}, reason={reason or 'valid'}", flush=True)


if __name__ == "__main__":
    main()
