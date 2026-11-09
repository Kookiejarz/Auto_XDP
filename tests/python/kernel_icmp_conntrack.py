"""Real IPv4/IPv6 ICMP kfunc checks in test_integration.sh's private namespaces."""
from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path
import socket
import struct
import subprocess
import sys
import time

from auto_xdp.bpf.conntrack import configure
from auto_xdp.telemetry.events import decode_event
from kernel_packet_telemetry import checksum, counter, run_packet
from pkt_relay import RingBufReader

REASON = 66  # ICMP_REPLY_UNTRACKED


def run(*args: str, **kwargs) -> str:
    return subprocess.check_output(args, text=True, **kwargs)


def send(family: int, source: str, target: str, kind: int, ident: int) -> None:
    packet = struct.pack("!BBHHH", kind, 0, 0, ident, 1) + b"axdp-icmp-test"
    if family == socket.AF_INET:
        packet = packet[:2] + struct.pack("!H", checksum(packet)) + packet[4:]
    protocol = socket.IPPROTO_ICMP if family == socket.AF_INET else socket.IPPROTO_ICMPV6
    with socket.socket(family, socket.SOCK_RAW, protocol) as sock:
        sock.bind((source, 0))
        sock.sendto(packet, (target, 0))  # IPv6 raw ICMP checksum is supplied by Linux.


def frame(family: int, source: str, target: str, ident: int, *,
          code: int = 0, sequence: int = 1, kind: int | None = None) -> bytes:
    v4 = family == socket.AF_INET
    kind = (0 if v4 else 129) if kind is None else kind
    src, dst = socket.inet_pton(family, source), socket.inet_pton(family, target)
    segment = struct.pack("!BBHHH", kind, code, 0, ident, sequence) + b"axdp-icmp-test"
    pseudo = b"" if v4 else src + dst + struct.pack("!I3xB", len(segment), 58)
    segment = segment[:2] + struct.pack("!H", checksum(pseudo + segment)) + segment[4:]
    if v4:
        ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(segment), 1, 0, 64, 1, 0, src, dst)
        ip = ip[:10] + struct.pack("!H", checksum(ip)) + ip[12:]
    else:
        ip = struct.pack("!IHBB16s16s", 6 << 28, len(segment), 58, 64, src, dst)
    return bytes.fromhex("020000000001020000000002" + ("0800" if v4 else "86dd")) + ip + segment


def expect(pin: Path, ifindex: int, packet: bytes, verdict: int) -> None:
    before = counter(pin / "pkt_counters", REASON)
    result, _ = run_packet(pin, ifindex, packet)
    assert result == verdict, f"expected XDP {verdict}, got {result}; packet={packet.hex()}"
    delta = counter(pin / "pkt_counters", REASON) - before
    assert delta == int(verdict == 1), f"wrong rejection counter: {delta}"


def entries(v4: bool, ident: int) -> list[str]:
    output = run("conntrack", "-L", "-f", "ipv4" if v4 else "ipv6",
                 "-p", "icmp" if v4 else "icmpv6", stderr=subprocess.DEVNULL)
    return [line for line in output.splitlines() if f"id={ident}" in line.split()]


@contextmanager
def nft_table(family: str, name: str, rules: str):
    subprocess.run(["nft", "-f", "-"], input=f"add table {family} {name}\n" + rules,
                   text=True, check=True)
    try:
        yield
    finally:
        subprocess.run(["nft", "delete", "table", family, name], check=True)


def check_family(pin: Path, ns: str, family: int, local: str, other: str, alias: str) -> None:
    v4 = family == socket.AF_INET
    version, request_type, reply_type = ("4", 8, 0) if v4 else ("6", 128, 129)
    ifindex = socket.if_nametoindex("axdp_v0")
    ident = 50100 if v4 else 50200
    # Exercise actual attached ingress and ordinary ping in both directions.
    run("ping", f"-{version}", "-n", "-c", "2", "-i", "0.05", "-W", "2", other)
    run("ip", "netns", "exec", ns, "ping", f"-{version}", "-n", "-c", "2",
        "-i", "0.05", "-W", "2", local)
    before = counter(pin / "pkt_counters", REASON)
    run("ip", "netns", "exec", ns, sys.executable, __file__, "--send",
        str(family), other, local, str(reply_type), str(ident))
    assert counter(pin / "pkt_counters", REASON) > before, "live unsolicited reply passed"

    # Suppress automatic responses: keep the entry UNREPLIED while test-run
    # probes the first reply. Lookup must neither require nor set SEEN_REPLY.
    setting = f"net.ipv{version}.icmp_echo_ignore_all" if v4 else "net.ipv6.icmp.echo_ignore_all"
    saved = run("ip", "netns", "exec", ns, "sysctl", "-n", setting).strip()
    run("ip", "netns", "exec", ns, "sysctl", "-qw", f"{setting}=1")
    try:
        ident += 1
        send(family, local, other, request_type, ident)
        rows = entries(v4, ident)
        assert len(rows) == 1 and "[UNREPLIED]" in rows[0], rows
        reply = frame(family, other, local, ident)
        expect(pin, ifindex, reply, 2)
        assert "[UNREPLIED]" in entries(v4, ident)[0], "lookup changed conntrack state"
        # Linux conntrack tracks the Echo ID, not each individual sequence.
        expect(pin, ifindex, frame(family, other, local, ident, sequence=77), 2)
        for packet in (frame(family, other, local, ident + 1),
                       frame(family, alias, local, ident),
                       frame(family, other, alias, ident),
                       frame(family, other, local, ident, code=1)):
            expect(pin, ifindex, packet, 1)
        reader = RingBufReader(str(pin / "pkt_ringbuf"))
        try:
            list(reader.drain())
            expect(pin, ifindex, frame(family, other, local, ident + 1), 1)
            events = [decode_event(raw) for raw in reader.drain()]
            assert len(events) == 1 and events[0]["reason_id"] == REASON, events
        finally:
            reader.close()
        peer_index = run("ip", "netns", "exec", ns, "cat", "/sys/class/net/axdp_v1/ifindex").strip()
        # ip netns exec remounts sysfs and hides our private bpffs. Enter only
        # the network namespace so the pinned program remains accessible.
        run("nsenter", f"--net=/run/netns/{ns}", sys.executable, __file__, "--probe",
            str(pin), peer_index, reply.hex())

        # Non-echo control traffic must retain its pre-existing treatment.
        controls = ((3, 4), (11, 0), (12, 0)) if v4 else ((1, 0), (2, 0), (3, 0), (4, 0), (135, 0))
        for kind, code in controls:
            expect(pin, ifindex, frame(family, other, local, 0, kind=kind, code=code), 2)

        timeout = Path("/proc/sys/net/netfilter/nf_conntrack_icmp" + ("" if v4 else "v6") + "_timeout")
        saved_timeout = timeout.read_text()
        try:
            timeout.write_text("1\n")
            ident += 2
            send(family, local, other, request_type, ident)
            expect(pin, ifindex, frame(family, other, local, ident), 2)
            time.sleep(1.2)
            expect(pin, ifindex, frame(family, other, local, ident), 1)
        finally:
            timeout.write_text(saved_timeout)

        nft_family, protocol = ("ip", "icmp") if v4 else ("ip6", "ipv6-icmp")
        ident += 1
        with nft_table(nft_family, "axdp_icmp_zone", f'''add chain {nft_family} axdp_icmp_zone out {{ type filter hook output priority raw; }}
add rule {nft_family} axdp_icmp_zone out meta l4proto {protocol} ct zone set 42
'''):
            send(family, local, other, request_type, ident)
            assert any("zone=42" in row for row in entries(v4, ident)), "test did not use zone 42"
            expect(pin, ifindex, frame(family, other, local, ident), 1)
        ident += 1
        with nft_table(nft_family, "axdp_icmp_notrack", f'''add chain {nft_family} axdp_icmp_notrack out {{ type filter hook output priority raw; }}
add rule {nft_family} axdp_icmp_notrack out meta l4proto {protocol} notrack
'''):
            send(family, local, other, request_type, ident)
            assert not entries(v4, ident), "NOTRACK fixture unexpectedly created a flow"
            expect(pin, ifindex, frame(family, other, local, ident), 1)

        ident += 1
        run("ip", f"-{version}", "addr", "add", alias + ("/24" if v4 else "/64"),
            "dev", "axdp_v0", *([] if v4 else ["nodad"]))
        try:
            with nft_table(nft_family, "axdp_icmp_nat", f'''add chain {nft_family} axdp_icmp_nat post {{ type nat hook postrouting priority srcnat; }}
add rule {nft_family} axdp_icmp_nat post meta l4proto {protocol} snat to {alias}
'''):
                send(family, local, other, request_type, ident)
                assert any(f"dst={alias}" in row for row in entries(v4, ident)), "SNAT fixture failed"
                expect(pin, ifindex, frame(family, other, alias, ident), 2)
                expect(pin, ifindex, frame(family, other, local, ident), 1)
        finally:
            run("ip", f"-{version}", "addr", "del", alias + ("/24" if v4 else "/64"), "dev", "axdp_v0")
        print(f"IPv{version}: live ping/drop, first reply, read-only lookup, tuple/namespace/zone isolation, "
              "telemetry, control messages, expiry, NOTRACK and SNAT passed")
    finally:
        run("ip", "netns", "exec", ns, "sysctl", "-qw", f"{setting}={saved}")


def main() -> None:
    pin, ns = Path(sys.argv[1]), sys.argv[2]
    configure()
    try:
        for family, local, other, alias in (
            (socket.AF_INET, "10.99.0.1", "10.99.0.2", "10.99.0.3"),
            (socket.AF_INET6, "2001:db8:99::1", "2001:db8:99::2", "2001:db8:99::3"),
        ):
            check_family(pin, ns, family, local, other, alias)
    finally:
        configure(remove=True)


if __name__ == "__main__":
    if sys.argv[1] == "--send":
        send(int(sys.argv[2]), sys.argv[3], sys.argv[4], int(sys.argv[5]), int(sys.argv[6]))
    elif sys.argv[1] == "--probe":
        expect(Path(sys.argv[2]), int(sys.argv[3]), bytes.fromhex(sys.argv[4]), 1)
    else:
        main()
