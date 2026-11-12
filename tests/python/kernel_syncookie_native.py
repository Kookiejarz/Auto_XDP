"""Send real short SYN frames through native veth XDP, rather than TEST_RUN.

Invoked inside the private client namespace by test_integration.sh. The
unassigned source IP avoids kernel-generated RSTs for these raw-socket probes.
"""
from pathlib import Path
import socket
import struct
import sys
import time

import kernel_packet_telemetry as packets


def main():
    interface, server_mac, port = sys.argv[1:]
    port = int(port)
    client_mac = bytes.fromhex(
        (Path("/sys/class/net") / interface / "address").read_text().strip().replace(":", "")
    )
    server_mac = bytes.fromhex(server_mac.replace(":", ""))
    with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3)) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1 << 20)
        sock.bind((interface, 0))
        sock.settimeout(0.1)
        for padding in (54, 60):
            expected = {}
            for index in range(100):
                packets.SPORT = 41000 + index + (100 if padding == 60 else 0)
                sequence = 100000 + packets.SPORT
                frame = packets.tcp_frame(port, 2, sequence=sequence, acknowledgement=0)
                frame = server_mac + client_mac + frame[12:]
                frame = frame.ljust(padding, b"\0")
                assert len(frame) == padding
                expected[packets.SPORT] = sequence + 1
                sock.send(frame)

            received = set()
            deadline = time.monotonic() + 2
            while received != expected.keys() and time.monotonic() < deadline:
                try:
                    frame = sock.recv(2048)
                except socket.timeout:
                    continue
                if (len(frame) < 54 or frame[:12] != client_mac + server_mac
                        or frame[12:14] != b"\x08\x00" or frame[23] != 6):
                    continue
                ip = frame[14:34]
                segment = frame[34:14 + struct.unpack_from("!H", ip, 2)[0]]
                source_port, dest_port = struct.unpack_from("!HH", segment)
                if source_port != port or dest_port not in expected or segment[13] & 0x12 != 0x12:
                    continue
                assert ip[0] == 0x45 and ip[12:20] == packets.DESTINATION + packets.SOURCE
                assert packets.checksum(ip) == 0, "invalid IPv4 checksum"
                pseudo = ip[12:20] + struct.pack("!BBH", 0, 6, len(segment))
                assert packets.checksum(pseudo + segment) == 0, "invalid TCP checksum"
                assert struct.unpack_from("!I", segment, 8)[0] == expected[dest_port]
                assert len(segment) == (segment[12] >> 4) * 4 == 24
                assert struct.unpack_from("!H", segment, 14)[0] > 0, "zero cookie SYN-ACK receive window"
                received.add(dest_port)
            assert len(received) == 100, f"{padding}-byte SYNs: {len(received)}/100 SYN-ACKs"
            print(f"Native {padding}-byte SYNs: 100/100 valid SYN-ACKs")


if __name__ == "__main__":
    main()
