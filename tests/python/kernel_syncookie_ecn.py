"""Cookie handshakes must negotiate ECN the way a classic-ECN listener would.

Invoked by test_integration.sh. The client side runs inside the fixture's peer
namespace; the server side runs on the protected host.

sniff IFACE PORT OUT READY  capture the client's view of one connection
server PORT READY BYTES   accept one connection and send BYTES
client HOST PORT BYTES    receive BYTES
check OUT CLIENT_TCP_ECN [host-refuses]  assert the negotiated ECN behaviour
"""
import json
import socket
import struct
import sys
import time


def flags_of(tcp):
    names = [name for bit, name in ((0x80, "CWR"), (0x40, "ECE"), (0x20, "URG"),
                                    (0x10, "ACK"), (0x08, "PSH"), (0x04, "RST"),
                                    (0x02, "SYN"), (0x01, "FIN")) if tcp[13] & bit]
    if tcp[12] & 1:
        names.insert(0, "AE")
    return "|".join(names)


def sniff(iface, port, out, ready):
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
    sock.bind((iface, 0))
    sock.settimeout(0.1)
    open(ready, "w").write("ready")
    packets = []
    deadline = time.monotonic() + 8
    closed_at = None
    while time.monotonic() < deadline and (closed_at is None or time.monotonic() < closed_at + 0.3):
        try:
            frame, addr = sock.recvfrom(65535)
        except socket.timeout:
            continue
        if frame[12:14] != b"\x08\x00" or frame[23] != 6:
            continue
        ihl = (frame[14] & 15) * 4
        tcp = frame[14 + ihl:]
        if port not in struct.unpack_from("!HH", tcp):
            continue
        payload = struct.unpack_from("!H", frame, 16)[0] - ihl - (tcp[12] >> 4) * 4
        packet = {"dir": "out" if addr[2] == socket.PACKET_OUTGOING else "in",
                  "flags": flags_of(tcp), "payload": payload, "ip_ecn": frame[15] & 3,
                  "window": struct.unpack_from("!H", tcp, 14)[0]}
        packets.append(packet)
        if packet["dir"] == "out" and "FIN" in packet["flags"]:
            closed_at = time.monotonic()
    with open(out, "w") as handle:
        json.dump(packets, handle)


def server(port, ready, total):
    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("10.99.0.1", port))
    listener.listen()
    open(ready, "w").write("ready")
    listener.settimeout(10)
    conn, _ = listener.accept()
    conn.settimeout(10)
    conn.sendall(b"x" * total)
    conn.shutdown(socket.SHUT_WR)
    conn.recv(1)
    conn.close()


def client(host, port, total):
    sock = socket.create_connection((host, port), timeout=10)
    received = 0
    while received < total:
        data = sock.recv(1 << 20)
        if not data:
            break
        received += len(data)
    sock.close()
    if received != total:
        raise SystemExit(f"received {received} of {total} bytes")


def check(out, client_ecn, host_ecn_refused=False):
    packets = json.load(open(out))
    requested = client_ecn in (1, 3) and not host_ecn_refused
    syn = next((p for p in packets if p["dir"] == "out" and p["flags"].endswith("SYN")
                and "ACK" not in p["flags"]), None)
    synack_index = next((i for i, p in enumerate(packets)
                         if p["dir"] == "in" and "SYN" in p["flags"] and "ACK" in p["flags"]), None)
    if syn is None or synack_index is None:
        raise SystemExit(f"tcp_ecn={client_ecn}: capture missed the SYN or SYN-ACK: {packets[:6]}")
    synack = packets[synack_index]
    third = next((p for p in packets[synack_index + 1:] if p["dir"] == "out"), None)
    if third is None:
        raise SystemExit(f"tcp_ecn={client_ecn}: capture missed the handshake ACK: {packets[:6]}")
    expected = "ECE|ACK|SYN" if requested else "ACK|SYN"
    problems = []
    # The XDP cookie SYN-ACK advertises its fixed bootstrap window; a native
    # listener answer would mean these rounds did not test the cookie path.
    if synack["window"] != 4096:
        problems.append(f"SYN-ACK window {synack['window']} is not the cookie bootstrap window")
    if synack["flags"] != expected or synack["ip_ecn"]:
        problems.append(f"SYN {syn['flags']} answered by {synack} (expected {expected}, Not-ECT)")
    if third["flags"] != "ACK" or third["payload"]:
        problems.append(f"handshake ACK carried ECN feedback or data: {third}")
    after = packets[synack_index + 1:]
    accecn = [p for p in after if "AE" in p["flags"]]
    if accecn:
        problems.append(f"AccECN feedback after a classic negotiation: {accecn[0]}")
    ect_data = [p for p in after if p["dir"] == "in" and p["payload"] and p["ip_ecn"]]
    if requested and not ect_data:
        problems.append("classic ECN negotiated but the server sent no ECT data")
    if not requested and ect_data:
        problems.append(f"server sent ECT data without ECN: {ect_data[0]}")
    if problems:
        raise SystemExit(f"tcp_ecn={client_ecn}: " + "; ".join(problems))
    print(f"tcp_ecn={client_ecn}: SYN {syn['flags']} -> SYN-ACK {synack['flags']}, "
          f"handshake ACK {third['flags']}, ECT data packets {len(ect_data)}")


if __name__ == "__main__":
    mode = sys.argv[1]
    if mode == "sniff":
        sniff(sys.argv[2], int(sys.argv[3]), sys.argv[4], sys.argv[5])
    elif mode == "server":
        server(int(sys.argv[2]), sys.argv[3], int(sys.argv[4]))
    elif mode == "client":
        client(sys.argv[2], int(sys.argv[3]), int(sys.argv[4]))
    else:
        check(sys.argv[2], int(sys.argv[3]), sys.argv[4:] == ["host-refuses"])
