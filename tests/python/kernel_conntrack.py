"""Real socket/namespace regressions for XDP Linux-conntrack reply admission.

Run only through tests/bash/test_integration.sh inside its private fixture.
"""
from __future__ import annotations

from contextlib import contextmanager
import json
from pathlib import Path
import select
import socket
import struct
import subprocess
import sys
import time

from kernel_packet_telemetry import counter


def peer(family: int, kind: int, address: str) -> None:
    with socket.socket(family, kind) as sock:
        sock.bind((address, 0))
        sock.settimeout(4)
        if kind == socket.SOCK_STREAM:
            sock.listen(1)
        print(json.dumps(sock.getsockname()[1]), flush=True)
        conn = sock
        try:
            for line in sys.stdin:
                cmd = json.loads(line)
                op = cmd[0]
                if op == "accept":
                    conn, _ = sock.accept()
                    conn.settimeout(4)
                    result = True
                elif op == "send":
                    result = conn.send(cmd[1].encode()) if kind == socket.SOCK_STREAM else sock.sendto(
                        cmd[1].encode(), tuple(cmd[2]))
                elif op == "recv":
                    if kind == socket.SOCK_STREAM:
                        result = conn.recv(4096).decode()
                    else:
                        data, addr = sock.recvfrom(4096)
                        result = [data.decode(), addr[:2]]
                else:
                    raise AssertionError(cmd)
                print(json.dumps(result), flush=True)
        finally:
            if conn is not sock:
                conn.close()


@contextmanager
def remote(ns: str, family: int, kind: int, address: str):
    proc = subprocess.Popen(["ip", "netns", "exec", ns, sys.executable,
                             __file__, "--peer", str(family), str(kind), address],
                            stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
    try:
        yield proc, receive(proc)
    finally:
        proc.terminate()
        proc.wait(timeout=5)


def request(proc, *command):
    proc.stdin.write(json.dumps(command) + "\n")
    proc.stdin.flush()


def receive(proc):
    assert select.select([proc.stdout], [], [], 5)[0], "namespace peer timed out"
    line = proc.stdout.readline()
    assert line, f"namespace peer exited: {proc.poll()}"
    return json.loads(line)


def update(pin: Path, name: str, port: int, value: bytes) -> None:
    subprocess.run(["bpftool", "map", "update", "pinned", str(pin / name),
                    "key", "hex", *struct.pack("<I", port).hex(" ").split(),
                    "value", "hex", *value.hex(" ").split()], check=True)


def blocked(sock, pin: Path, reason: int, send) -> None:
    before = counter(pin / "pkt_counters", reason)
    send()
    sock.settimeout(0.3)
    try:
        data = sock.recv(4096)
    except TimeoutError:
        pass
    else:
        raise AssertionError(f"unexpected admission: {data!r}")
    assert counter(pin / "pkt_counters", reason) > before, "not rejected by expected XDP rule"
    sock.settimeout(3)


def send_udp(proc, data, address):
    request(proc, "send", data, address)
    receive(proc)


def check_udp(pin: Path, ns: str, family: int, local: str, other: str, nat=False):
    with remote(ns, family, socket.SOCK_DGRAM, other) as (proc, port), \
            socket.socket(family, socket.SOCK_DGRAM) as sock:
        sock.bind((local, 49997 if nat else 0))
        sock.settimeout(3)
        target = [local, sock.getsockname()[1]]
        # A matching-looking source port without a prior request is not enough.
        blocked(sock, pin, 46, lambda: send_udp(proc, "unsolicited", target))
        request(proc, "recv")
        sock.sendto(b"request", (other, port))
        data, wire_target = receive(proc)
        assert data == "request"
        if nat:
            assert wire_target[1] == 49998, wire_target
        send_udp(proc, "first-reply", wire_target)
        assert sock.recv(4096) == b"first-reply", "first UDP reply lost"
        # Restart hook activation without losing the established flow.
        from auto_xdp.bpf.conntrack import configure
        configure()
        send_udp(proc, "after-reload", wire_target)
        assert sock.recv(4096) == b"after-reload"
        with remote(ns, family, socket.SOCK_DGRAM, other) as (stranger, _):
            blocked(sock, pin, 46, lambda: send_udp(stranger, "wrong-source-port", wire_target))
        with socket.socket(family, socket.SOCK_DGRAM) as unrelated:
            unrelated.bind((local, 0))
            blocked(unrelated, pin, 46, lambda: send_udp(
                proc, "wrong-destination-port", [local, unrelated.getsockname()[1]]))


def check_tcp(ns: str, family: int, local: str, other: str):
    with remote(ns, family, socket.SOCK_STREAM, other) as (proc, port), \
            socket.socket(family, socket.SOCK_STREAM) as sock:
        sock.bind((local, 0))
        sock.settimeout(3)
        request(proc, "accept")
        sock.connect((other, port))  # First SYN-ACK must pass while CT is SYN_SENT.
        assert receive(proc)
        sock.sendall(b"request")
        request(proc, "recv")
        assert receive(proc) == "request"
        sock.shutdown(socket.SHUT_WR)
        request(proc, "recv")
        assert receive(proc) == ""
        request(proc, "send", "response-after-half-close")
        receive(proc)
        assert sock.recv(4096) == b"response-after-half-close"


def check_udp_expiry(pin: Path, ns: str, family: int, local: str, other: str):
    # This suite runs in a private netns. Restore its setting even on failure;
    # a short unreplied timeout avoids flushing unrelated CT entries.
    timeout = Path("/proc/sys/net/netfilter/nf_conntrack_udp_timeout")
    saved = timeout.read_text()
    try:
        timeout.write_text("1\n")
        with remote(ns, family, socket.SOCK_DGRAM, other) as (proc, port), \
                socket.socket(family, socket.SOCK_DGRAM) as sock:
            sock.bind((local, 0))
            request(proc, "recv")
            sock.sendto(b"will-expire", (other, port))
            assert receive(proc)[0] == "will-expire"
            time.sleep(1.2)
            blocked(sock, pin, 46, lambda: send_udp(
                proc, "too-late", [local, sock.getsockname()[1]]))
    finally:
        timeout.write_text(saved)


def check_inbound_udp(pin: Path, ns: str, family: int, local: str, other: str):
    with remote(ns, family, socket.SOCK_DGRAM, other) as (proc, port), \
            socket.socket(family, socket.SOCK_DGRAM) as sock:
        sock.bind((local, 0))
        sock.settimeout(3)
        target = [local, sock.getsockname()[1]]
        update(pin, "udp_whitelist", target[1], struct.pack("<I", 1))
        send_udp(proc, "client-request", target)
        assert sock.recv(4096) == b"client-request"
        request(proc, "recv")
        sock.sendto(b"server-response", (other, port))
        assert receive(proc)[0] == "server-response"
        # Exceed a one-byte aggregate budget regardless of the current window.
        update(pin, "udp_port_policies", target[1], struct.pack("<6I", 0, 1, 32, 128, 0, 0))
        blocked(sock, pin, 30, lambda: send_udp(proc, "still-must-be-rate-limited", target))
        update(pin, "udp_whitelist", target[1], struct.pack("<I", 0))
        blocked(sock, pin, 46, lambda: send_udp(proc, "after-revocation", target))


def main():
    pin, ns = Path(sys.argv[1]), sys.argv[2]
    from auto_xdp.bpf.conntrack import configure, verify_lookup_abi
    configure()
    try:
        verify_lookup_abi()
        for family, local, other in [(socket.AF_INET, "10.99.0.1", "10.99.0.2"),
                                     (socket.AF_INET6, "2001:db8:99::1", "2001:db8:99::2")]:
            check_udp(pin, ns, family, local, other)
            check_tcp(ns, family, local, other)
            check_udp_expiry(pin, ns, family, local, other)
            check_inbound_udp(pin, ns, family, local, other)
            nft_family = "ip" if family == socket.AF_INET else "ip6"
            translated = f"{local}:49998" if family == socket.AF_INET else f"[{local}]:49998"
            rules = f'''add table {nft_family} axdp_reply_nat
add chain {nft_family} axdp_reply_nat post {{ type nat hook postrouting priority srcnat; }}
add rule {nft_family} axdp_reply_nat post udp sport 49997 snat to {translated}
'''
            subprocess.run(["nft", "-f", "-"], input=rules, text=True, check=True)
            try:
                check_udp(pin, ns, family, local, other, nat=True)
            finally:
                subprocess.run(["nft", "delete", "table", nft_family, "axdp_reply_nat"], check=True)
            print(f"IPv{4 if family == socket.AF_INET else 6}: replies, tuple isolation, expiry, half-close, inbound policy and SNAT passed")
    finally:
        configure(remove=True)


if __name__ == "__main__":
    if sys.argv[1] == "--peer":
        peer(int(sys.argv[2]), int(sys.argv[3]), sys.argv[4])
    else:
        main()
