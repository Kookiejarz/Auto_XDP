"""Real client-first transfers must not wait for a cookie zero-window probe.

The Bash kernel fixture starts the server and invokes the client inside its
private peer namespace. Both address families use fresh TCP connections.
"""
import argparse
import ctypes
import json
import os
from pathlib import Path
import socket
import statistics
import struct
import subprocess
import tempfile
import threading
import time


PAYLOADS = [b"cookie-first-payload"] * 5 + [bytes(range(256)) * 512]
HOSTS = [(socket.AF_INET, "10.99.0.1"), (socket.AF_INET6, "2001:db8:99::1")]


def established_ack_probe(pin, iface, host, peer, port):
    """Exercise the optional ACK gate with an actual socket and stale CT.

    Test-run does not inject this deliberately out-of-window ACK into Linux.
    The existing raw-wire tests separately prove unestablished ACK rejection.
    """
    from auto_xdp.bpf.syscall import bpf, obj_get
    from kernel_packet_telemetry import checksum
    family = socket.AF_INET6 if ':' in host else socket.AF_INET
    source = socket.inet_pton(family, peer[0]); dest = socket.inet_pton(family, host)
    tcp = struct.pack('!HHIIHHHH', peer[1], port, 42, 0xdeadbeef, (5 << 12) | 16, 65535, 0, 0)
    if family == socket.AF_INET:
        pseudo = source + dest + struct.pack('!BBH', 0, 6, len(tcp))
        ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 40, 0, 0, 64, 6, 0, source, dest)
        ip = ip[:10] + struct.pack('!H', checksum(ip)) + ip[12:]
        ether = bytes(12) + b'\x08\x00'
    else:
        pseudo = source + dest + struct.pack('!I3xB', len(tcp), 6)
        ip = struct.pack('!IHBB16s16s', 6 << 28, 20, 6, 64, source, dest)
        ether = bytes(12) + b'\x86\xdd'
    tcp = tcp[:16] + struct.pack('!H', checksum(pseudo+tcp)) + tcp[18:]
    packet = ether+ip+tcp
    scratch = bytearray(44)
    struct.pack_into('=BBHH', scratch, 0, family, 6, 14, 14+len(ip))
    struct.pack_into('!HH', scratch, 6, peer[1], port)
    scratch[12:12+len(source)] = source; scratch[28:28+len(dest)] = dest
    possible = Path('/sys/devices/system/cpu/possible').read_text().strip().split(',')
    cpus = sum(int(p.split('-')[-1])-int(p.split('-')[0])+1 for p in possible)
    values = ctypes.create_string_buffer((bytes(scratch)+bytes(4))*cpus)
    key = ctypes.create_string_buffer(4); attr = ctypes.create_string_buffer(32)
    fd = obj_get(str(pin/'slot_ctx_map'))
    try:
        struct.pack_into('=I4xQQQ', attr, 0, fd, ctypes.addressof(key), ctypes.addressof(values), 0)
        bpf(2, attr)
    finally:
        os.close(fd)
    with tempfile.TemporaryDirectory(prefix='axdp-established-ack-') as temp:
        root = Path(temp); (root/'packet').write_bytes(packet)
        (root/'context').write_bytes(struct.pack('<6I', 0, len(packet), 0, socket.if_nametoindex(iface), 0, 0))
        result = json.loads(subprocess.check_output(['bpftool', '-j', 'prog', 'run', 'pinned', str(pin/'syncookie_prog'),
            'data_in', str(root/'packet'), 'ctx_in', str(root/'context'), 'repeat', '1'], text=True))
        assert result['retval'] == 2, f'{host}: established socket ACK was treated as a handshake cookie: {result}'


def read_exact(sock, size):
    result = bytearray()
    while len(result) < size:
        part = sock.recv(size - len(result))
        if not part:
            raise AssertionError("peer closed before completing transfer")
        result.extend(part)
    return bytes(result)


def server(port, ready, output, stale_conntrack=False, pin=None, iface=None):
    records, errors, listeners, threads = [], [], [], []

    def serve(sock, host):
        try:
            for _ in PAYLOADS:
                conn, peer = sock.accept()
                with conn:
                    conn.settimeout(3)
                    size = struct.unpack("!I", read_exact(conn, 4))[0]
                    assert 0 < size <= 128 * 1024, size
                    payload = read_exact(conn, size)
                    if stale_conntrack and size == len(PAYLOADS[-1]):
                        # Emulate an old tuple surviving an XDP_TX handshake.
                        # Only the isolated fixture's exact active tuple is
                        # changed. A live socket must keep receiving data ACKs.
                        selector = ['-p', 'tcp', '-s', peer[0],
                                    '-d', host, '--sport', str(peer[1]), '--dport', str(port)]
                        deleted = subprocess.run(['conntrack', '-D', *selector], capture_output=True, text=True)
                        assert deleted.returncode in (0, 1), deleted.stderr
                        inserted = subprocess.run(['conntrack', '-I', *selector, '--state', 'CLOSE',
                                                   '--timeout', '30'], capture_output=True, text=True)
                        assert inserted.returncode == 0, inserted.stderr
                        if pin is not None:
                            established_ack_probe(pin, iface, host, peer, port)
                    conn.sendall(struct.pack("!I", size) + payload)
                    records.append({"host": host, "bytes": size})
        except Exception as exc:
            errors.append({"host": host, "error": repr(exc)})
            print(json.dumps(errors[-1]), flush=True)

    try:
        for family, host in HOSTS:
            sock = socket.socket(family, socket.SOCK_STREAM)
            listeners.append(sock)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            if family == socket.AF_INET6:
                sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            sock.bind((host, port))
            sock.listen(32)
            sock.settimeout(8)
            thread = threading.Thread(target=serve, args=(sock, host))
            thread.start()
            threads.append(thread)
        ready.write_text("ready")
        for thread in threads:
            thread.join(10)
        assert not any(thread.is_alive() for thread in threads), "server did not finish"
        assert not errors and len(records) == len(HOSTS) * len(PAYLOADS), (errors, records)
    finally:
        for sock in listeners:
            sock.close()
        output.write_text(json.dumps({"accepted": records, "errors": errors}) + "\n")


def client(port):
    for family, host in HOSTS:
        timings = []
        for payload in PAYLOADS:
            start = time.monotonic()
            with socket.socket(family, socket.SOCK_STREAM) as sock:
                sock.settimeout(3)
                sock.connect((host, port))
                sock.sendall(struct.pack("!I", len(payload)) + payload)
                size = struct.unpack("!I", read_exact(sock, 4))[0]
                assert size == len(payload)
                assert read_exact(sock, size) == payload, "transfer content changed"
            timings.append((time.monotonic() - start) * 1000)
        median = statistics.median(timings[:5])
        assert median < 100, f"{host}: first-payload median {median:.2f}ms suggests a persist-probe stall"
        print(json.dumps({"host": host, "new_connections": len(PAYLOADS),
                          "small_transfer_median_ms": median,
                          "multi_window_bytes": len(PAYLOADS[-1]),
                          "multi_window_roundtrip_ms": timings[-1]}), flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("server", "client"))
    parser.add_argument("port", type=int)
    parser.add_argument("--ready", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--stale-conntrack", action="store_true")
    parser.add_argument("--pin-dir", type=Path)
    parser.add_argument("--interface")
    args = parser.parse_args()
    if args.mode == "server":
        assert args.ready is not None and args.output is not None
        server(args.port, args.ready, args.output, args.stale_conntrack, args.pin_dir, args.interface)
    else:
        client(args.port)
