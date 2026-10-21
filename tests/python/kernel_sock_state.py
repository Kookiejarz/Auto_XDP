"""Real listener lifecycle contracts, invoked by the privileged kernel suite."""
from __future__ import annotations

import argparse
import errno
import os
from pathlib import Path
import socket

from auto_xdp.discovery.sock_state import SOCK_STATE_EVENT_SIZE, SockStateReader
from pkt_relay import RingBufReader, SOCK_STATE_RB_MAX_ENTRIES, attach_tracepoint


def bound_socket(family: int, address: str, port: int = 0) -> socket.socket:
    sock = socket.socket(family, socket.SOCK_STREAM)
    try:
        sock.settimeout(2)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if family == socket.AF_INET6:
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        sock.bind((address, port))
        return sock
    except BaseException:
        sock.close()
        raise


def expect_events(reader: RingBufReader, family: int, port: int,
                  actions: list[str], label: str) -> None:
    actual = []
    observed = []
    for raw in reader.drain():
        assert len(raw) == 16 and raw[13:] == bytes(3), "listener event ABI changed"
        event = SockStateReader.decode_raw(raw)
        assert event is not None and event["proto"] == "tcp"
        observed.append(event)
        if event["port"] == port and event["family"] == family:
            actual.append(event["action"])
    assert reader.invalid_records == 0, "invalid listener ring-buffer records"
    assert actual == actions, (
        f"{label}: IPv{family} port {port} expected {actions}, got {len(actual)} events: {actual}; "
        f"all observed events: {observed}"
    )


def exchange(listener: socket.socket, family: int, address: str) -> None:
    with socket.socket(family, socket.SOCK_STREAM) as client:
        client.settimeout(2)
        client.connect((address, listener.getsockname()[1]))
        accepted, _ = listener.accept()
        with accepted:
            accepted.settimeout(2)
            client.sendall(b"x")
            assert accepted.recv(1) == b"x"


def check_connections_and_relisten(reader: RingBufReader, family: int, address: str) -> None:
    version = 4 if family == socket.AF_INET else 6
    with bound_socket(family, address) as listener:
        port = listener.getsockname()[1]
        listener.listen(16)
        expect_events(reader, version, port, ["open"], "initial listen")
        for _ in range(32):
            exchange(listener, family, address)
        assert listener.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN) == 1
        expect_events(reader, version, port, [], "32 connections while listener stays open")

        listener.listen(64)
        expect_events(reader, version, port, [], "changing an existing listen backlog")
        listener.shutdown(socket.SHUT_RDWR)
        expect_events(reader, version, port, ["close"], "listener shutdown")
        listener.listen(16)
        expect_events(reader, version, port, ["open"], "listen again after shutdown")
        # A port chosen by bind(..., 0) can be reassigned when listening again.
        port = listener.getsockname()[1]
        exchange(listener, family, address)
        expect_events(reader, version, port, [], "connection after relisten")
    expect_events(reader, version, port, ["close"], "listener close")
    print(f"[INFO] IPv{version}: normal connections, backlog, shutdown, relisten and close passed")


def check_close_with_live_connection(reader: RingBufReader, family: int, address: str) -> None:
    version = 4 if family == socket.AF_INET else 6
    with bound_socket(family, address) as listener:
        port = listener.getsockname()[1]
        listener.listen(16)
        expect_events(reader, version, port, ["open"], "listen before live connection")
        with socket.socket(family, socket.SOCK_STREAM) as client:
            client.settimeout(2)
            client.connect((address, port))
            accepted, _ = listener.accept()
            with accepted:
                accepted.settimeout(2)
                expect_events(reader, version, port, [], "creating accepted socket")
                listener.close()
                expect_events(reader, version, port, ["close"], "close listener with accepted socket alive")
                client.sendall(b"x")
                assert accepted.recv(1) == b"x"
        expect_events(reader, version, port, [], "closing accepted socket and client")
    print(f"[INFO] IPv{version}: closing listener with an established connection passed")


def check_failed_listen(reader: RingBufReader, family: int, address: str) -> None:
    version = 4 if family == socket.AF_INET else 6
    with bound_socket(family, address) as listener:
        port = listener.getsockname()[1]
        # SO_REUSEADDR permits both binds before either socket starts listening.
        with bound_socket(family, address, port) as contender:
            listener.listen(16)
            expect_events(reader, version, port, ["open"], "listen before competing listen")
            try:
                contender.listen(16)
            except OSError as exc:
                assert exc.errno == errno.EADDRINUSE, exc
            else:
                raise AssertionError("competing listen unexpectedly succeeded")
            # inet_csk_listen_start enters LISTEN before checking the port and
            # returns to CLOSE on failure. Keep both rescan hints for this path.
            expect_events(reader, version, port, ["open", "close"], "failed listen rollback")
            assert listener.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN) == 1
            exchange(listener, family, address)
            expect_events(reader, version, port, [], "original listener remains available")
        expect_events(reader, version, port, [], "closing socket whose listen failed")
    expect_events(reader, version, port, ["close"], "closing original listener")
    print(f"[INFO] IPv{version}: failed listen rollback and original listener passed")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("pin_dir", type=Path)
    args = parser.parse_args()
    perf_fds = attach_tracepoint(str(args.pin_dir / "prog"), "sock/inet_sock_set_state")
    assert perf_fds, "cannot attach real listener tracepoint"
    try:
        reader = RingBufReader(str(args.pin_dir / "sock_state_rb"),
                               SOCK_STATE_RB_MAX_ENTRIES, SOCK_STATE_EVENT_SIZE)
        try:
            for family, address in ((socket.AF_INET, "127.0.0.1"), (socket.AF_INET6, "::1")):
                check_connections_and_relisten(reader, family, address)
                check_close_with_live_connection(reader, family, address)
                check_failed_listen(reader, family, address)
        finally:
            reader.close()
    finally:
        for fd in perf_fds:
            os.close(fd)
    print("[INFO] listener kernel lifecycle contracts passed for IPv4 and IPv6")


if __name__ == "__main__":
    main()
