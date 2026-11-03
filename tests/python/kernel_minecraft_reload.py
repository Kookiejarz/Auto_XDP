"""Real Minecraft TCP sessions survive compatible ingress/egress replacement."""
import json
from pathlib import Path
import select
import socket
import struct
import subprocess
import sys
import tempfile
from types import SimpleNamespace
from unittest import mock

from auto_xdp.admin import handlers
from auto_xdp.backends.xdp import XdpBackend
from auto_xdp.bpf.conntrack import configure
from auto_xdp.bpf.maps import BpfArrayMap
from kernel_handler_dispatch import run, update, line


def peer(family, address, port):
    with socket.socket(family, socket.SOCK_STREAM) as sock:
        sock.settimeout(5)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        sock.connect((address, port))
        print("connected", flush=True)
        for command in sys.stdin:
            action, data = command.strip().split()
            if action == "send":
                sock.sendall(bytes.fromhex(data))
                print("sent", flush=True)
            elif action == "recv":
                print(sock.recv(int(data)).hex(), flush=True)


def dump(path):
    return json.loads(run("bpftool", "-j", "map", "dump", "pinned", path).stdout)


def raw_value(row):
    return bytes(int(item, 0) for item in row["value"])


def main(root, ns, iface, local4, local6, obj, dispatcher):
    configure()
    table, live = root / "tcp_profile_handlers", root / "profile_handlers/tcp/1"
    state = live / "maps"
    generation = handlers.profile_state_generation(obj)
    shared = handlers.handler_shared_maps(obj, root)
    handlers.load_handler_object(table, 1, obj, live, shared)
    command = ["bpftool", "prog", "load", dispatcher, root / "reload_dispatcher", "type", "classifier"]
    for name in handlers.handler_object_maps(dispatcher):
        command += ["map", "name", name, "pinned", root / name]
    run(*command)
    run("tc", "qdisc", "add", "dev", iface, "clsact")
    run("tc", "filter", "add", "dev", iface, "egress", "pref", 49153, "handle", 2,
        "bpf", "direct-action", "object-pinned", root / "reload_dispatcher")
    try:
        for family, address in ((socket.AF_INET, local4), (socket.AF_INET6, local6)):
            port = 25565 + family
            policy = struct.pack("=IIQQ", 1, 1, 11, generation)
            update(root, "tcp_whitelist", struct.pack("=I", port), policy)
            with socket.socket(family, socket.SOCK_STREAM) as server:
                server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                server.bind((address, port))
                server.listen(1)
                server.settimeout(5)
                proc = subprocess.Popen(["ip", "netns", "exec", ns, sys.executable, __file__, "--peer",
                                         str(family), address, str(port)],
                                        stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
                try:
                    conn, _ = server.accept()
                    with conn:
                        conn.settimeout(5)
                        conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                        assert line(proc) == "connected"

                        def send(body):
                            proc.stdin.write("send " + body.hex() + "\n")
                            proc.stdin.flush()
                            assert line(proc) == "sent"

                        def receive(body):
                            data = b""
                            while len(data) < len(body):
                                part = conn.recv(len(body) - len(data))
                                assert part, "connection closed during replacement"
                                data += part
                            assert data == body

                        def reload():
                            ids = {name: handlers._pinned_map_id(state / name)
                                   for name in handlers.handler_state.object_contract(obj).maps}
                            old_program = handlers.pinned_program_id(live / "prog")
                            assert handlers.load_handler_object(table, 1, obj, live, shared)
                            assert handlers.pinned_program_id(live / "prog") != old_program
                            assert all(handlers._pinned_map_id(state / name) == value for name, value in ids.items())

                        handshake = b"\x0f\x00\x2f\x09localhost\x63\xdd\x02"
                        send(handshake)
                        receive(handshake)
                        pending = dump(state / "mc_l7_pending")
                        assert len(pending) == 1
                        before = raw_value(pending[0])
                        reload()
                        assert raw_value(dump(state / "mc_l7_pending")[0]) == before, "pending deadline/budget changed"
                        login = b"\x06\x00\x04Test"
                        send(login)
                        receive(login)
                        login_rate = dump(state / ("mc_login_rate4" if family == 2 else "mc_login_rate6"))
                        reload()
                        assert dump(state / ("mc_login_rate4" if family == 2 else "mc_login_rate6")) == login_rate
                        conn.sendall(b"\x01\x02")
                        proc.stdin.write("recv 2\n")
                        proc.stdin.flush()
                        assert line(proc) == "0102"
                        proof = dump(state / "mc_verified")
                        assert len(proof) == 1 and not dump(state / "mc_l7_pending")
                        send(b"PLAY-before")
                        receive(b"PLAY-before")
                        reload()
                        assert dump(state / "mc_verified") == proof, "verified proof/epoch changed"
                        send(b"PLAY-after")
                        receive(b"PLAY-after")
                        # A schema mismatch must reject before publication, leaving
                        # the established connection and both programs untouched.
                        incompatible = obj.with_name("minecraft_incompatible.o")
                        incompatible.write_bytes(obj.read_bytes().replace(b"minecraft-session-v1", b"minecraft-session-v2"))
                        old_ids = [handlers.pinned_program_id(live / name) for name in ("prog", "egress")]
                        try:
                            handlers.load_handler_object(table, 1, incompatible, live,
                                                         handlers.handler_shared_maps(incompatible, root))
                        except RuntimeError as exc:
                            assert "not compatible" in str(exc)
                        else:
                            raise AssertionError("incompatible schema was published")
                        assert [handlers.pinned_program_id(live / name) for name in ("prog", "egress")] == old_ids
                        send(b"PLAY-retained")
                        receive(b"PLAY-retained")
                        # Exercise the daemon's real CLI reload and pinned-map
                        # readback, including recovery without its JSON marker.
                        with tempfile.TemporaryDirectory(prefix="axdp-mc-release-") as directory:
                            release = Path(directory)
                            official = release / "handlers/minecraft_handler.o"
                            official.parent.mkdir()
                            official.write_bytes(obj.read_bytes())
                            ownership = release / "ownership.json"
                            backend = XdpBackend.__new__(XdpBackend)
                            backend._config = SimpleNamespace(BPF_PIN_DIR=str(root),
                                                              TOML_CONFIG_PATH=str(release / "absent.toml"))
                            backend.tcp_profile_map = BpfArrayMap(str(table))
                            try:
                                with mock.patch.object(backend, "_profile_install_dir", return_value=release), \
                                     mock.patch.object(backend, "_profile_marker", return_value=ownership):
                                    desired = {("public", port): "minecraft"}
                                    assert backend._ensure_profile_handlers(desired, generation, False) == (set(), generation)
                                    previous = handlers.pinned_program_id(live / "prog")
                                    official.write_bytes(official.read_bytes() + b"compiler-metadata-only-change")
                                    assert backend._ensure_profile_handlers(desired, generation, False) == (set(), generation)
                                    assert handlers.pinned_program_id(live / "prog") != previous
                                    official.write_bytes(incompatible.read_bytes())
                                    ownership.unlink()
                                    assert backend._ensure_profile_handlers(desired, generation, False) == (set(), generation)
                                    assert dump(state / "mc_verified") == proof
                                    send(b"PLAY-daemon")
                                    receive(b"PLAY-daemon")
                            finally:
                                backend.tcp_profile_map.close()
                        # Reusing a state map must never mask authorization revocation.
                        update(root, "tcp_whitelist", struct.pack("=I", port), struct.pack("=IIQQ", 1, 1, 12, generation))
                        send(b"REVOKED")
                        assert not select.select([conn], [], [], 0.35)[0], "old proof bypassed policy revocation"
                        update(root, "tcp_whitelist", struct.pack("=I", port), policy)
                        receive(b"REVOKED")  # TCP retransmits on the original socket.
                        print(f"Minecraft IPv{4 if family == 2 else 6}: pending deadline/budget, login rate, verified proof and live socket preserved; incompatible schema rejected; policy revocation enforced", flush=True)
                finally:
                    proc.terminate()
                    proc.wait(timeout=5)
            # Closing the peer sends FIN/RST; clear only this test's old proof by
            # unloading after the connection, then start the next family fresh.
            handlers.transactional_handler_pair(table, 1, None, live)
            handlers.load_handler_object(table, 1, obj, live, shared)
    finally:
        configure(remove=True)


if __name__ == "__main__":
    if sys.argv[1] == "--peer":
        peer(int(sys.argv[2]), sys.argv[3], int(sys.argv[4]))
    else:
        root, ns, iface, local4, local6, obj, dispatcher = sys.argv[1:]
        main(Path(root), ns, iface, local4, local6, Path(obj), Path(dispatcher))
