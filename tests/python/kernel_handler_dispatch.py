"""Live dual-entry plugin tests; invoked only inside the kernel suite's private netns."""
from contextlib import contextmanager
import json
from pathlib import Path
import select
import socket
import struct
import subprocess
import sys
from unittest import mock

from auto_xdp.admin import handlers, runtime
from auto_xdp.bpf.conntrack import configure
from kernel_packet_telemetry import counter


def run(*args):
    return subprocess.run([str(a) for a in args], check=True, capture_output=True, text=True)


def update(root, name, key, value):
    run("bpftool", "map", "update", "pinned", root / name,
        "key", "hex", *key.hex(" ").split(), "value", "hex", *value.hex(" ").split())


def metrics(path):
    data = json.loads(run("bpftool", "-j", "map", "lookup", "pinned", path,
                          "key", "0", "0", "0", "0").stdout)
    return struct.unpack("=QQQ6I", bytes(int(v, 0) for v in data["value"]))


def peer(family, kind, local, destination, port):
    with socket.socket(family, kind) as sock:
        sock.bind((local, 0))
        sock.settimeout(4)
        sock.connect((destination, port))
        sock.send(b"request")
        print("ready", flush=True)
        for line in sys.stdin:
            if line.strip() == "recv":
                print(sock.recv(1024).decode(), flush=True)
            elif line.strip() == "send":
                sock.send(b"request")
                print("sent", flush=True)


def line(proc):
    assert select.select([proc.stdout], [], [], 5)[0], "peer timed out"
    result = proc.stdout.readline().strip()
    assert result, f"peer exited: {proc.poll()}"
    return result


@contextmanager
def connection(ns, family, kind, local, other, port):
    with socket.socket(family, kind) as listener:
        listener.settimeout(5)
        listener.bind((local, port))
        if kind == socket.SOCK_STREAM:
            listener.listen(1)
        proc = subprocess.Popen(["ip", "netns", "exec", ns, sys.executable, __file__, "--peer",
                                 str(family), str(kind), other, local, str(port)],
                                stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
        conn = listener
        try:
            if kind == socket.SOCK_STREAM:
                conn, address = listener.accept()
                conn.settimeout(5)
                assert conn.recv(1024) == b"request"
            else:
                data, address = listener.recvfrom(1024)
                assert data == b"request"
            assert line(proc) == "ready"
            def reply():
                proc.stdin.write("recv\n")
                proc.stdin.flush()
                if kind == socket.SOCK_STREAM:
                    conn.sendall(b"reply")
                else:
                    conn.sendto(b"reply", address)
                assert line(proc) == "reply"
            yield reply, proc, conn
        finally:
            proc.terminate()
            proc.wait(timeout=5)
            if conn is not listener:
                conn.close()


def main(root, ns, iface, local4, other4, local6, other6, obj, replacement, dispatcher, chain):
    configure()
    ifindex = socket.if_nametoindex(iface)
    # Give replies a different interface from requests. Explicit denial on the
    # output interface must not override the remembered ingress service zone.
    out, peer_out = "axdp_hout", "axdp_cout"
    run("ip", "link", "add", out, "type", "veth", "peer", "name", peer_out)
    run("ip", "link", "set", peer_out, "netns", ns)
    try:
        for command in (
            ("ip", "addr", "add", "198.18.212.1/24", "dev", out),
            ("ip", "-6", "addr", "add", "fd42:212::1/64", "dev", out, "nodad"),
            ("ip", "link", "set", out, "up"),
            ("ip", "netns", "exec", ns, "ip", "addr", "add", "198.18.212.2/24", "dev", peer_out),
            ("ip", "netns", "exec", ns, "ip", "-6", "addr", "add", "fd42:212::2/64", "dev", peer_out, "nodad"),
            ("ip", "netns", "exec", ns, "ip", "link", "set", peer_out, "up"),
            ("ip", "route", "add", other4 + "/32", "via", "198.18.212.2", "dev", out),
            ("ip", "-6", "route", "add", other6 + "/128", "via", "fd42:212::2", "dev", out),
        ):
            run(*command)
        for name in ("all", "default", iface, out):
            Path(f"/proc/sys/net/ipv4/conf/{name}/rp_filter").write_text("0")
        for name in ("all", "default", peer_out):
            run("ip", "netns", "exec", ns, "sysctl", "-q", "-w", f"net.ipv4.conf.{name}.rp_filter=0")
        # Resolve neighbors explicitly: some test hosts inherit arp_filter=1,
        # which intentionally declines ARP when the reverse route is asymmetric.
        host_mac = Path(f"/sys/class/net/{iface}/address").read_text().strip()
        incoming = json.loads(run("ip", "netns", "exec", ns, "ip", "-j", "route", "get", local4).stdout)[0]["dev"]
        client_mac = json.loads(run("ip", "netns", "exec", ns, "ip", "-j", "link", "show", peer_out).stdout)[0]["address"]
        for af, destination in (("-4", local4), ("-6", local6)):
            run("ip", "netns", "exec", ns, "ip", af, "neigh", "replace", destination,
                "lladdr", host_mac, "nud", "permanent", "dev", incoming)
        for af, destination in (("-4", "198.18.212.2"), ("-6", "fd42:212::2")):
            run("ip", af, "neigh", "replace", destination, "lladdr", client_mac,
                "nud", "permanent", "dev", out)
        output_index = socket.if_nametoindex(out)
        cmd = ["bpftool", "prog", "load", dispatcher, root / "tc_egress_dispatch_prog", "type", "classifier"]
        for name in handlers.handler_object_maps(dispatcher):
            cmd += ["map", "name", name, "pinned", root / name]
        run(*cmd)
        (root / "chain-maps").mkdir()
        run("bpftool", "prog", "load", chain, root / "chain", "type", "classifier",
            "pinmaps", root / "chain-maps")
        run("tc", "qdisc", "add", "dev", out, "clsact")
        for pref, pin in ((49153, "tc_egress_dispatch_prog"), (49154, "chain")):
            run("tc", "filter", "add", "dev", out, "egress", "pref", pref, "handle", 2,
                "bpf", "direct-action", "object-pinned", root / pin)
        for family, local, other in ((socket.AF_INET, local4, other4), (socket.AF_INET6, local6, other6)):
            for kind, proto in ((socket.SOCK_STREAM, "tcp"), (socket.SOCK_DGRAM, "udp")):
                port = 42000 + family + kind
                table = root / f"{proto}_port_handlers"
                live = handlers.port_handler_dir(root, proto, port)
                handlers.load_handler_object(table, port, obj, live, handlers.handler_shared_maps(obj, root))
                key = struct.pack("=I", port)
                allow = struct.pack("=IIQQ", 1, 0, 0, 0) if proto == "tcp" else struct.pack("=I", 1)
                deny = bytes(len(allow))
                update(root, f"{proto}_whitelist", key, allow)
                update(root, f"{proto}_zone_whitelist", struct.pack("=II", ifindex, port), allow)
                update(root, f"{proto}_zone_whitelist", struct.pack("=II", output_index, port), deny)
                private = live / "maps/private_metrics"
                with connection(ns, family, kind, local, other, port) as (reply, proc, conn):
                    before_chain = metrics(root / "chain-maps/private_metrics")[1]
                    reply()
                    values = metrics(private)
                    assert values[0] and values[1] == values[2] == 1, values
                    assert values[3:8] == (2 if proto == "tcp" else 3, port, ifindex, family, 6 if proto == "tcp" else 17), values
                    assert metrics(root / "chain-maps/private_metrics")[1] > before_chain, "TC handler terminated the chain"
                    # Current ingress-zone denial overrides global allow, even
                    # with a previously admitted and tracked connection.
                    update(root, f"{proto}_zone_whitelist", struct.pack("=II", ifindex, port), deny)
                    reply()
                    assert metrics(private)[1] == 1, "revoked service reached TC plugin"
                    update(root, f"{proto}_zone_whitelist", struct.pack("=II", ifindex, port), allow)
                    # Removing only the TC array entry is a visible, non-blocking miss.
                    tc_map, _ = handlers.handler_egress_table(table)
                    handlers.prog_array_delete(tc_map, port)
                    misses = counter(root / "handler_eg_stats", 5)
                    reply()
                    assert metrics(private)[1] == 1
                    assert counter(root / "handler_eg_stats", 5) > misses
                    handlers.prog_array_update(tc_map, port, live / "egress")
                    # Exact address/family/interface scope is rechecked at egress.
                    runtime_value = bytes(64) + struct.pack("=II", 1 | 16, 0)
                    update(root, "xdp_runtime_cfg", bytes(4), runtime_value)
                    reply()
                    assert metrics(private)[1] == 1, "missing exact scope reached TC plugin"
                    address = socket.inet_pton(family, local).ljust(16, b"\0")
                    scope = struct.pack("=IHBB", ifindex, port, 6 if proto == "tcp" else 17, family) + address
                    update(root, "endpoint_scopes", scope, struct.pack("=I", 1))
                    reply()
                    assert metrics(private)[1] == 2
                    update(root, "xdp_runtime_cfg", bytes(4), bytes(64) + struct.pack("=II", 1, 0))
                    state_id = handlers._pinned_map_id(private)
                    ingress_id = handlers.pinned_program_id(live / "prog")
                    assert handlers.load_handler_object(table, port, replacement, live,
                                                       handlers.handler_shared_maps(replacement, root))
                    assert handlers._pinned_map_id(private) == state_id
                    assert handlers.pinned_program_id(live / "prog") != ingress_id
                    assert metrics(private)[1] == 2, "reload reset the live state"
                    reply()
                    assert metrics(private)[1] == 3, "established reply lost its service binding"
                    proc.stdin.write("send\n")
                    proc.stdin.flush()
                    assert line(proc) == "sent"
                    assert (conn.recv(1024) if proto == "tcp" else conn.recvfrom(1024)[0]) == b"request"
                    old_ids = [handlers.pinned_program_id(live / name) for name in ("prog", "egress")]
                    original_update = handlers.prog_array_update
                    injected = False

                    def fail_after_egress(table_path, key, pin):
                        nonlocal injected
                        if table_path == table and not injected:
                            injected = True
                            reply()  # New TC writes shared state while old XDP is still live.
                            raise RuntimeError("injected XDP publication failure")
                        return original_update(table_path, key, pin)

                    with mock.patch.object(handlers, "prog_array_update", side_effect=fail_after_egress):
                        try:
                            handlers.load_handler_object(table, port, obj, live,
                                                         handlers.handler_shared_maps(obj, root))
                        except RuntimeError as exc:
                            assert "previous generation restored" in str(exc), str(exc)
                        else:
                            raise AssertionError("failure injection did not reject replacement")
                    assert injected and metrics(private)[1] == 4, "rollback lost an in-flight state update"
                    assert [handlers.pinned_program_id(live / name) for name in ("prog", "egress")] == old_ids
                    assert handlers._pinned_map_id(private) == state_id
                    reply()
                    assert metrics(private)[1] == 5
                    print(f"IPv{4 if family == 2 else 6} {proto}: live replacement and cross-hook failure rollback preserve map ID and in-flight writes", flush=True)
                    handlers.transactional_handler_pair(table, port, None, live)
                    reply()  # Unload still permits the normal kernel reply.
                assert not live.exists()
                print(f"dual handler IPv{4 if family == 2 else 6} {proto}: shared state, asymmetric route, zone/scope revocation, tail miss, unload, chain passed", flush=True)
        port, profile = 43000, 9
        table = root / "tcp_profile_handlers"
        live = root / "profile_handlers/tcp" / str(profile)
        handlers.load_handler_object(table, profile, obj, live, handlers.handler_shared_maps(obj, root))
        private = live / "maps/private_metrics"
        key = struct.pack("=I", port)
        policy = struct.pack("=IIQQ", 1, profile, 11, 22)
        update(root, "tcp_whitelist", key, policy)
        with connection(ns, socket.AF_INET, socket.SOCK_STREAM, local4, other4, port) as (reply, proc, conn):
            reply()
            assert metrics(private)[1] == 1 and metrics(private)[3:5] == (1, profile)
            for policy_generation, profile_generation in ((12, 22), (11, 23)):
                update(root, "tcp_whitelist", key, struct.pack("=IIQQ", 1, profile, policy_generation, profile_generation))
                reply()
                assert metrics(private)[1] == 1, "stale profile binding reached TC plugin"
            update(root, "tcp_whitelist", key, policy)
            handlers.transactional_handler_pair(table, profile, None, live)
        print("profile route: policy and object generations rechecked at egress", flush=True)
        assert runtime._detach_handler_egress(root, [out])
        remaining = json.loads(run("tc", "-j", "filter", "show", "dev", out, "egress").stdout)
        assert not any(row.get("pref") == 49153 for row in remaining)
        assert any(row.get("pref") == 49154 for row in remaining), "cleanup removed another TC owner"
        print("runtime cleanup: owned dispatcher removed; later TC filter preserved", flush=True)
    except BaseException:
        for args in (("ip", "route"), ("ip", "neigh"),
                     ("ip", "netns", "exec", ns, "ip", "route"),
                     ("ip", "netns", "exec", ns, "ip", "neigh"),
                     ("tc", "-j", "filter", "show", "dev", out, "egress")):
            print(run(*args).stdout, flush=True)
        raise
    finally:
        run("ip", "link", "del", out)
        configure(remove=True)


if __name__ == "__main__":
    if sys.argv[1] == "--peer":
        peer(int(sys.argv[2]), int(sys.argv[3]), sys.argv[4], sys.argv[5], int(sys.argv[6]))
    else:
        root, ns, iface, local4, other4, local6, other6, obj, replacement, dispatcher, chain = sys.argv[1:]
        main(Path(root), ns, iface, local4, other4, local6, other6, Path(obj), Path(replacement), Path(dispatcher), Path(chain))
