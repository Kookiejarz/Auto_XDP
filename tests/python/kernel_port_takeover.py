"""Measure application delivery during real XDP endpoint takeover.

Run through reproducible-tests/port-takeover-reproduce.sh in an isolated Linux
container. This is an experiment, not a deterministic pytest regression.
"""
from __future__ import annotations

import argparse
import ctypes
import errno
import json
import os
from pathlib import Path
import select
import signal
import socket
import struct
import subprocess
import sys
import threading
import time

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
PIN = Path("/sys/fs/bpf/axdp_takeover")
RUN = Path("/run/axdp_takeover")
HOST = "10.98.0.1"
NS = "axdp_takeover_client"
IFACE = "axdp_take0"
PORT = 38080


def command(*args, **kwargs):
    return subprocess.run(args, check=True, text=True, **kwargs)


def receive(proc, timeout=10):
    assert select.select([proc.stdout], [], [], timeout)[0], "child readiness timed out"
    line = proc.stdout.readline()
    assert line, f"child exited: {proc.poll()}"
    return json.loads(line)


def listener(proto, name, path, waiting):
    assert ctypes.CDLL(None).prctl(15, name.encode(), 0, 0, 0) == 0
    if waiting:
        print(json.dumps({"pid": os.getpid(), "waiting": True}), flush=True)
        assert sys.stdin.readline().strip() == "bind"
    kind = socket.SOCK_STREAM if proto == "tcp" else socket.SOCK_DGRAM
    sock = socket.socket(socket.AF_INET, kind)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((HOST, PORT))
    if proto == "tcp":
        sock.listen(256)
    print(json.dumps({"bound_ns": time.monotonic_ns()}), flush=True)
    with open(path, "w", buffering=1) as records:
        while True:
            ready, _, _ = select.select([sock, sys.stdin], [], [], 0.2)
            if sys.stdin in ready:
                line = sys.stdin.readline().strip()
                assert line == "close", line
                sock.close()
                print(json.dumps({"closed_ns": time.monotonic_ns()}), flush=True)
                return
            if sock not in ready:
                continue
            if proto == "tcp":
                conn, address = sock.accept()
                with conn:
                    conn.settimeout(0.05)
                    try:
                        payload = conn.recv(256)
                        received = time.monotonic_ns()
                        if payload:
                            records.write(json.dumps({"recv_ns": received, "payload": payload.decode(),
                                                      "peer": address}) + "\n")
                            conn.sendall(b"received")
                    except (TimeoutError, ConnectionError):
                        pass
            else:
                payload, address = sock.recvfrom(256)
                records.write(json.dumps({"recv_ns": time.monotonic_ns(), "payload": payload.decode(),
                                          "peer": address}) + "\n")


def client(proto, path, interval_ms):
    stop = threading.Event()
    lock = threading.Lock()
    with open(path, "w", buffering=1) as records:
        def worker(index):
            seq = 0
            udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) if proto == "udp" else None
            try:
                while not stop.is_set():
                    sent = time.monotonic_ns()
                    payload = f"{index}:{seq}:{sent}".encode()
                    acknowledged = False
                    if udp:
                        udp.sendto(payload, (HOST, PORT))
                    else:
                        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as conn:
                            conn.settimeout(0.03)
                            try:
                                conn.connect((HOST, PORT))
                                conn.sendall(payload)
                                acknowledged = conn.recv(32) == b"received"
                            except OSError:
                                pass
                    with lock:
                        records.write(json.dumps({"send_ns": sent, "done_ns": time.monotonic_ns(),
                                                  "payload": payload.decode(), "ack": acknowledged}) + "\n")
                    seq += 1
                    stop.wait(float(interval_ms) / 1000)
            finally:
                if udp:
                    udp.close()
        threads = [threading.Thread(target=worker, args=(index,))
                   for index in range(4 if proto == "tcp" else 1)]
        for thread in threads:
            thread.start()
        print(json.dumps({"started_ns": time.monotonic_ns()}), flush=True)
        assert sys.stdin.readline().strip() == "stop"
        stop.set()
        for thread in threads:
            thread.join()


def start_listener(proto, name, path, waiting=False):
    proc = subprocess.Popen([sys.executable, __file__, "--listener", proto, name,
                             str(path), str(int(waiting))], stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE, text=True)
    ready = receive(proc)
    bound = None if waiting else ready
    return proc, bound


def tell(proc, message):
    proc.stdin.write(message + "\n")
    proc.stdin.flush()


def terminate(proc):
    if proc is None or proc.poll() is not None:
        return
    proc.send_signal(signal.SIGCONT)
    proc.terminate()
    try:
        proc.wait(timeout=3)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()


def records(path):
    return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []


def experiment(out, mode, proto, trial, pause_ms, relay_pid, interval_ms, telemetry):
    from auto_xdp.bpf.syscall import bpf, obj_get, BPF_MAP_LOOKUP_ELEM
    from auto_xdp.config import apply_toml_config, load_toml_config
    from auto_xdp.discovery.listeners import get_listening_ports
    from auto_xdp.policy import resolve_desired_state

    label = f"{mode}-{proto}-{trial:02d}"
    directory = out / label
    directory.mkdir()
    config_path = directory / "config.toml"
    relay_path = "/var/run/auto_xdp/pkt_events.sock"
    config_path.write_text(f'''[firewall]
bogon_filter = false
[under_attack]
enabled = {str(not telemetry).lower()}
[policy]
mode = "enforce"
[zones.public]
interfaces = []
cidrs = ["10.98.0.0/24"]
[daemon]
debounce_seconds = 0.4
log_level = "debug"
preferred_backend = "xdp"
[ringbuf]
socket_path = "{relay_path}"
[xdp]
bpf_pin_dir = "{PIN}"
[rate_limits.syn_by_proc]
axdp-ok = 0
[rate_limits.syn_agg_by_proc]
axdp-ok = 0
[subjects.allowed.resolve]
process_name = "axdp-ok"
[subjects.allowed.exposure.public.{proto}]
ports = [{PORT}]
''')
    procs = []
    fds = []
    watcher = None
    client_proc = None
    monitor_stop = threading.Event()
    transitions = []
    monitor = None
    with open(directory / "watch.log", "w") as watch_log:
        try:
            if mode == "periodic":
                os.kill(relay_pid, signal.SIGSTOP)
            allowed, _ = start_listener(proto, "axdp-ok", directory / "allowed.jsonl")
            procs.append(allowed)
            denied, _ = start_listener(proto, "axdp-denied", directory / "denied.jsonl", True)
            procs.append(denied)
            client_proc = subprocess.Popen(["ip", "netns", "exec", NS, sys.executable,
                __file__, "--client", proto, str(directory / "client.jsonl"), str(interval_ms)],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
            procs.append(client_proc)
            receive(client_proc)
            apply_toml_config(load_toml_config(str(config_path), strict=True))
            observed = get_listening_ports()
            desired = resolve_desired_state(observed)
            decisions = [item for item in desired.exposure_decisions
                         if item.endpoint.protocol == proto and item.endpoint.host_port == PORT]
            assert len(decisions) == 1 and decisions[0].action == "allow", repr(decisions)
            (directory / "before.json").write_text(json.dumps([
                {"action": item.action, "subject": item.subject, "instance_id": item.endpoint.instance_id,
                 "attribution": item.endpoint.attribution_state, "source": item.endpoint.attribution_source}
                for item in decisions], indent=2))
            scope_fd = obj_get(str(PIN / "endpoint_scopes"))
            port_fd = obj_get(str(PIN / ("tcp_whitelist" if proto == "tcp" else "udp_whitelist")))
            fds.extend([scope_fd, port_fd])

            def lookup(fd, raw_key, value_size):
                key = ctypes.create_string_buffer(raw_key)
                value = ctypes.create_string_buffer(value_size)
                attr = ctypes.create_string_buffer(128)
                struct.pack_into("=I", attr, 0, fd)
                struct.pack_into("=QQ", attr, 8, ctypes.addressof(key), ctypes.addressof(value))
                try:
                    bpf(BPF_MAP_LOOKUP_ELEM, attr)
                except OSError as exc:
                    if exc.errno == errno.ENOENT:
                        return 0
                    raise
                return struct.unpack_from("=I", value)[0]

            scope_key = struct.pack("=IHBB16s", 0, PORT, 6 if proto == "tcp" else 17,
                                    socket.AF_INET, socket.inet_aton(HOST) + bytes(12))
            def admission():
                return bool(lookup(scope_fd, scope_key, 4) and
                            lookup(port_fd, struct.pack("=I", PORT), 24 if proto == "tcp" else 4))

            env = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1", "RUN_STATE_DIR": str(RUN),
                   "XDP_OBJ_PATH": str(RUN / "firewall.o")}
            watcher = subprocess.Popen([sys.executable, str(ROOT / "xdp_port_sync.py"),
                "--config", str(config_path), "--watch", "--backend", "xdp", "--mode", "enforce"],
                stdout=watch_log, stderr=watch_log, env=env)
            procs.append(watcher)
            deadline = time.monotonic() + 20
            while not admission():
                assert watcher.poll() is None, "watcher exited before admission"
                assert time.monotonic() < deadline, "authorization was not installed"
                time.sleep(0.01)
            deadline = time.monotonic() + 3
            while not records(directory / "allowed.jsonl"):
                assert time.monotonic() < deadline, "authorized application never received data"
                time.sleep(0.01)
            # Let initial EXEC/open events drain before closing A; B and client
            # already exist so their startup cannot distort the takeover delay.
            time.sleep(1.2)
            assert admission()

            def poll_maps():
                last = None
                while not monitor_stop.is_set():
                    started = time.monotonic_ns()
                    value = admission()
                    finished = time.monotonic_ns()
                    if value != last:
                        transitions.append({"start_ns": started, "end_ns": finished, "allow": value})
                        last = value
                    elif value:
                        last_open[0] = {"start_ns": started, "end_ns": finished}
                    monitor_stop.wait(0.0005)

            last_open = [{}]
            monitor = threading.Thread(target=poll_maps)
            monitor.start()
            if mode == "paused":
                watcher.send_signal(signal.SIGSTOP)
                deadline = time.monotonic() + 1
                while "\nState:\tT" not in Path(f"/proc/{watcher.pid}/status").read_text():
                    assert time.monotonic() < deadline, "watcher was not stopped"
                    time.sleep(0.001)
            tell(allowed, "close")
            closed = receive(allowed)["closed_ns"]
            tell(denied, "bind")
            bound = receive(denied)["bound_ns"]
            resumed = None
            if mode == "paused":
                time.sleep(pause_ms / 1000)
                assert admission(), "paused coordinator unexpectedly revoked admission"
                resumed = time.monotonic_ns()
                watcher.send_signal(signal.SIGCONT)
            deadline = time.monotonic() + 35
            while admission():
                assert time.monotonic() < deadline, "admission never revoked"
                time.sleep(0.001)
            time.sleep(0.25)
            assert not admission(), "admission reopened after revocation"
            monitor_stop.set()
            monitor.join()
            tell(client_proc, "stop")
            client_proc.wait(timeout=3)
            observed = get_listening_ports()
            decisions = [item for item in resolve_desired_state(observed).exposure_decisions
                         if item.endpoint.protocol == proto and item.endpoint.host_port == PORT]
            assert len(decisions) == 1 and decisions[0].action == "drop", repr(decisions)
            (directory / "after.json").write_text(json.dumps([
                {"action": item.action, "subject": item.endpoint.subject,
                 "instance_id": item.endpoint.instance_id, "reason": item.reason}
                for item in decisions], indent=2))
            tell(denied, "close")
            receive(denied)
            denied.wait(timeout=3)
            blocked = next(item for item in transitions if not item["allow"] and item["end_ns"] >= closed)
            delivered = records(directory / "denied.jsonl")
            assert all(item["recv_ns"] >= bound for item in delivered)
            after_close_attempts = [item for item in records(directory / "client.jsonl")
                                    if item["send_ns"] > blocked["end_ns"]]
            assert after_close_attempts, "no traffic was tested after revocation"
            after_close_receives = [item for item in delivered
                                    if int(item["payload"].rsplit(":", 1)[1]) > blocked["end_ns"]]
            assert not after_close_receives, "application received newly sent traffic after revocation"
            result = {"mode": mode, "protocol": proto, "trial": trial,
                      "interval_ms": interval_ms, "telemetry": telemetry, "closed_ns": closed,
                      "bound_ns": bound, "resumed_ns": resumed,
                      "last_open_poll": last_open[0], "first_closed_poll": blocked,
                      "close_to_revoke_ms": (blocked["end_ns"] - closed) / 1e6,
                      "bind_to_revoke_ms": (blocked["end_ns"] - bound) / 1e6,
                      "takeover_ms": (bound - closed) / 1e6,
                      "unauthorized_receives": len(delivered),
                      "first_unauthorized_ms": (delivered[0]["recv_ns"] - closed) / 1e6 if delivered else None,
                      "last_unauthorized_ms": (delivered[-1]["recv_ns"] - closed) / 1e6 if delivered else None,
                      "authorized_receives": len(records(directory / "allowed.jsonl")),
                      "post_revoke_attempts": len(after_close_attempts),
                      "post_revoke_receives": len(after_close_receives),
                      "relay_disconnects": (directory / "watch.log").read_text().count("pkt_relay disconnected"),
                      "map_transitions": transitions}
            (directory / "result.json").write_text(json.dumps(result, indent=2))
            print(json.dumps(result), flush=True)
            return result
        finally:
            os.kill(relay_pid, signal.SIGCONT)
            monitor_stop.set()
            if monitor:
                monitor.join(timeout=3)
            for proc in reversed(procs):
                terminate(proc)
            for fd in fds:
                os.close(fd)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--listener", nargs=4)
    parser.add_argument("--client", nargs=3)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--trials", type=int, default=10)
    parser.add_argument("--modes", nargs="+", default=["relay", "periodic", "paused"])
    parser.add_argument("--pause-ms", type=int, default=1000)
    parser.add_argument("--relay-pid", type=int)
    parser.add_argument("--interval-ms", type=float, default=10)
    parser.add_argument("--telemetry", choices=["on", "off"], default="on")
    args = parser.parse_args()
    if args.listener:
        proto, name, path, waiting = args.listener
        listener(proto, name, path, bool(int(waiting)))
        return
    if args.client:
        client(*args.client)
        return
    assert args.output and args.trials > 0 and args.pause_ms > 0 and args.relay_pid and args.interval_ms > 0
    results = []
    for mode in args.modes:
        assert mode in {"relay", "periodic", "paused"}
        for proto in (("tcp", "udp") if mode == "periodic" else ("tcp",)):
            for trial in range(args.trials if mode == "relay" else 2):
                results.append(experiment(args.output, mode, proto, trial, args.pause_ms, args.relay_pid,
                                          args.interval_ms, args.telemetry == "on"))
                (args.output / "results.json").write_text(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
