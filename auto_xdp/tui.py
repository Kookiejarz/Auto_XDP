from __future__ import annotations

import curses
import datetime as _dt
import json
import os
import select
import shutil
import socket
import subprocess
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from auto_xdp.admin_cli import (
    _collect_ports,
    _collect_stats_rows,
    _detect_backend,
    _format_rate,
    _human_bytes,
    _lookup_port_procs,
    _read_xdp_map_id,
    _read_xdp_ports,
    _autodetect_iface,
)
from auto_xdp.bpf.maps import BpfGlobalRlMap, BpfPortPolicyMap


DEFAULT_SOCKET = "/var/run/auto_xdp/pkt_events.sock"
DEFAULT_TUI_MAX_EVENTS = 500
HIGH_CHURN_MAP_COUNT_INTERVAL = 30.0

_HIGH_CHURN_MAPS = {
    "tcp_ct4",
    "tcp_ct6",
    "udp_ct4",
    "udp_ct6",
    "sctp_conntrack",
    "tcp_pd4",
    "tcp_pd6",
    "hblk4",
    "hblk6",
    "udp_hv4",
    "udp_hv6",
    "syn4",
    "syn6",
    "synag4",
    "synag6",
    "udprt4",
    "udprt6",
    "udpag4",
    "udpag6",
    "tsc4",
    "tsc6",
    "tsc_pfx4",
    "tsc_pfx6",
}

try:
    import tomllib
except ImportError:
    try:
        import tomli as tomllib  # type: ignore[no-redef]
    except ImportError:
        tomllib = None  # type: ignore[assignment]


@dataclass
class MapUsage:
    name: str
    kind: str
    current: int | None
    maximum: int | None
    pct: float | None
    note: str = ""
    map_id: int | None = None
    memlock: int | None = None


@dataclass
class TuiSnapshot:
    backend: str = "-"
    iface: str = "-"
    map_id: str = "-"
    attach_mode: str = "-"
    attach_target: str = "-"
    attach_targets: list[tuple[str, str]] = field(default_factory=list)
    collected_at: float = 0.0
    stats: list[tuple[str, int, int, str]] = field(default_factory=list)
    maps: list[MapUsage] = field(default_factory=list)
    ports: list[tuple[str, int, str, str, str]] = field(default_factory=list)
    status: str = ""


@dataclass
class MapUsageCache:
    counts: dict[str, int] = field(default_factory=dict)
    refreshed_at: dict[str, float] = field(default_factory=dict)


class RelayClient:
    def __init__(self, path: str, max_events: int = 500) -> None:
        self.path = path
        self.max_events = max_events
        self.events: list[dict[str, Any]] = []
        self.events_offset = 0
        self.status = "relay: disconnected"
        self._sock: socket.socket | None = None
        self._buf = bytearray()
        self._next_retry = 0.0
        self.ports_dirty: bool = False

    @property
    def events_end(self) -> int:
        return self.events_offset + len(self.events)

    def close(self) -> None:
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
        self._sock = None

    def poll(self) -> None:
        now = time.monotonic()
        if self._sock is None:
            if now < self._next_retry:
                return
            self._next_retry = now + 2.0
            try:
                sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                sock.setblocking(False)
                sock.connect(self.path)
            except BlockingIOError:
                self._sock = sock
                self.status = "relay: connecting"
            except OSError as exc:
                if exc.errno == 2:
                    self.status = "relay: socket missing; run `sudo systemctl restart auto-xdp-relay`"
                else:
                    self.status = f"relay: {exc.strerror or exc}"
                return
            else:
                self._sock = sock
                self.status = "relay: connected"

        sock = self._sock
        if sock is None:
            return
        try:
            readable, _, _ = select.select([sock], [], [], 0)
        except OSError:
            self.close()
            self.status = "relay: disconnected"
            return
        if not readable:
            return

        while True:
            try:
                chunk = sock.recv(65536)
            except BlockingIOError:
                break
            except OSError:
                self.close()
                self.status = "relay: disconnected"
                break
            if not chunk:
                self.close()
                self.status = "relay: disconnected"
                break
            self._buf += chunk

        while True:
            nl = self._buf.find(b"\n")
            if nl < 0:
                break
            line = self._buf[:nl]
            del self._buf[:nl + 1]
            if not line:
                continue
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                continue
            if msg.get("type") == "history":
                history = msg.get("events", [])
                if isinstance(history, list):
                    history = history[-self.max_events:]
                else:
                    history = []
                for ev in history:
                    self._append(ev)
            elif msg.get("type") == "event":
                self._append(msg)
            self.status = "relay: connected"

    def _append(self, event: dict[str, Any]) -> None:
        event.setdefault("seen_at", time.time())
        if event.get("type") == "port_change":
            self.ports_dirty = True
        self.events.append(event)
        if len(self.events) > self.max_events:
            drop_count = len(self.events) - self.max_events
            del self.events[:drop_count]
            self.events_offset += drop_count


def _load_toml(path: str) -> dict[str, Any]:
    if tomllib is None:
        return {}
    try:
        with open(path, "rb") as fh:
            return tomllib.load(fh)
    except (FileNotFoundError, OSError):
        return {}


def _ringbuf_cfg(path: str) -> dict[str, Any]:
    cfg = _load_toml(path).get("ringbuf", {})
    return cfg if isinstance(cfg, dict) else {}


def _under_attack_enabled(path: str) -> bool:
    cfg = _load_toml(path).get("under_attack", {})
    return bool(cfg.get("enabled", False)) if isinstance(cfg, dict) else False


def _positive_int(value: Any, default: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return default
    return parsed if parsed > 0 else default


def _run_json(cmd: list[str]) -> Any:
    out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL)
    return json.loads(out)


def _all_map_info() -> dict[str, dict[str, Any]]:
    """Single bpftool call → map name → metadata dict."""
    if not shutil.which("bpftool"):
        return {}
    try:
        data = _run_json(["bpftool", "-j", "map"])
    except (subprocess.CalledProcessError, OSError, json.JSONDecodeError):
        return {}
    result: dict[str, dict[str, Any]] = {}
    if isinstance(data, list):
        for entry in data:
            if isinstance(entry, dict) and "name" in entry:
                name = str(entry["name"])
                if name not in result:
                    result[name] = entry
    return result


def _dump_count(path: Path) -> int | None:
    try:
        data = _run_json(["bpftool", "-j", "map", "dump", "pinned", str(path)])
    except (subprocess.CalledProcessError, OSError, json.JSONDecodeError):
        return None
    return len(data) if isinstance(data, list) else None


def _collect_map_usage(
    bpf_pin_dir: str,
    *,
    under_attack: bool = False,
    cache: MapUsageCache | None = None,
    now: float | None = None,
    high_churn_interval: float = HIGH_CHURN_MAP_COUNT_INTERVAL,
    sample_counts: bool = True,
) -> list[MapUsage]:
    pin_dir = Path(bpf_pin_dir)
    if not pin_dir.exists():
        return [MapUsage(str(pin_dir), "-", None, None, None, "missing")]
    now = time.monotonic() if now is None else now
    cache = cache or MapUsageCache()

    try:
        tcp_ports, udp_ports = _read_xdp_ports(bpf_pin_dir)
    except Exception:
        tcp_ports, udp_ports = [], []

    all_info = _all_map_info()
    bpftool_ok = bool(shutil.which("bpftool"))
    rows: list[MapUsage] = []
    for path in sorted(p for p in pin_dir.iterdir() if p.is_file()):
        info = all_info.get(path.name, {})
        if not bpftool_ok and not info:
            continue
        name = str(info.get("name") or path.name)
        kind = str(info.get("type") or "-")
        maximum = info.get("max_entries")
        maximum = int(maximum) if isinstance(maximum, int) else None
        current: int | None
        note = ""
        if path.name == "tcp_whitelist":
            current = len(tcp_ports)
            note = "open tcp"
        elif path.name == "udp_whitelist":
            current = len(udp_ports)
            note = "open udp"
        elif not sample_counts:
            current = cache.counts.get(path.name)
            note = "cached" if current is not None else "deferred"
        elif path.name in _HIGH_CHURN_MAPS:
            last = cache.refreshed_at.get(path.name, 0.0)
            if under_attack:
                current = cache.counts.get(path.name)
                note = "attack cached" if current is not None else "attack skip"
            elif path.name in cache.counts and now - last < high_churn_interval:
                current = cache.counts[path.name]
                note = "cached"
            else:
                current = _dump_count(path)
                if current is None:
                    current = cache.counts.get(path.name)
                    note = "cached" if current is not None else "live"
                else:
                    cache.counts[path.name] = current
                    cache.refreshed_at[path.name] = now
                    note = "sampled"
        elif kind in {"array", "percpu_array"}:
            current = _dump_count(path)
        elif kind in {"ringbuf", "prog_array"}:
            current = None
        else:
            current = _dump_count(path)
        pct = (current / maximum * 100.0) if current is not None and maximum else None
        map_id_val = info.get("id")
        map_id = int(map_id_val) if isinstance(map_id_val, int) else None
        memlock_val = info.get("bytes_memlock")
        memlock = int(memlock_val) if isinstance(memlock_val, int) else None
        rows.append(MapUsage(name, kind, current, maximum, pct, note, map_id=map_id, memlock=memlock))

    def sort_key(row: MapUsage) -> tuple[float, str]:
        return (-(row.pct or -1.0), row.name)

    return sorted(rows, key=sort_key)


def _safe_service(port: int, proto: str) -> str:
    try:
        return socket.getservbyport(port, proto.lower())
    except OSError:
        return "-"


def _read_policy(path: str) -> dict[int, tuple[int, int, int, int, int, int]]:
    if not Path(path).exists():
        return {}
    try:
        m = BpfPortPolicyMap(path)
    except OSError:
        return {}
    try:
        return m.active_structs()
    finally:
        m.close()


def _read_global_udp_rate(path: str) -> int:
    if not Path(path).exists():
        return 0
    try:
        m = BpfGlobalRlMap(path)
    except OSError:
        return 0
    try:
        return m.get()
    finally:
        m.close()


def _xdp_attach_mode(iface: str) -> str:
    try:
        result = subprocess.run(
            ["ip", "-d", "link", "show", "dev", iface],
            capture_output=True,
            text=True,
        )
    except OSError:
        return "unknown"
    if result.returncode != 0:
        return "missing"
    text = result.stdout
    if "xdpgeneric" in text:
        return "xdp generic"
    if "xdpoffload" in text:
        return "xdp offload"
    if "xdp" in text:
        return "xdp native"
    return "xdp off"


def _display_mode(mode: str) -> str:
    labels = {
        "auto": "AUTO",
        "xdp native": "XDP Native",
        "xdp generic": "XDP Generic",
        "xdp offload": "XDP Offload",
        "xdp off": "XDP Off",
        "missing": "Missing",
        "unknown": "Unknown",
    }
    if mode.startswith("nftables fallback"):
        return "nftables Fallback"
    return labels.get(mode, mode or "-")


def _mode_attr(mode: str) -> int:
    if mode in {"xdp native", "xdp offload"}:
        return curses.color_pair(2)
    if mode == "xdp generic":
        return curses.color_pair(4)
    if mode.startswith("nftables fallback"):
        return curses.color_pair(3)
    if mode == "auto":
        return curses.color_pair(8)
    if mode in {"xdp off", "missing"}:
        return curses.color_pair(3)
    return curses.A_NORMAL


def _mode_badge_attr(mode: str) -> int:
    if mode in {"xdp native", "xdp offload"}:
        return curses.color_pair(5) | curses.A_BOLD
    if mode == "xdp generic":
        return curses.color_pair(6) | curses.A_BOLD
    if mode.startswith("nftables fallback"):
        return curses.color_pair(7) | curses.A_BOLD
    if mode == "auto":
        return curses.color_pair(9) | curses.A_BOLD
    if mode in {"xdp off", "missing"}:
        return curses.color_pair(7) | curses.A_BOLD
    return curses.A_BOLD


def _limit_text(proto: str, port: int, tcp_policy: dict[int, tuple[int, ...]], udp_policy: dict[int, tuple[int, ...]], global_udp: int) -> str:
    if proto == "TCP":
        fields = tcp_policy.get(port)
        if not fields:
            return "-"
        parts = []
        if fields[0]:
            parts.append(f"syn {fields[0]}/s")
        if fields[1]:
            parts.append(f"agg {fields[1]}/s")
        if fields[2]:
            parts.append(f"conn {fields[2]}")
        return ", ".join(parts) or "-"
    fields = udp_policy.get(port)
    parts = []
    if fields:
        if fields[0]:
            parts.append(f"src {fields[0]}/s")
        if fields[1]:
            parts.append(f"agg {_human_bytes(fields[1])}/s")
    if global_udp:
        parts.append(f"global {_human_bytes(global_udp)}/s")
    return ", ".join(parts) or "-"


def _collect_port_rows(
    backend: str,
    bpf_pin_dir: str,
    nft_family: str,
    nft_table: str,
    *,
    include_processes: bool = True,
) -> list[tuple[str, int, str, str, str]]:
    tcp_ports, udp_ports = _collect_ports(backend, bpf_pin_dir, nft_family, nft_table)
    tcp_procs = _lookup_port_procs("tcp", tcp_ports) if include_processes else {}
    udp_procs = _lookup_port_procs("udp", udp_ports) if include_processes else {}
    tcp_policy = _read_policy(str(Path(bpf_pin_dir) / "tcp_port_policies"))
    udp_policy = _read_policy(str(Path(bpf_pin_dir) / "udp_port_policies"))
    global_udp = _read_global_udp_rate(str(Path(bpf_pin_dir) / "udp_global_rl"))

    rows: list[tuple[str, int, str, str, str]] = []
    for proto, ports, procs in (("TCP", tcp_ports, tcp_procs), ("UDP", udp_ports, udp_procs)):
        for port in sorted(ports):
            proc_text = ",".join(sorted(procs.get(port, set()))) or "-"
            rows.append((proto, port, _safe_service(port, proto), proc_text, _limit_text(proto, port, tcp_policy, udp_policy, global_udp)))
    return rows


def _rows_to_prev(rows: list[tuple[str, int, int]]) -> dict[str, tuple[int, int]]:
    return {name: (packets, bytes_) for name, packets, bytes_ in rows}


def _collect_snapshot(
    args: Any,
    prev_stats: dict[str, tuple[int, int]],
    prev_ts: float,
    map_cache: MapUsageCache | None = None,
    *,
    fast: bool = False,
) -> tuple[TuiSnapshot, dict[str, tuple[int, int]], float]:
    ifaces = (args.iface or "").split() or []
    if not ifaces:
        ifaces = [_autodetect_iface()]
    iface = ifaces[0]
    backend = _detect_backend(Path(args.bpf_pin_dir), Path(args.run_state_dir), ifaces, args.nft_family, args.nft_table)
    map_id = _read_xdp_map_id(args.bpf_pin_dir) if backend == "xdp" else "-"
    state_file = Path(args.run_state_dir) / "axdp_stats_tui.json"
    rows, map_id = _collect_stats_rows(backend, args.bpf_pin_dir, iface, args.nft_family, args.nft_table, state_file)
    now = time.monotonic()
    elapsed = max(now - prev_ts, 0.001)
    stats_rows = []
    for name, packets, bytes_ in rows:
        old_packets, old_bytes = prev_stats.get(name, (-1, -1))
        if old_packets >= 0:
            packet_delta = packets - old_packets
            byte_delta = -1 if bytes_ == -1 or old_bytes == -1 else bytes_ - old_bytes
            if packet_delta < 0:
                packet_delta = -1
            if byte_delta < 0:
                byte_delta = -1
            rate = _format_rate(packet_delta, byte_delta, elapsed)
        else:
            rate = "-"
        stats_rows.append((name, packets, bytes_, rate))
    if backend == "xdp":
        attach_targets = [(name, _xdp_attach_mode(name)) for name in ifaces]
        modes = {mode for _, mode in attach_targets}
        attach_mode = attach_targets[0][1] if len(modes) == 1 else "auto"
        attach_target = " ".join(name for name, _ in attach_targets)
    else:
        attach_mode = f"nftables fallback ({args.nft_family} {args.nft_table})"
        attach_targets = [(name, attach_mode) for name in ifaces]
        attach_target = " ".join(ifaces)

    snap = TuiSnapshot(
        backend=backend,
        iface=iface,
        map_id=map_id,
        attach_mode=attach_mode,
        attach_target=attach_target,
        attach_targets=attach_targets,
        collected_at=now,
        stats=stats_rows,
        maps=_collect_map_usage(
            args.bpf_pin_dir,
            under_attack=_under_attack_enabled(args.config),
            cache=map_cache,
            sample_counts=not fast,
        ),
        ports=_collect_port_rows(
            backend,
            args.bpf_pin_dir,
            args.nft_family,
            args.nft_table,
            include_processes=not fast,
        ),
    )
    return snap, _rows_to_prev(rows), now


class SnapshotWorker:
    def __init__(self, args: Any) -> None:
        self._args = args
        self._interval = max(float(args.interval), 0.5)
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._wakeup = threading.Event()
        self._thread = threading.Thread(target=self._run, name="auto-xdp-tui-collector", daemon=True)
        self._snapshot = TuiSnapshot(status="collecting")
        self._error = ""
        self._prev_stats: dict[str, tuple[int, int]] = {}
        self._prev_ts = time.monotonic()
        self._map_cache = MapUsageCache()
        self._first_collect = True

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        self._wakeup.set()
        self._thread.join(timeout=1.0)

    def wakeup(self) -> None:
        self._wakeup.set()

    def get(self) -> tuple[TuiSnapshot, str]:
        with self._lock:
            return self._snapshot, self._error

    def _set_result(self, snapshot: TuiSnapshot, error: str) -> None:
        with self._lock:
            self._snapshot = snapshot
            self._error = error

    def _run(self) -> None:
        while not self._stop.is_set():
            started = time.monotonic()
            try:
                snap, self._prev_stats, self._prev_ts = _collect_snapshot(
                    self._args,
                    self._prev_stats,
                    self._prev_ts,
                    self._map_cache,
                    fast=self._first_collect,
                )
                self._first_collect = False
                snap.status = f"updated {_dt.datetime.now().strftime('%H:%M:%S')}"
                self._set_result(snap, "")
            except Exception as exc:
                with self._lock:
                    self._error = str(exc)
            elapsed = time.monotonic() - started
            self._wakeup.wait(max(0.05, self._interval - elapsed))
            self._wakeup.clear()


@dataclass
class _WinSet:
    h: int
    w: int
    maps: Any
    events: Any
    summary: Any
    ports: Any


def _make_win_set(stdscr: Any) -> _WinSet | None:
    h, w = stdscr.getmaxyx()
    if h < 20 or w < 80:
        return None
    left_w = max(48, int(w * 0.56))
    right_w = w - left_w
    top_h = max(8, int((h - 1) * 0.36))
    summary_h = 8
    return _WinSet(
        h=h, w=w,
        maps=stdscr.derwin(top_h, left_w, 1, 0),
        events=stdscr.derwin(h - top_h - 1, left_w, 1 + top_h, 0),
        summary=stdscr.derwin(summary_h, right_w, 1, left_w),
        ports=stdscr.derwin(h - summary_h - 1, right_w, 1 + summary_h, left_w),
    )


def _clip(text: str, width: int) -> str:
    if width <= 0:
        return ""
    return text[: max(0, width - 1)]


def _map_visible_count(term_height: int) -> int:
    top_h = max(8, int((term_height - 1) * 0.36))
    return max(1, top_h - 3)


def _box(win: Any, title: str) -> None:
    h, w = win.getmaxyx()
    if h < 2 or w < 2:
        return
    win.box()
    win.addstr(0, 2, _clip(f" {title} ", max(0, w - 4)), curses.A_BOLD)


def _add(win: Any, y: int, x: int, text: str, attr: int = 0) -> None:
    h, w = win.getmaxyx()
    if 0 <= y < h and x < w:
        try:
            win.addstr(y, x, _clip(text, w - x), attr)
        except curses.error:
            pass


def _draw_maps(win: Any, rows: list[MapUsage], scroll: int, focused: bool) -> None:
    total_mem = sum(r.memlock for r in rows if r.memlock is not None)
    mem_label = f"  total {_human_bytes(total_mem)}" if total_mem else ""
    _box(win, f"BPF maps{mem_label}" + (" *" if focused else ""))
    _add(win, 1, 1, f"{'id':>5} {'map':<18} {'type':<10} {'used':>7} {'max':>7} {'%':>5} {'mem':>8}")
    visible = max(0, win.getmaxyx()[0] - 3)
    scroll = max(0, min(scroll, max(0, len(rows) - visible)))
    for idx, row in enumerate(rows[scroll: scroll + visible], start=2):
        id_str = str(row.map_id) if row.map_id is not None else "-"
        used = "-" if row.current is None else str(row.current)
        maximum = "-" if row.maximum is None else str(row.maximum)
        pct = "-" if row.pct is None else f"{row.pct:5.1f}"
        mem = "-" if row.memlock is None else _human_bytes(row.memlock)
        attr = curses.A_NORMAL
        if row.pct is not None and row.pct >= 80:
            attr = curses.color_pair(3) | curses.A_BOLD
        _add(win, idx, 1, f"{id_str:>5} {row.name:<18.18} {row.kind:<10.10} {used:>7} {maximum:>7} {pct:>5} {mem:>8}", attr)
    if len(rows) > visible:
        _add(win, win.getmaxyx()[0] - 1, 2, f"{scroll + 1}-{min(scroll + visible, len(rows))}/{len(rows)}  tab focus", curses.A_DIM)


def _draw_summary(win: Any, snap: TuiSnapshot) -> None:
    _box(win, "stats")
    _add(win, 1, 1, "Mode: ")
    _add(win, 1, 7, f"[{_display_mode(snap.attach_mode)}]", _mode_attr(snap.attach_mode))
    _add(win, 2, 1, "Attach: ")
    x = 9
    targets = snap.attach_targets or [(snap.attach_target, snap.attach_mode)]
    for idx, (target, mode) in enumerate(targets):
        if idx:
            _add(win, 2, x, " ")
            x += 1
        _add(win, 2, x, target, _mode_badge_attr(mode))
        x += len(target)
    _add(win, win.getmaxyx()[0] - 1, 2, snap.status, curses.A_DIM)
    drops = next((r for r in snap.stats if r[0] == "XDP_DROP_TOTAL"), None)
    total = next((r for r in snap.stats if r[0] == "XDP_TOTAL"), None)
    iface = next((r for r in snap.stats if r[0] == "IFACE_RX"), None)
    y = 3
    for row in (total, drops, iface):
        if row is None:
            continue
        name, packets, bytes_, rate = row
        _add(win, y, 1, f"{name:<14} {packets:<12} {_human_bytes(bytes_):<11} {rate}")
        y += 1


def _event_bottom_top(relay: RelayClient, visible: int) -> int:
    return max(relay.events_offset, relay.events_end - visible)


def _clamp_event_top(relay: RelayClient, visible: int, top: int) -> int:
    if not relay.events:
        return relay.events_offset
    return max(relay.events_offset, min(top, _event_bottom_top(relay, visible)))


def _event_window(relay: RelayClient, visible: int, top: int) -> tuple[int, int, list[dict[str, Any]]]:
    top = _clamp_event_top(relay, visible, top)
    start = max(0, top - relay.events_offset)
    events = relay.events[start:start + visible] if visible else []
    return top, start, events


def _draw_events(win: Any, relay: RelayClient, snap: TuiSnapshot, top: int, focused: bool) -> None:
    _box(win, "events" + (" *" if focused else ""))
    _add(win, 1, 1, f"{'time':<8} {'v':<5} {'protocol':<8} {'source':<36} {'dport':>5} reason")
    visible = max(0, win.getmaxyx()[0] - 3)
    _, start, events = _event_window(relay, visible, top)
    follow = top >= _event_bottom_top(relay, visible)
    for i, ev in enumerate(events, start=2):
        ts = float(ev.get("seen_at", time.time()))
        tstr = _dt.datetime.fromtimestamp(ts).strftime("%H:%M:%S")
        verdict = str(ev.get("verdict", "DROP"))
        attr = curses.color_pair(2) if verdict == "ALLOW" else curses.color_pair(3)
        source = f"{ev.get('src', '-')}/{ev.get('sport', '-')}"
        line = f"{tstr:<8} {verdict:<5} {str(ev.get('proto', '-')):<8.8} {source:<36.36} {str(ev.get('dport', '-')):>5} {ev.get('reason', '-')}"
        _add(win, i, 1, line, attr)
    footer = relay.status
    if visible > 0 and len(relay.events) > visible:
        oldest = start + 1
        newest = min(start + len(events), len(relay.events))
        live_tag = " [LIVE]" if follow else " [PAUSED ↑↓]"
        footer = f"{oldest}-{newest}/{len(relay.events)}{live_tag}  tab focus  {relay.status}"
    _add(win, win.getmaxyx()[0] - 1, 2, footer, curses.A_DIM)


def _port_key(row: tuple[str, int, str, str, str]) -> tuple[str, int]:
    return row[0], row[1]


def _filter_port_rows(
    rows: list[tuple[str, int, str, str, str]],
    proto_filter: str,
) -> list[tuple[str, int, str, str, str]]:
    if proto_filter not in {"TCP", "UDP"}:
        return rows
    return [row for row in rows if row[0] == proto_filter]


def _port_filter_title(proto_filter: str) -> str:
    if proto_filter == "TCP":
        return "ports / services / limits [TCP]"
    if proto_filter == "UDP":
        return "ports / services / limits [UDP]"
    return "ports / services / limits [all]"


def _draw_ports(
    win: Any,
    rows: list[tuple[str, int, str, str, str]],
    port_marks: dict[tuple[str, int], tuple[str, float, tuple[str, int, str, str, str]]],
    proto_filter: str = "all",
) -> None:
    _box(win, _port_filter_title(proto_filter))
    _add(win, 1, 1, f"{'p':<3} {'port':>5} {'service':<12} {'process':<16} limit")
    now = time.monotonic()
    display_rows = list(rows)
    current_keys = {_port_key(row) for row in rows}
    removed_rows = [
        marked_row
        for key, (kind, expires_at, marked_row) in port_marks.items()
        if kind == "removed" and expires_at > now and key not in current_keys
    ]
    display_rows.extend(sorted(removed_rows, key=lambda row: (row[0], row[1])))
    display_rows = _filter_port_rows(display_rows, proto_filter)

    for idx, (proto, port, svc, proc, limit) in enumerate(display_rows[: max(0, win.getmaxyx()[0] - 3)], start=2):
        mark = port_marks.get((proto, port))
        attr = curses.A_NORMAL
        if mark and mark[1] > now:
            if mark[0] == "added":
                attr = curses.color_pair(4) | curses.A_BOLD
            elif mark[0] == "removed":
                attr = curses.color_pair(3) | curses.A_BOLD
        _add(win, idx, 1, f"{proto:<3} {port:>5} {svc:<12.12} {proc:<16.16} {limit}", attr)


def _draw(
    stdscr: Any,
    snap: TuiSnapshot,
    relay: RelayClient,
    last_error: str,
    map_scroll: int,
    event_top: int,
    focus: str,
    port_marks: dict[tuple[str, int], tuple[str, float, tuple[str, int, str, str, str]]],
    wins: _WinSet | None,
    port_filter: str,
) -> None:
    stdscr.erase()
    h, w = stdscr.getmaxyx()
    if wins is None:
        _add(stdscr, 0, 0, "terminal too small; need at least 80x20")
        stdscr.refresh()
        return
    now = _dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    title = f"Auto XDP TUI  backend={snap.backend} iface={snap.iface} mode={snap.attach_mode} map={snap.map_id} ports={port_filter}  {now}  tab:focus t/u:ports q:quit"
    _add(stdscr, 0, 0, _clip(title, w), curses.A_REVERSE)
    if last_error:
        _add(stdscr, h - 1, 0, _clip(last_error, w), curses.color_pair(3) | curses.A_BOLD)
    _draw_maps(wins.maps, snap.maps, map_scroll, focus == "maps")
    _draw_events(wins.events, relay, snap, event_top, focus == "events")
    _draw_summary(wins.summary, snap)
    _draw_ports(wins.ports, snap.ports, port_marks, port_filter)
    stdscr.refresh()


def _curses_main(stdscr: Any, args: Any) -> int:
    curses.curs_set(0)
    curses.start_color()
    curses.use_default_colors()
    curses.init_pair(2, curses.COLOR_GREEN, -1)
    curses.init_pair(3, curses.COLOR_RED, -1)
    curses.init_pair(4, curses.COLOR_YELLOW, -1)
    curses.init_pair(5, curses.COLOR_BLACK, curses.COLOR_GREEN)
    curses.init_pair(6, curses.COLOR_BLACK, curses.COLOR_YELLOW)
    curses.init_pair(7, curses.COLOR_WHITE, curses.COLOR_RED)
    curses.init_pair(8, curses.COLOR_CYAN, -1)
    curses.init_pair(9, curses.COLOR_BLACK, curses.COLOR_CYAN)
    stdscr.nodelay(True)
    stdscr.timeout(50)

    relay = RelayClient(args.socket, max_events=int(args.tui_max_events))
    worker = SnapshotWorker(args)
    worker.start()
    map_scroll = 0
    event_top = 0
    focus = "maps"
    last_ports_snapshot_at = 0.0
    previous_port_rows: dict[tuple[str, int], tuple[str, int, str, str, str]] | None = None
    port_marks: dict[tuple[str, int], tuple[str, float, tuple[str, int, str, str, str]]] = {}
    port_filter = "all"
    wins: _WinSet | None = None

    def _refresh_wins() -> None:
        nonlocal wins
        h, w = stdscr.getmaxyx()
        if wins is not None and wins.h == h and wins.w == w:
            return
        stdscr.clear()
        wins = _make_win_set(stdscr)

    _refresh_wins()

    try:
        while True:
            ch = stdscr.getch()
            if ch in (ord("q"), ord("Q")):
                return 0
            if ch == curses.KEY_RESIZE:
                _refresh_wins()
            elif ch in (ord("t"), ord("T")):
                port_filter = "all" if port_filter == "TCP" else "TCP"
            elif ch in (ord("u"), ord("U")):
                port_filter = "all" if port_filter == "UDP" else "UDP"
            snap, last_error = worker.get()
            now = time.monotonic()
            port_marks = {
                key: mark
                for key, mark in port_marks.items()
                if mark[1] > now
            }
            if relay.ports_dirty:
                relay.ports_dirty = False
                worker.wakeup()
            if snap.collected_at > last_ports_snapshot_at:
                current_port_rows = {_port_key(row): row for row in snap.ports}
                if previous_port_rows is not None:
                    expires_at = now + 2.0
                    previous_keys = set(previous_port_rows)
                    current_keys = set(current_port_rows)
                    for key in current_keys - previous_keys:
                        port_marks[key] = ("added", expires_at, current_port_rows[key])
                    for key in previous_keys - current_keys:
                        port_marks[key] = ("removed", expires_at, previous_port_rows[key])
                previous_port_rows = current_port_rows
                last_ports_snapshot_at = snap.collected_at
            if wins is not None:
                map_visible = max(1, wins.maps.getmaxyx()[0] - 3)
                event_visible = max(1, wins.events.getmaxyx()[0] - 3)
            else:
                map_visible = 1
                event_visible = 1
            map_scroll_max = max(0, len(snap.maps) - map_visible)
            event_top = _clamp_event_top(relay, event_visible, event_top)
            if ch == 9:
                focus = "events" if focus == "maps" else "maps"
            if ch == curses.KEY_UP:
                if focus == "events":
                    event_top = max(relay.events_offset, event_top - 1)
                else:
                    map_scroll = max(0, map_scroll - 1)
            elif ch == curses.KEY_DOWN:
                if focus == "events":
                    event_top = min(_event_bottom_top(relay, event_visible), event_top + 1)
                else:
                    map_scroll = min(map_scroll_max, map_scroll + 1)
            elif ch == curses.KEY_PPAGE:
                if focus == "events":
                    event_top = max(relay.events_offset, event_top - event_visible)
                else:
                    map_scroll = max(0, map_scroll - map_visible)
            elif ch == curses.KEY_NPAGE:
                if focus == "events":
                    event_top = min(_event_bottom_top(relay, event_visible), event_top + event_visible)
                else:
                    map_scroll = min(map_scroll_max, map_scroll + map_visible)
            follow_events = event_top >= _event_bottom_top(relay, event_visible)
            relay.poll()
            _refresh_wins()
            map_scroll = min(map_scroll, max(0, len(snap.maps) - map_visible))
            if follow_events:
                event_top = _event_bottom_top(relay, event_visible)
            else:
                event_top = _clamp_event_top(relay, event_visible, event_top)
            _draw(stdscr, snap, relay, last_error, map_scroll, event_top, focus, port_marks, wins, port_filter)
    finally:
        worker.stop()
        relay.close()


def run_tui(args: Any) -> int:
    if os.name != "posix":
        raise RuntimeError("TUI requires a POSIX terminal")
    rb_cfg = _ringbuf_cfg(args.config)
    if not args.socket:
        args.socket = str(rb_cfg.get("socket_path", DEFAULT_SOCKET))
    args.tui_max_events = _positive_int(
        getattr(args, "tui_max_events", None) or rb_cfg.get("tui_max_events", DEFAULT_TUI_MAX_EVENTS),
        DEFAULT_TUI_MAX_EVENTS,
    )
    try:
        return curses.wrapper(_curses_main, args)
    except curses.error as exc:
        raise RuntimeError("TUI requires an interactive terminal") from exc
