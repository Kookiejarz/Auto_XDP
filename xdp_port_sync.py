#!/usr/bin/env python3
"""XDP Port Whitelist Auto-Sync Daemon

Port discovery  : psutil  (reads /proc directly, no subprocesses)
Map operations  : bpf(2) syscall via ctypes  (no bpftool)
Event trigger   : Linux Netlink Process Connector (EXEC/EXIT)
Fallback        : periodic poll every --interval seconds (default 30)
"""
from __future__ import annotations
import argparse, ctypes, ctypes.util, logging, os, platform
import select, socket, struct, sys, time
from dataclasses import dataclass, field

try:
    import psutil
except ImportError:
    sys.exit("psutil not installed. Run: pip3 install psutil")

TCP_MAP_PATH = "/sys/fs/bpf/xdp_fw/tcp_whitelist"
UDP_MAP_PATH = "/sys/fs/bpf/xdp_fw/udp_whitelist"

# Always-whitelisted ports (e.g. SSH emergency fallback)
TCP_PERMANENT: dict[int, str] = {}
UDP_PERMANENT: dict[int, str] = {}

# Wait this long after an EXEC/EXIT event before scanning,
# giving the new process time to call bind().
DEBOUNCE_S = 0.3

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger(__name__)

# psutil 6.0 renamed net_connections() → connections()
_net_connections = getattr(psutil, "connections", psutil.net_connections)

# ── BPF syscall layer ─────────────────────────────────────────────────
_libc   = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
_NR_BPF: int = {
    "x86_64":  321,
    "aarch64": 280,
    "armv7l":  386,
    "armv6l":  386,
}.get(platform.machine(), 321)

_BPF_MAP_LOOKUP_ELEM = 1
_BPF_MAP_UPDATE_ELEM = 2
_BPF_OBJ_GET         = 7


def _bpf(cmd: int, attr: ctypes.Array) -> int:
    ret = _libc.syscall(_NR_BPF, ctypes.c_int(cmd), attr, ctypes.c_uint(len(attr)))
    if ret < 0:
        err = ctypes.get_errno()
        raise OSError(err, os.strerror(err))
    return ret


def _obj_get(path: str) -> int:
    """Open a pinned BPF object; return its fd."""
    path_b = ctypes.create_string_buffer(path.encode() + b"\x00")
    attr   = ctypes.create_string_buffer(128)
    struct.pack_into("=Q", attr, 0, ctypes.cast(path_b, ctypes.c_void_p).value or 0)
    return _bpf(_BPF_OBJ_GET, attr)


class BpfArrayMap:
    """Pinned BPF ARRAY map (key = __u32 port, value = __u32 0/1).

    Write-through in-memory cache — sync_once() only issues syscalls for
    ports that actually changed.  Cache starts empty; the first sync_once()
    call populates it.  Any stale entries from a previous daemon run are
    cleaned up on the first sync cycle.

    bpf_attr layout for MAP_LOOKUP / MAP_UPDATE:
      offset  0 : map_fd  (u32)
      offset  4 : pad     (4 bytes)
      offset  8 : key ptr (u64)
      offset 16 : val ptr (u64)
      offset 24 : flags   (u64)
    """

    def __init__(self, path: str) -> None:
        self.path  = path
        self.fd    = _obj_get(path)
        self._cache: set[int] = set()

        # Pre-allocate reusable ctypes buffers (avoids per-call allocation)
        self._key  = ctypes.create_string_buffer(4)
        self._val  = ctypes.create_string_buffer(4)
        self._attr = ctypes.create_string_buffer(128)
        k_ptr = ctypes.cast(self._key, ctypes.c_void_p).value or 0
        v_ptr = ctypes.cast(self._val, ctypes.c_void_p).value or 0
        struct.pack_into("=I4xQQQ", self._attr, 0, self.fd, k_ptr, v_ptr, 0)

    def close(self) -> None:
        if self.fd >= 0:
            os.close(self.fd)
            self.fd = -1

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass

    def _update(self, port: int, val: int) -> None:
        struct.pack_into("=I", self._key, 0, port)
        struct.pack_into("=I", self._val, 0, val)
        _bpf(_BPF_MAP_UPDATE_ELEM, self._attr)  # flags=0 → BPF_ANY

    def active_ports(self) -> set[int]:
        return set(self._cache)

    def set(self, port: int, val: int, dry_run: bool = False) -> bool:
        """Write val (0 or 1) for port; update the cache on success."""
        if dry_run:
            log.info("[DRY] %s port %d → %d", self.path, port, val)
            self._cache.add(port) if val else self._cache.discard(port)
            return True
        try:
            self._update(port, val)
            self._cache.add(port) if val else self._cache.discard(port)
            return True
        except OSError as exc:
            log.warning("BPF update failed port=%d: %s", port, exc)
            return False


# ── Port discovery ────────────────────────────────────────────────────
@dataclass
class PortState:
    tcp: set = field(default_factory=set)
    udp: set = field(default_factory=set)


def get_listening_ports() -> PortState:
    """Read listening TCP/UDP ports via psutil (no subprocess)."""
    state = PortState()
    for conn in _net_connections(kind="inet"):
        if not (conn.laddr and conn.laddr.port):
            continue
        if conn.type == socket.SOCK_STREAM and conn.status == psutil.CONN_LISTEN:
            state.tcp.add(conn.laddr.port)
        elif conn.type == socket.SOCK_DGRAM:
            state.udp.add(conn.laddr.port)
    return state


# ── Sync ──────────────────────────────────────────────────────────────
def sync_once(tcp_map: BpfArrayMap, udp_map: BpfArrayMap, dry_run: bool) -> None:
    current    = get_listening_ports()
    tcp_target = current.tcp | set(TCP_PERMANENT)
    udp_target = current.udp | set(UDP_PERMANENT)
    changed    = False

    for port in sorted(tcp_target - tcp_map.active_ports()):
        tag = f" [{TCP_PERMANENT[port]}]" if port in TCP_PERMANENT else ""
        if tcp_map.set(port, 1, dry_run):
            log.info("TCP +%d%s", port, tag)
            changed = True

    for port in sorted(tcp_map.active_ports() - tcp_target - set(TCP_PERMANENT)):
        if tcp_map.set(port, 0, dry_run):
            log.info("TCP -%d  (stopped)", port)
            changed = True

    for port in sorted(udp_target - udp_map.active_ports()):
        tag = f" [{UDP_PERMANENT[port]}]" if port in UDP_PERMANENT else ""
        if udp_map.set(port, 1, dry_run):
            log.info("UDP +%d%s", port, tag)
            changed = True

    for port in sorted(udp_map.active_ports() - udp_target - set(UDP_PERMANENT)):
        if udp_map.set(port, 0, dry_run):
            log.info("UDP -%d  (stopped)", port)
            changed = True

    if not changed:
        log.debug("Whitelist up-to-date.")


# ── Netlink Process Connector ─────────────────────────────────────────
_NETLINK_CONNECTOR    = 11
_CN_IDX_PROC          = 1
_NLMSG_HDRLEN         = 16
_CN_MSG_HDRLEN        = 20   # idx(4)+val(4)+seq(4)+ack(4)+len(2)+flags(2)
_NLMSG_MIN_TYPE       = 0x10
_PROC_CN_MCAST_LISTEN = 1
_PROC_EVENT_EXEC      = 0x00000002
_PROC_EVENT_EXIT      = 0x80000000


def _make_subscribe_msg(pid: int) -> bytes:
    op  = struct.pack("I", _PROC_CN_MCAST_LISTEN)
    cn  = struct.pack("IIIIHH", _CN_IDX_PROC, 1, 0, 0, len(op), 0) + op
    hdr = struct.pack("IHHII", _NLMSG_HDRLEN + len(cn), _NLMSG_MIN_TYPE, 0, 0, pid)
    return hdr + cn


def open_proc_connector():
    try:
        sock = socket.socket(socket.AF_NETLINK, socket.SOCK_DGRAM, _NETLINK_CONNECTOR)
        sock.bind((os.getpid(), _CN_IDX_PROC))
        sock.send(_make_subscribe_msg(os.getpid()))
        log.info("Netlink proc connector active — event-driven mode.")
        return sock
    except OSError as exc:
        log.warning("Netlink unavailable (%s); falling back to poll-only mode.", exc)
        return None


def drain_proc_events(sock: socket.socket) -> bool:
    """Drain buffered netlink messages; return True if any EXEC/EXIT seen."""
    triggered = False
    while True:
        try:
            rdy, _, _ = select.select([sock], [], [], 0)
            if not rdy:
                break
            data = sock.recv(4096)
        except OSError:
            break
        offset = 0
        while offset + _NLMSG_HDRLEN <= len(data):
            nl_len = struct.unpack_from("I", data, offset)[0]
            if nl_len < _NLMSG_HDRLEN:
                break
            cn_off = offset + _NLMSG_HDRLEN
            if cn_off + _CN_MSG_HDRLEN <= offset + nl_len:
                idx     = struct.unpack_from("I", data, cn_off)[0]
                cn_data = cn_off + _CN_MSG_HDRLEN
                if idx == _CN_IDX_PROC and cn_data + 4 <= offset + nl_len:
                    what = struct.unpack_from("I", data, cn_data)[0]
                    if what in (_PROC_EVENT_EXEC, _PROC_EVENT_EXIT):
                        triggered = True
            offset += (nl_len + 3) & ~3  # NLMSG_ALIGN
    return triggered


# ── Watch loop ────────────────────────────────────────────────────────
def watch(interval: int, dry_run: bool) -> None:
    tcp_map = BpfArrayMap(TCP_MAP_PATH)
    udp_map = BpfArrayMap(UDP_MAP_PATH)
    nl      = open_proc_connector()

    sync_once(tcp_map, udp_map, dry_run)
    last_sync_t  = time.monotonic()
    last_event_t = 0.0

    try:
        while True:
            now       = time.monotonic()
            poll_due  = last_sync_t + interval
            deb_due   = (last_event_t + DEBOUNCE_S) if last_event_t else float("inf")
            sleep_for = max(0.05, min(poll_due, deb_due) - now)

            try:
                if nl and not last_event_t:
                    # Do NOT select while already debouncing — prevents spinning
                    # when EXEC/EXIT events arrive continuously (cron, logrotate).
                    rdy, _, _ = select.select([nl], [], [], sleep_for)
                    if rdy and drain_proc_events(nl):
                        log.debug("Proc event — debounce armed.")
                        last_event_t = time.monotonic()
                else:
                    time.sleep(sleep_for)
            except OSError as exc:
                log.warning("Netlink error (%s); switching to poll-only mode.", exc)
                if nl:
                    nl.close()
                nl = None
                continue

            now            = time.monotonic()
            debounce_fired = bool(last_event_t) and (now - last_event_t >= DEBOUNCE_S)
            fallback_fired = (now - last_sync_t >= interval)

            if debounce_fired or fallback_fired:
                # Flush events that piled up during debounce/poll window
                # to prevent self-triggering on our own psutil /proc reads.
                if nl:
                    drain_proc_events(nl)
                log.debug("Sync triggered by %s.", "event" if debounce_fired else "poll")
                try:
                    sync_once(tcp_map, udp_map, dry_run)
                except Exception as exc:
                    log.error("Sync error: %s", exc)
                last_sync_t  = time.monotonic()
                last_event_t = 0.0

    except KeyboardInterrupt:
        log.info("Shutting down.")
    finally:
        if nl:
            nl.close()
        tcp_map.close()
        udp_map.close()


# ── Entry point ───────────────────────────────────────────────────────
def main() -> None:
    p = argparse.ArgumentParser(description="XDP port-whitelist sync daemon")
    p.add_argument("--watch",    action="store_true",
                   help="Run as a daemon (event-driven + fallback poll)")
    p.add_argument("--interval", type=int, default=30,
                   help="Fallback poll interval in seconds (default: 30)")
    p.add_argument("--dry-run",  action="store_true",
                   help="Print operations without executing them")
    args = p.parse_args()

    if args.watch:
        watch(args.interval, args.dry_run)
    else:
        tcp_map = BpfArrayMap(TCP_MAP_PATH)
        udp_map = BpfArrayMap(UDP_MAP_PATH)
        try:
            sync_once(tcp_map, udp_map, args.dry_run)
            log.info("Sync completed.")
        finally:
            tcp_map.close()
            udp_map.close()


if __name__ == "__main__":
    main()
