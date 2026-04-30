"""Port discovery: SOCK_DIAG netlink on Linux, psutil fallback elsewhere."""
from __future__ import annotations

import ipaddress
import logging
import os
import socket
import struct
import subprocess
import sys

from auto_xdp import config as cfg
from auto_xdp.state import ObservedState

log = logging.getLogger(__name__)

_IS_LINUX = sys.platform == "linux"

# ── psutil (non-Linux fallback) ───────────────────────────────────────────────

try:
    import psutil
except ImportError:
    psutil = None

# Kept for backward-compat import by external callers.
_net_connections = None
if psutil is not None:
    _net_connections = getattr(psutil, "connections", psutil.net_connections)

# SOCK_DIAG constants & structs

_NETLINK_INET_DIAG = 4
_SOCK_DIAG_BY_FAMILY = 20
_NLMSG_DONE = 3
_NLMSG_ERROR = 2
_NLM_F_REQUEST = 0x01
_NLM_F_DUMP = 0x300  # NLM_F_ROOT | NLM_F_MATCH

_SS_LISTEN = 1 << 10
_SS_ESTABLISHED = 1 << 1
_SS_ALL = 0xFFFFFFFF

_IPPROTO_SCTP = 132

# struct nlmsghdr (16 bytes)
_NLMSGHDR = struct.Struct("=IHHII")
# struct inet_diag_req_v2 (56 bytes)
_DIAG_REQ = struct.Struct("=BBBBIHH16s16sIII")
# struct inet_diag_msg (72 bytes)
_DIAG_MSG = struct.Struct("=BBBBHH16s16sIIIIIIII")

_NLMSGHDR_SZ = _NLMSGHDR.size   # 16
_DIAG_REQ_SZ = _DIAG_REQ.size   # 56
_DIAG_MSG_SZ = _DIAG_MSG.size   # 72
_ZERO16 = bytes(16)
_RECV_BUFSZ = 1 << 16  # 64 KB


# low-level netlink helpers

def _nldiag_dump(family: int, proto: int, states: int):
    """Yield (sport_h, dport_h, src_16b, dst_16b, inode, rqueue) per matching socket.

    Ports are returned in host byte order.  Addresses are 16-byte big-endian
    buffers suitable for socket.inet_ntop / struct.pack("!...").
    """
    with socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, _NETLINK_INET_DIAG) as nl:
        nl.bind((0, 0))
        req = (
            _NLMSGHDR.pack(
                _NLMSGHDR_SZ + _DIAG_REQ_SZ,
                _SOCK_DIAG_BY_FAMILY,
                _NLM_F_REQUEST | _NLM_F_DUMP,
                1, 0,
            )
            + _DIAG_REQ.pack(
                family, proto, 0, 0, states,
                0, 0, _ZERO16, _ZERO16, 0, 0xFFFFFFFF, 0xFFFFFFFF,
            )
        )
        nl.sendall(req)
        buf = bytearray(_RECV_BUFSZ)
        while True:
            n = nl.recv_into(buf)
            if n == 0:
                break
            offset = 0
            done = False
            while offset + _NLMSGHDR_SZ <= n:
                msg_len, msg_type, _fl, _seq, _pid = _NLMSGHDR.unpack_from(buf, offset)
                if msg_len < _NLMSGHDR_SZ:
                    break
                if msg_type == _NLMSG_DONE:
                    done = True
                    break
                if msg_type == _NLMSG_ERROR:
                    done = True
                    break
                if (
                    msg_type == _SOCK_DIAG_BY_FAMILY
                    and offset + _NLMSGHDR_SZ + _DIAG_MSG_SZ <= n
                ):
                    (
                        _fam, _st, _ti, _re,
                        sport_raw, dport_raw, src, dst,
                        _if, _c0, _c1,
                        _exp, rqueue, _wq, _uid, inode,
                    ) = _DIAG_MSG.unpack_from(buf, offset + _NLMSGHDR_SZ)
                    yield (
                        socket.ntohs(sport_raw),
                        socket.ntohs(dport_raw),
                        src, dst, inode, rqueue,
                    )
                offset += (msg_len + 3) & ~3
            if done:
                break


def _build_inode_pid() -> dict[int, int]:
    """Return {socket_inode: pid} by scanning /proc/*/fd symlinks."""
    result: dict[int, int] = {}
    try:
        with os.scandir("/proc") as proc_it:
            for proc_entry in proc_it:
                if not proc_entry.name.isdigit():
                    continue
                pid = int(proc_entry.name)
                try:
                    with os.scandir(f"/proc/{pid}/fd") as fd_it:
                        for fd_entry in fd_it:
                            try:
                                link = os.readlink(fd_entry.path)
                                if link.startswith("socket:["):
                                    result[int(link[8:-1])] = pid
                            except OSError:
                                pass
                except OSError:
                    pass
    except OSError:
        pass
    return result


def _pid_comm(pid: int) -> str:
    try:
        with open(f"/proc/{pid}/comm") as f:
            return f.read().strip()
    except OSError:
        return ""


def _addr_str(family: int, raw: bytes) -> str:
    return socket.inet_ntop(family, raw[:4] if family == socket.AF_INET else raw)


def _pack_conntrack_key_raw(family: int, sport_h: int, dport_h: int, src: bytes, dst: bytes) -> bytes:
    """Pack XDP conntrack lookup key from SOCK_DIAG fields."""
    if family == socket.AF_INET:
        return struct.pack("!HH4s4s", dport_h, sport_h, dst[:4], src[:4])
    return struct.pack("!HH16s16s", dport_h, sport_h, dst, src)


# shared helpers (used by both paths)

def _pack_tcp_conntrack_key(conn) -> bytes:
    if conn.family == socket.AF_INET:
        remote_ip = socket.inet_aton(conn.raddr.ip)
        local_ip = socket.inet_aton(conn.laddr.ip)
        return struct.pack("!HH4s4s", conn.raddr.port, conn.laddr.port, remote_ip, local_ip)
    remote_ip = socket.inet_pton(socket.AF_INET6, conn.raddr.ip)
    local_ip = socket.inet_pton(socket.AF_INET6, conn.laddr.ip)
    return struct.pack("!HH16s16s", conn.raddr.port, conn.laddr.port, remote_ip, local_ip)


def _resolve_pid_name(pid: int, cache: dict[int, str]) -> str:
    if pid not in cache:
        try:
            cache[pid] = psutil.Process(pid).name()
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess) as exc:
            log.debug("Failed to resolve process name for pid=%s: %s", pid, exc)
            cache[pid] = ""
    return cache[pid]


def _discovery_exclude_networks() -> tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]:
    nets: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    for cidr in cfg.DISCOVERY_EXCLUDE_BIND_CIDRS:
        try:
            nets.append(ipaddress.ip_network(cidr, strict=False))
        except ValueError:
            log.warning("Ignoring invalid discovery exclude_bind_cidrs entry: %s", cidr)
    return tuple(nets)


def _bind_ip_is_exposed(
    ip_str: str,
    exclude_nets: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...],
) -> bool:
    if ip_str in ("0.0.0.0", "::", "*"):
        return True
    try:
        addr = ipaddress.ip_address(ip_str.split("%", 1)[0])
    except ValueError:
        return True
    if cfg.DISCOVERY_EXCLUDE_LOOPBACK and addr.is_loopback:
        return False
    if addr.is_multicast:
        return False
    if addr.is_link_local:
        return False
    for net in exclude_nets:
        if addr.version == net.version and addr in net:
            return False
    return True


def _parse_proc_udp(path: str) -> dict[int, dict]:
    """Parse /proc/net/udp[6], return local_port → {rx_queue, drops}."""
    result: dict[int, dict] = {}
    try:
        with open(path) as f:
            for line in f:
                parts = line.split()
                if len(parts) < 10 or parts[0] == "sl":
                    continue
                try:
                    local_port = int(parts[1].split(":")[1], 16)
                    tx_rx = parts[4].split(":")
                    rx_queue = int(tx_rx[1], 16) if len(tx_rx) > 1 else 0
                    drops = int(parts[-1]) if len(parts) > 12 else 0
                except (ValueError, IndexError):
                    continue
                if local_port in result:
                    result[local_port]["rx_queue"] += rx_queue
                    result[local_port]["drops"] += drops
                else:
                    result[local_port] = {"rx_queue": rx_queue, "drops": drops}
    except OSError:
        pass
    return result


def _build_systemd_socket_map() -> dict[int, str]:
    """Return port → service name for systemd socket-activated services."""
    result: dict[int, str] = {}
    try:
        out = subprocess.check_output(
            ["systemctl", "list-sockets", "--no-pager", "--no-legend", "--all"],
            stderr=subprocess.DEVNULL,
            timeout=5,
        ).decode(errors="replace")
    except (FileNotFoundError, subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError):
        return result
    for line in out.splitlines():
        parts = line.split()
        if len(parts) < 2:
            continue
        listen_addr = parts[0]
        if ":" not in listen_addr:
            continue
        try:
            port = int(listen_addr.rsplit(":", 1)[1])
        except ValueError:
            continue
        unit = parts[2] if len(parts) >= 3 else parts[1]
        name = unit.split(".")[0]
        if name:
            result.setdefault(port, name)
    return result


# Linux netlink implementation

def _get_listening_ports_netlink() -> ObservedState:
    """Query sockets via SOCK_DIAG — no subprocess, no psutil."""
    state = ObservedState()
    exclude_nets = _discovery_exclude_networks()

    inode_pid: dict[int, int] | None = None
    pid_names: dict[int, str] = {}
    systemd_socket_map: dict[int, str] | None = None

    def _proc_name(inode: int) -> str:
        nonlocal inode_pid, systemd_socket_map
        if not inode:
            return ""
        if inode_pid is None:
            inode_pid = _build_inode_pid()
        pid = inode_pid.get(inode)
        if pid is None:
            return ""
        if pid not in pid_names:
            pid_names[pid] = _pid_comm(pid)
        return pid_names[pid]

    def _resolve_systemd(name: str, port: int) -> str:
        nonlocal systemd_socket_map
        if name != "systemd":
            return name
        if systemd_socket_map is None:
            systemd_socket_map = _build_systemd_socket_map()
        return systemd_socket_map.get(port, name)

    # TCP LISTEN
    for family in (socket.AF_INET, socket.AF_INET6):
        for sport_h, _dp, src, _dst, inode, _rq in _nldiag_dump(family, socket.IPPROTO_TCP, _SS_LISTEN):
            port = sport_h
            if not _bind_ip_is_exposed(_addr_str(family, src), exclude_nets):
                continue
            state.tcp.add(port)
            name = _resolve_systemd(_proc_name(inode), port)
            if name:
                state.tcp_processes[port] = name

    # TCP ESTABLISHED — seed conntrack for existing flows
    for family in (socket.AF_INET, socket.AF_INET6):
        for sport_h, dport_h, src, dst, _inode, _rq in _nldiag_dump(
            family, socket.IPPROTO_TCP, _SS_ESTABLISHED
        ):
            if not _bind_ip_is_exposed(_addr_str(family, src), exclude_nets):
                continue
            try:
                state.established.add(_pack_conntrack_key_raw(family, sport_h, dport_h, src, dst))
            except (OSError, ValueError):
                continue

    # UDP — collect drops from /proc, rqueue from SOCK_DIAG
    proc_udp: dict[int, dict] = {}
    for _path in ("/proc/net/udp", "/proc/net/udp6"):
        for _port, _data in _parse_proc_udp(_path).items():
            if _port in proc_udp:
                proc_udp[_port]["drops"] += _data["drops"]
            else:
                proc_udp[_port] = {"drops": _data["drops"]}

    udp_agg: dict[int, dict] = {}
    for family in (socket.AF_INET, socket.AF_INET6):
        for sport_h, dport_h, src, _dst, inode, rqueue in _nldiag_dump(
            family, socket.IPPROTO_UDP, _SS_ALL
        ):
            port = sport_h
            if port == 0:
                continue
            connected = dport_h != 0
            if port not in udp_agg:
                udp_agg[port] = {
                    "family": family,
                    "src": src,
                    "inode": inode,
                    "rqueue": rqueue,
                    "count": 1,
                    "connected_only": connected,
                }
            else:
                udp_agg[port]["rqueue"] += rqueue
                udp_agg[port]["count"] += 1
                if not connected:
                    udp_agg[port]["connected_only"] = False

    for port, info in udp_agg.items():
        family, src = info["family"], info["src"]
        if not _bind_ip_is_exposed(_addr_str(family, src), exclude_nets):
            continue
        if info["connected_only"]:
            server_signal = (
                info["count"] > 1               # SO_REUSEPORT proxy
                or info["rqueue"] > 0           # receive backlog (from SOCK_DIAG)
                or proc_udp.get(port, {}).get("drops", 0) > 0
            )
            if not server_signal:
                continue
        state.udp.add(port)
        name = _resolve_systemd(_proc_name(info["inode"]), port)
        if name:
            state.udp_processes[port] = name
        opts: set[str] = set()
        if info["count"] > 1:
            opts.add("SO_REUSEPORT")
        if info["rqueue"] > 0:
            opts.add("rx_queue>0")
        if proc_udp.get(port, {}).get("drops", 0) > 0:
            opts.add("drops>0")
        if opts:
            state.udp_sock_opts[port] = frozenset(opts)

    # SCTP LISTEN
    try:
        for family in (socket.AF_INET, socket.AF_INET6):
            for sport_h, _dp, src, _dst, _in, _rq in _nldiag_dump(
                family, _IPPROTO_SCTP, _SS_LISTEN
            ):
                if _bind_ip_is_exposed(_addr_str(family, src), exclude_nets):
                    state.sctp.add(sport_h)
    except OSError:
        pass

    return state


# psutil fallback (non-Linux)

def _collect_proc_udp_stats() -> dict[int, dict]:
    proc_udp: dict[int, dict] = {}
    for path in ("/proc/net/udp", "/proc/net/udp6"):
        for port, data in _parse_proc_udp(path).items():
            if port in proc_udp:
                proc_udp[port]["rx_queue"] += data["rx_queue"]
                proc_udp[port]["drops"] += data["drops"]
            else:
                proc_udp[port] = dict(data)
    return proc_udp


def _resolve_process_name(
    pid: int | None,
    port: int,
    pid_names: dict[int, str],
    systemd_map: dict[int, str] | None,
) -> tuple[str, dict[int, str] | None]:
    if pid is None:
        return "", systemd_map
    name = _resolve_pid_name(pid, pid_names)
    if name == "systemd":
        if systemd_map is None:
            systemd_map = _build_systemd_socket_map()
        name = systemd_map.get(port, name)
    return name, systemd_map


def _annotate_udp_sock_opts(port: int, proc_udp: dict[int, dict], state: ObservedState) -> None:
    pd = proc_udp.get(port, {})
    opts: set[str] = set()
    if pd.get("rx_queue", 0) > 0:
        opts.add("rx_queue>0")
    if pd.get("drops", 0) > 0:
        opts.add("drops>0")
    if opts:
        state.udp_sock_opts[port] = state.udp_sock_opts.get(port, frozenset()) | frozenset(opts)


def _get_listening_ports_psutil(cached_conns=None) -> ObservedState:
    if psutil is None or _net_connections is None:
        sys.exit("psutil not installed. Run: pip3 install psutil")

    connections = cached_conns if cached_conns is not None else _net_connections(kind="inet")
    state = ObservedState()
    exclude_nets = _discovery_exclude_networks()
    pid_names: dict[int, str] = {}
    proc_udp = _collect_proc_udp_stats()
    systemd_map: dict[int, str] | None = None

    for conn in connections:
        if not (conn.laddr and conn.laddr.port):
            continue
        port = conn.laddr.port
        if conn.type == socket.SOCK_STREAM:
            if conn.status == psutil.CONN_LISTEN:
                if not _bind_ip_is_exposed(conn.laddr.ip, exclude_nets):
                    continue
                state.tcp.add(port)
                name, systemd_map = _resolve_process_name(getattr(conn, "pid", None), port, pid_names, systemd_map)
                if name:
                    state.tcp_processes[port] = name
            elif conn.status == psutil.CONN_ESTABLISHED and conn.raddr:
                if not _bind_ip_is_exposed(conn.laddr.ip, exclude_nets):
                    continue
                try:
                    state.established.add(_pack_tcp_conntrack_key(conn))
                except (OSError, ValueError):
                    continue
        elif conn.type in (socket.SOCK_DGRAM, socket.SOCK_SEQPACKET):
            if conn.raddr:
                if conn.type != socket.SOCK_DGRAM:
                    continue
                pd = proc_udp.get(port, {})
                if not (pd.get("rx_queue", 0) > 0 or pd.get("drops", 0) > 0):
                    continue
            if not _bind_ip_is_exposed(conn.laddr.ip, exclude_nets):
                continue
            if conn.type == socket.SOCK_DGRAM:
                state.udp.add(port)
                name, systemd_map = _resolve_process_name(getattr(conn, "pid", None), port, pid_names, systemd_map)
                if name:
                    state.udp_processes[port] = name
                _annotate_udp_sock_opts(port, proc_udp, state)
            else:
                state.sctp.add(port)

    return state


# public API

def get_listening_ports(cached_conns=None) -> ObservedState:
    """Read externally reachable listening TCP/UDP/SCTP ports."""
    if _IS_LINUX:
        return _get_listening_ports_netlink()
    return _get_listening_ports_psutil(cached_conns)
