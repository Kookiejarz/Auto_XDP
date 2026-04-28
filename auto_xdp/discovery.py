"""Port discovery: reads listening sockets via psutil, applies exposure filters."""
from __future__ import annotations

import ipaddress
import logging
import socket
import struct
import sys

try:
    import psutil
except ImportError:
    psutil = None

from auto_xdp import config as cfg
from auto_xdp.state import ObservedState

log = logging.getLogger(__name__)

# psutil 6.0 renamed net_connections() -> connections()
_net_connections = None
if psutil is not None:
    _net_connections = getattr(psutil, "connections", psutil.net_connections)


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
        except Exception as exc:
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
    # Wildcard binds mean "all addresses" and should be treated as externally reachable.
    if ip_str in ("0.0.0.0", "::", "*"):
        return True
    try:
        addr = ipaddress.ip_address(ip_str.split("%", 1)[0])
    except ValueError:
        # If the address is malformed or uses an unexpected format, fail open.
        return True
    if cfg.DISCOVERY_EXCLUDE_LOOPBACK and addr.is_loopback:
        return False
    for net in exclude_nets:
        if addr.version == net.version and addr in net:
            return False
    return True


def get_listening_ports(cached_conns=None) -> ObservedState:
    """Read externally reachable listening TCP/UDP/SCTP ports via psutil."""
    if psutil is None or _net_connections is None:
        sys.exit("psutil not installed. Run: pip3 install psutil")

    connections = cached_conns if cached_conns is not None else _net_connections(kind="inet")
    state = ObservedState()
    exclude_nets = _discovery_exclude_networks()
    pid_names: dict[int, str] = {}

    for conn in connections:
        if not (conn.laddr and conn.laddr.port):
            continue

        port = conn.laddr.port
        if conn.type == socket.SOCK_STREAM:
            if conn.status == psutil.CONN_LISTEN:
                if not _bind_ip_is_exposed(conn.laddr.ip, exclude_nets):
                    continue
                state.tcp.add(port)
                pid = getattr(conn, "pid", None)
                if pid is not None:
                    name = _resolve_pid_name(pid, pid_names)
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
            # UDP/SEQPACKET: keep only unconnected server-style sockets (no remote peer).
            if conn.raddr:
                continue
            if not _bind_ip_is_exposed(conn.laddr.ip, exclude_nets):
                continue
            if conn.type == socket.SOCK_DGRAM:
                state.udp.add(port)
                pid = getattr(conn, "pid", None)
                if pid is not None:
                    name = _resolve_pid_name(pid, pid_names)
                    if name:
                        state.udp_processes[port] = name
            else:
                state.sctp.add(port)

    return state
