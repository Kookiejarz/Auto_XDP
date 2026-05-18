"""Rate-limit policy resolution helpers for port sync and firewall rules."""

from auto_xdp import config as cfg
from auto_xdp.services import service_name
from auto_xdp.state import DesiredState, ObservedState

_NS_PER_SECOND = 1_000_000_000


def _seconds_to_ns(value: float) -> int:
    return int(value * _NS_PER_SECOND)


def _xdp_runtime_config() -> tuple[int, int, int, int, int, int, int, int]:
    icmp_ns_per_token = 0
    if cfg.XDP_ICMP_RATE_PPS > 0:
        icmp_ns_per_token = max(1, int(_NS_PER_SECOND / cfg.XDP_ICMP_RATE_PPS))
    return (
        _seconds_to_ns(cfg.XDP_TCP_TIMEOUT_SECONDS),
        _seconds_to_ns(cfg.XDP_UDP_TIMEOUT_SECONDS),
        _seconds_to_ns(cfg.XDP_CONNTRACK_REFRESH_SECONDS),
        cfg.XDP_ICMP_BURST_PACKETS,
        icmp_ns_per_token,
        _seconds_to_ns(cfg.XDP_UDP_GLOBAL_WINDOW_SECONDS),
        _seconds_to_ns(cfg.XDP_RATE_WINDOW_SECONDS),
        _seconds_to_ns(cfg.XDP_SYN_TIMEOUT_SECONDS),
    )


def _explicit_lookup(
    port: int,
    proc: str,
    proc_limits: dict[str, int],
    service_limits: dict[str, int],
) -> int | None:
    """Return explicit operator value for the port, or None if no entry matches.

    Critically distinguishes "explicit 0 (pin off)" from "missing entry"
    (which lets callers apply default-tier values).
    """
    if proc and proc in proc_limits:
        return proc_limits[proc]
    svc = service_name(port, "tcp")
    if svc and svc in service_limits:
        return service_limits[svc]
    return None


def _is_sensitive(port: int, proc: str) -> bool:
    """A port is sensitive iff the owning proc/service has rate <= threshold.

    Rate 0 (pin off) is exempt, not sensitive — it does not promote
    the port to the strict tier.
    """
    threshold = cfg.XDP_SENSITIVE_PORT_THRESHOLD
    if proc:
        rate = cfg._SYN_RATE_BY_PROC.get(proc)
        if rate is not None and 0 < rate <= threshold:
            return True
    svc = service_name(port, "tcp")
    if svc:
        rate = cfg._SYN_RATE_BY_SERVICE.get(svc)
        if rate is not None and 0 < rate <= threshold:
            return True
    return False


def _resolve_service_limit(
    port: int,
    proto: str,
    proc: str,
    proc_limits: dict[str, int],
    service_limits: dict[str, int],
) -> int:
    if proc:
        limit = proc_limits.get(proc)
        if limit is not None:
            return limit
    svc = service_name(port, proto)
    if not svc:
        return 0
    return service_limits.get(svc, 0)


def _port_rate_limit(port: int, proc: str = "") -> int:
    # Proc-table is authoritative explicit override (inc. explicit 0 = pin off).
    if proc and proc in cfg._SYN_RATE_BY_PROC:
        return cfg._SYN_RATE_BY_PROC[proc]
    # Service-table entry ≤ threshold acts as a sensitivity marker; the resolver
    # applies the strict default rather than the raw service value.
    if _is_sensitive(port, proc):
        return cfg.XDP_DEFAULT_TCP_SYN_RATE_STRICT
    # Explicit service-table value above the sensitive threshold.
    explicit = _explicit_lookup(
        port, proc, cfg._SYN_RATE_BY_PROC, cfg._SYN_RATE_BY_SERVICE,
    )
    if explicit is not None:
        return explicit
    return cfg.XDP_DEFAULT_TCP_SYN_RATE


def _syn_aggregate_rate_limit(port: int, proc: str = "") -> int:
    explicit = _explicit_lookup(
        port, proc, cfg._SYN_AGG_RATE_BY_PROC, cfg._SYN_AGG_RATE_BY_SERVICE,
    )
    if explicit is not None:
        return explicit
    if _is_sensitive(port, proc):
        return cfg.XDP_DEFAULT_TCP_SYN_AGG_RATE_STRICT
    return cfg.XDP_DEFAULT_TCP_SYN_AGG_RATE


def _tcp_conn_limit(port: int, proc: str = "") -> int:
    explicit = _explicit_lookup(
        port, proc, cfg._TCP_CONN_BY_PROC, cfg._TCP_CONN_BY_SERVICE,
    )
    if explicit is not None:
        return explicit
    if _is_sensitive(port, proc):
        return cfg.XDP_DEFAULT_TCP_ESTABLISHED_PER_SRC_STRICT
    return cfg.XDP_DEFAULT_TCP_ESTABLISHED_PER_SRC


def _tcp_conn_prefix_limit(port: int, proc: str = "") -> int:
    explicit = _explicit_lookup(
        port, proc, cfg._TCP_CONN_PREFIX_BY_PROC, cfg._TCP_CONN_PREFIX_BY_SERVICE,
    )
    if explicit is not None:
        return explicit
    if _is_sensitive(port, proc):
        return cfg.XDP_DEFAULT_TCP_ESTABLISHED_PER_PREFIX_STRICT
    return cfg.XDP_DEFAULT_TCP_ESTABLISHED_PER_PREFIX


def _tcp_conn_port_limit(port: int, proc: str = "") -> int:
    explicit = _explicit_lookup(
        port, proc, cfg._TCP_CONN_PORT_BY_PROC, cfg._TCP_CONN_PORT_BY_SERVICE,
    )
    if explicit is not None:
        return explicit
    if _is_sensitive(port, proc):
        return cfg.XDP_DEFAULT_TCP_ESTABLISHED_PER_PORT_STRICT
    return cfg.XDP_DEFAULT_TCP_ESTABLISHED_PER_PORT


def _udp_port_rate_limit(port: int, proc: str = "") -> int:
    """Return the UDP rate limit for a port, or 0 to skip rate limiting."""
    return _resolve_service_limit(port, "udp", proc, cfg._UDP_RATE_BY_PROC, cfg._UDP_RATE_BY_SERVICE)


def _udp_aggregate_byte_limit(port: int, proc: str = "") -> int:
    limit = _resolve_service_limit(
        port, "udp", proc, cfg._UDP_AGG_BYTES_BY_PROC, cfg._UDP_AGG_BYTES_BY_SERVICE
    )
    if limit > 0:
        return limit
    base = _udp_port_rate_limit(port, proc)
    return base * 1200 if base > 0 else 0


def _resolve_port_limits(
    ports: set[int],
    process_names: dict[int, str],
    resolver,
) -> dict[int, int]:
    """Return resolver(port, proc) for every port — including 0 (pin off).

    Pre-default-on, this filtered out 0 to keep the desired-state map small.
    Now every auto-discovered port produces an entry so default-tier values
    propagate to the BPF policy map."""
    return {port: resolver(port, process_names.get(port, "")) for port in ports}


def _desired_acl_rules() -> dict[tuple[str, str], frozenset[int]]:
    desired: dict[tuple[str, str], frozenset[int]] = {}
    for rule in cfg.ACL_RULES:
        proto = rule["proto"]
        cidr = rule["cidr"]
        ports = rule["ports"]
        if not ports:
            continue
        desired[(proto, cidr)] = frozenset(ports)
    return desired


def resolve_desired_state(observed: ObservedState) -> DesiredState:
    tcp_ports = set(observed.tcp) | set(cfg.TCP_PERMANENT)
    udp_ports = set(observed.udp) | set(cfg.UDP_PERMANENT)
    sctp_ports = set(observed.sctp) | set(cfg.SCTP_PERMANENT)

    return DesiredState(
        tcp_ports=tcp_ports,
        udp_ports=udp_ports,
        sctp_ports=sctp_ports,
        trusted_cidrs=set(cfg.TRUSTED_SRC_IPS),
        conntrack_entries=set(observed.established),
        tcp_syn_rate_limits=_resolve_port_limits(tcp_ports, observed.tcp_processes, _port_rate_limit),
        tcp_syn_agg_rate_limits=_resolve_port_limits(
            tcp_ports, observed.tcp_processes, _syn_aggregate_rate_limit
        ),
        tcp_conn_limits=_resolve_port_limits(tcp_ports, observed.tcp_processes, _tcp_conn_limit),
        tcp_conn_prefix_limits=_resolve_port_limits(
            tcp_ports, observed.tcp_processes, _tcp_conn_prefix_limit
        ),
        tcp_conn_port_limits=_resolve_port_limits(
            tcp_ports, observed.tcp_processes, _tcp_conn_port_limit
        ),
        udp_rate_limits=_resolve_port_limits(udp_ports, observed.udp_processes, _udp_port_rate_limit),
        udp_agg_rate_limits=_resolve_port_limits(
            udp_ports, observed.udp_processes, _udp_aggregate_byte_limit
        ),
        acl_rules=_desired_acl_rules(),
        bogon_filter_enabled=cfg.BOGON_FILTER_ENABLED,
        drop_events_enabled=cfg.DROP_EVENTS_ENABLED,
        rate_limit_source_prefix_v4=cfg.RATE_LIMIT_SOURCE_PREFIX_V4,
        rate_limit_source_prefix_v6=cfg.RATE_LIMIT_SOURCE_PREFIX_V6,
        udp_global_byte_rate=cfg.XDP_UDP_GLOBAL_BYTE_RATE,
        xdp_runtime_config=_xdp_runtime_config(),
    )
