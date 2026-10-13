"""Rate-limit policy resolution helpers for port sync and firewall rules."""

from dataclasses import replace
from typing import Any
from collections.abc import Mapping

from auto_xdp import config as cfg
from auto_xdp.discovery.services import service_name
from auto_xdp.state import DesiredState, EndpointPolicy, ExposureDecision, ObservedState, RuntimeEndpoint

_NS_PER_SECOND = 1_000_000_000


def _seconds_to_ns(value: float) -> int:
    return int(value * _NS_PER_SECOND)


def _xdp_runtime_config(*, config: cfg.ConfigSnapshot | None = None) -> tuple[int, int, int, int, int, int, int, int]:
    config = cfg.snapshot_config() if config is None else config
    icmp_ns_per_token = 0
    if config.XDP_ICMP_RATE_PPS > 0:
        icmp_ns_per_token = max(1, int(_NS_PER_SECOND / config.XDP_ICMP_RATE_PPS))
    return (
        0,
        0,
        0,
        config.XDP_ICMP_BURST_PACKETS,
        icmp_ns_per_token,
        _seconds_to_ns(config.XDP_UDP_GLOBAL_WINDOW_SECONDS),
        _seconds_to_ns(config.XDP_RATE_WINDOW_SECONDS),
        0,
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


def _is_sensitive(port: int, proc: str, *, config: cfg.ConfigSnapshot | None = None) -> bool:
    """A port is sensitive iff the owning proc/service has rate <= threshold.

    Rate 0 (pin off) is exempt, not sensitive — it does not promote
    the port to the strict tier.
    """
    config = cfg.snapshot_config() if config is None else config
    threshold = config.XDP_SENSITIVE_PORT_THRESHOLD
    if proc:
        rate = config._SYN_RATE_BY_PROC.get(proc)
        if rate is not None and 0 < rate <= threshold:
            return True
    svc = service_name(port, "tcp")
    if svc:
        rate = config._SYN_RATE_BY_SERVICE.get(svc)
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


def _port_rate_limit(port: int, proc: str = "", *, config: cfg.ConfigSnapshot | None = None) -> int:
    # Proc-table is authoritative explicit override (inc. explicit 0 = pin off).
    config = cfg.snapshot_config() if config is None else config
    if proc and proc in config._SYN_RATE_BY_PROC:
        return config._SYN_RATE_BY_PROC[proc]
    # Service-table entry ≤ threshold acts as a sensitivity marker; the resolver
    # applies the strict default rather than the raw service value.
    if _is_sensitive(port, proc, config=config):
        return config.XDP_DEFAULT_TCP_SYN_RATE_STRICT
    # Explicit service-table value above the sensitive threshold.
    explicit = _explicit_lookup(
        port, proc, config._SYN_RATE_BY_PROC, config._SYN_RATE_BY_SERVICE,
    )
    if explicit is not None:
        return explicit
    return config.XDP_DEFAULT_TCP_SYN_RATE


def _syn_aggregate_rate_limit(port: int, proc: str = "", *, config: cfg.ConfigSnapshot | None = None) -> int:
    config = cfg.snapshot_config() if config is None else config
    explicit = _explicit_lookup(
        port, proc, config._SYN_AGG_RATE_BY_PROC, config._SYN_AGG_RATE_BY_SERVICE,
    )
    if explicit is not None:
        return explicit
    if _is_sensitive(port, proc, config=config):
        return config.XDP_DEFAULT_TCP_SYN_AGG_RATE_STRICT
    return config.XDP_DEFAULT_TCP_SYN_AGG_RATE


def _syncookie_mode(port: int, proc: str = "", *, config: cfg.ConfigSnapshot | None = None) -> str:
    config = cfg.snapshot_config() if config is None else config
    if not config.SYNCOOKIE_ENABLED:
        return config.SYNCOOKIE_MODE_OFF
    if port in config._SYNCOOKIE_BY_PORT:
        return config._SYNCOOKIE_BY_PORT[port]
    if proc and proc in config._SYNCOOKIE_BY_PROC:
        return config._SYNCOOKIE_BY_PROC[proc]
    svc = service_name(port, "tcp")
    if svc and svc in config._SYNCOOKIE_BY_SERVICE:
        return config._SYNCOOKIE_BY_SERVICE[svc]
    return config.SYNCOOKIE_DEFAULT_MODE


def _syncookie_port_rate_limit(port: int, proc: str = "", *, config: cfg.ConfigSnapshot | None = None) -> int:
    config = cfg.snapshot_config() if config is None else config
    if port in config._SYNCOOKIE_PORT_RATE_BY_PORT:
        return config._SYNCOOKIE_PORT_RATE_BY_PORT[port]
    if proc and proc in config._SYNCOOKIE_PORT_RATE_BY_PROC:
        return config._SYNCOOKIE_PORT_RATE_BY_PROC[proc]
    svc = service_name(port, "tcp")
    if svc and svc in config._SYNCOOKIE_PORT_RATE_BY_SERVICE:
        return config._SYNCOOKIE_PORT_RATE_BY_SERVICE[svc]
    return config.SYNCOOKIE_PORT_RATE_DEFAULT or _port_rate_limit(port, proc, config=config)


def rate_map_entries_v6(_v4_entries: int, *, config: cfg.ConfigSnapshot | None = None) -> int:
    """Return the fixed v6 capacity required by the compiled map template."""
    config = cfg.snapshot_config() if config is None else config
    return config.RATE_MAP_ENTRIES_V6


def _rate_map_entries(port: int, proc: str = "", *, config: cfg.ConfigSnapshot | None = None) -> int:
    """v4 inner rate-map capacity for a rate-limited port."""
    config = cfg.snapshot_config() if config is None else config
    explicit = _explicit_lookup(
        port, proc, config._RATE_MAP_ENTRIES_BY_PROC, config._RATE_MAP_ENTRIES_BY_SERVICE,
    )
    if explicit is not None:
        return explicit
    return config.RATE_MAP_ENTRIES_V4


def _udp_port_rate_limit(port: int, proc: str = "", *, config: cfg.ConfigSnapshot | None = None) -> int:
    """Return the UDP rate limit for a port, or 0 to skip rate limiting."""
    config = cfg.snapshot_config() if config is None else config
    return _resolve_service_limit(port, "udp", proc, config._UDP_RATE_BY_PROC, config._UDP_RATE_BY_SERVICE)


def _udp_aggregate_byte_limit(port: int, proc: str = "", *, config: cfg.ConfigSnapshot | None = None) -> int:
    config = cfg.snapshot_config() if config is None else config
    limit = _resolve_service_limit(
        port, "udp", proc, config._UDP_AGG_BYTES_BY_PROC, config._UDP_AGG_BYTES_BY_SERVICE
    )
    if limit > 0:
        return limit
    base = _udp_port_rate_limit(port, proc, config=config)
    return base * 1200 if base > 0 else 0


def _desired_acl_rules(*, config: cfg.ConfigSnapshot | None = None) -> dict[tuple[str, str], frozenset[int]]:
    config = cfg.snapshot_config() if config is None else config
    desired: dict[tuple[str, str], frozenset[int]] = {}
    for rule in config.ACL_RULES:
        proto = rule["proto"]
        cidr = rule["cidr"]
        ports = rule["ports"]
        if not ports:
            continue
        desired[(proto, cidr)] = frozenset(ports)
    return desired


def _unit_name(value: object) -> str:
    return str(value).strip().removesuffix(".service")


def _container_label_match(value: object, labels: dict[str, str]) -> bool:
    if isinstance(value, Mapping):
        return all(labels.get(str(key)) == str(label) for key, label in value.items())
    if isinstance(value, str) and "=" in value:
        key, label = value.split("=", 1)
        return labels.get(key.strip()) == label.strip()
    return False


def _container_resolver_matches(endpoint: RuntimeEndpoint, resolve: Mapping[str, Any]) -> bool:
    identity_keys = {"container_id", "container_name", "container_label"}
    if not identity_keys.intersection(resolve):
        return False
    if endpoint.attribution_state != "exact" or not endpoint.container_runtime:
        return False
    runtime = str(resolve.get("container_runtime", "")).strip().lower()
    if runtime and runtime != endpoint.container_runtime:
        return False
    container_id = str(resolve.get("container_id", "")).strip().lower()
    if container_id and not endpoint.container_id.startswith(container_id):
        return False
    container_name = str(resolve.get("container_name", "")).strip()
    if container_name and container_name != endpoint.container_name:
        return False
    label = resolve.get("container_label")
    return not label or _container_label_match(label, endpoint.container_labels)


def _has_exposure_policy(subject: Mapping[str, Any]) -> bool:
    for zone in subject.get("exposure", {}).values():
        if isinstance(zone, Mapping) and (
            zone.get("deny")
            or any(
                isinstance(zone.get(proto), Mapping) and zone[proto].get("ports")
                for proto in ("tcp", "udp", "sctp")
            )
        ):
            return True
    return False


def _subject_for_endpoint(endpoint: RuntimeEndpoint, *, config: cfg.ConfigSnapshot | None = None) -> tuple[str, Mapping[str, Any]] | None:
    """Resolve runtime evidence to an explicitly configured policy subject."""
    config = cfg.snapshot_config() if config is None else config
    if endpoint.attribution_state in {"unknown", "ambiguous"} or not endpoint.subject:
        return None
    for name, spec in config.SUBJECTS.items():
        if not isinstance(spec, Mapping) or not _has_exposure_policy(spec):
            continue
        resolve = spec.get("resolve", {})
        if not isinstance(resolve, Mapping):
            continue
        if _container_resolver_matches(endpoint, resolve):
            return name, spec
        unit = resolve.get("systemd_unit")
        process = resolve.get("process_name")
        if unit and _unit_name(unit) == _unit_name(endpoint.subject):
            return name, spec
        if process and str(process) == endpoint.subject:
            return name, spec
        if not unit and not process and str(name) == endpoint.subject:
            return name, spec
    return None


def _grant_for(endpoint: RuntimeEndpoint, subject: Mapping[str, Any]) -> tuple[bool, str, str]:
    exposure = subject.get("exposure", {})
    zone = exposure.get(endpoint.ingress_zone, {}) if isinstance(exposure, Mapping) else {}
    if not isinstance(zone, Mapping):
        return False, "no exposure grant for ingress zone", ""
    if bool(zone.get("deny", False)):
        return False, "subject explicitly denies this ingress zone", ""
    protocol = zone.get(endpoint.protocol, {})
    if not isinstance(protocol, Mapping):
        return False, "no exposure grant for protocol", ""
    ports = protocol.get("ports", [])
    if endpoint.host_port not in {int(port) for port in ports}:
        return False, "port is not listed in the exposure grant", ""
    protection = subject.get("protection", {})
    profile = str(protection.get("profile", "")).strip().lower() if isinstance(protection, Mapping) else ""
    if profile and (profile != "minecraft" or endpoint.protocol != "tcp"):
        return False, "protection profile is unavailable for this protocol", profile
    return True, "matched explicit exposure grant", profile


def resolve_exposure_decisions(observed: ObservedState, *, config: cfg.ConfigSnapshot | None = None) -> list[ExposureDecision]:
    """Compile runtime endpoints against explicit workload exposure grants."""
    config = cfg.snapshot_config() if config is None else config
    decisions: list[ExposureDecision] = []
    for observed_endpoint in observed.endpoints:
        endpoints = (
            tuple(
                replace(observed_endpoint, ingress_zone=zone)
                for zone in config.ZONES
            )
            if observed_endpoint.bind_scope == "wildcard" and config.ZONES
            else (observed_endpoint,)
        )
        for endpoint in endpoints:
            resolved = _subject_for_endpoint(endpoint, config=config)
            if resolved is None:
                decisions.append(
                    ExposureDecision(
                        endpoint, "drop", "unknown or unapproved workload ownership"
                    )
                )
                continue
            subject_name, subject = resolved
            allowed, reason, profile = _grant_for(endpoint, subject)
            decisions.append(
                ExposureDecision(
                    endpoint,
                    "allow" if allowed else "drop",
                    reason,
                    subject_name,
                    profile,
                )
            )

    # One interface zone can only express one owner/profile for a protocol/port.
    # Different zones are independent endpoint policies.
    grouped: dict[tuple[str, int, str], list[ExposureDecision]] = {}
    for decision in decisions:
        grouped.setdefault(
            (
                decision.endpoint.protocol,
                decision.endpoint.host_port,
                decision.endpoint.ingress_zone,
            ), []
        ).append(decision)
    for group in grouped.values():
        if len(group) < 2:
            continue
        if any(item.endpoint.attribution_state in {"unknown", "ambiguous"} for item in group):
            for item in group:
                item.action = "drop"
                item.reason = "shared port has unknown or ambiguous ownership"
        elif len({(item.subject, item.protection_profile) for item in group}) > 1:
            for item in group:
                item.action = "drop"
                item.reason = "shared port has incompatible subject protection"
    return decisions


def resolve_desired_state(observed: ObservedState, *, config: cfg.ConfigSnapshot | None = None) -> DesiredState:
    config = cfg.snapshot_config() if config is None else config
    decisions = resolve_exposure_decisions(observed, config=config)
    desired = _global_desired_state(config)
    desired.exposure_decisions = decisions
    for decision in decisions:
        endpoint = decision.endpoint
        port = endpoint.host_port
        process = endpoint.process_name or endpoint.subject
        if not process:
            processes = observed.tcp_processes if endpoint.protocol == "tcp" else observed.udp_processes
            process = processes.get(port, "")
        policy = _endpoint_policy(endpoint, process, config, decision)
        previous = desired.endpoint_policies.get(endpoint.key)
        if previous is not None:
            instances = sorted(set(previous.instance_id.split(",") + [policy.instance_id]) - {""})
            if replace(previous, instance_id="") != replace(policy, instance_id=""):
                policy = replace(policy, allow=False, reason="conflicting listeners share endpoint identity")
            policy = replace(policy, instance_id=",".join(instances))
        desired.endpoint_policies[endpoint.key] = policy
    return desired


def _endpoint_policy(endpoint: RuntimeEndpoint, process: str, config: cfg.ConfigSnapshot,
                     decision: ExposureDecision) -> EndpointPolicy:
    port = endpoint.host_port
    tcp = endpoint.protocol == "tcp"
    udp = endpoint.protocol == "udp"
    return EndpointPolicy(
        allow=decision.action == "allow",
        reason=decision.reason,
        subject=decision.subject,
        instance_id=endpoint.instance_id,
        profile=decision.protection_profile,
        syn_rate=_port_rate_limit(port, process, config=config) if tcp else 0,
        syn_aggregate_rate=_syn_aggregate_rate_limit(port, process, config=config) if tcp else 0,
        udp_rate=_udp_port_rate_limit(port, process, config=config) if udp else 0,
        udp_byte_rate=_udp_aggregate_byte_limit(port, process, config=config) if udp else 0,
        syncookie_mode=_syncookie_mode(port, process, config=config) if tcp else "off",
        syncookie_rate=_syncookie_port_rate_limit(port, process, config=config) if tcp else 0,
        rate_map_entries=_rate_map_entries(port, process, config=config) if tcp or udp else 0,
    )


def _global_desired_state(config: cfg.ConfigSnapshot) -> DesiredState:
    return DesiredState(
        config=config,
        trusted_cidrs=set(config.TRUSTED_SRC_IPS),
        acl_rules=_desired_acl_rules(config=config),
        bogon_filter_enabled=config.BOGON_FILTER_ENABLED,
        drop_events_enabled=config.DROP_EVENTS_ENABLED,
        rate_limit_source_prefix_v4=config.RATE_LIMIT_SOURCE_PREFIX_V4,
        rate_limit_source_prefix_v6=config.RATE_LIMIT_SOURCE_PREFIX_V6,
        udp_global_byte_rate=config.XDP_UDP_GLOBAL_BYTE_RATE,
        xdp_runtime_config=_xdp_runtime_config(config=config),
    )
