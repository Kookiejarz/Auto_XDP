"""Shared observed/desired state models for sync reconciliation."""
from __future__ import annotations

from dataclasses import dataclass, field, fields
from typing import Literal, TypeVar
import ipaddress

from auto_xdp.config import ConfigSnapshot, snapshot_config


_ValueT = TypeVar("_ValueT")
EndpointKey = tuple[str, str, int, str]


@dataclass(frozen=True)
class EndpointPolicy:
    """Resolved authorization and protection for one endpoint identity."""

    allow: bool
    reason: str
    subject: str = ""
    instance_id: str = ""
    profile: str = ""
    syn_rate: int = 0
    syn_aggregate_rate: int = 0
    udp_rate: int = 0
    udp_byte_rate: int = 0
    syncookie_mode: str = "off"
    syncookie_rate: int = 0
    rate_map_entries: int = 0


@dataclass
class RuntimeEndpoint:
    """A live endpoint and the evidence used to attribute it."""

    protocol: str
    host_address: str
    host_port: int
    bind_scope: str
    ingress_zone: str = "unknown"
    subject: str = ""
    attribution_state: str = "unknown"
    attribution_source: str = ""
    container_runtime: str = ""
    container_id: str = ""
    container_name: str = ""
    container_labels: dict[str, str] = field(default_factory=dict)
    # Socket inode (Linux) or pid/fd pair (fallback), used to distinguish a
    # restarted listener even when debounce hides the closed intermediate state.
    instance_id: str = ""
    process_name: str = ""

    @property
    def key(self) -> EndpointKey:
        return self.protocol, self.host_address, self.host_port, self.ingress_zone


@dataclass
class ExposureDecision:
    """Explain why one observed endpoint is or is not effective."""

    endpoint: RuntimeEndpoint
    action: str
    reason: str
    subject: str = ""
    protection_profile: str = ""


@dataclass
class ObservedState:
    """Facts discovered from the local system."""

    tcp: set[int] = field(default_factory=set)
    udp: set[int] = field(default_factory=set)
    sctp: set[int] = field(default_factory=set)
    tcp_processes: dict[int, str] = field(default_factory=dict)
    udp_processes: dict[int, str] = field(default_factory=dict)
    udp_sock_opts: dict[int, frozenset[str]] = field(default_factory=dict)
    endpoints: list[RuntimeEndpoint] = field(default_factory=list)


@dataclass
class DesiredState:
    """Policy-resolved target state to apply to the active backend."""

    config: ConfigSnapshot = field(default_factory=snapshot_config, repr=False, compare=False)
    endpoint_policies: dict[EndpointKey, EndpointPolicy] = field(default_factory=dict)
    trusted_cidrs: set[str] = field(default_factory=set)
    acl_rules: dict[tuple[str, str], frozenset[int]] = field(default_factory=dict)
    bogon_filter_enabled: bool = False
    drop_events_enabled: bool = True
    rate_limit_source_prefix_v4: int = 32
    rate_limit_source_prefix_v6: int = 128
    udp_global_byte_rate: int = 0
    exposure_decisions: list[ExposureDecision] = field(default_factory=list)
    xdp_runtime_config: tuple[int, int, int, int, int, int, int, int] = (
        0,
        0,
        0,
        100,
        10_000_000,
        1_000_000_000,
        1_000_000_000,
        0,
    )


@dataclass
class BackendProjection(DesiredState):
    """Compiled native port/map values; logical targets only use endpoint policies.

    The disabled gate is exclusively for explicit legacy port adapters/bootstrap.
    """

    endpoint_policy_enabled: bool = False
    tcp_ports: set[int] = field(default_factory=set)
    udp_ports: set[int] = field(default_factory=set)
    sctp_ports: set[int] = field(default_factory=set)
    tcp_syn_rate_limits: dict[int, int] = field(default_factory=dict)
    tcp_syn_agg_rate_limits: dict[int, int] = field(default_factory=dict)
    tcp_syncookie_modes: dict[int, str] = field(default_factory=dict)
    tcp_syncookie_rate_limits: dict[int, int] = field(default_factory=dict)
    udp_rate_limits: dict[int, int] = field(default_factory=dict)
    udp_agg_rate_limits: dict[int, int] = field(default_factory=dict)
    tcp_rate_map_entries: dict[int, int] = field(default_factory=dict)
    udp_rate_map_entries: dict[int, int] = field(default_factory=dict)
    zone_tcp_ports: dict[str, set[int]] = field(default_factory=dict)
    zone_udp_ports: dict[str, set[int]] = field(default_factory=dict)
    tcp_protection_profiles: dict[tuple[str, int], str] = field(default_factory=dict)


@dataclass
class AppliedState:
    """Backend-observed state currently applied in the kernel/runtime."""

    endpoint_admission: dict[EndpointKey, Literal["admitted", "closed", "unknown"]] = field(default_factory=dict)
    endpoint_policies: dict[EndpointKey, EndpointPolicy] = field(default_factory=dict)
    # Missing evidence always means unknown, including an empty collection.
    evidence: dict[str, Literal["confirmed", "cached", "unknown"]] = field(default_factory=dict)
    tcp_ports: set[int] = field(default_factory=set)
    udp_ports: set[int] = field(default_factory=set)
    sctp_ports: set[int] = field(default_factory=set)
    trusted_cidrs: set[str] = field(default_factory=set)
    tcp_syn_rate_limits: dict[int, int] = field(default_factory=dict)
    tcp_syn_agg_rate_limits: dict[int, int] = field(default_factory=dict)
    tcp_syncookie_modes: dict[int, str] = field(default_factory=dict)
    tcp_syncookie_rate_limits: dict[int, int] = field(default_factory=dict)
    udp_rate_limits: dict[int, int] = field(default_factory=dict)
    udp_agg_rate_limits: dict[int, int] = field(default_factory=dict)
    acl_rules: dict[tuple[str, str], frozenset[int]] = field(default_factory=dict)
    bogon_filter_enabled: bool | None = None
    drop_events_enabled: bool | None = None
    rate_limit_source_prefix_v4: int = 32
    rate_limit_source_prefix_v6: int = 128
    udp_global_byte_rate: int | None = None
    xdp_runtime_config: tuple[int, int, int, int, int, int, int, int] | None = None
    zone_tcp_ports: dict[str, set[int]] = field(default_factory=dict)
    zone_udp_ports: dict[str, set[int]] = field(default_factory=dict)


@dataclass
class ReconcilePlan:
    target: DesiredState | None = None
    endpoint_upserts: dict[EndpointKey, EndpointPolicy] = field(default_factory=dict)
    endpoint_removals: set[EndpointKey] = field(default_factory=set)
    steps: tuple["ReconcileStep", ...] = ()
    tcp_ports_to_add: set[int] = field(default_factory=set)
    tcp_ports_to_remove: set[int] = field(default_factory=set)
    udp_ports_to_add: set[int] = field(default_factory=set)
    udp_ports_to_remove: set[int] = field(default_factory=set)
    sctp_ports_to_add: set[int] = field(default_factory=set)
    sctp_ports_to_remove: set[int] = field(default_factory=set)
    trusted_cidrs_to_add: set[str] = field(default_factory=set)
    trusted_cidrs_to_remove: set[str] = field(default_factory=set)
    tcp_syn_rate_limits_to_upsert: dict[int, int] = field(default_factory=dict)
    tcp_syn_rate_limits_to_remove: set[int] = field(default_factory=set)
    tcp_syn_agg_rate_limits_to_upsert: dict[int, int] = field(default_factory=dict)
    tcp_syn_agg_rate_limits_to_remove: set[int] = field(default_factory=set)
    tcp_syncookie_modes_to_upsert: dict[int, str] = field(default_factory=dict)
    tcp_syncookie_modes_to_remove: set[int] = field(default_factory=set)
    tcp_syncookie_rate_limits_to_upsert: dict[int, int] = field(default_factory=dict)
    tcp_syncookie_rate_limits_to_remove: set[int] = field(default_factory=set)
    udp_rate_limits_to_upsert: dict[int, int] = field(default_factory=dict)
    udp_rate_limits_to_remove: set[int] = field(default_factory=set)
    udp_agg_rate_limits_to_upsert: dict[int, int] = field(default_factory=dict)
    udp_agg_rate_limits_to_remove: set[int] = field(default_factory=set)
    acl_rules_to_upsert: dict[tuple[str, str], frozenset[int]] = field(default_factory=dict)
    acl_rules_to_remove: set[tuple[str, str]] = field(default_factory=set)
    bogon_filter_update: bool | None = None
    drop_events_update: bool | None = None
    udp_global_byte_rate_update: int | None = None


@dataclass(frozen=True)
class ReconcileStep:
    operation: Literal["revoke", "prepare", "admit", "cleanup"]
    depends_on: tuple[str, ...] = ()
    endpoints: frozenset[EndpointKey] = frozenset()


@dataclass(frozen=True)
class ApplyOperation:
    stage: str
    resource: str
    operation: str


@dataclass(frozen=True)
class ApplyFailure:
    operation: ApplyOperation
    reason: str
    endpoint: EndpointKey | None = None


@dataclass
class ApplyResult:
    dry_run: bool = False
    plan: ReconcilePlan | None = None
    succeeded: list[ApplyOperation] = field(default_factory=list)
    failures: list[ApplyFailure] = field(default_factory=list)
    closed_endpoints: set[EndpointKey] = field(default_factory=set)
    blocked_endpoints: dict[EndpointKey, str] = field(default_factory=dict)
    unconfirmed: dict[str, str] = field(default_factory=dict)
    applied: AppliedState | None = None

    @property
    def successful(self) -> bool:
        return self.applied is not None and self.plan is not None and not (
            self.dry_run or self.failures or self.blocked_endpoints or self.unconfirmed
        )


def project_endpoint_policies(desired: DesiredState) -> tuple[BackendProjection, dict[EndpointKey, str]]:
    """Compile endpoint policies for the existing port-level protection maps.

    Address/zone admission remains exact. Protection values sharing one native
    port key must agree; incompatible endpoints stay closed rather than being
    silently collapsed to the last listener's configuration.
    """
    if isinstance(desired, BackendProjection) and not desired.endpoint_policy_enabled:
        return desired, {}
    from dataclasses import replace

    # ponytail: port-keyed protection maps; migrate their ABI when differing limits are needed.
    groups: dict[tuple[str, int], list[tuple[EndpointKey, EndpointPolicy]]] = {}
    for key, policy in desired.endpoint_policies.items():
        proto, address, port, zone = key
        if proto not in {"tcp", "udp", "sctp"} or not 1 <= port <= 65535:
            raise ValueError(f"Invalid endpoint identity: {key}")
        if address != "*":
            ipaddress.ip_address(address.split("%", 1)[0])
        if policy.syncookie_mode not in {"off", "auto", "always"}:
            raise ValueError(f"Invalid SYN-cookie mode: {key}")
        if min(policy.syn_rate, policy.syn_aggregate_rate, policy.udp_rate,
               policy.udp_byte_rate, policy.syncookie_rate, policy.rate_map_entries) < 0:
            raise ValueError(f"Negative endpoint protection value: {key}")
        if policy.allow:
            groups.setdefault((key[0], key[2]), []).append((key, policy))
    blocked: dict[EndpointKey, str] = {}
    for entries in groups.values():
        protections = {
            (policy.syn_rate, policy.syn_aggregate_rate, policy.udp_rate,
             policy.udp_byte_rate, policy.syncookie_mode, policy.syncookie_rate,
             policy.rate_map_entries)
            for _, policy in entries
        }
        if len(protections) > 1:
            for key, _ in entries:
                blocked[key] = "port-level protection cannot represent different endpoint limits"
    # An unresolved denied bind cannot be isolated from a same-port wildcard.
    # Close its native port group rather than allowing the wildcard to shadow it.
    for key in desired.endpoint_policies:
        try:
            endpoint_scope(key, desired.config)
        except ValueError as exc:
            for other, policy in desired.endpoint_policies.items():
                if policy.allow and (other[0], other[2]) == (key[0], key[2]):
                    blocked[other] = str(exc)
    profiles: dict[tuple[str, int, str], list[tuple[EndpointKey, EndpointPolicy]]] = {}
    for key, policy in desired.endpoint_policies.items():
        if policy.allow:
            profiles.setdefault((key[0], key[2], key[3]), []).append((key, policy))
    for entries in profiles.values():
        if len({policy.profile for _, policy in entries}) > 1:
            blocked.update((key, "zone/port protection cannot represent different profiles") for key, _ in entries)
    policies = {
        key: replace(policy, allow=False, reason=blocked[key]) if key in blocked else policy
        for key, policy in desired.endpoint_policies.items()
    }
    allowed = [(key, policy) for key, policy in policies.items() if policy.allow]
    global_public = not desired.config.ZONES.get("public", {}).get("interfaces", ())
    tcp = {key[2] for key, _ in allowed if key[0] == "tcp" and key[3] == "public" and global_public}
    udp = {key[2] for key, _ in allowed if key[0] == "udp" and key[3] == "public" and global_public}
    zones_tcp: dict[str, set[int]] = {}
    zones_udp: dict[str, set[int]] = {}
    for key, _ in allowed:
        if key[0] in {"tcp", "udp"}:
            (zones_tcp if key[0] == "tcp" else zones_udp).setdefault(key[3], set()).add(key[2])
    tcp_policies = {key[2]: policy for key, policy in allowed if key[0] == "tcp"}
    udp_policies = {key[2]: policy for key, policy in allowed if key[0] == "udp"}
    return BackendProjection(
        **{item.name: getattr(desired, item.name) for item in fields(DesiredState)
           if item.name != "endpoint_policies"},
        endpoint_policy_enabled=True, endpoint_policies=policies,
        tcp_ports=tcp, udp_ports=udp,
        sctp_ports={key[2] for key, _ in allowed if key[0] == "sctp"},
        zone_tcp_ports=zones_tcp, zone_udp_ports=zones_udp,
        tcp_syn_rate_limits={port: policy.syn_rate for port, policy in tcp_policies.items()},
        tcp_syn_agg_rate_limits={port: policy.syn_aggregate_rate for port, policy in tcp_policies.items()},
        tcp_syncookie_modes={port: policy.syncookie_mode for port, policy in tcp_policies.items()
                            if policy.syncookie_mode != "off"},
        tcp_syncookie_rate_limits={port: policy.syncookie_rate for port, policy in tcp_policies.items()
                                  if policy.syncookie_mode != "off"},
        tcp_rate_map_entries={port: policy.rate_map_entries for port, policy in tcp_policies.items()
                             if policy.syn_rate > 0},
        udp_rate_limits={port: policy.udp_rate for port, policy in udp_policies.items()},
        udp_agg_rate_limits={port: policy.udp_byte_rate for port, policy in udp_policies.items()},
        udp_rate_map_entries={port: policy.rate_map_entries for port, policy in udp_policies.items()
                             if policy.udp_rate > 0},
        tcp_protection_profiles={(key[3], key[2]): policy.profile for key, policy in allowed
                                 if key[0] == "tcp" and policy.profile},
    ), blocked


def _dict_upserts(
    desired: dict[int, _ValueT], applied: dict[int, _ValueT]
) -> dict[int, _ValueT]:
    return {key: value for key, value in desired.items() if applied.get(key) != value}


def _dict_removals(
    desired: dict[int, _ValueT], applied: dict[int, _ValueT]
) -> set[int]:
    return set(applied) - set(desired)


def _acl_upserts(
    desired: dict[tuple[str, str], frozenset[int]],
    applied: dict[tuple[str, str], frozenset[int]],
) -> dict[tuple[str, str], frozenset[int]]:
    return {key: ports for key, ports in desired.items() if applied.get(key) != ports}


def compute_reconcile_plan(desired: DesiredState, applied: AppliedState) -> ReconcilePlan:
    target = desired
    if not isinstance(desired, BackendProjection):
        desired, _ = project_endpoint_policies(desired)
    plan = ReconcilePlan(
        target=target,
        endpoint_upserts={key: value for key, value in desired.endpoint_policies.items()
                          if applied.endpoint_policies.get(key) != value},
        endpoint_removals=set(applied.endpoint_policies) - set(desired.endpoint_policies),
        tcp_ports_to_add=desired.tcp_ports - applied.tcp_ports,
        tcp_ports_to_remove=applied.tcp_ports - desired.tcp_ports,
        udp_ports_to_add=desired.udp_ports - applied.udp_ports,
        udp_ports_to_remove=applied.udp_ports - desired.udp_ports,
        sctp_ports_to_add=desired.sctp_ports - applied.sctp_ports,
        sctp_ports_to_remove=applied.sctp_ports - desired.sctp_ports,
        trusted_cidrs_to_add=desired.trusted_cidrs - applied.trusted_cidrs,
        trusted_cidrs_to_remove=applied.trusted_cidrs - desired.trusted_cidrs,
        tcp_syn_rate_limits_to_upsert=_dict_upserts(
            desired.tcp_syn_rate_limits, applied.tcp_syn_rate_limits
        ),
        tcp_syn_rate_limits_to_remove=_dict_removals(
            desired.tcp_syn_rate_limits, applied.tcp_syn_rate_limits
        ),
        tcp_syn_agg_rate_limits_to_upsert=_dict_upserts(
            desired.tcp_syn_agg_rate_limits, applied.tcp_syn_agg_rate_limits
        ),
        tcp_syn_agg_rate_limits_to_remove=_dict_removals(
            desired.tcp_syn_agg_rate_limits, applied.tcp_syn_agg_rate_limits
        ),
        tcp_syncookie_modes_to_upsert=_dict_upserts(
            desired.tcp_syncookie_modes, applied.tcp_syncookie_modes
        ),
        tcp_syncookie_modes_to_remove=_dict_removals(
            desired.tcp_syncookie_modes, applied.tcp_syncookie_modes
        ),
        tcp_syncookie_rate_limits_to_upsert=_dict_upserts(
            desired.tcp_syncookie_rate_limits, applied.tcp_syncookie_rate_limits
        ),
        tcp_syncookie_rate_limits_to_remove=_dict_removals(
            desired.tcp_syncookie_rate_limits, applied.tcp_syncookie_rate_limits
        ),
        udp_rate_limits_to_upsert=_dict_upserts(
            desired.udp_rate_limits, applied.udp_rate_limits
        ),
        udp_rate_limits_to_remove=_dict_removals(
            desired.udp_rate_limits, applied.udp_rate_limits
        ),
        udp_agg_rate_limits_to_upsert=_dict_upserts(
            desired.udp_agg_rate_limits, applied.udp_agg_rate_limits
        ),
        udp_agg_rate_limits_to_remove=_dict_removals(
            desired.udp_agg_rate_limits, applied.udp_agg_rate_limits
        ),
        acl_rules_to_upsert=_acl_upserts(desired.acl_rules, applied.acl_rules),
        acl_rules_to_remove=set(applied.acl_rules) - set(desired.acl_rules),
    )
    changed = frozenset(plan.endpoint_upserts)
    revoked = frozenset(plan.endpoint_removals) | frozenset(
        key for key in changed if key in applied.endpoint_policies
    )
    plan.steps = (
        ReconcileStep("revoke", endpoints=revoked),
        ReconcileStep("prepare", ("revoke",), changed),
        ReconcileStep("admit", ("prepare",), frozenset(
            key for key in changed if desired.endpoint_policies[key].allow
        )),
        ReconcileStep("cleanup", ("admit",), frozenset(plan.endpoint_removals)),
    )
    if applied.bogon_filter_enabled is None or applied.bogon_filter_enabled != desired.bogon_filter_enabled:
        plan.bogon_filter_update = desired.bogon_filter_enabled
    if applied.drop_events_enabled is None or applied.drop_events_enabled != desired.drop_events_enabled:
        plan.drop_events_update = desired.drop_events_enabled
    if applied.udp_global_byte_rate is None or applied.udp_global_byte_rate != desired.udp_global_byte_rate:
        plan.udp_global_byte_rate_update = desired.udp_global_byte_rate
    return plan


def endpoint_scope(key: EndpointKey, config: ConfigSnapshot) -> tuple[tuple[str, ...], tuple[int, ...], str]:
    """Resolve a zone and bind address without widening an absent/private zone."""
    _, address, _, zone = key
    interfaces = tuple(name for name in config.ZONES.get(zone, {}).get("interfaces", ()) if name != "*")
    if not interfaces and zone != "public":
        raise ValueError(f"Zone {zone!r} has no concrete ingress interfaces")
    if address == "*":
        return interfaces, (4, 6), ""
    ip = ipaddress.ip_address(address.split("%", 1)[0])
    return interfaces, (ip.version,), "" if ip.is_unspecified else str(ip)
