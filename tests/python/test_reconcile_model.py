"""Shared contracts across discovery, policy, and backend application."""
from dataclasses import replace
import errno
import socket
import struct
from unittest import mock

import pytest

from auto_xdp import config as cfg, policy, syncer
from auto_xdp.backends.nftables import NftablesBackend
from auto_xdp.backends.xdp import XdpBackend
from auto_xdp.bpf.maps import BpfEndpointScopeMap, CacheVerifyMixin
from auto_xdp.state import (
    AppliedState, DesiredState, EndpointPolicy, ObservedState, RuntimeEndpoint, ReconcileStep,
    compute_reconcile_plan, project_endpoint_policies,
)
from test_xdp_port_sync import (
    FakePortMap, FakeTrustedMap, FakeRuntimeConfigMap, _make_failing_backend,
)


KEY = ("tcp", "198.51.100.10", 8080, "public")


def target(policies=None, **settings):
    snapshot = cfg.ConfigSnapshot({**cfg.snapshot_config().values, **settings})
    return DesiredState(config=snapshot,
                        endpoint_policies=policies if policies is not None else {KEY: EndpointPolicy(True, "grant")})


def test_snapshot_is_deeply_immutable_and_candidate_validation_is_pure():
    before = cfg.snapshot_config()
    raw = {"zones": {"public": {"interfaces": ["eth0"]}}}
    candidate = cfg.parse_toml_config(raw)
    raw["zones"]["public"]["interfaces"].append("eth1")
    assert candidate.ZONES["public"]["interfaces"] == ("eth0",)
    with pytest.raises(TypeError):
        candidate.ZONES["public"]["interfaces"] = ()
    with pytest.raises(ValueError):
        cfg.parse_toml_config({"policy": {"mode": "invalid"}})
    assert cfg.snapshot_config().values == before.values


def test_policy_and_backend_use_the_supplied_snapshot_after_reload():
    snapshot = cfg.parse_toml_config({
        "rate_limits": {"syn_by_proc": {"web": 123}},
        "zones": {"public": {"interfaces": []}},
        "subjects": {"web": {"resolver": {"comm": "web"},
                             "exposure": {"public": {"tcp": {"ports": [8080]}}}}},
    })
    endpoint = RuntimeEndpoint("tcp", KEY[1], KEY[2], "address", "public", "web", "delegated",
                               process_name="web", instance_id="socket:1")
    with mock.patch.object(cfg, "_SYN_RATE_BY_PROC", {"web": 999}), mock.patch.object(cfg, "ZONES", {}):
        desired = policy.resolve_desired_state(ObservedState(endpoints=[endpoint]), config=snapshot)
    assert desired.config is snapshot
    assert desired.endpoint_policies[KEY].syn_rate == 123
    assert desired.endpoint_policies[KEY].instance_id == "socket:1"


def test_one_round_passes_the_identical_snapshot_to_discovery_and_policy():
    observed = ObservedState()
    with mock.patch.object(syncer, "observe_system_state", return_value=observed) as discover, \
         mock.patch.object(syncer, "resolve_desired_state", return_value=DesiredState()) as resolve:
        report = syncer.sync_once(None, False, mode="observe")
    assert discover.call_args.kwargs["config"] is report["config"]
    assert resolve.call_args.kwargs["config"] is report["config"]
    assert report["apply_result"] is None


def test_projection_preserves_address_zone_and_rejects_unrepresentable_limits():
    other = ("tcp", "198.51.100.11", 8080, "trusted")
    desired = target({KEY: EndpointPolicy(True, "grant", syn_rate=5),
                      other: EndpointPolicy(True, "grant", syn_rate=10)},
                     ZONES={"public": {"interfaces": []}, "trusted": {"interfaces": ["wg0"]}})
    effective, blocked = project_endpoint_policies(desired)
    assert set(blocked) == {KEY, other}
    assert not effective.tcp_ports and not effective.zone_tcp_ports
    assert desired.endpoint_policies[KEY].allow  # target intent remains intact
    compatible = replace(desired, endpoint_policies={key: replace(value, syn_rate=5)
                                                    for key, value in desired.endpoint_policies.items()})
    effective, blocked = project_endpoint_policies(compatible)
    assert not blocked and set(effective.endpoint_policies) == {KEY, other}
    assert effective.zone_tcp_ports == {"public": {8080}, "trusted": {8080}}


def test_listener_restart_requires_close_prepare_open_and_absence_is_unknown():
    old = EndpointPolicy(True, "grant", instance_id="1", profile="minecraft")
    desired = target({KEY: replace(old, instance_id="2")})
    plan = compute_reconcile_plan(desired, AppliedState(endpoint_policies={KEY: old}))
    assert plan.target is desired
    assert [step.operation for step in plan.steps] == ["revoke", "prepare", "admit", "cleanup"]
    assert KEY in plan.steps[0].endpoints and KEY in plan.steps[2].endpoints
    assert plan.steps[2].depends_on == ("prepare",)
    assert AppliedState().evidence.get("endpoint_policies", "unknown") == "unknown"


def test_xdp_scope_abi_and_private_tombstone_do_not_widen_ipv4_address():
    backend = XdpBackend.__new__(XdpBackend)
    desired = target(ZONES={"public": {"interfaces": []}, "trusted": {"interfaces": ["wg0"]}})
    with mock.patch.object(socket, "if_nametoindex", return_value=7):
        values, blocked = backend._scope_values(desired)
    assert not blocked
    assert values[struct.pack("=IHBB16s", 0, 8080, 6, 2, socket.inet_aton(KEY[1]) + bytes(12))] == 1
    assert values[struct.pack("=IHBB16s", 7, 8080, 6, 2, bytes(16))] == 0
    assert all(len(raw) == 24 and raw[7] == 2 for raw in values)
    private = target({("udp", "::", 53, "trusted"): EndpointPolicy(True, "grant")}, ZONES={})
    values, blocked = backend._scope_values(private)
    assert not values and blocked


class ScopeMap:
    path = "endpoint_scopes"

    def __init__(self):
        self.cache = {}
        self.fail_admit = False
        self.fail_revoke = False
        self.unreadable = False

    def active(self):
        return dict(self.cache)

    def set(self, key, value, dry_run=False):
        if self.fail_revoke and not value:
            self.last_error = "injected revoke failure"
            return False
        if self.fail_admit and value:
            self.last_error = "injected ENOSPC"
            return False
        if not dry_run:
            self.cache[key] = value
        return True

    def delete(self, key, dry_run=False):
        if not dry_run:
            self.cache.pop(key, None)
        return True

    def verify(self):
        if self.unreadable:
            raise OSError(errno.EPERM, "injected read failure")
        return 0


def xdp_backend():
    backend = _make_failing_backend()
    for name in ("sctp_map", "syn_rate_map", "syn_agg_rate_map", "udp_rate_map", "udp_agg_rate_map",
                 "acl_maps", "global_rl_map", "sit4_map", "syn4_outer", "syn6_outer", "udprt4_outer", "udprt6_outer"):
        setattr(backend, name, None)
    backend.tcp_map, backend.udp_map, backend.trusted_map = FakePortMap(), FakePortMap(), FakeTrustedMap()
    for resource in (backend.tcp_map, backend.udp_map, backend.trusted_map):
        resource.verify = lambda: 0
    backend.runtime_config_map = FakeRuntimeConfigMap()
    backend.endpoint_map = ScopeMap()
    backend._save_policy_generations = lambda: None
    return backend


def test_xdp_reports_partial_failure_and_confirms_closed_admission():
    backend = xdp_backend()
    backend.endpoint_map.fail_admit = True
    result = backend.reconcile(target(), False)
    assert not result.successful
    assert result.failures[0].reason == "injected ENOSPC"
    assert KEY in result.blocked_endpoints and KEY in result.closed_endpoints
    assert result.applied.endpoint_admission[KEY] == "closed"
    assert all(not value for value in backend.endpoint_map.active().values())


def test_xdp_honors_plan_dependencies_before_admitting_endpoints():
    backend = xdp_backend()
    desired = target()
    plan = compute_reconcile_plan(desired, backend.get_applied_state())
    plan.steps = (plan.steps[0], ReconcileStep("admit", ("prepare",)))
    with mock.patch.object(backend, "build_reconcile_plan", return_value=plan):
        result = backend.reconcile(desired, False)
    assert "admit" in result.unconfirmed and not result.successful
    assert not backend.tcp_map.active_ports()
    assert result.applied.endpoint_admission.get(KEY, "unknown") == "unknown"
    assert KEY not in result.applied.endpoint_policies


def test_profile_cleanup_failure_keeps_its_reason_in_the_same_failure_journal():
    backend = xdp_backend()
    backend.tcp_profile_map = mock.Mock()
    backend.tcp_profile_map.value.return_value = (42,)
    with mock.patch.object(backend, "_pinned_program_id", return_value=None):
        result = backend.reconcile(target({}), False)
    assert backend.last_apply_failures == len(result.failures) == 1
    assert result.failures[0].operation.stage == "cleanup"
    assert "inconsistent pinned profile handler" in result.failures[0].reason


def test_readback_failure_and_dry_run_never_claim_confirmation():
    backend = xdp_backend()
    backend.endpoint_map.unreadable = True
    result = backend.reconcile(target(), False)
    assert result.applied.evidence["endpoint_map"] == "unknown"
    assert "endpoint_map" in result.unconfirmed and not result.closed_endpoints
    backend = xdp_backend()
    result = backend.reconcile(target(), True)
    assert result.dry_run and not result.successful and not result.succeeded
    assert not backend.endpoint_map.active()
    assert not getattr(backend, "_endpoint_cache", {})
    assert "confirmed" not in result.applied.evidence.values()


def test_failed_kernel_read_preserves_the_previous_cache():
    resource = BpfEndpointScopeMap.__new__(BpfEndpointScopeMap)
    resource.fd, resource.path, resource._cache = 0, "endpoint_scopes", {bytes(24): 1}
    with mock.patch("auto_xdp.bpf.maps.bpf", side_effect=OSError(errno.EPERM, "denied")):
        with pytest.raises(OSError):
            CacheVerifyMixin.verify(resource)
    resource.fd = -1
    assert resource.active() == {bytes(24): 1}


def test_nft_scope_precedes_trust_and_limits_and_transaction_failure_retains_state():
    backend = NftablesBackend.__new__(NftablesBackend)
    desired = target(ZONES={"public": {"interfaces": []}, "trusted": {"interfaces": ["wg0"]}})
    backend._config = desired.config
    effective, _ = project_endpoint_policies(desired)
    rendered = backend._render_ruleset(effective, replace=True)
    assert 'meta nfproto ipv4 ip daddr 198.51.100.10 tcp dport 8080 counter return' in rendered
    assert 'iifname != { "wg0" }' in rendered
    assert rendered.index("jump endpoint_admission") < rendered.index("ip saddr @trusted")
    assert "ct direction reply counter accept" in rendered
    backend._policy_signature = None
    previous = AppliedState(tcp_ports={22}, evidence={"policy": "cached"})
    backend.get_applied_state = lambda: previous
    with mock.patch.object(backend, "_install_ruleset", side_effect=RuntimeError("transaction rejected")):
        result = backend.apply_reconcile_plan(compute_reconcile_plan(desired, previous), False, desired)
    assert result.applied is previous and result.failures[0].reason == "transaction rejected"
    assert result.unconfirmed and not result.closed_endpoints


def test_revocation_failure_preserves_protection_and_is_not_reported_closed():
    backend = xdp_backend()
    desired = target({KEY: EndpointPolicy(True, "grant", instance_id="new")})
    values, _ = backend._scope_values(desired)
    backend.endpoint_map.cache = values
    backend.endpoint_map.fail_revoke = True
    backend._endpoint_cache = {KEY: EndpointPolicy(True, "grant", instance_id="old")}
    with mock.patch.object(backend, "_ensure_profile_handlers") as prepare, \
         mock.patch.object(backend, "_remove_stale_profile_handlers") as cleanup:
        result = backend.reconcile(desired, False)
    prepare.assert_not_called()
    cleanup.assert_not_called()
    assert result.failures and KEY not in result.closed_endpoints
    assert backend._endpoint_cache[KEY].instance_id == "old"


def test_unresolved_denied_listener_cannot_be_shadowed_by_a_wildcard_grant():
    wildcard = ("tcp", "0.0.0.0", 8080, "public")
    denied = ("tcp", "198.51.100.10", 8080, "unknown")
    desired = target({wildcard: EndpointPolicy(True, "grant"), denied: EndpointPolicy(False, "no attribution")}, ZONES={})
    effective, blocked = project_endpoint_policies(desired)
    assert wildcard in blocked and not effective.tcp_ports


def test_nft_transaction_ack_confirms_state_but_later_cache_is_labeled_cached():
    backend = NftablesBackend.__new__(NftablesBackend)
    desired = target()
    backend._config = desired.config
    backend._remember_desired(project_endpoint_policies(DesiredState(config=desired.config))[0])
    with mock.patch.object(backend, "_install_ruleset"):
        result = backend.reconcile(desired, False)
    assert result.successful and result.applied.evidence["policy"] == "confirmed"
    assert result.applied.endpoint_admission[KEY] == "admitted"
    assert backend.get_applied_state().evidence["policy"] == "cached"


def test_canonical_listener_identity_changes_profile_generation_without_legacy_decisions():
    backend = XdpBackend.__new__(XdpBackend)
    backend._policy_generations = {}
    first = target({KEY: EndpointPolicy(True, "grant", instance_id="1", profile="minecraft")})
    second = replace(first, endpoint_policies={KEY: replace(first.endpoint_policies[KEY], instance_id="2")})
    first, _ = project_endpoint_policies(first)
    second, _ = project_endpoint_policies(second)
    old = backend._endpoint_generation(first, ("public", 8080), "minecraft")
    assert backend._endpoint_generation(first, ("public", 8080), "minecraft") == old
    assert backend._endpoint_generation(second, ("public", 8080), "minecraft") != old


@pytest.mark.parametrize("value", [-1, 1 << 32])
def test_candidate_rejects_limits_outside_the_native_rate_abi(value):
    with pytest.raises(ValueError):
        cfg.parse_toml_config({"rate_limits": {"udp_by_proc": {"web": value}}})
