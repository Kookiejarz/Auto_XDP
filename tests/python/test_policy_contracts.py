"""Deterministic contracts for the public userspace policy resolver."""

import pytest

from auto_xdp import config as cfg
from auto_xdp import policy
from auto_xdp.state import ObservedState, RuntimeEndpoint


DEFAULTS = {
    "XDP_DEFAULT_TCP_SYN_RATE": 100,
    "XDP_DEFAULT_TCP_SYN_RATE_STRICT": 5,
    "XDP_DEFAULT_TCP_SYN_AGG_RATE": 1000,
    "XDP_DEFAULT_TCP_SYN_AGG_RATE_STRICT": 50,
    "XDP_SENSITIVE_PORT_THRESHOLD": 5,
}

LIMIT_TABLES = (
    "_SYN_RATE_BY_PROC",
    "_SYN_RATE_BY_SERVICE",
    "_SYN_AGG_RATE_BY_PROC",
    "_SYN_AGG_RATE_BY_SERVICE",
    "_RATE_MAP_ENTRIES_BY_PROC",
    "_RATE_MAP_ENTRIES_BY_SERVICE",
)


@pytest.fixture(autouse=True)
def isolated_policy(monkeypatch: pytest.MonkeyPatch) -> None:
    for name, value in DEFAULTS.items():
        monkeypatch.setattr(cfg, name, value)
    for name in LIMIT_TABLES:
        monkeypatch.setattr(cfg, name, {})
    for name in ("TRUSTED_SRC_IPS",):
        monkeypatch.setattr(cfg, name, {})
    monkeypatch.setattr(cfg, "ACL_RULES", [])
    monkeypatch.setattr(cfg, "POLICY_MODE", "audit")
    monkeypatch.setattr(cfg, "ZONES", {"public": {"interfaces": [], "cidrs": []}})
    monkeypatch.setattr(cfg, "SUBJECTS", {})
    monkeypatch.setattr(cfg, "UNKNOWN_SUBJECTS", {"public": "deny"})
    monkeypatch.setattr(
        policy,
        "service_name",
        lambda port, proto: "ssh" if proto == "tcp" and port == 22 else "",
    )


def resolved_tcp_policy(port: int = 8080, proc: str = "app") -> tuple[int, ...]:
    desired = policy._desired_state_for_ports(
        ObservedState(tcp={port}, tcp_processes={port: proc})
    )
    return (
        desired.tcp_syn_rate_limits[port],
        desired.tcp_syn_agg_rate_limits[port],
    )


def test_default_tcp_protection_contract() -> None:
    assert {name: getattr(cfg, name) for name in DEFAULTS} == DEFAULTS
    assert resolved_tcp_policy() == (100, 1000)


def test_process_overrides_all_tcp_protection_layers() -> None:
    cfg._SYN_RATE_BY_PROC["app"] = 11
    cfg._SYN_AGG_RATE_BY_PROC["app"] = 12
    assert resolved_tcp_policy() == (11, 12)


def test_sensitive_service_selects_strict_defaults() -> None:
    cfg._SYN_RATE_BY_SERVICE["ssh"] = 2
    assert resolved_tcp_policy(port=22, proc="") == (5, 50)


def test_service_value_above_threshold_remains_explicit() -> None:
    cfg._SYN_RATE_BY_SERVICE["ssh"] = 10
    assert resolved_tcp_policy(port=22, proc="") == (10, 1000)


def test_zero_pinned_syn_limit_remains_in_desired_state() -> None:
    cfg._SYN_RATE_BY_PROC["benchmark"] = 0
    desired = policy._desired_state_for_ports(
        ObservedState(tcp={9090}, tcp_processes={9090: "benchmark"})
    )

    assert desired.tcp_syn_rate_limits == {9090: 0}
    assert desired.tcp_rate_map_entries == {}


def test_every_observed_port_receives_default_policy() -> None:
    desired = policy._desired_state_for_ports(
        ObservedState(
            tcp={8080, 9000},
            tcp_processes={8080: "app-a", 9000: "app-b"},
        )
    )
    assert desired.tcp_syn_rate_limits == {8080: 100, 9000: 100}


def test_service_aware_policy_requires_explicit_grant_and_runtime_owner() -> None:
    cfg.ZONES = {"public": {"interfaces": []}}
    cfg.SUBJECTS = {
        "website": {
            "resolve": {"systemd_unit": "nginx.service"},
            "exposure": {"public": {"tcp": {"ports": [443]}}},
            "protection": {"profile": "web"},
        }
    }
    observed = ObservedState(endpoints=[
        RuntimeEndpoint("tcp", "0.0.0.0", 443, "wildcard", "public", "nginx", "exact"),
        RuntimeEndpoint("tcp", "0.0.0.0", 8080, "wildcard", "public", "nginx", "exact"),
        RuntimeEndpoint("tcp", "0.0.0.0", 22, "wildcard", "public", "unknown", "unknown"),
    ])

    desired = policy.resolve_desired_state(observed)

    assert desired.tcp_ports == {443}
    assert [item.action for item in desired.exposure_decisions] == ["allow", "drop", "drop"]
    assert desired.exposure_decisions[0].protection_profile == "web"


def test_shared_port_with_incompatible_protection_is_closed() -> None:
    cfg.ZONES = {"public": {"interfaces": []}}
    cfg.SUBJECTS = {
        "a": {
            "resolve": {"process_name": "a"},
            "exposure": {"public": {"tcp": {"ports": [443]}}},
            "protection": {"profile": "web"},
        },
        "b": {
            "resolve": {"process_name": "b"},
            "exposure": {"public": {"tcp": {"ports": [443]}}},
            "protection": {"profile": "tls"},
        },
    }
    observed = ObservedState(endpoints=[
        RuntimeEndpoint("tcp", "192.0.2.1", 443, "specific", "public", "a", "shared"),
        RuntimeEndpoint("tcp", "192.0.2.2", 443, "specific", "public", "b", "shared"),
    ])

    decisions = policy.resolve_exposure_decisions(observed)

    assert all(item.action == "drop" for item in decisions)
    assert all("incompatible" in item.reason for item in decisions)


def test_shared_port_with_unknown_owner_is_closed() -> None:
    cfg.ZONES = {"public": {"interfaces": []}}
    cfg.SUBJECTS = {
        "dns": {
            "resolve": {"process_name": "dns-a"},
            "exposure": {"public": {"udp": {"ports": [5353]}}},
        }
    }
    observed = ObservedState(endpoints=[
        RuntimeEndpoint("udp", "0.0.0.0", 5353, "specific", "public", "dns-a", "shared"),
        RuntimeEndpoint("udp", "192.0.2.10", 5353, "specific", "public", "", "ambiguous"),
    ])

    decisions = policy.resolve_exposure_decisions(observed)

    assert all(item.action == "drop" for item in decisions)
    assert all("unknown or ambiguous" in item.reason for item in decisions)


def test_private_grant_uses_zone_admission_without_public_port() -> None:
    cfg.ZONES = {
        "public": {"interfaces": []},
        "trusted": {"interfaces": ["wg0"]},
    }
    cfg.SUBJECTS = {
        "postgres": {
            "resolve": {"process_name": "postgres"},
            "exposure": {"trusted": {"tcp": {"ports": [5432]}}},
        }
    }

    desired = policy.resolve_desired_state(ObservedState(endpoints=[
        RuntimeEndpoint("tcp", "192.0.2.10", 5432, "specific", "trusted", "postgres", "delegated"),
    ]))

    assert desired.tcp_ports == set()
    assert desired.zone_tcp_ports == {"trusted": {5432}}
    assert desired.tcp_syn_rate_limits == {5432: 100}


def test_wildcard_listener_is_evaluated_for_each_ingress_zone() -> None:
    cfg.ZONES = {
        "public": {"interfaces": ["eth0"]},
        "trusted": {"interfaces": ["wg0"]},
    }
    cfg.SUBJECTS = {
        "postgres": {
            "resolve": {"systemd_unit": "postgres.service"},
            "exposure": {"trusted": {"tcp": {"ports": [5432]}}},
        }
    }

    desired = policy.resolve_desired_state(ObservedState(endpoints=[
        RuntimeEndpoint(
            "tcp", "0.0.0.0", 5432, "wildcard", "public",
            "postgres.service", "exact", "systemd-cgroup",
        ),
    ]))

    by_zone = {item.endpoint.ingress_zone: item.action for item in desired.exposure_decisions}
    assert by_zone == {"public": "drop", "trusted": "allow"}
    assert desired.tcp_ports == set()
    assert desired.zone_tcp_ports == {"trusted": {5432}}


def test_interface_scoped_public_grant_does_not_use_global_port_map() -> None:
    cfg.ZONES = {"public": {"interfaces": ["eth0"]}}
    cfg.SUBJECTS = {
        "web": {
            "resolve": {"process_name": "web"},
            "exposure": {"public": {"tcp": {"ports": [443]}}},
        }
    }

    desired = policy.resolve_desired_state(ObservedState(endpoints=[
        RuntimeEndpoint("tcp", "192.0.2.10", 443, "specific", "public", "web", "delegated"),
    ]))

    assert desired.tcp_ports == set()
    assert desired.zone_tcp_ports == {"public": {443}}
