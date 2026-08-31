"""Deterministic contracts for the public userspace policy resolver."""

import pytest

from auto_xdp import config as cfg
from auto_xdp import policy
from auto_xdp.state import ObservedState


DEFAULTS = {
    "XDP_DEFAULT_TCP_SYN_RATE": 100,
    "XDP_DEFAULT_TCP_SYN_RATE_STRICT": 5,
    "XDP_DEFAULT_TCP_SYN_AGG_RATE": 1000,
    "XDP_DEFAULT_TCP_SYN_AGG_RATE_STRICT": 50,
    "XDP_DEFAULT_TCP_ESTABLISHED_PER_SRC": 50,
    "XDP_DEFAULT_TCP_ESTABLISHED_PER_SRC_STRICT": 5,
    "XDP_DEFAULT_TCP_ESTABLISHED_PER_PREFIX": 200,
    "XDP_DEFAULT_TCP_ESTABLISHED_PER_PREFIX_STRICT": 20,
    "XDP_DEFAULT_TCP_ESTABLISHED_PER_PORT": 5000,
    "XDP_DEFAULT_TCP_ESTABLISHED_PER_PORT_STRICT": 200,
    "XDP_SENSITIVE_PORT_THRESHOLD": 5,
}

LIMIT_TABLES = (
    "_SYN_RATE_BY_PROC",
    "_SYN_RATE_BY_SERVICE",
    "_SYN_AGG_RATE_BY_PROC",
    "_SYN_AGG_RATE_BY_SERVICE",
    "_TCP_CONN_BY_PROC",
    "_TCP_CONN_BY_SERVICE",
    "_TCP_CONN_PREFIX_BY_PROC",
    "_TCP_CONN_PREFIX_BY_SERVICE",
    "_TCP_CONN_PORT_BY_PROC",
    "_TCP_CONN_PORT_BY_SERVICE",
    "_RATE_MAP_ENTRIES_BY_PROC",
    "_RATE_MAP_ENTRIES_BY_SERVICE",
)


@pytest.fixture(autouse=True)
def isolated_policy(monkeypatch: pytest.MonkeyPatch) -> None:
    for name, value in DEFAULTS.items():
        monkeypatch.setattr(cfg, name, value)
    for name in LIMIT_TABLES:
        monkeypatch.setattr(cfg, name, {})
    for name in ("TCP_PERMANENT", "UDP_PERMANENT", "SCTP_PERMANENT", "TRUSTED_SRC_IPS"):
        monkeypatch.setattr(cfg, name, {})
    monkeypatch.setattr(cfg, "ACL_RULES", [])
    monkeypatch.setattr(
        policy,
        "service_name",
        lambda port, proto: "ssh" if proto == "tcp" and port == 22 else "",
    )


def resolved_tcp_policy(port: int = 8080, proc: str = "app") -> tuple[int, ...]:
    desired = policy.resolve_desired_state(
        ObservedState(tcp={port}, tcp_processes={port: proc})
    )
    return (
        desired.tcp_syn_rate_limits[port],
        desired.tcp_syn_agg_rate_limits[port],
        desired.tcp_conn_limits[port],
        desired.tcp_conn_prefix_limits[port],
        desired.tcp_conn_port_limits[port],
    )


def test_default_tcp_protection_contract() -> None:
    assert {name: getattr(cfg, name) for name in DEFAULTS} == DEFAULTS
    assert resolved_tcp_policy() == (100, 1000, 50, 200, 5000)


def test_process_overrides_all_tcp_protection_layers() -> None:
    cfg._SYN_RATE_BY_PROC["app"] = 11
    cfg._SYN_AGG_RATE_BY_PROC["app"] = 12
    cfg._TCP_CONN_BY_PROC["app"] = 13
    cfg._TCP_CONN_PREFIX_BY_PROC["app"] = 14
    cfg._TCP_CONN_PORT_BY_PROC["app"] = 15

    assert resolved_tcp_policy() == (11, 12, 13, 14, 15)


def test_sensitive_service_selects_strict_defaults() -> None:
    cfg._SYN_RATE_BY_SERVICE["ssh"] = 2
    assert resolved_tcp_policy(port=22, proc="") == (5, 50, 5, 20, 200)


def test_service_value_above_threshold_remains_explicit() -> None:
    cfg._SYN_RATE_BY_SERVICE["ssh"] = 10
    assert resolved_tcp_policy(port=22, proc="") == (10, 1000, 50, 200, 5000)


def test_zero_pinned_syn_limit_remains_in_desired_state() -> None:
    cfg._SYN_RATE_BY_PROC["benchmark"] = 0
    desired = policy.resolve_desired_state(
        ObservedState(tcp={9090}, tcp_processes={9090: "benchmark"})
    )

    assert desired.tcp_syn_rate_limits == {9090: 0}
    assert desired.tcp_rate_map_entries == {}


def test_every_observed_port_receives_default_policy() -> None:
    desired = policy.resolve_desired_state(
        ObservedState(
            tcp={8080, 9000},
            tcp_processes={8080: "app-a", 9000: "app-b"},
        )
    )
    assert desired.tcp_syn_rate_limits == {8080: 100, 9000: 100}
