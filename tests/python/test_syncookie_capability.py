from unittest import mock
import json
from pathlib import Path
import subprocess

import pytest

from auto_xdp.bpf.syncookie import (
    HELPERS,
    acquire_sysctl,
    probe_reqsk_handoff_environment,
    probe_syncookie_capability,
    release_sysctl,
)


def test_syncookie_capability_requires_all_helpers_and_sysctl(monkeypatch):
    output = "\n".join(HELPERS)
    monkeypatch.setattr("auto_xdp.bpf.syncookie.shutil.which", lambda _: "/usr/sbin/bpftool")
    monkeypatch.setattr(
        "auto_xdp.bpf.syncookie.subprocess.run",
        lambda *args, **kwargs: mock.Mock(stdout=output, stderr=""),
    )
    with mock.patch(
        "builtins.open", mock.mock_open(read_data="1\n")
    ):
        capability = probe_syncookie_capability()
    assert capability.available


def test_syncookie_capability_rejects_zero_sysctl(monkeypatch):
    monkeypatch.setattr("auto_xdp.bpf.syncookie.shutil.which", lambda _: "/usr/sbin/bpftool")
    monkeypatch.setattr(
        "auto_xdp.bpf.syncookie.subprocess.run",
        lambda *args, **kwargs: mock.Mock(stdout="\n".join(HELPERS), stderr=""),
    )
    with mock.patch(
        "builtins.open", mock.mock_open(read_data="0\n")
    ):
        capability = probe_syncookie_capability()
    assert capability.helpers
    assert not capability.available


def _environment(monkeypatch, *, hooks="", rules=None, legacy=None,
                 hooks_status=0, rules_status=0):
    calls = []
    monkeypatch.setattr("auto_xdp.bpf.syncookie.shutil.which", lambda _: "/usr/sbin/nft")
    if rules is None:
        rules = {"nftables": [{"metainfo": {"json_schema_version": 1}}]}
    text = json.dumps(rules) if not isinstance(rules, str) else rules

    def run(command, **kwargs):
        calls.append(command)
        assert kwargs.get("timeout") == 5
        if command[1:] == ["list", "hooks", "inet"]:
            return subprocess.CompletedProcess(command, hooks_status, hooks, "")
        assert command[1:] == ["-j", "list", "ruleset"]
        return subprocess.CompletedProcess(command, rules_status, text, "")

    monkeypatch.setattr("auto_xdp.bpf.syncookie.subprocess.run", run)
    original = Path.read_text

    def read(path, **kwargs):
        if str(path) in ("/proc/net/ip_tables_names", "/proc/net/ip6_tables_names"):
            value = (legacy or {}).get(path.name, "")
            if isinstance(value, Exception):
                raise value
            return value
        return original(path, **kwargs)

    monkeypatch.setattr(Path, "read_text", read)
    return calls


def test_reqsk_gate_rejects_actual_nat_local_in_hook(monkeypatch):
    calls = _environment(monkeypatch, hooks="family ip { hook input { +0000000100 nf_nat_ipv4_local_in [nf_nat] } }")
    ready, reason = probe_reqsk_handoff_environment()
    assert not ready and "NAT LOCAL_IN" in reason
    assert len(calls) == 1


def test_reqsk_gate_empty_hook_dump_does_not_hide_docker_nat(monkeypatch):
    _environment(monkeypatch, rules={"nftables": [
        {"chain": {"family": "ip", "type": "nat", "hook": "output", "name": "OUTPUT"}},
    ]})
    ready, reason = probe_reqsk_handoff_environment()
    assert not ready and "NAT base chain" in reason


@pytest.mark.parametrize("expression", [
    {"dnat": {"addr": "127.0.0.11"}},
    {"xt": {"type": "target", "name": "SNAT"}},
])
def test_reqsk_gate_rejects_native_and_xt_nat_rules(monkeypatch, expression):
    _environment(monkeypatch, rules={"nftables": [{"rule": {"expr": [expression]}}]})
    ready, reason = probe_reqsk_handoff_environment()
    assert not ready and "NAT rule" in reason


@pytest.mark.parametrize("name", ["ip_tables_names", "ip6_tables_names"])
def test_reqsk_gate_rejects_legacy_nat(monkeypatch, name):
    _environment(monkeypatch, legacy={name: "filter\nnat\n"})
    ready, reason = probe_reqsk_handoff_environment()
    assert not ready and "legacy iptables NAT" in reason


def test_reqsk_gate_allows_verified_clean_namespace(monkeypatch):
    calls = _environment(monkeypatch, hooks_status=1, legacy={
        "ip_tables_names": "filter\n",
        "ip6_tables_names": FileNotFoundError(),
    })
    assert probe_reqsk_handoff_environment() == (True, "")
    assert ["/usr/sbin/nft", "-j", "list", "hooks"] not in calls


def test_reqsk_gate_allows_non_nat_firewall(monkeypatch):
    _environment(monkeypatch, rules={"nftables": [
        {"chain": {"family": "inet", "type": "filter", "hook": "input"}},
        {"rule": {"expr": [{"accept": None}]}}
    ]})
    assert probe_reqsk_handoff_environment() == (True, "")


@pytest.mark.parametrize("rules", ["bad-json", "{}", '{"nftables": null}'])
def test_reqsk_gate_does_not_claim_ready_for_unknown_rules(monkeypatch, rules):
    _environment(monkeypatch, rules=rules)
    ready, reason = probe_reqsk_handoff_environment()
    assert not ready and "unknown" in reason


def test_reqsk_gate_rejects_failed_ruleset_query(monkeypatch):
    _environment(monkeypatch, rules_status=1)
    ready, reason = probe_reqsk_handoff_environment()
    assert not ready and "unknown" in reason


def test_reqsk_gate_rejects_unreadable_legacy_tables(monkeypatch):
    _environment(monkeypatch, legacy={"ip6_tables_names": PermissionError()})
    ready, reason = probe_reqsk_handoff_environment()
    assert not ready and "unknown" in reason


def test_reqsk_gate_rejects_missing_nft(monkeypatch):
    monkeypatch.setattr("auto_xdp.bpf.syncookie.shutil.which", lambda _: None)
    ready, reason = probe_reqsk_handoff_environment()
    assert not ready and "unknown" in reason


def test_reqsk_gate_rejects_probe_timeout(monkeypatch):
    monkeypatch.setattr("auto_xdp.bpf.syncookie.shutil.which", lambda _: "/usr/sbin/nft")
    def timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired(args[0], 5)
    monkeypatch.setattr("auto_xdp.bpf.syncookie.subprocess.run", timeout)
    ready, reason = probe_reqsk_handoff_environment()
    assert not ready and "unknown" in reason


def test_capability_downgrades_level2_when_environment_is_incompatible(monkeypatch):
    output = "\n".join((*HELPERS, "bpf_sk_assign_tcp_reqsk"))
    monkeypatch.setattr("auto_xdp.bpf.syncookie.shutil.which", lambda _: "/usr/sbin/bpftool")
    monkeypatch.setattr("auto_xdp.bpf.syncookie.subprocess.run",
                        lambda command, **kwargs: subprocess.CompletedProcess(command, 0, output, ""))
    monkeypatch.setattr("auto_xdp.bpf.syncookie.probe_reqsk_handoff_environment",
                        lambda: (False, "NAT LOCAL_IN incompatible"))
    with mock.patch("builtins.open", mock.mock_open(read_data="1\n")):
        capability = probe_syncookie_capability()
    assert capability.helpers and capability.reqsk_handoff and capability.sysctl_ready
    assert capability.level == 1
    assert not capability.available
    assert capability.status == "degraded"
    assert not capability.as_dict()["reqsk_attrs"]["timestamp"]
    assert capability.reason == "NAT LOCAL_IN incompatible"


def test_sysctl_release_restores_owned_value(tmp_path):
    sysctl = tmp_path / "tcp_syncookies"
    state = tmp_path / "ownership.json"
    sysctl.write_text("0\n")
    acquire_sysctl(state, path=sysctl, desired=1)
    assert sysctl.read_text() == "1\n"
    assert release_sysctl(state, path=sysctl)
    assert sysctl.read_text() == "0\n"


def test_sysctl_release_preserves_operator_override(tmp_path):
    sysctl = tmp_path / "tcp_syncookies"
    state = tmp_path / "ownership.json"
    sysctl.write_text("0\n")
    acquire_sysctl(state, path=sysctl, desired=1)
    sysctl.write_text("2\n")
    assert not release_sysctl(state, path=sysctl)
    assert sysctl.read_text() == "2\n"


def test_sysctl_reacquire_preserves_original_value(tmp_path):
    sysctl = tmp_path / "tcp_syncookies"
    state = tmp_path / "ownership.json"
    sysctl.write_text("0\n")

    first = acquire_sysctl(state, path=sysctl)
    second = acquire_sysctl(state, path=sysctl)

    assert second == first
    assert second.old_value == 0
    assert release_sysctl(state, path=sysctl)
    assert sysctl.read_text() == "0\n"
