"""Audit approvals use live workload identity and retain the configured mode."""
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from auto_xdp.admin import approvals, config_file
from auto_xdp.state import ObservedState, RuntimeEndpoint
from auto_xdp.tui import app


@pytest.fixture
def audit(tmp_path, monkeypatch):
    config = tmp_path / "config.toml"
    config_file.write_toml(config, {
        "policy": {"mode": "audit"},
        "zones": {"public": {"interfaces": []}, "trusted": {"interfaces": ["wg0"]}},
    })
    endpoints = [RuntimeEndpoint("tcp", address, 22, "wildcard", subject="sshd.service",
                    attribution_state="exact", attribution_source="systemd-cgroup")
                 for address in ("0.0.0.0", "::")]
    observed = ObservedState(endpoints=endpoints)
    monkeypatch.setattr(app, "get_listening_ports", lambda **kwargs: observed)
    monkeypatch.setattr(app.os, "geteuid", lambda: 0)
    monkeypatch.setattr(app.os, "chown", lambda *args: None)
    monkeypatch.setattr(approvals, "reload_daemon", Mock())
    monkeypatch.delenv("AUTO_XDP_APPROVAL_STORE", raising=False)
    args = SimpleNamespace(config=str(config), run_state_dir=str(tmp_path / "run"))
    return SimpleNamespace(args=args, config=config, observed=observed,
                           rows=lambda: app._collect_audit_rows(str(config)),
                           store=approvals.store_path(args.run_state_dir))


def selected(audit):
    return next(row for row in audit.rows() if row["zone"] == "public" and row["address"] == "0.0.0.0")


def test_audit_approval_grants_only_selected_service_port_and_zone(audit):
    result = app._approve_audit_row(audit.args, selected(audit))
    config = config_file.load_toml(audit.config)
    assert config["policy"]["mode"] == "audit"
    assert config["subjects"] == {"sshd": {
        "resolve": {"systemd_unit": "sshd.service"}, "exposure": {"public": {"tcp": {"ports": [22]}}},
    }}
    assert "non-filtering" in result
    assert all(row["action"] == ("allow" if row["zone"] == "public" else "drop") for row in audit.rows())
    assert [row["status"] for row in approvals.list_requests(audit.store)] == ["approved"]
    approvals.reload_daemon.assert_called_once()


def test_audit_approval_reuses_matching_pending_request(audit):
    existing = approvals.create_request(audit.store, audit.config, subject="sshd", zone="public", protocol="tcp",
        ports=[22], reason="review SSH", systemd_unit="sshd.service")
    app._approve_audit_row(audit.args, selected(audit))
    requests = approvals.list_requests(audit.store)
    assert len(requests) == 1 and requests[0]["id"] == existing["id"] and requests[0]["status"] == "approved"


def test_audit_approval_does_not_authorize_changed_owner(audit):
    old = selected(audit)
    for endpoint in audit.observed.endpoints:
        endpoint.subject = "other.service"
    with pytest.raises(ValueError, match="changed"):
        app._approve_audit_row(audit.args, old)
    assert not audit.store.exists()
    assert "subjects" not in config_file.load_toml(audit.config)


@pytest.mark.parametrize("attribution", ["unknown", "ambiguous"])
def test_audit_requires_usable_identity(audit, attribution):
    for endpoint in audit.observed.endpoints:
        endpoint.attribution_state = attribution
    with pytest.raises(ValueError, match="identity"):
        app._approve_audit_row(audit.args, selected(audit))
    assert not audit.store.exists()


def test_audit_approval_respects_explicit_deny(audit):
    config = config_file.load_toml(audit.config)
    config["subjects"] = {"ssh_admin": {"resolve": {"systemd_unit": "sshd.service"}, "exposure": {"public": {"deny": True}}}}
    config_file.write_toml(audit.config, config)
    with pytest.raises(ValueError, match="policy conflict"):
        app._approve_audit_row(audit.args, selected(audit))
    assert config_file.load_toml(audit.config) == config
    assert not audit.store.exists()
