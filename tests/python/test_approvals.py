"""Approval persistence across interruptions and controller notification."""
import signal
import subprocess
from http import HTTPStatus
from pathlib import Path
from unittest.mock import Mock, patch

import pytest

from auto_xdp.admin import approval_api, approvals, cli, config_file


pytestmark = pytest.mark.component


@pytest.fixture
def request_files(tmp_path, monkeypatch):
    config = tmp_path / "config.toml"
    store = tmp_path / "state" / "approvals.json"
    config_file.write_toml(config, {"subjects": {"web": {
        "resolve": {"systemd_unit": "web.service"},
        "exposure": {"public": {"tcp": {"ports": [80]}}},
    }}})
    request = approvals.create_request(store, config, subject="web", zone="public",
                                       protocol="tcp", ports=[80, 443], reason="enable HTTPS")
    monkeypatch.setattr(approvals, "reload_daemon", Mock())
    return store, config, request["id"]


@pytest.mark.parametrize("failure", ["journal", "publish", "ledger"])
def test_approval_retry_keeps_original_port_contribution(request_files, failure):
    store, config, request_id = request_files
    save = approvals._save
    replace = Path.replace

    def fail_save(path, data):
        if (failure == "ledger" and path == store) or (failure == "journal" and path != store):
            raise OSError("interrupted save")
        save(path, data)

    def fail_publish(staged, destination):
        if failure == "publish" and destination == config:
            raise OSError("interrupted publish")
        return replace(staged, destination)

    with patch.object(approvals, "_save", fail_save), patch.object(Path, "replace", fail_publish):
        with pytest.raises(OSError, match="interrupted"):
            approvals.approve_request(store, config, request_id, actor="first operator")

    published = failure == "ledger"
    assert approvals.list_grants(config)[0]["ports"] == ([80, 443] if published else [80])
    # An unrelated edit between the crash and the next management command survives recovery.
    data = config_file.load_toml(config)
    data["daemon"] = {"log_level": "debug"}
    config_file.write_toml(config, data)
    assert approvals.list_requests(store)[0]["status"] == ("approved" if published else "pending")
    assert approvals.reload_daemon.call_count == int(published)

    approved = approvals.approve_request(store, config, request_id, actor="retrying operator")
    assert approved["applied_ports"] == [443]
    assert approved["approver"] == ("first operator" if published else "retrying operator")
    approvals.revoke_request(store, config, request_id)
    assert approvals.list_grants(config)[0]["ports"] == [80]
    assert config_file.load_toml(config)["daemon"] == {"log_level": "debug"}
    revision, history = approvals.list_history(store)
    assert revision == 3
    assert [item["action"] for item in history] == ["request", "approve", "revoke"]
    assert set(store.parent.iterdir()) == {store, Path(f"{store}.lock")}
    assert not list(config.parent.glob(".config.toml.*"))


@pytest.mark.parametrize("action", ["revoke", "deny"])
def test_interrupted_removal_records_one_audit_entry(request_files, action):
    store, config, request_id = request_files
    approvals.approve_request(store, config, request_id)
    save = approvals._save

    def fail_ledger(path, data):
        if path == store:
            raise OSError("ledger unavailable")
        save(path, data)

    with patch.object(approvals, "_save", fail_ledger), pytest.raises(OSError, match="ledger unavailable"):
        if action == "revoke":
            approvals.revoke_request(store, config, request_id)
        else:
            approvals.deny_grant(store, config, subject="web", zone="public",
                                 protocol="tcp", ports=[443], reason="retire HTTPS")

    assert approvals.list_grants(config)[0]["ports"] == [80]
    revision, history = approvals.list_history(store)
    assert revision == 3
    assert [item["action"] for item in history] == ["request", "approve", action]
    if action == "revoke":
        assert approvals.revoke_request(store, config, request_id)["status"] == "revoked"
        assert approvals.list_history(store) == (revision, history)


def test_openrc_policy_reload_uses_the_running_service_only():
    with patch.object(Path, "is_dir", return_value=False), patch.object(approvals.shutil, "which", return_value="/sbin/rc-service"), \
         patch.object(subprocess, "run") as run:
        approvals.reload_daemon()
    assert run.call_args.args[0] == ["rc-service", "--ifexists", "--ifstarted", "xdp-port-sync", "restart"]
    assert run.call_args.kwargs["check"]


@pytest.mark.parametrize("pid", [0, 5678])
def test_systemd_policy_reload_signals_the_running_controller(pid):
    result = subprocess.CompletedProcess([], 0, str(pid))
    with patch.object(Path, "is_dir", return_value=True), patch.object(subprocess, "run", return_value=result), \
         patch.object(approvals.os, "kill") as send_signal:
        approvals.reload_daemon()
    if pid:
        send_signal.assert_called_once_with(pid, signal.SIGHUP)
    else:
        send_signal.assert_not_called()


def test_allow_reports_saved_policy_when_openrc_restart_fails(tmp_path, monkeypatch, capsys):
    config = tmp_path / "config.toml"
    config.write_text("[zones.public]\ninterfaces = []\n")
    monkeypatch.delenv("AUTO_XDP_APPROVAL_STORE", raising=False)
    monkeypatch.setattr(approvals.os, "geteuid", lambda: 0)
    monkeypatch.setattr(approvals.os, "chown", Mock())
    is_dir = Path.is_dir
    monkeypatch.setattr(Path, "is_dir", lambda path: path != Path("/run/systemd/system") and is_dir(path))
    monkeypatch.setattr(approvals.shutil, "which", lambda name: "/sbin/rc-service")
    failure = subprocess.CalledProcessError(1, "rc-service", stderr="restart failed")
    args = ["--config", str(config), "--run-state-dir", str(tmp_path)]
    allow = [*args, "allow", "web.service", "tcp/443"]
    deny = [*args, "deny", "web.service", "tcp/443"]
    with patch.object(subprocess, "run", side_effect=failure):
        result = cli.main(allow)
    assert result == 1
    assert "Policy saved, but xdp-port-sync reload failed: restart failed" in capsys.readouterr().err
    assert approvals.list_grants(config)[0]["ports"] == [443]
    with patch.object(subprocess, "run") as notify:
        assert cli.main(allow) == 0
        assert "approval #1" in capsys.readouterr().out
        notify.assert_called_once()
    with patch.object(subprocess, "run", side_effect=failure):
        assert cli.main(deny) == 1
    with patch.object(subprocess, "run") as notify:
        assert cli.main(deny) == 0
        notify.assert_called_once()
    store = approvals.store_path(tmp_path)
    assert approvals.list_grants(config) == []
    assert [item["action"] for item in approvals.list_history(store)[1]] == ["request", "approve", "deny"]
    with patch.object(subprocess, "run"):
        assert cli.main(allow) == 0
    assert approvals.list_requests(store)[-1]["applied_ports"] == [443]


def test_allow_retry_can_finish_its_pending_request(request_files):
    store, config, request_id = request_files
    args = dict(subject="web", zone="public", protocol="tcp", ports=[80, 443], reason="enable HTTPS")
    with pytest.raises(ValueError, match="already pending"):
        approvals.create_request(store, config, **args)
    same = approvals.create_request(store, config, **args, reuse_matching=True)
    approved = approvals.approve_request(store, config, same["id"])
    assert approved["id"] == request_id and approved["applied_ports"] == [443]


def test_api_approval_can_retry_after_a_failed_reload(request_files):
    store, config, request_id = request_files
    handler = Mock(spec=approval_api.ApprovalHandler)
    handler.server = Mock(approval_store=store, config_path=config)
    handler.path = f"/v1/approvals/{request_id}/approve"
    handler._authorized.return_value = True
    handler._body.return_value = {}
    error = approvals.PolicyReloadError("controller restart failed")
    approvals.reload_daemon.side_effect = [error, None]

    approval_api.ApprovalHandler.do_POST(handler)
    handler._json.assert_called_once_with(HTTPStatus.SERVICE_UNAVAILABLE, {"error": str(error), "policy_saved": True})
    assert approvals.list_grants(config)[0]["ports"] == [80, 443]

    handler._json.reset_mock()
    approval_api.ApprovalHandler.do_POST(handler)
    status, approved = handler._json.call_args.args
    assert status == HTTPStatus.OK and approved["applied_ports"] == [443]
    assert approvals.reload_daemon.call_count == 2
    assert [item["action"] for item in approvals.list_history(store)[1]] == ["request", "approve"]
