"""Management edits must not overwrite a concurrent grant revocation."""
import multiprocessing
import os
import stat
from pathlib import Path

import pytest

from auto_xdp.admin import approvals, cli, config_file, handler_catalog as catalog


pytestmark = pytest.mark.component


def _paused_editor(context, ready, resume, result, command):
    original = config_file.read_snapshot
    def read(path):
        document = original(path)
        ready.set()
        if not resume.wait(15):
            raise RuntimeError("test writer was not resumed")
        return document
    config_file.read_snapshot = read
    try:
        if command == "module":
            catalog.configure(context, catalog.Module("icmp", "ICMP", "icmp_handler.o", "icmp", 0),
                              {"enabled": True})
            result.put("saved")
        else:
            result.put(cli.main(["--config", str(context.config), "log-level", "debug"]))
    except config_file.ConfigConflictError:
        result.put("conflict")


@pytest.mark.parametrize("command", ["module", "cli"])
def test_concurrent_editor_cannot_resurrect_revoked_approval(tmp_path, monkeypatch, command):
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.setattr(os, "fchown", lambda *args: None)
    config = tmp_path / "config.toml"
    store = tmp_path / "approvals.json"
    config_file.write_toml(config, {
        "zones": {"public": {"interfaces": []}},
        "subjects": {"web": {"resolve": {"systemd_unit": "web.service"}}},
    })
    request = approvals.create_request(store, config, subject="web", zone="public", protocol="tcp",
                                       ports=[443], reason="publish service")
    approvals.approve_request(store, config, request["id"])
    context = catalog.Context(config, tmp_path / "release", tmp_path / "handlers",
                              tmp_path / "bpf", tmp_path / "run")
    process_context = multiprocessing.get_context("fork")
    ready, resume, result = process_context.Event(), process_context.Event(), process_context.Queue()
    editor = process_context.Process(target=_paused_editor, args=(context, ready, resume, result, command))
    editor.start()
    try:
        assert ready.wait(10), "editor did not read its snapshot"
        approvals.revoke_request(store, config, request["id"])
        resume.set()
        assert result.get(timeout=10) == ("conflict" if command == "module" else 1)
        editor.join(10)
        assert editor.exitcode == 0
    finally:
        resume.set()
        if editor.is_alive():
            editor.terminate()
        editor.join(10)
    assert approvals.list_grants(config) == []
    assert approvals.list_requests(store)[0]["status"] == "revoked"
    assert "modules" not in config_file.load_toml(config)
    # A deliberate new edit can succeed without restoring the revoked grant.
    assert cli.main(["--config", str(config), "log-level", "debug"]) == 0
    assert approvals.list_grants(config) == []
    assert config_file.load_toml(config)["daemon"]["log_level"] == "debug"


def test_aliases_share_revision_and_stale_aba_edit_is_rejected(tmp_path):
    path = tmp_path / "config.toml"
    config_file.write_toml(path, {"value": "A"})
    alias = tmp_path / "alias.toml"
    alias.symlink_to(path)
    stale = config_file.read_snapshot(alias)
    config_file.read_snapshot(path).save({"value": "B"})
    config_file.read_snapshot(alias).save({"value": "A"})
    with pytest.raises(config_file.ConfigConflictError):
        stale.save({"value": "stale"})
    with pytest.raises(config_file.ConfigConflictError):
        config_file.write_toml(alias, {"value": "blind overwrite"})
    assert config_file.load_toml(path) == {"value": "A"}
    assert alias.is_symlink()
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_approval_conflict_does_not_record_a_successful_approval(tmp_path, monkeypatch):
    config, store = tmp_path / "config.toml", tmp_path / "approvals.json"
    config_file.write_toml(config, {"subjects": {"web": {"resolve": {"systemd_unit": "web.service"}}}})
    request = approvals.create_request(store, config, subject="web", zone="public", protocol="tcp",
                                       ports=[443], reason="publish service")
    def concurrent_edit(path):
        stale = config_file.read_snapshot(path)
        fresh = config_file.read_snapshot(path)
        fresh.data["daemon"] = {"log_level": "debug"}
        fresh.save()
        return stale
    monkeypatch.setattr(approvals, "read_snapshot", concurrent_edit)
    with pytest.raises(config_file.ConfigConflictError):
        approvals.approve_request(store, config, request["id"])
    assert approvals.list_requests(store)[0]["status"] == "pending"
    assert [item["action"] for item in approvals.list_history(store)[1]] == ["request"]
    assert approvals.list_grants(config) == []
    assert config_file.load_toml(config)["daemon"]["log_level"] == "debug"


def test_initialization_preserves_concurrent_creation_and_template_comments(tmp_path):
    path = tmp_path / "config.toml"
    missing = config_file.read_snapshot(path)
    assert config_file.ensure_config_exists(path, template='# keep me\nvalue = "first"\n')
    assert not config_file.ensure_config_exists(path, template='value = "second"\n')
    with pytest.raises(config_file.ConfigConflictError):
        missing.save({"value": "stale creation"})
    assert path.read_text() == '# keep me\nvalue = "first"\n'


def test_failed_atomic_publish_keeps_old_file_and_removes_temporary_file(tmp_path, monkeypatch):
    path = tmp_path / "config.toml"
    config_file.write_toml(path, {"value": "old"})
    document = config_file.read_snapshot(path)
    before = set(tmp_path.iterdir())
    def fail(*args):
        raise OSError("publish failed")
    monkeypatch.setattr(Path, "replace", fail)
    with pytest.raises(OSError, match="publish failed"):
        document.save({"value": "new"})
    assert config_file.load_toml(path) == {"value": "old"}
    assert set(tmp_path.iterdir()) == before
