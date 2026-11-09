from types import SimpleNamespace
from unittest import mock

import pytest

from auto_xdp.tui import app
from auto_xdp.tui.metrics import HostMetrics, NetworkMetrics


@pytest.fixture
def snapshot_env(tmp_path, monkeypatch):
    config = tmp_path / "config.toml"
    config.write_text('[policy]\nmode = "audit"\n')
    args = SimpleNamespace(
        iface="ens5", config=str(config), bpf_pin_dir=str(tmp_path / "pins"),
        run_state_dir=str(tmp_path / "run"), nft_family="inet", nft_table="auto_xdp",
    )
    backend = mock.Mock(side_effect=RuntimeError("No active Auto XDP backend detected."))
    stats = mock.Mock(return_value=([("XDP_TOTAL", 100, 4096)], "42"))
    ports = mock.Mock(return_value=[("TCP", 22, "ssh", "sshd", "-")])
    audit_rows = [{"action": "allow", "protocol": "TCP", "port": 22, "subject": "sshd"}]
    monkeypatch.setattr(app, "detect_backend", backend)
    monkeypatch.setattr(app, "collect_stats_rows", stats)
    monkeypatch.setattr(app, "_collect_port_rows", ports)
    monkeypatch.setattr(app, "_collect_map_usage", mock.Mock(return_value=[]))
    monkeypatch.setattr(app, "_collect_audit_rows", lambda path: audit_rows)
    monkeypatch.setattr(app, "read_xdp_map_id", lambda path: "42")
    monkeypatch.setattr(app, "_xdp_attach_mode", lambda iface: "xdp native")
    monkeypatch.setattr(app, "_read_packet_events_enabled", lambda path: True)
    monkeypatch.setattr(app, "_read_cookie_runtime", lambda path: None)
    resources = mock.Mock(spec=app.ResourceSampler)
    resources.sample.return_value = (
        HostMetrics(cpu_percent=12.5), NetworkMetrics(iface="ens5", rx_bytes=4096),
    )
    return SimpleNamespace(
        args=args, config=config, backend=backend, stats=stats, ports=ports,
        audit_rows=audit_rows, resources=resources,
    )


@pytest.mark.parametrize("mode", ["audit", "observe"])
def test_inactive_policy_keeps_host_and_audit_monitoring(snapshot_env, mode):
    env = snapshot_env
    env.config.write_text(f'[policy]\nmode = "{mode}"\n')
    snap, previous, timestamp = app._collect_snapshot(
        env.args, {"XDP_TOTAL": (9999, 65536)}, 1, resource_sampler=env.resources,
    )
    assert snap.backend == "inactive"
    assert snap.policy_mode == mode
    assert snap.attach_mode == f"inactive ({mode})"
    assert snap.attach_targets == [("ens5", f"inactive ({mode})")]
    assert snap.network.rx_bytes == 4096
    assert snap.host.cpu_percent == 12.5
    assert snap.audit_rows == env.audit_rows
    assert snap.audit_status == ""
    assert snap.stats == []
    assert [(proto, port, owner, limit) for proto, port, _, owner, limit in snap.ports] == [
        ("TCP", 22, "sshd", "not active"),
    ]
    assert snap.rates == previous == {}
    assert snap.map_id == "-"
    env.stats.assert_not_called()
    env.ports.assert_not_called()
    env.resources.sample.assert_called_once_with("ens5", timestamp)


def test_enforce_without_backend_still_reports_failure(snapshot_env):
    env = snapshot_env
    env.config.write_text('[policy]\nmode = "enforce"\n')
    snap, _, _ = app._collect_snapshot(env.args, {}, 1)
    assert snap.policy_mode == "enforce" and snap.backend == "inactive"
    assert "No active Auto XDP backend" in snap.protection_error
    env.stats.assert_not_called()


@pytest.mark.parametrize("content", [None, '[policy', '[policy]\nmode = "typo"\n', 'policy = []'])
def test_bad_or_missing_config_is_not_reported_as_inactive(snapshot_env, content):
    env = snapshot_env
    if content is None:
        env.config.unlink()
    else:
        env.config.write_text(content)
    with pytest.raises((OSError, ValueError)):
        app._collect_snapshot(env.args, {}, 1)


@pytest.mark.parametrize("backend", ["xdp", "nftables"])
def test_snapshot_recovers_when_backend_activates(snapshot_env, backend):
    env = snapshot_env
    _, previous, timestamp = app._collect_snapshot(env.args, {}, 1)
    env.backend.side_effect = None
    env.backend.return_value = backend
    snap, previous, _ = app._collect_snapshot(env.args, previous, timestamp)
    assert snap.backend == backend
    assert snap.ports == env.ports.return_value
    assert previous == {"XDP_TOTAL": (100, 4096)}
    assert snap.rates["XDP_TOTAL"] == (None, None)
    assert snap.attach_mode == (
        "xdp native" if backend == "xdp" else "nftables fallback (inet auto_xdp)"
    )
    env.stats.assert_called_once()
    env.ports.assert_called_once()


def test_policy_mode_follows_configuration_not_backend_label(snapshot_env):
    env = snapshot_env
    env.backend.side_effect = None
    env.backend.return_value = "xdp"
    snap, previous, timestamp = app._collect_snapshot(env.args, {}, 1)
    assert snap.policy_mode == "audit"
    env.config.write_text('[policy]\nmode="enforce"\n')
    snap, _, _ = app._collect_snapshot(env.args, previous, timestamp)
    assert snap.policy_mode == "enforce"
