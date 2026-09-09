"""Container attribution contracts for Docker/Podman-aware policy."""

from unittest import mock
from pathlib import Path
import tempfile

import pytest

from auto_xdp import config as cfg
from auto_xdp import discovery, policy
from auto_xdp import approvals
from auto_xdp.state import ObservedState, RuntimeEndpoint


def test_docker_published_port_is_attributed_from_inspect(monkeypatch: pytest.MonkeyPatch) -> None:
    record = {
        "Id": "a" * 64,
        "Name": "/web",
        "Config": {"Labels": {"app": "web"}},
        "NetworkSettings": {
            "Ports": {"8080/tcp": [{"HostIp": "0.0.0.0", "HostPort": "18080"}]}
        },
    }
    monkeypatch.setattr(discovery, "_CONTAINER_METADATA_UNTIL", 0.0)
    monkeypatch.setattr(
        discovery,
        "_container_inspect",
        lambda runtime: [record] if runtime == "docker" else [],
    )
    monkeypatch.setattr(discovery, "_endpoint_zone", lambda _address: "public")
    discovery._container_metadata()

    endpoint = discovery._endpoint("tcp", "0.0.0.0", 18080, "docker-proxy", "delegated", "process-name")

    assert endpoint.subject == "docker:" + "a" * 12
    assert endpoint.attribution_state == "exact"
    assert endpoint.attribution_source == "docker-inspect"
    assert endpoint.container_id == "a" * 64
    assert endpoint.container_labels == {"app": "web"}


def test_container_port_collision_is_not_authorized(monkeypatch: pytest.MonkeyPatch) -> None:
    records = [
        {"Id": "a" * 64, "Name": "/one", "Config": {}, "NetworkSettings": {"Ports": {"80/tcp": [{"HostPort": "18080"}]}}},
        {"Id": "b" * 64, "Name": "/two", "Config": {}, "NetworkSettings": {"Ports": {"80/tcp": [{"HostPort": "18080"}]}}},
    ]
    monkeypatch.setattr(discovery, "_CONTAINER_METADATA_UNTIL", 0.0)
    monkeypatch.setattr(discovery, "_container_inspect", lambda runtime: records if runtime == "docker" else [])
    monkeypatch.setattr(discovery, "_endpoint_zone", lambda _address: "public")
    discovery._container_metadata()

    endpoint = discovery._endpoint("tcp", "0.0.0.0", 18080, "docker-proxy", "delegated", "process-name")

    assert endpoint.subject == ""
    assert endpoint.attribution_state == "ambiguous"
    assert policy.resolve_exposure_decisions(ObservedState(endpoints=[endpoint]))[0].action == "drop"


def test_container_cgroup_uses_inspected_identity(monkeypatch: pytest.MonkeyPatch) -> None:
    container_id = "c" * 64
    identity = discovery.ContainerIdentity("podman", container_id, "api", {})
    monkeypatch.setattr(discovery, "_CONTAINER_BY_ID", {container_id: identity})
    with mock.patch("builtins.open", mock.mock_open(read_data=f"0::/user.slice/libpod-{container_id}.scope\n")):
        result = discovery._container_from_pid(123)
    assert result == identity


def test_container_resolver_matches_runtime_name_and_label(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cfg, "SUBJECTS", {
        "web": {
            "resolve": {"container_runtime": "docker", "container_name": "web", "container_label": {"app": "web"}},
            "exposure": {"public": {"tcp": {"ports": [18080]}}},
        }
    })
    monkeypatch.setattr(cfg, "ZONES", {"public": {"interfaces": []}})
    endpoint = RuntimeEndpoint(
        "tcp", "0.0.0.0", 18080, "wildcard", "public", "docker:" + "a" * 12, "exact", "docker-inspect",
        "docker", "a" * 64, "web", {"app": "web"},
    )

    decisions = policy.resolve_exposure_decisions(ObservedState(endpoints=[endpoint]))

    assert decisions[0].action == "allow"
    assert decisions[0].subject == "web"


def test_container_approval_writes_runtime_resolver() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        config_path = root / "config.toml"
        store_path = root / "run" / "approval.json"
        config_path.write_text("[zones.public]\ninterfaces = []\n[subjects.web]\n")
        request = approvals.create_request(
            store_path,
            config_path,
            subject="web",
            zone="public",
            protocol="tcp",
            ports=[18080],
            reason="publish container service",
            container_runtime="docker",
            container_name="web",
        )

        approvals.approve_request(store_path, config_path, request["id"], actor="approver")

        text = config_path.read_text()
        assert 'container_runtime = "docker"' in text
        assert 'container_name = "web"' in text
