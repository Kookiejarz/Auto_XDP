from unittest import mock

from auto_xdp.bpf.syncookie import (
    HELPERS,
    acquire_sysctl,
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
