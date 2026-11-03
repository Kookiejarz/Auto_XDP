"""Disabling the runtime must detach its generic egress hook without deleting foreign filters."""
import json
import subprocess
from unittest import mock

import pytest

from auto_xdp.admin import runtime

pytestmark = pytest.mark.component


@pytest.mark.parametrize("actual_id, handle, removed", [(42, "0x2", True), (99, "0x2", False), (42, "0x3", False)])
@pytest.mark.parametrize("nested", [False, True])
@pytest.mark.parametrize("pin_name", ["tc_egress_dispatch_prog", "minecraft_egress_prog"])
def test_egress_cleanup_checks_program_identity_and_handle(tmp_path, actual_id, handle, removed, nested, pin_name):
    (tmp_path / pin_name).touch()
    calls = []
    def run(command):
        calls.append(command)
        return subprocess.CompletedProcess(command, 0, json.dumps([
            {"kind": "bpf", "options": {"handle": handle, **(
                {"prog": {"id": actual_id}} if nested else {"id": actual_id})}},
        ]), "")
    with mock.patch.object(runtime, "_pinned_xdp_program_id", side_effect=[42, None]), \
         mock.patch.object(runtime, "_command_exists", return_value=True), \
         mock.patch.object(runtime, "_run_text", side_effect=run):
        messages = runtime._detach_handler_egress(tmp_path, ["eth0"])
    assert bool(messages) == removed
    assert any("del" in command for command in calls) == removed
    if removed:
        assert calls[-1] == ["tc", "filter", "del", "dev", "eth0", "egress", "protocol", "all", "pref", "49153", "handle", "2", "bpf"]


def test_unreadable_egress_does_not_report_a_successful_cleanup(tmp_path):
    (tmp_path / "tc_egress_dispatch_prog").touch()
    with mock.patch.object(runtime, "_pinned_xdp_program_id", side_effect=[42, None]), \
         mock.patch.object(runtime, "_command_exists", return_value=True), \
         mock.patch.object(runtime, "_run_text", return_value=subprocess.CompletedProcess([], 1, "", "denied")), \
         pytest.raises(RuntimeError, match="Cannot inspect handler egress"):
        runtime._detach_handler_egress(tmp_path, ["eth0"])
