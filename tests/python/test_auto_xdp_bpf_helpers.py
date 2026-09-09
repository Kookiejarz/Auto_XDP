import io
import struct
import sys
import unittest
from contextlib import redirect_stderr
from unittest import mock

import pytest

import support


helpers = support.load_module("auto_xdp_bpf_helpers_test", "auto_xdp_bpf_helpers.py")

pytestmark = pytest.mark.component


class AutoXdpBpfHelpersTests(unittest.TestCase):
    def test_cmd_pin_maps_pins_each_reported_map(self):
        check_output = mock.Mock(
            side_effect=[
                '{"map_ids": [7, 8]}',
                '{"name": "tcp_whitelist"}',
                '{"name": "udp_whitelist"}',
            ]
        )

        with mock.patch.object(helpers.subprocess, "check_output", check_output), \
             mock.patch.object(helpers.subprocess, "check_call") as check_call:
            rc = helpers.cmd_pin_maps(42, "/sys/fs/bpf/xdp_fw")

        self.assertEqual(rc, 0)
        self.assertEqual(check_call.call_count, 2)
        check_call.assert_any_call(
            ["bpftool", "map", "pin", "id", "7", "/sys/fs/bpf/xdp_fw/tcp_whitelist"]
        )
        check_call.assert_any_call(
            ["bpftool", "map", "pin", "id", "8", "/sys/fs/bpf/xdp_fw/udp_whitelist"]
        )

    def test_cmd_pin_maps_falls_back_to_nested_maps_list(self):
        check_output = mock.Mock(
            side_effect=[
                '{"maps": [{"id": 99}]}',
                '{"name": "pkt_counters"}',
            ]
        )

        with mock.patch.object(helpers.subprocess, "check_output", check_output), \
             mock.patch.object(helpers.subprocess, "check_call") as check_call:
            rc = helpers.cmd_pin_maps(11, "/pins")

        self.assertEqual(rc, 0)
        check_call.assert_called_once_with(
            ["bpftool", "map", "pin", "id", "99", "/pins/pkt_counters"]
        )

    def test_cmd_pin_maps_returns_error_when_no_map_ids_exist(self):
        stderr = io.StringIO()
        with redirect_stderr(stderr), \
             mock.patch.object(helpers.subprocess, "check_output", return_value="{}"):
            rc = helpers.cmd_pin_maps(1, "/pins")

        self.assertEqual(rc, 1)
        self.assertIn("no map ids found", stderr.getvalue())

    def test_main_dispatches_pin_maps_subcommand(self):
        with mock.patch.object(sys, "argv", [
            "auto_xdp_bpf_helpers.py",
            "pin-maps",
            "--prog-id",
            "7",
            "--pin-dir",
            "/pins",
        ]), mock.patch.object(helpers, "cmd_pin_maps", return_value=0) as pin_cmd:
            rc = helpers.main()

        self.assertEqual(rc, 0)
        pin_cmd.assert_called_once_with(7, "/pins")


if __name__ == "__main__":
    unittest.main(verbosity=2)
