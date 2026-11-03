import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from auto_xdp.admin import handlers


class PortHandlerUnloadTests(unittest.TestCase):
    def test_high_port_unload_encodes_complete_key_before_removing_pins(self):
        for port, encoded in ((19053, ["109", "74", "0", "0"]), (65535, ["255", "255", "0", "0"])):
            with self.subTest(port=port), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                pin = handlers.port_handler_dir(root, "udp", port)
                pin.mkdir(parents=True)
                (pin / "prog").touch()
                with mock.patch.object(handlers, "_pinned_u32_lookup", side_effect=[7, None, None]), \
                     mock.patch.object(handlers, "pinned_program_id", return_value=7), \
                     mock.patch.object(handlers.subprocess, "run", return_value=subprocess.CompletedProcess([], 0)) as run, \
                     mock.patch.object(handlers, "flush_udp_validated_for_port") as flush:
                    handlers.cleanup_existing_port_handler(root, "udp", port)
                self.assertEqual(run.call_args.args[0], [
                    "bpftool", "map", "delete", "pinned", str(root / "udp_port_handlers"), "key", *encoded,
                ])
                flush.assert_called_once_with(root, port)
                self.assertFalse(pin.exists())

    def test_failed_delete_keeps_active_program_pins_and_validation_cache(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            pin = handlers.port_handler_dir(root, "udp", 19053)
            pin.mkdir(parents=True)
            (pin / "prog").touch()
            with mock.patch.object(handlers, "prog_array_delete", return_value=False), \
                 mock.patch.object(handlers, "_pinned_u32_lookup", return_value=5265), \
                 mock.patch.object(handlers, "pinned_program_id", return_value=5265), \
                 mock.patch.object(handlers, "prog_array_update"), \
                 mock.patch.object(handlers, "flush_udp_validated_for_port") as flush:
                with self.assertRaisesRegex(RuntimeError, "previous generation restored"):
                    handlers.cleanup_existing_port_handler(root, "udp", 19053)
            flush.assert_not_called()
            self.assertTrue((pin / "prog").exists())

    def test_already_absent_entry_still_cleans_unused_pins(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            pin = handlers.port_handler_dir(root, "tcp", 65535)
            pin.mkdir(parents=True)
            (pin / "prog").touch()
            with mock.patch.object(handlers, "prog_array_delete", return_value=False), \
                 mock.patch.object(handlers, "_pinned_u32_lookup", return_value=None), \
                 mock.patch.object(handlers, "flush_udp_validated_for_port") as flush:
                handlers.cleanup_existing_port_handler(root, "tcp", 65535)
            flush.assert_not_called()
            self.assertFalse(pin.exists())
