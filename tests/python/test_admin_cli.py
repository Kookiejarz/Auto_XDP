import subprocess
import tempfile
import unittest
from io import StringIO
from pathlib import Path
from unittest import mock

import pytest

import auto_xdp.admin.main as admin_main
import auto_xdp.admin_cli as admin_cli


pytestmark = pytest.mark.component


class AdminCliTests(unittest.TestCase):
    def test_human_format_helpers_render_expected_output(self):
        # Migrated from the removed bash helpers (human_bytes / human_bps /
        # format_rate) after axdp delegated stats formatting to admin_cli.
        self.assertEqual(admin_cli._human_bytes(1536), "1.50 KiB")
        self.assertEqual(admin_cli._human_bytes(-1), "-")
        self.assertEqual(admin_cli._human_bytes(512), "512 B")
        self.assertEqual(admin_cli._human_bps(1500), "1.50 Kbps")
        self.assertEqual(admin_cli._human_bps(-1), "-")
        self.assertEqual(admin_cli._format_rate(10, 125, 1), "10.00 pps / 1.00 Kbps")
        self.assertEqual(admin_cli._format_rate(-1, 125, 1), "-")

    def test_stats_parser_sets_expected_flags(self):
        parser = admin_cli.build_parser()
        args = parser.parse_args(
            ["--config", "/tmp/c.toml", "stats", "--watch", "--rates", "--interval", "5"]
        )
        self.assertTrue(args.watch)
        self.assertTrue(args.rates)
        self.assertEqual(args.interval, 5.0)

    def test_ports_parser_sets_expected_flags(self):
        parser = admin_cli.build_parser()
        args = parser.parse_args(
            ["--config", "/tmp/c.toml", "ports", "--watch", "--interval", "7"]
        )
        self.assertTrue(args.watch)
        self.assertEqual(args.interval, 7.0)

    def test_config_init_writes_default_template(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "config.toml"

            rc = admin_cli.main(["--config", str(config_path), "config", "init"])

            self.assertEqual(rc, 0)
            self.assertTrue(config_path.exists())
            text = config_path.read_text()
            expected = (Path(admin_cli.__file__).with_name("default_config.toml")).read_text()
            self.assertEqual(text, expected)
            self.assertIn("[daemon]", text)
            self.assertIn("[slots]", text)
            self.assertIn('default_action = "drop"', text)

    def test_trust_add_normalizes_cidr(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "config.toml"
            config_path.write_text("[trusted_ips]\n")

            rc = admin_cli.main(
                [
                    "--config",
                    str(config_path),
                    "trust",
                    "add",
                    "203.0.113.9",
                    "office",
                ]
            )

            self.assertEqual(rc, 0)
            text = config_path.read_text()
            self.assertIn('"203.0.113.9/32" = "office"', text)

    def test_slot_load_builtin_sctp_reuses_shared_maps_and_updates_config(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            config_path = root / "config.toml"
            bpf_pin_dir = root / "bpf"
            handlers_dir = root / "handlers"
            (bpf_pin_dir / "handlers").mkdir(parents=True)
            handlers_dir.mkdir()

            for path in (
                bpf_pin_dir / "slot_ctx_map",
                bpf_pin_dir / "sctp_whitelist",
                bpf_pin_dir / "sctp_conntrack",
                bpf_pin_dir / "proto_handlers",
            ):
                path.touch()
            (handlers_dir / "sctp_handler.o").touch()

            calls: list[list[str]] = []

            def fake_run(cmd, capture_output=False, text=False):
                calls.append(list(cmd))
                return subprocess.CompletedProcess(cmd, 0, "", "")

            with mock.patch("auto_xdp.admin_cli.subprocess.run", side_effect=fake_run), \
                 mock.patch("auto_xdp.admin_cli._transactional_file_prog_swap") as swap:
                rc = admin_cli.main(
                    [
                        "--config",
                        str(config_path),
                        "--bpf-pin-dir",
                        str(bpf_pin_dir),
                        "--install-dir",
                        str(root),
                        "--handlers-dir",
                        str(handlers_dir),
                        "slot",
                        "load",
                        "sctp",
                    ]
                )

            self.assertEqual(rc, 0)
            self.assertEqual(len(calls), 1)
            self.assertIn("slot_ctx_map", calls[0])
            self.assertIn("sctp_whitelist", calls[0])
            self.assertIn("sctp_conntrack", calls[0])
            swap.assert_called_once()
            self.assertEqual(swap.call_args.args[0], bpf_pin_dir / "proto_handlers")
            self.assertEqual(swap.call_args.args[1], 132)
            text = config_path.read_text()
            self.assertIn('[slots]', text)
            self.assertIn('enabled = ["sctp"]', text)

    def test_file_handler_swap_keeps_old_pin_until_verified_commit(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            map_path = root / "proto_handlers"
            live_pin = root / "proto_47"
            candidate_pin = root / "proto_47_next"
            map_path.touch()
            live_pin.write_text("old")
            candidate_pin.write_text("new")
            active = {47: 1}
            operations: list[str] = []

            def prog_id(path: Path) -> int:
                return 1 if path.read_text() == "old" else 2

            def update(_map: Path, key: int, pin: Path) -> None:
                operations.append(f"update:{pin.read_text()}")
                active[key] = prog_id(pin)

            with mock.patch.object(admin_cli, "_pinned_program_id", side_effect=prog_id), \
                 mock.patch.object(admin_cli, "_prog_array_entry_id", side_effect=lambda _m, key: active.get(key)), \
                 mock.patch.object(admin_cli, "_prog_array_update", side_effect=update):
                admin_cli._transactional_file_prog_swap(map_path, 47, candidate_pin, live_pin)

            self.assertEqual(active[47], 2)
            self.assertEqual(live_pin.read_text(), "new")
            self.assertFalse(candidate_pin.exists())
            self.assertEqual(operations, ["update:new"])
            self.assertFalse(list(root.glob("proto_47_rollback_*")))

    def test_file_handler_swap_restores_old_program_when_verification_fails(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            map_path = root / "proto_handlers"
            live_pin = root / "proto_50"
            candidate_pin = root / "proto_50_next"
            map_path.touch()
            live_pin.write_text("old")
            candidate_pin.write_text("new")
            active = {50: 1}
            updates: list[int] = []

            def prog_id(path: Path) -> int:
                return 1 if path.read_text() == "old" else 2

            def update(_map: Path, key: int, pin: Path) -> None:
                active[key] = prog_id(pin)
                updates.append(active[key])

            verifies = [RuntimeError("candidate mismatch"), None]
            with mock.patch.object(admin_cli, "_pinned_program_id", side_effect=prog_id), \
                 mock.patch.object(admin_cli, "_prog_array_entry_id", side_effect=lambda _m, key: active.get(key)), \
                 mock.patch.object(admin_cli, "_prog_array_update", side_effect=update), \
                 mock.patch.object(admin_cli, "_verify_prog_array_entry", side_effect=verifies):
                with self.assertRaisesRegex(RuntimeError, "previous program restored"):
                    admin_cli._transactional_file_prog_swap(map_path, 50, candidate_pin, live_pin)

            self.assertEqual(active[50], 1)
            self.assertEqual(updates, [2, 1])
            self.assertEqual(live_pin.read_text(), "old")
            self.assertFalse(candidate_pin.exists())

    def test_directory_handler_swap_commits_candidate_then_removes_old_generation(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            map_path = root / "tcp_port_handlers"
            live_dir = root / "443"
            candidate_dir = root / "443_next"
            map_path.touch()
            live_dir.mkdir()
            candidate_dir.mkdir()
            (live_dir / "prog").write_text("old")
            (live_dir / "private_map").write_text("old-map")
            (candidate_dir / "prog").write_text("new")
            (candidate_dir / "private_map").write_text("new-map")
            active = {443: 10}

            def prog_id(path: Path) -> int:
                return 10 if path.read_text() == "old" else 20

            def update(_map: Path, key: int, pin: Path) -> None:
                active[key] = prog_id(pin)

            with mock.patch.object(admin_cli, "_pinned_program_id", side_effect=prog_id), \
                 mock.patch.object(admin_cli, "_prog_array_entry_id", side_effect=lambda _m, key: active.get(key)), \
                 mock.patch.object(admin_cli, "_prog_array_update", side_effect=update):
                admin_cli._transactional_dir_prog_swap(map_path, 443, candidate_dir, live_dir)

            self.assertEqual(active[443], 20)
            self.assertEqual((live_dir / "prog").read_text(), "new")
            self.assertEqual((live_dir / "private_map").read_text(), "new-map")
            self.assertFalse(candidate_dir.exists())
            self.assertFalse(list(root.glob("443_rollback_*")))

    def test_slot_list_excludes_port_handler_candidates(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            config_path = root / "config.toml"
            bpf_pin_dir = root / "bpf"
            handlers_dir = root / "handlers"
            handlers_dir.mkdir()
            bpf_pin_dir.mkdir()
            (bpf_pin_dir / "proto_handlers").touch()
            (handlers_dir / "minecraft_handler.c").write_text(
                'struct { int x; } tcp_ct4 SEC(".maps");\nSEC("xdp/minecraft") int x(void *ctx) { return 0; }\n'
            )
            (handlers_dir / "minecraft_handler.o").touch()

            stdout = StringIO()
            with mock.patch("sys.stdout", stdout):
                rc = admin_cli.main(
                    [
                        "--config",
                        str(config_path),
                        "--bpf-pin-dir",
                        str(bpf_pin_dir),
                        "--handlers-dir",
                        str(handlers_dir),
                        "slot",
                        "list",
                    ]
                )

            self.assertEqual(rc, 0)
            output = stdout.getvalue()
            self.assertIn("Available handlers:", output)
            self.assertNotIn("minecraft_handler", output)
            self.assertNotIn("minecraft", output)

    def test_port_handler_list_shows_available_local_handler_files(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            config_path = root / "config.toml"
            bpf_pin_dir = root / "bpf"
            handlers_dir = root / "handlers"
            handlers_dir.mkdir()
            bpf_pin_dir.mkdir()
            (handlers_dir / "gre_handler.o").touch()
            (handlers_dir / "custom_47_demo.o").touch()
            (handlers_dir / "minecraft_handler.c").write_text(
                'struct { int x; } tcp_ct4 SEC(".maps");\nSEC("xdp/minecraft") int x(void *ctx) { return 0; }\n'
            )
            (handlers_dir / "minecraft_handler.o").touch()

            stdout = StringIO()
            with mock.patch("sys.stdout", stdout):
                rc = admin_cli.main(
                    [
                        "--config",
                        str(config_path),
                        "--bpf-pin-dir",
                        str(bpf_pin_dir),
                        "--handlers-dir",
                        str(handlers_dir),
                        "port-handler",
                        "list",
                    ]
                )

            self.assertEqual(rc, 0)
            output = stdout.getvalue()
            self.assertIn("Available local port handler files:", output)
            self.assertIn("minecraft_handler", output)
            self.assertIn(str(handlers_dir / "minecraft_handler.o"), output)
            self.assertNotIn("custom_47_demo", output)
            self.assertNotIn(str(handlers_dir / "gre_handler.o"), output)

    def test_display_proc_name_resolves_systemd_socket_unit(self):
        with mock.patch("auto_xdp.admin_cli._build_systemd_socket_map", return_value={50168: "ssh"}):
            name, systemd_map = admin_cli._display_proc_name("systemd", 50168, None)

        self.assertEqual(name, "ssh")
        self.assertEqual(systemd_map, {50168: "ssh"})

    def test_display_proc_name_keeps_systemd_when_socket_unit_unknown(self):
        with mock.patch("auto_xdp.admin_cli._build_systemd_socket_map", return_value={}):
            name, systemd_map = admin_cli._display_proc_name("systemd", 50168, None)

        self.assertEqual(name, "systemd")
        self.assertEqual(systemd_map, {})

    def test_admin_main_backend_json_matches_backend_snapshot(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            env_config = root / "auto_xdp.env"
            run_state_dir = root / "run"
            bpf_pin_dir = root / "bpf"
            bin_dir = root / "bin"
            run_state_dir.mkdir()
            bpf_pin_dir.mkdir()
            bin_dir.mkdir()

            runtime_state = root / "runtime-state.json"
            machine_state = root / "machine-state.json"

            env_config.write_text(
                'IFACES="eth9"\nPREFERRED_BACKEND="auto"\n'
                f'RUNTIME_STATE="{runtime_state}"\nMACHINE_STATE="{machine_state}"\n'
            )
            runtime_state.write_text(
                '{"generation":"verified","healthy":true,"xdp_mode":"native",'
                '"interfaces":{"eth9":{"program_id":77}}}'
            )
            machine_state.write_text('{"excluded":{"lo":"loopback"}}')
            (run_state_dir / "backend").write_text("xdp\n")
            (run_state_dir / "xdp_mode").write_text("native\n")
            for path in (
                bpf_pin_dir / "pkt_counters",
                bpf_pin_dir / "tcp_ct4",
                bpf_pin_dir / "tcp_ct6",
                bpf_pin_dir / "udp_ct4",
                bpf_pin_dir / "udp_ct6",
            ):
                path.touch()

            (bin_dir / "ip").write_text(
                "#!/bin/sh\n"
                "case \"$*\" in\n"
                "  *'-j -d'*) printf '%s\\n' '[{\"ifname\":\"eth9\",\"xdp\":{\"prog_id\":77}}]' ;;\n"
                "  *) printf '%s\\n' '2: eth9: <BROADCAST> mtu 1500 xdp' ;;\n"
                "esac\n"
            )
            (bin_dir / "tc").write_text(
                "#!/bin/sh\n"
                "if [ \"$1\" = \"filter\" ]; then\n"
                "  printf '%s\\n' 'filter protocol all pref 49152 bpf chain 0'\n"
                "fi\n"
            )
            (bin_dir / "bpftool").write_text(
                "#!/bin/sh\n"
                "case \"$*\" in\n"
                "  *\"tcp_ct4\"*) printf '%s\\n' '[{\"key\":[1]}]' ;;\n"
                "  *\"tcp_ct6\"*) printf '%s\\n' '[{\"key\":[1]}]' ;;\n"
                "  *\"udp_ct4\"*) printf '%s\\n' '[{\"key\":[1]}]' ;;\n"
                "  *\"udp_ct6\"*) printf '%s\\n' '[]' ;;\n"
                "  *) printf '%s\\n' '[]' ;;\n"
                "esac\n"
            )
            for name in ("ip", "tc", "bpftool"):
                (bin_dir / name).chmod(0o755)

            with mock.patch.dict("os.environ", {"PATH": f"{bin_dir}:{Path('/usr/bin')}:{Path('/bin')}"}, clear=False), \
                 mock.patch("sys.stdout.write") as write_mock:
                rc = admin_main.main(
                    [
                        "--env-config",
                        str(env_config),
                        "--bpf-pin-dir",
                        str(bpf_pin_dir),
                        "--run-state-dir",
                        str(run_state_dir),
                        "backend",
                        "--json",
                    ]
                )

            self.assertEqual(rc, 0)
            output = "".join(call.args[0] for call in write_mock.call_args_list).strip()
            self.assertIn('"backend": "xdp"', output)
            self.assertIn('"interfaces": ["eth9"]', output)
            self.assertIn('"conntrack": {"tcp": 2, "udp": 1}', output)
            self.assertIn('"generation": "verified"', output)
            self.assertIn('"healthy": true', output)
            self.assertIn('"excluded_interfaces": {"lo": "loopback"}', output)

    def test_exclude_port_commands_round_trip(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "config.toml"
            config_path.write_text("[discovery]\nexclude_ports = []\n")

            rc = admin_cli.main(
                ["--config", str(config_path), "exclude", "port", "add", "8080", "9090"]
            )
            self.assertEqual(rc, 0)
            self.assertIn("exclude_ports = [8080, 9090]", config_path.read_text())

            rc = admin_cli.main(
                ["--config", str(config_path), "exclude", "port", "del", "8080"]
            )
            self.assertEqual(rc, 0)
            self.assertIn("exclude_ports = [9090]", config_path.read_text())


if __name__ == "__main__":
    unittest.main()
