import subprocess
import tempfile
import unittest
import json
from io import StringIO
from pathlib import Path
from unittest import mock

import pytest

import auto_xdp.admin.main as admin_main
import auto_xdp.admin.detect as admin_detect
import auto_xdp.admin.runtime as admin_runtime
import auto_xdp.admin_cli as admin_cli
from auto_xdp import approvals
from auto_xdp.state import DesiredState, ExposureDecision, ObservedState, RuntimeEndpoint


pytestmark = pytest.mark.component


class AdminCliTests(unittest.TestCase):
    def test_approval_store_supports_persistent_axdp_path(self):
        with mock.patch.dict(
            "os.environ", {"AUTO_XDP_APPROVAL_STORE": "/etc/auto_xdp/approvals.json"}
        ):
            self.assertEqual(
                approvals.store_path("/run/auto_xdp"),
                Path("/etc/auto_xdp/approvals.json"),
            )

    def test_xdp_detection_preserves_offload_mode(self):
        with mock.patch.object(
            admin_detect.subprocess,
            "check_output",
            return_value="2: eth0: <UP> xdpoffload prog/xdp id 77",
        ):
            self.assertEqual(admin_detect.iface_xdp_state("eth0"), "offload")

    def test_allow_and_deny_service_shortcuts_update_policy_and_audit(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            config_path = root / "config.toml"
            run_dir = root / "run"
            config_path.write_text("[zones.public]\ninterfaces = []\n[policy]\nmode = \"audit\"\n")

            with mock.patch.object(admin_cli.os, "geteuid", return_value=0), \
                 mock.patch.object(approvals, "reload_daemon"):
                self.assertEqual(admin_cli.main([
                    "--config", str(config_path), "--run-state-dir", str(run_dir),
                    "allow", "paper.service", "tcp/25565", "--profile", "minecraft",
                ]), 0)
                self.assertEqual(admin_cli.main([
                    "--config", str(config_path), "--run-state-dir", str(run_dir),
                    "deny", "paper.service", "tcp/25565",
                ]), 0)

            config = config_path.read_text()
            self.assertIn('systemd_unit = "paper.service"', config)
            self.assertIn('profile = "minecraft"', config)
            self.assertIn("ports = []", config)
            state = json.loads((run_dir / "approval_requests.json").read_text())
            self.assertEqual(
                [item["action"] for item in state["history"]],
                ["request", "approve", "deny"],
            )

    def test_allow_container_shortcut_accepts_tcp_or_udp_endpoint(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            config_path = root / "config.toml"
            run_dir = root / "run"
            config_path.write_text("[zones.public]\ninterfaces = []\n[policy]\nmode = \"audit\"\n")

            with mock.patch.object(admin_cli.os, "geteuid", return_value=0), \
                 mock.patch.object(approvals, "reload_daemon"):
                self.assertEqual(admin_cli.main([
                    "--config", str(config_path), "--run-state-dir", str(run_dir),
                    "allow", "--subject", "docker:a833cfc68335", "udp/19132",
                ]), 0)

            config = config_path.read_text()
            self.assertIn('container_runtime = "docker"', config)
            self.assertIn('container_id = "a833cfc68335"', config)
            self.assertIn("ports = [19132]", config)

    def test_admin_parser_reports_axdp_program_name(self):
        self.assertEqual(admin_cli.build_parser().prog, "axdp")

    def test_policy_mode_round_trip(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "config.toml"
            config_path.write_text("[firewall]\nbogon_filter = false\n[policy]\nmode = \"audit\"\n")

            with mock.patch.object(admin_cli.os, "geteuid", return_value=0):
                self.assertEqual(
                    admin_cli.main(["--config", str(config_path), "policy", "mode", "enforce"]),
                    0,
                )
            self.assertIn('mode = "enforce"', config_path.read_text())
            self.assertIn("bogon_filter = false", config_path.read_text())

    def test_deactivate_runtime_detaches_only_owned_xdp_and_removes_pins(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            env_config = root / "auto_xdp.env"
            pin_dir = root / "sys" / "fs" / "bpf" / "xdp_fw"
            run_dir = root / "run"
            pin_dir.mkdir(parents=True)
            run_dir.mkdir()
            (pin_dir / "prog").write_text("")
            env_config.write_text('IFACES="eth0"\n')
            attached = {"eth0": 77}

            def run_text(command):
                if command[:4] == ["ip", "link", "set", "dev"]:
                    attached[command[4]] = None
                return subprocess.CompletedProcess(command, 0, "", "")

            context = admin_runtime.RuntimeContext(env_config, pin_dir, run_dir, "inet", "auto_xdp")
            with mock.patch.object(admin_runtime, "_pinned_xdp_program_id", return_value=77), \
                 mock.patch.object(admin_runtime, "_iface_xdp_program_id", side_effect=lambda iface: attached[iface]), \
                 mock.patch.object(admin_runtime, "_iface_xdp_state", return_value="native"), \
                 mock.patch.object(admin_runtime, "_all_interface_names", return_value=[]), \
                 mock.patch.object(admin_runtime, "_command_exists", return_value=False), \
                 mock.patch.object(admin_runtime, "_run_text", side_effect=run_text):
                messages = admin_runtime.deactivate_runtime(context)

            self.assertFalse(pin_dir.exists())
            self.assertIn("detached Auto XDP from eth0", messages)

    def test_deactivate_runtime_includes_previously_managed_interfaces(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            env_config = root / "auto_xdp.env"
            pin_dir = root / "sys" / "fs" / "bpf" / "xdp_fw"
            run_dir = root / "run"
            pin_dir.mkdir(parents=True)
            run_dir.mkdir()
            (pin_dir / "prog").write_text("")
            env_config.write_text('IFACES="eth0"\n')
            attached = {"eth0": None, "eth1": 77}

            def run_text(command):
                if command[:4] == ["ip", "link", "set", "dev"]:
                    attached[command[4]] = None
                return subprocess.CompletedProcess(command, 0, "", "")

            context = admin_runtime.RuntimeContext(
                env_config, pin_dir, run_dir, "inet", "auto_xdp"
            )
            with mock.patch.object(admin_runtime, "_pinned_xdp_program_id", return_value=77), \
                 mock.patch.object(
                     admin_runtime,
                     "_iface_xdp_program_id",
                     side_effect=lambda iface: attached[iface],
                 ), \
                 mock.patch.object(admin_runtime, "_iface_xdp_state", return_value="native"), \
                 mock.patch.object(admin_runtime, "_all_interface_names", return_value=["eth0", "eth1"]), \
                 mock.patch.object(admin_runtime, "_command_exists", return_value=False), \
                 mock.patch.object(admin_runtime, "_run_text", side_effect=run_text):
                messages = admin_runtime.deactivate_runtime(context)

            self.assertIn("detached Auto XDP from eth1", messages)

    def test_deactivate_runtime_rejects_unsafe_pin_root(self):
        context = admin_runtime.RuntimeContext(
            Path("/tmp/absent-auto-xdp.env"), Path("/"), Path("/tmp/run"),
            "inet", "auto_xdp",
        )
        with self.assertRaisesRegex(RuntimeError, "unsafe BPF pin path"):
            admin_runtime.deactivate_runtime(context)

    def test_deactivate_runtime_refuses_foreign_xdp(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            env_config = root / "auto_xdp.env"
            pin_dir = root / "sys" / "fs" / "bpf" / "xdp_fw"
            pin_dir.mkdir(parents=True)
            (pin_dir / "prog").write_text("")
            env_config.write_text('IFACES="eth0"\n')
            context = admin_runtime.RuntimeContext(env_config, pin_dir, root / "run", "inet", "auto_xdp")

            with mock.patch.object(admin_runtime, "_pinned_xdp_program_id", return_value=77), \
                 mock.patch.object(admin_runtime, "_iface_xdp_program_id", return_value=88):
                with self.assertRaisesRegex(RuntimeError, "non-Auto-XDP"):
                    admin_runtime.deactivate_runtime(context)
            self.assertTrue(pin_dir.exists())

    def test_backend_report_treats_audit_without_dataplane_as_healthy(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            config_path = root / "config.toml"
            env_config = root / "auto_xdp.env"
            install_dir = root / "install"
            install_dir.mkdir()
            (install_dir / "release.json").write_text('{"release":"test-release"}\n')
            config_path.write_text('[policy]\nmode = "audit"\n')
            env_config.write_text(
                f'IFACES="eth0"\nTOML_CONFIG="{config_path}"\nINSTALL_DIR="{install_dir}"\n'
            )
            context = admin_runtime.RuntimeContext(
                env_config, root / "bpf", root / "run", "inet", "auto_xdp"
            )

            with mock.patch.object(admin_runtime, "detect_backend", side_effect=RuntimeError("none")), \
                 mock.patch.object(admin_runtime, "_iface_xdp_state", return_value="off"):
                report = admin_runtime.collect_backend_report(context)

            self.assertEqual(report.backend, "inactive")
            self.assertTrue(report.healthy)
            self.assertEqual(report.policy, "audit (data plane inactive)")

    def test_approval_workflow_updates_and_reverts_service_exposure(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            config_path = root / "config.toml"
            store_path = root / "run" / "approval_requests.json"
            config_path.write_text(
                "[zones.public]\ninterfaces = []\n"
                "[subjects.web.resolve]\nsystemd_unit = \"nginx.service\"\n"
            )

            request = approvals.create_request(
                store_path,
                config_path,
                subject="web",
                zone="public",
                protocol="tcp",
                ports=[443],
                reason="publish the website",
                actor="tester",
            )
            self.assertEqual(request["status"], "pending")
            with mock.patch.object(approvals, "reload_daemon"):
                approved = approvals.approve_request(store_path, config_path, request["id"], actor="approver")
            self.assertEqual(approved["status"], "approved")
            self.assertIn("ports = [443]", config_path.read_text())
            self.assertEqual(approvals.list_grants(config_path)[0]["ports"], [443])

            with mock.patch.object(approvals, "reload_daemon"):
                revoked = approvals.revoke_request(store_path, config_path, request["id"], actor="approver")
            self.assertEqual(revoked["status"], "revoked")
            self.assertIn("ports = []", config_path.read_text())
            state = json.loads(store_path.read_text())
            self.assertEqual(state["revision"], 3)
            self.assertEqual([item["action"] for item in state["history"]], ["request", "approve", "revoke"])

    def test_approval_new_subject_requires_runtime_identity(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            config_path = root / "config.toml"
            config_path.write_text("[zones.public]\ninterfaces = []\n")
            with self.assertRaisesRegex(ValueError, "systemd-unit or --process-name"):
                approvals.create_request(
                    root / "approval.json",
                    config_path,
                    subject="web",
                    zone="public",
                    protocol="tcp",
                    ports=[443],
                    reason="missing resolver",
                )

    def test_approval_rejects_resolver_owned_by_another_subject(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            config_path = root / "config.toml"
            config_path.write_text(
                "[zones.public]\ninterfaces = []\n"
                "[subjects.web.resolve]\nsystemd_unit = \"nginx.service\"\n"
                "[subjects.web.exposure.public.tcp]\nports = [80]\n"
            )

            with self.assertRaisesRegex(ValueError, "resolver already belongs to subject web"):
                approvals.create_request(
                    root / "approval.json",
                    config_path,
                    subject="website",
                    zone="public",
                    protocol="tcp",
                    ports=[443],
                    reason="duplicate resolver",
                    systemd_unit="nginx.service",
                )

    def test_approval_commands_are_root_only(self):
        parser = admin_cli.build_parser()
        self.assertEqual(parser.parse_args(["--config", "/tmp/c.toml", "approval", "list"]).command, "approval")
        with mock.patch.object(admin_cli.os, "geteuid", return_value=1000), mock.patch("sys.stderr", new=StringIO()):
            self.assertEqual(admin_cli.main(["--config", "/tmp/c.toml", "approval", "list"]), 77)

    def test_exposure_and_explain_render_policy_decisions(self):
        endpoint = RuntimeEndpoint(
            "tcp", "0.0.0.0", 443, "wildcard", "public", "nginx.service", "exact", "systemd-cgroup"
        )
        decision = ExposureDecision(endpoint, "allow", "matched explicit exposure grant", "website", "web")
        args = mock.Mock(config="/tmp/config.toml", iface="", bpf_pin_dir="/tmp/bpf", run_state_dir="/tmp/run", nft_family="inet", nft_table="auto_xdp", endpoint="tcp/443")
        with mock.patch.object(admin_cli, "_policy_snapshot", return_value=(ObservedState(), DesiredState(exposure_decisions=[decision]))), \
             mock.patch.object(admin_cli, "_active_backend_name", return_value="xdp"), \
             mock.patch("sys.stdout", new=StringIO()) as output:
            self.assertEqual(admin_cli._cmd_exposure(args), 0)
            exposure = output.getvalue()
        self.assertIn("PUBLIC", exposure)
        self.assertIn("443/tcp", exposure)
        self.assertIn("grant: website.public_https", exposure)
        self.assertIn("status: allowed", exposure)

        with mock.patch.object(admin_cli, "_policy_snapshot", return_value=(ObservedState(), DesiredState(exposure_decisions=[decision]))), \
             mock.patch.object(admin_cli, "_active_backend_name", return_value="xdp"), \
             mock.patch("sys.stdout", new=StringIO()) as output:
            self.assertEqual(admin_cli._cmd_explain(args), 0)
            explanation = output.getvalue()
        self.assertIn("ALLOW", explanation)
        self.assertIn("0.0.0.0:443", explanation)
        self.assertIn("nginx.service", explanation)
        self.assertIn("public/tcp/443", explanation)
        self.assertIn("XDP", explanation)

    def test_exposure_shows_owner_for_blocked_endpoint(self):
        endpoint = RuntimeEndpoint(
            "tcp", "0.0.0.0", 25565, "wildcard", "public",
            "paper.service", "exact", "systemd-cgroup",
        )
        decision = ExposureDecision(
            endpoint, "block", "no explicit exposure grant", "", "minecraft"
        )
        args = mock.Mock(
            config="/tmp/config.toml", iface="", bpf_pin_dir="/tmp/bpf",
            run_state_dir="/tmp/run", nft_family="inet", nft_table="auto_xdp",
        )
        with mock.patch.object(
            admin_cli,
            "_policy_snapshot",
            return_value=(ObservedState(), DesiredState(exposure_decisions=[decision])),
        ), mock.patch.object(admin_cli, "_active_backend_name", return_value="inactive"), \
             mock.patch("sys.stdout", new=StringIO()) as output:
            self.assertEqual(admin_cli._cmd_exposure(args), 0)

        self.assertIn("owner: paper.service", output.getvalue())
        self.assertIn("status: blocked", output.getvalue())

    def test_explain_missing_endpoint_is_blocked(self):
        args = mock.Mock(config="/tmp/config.toml", iface="", bpf_pin_dir="/tmp/bpf", run_state_dir="/tmp/run", nft_family="inet", nft_table="auto_xdp", endpoint="tcp/443")
        with mock.patch.object(admin_cli, "_policy_snapshot", return_value=(ObservedState(), DesiredState())), \
             mock.patch.object(admin_cli, "_active_backend_name", return_value="nftables"), \
             mock.patch("sys.stdout", new=StringIO()) as output:
            self.assertEqual(admin_cli._cmd_explain(args), 0)
        self.assertIn("BLOCK", output.getvalue())
        self.assertIn("not listening", output.getvalue())

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

    def test_profile_handler_load_reuses_shared_maps_and_profile_array(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            bpf_pin_dir = root / "bpf"
            bpf_pin_dir.mkdir()
            for name in (
                "tcp_profile_handlers",
                "slot_ctx_map",
                "profile_ctx_map",
                "mc_l7_pending",
                "pkt_counters",
                "byte_counters",
            ):
                (bpf_pin_dir / name).touch()
            handler = root / "minecraft_handler.o"
            handler.touch()

            with mock.patch.object(admin_cli, "_run_checked") as run, \
                 mock.patch.object(admin_cli, "_transactional_dir_prog_swap") as swap:
                rc = admin_cli.main(
                    [
                        "--config",
                        str(root / "config.toml"),
                        "--bpf-pin-dir",
                        str(bpf_pin_dir),
                        "profile-handler",
                        "load",
                        "3",
                        str(handler),
                    ]
                )

            self.assertEqual(rc, 0)
            command = run.call_args.args[0]
            for name in (
                "slot_ctx_map", "profile_ctx_map", "mc_l7_pending",
                "pkt_counters", "byte_counters",
            ):
                self.assertIn(name, command)
            self.assertEqual(swap.call_args.args[0], bpf_pin_dir / "tcp_profile_handlers")
            self.assertEqual(swap.call_args.args[1], 3)
            self.assertEqual(
                swap.call_args.args[3],
                bpf_pin_dir / "profile_handlers" / "tcp" / "3",
            )

    def test_profile_handler_unload_retains_pin_when_array_delete_fails(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            bpf_pin_dir = Path(tmpdir) / "bpf"
            handler_map = bpf_pin_dir / "tcp_profile_handlers"
            live_pin = bpf_pin_dir / "profile_handlers" / "tcp" / "3" / "prog"
            live_pin.parent.mkdir(parents=True)
            live_pin.touch()
            handler_map.touch()

            with mock.patch.object(admin_cli, "_pinned_program_id", return_value=42), \
                 mock.patch.object(admin_cli, "_prog_array_entry_id", return_value=42), \
                 mock.patch.object(admin_cli, "_prog_array_delete", return_value=False):
                rc = admin_cli.main(
                    [
                        "--config",
                        str(Path(tmpdir) / "config.toml"),
                        "--bpf-pin-dir",
                        str(bpf_pin_dir),
                        "profile-handler",
                        "unload",
                        "3",
                    ]
                )

            self.assertEqual(rc, 1)
            self.assertTrue(live_pin.exists())

    def test_slot_list_excludes_port_handler_candidates(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            config_path = root / "config.toml"
            bpf_pin_dir = root / "bpf"
            handlers_dir = root / "handlers"
            handlers_dir.mkdir()
            bpf_pin_dir.mkdir()
            (bpf_pin_dir / "proto_handlers").touch()

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
            builtin_handlers_dir = root / "install" / "handlers"
            handlers_dir.mkdir()
            bpf_pin_dir.mkdir()
            builtin_handlers_dir.mkdir(parents=True)
            (handlers_dir / "gre_handler.o").touch()
            (handlers_dir / "custom_47_demo.o").touch()
            (builtin_handlers_dir / "minecraft_handler.c").write_text("hblk4", encoding="ascii")
            (builtin_handlers_dir / "minecraft_handler.o").touch()
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
                        "--install-dir",
                        str(root / "install"),
                        "port-handler",
                        "list",
                    ]
                )

            self.assertEqual(rc, 0)
            output = stdout.getvalue()
            self.assertIn("Available local port handler files:", output)
            self.assertNotIn("minecraft_handler", output)
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
            (bpf_pin_dir / "pkt_counters").touch()

            (bin_dir / "ip").write_text(
                "#!/bin/sh\n"
                "case \"$*\" in\n"
                "  *'-j -d'*) printf '%s\\n' '[{\"ifname\":\"eth9\",\"xdp\":{\"prog_id\":77}}]' ;;\n"
                "  *) printf '%s\\n' '2: eth9: <BROADCAST> mtu 1500 xdp' ;;\n"
                "esac\n"
            )
            (bin_dir / "bpftool").write_text(
                "#!/bin/sh\nprintf '%s\\n' '[]'\n"
            )
            for name in ("ip", "bpftool"):
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
