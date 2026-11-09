"""Contracts for discovery, durable installation and real activation routing."""
import json
import os
import subprocess
import sys
from pathlib import Path
from unittest import mock

import pytest

from auto_xdp.admin import cli, config_file, handler_catalog as catalog, handlers
from auto_xdp.tui.handlers import HandlerCache, collect_handlers


@pytest.fixture
def context(tmp_path, monkeypatch):
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.setattr(os, "chown", lambda *args: None)
    install = tmp_path / "release"
    (install / "handlers").mkdir(parents=True)
    root = tmp_path / "bpffs"
    root.mkdir()
    return catalog.Context(tmp_path / "config.toml", install, tmp_path / "custom", root, tmp_path / "run")


@pytest.fixture
def compiler(monkeypatch):
    def compile_source(source, proto, output, **kwargs):
        output.mkdir(parents=True, exist_ok=True)
        obj = output / "test.o"
        obj.write_bytes(source.read_bytes() + json.dumps(kwargs.get("defines", {})).encode())
        return obj
    compile_mock = mock.Mock(side_effect=compile_source)
    monkeypatch.setattr(handlers, "compile_handler_source", compile_mock)
    monkeypatch.setattr(handlers, "handler_object_programs", lambda path: ("ingress", None))
    return compile_mock


def write_manifest(path, **overrides):
    data = dict(version=1, id="custom", kind="udp", target=30120,
                fields=[dict(name="limit", label="Packet limit", type="int", define="PACKET_LIMIT", default=10, minimum=1, maximum=100)])
    data.update(overrides)
    path.write_text(json.dumps(data))


def test_icmp_catalog_has_one_managed_entry_and_hides_native_dependency(context):
    sdk = context.install_dir / "handlers"
    for name in ("icmp_handler.c", "icmp_handler.o", "axdp_icmp.c", "axdp_icmp.o", "axdp_icmp.mod.c", "axdp_icmp.mod.o"):
        (sdk / name).touch()
    modules = catalog.discover(context, {})
    icmp = [module for module in modules if module.id == "icmp"]
    assert len(icmp) == 1 and icmp[0].kernel_dependencies == ("axdp_icmp",)
    assert [field.name for field in catalog.fields_for(icmp[0])] == ["enabled"]
    assert not any("axdp_icmp" in module.path for module in modules)
    assert not any(module.id != "icmp" and "icmp_handler" in module.path for module in modules)


@pytest.mark.parametrize("enabled", [False, True])
def test_icmp_apply_uses_managed_runtime_and_both_family_readback(context, monkeypatch, enabled):
    context.config.write_text('[policy]\nmode="enforce"\n')
    module = next(item for item in catalog.discover(context) if item.id == "icmp")
    refresh = mock.Mock(return_value={})
    verify = mock.Mock(return_value=42 if enabled else None)
    monkeypatch.setattr(catalog, "_refresh_managed_runtime", refresh)
    monkeypatch.setattr(catalog.module_runtime, "verify_icmp", verify)
    result = catalog.configure(context, module, {"enabled": enabled}, apply=True)
    assert config_file.load_toml(context.config)["modules"]["icmp"]["enabled"] is enabled
    refresh.assert_called_once_with(context)
    verify.assert_called_once_with(context.bpf_pin_dir, enabled=enabled)
    assert ("IPv4 and IPv6" if enabled else "disabled") in result


def test_icmp_audit_apply_saves_preference_without_claiming_protection(context, monkeypatch):
    context.config.write_text('[policy]\nmode="audit"\n')
    module = next(item for item in catalog.discover(context) if item.id == "icmp")
    monkeypatch.setattr(catalog, "_refresh_managed_runtime", lambda context: {})
    monkeypatch.setattr(catalog.module_runtime, "verify_icmp", lambda *args, **kwargs: pytest.fail("audit readback"))
    result = catalog.configure(context, module, {"enabled": True}, apply=True)
    assert "does not activate" in result
    assert config_file.load_toml(context.config)["modules"]["icmp"]["enabled"] is True


def test_discovery_lists_unloaded_builtins_bare_objects_sources_and_external_config(context):
    sdk = context.install_dir / "handlers"
    (sdk / "gre_handler.c").touch()
    (sdk / "gre_handler.o").touch()
    context.handlers_dir.mkdir()
    (context.handlers_dir / "unusual.o").touch()  # no source/filename heuristics
    (context.handlers_dir / "plain.c").write_text('SEC("xdp") int check(void *p) { return 2; }')
    (context.handlers_dir / "plain.o").touch()
    external = context.config.parent / "external.o"
    external.touch()
    modules = catalog.discover(context, {"port_handlers": {"tcp": {"8080": str(external)}}})
    assert {m.id for m in modules} >= {"gre", "esp", "sctp", "minecraft", "syncookie"}
    assert [Path(m.path).name for m in modules].count("gre_handler.o") == 1
    assert "gre_handler.c" not in [Path(m.path).name for m in modules]
    assert "plain.c" not in [Path(m.path).name for m in modules]
    assert {Path(m.path).name for m in modules} >= {"plain.o", "unusual.o", "external.o"}


def test_manifest_parameters_choose_source_and_reject_malformed_metadata(context):
    context.handlers_dir.mkdir()
    source = context.handlers_dir / "custom.c"
    source.touch()
    source.with_suffix(".o").touch()
    manifest = source.with_suffix(".handler.json")
    write_manifest(manifest)
    module = catalog.select(context, "custom")
    assert module.path == str(source.resolve())
    assert module.fields[0].name == "limit"
    write_manifest(manifest, fields=[dict(name="limit", type="string", default="1", define="LIMIT")])
    invalid = next(m for m in catalog.discover(context) if m.id == "custom")
    assert "int and bool" in invalid.error
    with pytest.raises(ValueError, match="int and bool"):
        catalog.select(context, "custom")


@pytest.mark.parametrize("field,value", [
    (catalog.Field("v", "v", "int", minimum=1), True),
    (catalog.Field("v", "v", "int", minimum=1), 1.5),
    (catalog.Field("v", "v", "number"), "nan"),
    (catalog.Field("v", "v", "number"), "inf"),
    (catalog.Field("v", "v", "int", maximum=10), "11"),
    (catalog.Field("v", "v", "bool"), "perhaps"),
    (catalog.Field("v", "v", choices=("a", "b")), "c"),
    (catalog.Field("v", "v", "json"), "[]"),
])
def test_invalid_parameter_values_fail_before_use(field, value):
    with pytest.raises(ValueError):
        field.parse(value)


def test_install_copies_nested_headers_and_compiles_declared_defaults(context, compiler):
    package = context.config.parent / "package"
    (package / "include").mkdir(parents=True)
    (package / "main.c").write_text('#include "include/options.h"\nint value = PACKET_LIMIT;')
    (package / "include/options.h").write_text("/* options */")
    write_manifest(package / "handler.json", entry="main.c")
    module = catalog.install(context, package)
    assert Path(module.path).read_text().startswith('#include "include/options.h"')
    assert (Path(module.path).parent / "include/options.h").is_file()
    assert compiler.call_args.kwargs["defines"] == {"PACKET_LIMIT": 10}
    assert not context.config.exists()  # installing is not activation
    assert catalog.select(context, module.id).path == module.path
    assert not list((context.handlers_dir / "catalog").glob(".install-*"))
    assert not list((context.handlers_dir / "builds").iterdir())
    with pytest.raises(ValueError, match="already installed"):
        catalog.install(context, package)


def test_install_does_not_require_a_binding_and_survives_source_removal(context, compiler):
    source = context.config.parent / "filter.c"
    source.write_text("int x;")
    module = catalog.install(context, source, kind="tcp")
    source.unlink()
    obj = catalog._prepare_object(context, module, {"enabled": True, "target": 8080})
    assert obj.exists()
    assert Path(module.path).is_file()


def test_install_failure_never_publishes_partial_package(context, compiler):
    source = context.config.parent / "bad.c"
    source.write_text("invalid C")
    compiler.side_effect = RuntimeError("compiler rejected source")
    with pytest.raises(RuntimeError, match="compiler rejected"):
        catalog.install(context, source)
    assert list((context.handlers_dir / "catalog").iterdir()) == []
    assert list((context.handlers_dir / "builds").iterdir()) == []


def test_failed_install_remains_discoverable_with_diagnostics_until_success(context, compiler):
    package = context.config.parent / "external-package"
    package.mkdir()
    source = package / "main.c"
    source.write_text("invalid C")
    write_manifest(package / "handler.json", entry="main.c")
    successful_compile = compiler.side_effect
    compiler.side_effect = RuntimeError("main.c:1:1: error: unknown type name\ninvalid C\n^")
    with pytest.raises(RuntimeError, match="unknown type name"):
        catalog.install(context, package)
    module = catalog.select(context, "custom")
    assert module.path == str(source)
    assert module.build_error.endswith("invalid C\n^")
    assert not module.error and module.fields[0].name == "limit"
    assert not context.config.exists()
    assert list((context.handlers_dir / "catalog").iterdir()) == []
    compiler.side_effect = successful_compile
    source.write_text("int x;")
    installed = catalog.install(context, package)
    assert catalog.select(context, "custom").path == installed.path
    assert not catalog.select(context, "custom").build_error
    assert not list((context.handlers_dir / ".diagnostics").glob("*.json"))


def test_failed_rebuild_preserves_live_binding_and_warning_survives_draft(context, compiler, capsys):
    source = context.config.parent / "custom.c"
    source.write_text("int x;")
    write_manifest(source.with_suffix(".handler.json"))
    module = catalog.install(context, source)
    successful_compile = compiler.side_effect
    with mock.patch.object(handlers, "handler_shared_maps", return_value=[]), \
            mock.patch.object(handlers, "load_handler_object") as activate:
        catalog.configure(context, module, {}, apply=True)
        original = context.config.read_bytes()
        activate.reset_mock()
        compiler.side_effect = RuntimeError("error: expected ';'\nint x\n     ^")
        with pytest.raises(RuntimeError, match="expected"):
            catalog.configure(context, module, {"limit": 50}, apply=True)
        assert context.config.read_bytes() == original
        activate.assert_not_called()
        warning = catalog.select(context, "custom")
        assert warning.build_error and not warning.error
        catalog.configure(context, warning, {"limit": 50})
        assert catalog.select(context, "custom").build_error == warning.build_error
        (context.bpf_pin_dir / "udp_port_handlers").touch()
        def query(*args):
            return [] if args[0] == "-f" else [{"key": 30120, "value": 42}]
        with mock.patch("auto_xdp.tui.handlers._query", side_effect=query):
            inventory = collect_handlers(str(context.bpf_pin_dir), config_file.load_toml(context.config),
                                         HandlerCache(), context=context)
            row = next(row for row in inventory.rows if row.module and row.module.id == "custom")
            assert row.state == "loaded" and row.program_id == 42 and row.module.build_error
            base = ["--config", str(context.config), "--handlers-dir", str(context.handlers_dir),
                    "--install-dir", str(context.install_dir), "--bpf-pin-dir", str(context.bpf_pin_dir)]
            assert cli.main([*base, "handler", "list", "--json"]) == 0
            output = json.loads(capsys.readouterr().out)
            assert next(item for item in output["modules"] if item["id"] == "custom")["build_error"] == warning.build_error
            assert cli.main([*base, "handler", "list"]) == 0
            assert "⚠ last build/check failed" in capsys.readouterr().out
        compiler.side_effect = successful_compile
        catalog.configure(context, warning, {}, apply=True)
        activate.assert_called_once()
        assert not catalog.select(context, "custom").build_error


def test_removed_failure_candidates_and_corrupt_diagnostic_records_do_not_break_discovery(context, compiler):
    source = context.config.parent / "missing.c"
    source.write_text("bad C")
    compiler.side_effect = RuntimeError("bad C")
    with pytest.raises(RuntimeError):
        catalog.install(context, source)
    source.unlink()
    (context.handlers_dir / ".diagnostics/broken.json").write_text("{")
    assert all(module.path != str(source) for module in catalog.discover(context))


def test_failed_install_candidate_can_be_applied_then_reconfigured(context, compiler):
    package = context.config.parent / "external-package"
    package.mkdir()
    (package / "main.c").write_text("bad C")
    write_manifest(package / "handler.json", entry="main.c")
    successful_compile = compiler.side_effect
    compiler.side_effect = RuntimeError("bad C")
    with pytest.raises(RuntimeError):
        catalog.install(context, package)
    compiler.side_effect = successful_compile
    with mock.patch.object(handlers, "handler_shared_maps", return_value=[]), \
            mock.patch.object(handlers, "load_handler_object"):
        catalog.configure(context, catalog.select(context, "custom"), {}, apply=True)
        module = catalog.select(context, "custom")
        assert not module.build_error and module.fields[0].name == "limit"
        catalog.configure(context, module, {"limit": 50}, apply=True)
        assert compiler.call_args.kwargs["defines"] == {"PACKET_LIMIT": 50}


def test_compiler_diagnostics_are_returned_to_caller_without_corrupting_tui(capsys):
    with pytest.raises(RuntimeError, match="source.c:7: error: expected expression"):
        handlers.run_checked([sys.executable, "-c",
                              "import sys; sys.stderr.write('source.c:7: error: expected expression\\n'); sys.exit(1)"],
                             "Failed to compile source.c", include_detail=True)
    assert capsys.readouterr().err == ""


def test_install_rejects_directory_escape(context, compiler):
    package = context.config.parent / "package"
    package.mkdir()
    (package.parent / "outside.h").write_text("int secret;")
    (package / "main.c").write_text('#include "../outside.h"')
    with pytest.raises(ValueError, match="escapes package"):
        catalog.install(context, package / "main.c")
    compiler.assert_not_called()


def test_install_rejects_non_handler_object_without_publication(context):
    source = context.config.parent / "random.o"
    source.write_bytes(b"not BPF")
    with mock.patch.object(handlers, "handler_object_programs", side_effect=RuntimeError("not a handler")):
        with pytest.raises(RuntimeError, match="not a handler"):
            catalog.install(context, source)
    assert list((context.handlers_dir / "catalog").iterdir()) == []


def test_save_is_a_draft_and_apply_uses_validated_values_and_common_loader(context, compiler):
    source = context.config.parent / "custom.c"
    source.write_text("int x = PACKET_LIMIT;")
    write_manifest(source.with_suffix(".handler.json"))
    module = catalog.install(context, source)
    with mock.patch.object(handlers, "handler_shared_maps", return_value=[]) as maps, \
            mock.patch.object(handlers, "load_handler_object") as load:
        catalog.configure(context, module, {"limit": "25"})
        draft = config_file.load_toml(context.config)
        assert draft["modules"]["custom"]["draft"]["limit"] == 25
        assert "port_handlers" not in draft
        load.assert_not_called()
        catalog.configure(context, module, {}, apply=True)
        active = config_file.load_toml(context.config)
        obj = Path(active["port_handlers"]["udp"]["30120"])
        assert obj.is_file()
        assert compiler.call_args.kwargs["defines"] == {"PACKET_LIMIT": 25}
        assert load.call_args.args[:3] == (context.bpf_pin_dir / "udp_port_handlers", 30120, obj)
        assert maps.call_args.args == (obj, context.bpf_pin_dir)
        assert active["handler_bindings"]["udp"]["30120"]["module"] == "custom"
        assert active["modules"]["custom"]["limit"] == 25
        assert "draft" not in active["modules"]["custom"]
        assert "handler_settings" not in active


@pytest.mark.parametrize("name", ["icmp", "syncookie"])
def test_managed_module_save_keeps_current_settings_until_apply(context, monkeypatch, name):
    config_file.write_toml(context.config, {"modules": {name: {"enabled": False}}})
    module = catalog.select(context, name)
    refresh = mock.Mock(return_value={})
    monkeypatch.setattr(catalog, "_refresh_managed_runtime", refresh)
    monkeypatch.setattr(catalog, "_managed_result", lambda *args: "applied")
    catalog.configure(context, module, {"enabled": True})
    data = config_file.load_toml(context.config)
    assert data["modules"][name]["enabled"] is False
    assert data["modules"][name]["draft"]["enabled"] is True
    refresh.assert_not_called()
    catalog.configure(context, module, {}, apply=True)
    data = config_file.load_toml(context.config)
    assert data["modules"][name]["enabled"] is True
    assert "draft" not in data["modules"][name]
    assert name not in data and "handler_settings" not in data
    refresh.assert_called_once_with(context)


@pytest.mark.parametrize("updates,match", [
    ({"bogus": 2}, "Unknown handler parameters"),
    ({"invalid_ack_rate_pps": 0}, "minimum"),
    ({"by_port": '{"0": "always"}'}, "syncookie.by_port"),
])
def test_invalid_settings_leave_config_and_runtime_untouched(context, compiler, updates, match):
    config_file.write_toml(context.config, {"modules": {"syncookie": {"enabled": False}}})
    original = context.config.read_bytes()
    module = catalog.select(context, "syncookie")
    with mock.patch.object(catalog, "_refresh_managed_runtime") as refresh:
        with pytest.raises(ValueError, match=match):
            catalog.configure(context, module, updates, apply=True)
        refresh.assert_not_called()
    assert context.config.read_bytes() == original


def test_runtime_failure_is_reported_as_saved_but_not_applied(context, compiler):
    module = catalog.Module("udp", "UDP check", str(context.config.parent / "input.o"), "udp", 30120)
    Path(module.path).touch()
    with mock.patch.object(handlers, "handler_shared_maps", return_value=[]), \
            mock.patch.object(handlers, "load_handler_object", side_effect=RuntimeError("old generation restored")):
        with pytest.raises(RuntimeError, match="saved, but activation failed: old generation restored"):
            catalog.configure(context, module, {}, apply=True)
    assert config_file.load_toml(context.config)["port_handlers"]["udp"]["30120"] == str(Path(module.path).resolve())


def test_slot_application_replaces_same_protocol_configuration_and_disables_owned_target(context, compiler):
    source = context.install_dir / "handlers/gre_handler.o"
    source.touch()
    config_file.write_toml(context.config, {"slots": {"enabled": ["gre", "esp", {"proto": 47, "path": "/old.o"}]}})
    module = catalog.select(context, "gre")
    with mock.patch.object(handlers, "load_protocol_handler") as load:
        catalog.configure(context, module, {}, apply=True)
        load.assert_called_once_with(context.bpf_pin_dir, 47, source.resolve())
    entries = config_file.load_toml(context.config)["slots"]["enabled"]
    assert entries == ["esp", {"proto": 47, "path": str(source.resolve())}]
    with mock.patch.object(handlers, "unload_protocol_handler") as unload:
        catalog.configure(context, module, {"enabled": False}, apply=True)
        unload.assert_called_once_with(context.bpf_pin_dir, 47)
    assert config_file.load_toml(context.config)["slots"]["enabled"] == ["esp"]


def test_disable_refuses_target_owned_by_another_module(context):
    module = catalog.Module("one", "One", "/one.o", "tcp", 80)
    config_file.write_toml(context.config, {"port_handlers": {"tcp": {"80": "/two.o"}}})
    before = context.config.read_bytes()
    with mock.patch.object(handlers, "cleanup_existing_port_handler") as unload:
        with pytest.raises(ValueError, match="No saved binding"):
            catalog.configure(context, module, {"enabled": False}, apply=True)
        unload.assert_not_called()
    assert context.config.read_bytes() == before


def test_old_catalog_binding_does_not_override_a_new_legacy_cli_assignment(context):
    module = catalog.Module("one", "One", "/one.o", "tcp", 80)
    data = {"port_handlers": {"tcp": {"80": "/two.o"}},
            "handler_bindings": {"tcp": {"80": {"module": "one", "path": "/one.o"}}}}
    config_file.write_toml(context.config, data)
    with pytest.raises(ValueError, match="No saved binding"):
        catalog.configure(context, module, {"enabled": False}, apply=True)


def test_successful_rebuild_retires_only_unreferenced_managed_builds(context, compiler):
    source = context.config.parent / "custom.c"
    source.write_text("int x;")
    module = catalog.Module("custom", "Custom", str(source), "tcp", 8080)
    unknown = context.handlers_dir / "builds/other"
    unknown.mkdir(parents=True)
    (unknown / "data").write_text("not managed")
    with mock.patch.object(handlers, "handler_shared_maps", return_value=[]), mock.patch.object(handlers, "load_handler_object"):
        catalog.configure(context, module, {}, apply=True)
        first = Path(config_file.load_toml(context.config)["port_handlers"]["tcp"]["8080"])
        catalog.configure(context, module, {"target": 9090}, apply=True)
        assert first.exists()  # still assigned to 8080
        catalog.configure(context, module, {"target": 8080}, apply=True)
        assert not first.exists()
        assert (unknown / "data").read_text() == "not managed"
        for obj in config_file.load_toml(context.config)["port_handlers"]["tcp"].values():
            assert Path(obj).is_file()


def test_post_rename_config_error_retains_referenced_object(context, compiler):
    source = context.config.parent / "custom.c"
    source.write_text("int x;")
    module = catalog.Module("custom", "Custom", str(source), "tcp", 8080)
    real_write = config_file.write_toml
    def write_then_fail(path, data):
        real_write(path, data)
        raise OSError("post-rename failure")
    with mock.patch.object(config_file, "write_toml", side_effect=write_then_fail):
        with pytest.raises(OSError, match="post-rename"):
            catalog.configure(context, module, {}, apply=True)
    obj = Path(config_file.load_toml(context.config)["port_handlers"]["tcp"]["8080"])
    assert obj.is_file()


def test_minecraft_configuration_only_changes_protection_of_existing_subject(context):
    data = {"subjects": {"paper": {"resolve": {"systemd_unit": "paper.service"},
                                    "exposure": {"public": {"tcp": {"ports": [25565]}}}}}}
    config_file.write_toml(context.config, data)
    module = catalog.select(context, "minecraft")
    with mock.patch.object(catalog, "_refresh_managed_runtime") as refresh:
        result = catalog.configure(context, module, {"subject": "paper"}, apply=True)
        assert "audit" in result
        refresh.assert_called_once()
    after = config_file.load_toml(context.config)
    assert after["subjects"]["paper"]["exposure"] == data["subjects"]["paper"]["exposure"]
    assert after["subjects"]["paper"]["protection"]["profile"] == "minecraft"
    with pytest.raises(ValueError, match="Unknown policy subject"):
        catalog.configure(context, module, {"subject": "unconfigured"}, apply=True)


def test_managed_activation_checks_runtime_context_before_launching(context):
    (context.install_dir / "auto_xdp_start.sh").touch()
    env_file = context.config.parent / "auto_xdp.env"
    env_file.write_text(f'TOML_CONFIG="{context.config}"\nBPF_PIN_DIR="/wrong/root"\nIFACES="veth0"\n')
    with mock.patch.object(catalog.subprocess, "run") as launch:
        with pytest.raises(ValueError, match="BPF_PIN_DIR"):
            catalog._refresh_managed_runtime(context)
        launch.assert_not_called()
        env_file.write_text(f'TOML_CONFIG="{context.config}"\nBPF_PIN_DIR="{context.bpf_pin_dir}"\nIFACES="veth0"\n')
        launch.return_value = subprocess.CompletedProcess([], 0, "", "")
        env = catalog._refresh_managed_runtime(context)
        assert env["IFACES"] == "veth0"
        assert launch.call_args.args[0] == ["bash", str(context.install_dir / "auto_xdp_start.sh"), "--sync-once"]
        assert launch.call_args.kwargs["env"]["CONFIG_FILE"] == str(env_file)
        assert "shell" not in launch.call_args.kwargs


def test_controller_identity_requires_the_same_install_and_config(context, tmp_path):
    proc = tmp_path / "proc/123"
    proc.mkdir(parents=True)
    def command(*args):
        (proc / "cmdline").write_bytes("\0".join(args).encode() + b"\0")
    script = str(context.install_dir / "xdp_port_sync.py")
    command("python3", script, "--config", str(context.config), "--watch")
    assert catalog._daemon_matches(context, 123, tmp_path / "proc")
    command("python3", script, "--config", "/other/config.toml", "--watch")
    assert not catalog._daemon_matches(context, 123, tmp_path / "proc")
    command("python3", "/other/xdp_port_sync.py", "--config", str(context.config), "--watch")
    assert not catalog._daemon_matches(context, 123, tmp_path / "proc")
    command("python3", script, "--config", str(context.config))
    assert not catalog._daemon_matches(context, 123, tmp_path / "proc")
    env = tmp_path / "auto_xdp.env"
    env.write_text(f'TOML_CONFIG="{context.config}"\nBPF_PIN_DIR="{context.bpf_pin_dir}"\n')
    (proc / "environ").write_bytes(f"CONFIG_FILE={env}\0".encode())
    command("bash", str(context.install_dir / "auto_xdp_start.sh"))
    assert catalog._daemon_matches(context, 123, tmp_path / "proc")
    env.write_text('TOML_CONFIG="/another/config.toml"\n')
    assert not catalog._daemon_matches(context, 123, tmp_path / "proc")


@pytest.mark.parametrize("matches", [False, True])
@pytest.mark.parametrize("relay_active", [False, True])
def test_controller_detection_leaves_unrelated_services_alone(context, matches, relay_active):
    def query(command, **kwargs):
        return subprocess.CompletedProcess(command, 0 if command[1] == "show" or relay_active else 3, "123\n", "")
    with mock.patch.object(catalog.subprocess, "run", side_effect=query), \
            mock.patch.object(catalog, "_daemon_matches", return_value=matches):
        commands = catalog._controller_commands(context)
    start = ["systemctl", "start", "xdp-port-sync"] + (["auto-xdp-relay"] if relay_active else [])
    assert commands == ((["systemctl", "stop", "xdp-port-sync"], start) if matches else None)


@pytest.mark.parametrize("failure", [None, "apply", "interrupt", "stop", "restart", "both"])
def test_managed_apply_has_one_writer_and_always_restores_controller(context, failure):
    (context.install_dir / "auto_xdp_start.sh").touch()
    (context.config.parent / "auto_xdp.env").write_text(f'TOML_CONFIG="{context.config}"\nBPF_PIN_DIR="{context.bpf_pin_dir}"\n')
    calls = []
    def run(command, **kwargs):
        stage = "apply" if command[0] == "bash" else command[1]
        calls.append(stage)
        if failure == "interrupt" and stage == "apply":
            raise KeyboardInterrupt()
        if (failure in {"apply", "both"} and stage == "apply" or failure == "stop" and stage == "stop"
                or failure in {"restart", "both"} and stage == "start"):
            return subprocess.CompletedProcess(command, 1, "actual failure on stdout", "a preceding warning")
        return subprocess.CompletedProcess(command, 0, "", "")
    with mock.patch.object(catalog, "_controller_commands", return_value=(["systemctl", "stop", "xdp-port-sync"], ["systemctl", "start", "xdp-port-sync"])), \
            mock.patch.object(catalog.subprocess, "run", side_effect=run):
        if failure:
            with pytest.raises(KeyboardInterrupt if failure == "interrupt" else RuntimeError) as exc:
                catalog._refresh_managed_runtime(context)
            if failure != "interrupt":
                assert "actual failure on stdout" in str(exc.value) and "a preceding warning" in str(exc.value)
                if failure == "both":
                    assert "Controller restart also failed" in str(exc.value)
        else:
            catalog._refresh_managed_runtime(context)
    assert calls == (["stop", "start"] if failure == "stop" else ["stop", "apply", "start"])


@pytest.mark.parametrize("tc_program,valid", [(200, True), (201, False)])
@pytest.mark.parametrize("nested", [False, True])
def test_syncookie_apply_verifies_xdp_entry_and_tc_ingress_on_each_interface(context, tc_program, valid, nested):
    (context.bpf_pin_dir / "modules/syncookie").mkdir(parents=True)
    (context.bpf_pin_dir / "modules/syncookie/prog").touch()
    (context.bpf_pin_dir / "syncookie_prog_array").touch()
    module = catalog.select(context, "syncookie")
    with mock.patch.object(handlers, "pinned_program_id", side_effect=[100, 200]), \
            mock.patch.object(handlers, "_pinned_u32_lookup", return_value=100), \
            mock.patch.object(catalog.subprocess, "run", return_value=subprocess.CompletedProcess(
                [], 0, json.dumps([{"kind": "bpf", "pref": 49151, "options": {"handle": "0x2", **({"prog": {"id": tc_program}} if nested else {"id": tc_program})}}]), "")) as query:
        if valid:
            result = catalog._managed_result(context, module, {"enabled": True}, {"IFACES": "veth0 veth1"})
            assert "program 100" in result
            assert [call.args[0][-2] for call in query.call_args_list] == ["veth0", "veth1"]
        else:
            with pytest.raises(RuntimeError, match="not attached"):
                catalog._managed_result(context, module, {"enabled": True}, {"IFACES": "veth0 veth1"})


def test_missing_syncookie_program_is_not_reported_as_success(context):
    module = catalog.select(context, "syncookie")
    with pytest.raises(RuntimeError, match="not activated"):
        catalog._managed_result(context, module, {"enabled": True}, {"IFACES": "veth0"})


def test_nonroot_cannot_install_or_change_handlers(context, monkeypatch):
    monkeypatch.setattr(os, "geteuid", lambda: 501)
    with pytest.raises(PermissionError):
        catalog.install(context, Path("file.c"))
    with pytest.raises(PermissionError):
        catalog.configure(context, catalog.select(context, "gre"), {})
    assert not context.config.exists()


def test_cli_lists_sources_and_exposes_shared_configuration_schema(context, capsys):
    base = ["--config", str(context.config), "--install-dir", str(context.install_dir),
            "--handlers-dir", str(context.handlers_dir), "--bpf-pin-dir", str(context.bpf_pin_dir)]
    with mock.patch("auto_xdp.tui.handlers._query", return_value=[]):
        assert cli.main([*base, "handler", "list", "--json"]) == 0
    listing = json.loads(capsys.readouterr().out)
    assert {m["id"] for m in listing["modules"]} >= {"minecraft", "syncookie", "gre"}
    assert cli.main([*base, "handler", "config", "syncookie"]) == 0
    schema = json.loads(capsys.readouterr().out)
    assert {item["name"] for item in schema["fields"]} >= {"default_mode", "by_port", "invalid_ack_rate_pps"}
    assert not context.config.exists()


def test_inventory_keeps_active_programs_and_adds_available_modules_when_xdp_missing(context):
    with mock.patch("auto_xdp.tui.handlers._query", return_value=[]):
        result = collect_handlers(str(context.bpf_pin_dir), {}, HandlerCache(), context=context)
    assert {row.module.id for row in result.rows if row.module} >= {"gre", "esp", "sctp", "minecraft", "syncookie"}
    assert all(row.program_id is None and row.state != "loaded" for row in result.rows)


def test_catalog_binding_attaches_configuration_to_both_runtime_entries(context):
    obj = context.install_dir / "handlers/gre_handler.o"
    obj.touch()
    (context.bpf_pin_dir / "proto_handlers").touch()
    (context.bpf_pin_dir / "tc_proto_handlers").touch()
    data = {"handler_bindings": {"slot": {"47": {"module": "gre", "path": str(obj)}}},
            "slots": {"enabled": [{"proto": 47, "path": str(obj)}]}}
    def query(*args):
        return [] if args[0] == "-f" else [{"key": 47, "value": 11 if args[-1].endswith("/proto_handlers") else 12}]
    with mock.patch("auto_xdp.tui.handlers._query", side_effect=query):
        result = collect_handlers(str(context.bpf_pin_dir), data, HandlerCache(), context=context)
    gre = [row for row in result.rows if row.module and row.module.id == "gre"]
    assert {(row.kind, row.program_id) for row in gre} == {("SLOT", 11), ("TC_SLOT", 12)}
