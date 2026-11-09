"""Opt-in real curses/tmux workflow, within the catalog test's private netns.

Run with HANDLER_TUI_E2E=1 and KERNEL_TEST_FILTER=handler_catalog. Requires tmux.
"""
import json
import os
from pathlib import Path
import shlex
import socket
import subprocess
import sys
import tempfile
import time

from auto_xdp.admin import config_file, handlers
from auto_xdp.admin.handler_catalog import Context
from auto_xdp.tui.handlers import HandlerCache, collect_handlers
from kernel_handler_catalog import SOURCE
from kernel_handler_dispatch import run
from kernel_packet_telemetry import frame, run_packet


def main(root, iface, repository):
    with tempfile.TemporaryDirectory(prefix="axdp-tui-live-") as directory:
        base = Path(directory)
        captures = Path(os.environ.get("HANDLER_TUI_ARTIFACTS", str(base / "captures")))
        captures.mkdir(parents=True, exist_ok=True)
        config, custom = base / "config.toml", base / "handlers"
        config_file.write_toml(config, {"slots": {"enabled": []}, "xdp": {"bpf_pin_dir": str(root)}})
        package = base / "input"
        (package / "include").mkdir(parents=True)
        (package / "main.c").write_text(SOURCE)
        (package / "include/options.h").write_text("#ifndef CATALOG_VERDICT\n#define CATALOG_VERDICT 2\n#endif\n")
        metadata = {"version": 1, "id": "tui-demo", "name": "TUI demo", "entry": "main.c", "kind": "slot", "target": 47,
                    "fields": [{"name": "verdict", "label": "Packet action", "type": "int", "define": "CATALOG_VERDICT",
                                "default": 2, "choices": [1, 2]}]}
        (package / "handler.json").write_text(json.dumps(metadata))
        command = [sys.executable, "-m", "auto_xdp.admin.cli", "--config", str(config), "--install-dir", str(repository),
                   "--handlers-dir", str(custom), "--bpf-pin-dir", str(root), "--run-state-dir", str(base / "run"),
                   "--iface", iface]
        server = "axdp-tui-" + str(os.getpid())
        def tmux(*args):
            return run("tmux", "-L", server, *args).stdout
        def screen():
            return tmux("capture-pane", "-p", "-t", "live:0.0")
        def capture(name):
            result = screen()
            (captures / (name + ".txt")).write_text(result)
            return result
        def wait(check, description):
            deadline = time.monotonic() + 20
            last = ""
            while time.monotonic() < deadline:
                last = screen()
                if check(last):
                    return last
                time.sleep(0.1)
            (captures / "timeout.txt").write_text(last)
            raise AssertionError(description + "\n" + last)
        def keys(*items):
            tmux("send-keys", "-t", "live:0.0", *items)
        def text(value):
            tmux("send-keys", "-l", "-t", "live:0.0", str(value))
        def install(path, title):
            keys("i")
            wait(lambda s: "Install local" in s, "install path prompt")
            text(path)
            keys("Enter")
            wait(lambda s: "Module name" in s, "module name prompt")
            keys("Enter")
            wait(lambda s: "Handler configuration / " + title in s, "installed module configuration")
        context = Context(config, repository, custom, root, base / "run", iface)
        def select(identifier):
            data = config_file.load_toml(config)
            rows = collect_handlers(str(root), data, HandlerCache(), context=context).rows
            index = next(i for i, row in enumerate(rows) if row.module and row.module.id == identifier)
            keys(*(["Up"] * (len(rows) + 2)))
            if index:
                keys(*(["Down"] * index))
            keys("Enter")
        live = root / "protocol_handlers/47"
        packet = frame(47, bytes.fromhex("00000800"))
        ifindex = socket.if_nametoindex(iface)
        try:
            shell = "cd " + shlex.quote(str(repository)) + " && " + shlex.join([
                "env", "TERM=xterm-256color", "LANG=C.UTF-8", "PYTHONPATH=" + str(repository),
                *command, "tui", "--interval", "0.1", "--socket", str(base / "missing.sock")])
            tmux("new-session", "-d", "-s", "live", "-x", "140", "-y", "42", shell)
            wait(lambda s: "Ports" in s or "Auto XDP" in s, "TUI started")
            keys("h")
            wait(lambda s: "Handlers & slots" in s, "handler catalog opened")
            install(package, "TUI demo")
            capture("01-installed-form")
            assert (custom / "catalog/tui-demo/main.c").exists()
            assert "handler_bindings" not in config_file.load_toml(config)
            keys("s")
            wait(lambda s: "Configuration saved" in s, "saved draft")
            assert "handler_bindings" not in config_file.load_toml(config)
            keys("a")
            wait(lambda s: "Applied TUI demo" in s, "applied module")
            first = handlers.pinned_program_id(live / "prog")
            assert run_packet(root, ifindex, packet)[0] == 2
            keys("Down", "Down", "Right", "s")
            wait(lambda s: "Configuration saved" in s, "saved changed compiler parameter")
            assert config_file.load_toml(config)["modules"]["tui-demo"]["draft"]["verdict"] == 1
            assert handlers.pinned_program_id(live / "prog") == first
            assert run_packet(root, ifindex, packet)[0] == 2
            keys("a")
            wait(lambda s: "Applied TUI demo" in s, "applied changed parameter")
            second = handlers.pinned_program_id(live / "prog")
            assert second != first and run_packet(root, ifindex, packet)[0] == 1
            capture("02-applied-drop")
            source = custom / "catalog/tui-demo/main.c"
            source.write_text(SOURCE + "\n#error TUI_EXPECTED_COMPILE_FAILURE\n")
            original = config.read_bytes()
            keys("a")
            wait(lambda s: "e errors" in s, "compile failure warning")
            keys("e")
            wait(lambda s: "TUI_EXPECTED_COMPILE_FAILURE" in s, "compiler diagnostic viewer")
            capture("03-compiler-diagnostics")
            assert config.read_bytes() == original
            assert handlers.pinned_program_id(live / "prog") == second
            assert run_packet(root, ifindex, packet)[0] == 1
            keys("Escape", "Escape")
            wait(lambda s: "⚠" in s and "Last build/check failed" in s, "catalog warning after failed rebuild")
            listing = capture("04-loaded-with-warning")
            assert any("⚠" in line and "loaded" in line and str(second) in line for line in listing.splitlines())
            modules = json.loads(run(*command, "handler", "list", "--json").stdout)["modules"]
            assert "TUI_EXPECTED_COMPILE_FAILURE" in next(m for m in modules if m["id"] == "tui-demo")["build_error"]
            source.write_text(SOURCE)
            select("tui-demo")
            wait(lambda s: "Handler configuration / TUI demo" in s, "reopened failed module")
            keys("a")
            wait(lambda s: "Applied TUI demo" in s and "e errors" not in s, "successful retry clears warning")
            third = handlers.pinned_program_id(live / "prog")
            assert third != second and run_packet(root, ifindex, packet)[0] == 1
            keys("Escape")
            wait(lambda s: "Handlers & slots" in s and "Last build/check failed" not in s, "cleared catalog warning")
            broken = base / "broken"
            (broken / "include").mkdir(parents=True)
            (broken / "include/options.h").write_text((package / "include/options.h").read_text())
            (broken / "main.c").write_text(SOURCE + "\n#error TUI_INSTALL_EXPECTED_FAILURE\n")
            (broken / "handler.json").write_text(json.dumps({**metadata, "id": "tui-broken", "name": "TUI broken"}))
            keys("i")
            wait(lambda s: "Install local" in s, "broken package path prompt")
            text(broken)
            keys("Enter")
            wait(lambda s: "Module name" in s, "broken module name prompt")
            keys("Enter")
            wait(lambda s: "build fail" in s and "⚠" in s, "failed install remains a warning candidate")
            capture("05-failed-install-candidate")
            assert not (custom / "catalog/tui-broken").exists()
            assert handlers.pinned_program_id(live / "prog") == third
            (broken / "main.c").write_text(SOURCE)
            install(broken, "TUI broken")
            keys("Escape")
            wait(lambda s: "Handlers & slots" in s and "build fail" not in s, "failed install retried successfully")
            select("tui-demo")
            wait(lambda s: "Handler configuration / TUI demo" in s, "open live module to disable")
            keys("Space", "a")
            wait(lambda s: "Disabled TUI demo" in s, "disable module through TUI")
            assert not live.exists()
            assert handlers._pinned_u32_lookup(root / "proto_handlers", (47).to_bytes(4, sys.byteorder)) is None
            assert handlers._pinned_u32_lookup(root / "tc_proto_handlers", (47).to_bytes(4, sys.byteorder)) is None
            capture("06-disabled")
            keys("Escape", "q")
            print("real TUI: install, draft, apply, packet verdict, compiler diagnostics, loaded warning, retry, failed-install recovery and disable PASS")
        except Exception:
            try:
                capture("failure")
            except subprocess.SubprocessError:
                pass
            raise
        finally:
            subprocess.run(["tmux", "-L", server, "kill-server"], capture_output=True)
