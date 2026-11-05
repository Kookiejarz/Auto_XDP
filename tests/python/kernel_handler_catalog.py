"""Exercise CLI installation/configuration against the real BPF dispatcher.

The Bash integration caller provides a private network and bpffs namespace.
"""
import json
import os
from pathlib import Path
import shutil
import socket
import sys
import tempfile

from auto_xdp.admin import config_file, handlers
from auto_xdp.admin.handler_catalog import Context
from auto_xdp.tui.handlers import HandlerCache, collect_handlers
from kernel_handler_dispatch import run
from kernel_packet_telemetry import frame, run_packet


SOURCE = '''
#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include "handler_state.h"
#include "include/options.h"
AXDP_STATE_SCHEMA("catalog-demo-v1", "[]");
SEC("xdp") int catalog_ingress(struct xdp_md *ctx) { return CATALOG_VERDICT; }
SEC("tc") int catalog_egress(struct __sk_buff *skb) { return TC_ACT_UNSPEC; }
char LICENSE[] SEC("license") = "GPL";
'''


def main(root, iface, repository):
    with tempfile.TemporaryDirectory(prefix="axdp-catalog-") as directory:
        base = Path(directory)
        package = base / "input"
        (package / "include").mkdir(parents=True)
        (package / "main.c").write_text(SOURCE)
        (package / "include/options.h").write_text("#ifndef CATALOG_VERDICT\n#define CATALOG_VERDICT 2\n#endif\n")
        (package / "handler.json").write_text(json.dumps({
            "version": 1, "id": "catalog-demo", "entry": "main.c", "kind": "slot", "target": 47,
            "fields": [{"name": "verdict", "label": "Packet action", "type": "int", "define": "CATALOG_VERDICT",
                        "default": 2, "choices": [1, 2]}],
        }))
        config = base / "config.toml"
        custom = base / "handlers"
        config_file.write_toml(config, {"slots": {"enabled": []}, "xdp": {"bpf_pin_dir": str(root)}})
        command = [sys.executable, "-m", "auto_xdp.admin.cli", "--config", config,
                   "--install-dir", repository, "--handlers-dir", custom, "--bpf-pin-dir", root,
                   "handler"]
        run(*command, "install", package)
        assert handlers._pinned_u32_lookup(root / "proto_handlers", (47).to_bytes(4, sys.byteorder)) is None
        assert "handler_bindings" not in config_file.load_toml(config)
        shutil.rmtree(package)
        run(*command, "apply", "catalog-demo")
        live = root / "protocol_handlers/47"
        first = handlers.pinned_program_id(live / "prog")
        assert (live / "egress").exists()
        packet = frame(47, bytes.fromhex("00000800"))
        ifindex = socket.if_nametoindex(iface)
        assert run_packet(root, ifindex, packet)[0] == 2
        run(*command, "config", "catalog-demo", "--set", "verdict=1")
        assert handlers.pinned_program_id(live / "prog") == first
        assert run_packet(root, ifindex, packet)[0] == 2  # saved draft is not live
        run(*command, "apply", "catalog-demo")
        second = handlers.pinned_program_id(live / "prog")
        assert second != first
        assert run_packet(root, ifindex, packet)[0] == 1  # compiler parameter changed packet behavior
        context = Context(config, repository, custom, root, base / "run")
        inventory = collect_handlers(str(root), config_file.load_toml(config), HandlerCache(), context=context)
        rows = [row for row in inventory.rows if row.module and row.module.id == "catalog-demo"]
        assert {(row.kind, row.state) for row in rows} == {("SLOT", "loaded"), ("TC_SLOT", "loaded")}
        before = config.read_bytes()
        import subprocess
        invalid = subprocess.run([str(v) for v in (*command, "apply", "catalog-demo", "--set", "verdict=9")],
                                 capture_output=True, text=True)
        assert invalid.returncode != 0 and "choose" in invalid.stderr
        assert config.read_bytes() == before and handlers.pinned_program_id(live / "prog") == second
        assert run_packet(root, ifindex, packet)[0] == 1
        run(*command, "apply", "catalog-demo", "--set", "enabled=false")
        assert not live.exists()
        assert handlers._pinned_u32_lookup(root / "proto_handlers", (47).to_bytes(4, sys.byteorder)) is None
        assert handlers._pinned_u32_lookup(root / "tc_proto_handlers", (47).to_bytes(4, sys.byteorder)) is None
        assert handlers.handler_egress_id(root, 4, 47) is None
        assert config_file.load_toml(config)["slots"]["enabled"] == []
        assert not list((custom / "builds").iterdir())
        installed = custom / "catalog/catalog-demo/main.c"
        assert installed.exists()
        listing = json.loads(run(*command, "list", "--json").stdout)
        assert any(module["id"] == "catalog-demo" for module in listing["modules"])
    print("handler catalog: installed sources + nested headers; typed config changes real packet verdicts; save/apply/disable and cleanup verified")
    if os.environ.get("HANDLER_TUI_E2E") == "1":
        from kernel_handler_tui import main as tui_main
        tui_main(root, iface, repository)


if __name__ == "__main__":
    main(Path(sys.argv[1]), sys.argv[2], Path(sys.argv[3]))
