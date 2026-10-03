"""Activate namespace-local conntrack hooks without changing packet verdicts.

A ct expression holds nf_ct_netns_get() for IPv4 and IPv6. Loading the module
alone does not guarantee active hooks. Actual XDP object loading separately
verifies the lookup/release kfuncs before the transactional interface switch.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys

TABLE = "auto_xdp_conntrack"
OWNER = "auto-xdp conntrack activation v1"


def verify_lookup_abi() -> None:
    # Early lookup kfuncs had reserved[3], not an output direction. They can
    # load our program but cannot supply the REPLY exception. Probe BTF rather
    # than a version string, so vendor backports and built-in modules work.
    module = Path("/sys/kernel/btf/nf_conntrack")
    btf = module if module.exists() else Path("/sys/kernel/btf/vmlinux")
    result = subprocess.run([os.environ.get("BPFTOOL_BIN", "bpftool"), "-j", "btf",
                             "dump", "file", str(btf), "format", "raw"],
                            capture_output=True, text=True, check=True, timeout=10)
    for row in json.loads(result.stdout)["types"]:
        if row.get("kind") != "STRUCT" or row.get("name") != "bpf_ct_opts":
            continue
        offsets = {member["name"]: member["bits_offset"] for member in row["members"]}
        if all(offsets.get(name) == offset for name, offset in
               {"netns_id": 0, "error": 32, "l4proto": 64, "dir": 72}.items()):
            return
    raise RuntimeError("kernel bpf_ct_opts lacks the supported REPLY direction ABI")


def configure(*, remove: bool = False) -> None:
    # Listing all tables distinguishes absence from permission/tooling errors.
    result = subprocess.run(["nft", "-j", "list", "tables"],
                            capture_output=True, text=True, check=True, timeout=10)
    tables = json.loads(result.stdout)["nftables"]
    exists = any(row.get("table", {}).get("family") == "inet" and
                 row["table"].get("name") == TABLE for row in tables)
    if exists:
        result = subprocess.run(["nft", "-j", "list", "table", "inet", TABLE],
                                capture_output=True, text=True, check=True, timeout=10)
        rows = json.loads(result.stdout)["nftables"]
        if not any(row.get("table", {}).get("comment") == OWNER for row in rows):
            raise RuntimeError(f"refusing to modify unowned inet table {TABLE}")
    elif remove:
        return

    # One atomic transaction repairs our dedicated table, with no interval in
    # which the last ct-expression reference is released. Never flush conntrack
    # entries, other tables, NAT, sysctls, or operator rules.
    commands = f"delete table inet {TABLE}\n" if exists else ""
    if not remove:
        commands += f'''create table inet {TABLE} {{ comment "{OWNER}"; }}
add chain inet {TABLE} track {{ type filter hook output priority filter; policy accept; }}
add rule inet {TABLE} track ct state established counter
'''
    subprocess.run(["nft", "-f", "-"], input=commands, text=True,
                   capture_output=True, check=True, timeout=10)


if __name__ == "__main__":
    try:
        if sys.argv[1:] not in ([], ["--remove"]):
            raise RuntimeError("usage: python -m auto_xdp.bpf.conntrack [--remove]")
        configure(remove=sys.argv[1:] == ["--remove"])
        if not sys.argv[1:]:
            verify_lookup_abi()
    except (OSError, ValueError, KeyError, RuntimeError, subprocess.SubprocessError) as exc:
        detail = getattr(exc, "stderr", "") or str(exc)
        print(f"Linux conntrack activation failed: {detail}", file=sys.stderr)
        raise SystemExit(1)
