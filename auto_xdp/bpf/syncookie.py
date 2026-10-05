"""Runtime capability checks for the optional kernel SYN-cookie path."""
from __future__ import annotations

import shutil
import subprocess
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from auto_xdp.install_state import atomic_write_json

HELPERS = (
    "bpf_tcp_raw_gen_syncookie_ipv4",
    "bpf_tcp_raw_gen_syncookie_ipv6",
    "bpf_tcp_raw_check_syncookie_ipv4",
    "bpf_tcp_raw_check_syncookie_ipv6",
)


@dataclass(frozen=True)
class SyncookieCapability:
    helpers: bool
    sysctl_ready: bool
    reason: str = ""
    helper_v4: bool = False
    helper_v6: bool = False
    reqsk_handoff: bool = False
    handoff_environment_ready: bool = True

    @property
    def level(self) -> int:
        if not self.helpers:
            return 0
        return 2 if self.reqsk_handoff and self.handoff_environment_ready else 1

    @property
    def available(self) -> bool:
        return self.helpers and self.sysctl_ready and self.handoff_environment_ready

    @property
    def status(self) -> str:
        if self.available:
            return "ready"
        return "unsupported" if not self.helpers else "degraded"

    def as_dict(self) -> dict[str, Any]:
        return {"status": self.status, "helpers": self.helpers,
                "helper_v4": self.helper_v4, "helper_v6": self.helper_v6,
                "sysctl_ready": self.sysctl_ready, "level": self.level,
                "reqsk_handoff": self.reqsk_handoff,
                "handoff_environment_ready": self.handoff_environment_ready,
                "reqsk_attrs": {"mss": self.level == 2,
                                 "timestamp": self.level == 2,
                                 "wscale": self.level == 2,
                                 "sack": self.level == 2,
                                 "ecn": self.level == 2},
                "reason": self.reason}


def _nat_expression(value: Any) -> bool:
    if isinstance(value, dict):
        if any(key in value for key in ("snat", "dnat", "masquerade", "redirect")):
            return True
        xt = value.get("xt")
        if (isinstance(xt, dict) and xt.get("type") == "target"
                and xt.get("name") in {"SNAT", "DNAT", "MASQUERADE", "REDIRECT", "NETMAP", "SAME"}):
            return True
        return any(_nat_expression(child) for child in value.values())
    return isinstance(value, list) and any(_nat_expression(child) for child in value)


def probe_reqsk_handoff_environment() -> tuple[bool, str]:
    """Read-only, current-netns gate for NAT that can orphan a BPF reqsk.

    A successful TC assignment is not enough: NAT LOCAL_IN can compare the
    not-yet-initialized request socket port with conntrack, then clear skb->sk
    before cookie_bpf_check(). Do not enable this combination or change NAT.
    """
    nft = shutil.which("nft")
    if not nft:
        return False, "SYN-cookie Level 2 environment unknown: nft is unavailable; cannot inspect current-netns NAT"
    try:
        # Do not request JSON here: nft 1.0.9 aborts on `-j list hooks`.
        hooks = subprocess.run(
            [nft, "list", "hooks", "inet"], capture_output=True, text=True,
            check=False, timeout=5,
        )
        if hooks.returncode == 0 and re.search(r"\bnf_nat_(?:ipv4|ipv6|inet)_local_in\b", hooks.stdout):
            return False, "SYN-cookie Level 2 incompatible: current-netns NAT LOCAL_IN hook can discard the assigned request socket"
    except (OSError, subprocess.TimeoutExpired):
        pass

    # Hook dumps can be unsupported or even empty with exit 0 on old nft.
    # Cross-check the ruleset and legacy tables rather than treating that as
    # proof that no NAT hook is installed. Any NAT base chain registers the
    # implicit LOCAL_IN hook, including an output-only Docker DNS NAT chain.
    try:
        rules = subprocess.run(
            [nft, "-j", "list", "ruleset"], capture_output=True, text=True,
            check=False, timeout=5,
        )
        if rules.returncode != 0:
            raise ValueError("nft ruleset query failed")
        data = json.loads(rules.stdout)
        rows = data.get("nftables") if isinstance(data, dict) else None
        if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
            raise ValueError("unrecognized nft ruleset")
        for row in rows:
            chain = row.get("chain", {})
            if isinstance(chain, dict) and chain.get("type") == "nat":
                return False, "SYN-cookie Level 2 incompatible: current-netns nftables NAT base chain can discard the assigned request socket"
            rule = row.get("rule", {})
            if isinstance(rule, dict) and _nat_expression(rule.get("expr", [])):
                return False, "SYN-cookie Level 2 incompatible: current-netns nftables NAT rule can discard the assigned request socket"
    except (OSError, ValueError, subprocess.TimeoutExpired):
        return False, "SYN-cookie Level 2 environment unknown: cannot verify the current-netns nftables ruleset"

    for name in ("ip_tables_names", "ip6_tables_names"):
        path = Path("/proc/net") / name
        try:
            tables = path.read_text(encoding="ascii").split()
        except FileNotFoundError:
            # Legacy table registration also creates this namespace's proc
            # listing; absent listing means the legacy subsystem is absent.
            continue
        except (OSError, UnicodeError):
            return False, f"SYN-cookie Level 2 environment unknown: cannot inspect current-netns {name}"
        if "nat" in tables:
            return False, "SYN-cookie Level 2 incompatible: current-netns legacy iptables NAT table can discard the assigned request socket"
    return True, ""


def probe_syncookie_capability(*, sysctl_path: str | Path = "/proc/sys/net/ipv4/tcp_syncookies") -> SyncookieCapability:
    bpftool = shutil.which("bpftool")
    if not bpftool:
        return SyncookieCapability(False, False, "bpftool not found")
    try:
        result = subprocess.run(
            [bpftool, "feature", "probe", "kernel"],
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError as exc:
        return SyncookieCapability(False, False, f"bpftool probe failed: {exc}")
    output = result.stdout + result.stderr
    helper_v4 = all(helper in output for helper in (HELPERS[0], HELPERS[2]))
    helper_v6 = all(helper in output for helper in (HELPERS[1], HELPERS[3]))
    missing = [helper for helper in HELPERS if helper not in output]
    reqsk_handoff = False
    try:
        btf = subprocess.run(
            [bpftool, "btf", "dump", "file", "/sys/kernel/btf/vmlinux", "format", "raw"],
            capture_output=True, text=True, check=False,
        )
        reqsk_handoff = "bpf_sk_assign_tcp_reqsk" in (btf.stdout + btf.stderr)
    except OSError:
        pass
    if missing:
        return SyncookieCapability(False, False, f"missing helpers: {', '.join(missing)}", helper_v4, helper_v6, reqsk_handoff)

    environment_ready, environment_reason = (True, "")
    if reqsk_handoff:
        environment_ready, environment_reason = probe_reqsk_handoff_environment()

    try:
        with open(sysctl_path, encoding="ascii") as fh:
            sysctl_ready = int(fh.read().strip()) != 0
    except (OSError, ValueError):
        sysctl_ready = False
    reason = environment_reason
    if not sysctl_ready:
        reason = reason or "net.ipv4.tcp_syncookies is zero or unavailable"
    return SyncookieCapability(True, sysctl_ready, reason, helper_v4, helper_v6,
                              reqsk_handoff, environment_ready)


SYSCTL_PATH = Path("/proc/sys/net/ipv4/tcp_syncookies")


@dataclass(frozen=True)
class SysctlOwnership:
    path: str
    old_value: int
    managed_value: int
    owner: str
    netns_inode: int

    def as_dict(self) -> dict[str, Any]:
        return self.__dict__.copy()


def _read_sysctl(path: str | Path = SYSCTL_PATH) -> int:
    return int(Path(path).read_text(encoding="ascii").strip())


def _write_sysctl(value: int, path: str | Path = SYSCTL_PATH) -> None:
    Path(path).write_text(f"{value}\n", encoding="ascii")


def acquire_sysctl(state_path: str | Path, *, desired: int = 1,
                   path: str | Path = SYSCTL_PATH,
                   owner: str = "auto-xdp") -> SysctlOwnership:
    """Acquire a namespace-scoped value and persist enough data to restore it."""
    state_file = Path(state_path)
    if state_file.exists():
        saved = json.loads(state_file.read_text())
        record = SysctlOwnership(**saved)
        try:
            current_netns = Path("/proc/self/ns/net").stat().st_ino
        except OSError:
            current_netns = 0
        if (record.path != str(path) or record.owner != owner
                or record.netns_inode not in (0, current_netns)
                or record.managed_value != desired
                or _read_sysctl(path) != desired):
            raise RuntimeError("existing SYN-cookie sysctl ownership does not match")
        return record
    current = _read_sysctl(path)
    try:
        netns_inode = Path("/proc/self/ns/net").stat().st_ino
    except OSError:
        netns_inode = 0
    record = SysctlOwnership(str(path), current, desired, owner, netns_inode)
    if current != desired:
        _write_sysctl(desired, path)
    atomic_write_json(state_file, record.as_dict(), mode=0o600)
    return record


def release_sysctl(state_path: str | Path, *, path: str | Path = SYSCTL_PATH) -> bool:
    """Restore only if the operator has not changed the managed value."""
    try:
        record = json.loads(Path(state_path).read_text())
        try:
            current_netns = Path("/proc/self/ns/net").stat().st_ino
        except OSError:
            current_netns = 0
        if (str(record["path"]) != str(path)
                or (int(record.get("netns_inode", 0)) not in (0, current_netns))
                or _read_sysctl(path) != int(record["managed_value"])):
            return False
        _write_sysctl(int(record["old_value"]), path)
        Path(state_path).unlink()
        return True
    except (OSError, ValueError, KeyError, json.JSONDecodeError):
        return False
