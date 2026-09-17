"""Runtime capability checks for the optional kernel SYN-cookie path."""
from __future__ import annotations

import shutil
import subprocess
import json
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

    @property
    def level(self) -> int:
        if not self.helpers:
            return 0
        return 2 if self.reqsk_handoff else 1

    @property
    def available(self) -> bool:
        return self.helpers and self.sysctl_ready

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
                "reqsk_attrs": {"mss": self.reqsk_handoff,
                                 "timestamp": self.reqsk_handoff,
                                 "wscale": self.reqsk_handoff,
                                 "sack": self.reqsk_handoff,
                                 "ecn": self.reqsk_handoff},
                "reason": self.reason}


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

    try:
        with open(sysctl_path, encoding="ascii") as fh:
            sysctl_ready = int(fh.read().strip()) != 0
    except (OSError, ValueError):
        sysctl_ready = False
    if not sysctl_ready:
        return SyncookieCapability(True, False, "net.ipv4.tcp_syncookies is zero or unavailable", helper_v4, helper_v6, reqsk_handoff)
    return SyncookieCapability(True, True, "", helper_v4, helper_v6, reqsk_handoff)


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
