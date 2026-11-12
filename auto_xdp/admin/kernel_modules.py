"""Resolve declared .ko dependencies before publishing a BPF generation.

System modules use modprobe. The bundled ICMP dependency can be built for the
running kernel from the installed SDK; no downloads or package installs occur.
"""
from __future__ import annotations

import fcntl
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

from auto_xdp.admin.handler_state import object_section


BUNDLED_SOURCES = {"axdp_icmp": "axdp_icmp.c"}
KERNEL_MODULES_DIR = Path("/lib/modules")
BUILD_LOCK = Path("/run/auto_xdp/kernel-modules.lock")


def dependencies(obj: Path) -> tuple[str, ...]:
    payload = object_section(obj, b".axdp_kmods")
    if payload is None:
        return ()
    try:
        names = json.loads(payload)
        if not isinstance(names, list) or len(names) > 8 or any(
            not isinstance(name, str) or not re.fullmatch(r"[a-zA-Z][a-zA-Z0-9_]{0,63}", name)
            for name in names
        ) or len(set(names)) != len(names):
            raise ValueError("expected up to eight distinct module names")
        return tuple(names)
    except (ValueError, UnicodeError) as exc:
        raise RuntimeError(f"Invalid kernel dependencies in {obj}: {exc}") from exc


def _run(command: list[str], *, cwd: Path | None = None, timeout: int = 30) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(command, cwd=cwd, capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.SubprocessError) as exc:
        raise RuntimeError(f"Kernel dependency command failed: {command[0]}: {exc}") from exc


def sdk_directory() -> Path:
    for root in (Path(__file__).resolve().parents[2], Path(__file__).resolve().parents[3]):
        if (root / "handlers/Kbuild").is_file():
            return root / "handlers"
    raise RuntimeError("Bundled kernel module source is missing; reinstall the Auto XDP handler SDK")


def _build_install(name: str) -> None:
    kernel = os.uname().release
    build_dir = KERNEL_MODULES_DIR / kernel / "build"
    if not (build_dir / "Makefile").is_file():
        raise RuntimeError(f"{name} needs development headers for running kernel {kernel}; install that kernel's headers/devel package and retry")
    sdk = sdk_directory()
    # Kbuild leaves native .o/.mod files. Keep these away from BPF objects and
    # atomically installed releases, and serialize builds across handler roots.
    lock = BUILD_LOCK
    lock.parent.mkdir(parents=True, exist_ok=True)
    with lock.open("a") as stream:
        fcntl.flock(stream, fcntl.LOCK_EX)
        if _run(["modprobe", name]).returncode == 0:
            return
        with tempfile.TemporaryDirectory(prefix="axdp-kmod-") as directory:
            build = Path(directory)
            for filename in (BUNDLED_SOURCES[name], "Kbuild", "Makefile.kmod"):
                shutil.copyfile(sdk / filename, build / filename)
            shutil.copyfile(sdk.parent / "bpf/include/icmp_ct_tuple.h", build / "icmp_ct_tuple.h")
            result = _run(["make", "-f", "Makefile.kmod", f"KVER={kernel}",
                           f"KDIR={build_dir}", "install"], cwd=build, timeout=120)
            if result.returncode:
                detail = (result.stderr + "\n" + result.stdout).strip()
                raise RuntimeError(f"Cannot build/install kernel dependency {name} for {kernel}:\n{detail}")


def ensure(obj: Path) -> None:
    for name in dependencies(obj):
        result = _run(["modprobe", name])
        if result.returncode == 0:
            continue
        # Rebuilding cannot fix a signature/permission failure on an existing
        # module. Only auto-build a bundled dependency absent for this kernel.
        present = _run(["modinfo", "-n", name])
        if name in BUNDLED_SOURCES and present.returncode != 0:
            _build_install(name)
            result = _run(["modprobe", name])
        if result.returncode:
            raise RuntimeError(f"Cannot load kernel dependency {name}: {result.stderr.strip() or result.stdout.strip()}")
