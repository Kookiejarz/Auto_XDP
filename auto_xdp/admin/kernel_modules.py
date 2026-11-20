"""Resolve declared .ko dependencies before publishing a BPF generation.

System modules use modprobe. The bundled ICMP dependency can be built for the
running kernel from the installed SDK; no downloads or package installs occur.
"""
from __future__ import annotations

from contextlib import contextmanager, nullcontext
import contextvars
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import threading
from typing import ContextManager, Iterator

from auto_xdp.admin.handler_state import object_section


BUNDLED_SOURCES = {"axdp_icmp": "axdp_icmp.c"}
KERNEL_MODULES_DIR = Path("/lib/modules")
BUILD_LOCK = Path("/run/auto_xdp/kernel-modules.lock")
SYS_MODULE_DIR = Path("/sys/module")


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


def bundled_module_path(name: str) -> Path:
    """Where Makefile.kmod installs a bundled module for the running kernel."""
    return KERNEL_MODULES_DIR / os.uname().release / "extra/auto_xdp" / f"{name}.ko"


def kfunc_ids_unresolved(module: Path) -> bool:
    """Detect a bundled module whose kfunc ID set was never filled in.

    resolve_btfids writes the entry count as the first word of `.BTF_ids`.
    A build that skipped it still loads, but registers no kfunc: the verifier
    then rejects every caller with "calling kernel function ... is not
    allowed". A missing or unreadable module is not judged.
    """
    try:
        payload = object_section(module, b".BTF_ids")
    except (OSError, RuntimeError):
        return False
    return payload is not None and not payload[:4].strip(b"\0")


def module_damaged(module: Path) -> bool:
    """A bundled module file that is present but not a readable ELF object.

    For example truncated by an install that was interrupted before the
    atomic install in Makefile.kmod existed. modprobe rejects it, and since
    the file exists, a plain "missing module" check would never rebuild it.
    """
    try:
        if not module.is_file():
            return False
        with module.open("rb") as handle:
            if handle.read(4) != b"\x7fELF":
                return True
        object_section(module, b".BTF_ids")
    except OSError:
        return False
    except RuntimeError:
        return True
    return False


class BuildRequired(RuntimeError):
    """A bundled dependency needs a kernel-module build, and builds are disabled."""


_BUILDS_ALLOWED: contextvars.ContextVar[bool] = contextvars.ContextVar("axdp_kmod_builds", default=True)


@contextmanager
def builds_disabled() -> Iterator[None]:
    """Fail fast instead of building, e.g. while the daemon retries a degraded module.

    A build can take minutes; it is left to the runtime start and to an
    explicit `axdp handler apply`, never to an ordinary policy update.
    """
    token = _BUILDS_ALLOWED.set(False)
    try:
        yield
    finally:
        _BUILDS_ALLOWED.reset(token)


def _require_build(name: str, why: str) -> None:
    if not _BUILDS_ALLOWED.get():
        raise BuildRequired(f"{name} {why}; it is built on the next runtime start or "
                            f"'axdp handler apply', not during a policy update")


_LOCK_STATE = threading.local()


@contextmanager
def _build_lock() -> Iterator[None]:
    """Serialize everything that loads, builds, installs or unloads a bundled module.

    Reentrant within a thread. While builds are disabled (a daemon retry), a
    busy lock means another loader is working: fail fast instead of waiting
    behind a build that can take minutes.
    """
    if getattr(_LOCK_STATE, "depth", 0):
        _LOCK_STATE.depth += 1
        try:
            yield
        finally:
            _LOCK_STATE.depth -= 1
        return
    BUILD_LOCK.parent.mkdir(parents=True, exist_ok=True)
    with BUILD_LOCK.open("a") as stream:
        if _BUILDS_ALLOWED.get():
            fcntl.flock(stream, fcntl.LOCK_EX)
        else:
            try:
                fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise BuildRequired("another loader holds the kernel-module lock; retried later") from exc
        _LOCK_STATE.depth = 1
        try:
            yield
        finally:
            _LOCK_STATE.depth = 0


def dependency_lock(obj: Path) -> ContextManager[None]:
    """Held from `ensure` through the BPF load that takes the module reference.

    Only then is "loaded with refcnt 0" proof that a copy is stale: no other
    loader can be between its modprobe and its first BPF user.
    """
    if any(name in BUNDLED_SOURCES for name in dependencies(obj)):
        return _build_lock()
    return nullcontext()


def _module_in_use(name: str) -> bool | None:
    """Reference count of a loaded module; None when it is not loaded."""
    directory = SYS_MODULE_DIR / name
    if not directory.exists():
        return None
    try:
        return int((directory / "refcnt").read_text().strip() or "0") > 0
    except (OSError, ValueError):
        return True  # cannot tell: never force an unload


def _reload_token_path(name: str) -> Path:
    return BUILD_LOCK.with_name(f"kmod-reloads-{name}")


def reload_token(name: str) -> str:
    """Changes whenever a loader unloads `name`; read before a load attempt.

    A loader whose load failed may only unload the module if nobody reloaded
    it since that attempt: refcnt 0 cannot tell a stale copy from one another
    loader has just loaded and not yet used.
    """
    try:
        return _reload_token_path(name).read_text()
    except OSError:
        return ""


def _reload_unused(name: str) -> bool:
    """Replace a loaded copy that no BPF program uses with the file on disk.

    Called with the build lock held. A build without resolved kfunc IDs can
    never gain a BPF user (the verifier rejects every caller), so an unused
    loaded copy may be the broken one; a used copy registers the kfunc.
    """
    if _module_in_use(name) is not False:
        return False
    result = _run(["modprobe", "-r", name])
    if result.returncode:
        raise RuntimeError(f"The loaded {name} could not be unloaded to load its rebuilt file "
                           f"({result.stderr.strip() or result.stdout.strip()}); reboot or unload it manually")
    token = _reload_token_path(name)
    token.write_text(str(int(reload_token(name) or "0") + 1))
    return True


def _toolchain_fingerprint(digest: "hashlib._Hash") -> None:
    build_dir = KERNEL_MODULES_DIR / os.uname().release / "build"
    for path in (build_dir / "Makefile", build_dir / "vmlinux", build_dir / "scripts/gen-btf.sh",
                 build_dir / "scripts/Makefile.modfinal", build_dir / "scripts/Makefile.btf",
                 build_dir / "tools/bpf/resolve_btfids/resolve_btfids",
                 shutil.which("pahole"), shutil.which("objcopy"), Path(__file__)):
        try:
            info = Path(path).stat() if path else None
        except OSError:
            info = None
        digest.update(repr((str(path), info and (info.st_size, info.st_mtime_ns))).encode())
    try:
        digest.update(_run(["pahole", "--version"]).stdout.encode())
    except RuntimeError:
        digest.update(b"no pahole")


def _sdk_fingerprint(name: str) -> str:
    """Identify one build attempt: kernel, SDK sources and the BTF toolchain.

    Upgrading pahole, resolve_btfids, binutils, the kernel headers or this
    loader, as the error text advises, permits another attempt without a reboot.
    """
    sdk = sdk_directory()
    digest = hashlib.sha256(os.uname().release.encode())
    for path in (sdk / BUNDLED_SOURCES[name], sdk / "Kbuild", sdk / "Makefile.kmod",
                 sdk.parent / "bpf/include/icmp_ct_tuple.h"):
        digest.update(path.read_bytes())
    _toolchain_fingerprint(digest)
    return digest.hexdigest()[:16]


def _rebuild_unresolved(name: str, module: Path) -> None:
    """Replace a module this loader installed without kfunc IDs.

    An older SDK may have built it for this kernel; the installed one may know
    how to resolve the IDs. If its build succeeds and still leaves them empty,
    building again cannot help: that outcome is remembered under /run (per
    boot, kernel, SDK content and toolchain). A build that fails outright is
    retried. Build, install and unload happen under one lock, so a concurrent
    loader can never unload a module another one has just loaded.
    """
    kernel = os.uname().release
    problem = (f"{module} was built without resolved kfunc IDs for kernel {kernel} "
               "(its .BTF_ids set is empty), so the kernel rejects BPF programs that call it")
    remedy = "upgrade Auto XDP (or pahole/resolve_btfids), then apply the module again"
    stamp = BUILD_LOCK.with_name(f"kmod-rebuilt-{name}-{_sdk_fingerprint(name)}")
    if stamp.exists():
        raise RuntimeError(f"{problem}; this release already rebuilt it without effect: {remedy}")
    _require_build(name, f"at {module} has no resolved kfunc IDs and must be rebuilt")
    with _build_lock():
        if not kfunc_ids_unresolved(module):
            # Another loader replaced it while this one waited, and unloaded
            # the stale copy under this lock; what is loaded now is its new one.
            return
        _make_install(name)
        if kfunc_ids_unresolved(module):
            stamp.touch()
            raise RuntimeError(f"{problem}; rebuilding it with this release did not help: {remedy}")
        # The previous build may still be loaded; nothing can be using its kfunc.
        _reload_unused(name)


def reload_tokens(obj: Path) -> dict[str, str]:
    return {name: reload_token(name) for name in dependencies(obj) if name in BUNDLED_SOURCES}


def reload_stale(obj: Path, tokens: dict[str, str]) -> bool:
    """After a verifier "kernel function ... is not allowed", reload unused dependencies.

    The file on disk may have been repaired (a manual `make install`, or a
    loader interrupted before its unload) while the broken build stays loaded,
    which modprobe alone never replaces. `tokens` are the reload tokens read
    before the failed attempt. Returns True when the caller may retry once.
    """
    reloaded = False
    for name in dependencies(obj):
        if name not in BUNDLED_SOURCES or kfunc_ids_unresolved(bundled_module_path(name)):
            continue
        with _build_lock():
            if reload_token(name) != tokens.get(name, ""):
                # Another loader reloaded it after this attempt; just retry.
                reloaded = True
                continue
            if _reload_unused(name):
                result = _run(["modprobe", name])
                if result.returncode:
                    raise RuntimeError(f"Cannot load kernel dependency {name}: "
                                       f"{result.stderr.strip() or result.stdout.strip()}")
                reloaded = True
    return reloaded


def _make_install(name: str) -> None:
    """Build and install a bundled module. Called with the build lock held."""
    kernel = os.uname().release
    build_dir = KERNEL_MODULES_DIR / kernel / "build"
    if not (build_dir / "Makefile").is_file():
        raise RuntimeError(f"{name} needs development headers for running kernel {kernel}; install that kernel's headers/devel package and retry")
    sdk = sdk_directory()
    # Kbuild leaves native .o/.mod files. Keep these away from BPF objects and
    # atomically installed releases.
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


def _build_install(name: str) -> None:
    _require_build(name, f"is not installed for kernel {os.uname().release}")
    with _build_lock():
        if _run(["modprobe", name]).returncode == 0:
            return  # another loader installed it while this one waited
        _make_install(name)


def ensure(obj: Path) -> None:
    for name in dependencies(obj):
        if name in BUNDLED_SOURCES:
            # modprobe succeeds for a module that registers no kfunc, so a
            # wrongly built one would otherwise stay broken across restarts.
            module = bundled_module_path(name)
            if kfunc_ids_unresolved(module):
                _rebuild_unresolved(name, module)
        result = _run(["modprobe", name])
        if result.returncode == 0:
            continue
        # Rebuilding cannot fix a signature/permission failure on an existing
        # module. Only auto-build a bundled dependency absent for this kernel,
        # or one whose installed file is damaged.
        present = _run(["modinfo", "-n", name])
        if name in BUNDLED_SOURCES and (present.returncode != 0 or module_damaged(bundled_module_path(name))):
            _build_install(name)
            result = _run(["modprobe", name])
        if result.returncode:
            raise RuntimeError(f"Cannot load kernel dependency {name}: {result.stderr.strip() or result.stdout.strip()}")
