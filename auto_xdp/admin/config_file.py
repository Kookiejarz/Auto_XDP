"""Versioned TOML read/modify/write transactions shared by management clients."""
from __future__ import annotations

from importlib import resources
from contextlib import contextmanager
from dataclasses import dataclass
import fcntl
import hashlib
import json
import math
import os
import re
import tempfile
from pathlib import Path
from typing import Any, Iterator

try:
    import tomllib
except ImportError:
    try:
        import tomli as tomllib
    except ImportError:
        tomllib = None


_BARE_KEY_RE = re.compile(r"^[A-Za-z0-9_-]+$")
MISSING_REVISION = "missing"


class ConfigConflictError(ValueError):
    """The configuration changed since this edit was read."""


@dataclass(frozen=True)
class ConfigDocument:
    path: Path
    data: dict[str, Any]
    revision: str

    def save(self, data: dict[str, Any] | None = None) -> str:
        """Commit this edit once, rejecting any intervening writer."""
        return write_toml(self.path, self.data if data is None else data,
                          expected_revision=self.revision)


def _read_version(path: Path) -> tuple[bytes | None, str]:
    try:
        with path.open("rb") as handle:
            before = os.fstat(handle.fileno())
            raw = handle.read()
            after = os.fstat(handle.fileno())
    except FileNotFoundError:
        return None, MISSING_REVISION
    def identity(value: os.stat_result) -> tuple[int, ...]:
        return (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns)
    if identity(before) != identity(after):
        raise ConfigConflictError(f"Configuration changed while reading {path}; reload and retry")
    # Include file identity as well as content: replacing A with B and then A
    # must not make an old editor's revision current again.
    digest = hashlib.sha256(repr(identity(after)).encode("ascii") + b"\0" + raw).hexdigest()
    return raw, digest


def read_snapshot(path: Path) -> ConfigDocument:
    path = path.resolve()
    raw, revision = _read_version(path)
    return ConfigDocument(path, {} if raw is None else _parse_toml(raw.decode("utf-8")), revision)


@contextmanager
def _config_lock(path: Path) -> Iterator[None]:
    # Lock a stable sibling, never the TOML inode replaced by a commit. All
    # writers use canonical paths, so symlink aliases share this lock.
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(f"{path}.lock", flags, 0o600)
    try:
        os.fchmod(fd, 0o600)
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        os.close(fd)


def default_config_template() -> str:
    try:
        return resources.files("auto_xdp").joinpath("default_config.toml").read_text()
    except (FileNotFoundError, ModuleNotFoundError):
        return (Path(__file__).resolve().parents[2] / "config.toml").read_text()


def load_toml(path: Path) -> dict[str, Any]:
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return {}
    return _parse_toml(text)


def _parse_toml(text: str) -> dict[str, Any]:
    if tomllib is not None:
        return tomllib.loads(text)
    return _parse_toml_fallback(text)


def _parse_toml_fallback(text: str) -> dict[str, Any]:
    def split_items(raw: str) -> list[str]:
        items: list[str] = []
        cur: list[str] = []
        depth = 0
        in_str = False
        escape = False
        string_char: str | None = None
        for ch in raw[1:-1]:
            if escape:
                cur.append(ch)
                escape = False
                continue
            if ch == "\\" and in_str:
                cur.append(ch)
                escape = True
                continue
            if ch in ('"', "'") and not in_str:
                in_str = True
                string_char = ch
                cur.append(ch)
                continue
            if ch == string_char and in_str:
                in_str = False
                string_char = None
                cur.append(ch)
                continue
            if not in_str:
                if ch in ("[", "{"):
                    depth += 1
                elif ch in ("]", "}"):
                    depth -= 1
                elif ch == "," and depth == 0:
                    item = "".join(cur).strip()
                    if item:
                        items.append(item)
                    cur = []
                    continue
            cur.append(ch)
        item = "".join(cur).strip()
        if item:
            items.append(item)
        return items

    def parse_value(raw: str) -> Any:
        raw = raw.strip()
        if raw.startswith('"'):
            try:
                return json.loads(raw)
            except json.JSONDecodeError:
                if not raw.endswith('"') or len(raw) < 2:
                    raise ValueError(f"Malformed string value in config: {raw!r}")
                return raw[1:-1]
        if raw.startswith("'"):
            if not raw.endswith("'") or len(raw) < 2:
                raise ValueError(f"Malformed string value in config: {raw!r}")
            return raw[1:-1]
        if raw == "true":
            return True
        if raw == "false":
            return False
        if raw.startswith("["):
            return [parse_value(item) for item in split_items(raw)]
        if raw.startswith("{"):
            return {
                key.strip(): parse_value(value)
                for key, sep, value in (part.partition("=") for part in split_items(raw))
                if sep
            }
        try:
            return int(raw)
        except ValueError:
            pass
        try:
            return float(raw)
        except ValueError:
            return raw

    root: dict[str, Any] = {}
    current: dict[str, Any] = root
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        table_match = re.match(r"^\[([^\[\]]+)\]$", line)
        if table_match:
            current = root
            for key in table_match.group(1).split("."):
                current = current.setdefault(key.strip(), {})
            continue
        key_match = re.match(r"^([A-Za-z0-9_-]+)\s*=\s*(.+)$", line)
        if key_match:
            current[key_match.group(1)] = parse_value(key_match.group(2).strip())
    return root


def _fmt_key(key: Any) -> str:
    key = str(key)
    return key if _BARE_KEY_RE.match(key) else json.dumps(key)


def _fmt_path(parts: list[Any]) -> str:
    return ".".join(_fmt_key(part) for part in parts)


def _is_array_of_tables(value: Any) -> bool:
    return isinstance(value, list) and bool(value) and all(isinstance(item, dict) for item in value)


def _fmt_value(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int) and not isinstance(value, bool):
        return str(value)
    if isinstance(value, float):
        if math.isnan(value) or math.isinf(value):
            raise ValueError("TOML does not support NaN or infinity")
        return repr(value)
    if isinstance(value, str):
        return json.dumps(value)
    if isinstance(value, list):
        return "[" + ", ".join(_fmt_value(item) for item in value) + "]"
    if isinstance(value, dict):
        inner = ", ".join(f"{_fmt_key(k)} = {_fmt_value(v)}" for k, v in value.items())
        return "{ " + inner + " }"
    raise TypeError(f"unsupported TOML value: {type(value).__name__}")


def _emit_table_body(table: dict[str, Any], path_parts: list[Any]) -> list[str]:
    lines: list[str] = []
    scalar_items: list[tuple[str, Any]] = []
    array_table_items: list[tuple[str, list[dict[str, Any]]]] = []
    table_items: list[tuple[str, dict[str, Any]]] = []

    for key, value in table.items():
        if _is_array_of_tables(value):
            array_table_items.append((key, value))
        elif isinstance(value, dict):
            table_items.append((key, value))
        else:
            scalar_items.append((key, value))

    for key, value in scalar_items:
        lines.append(f"{_fmt_key(key)} = {_fmt_value(value)}")

    for key, value in array_table_items:
        if lines:
            lines.append("")
        child_path = path_parts + [key]
        for idx, item in enumerate(value):
            if idx > 0:
                lines.append("")
            lines.append(f"[[{_fmt_path(child_path)}]]")
            lines.extend(_emit_table_body(item, child_path))

    for key, value in table_items:
        if lines:
            lines.append("")
        child_path = path_parts + [key]
        lines.append(f"[{_fmt_path(child_path)}]")
        lines.extend(_emit_table_body(value, child_path))

    return lines


def _stage_text(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.")
    staged = Path(name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as tmp:
            os.fchmod(tmp.fileno(), 0o600)
            if os.geteuid() == 0:
                os.fchown(tmp.fileno(), 0, 0)
            tmp.write(text)
            tmp.flush()
            os.fsync(tmp.fileno())
    except BaseException:
        staged.unlink(missing_ok=True)
        raise
    return staged


def _toml_text(data: dict[str, Any]) -> str:
    return "\n".join(_emit_table_body(data, [])).rstrip() + "\n"


def stage_toml(path: Path, data: dict[str, Any]) -> Path:
    """Create the durable same-directory stage used by the approval journal."""
    return _stage_text(path, _toml_text(data))


@contextmanager
def checked_revision(path: Path, expected: str) -> Iterator[None]:
    """Hold the common writer lock from revision validation through publication."""
    with _config_lock(path):
        if _read_version(path)[1] != expected:
            raise ConfigConflictError(f"Configuration changed at {path}; reload and retry (no changes saved)")
        yield


def _atomic_write(path: Path, text: str) -> str:
    staged = _stage_text(path, text)
    try:
        staged.replace(path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
        return _read_version(path)[1]
    finally:
        staged.unlink(missing_ok=True)


def write_toml(path: Path, data: dict[str, Any], *, expected_revision: str = MISSING_REVISION) -> str:
    """Publish a versioned edit. The default revision allows initial creation."""
    text = _toml_text(data)
    path = path.resolve()
    with checked_revision(path, expected_revision):
        return _atomic_write(path, text)


def load_config(path: str) -> tuple[Path, dict[str, Any]]:
    config_path = Path(path)
    return config_path, load_toml(config_path)


def ensure_config_exists(path: Path, *, template: str | None = None) -> bool:
    """Create a template once, without overwriting a concurrent initialization."""
    path = path.resolve()
    with _config_lock(path):
        if _read_version(path)[1] != MISSING_REVISION:
            return False
        text = default_config_template() if template is None else template
        _parse_toml(text)
        _atomic_write(path, text)
        return True
