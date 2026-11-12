"""TOML file loading and atomic writing shared by management clients."""
from __future__ import annotations

from importlib import resources
import json
import math
import os
import re
import tempfile
from pathlib import Path
from typing import Any

try:
    import tomllib
except ImportError:
    try:
        import tomli as tomllib
    except ImportError:
        tomllib = None


_BARE_KEY_RE = re.compile(r"^[A-Za-z0-9_-]+$")


def default_config_template() -> str:
    try:
        return resources.files("auto_xdp").joinpath("default_config.toml").read_text()
    except (FileNotFoundError, ModuleNotFoundError):
        return (Path(__file__).resolve().parents[2] / "config.toml").read_text()


def load_toml(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    if tomllib is not None:
        with path.open("rb") as fh:
            return tomllib.load(fh)
    return _parse_toml_fallback(path.read_text())


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


def write_toml(path: Path, data: dict[str, Any]) -> None:
    lines = _emit_table_body(data, [])
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", dir=path.parent, delete=False) as tmp:
        tmp.write("\n".join(lines).rstrip() + "\n")
        tmp_path = Path(tmp.name)
    tmp_path.chmod(0o600)
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        os.chown(tmp_path, 0, 0)
    tmp_path.replace(path)
    path.chmod(0o600)
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        os.chown(path, 0, 0)


def load_config(path: str) -> tuple[Path, dict[str, Any]]:
    config_path = Path(path)
    return config_path, load_toml(config_path)


def ensure_config_exists(path: Path) -> None:
    if path.exists():
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(default_config_template())
