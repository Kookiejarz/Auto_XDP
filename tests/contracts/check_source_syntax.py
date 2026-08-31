#!/usr/bin/env python3
"""Parse maintained Python and structured configuration sources."""

from __future__ import annotations

import ast
import json
import tokenize
from pathlib import Path
from typing import Any, Callable

try:
    import tomllib
except ModuleNotFoundError:  # Python 3.10 uses the project's tomli dependency.
    import tomli as tomllib  # type: ignore[no-redef]


ROOT = Path(__file__).resolve().parents[2]
MIN_PYTHON = (3, 10)
SOURCE_TREES = (
    ROOT / "auto_xdp",
    ROOT / "tests",
    ROOT / ".github" / "workflows",
)


def maintained_sources(suffixes: tuple[str, ...]) -> list[Path]:
    """Discover project-owned sources without descending into local tooling."""
    sources = [
        path
        for path in ROOT.iterdir()
        if path.is_file() and path.suffix in suffixes
    ]
    for source_tree in SOURCE_TREES:
        if not source_tree.is_dir():
            continue
        sources.extend(
            path
            for path in source_tree.rglob("*")
            if path.is_file() and path.suffix in suffixes
        )
    return sorted(set(sources))


def parse_python(path: Path) -> None:
    with tokenize.open(path) as source:
        ast.parse(
            source.read(),
            filename=str(path),
            feature_version=MIN_PYTHON,
        )


def parse_toml(path: Path) -> None:
    with path.open("rb") as source:
        tomllib.load(source)


def parse_json(path: Path) -> None:
    with path.open(encoding="utf-8") as source:
        json.load(source)


def parse_yaml(path: Path) -> None:
    try:
        import yaml
    except ModuleNotFoundError as exc:
        raise RuntimeError(
            "PyYAML is required for workflow syntax checks; install the dev dependencies"
        ) from exc

    with path.open(encoding="utf-8") as source:
        yaml.safe_load(source)


def check_group(
    label: str,
    suffixes: tuple[str, ...],
    parser: Callable[[Path], Any],
    *,
    required: bool = False,
) -> int:
    sources = maintained_sources(suffixes)
    if required and not sources:
        raise RuntimeError(f"no maintained {label} sources discovered")
    for path in sources:
        parser(path)
    print(f"[INFO] {label} syntax files={len(sources)}")
    return len(sources)


def main() -> int:
    check_group("python 3.10", (".py",), parse_python, required=True)
    check_group("toml", (".toml",), parse_toml)
    check_group("json", (".json",), parse_json)
    check_group("workflow yaml", (".yml", ".yaml"), parse_yaml, required=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
