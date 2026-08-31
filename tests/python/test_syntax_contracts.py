from __future__ import annotations

from pathlib import Path

import pytest

from tests.contracts import check_source_syntax


def test_python_discovery_includes_test_infrastructure() -> None:
    relative = {
        path.relative_to(check_source_syntax.ROOT).as_posix()
        for path in check_source_syntax.maintained_sources((".py",))
    }

    assert "tests/conftest.py" in relative
    assert "tests/contracts/check_source_syntax.py" in relative


def test_python_parser_enforces_minimum_supported_version(tmp_path: Path) -> None:
    source = tmp_path / "newer_syntax.py"
    source.write_text("type NewSyntax = int\n", encoding="utf-8")

    with pytest.raises(SyntaxError):
        check_source_syntax.parse_python(source)


def test_toml_parser_rejects_duplicate_keys(tmp_path: Path) -> None:
    source = tmp_path / "invalid.toml"
    source.write_text("value = 1\nvalue = 2\n", encoding="utf-8")

    with pytest.raises(check_source_syntax.tomllib.TOMLDecodeError):
        check_source_syntax.parse_toml(source)


def test_json_parser_rejects_trailing_comma(tmp_path: Path) -> None:
    source = tmp_path / "invalid.json"
    source.write_text('{"value": 1,}\n', encoding="utf-8")

    with pytest.raises(check_source_syntax.json.JSONDecodeError):
        check_source_syntax.parse_json(source)


def test_yaml_parser_rejects_invalid_mapping(tmp_path: Path) -> None:
    yaml = pytest.importorskip("yaml")
    source = tmp_path / "invalid.yml"
    source.write_text("key: [unterminated\n", encoding="utf-8")

    with pytest.raises(yaml.YAMLError):
        check_source_syntax.parse_yaml(source)
