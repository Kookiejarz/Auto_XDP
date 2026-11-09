"""Only the module namespace drives managed protection; drafts stay inactive."""
from pathlib import Path

import pytest

from auto_xdp import config
from auto_xdp.admin import config_file


def test_module_settings_and_overrides_are_read_from_the_new_namespace():
    values = config.parse_toml_config({"modules": {
        "syncookie": {"enabled": True, "default_mode": "always",
                      "by_port": {"443": "auto"}, "port_rate_by_port": {"443": 5000}},
    }})
    assert values.SYNCOOKIE_ENABLED
    assert values.SYNCOOKIE_DEFAULT_MODE == "always"
    assert values._SYNCOOKIE_BY_PORT == {443: "auto"}
    assert values._SYNCOOKIE_PORT_RATE_BY_PORT == {443: 5000}


def test_drafts_do_not_enable_or_change_running_protection():
    values = config.parse_toml_config({"modules": {
        "syncookie": {"enabled": True, "default_mode": "auto",
                      "draft": {"enabled": False, "default_mode": "always"}},
    }})
    assert values.SYNCOOKIE_ENABLED and values.SYNCOOKIE_DEFAULT_MODE == "auto"


@pytest.mark.parametrize("section", ["icmp", "syncookie", "handler_settings"])
@pytest.mark.parametrize("with_new", [False, True])
def test_retired_sections_are_rejected_even_when_new_config_is_also_present(section, with_new):
    data = {section: {"enabled": True}}
    if with_new:
        data["modules"] = {"icmp": {"enabled": False}}
    before = config.snapshot_config()
    with pytest.raises(ValueError, match="Unsupported module configuration"):
        config.apply_toml_config(data)
    assert config.snapshot_config() == before


@pytest.mark.parametrize("data", [
    {"modules": []}, {"modules": {"icmp": True}},
    {"modules": {"icmp": {"enabled": "true"}}},
    {"modules": {"syncookie": {"enabled": 1}}},
    {"modules": {"custom": {"draft": []}}},
    {"modules": {"custom": {"draft": {"enabled": "false"}}}},
])
def test_malformed_module_configuration_is_rejected(data):
    with pytest.raises(ValueError, match="modules"):
        config.parse_toml_config(data)


@pytest.mark.parametrize("name", ["config.toml", "auto_xdp/default_config.toml"])
def test_shipped_templates_use_current_module_config(name):
    data = config_file.load_toml(Path(__file__).resolve().parents[2] / name)
    assert {"syncookie"} <= config.module_configs(data).keys()
    config.parse_toml_config(data)
