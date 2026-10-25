import json
import subprocess
from unittest import mock

import pytest

from auto_xdp.admin.detect import iface_xdp_state
from auto_xdp.tui.app import _xdp_attach_mode
from auto_xdp.xdp_link import xdp_mode_from_link


@pytest.mark.parametrize("name", ["eth0", "xdp0", "xdpgeneric0", "xdpoffload0"])
def test_names_and_aliases_do_not_imply_an_attachment(name):
    assert xdp_mode_from_link([{
        "ifname": name, "ifalias": "xdpgeneric prog/xdp native", "link_type": "ether",
    }]) == "off"


@pytest.mark.parametrize("number,expected", [(0, "off"), (1, "native"), (2, "generic"), (3, "offload")])
@pytest.mark.parametrize("nested", [False, True])
def test_modes_use_kernel_values_with_old_and_nested_program_schema(number, expected, nested):
    prog = {"id": 77, "name": "xdpgeneric_fake", "btf_id": 12}
    xdp = {"mode": number, **({"prog": prog} if nested else prog)}
    if number:
        xdp["attached"] = [{"mode": number, "prog": prog}]
    assert xdp_mode_from_link([{"ifname": "eth0", "xdp": xdp}]) == expected


def test_multiple_modes_are_not_reported_as_one_native_program():
    data = [{"ifname": "eth0", "xdp": {
        "mode": 4, "attached": [
            {"mode": 1, "prog": {"id": 77}},
            {"mode": 3, "prog": {"id": 88}},
        ],
    }}]
    assert xdp_mode_from_link(data) == "multi"


@pytest.mark.parametrize("data", [
    None, {}, "xdpgeneric", [None], [{"ifname": "a"}, {"ifname": "b"}],
    [{"ifname": "eth0", "xdp": None}],
    [{"ifname": "eth0", "xdp": {"prog": {"id": 77}}}],
    [{"ifname": "eth0", "xdp": {"mode": True}}],
    [{"ifname": "eth0", "xdp": {"mode": "native"}}],
    [{"ifname": "eth0", "xdp": {"mode": 99}}],
    [{"ifname": "eth0", "xdp": {"mode": 1, "attached": {}}}],
    [{"ifname": "eth0", "xdp": {"mode": 1, "attached": [{"mode": 2}]}}],
])
def test_unreadable_or_inconsistent_state_is_unknown(data):
    assert xdp_mode_from_link(data) == "unknown"


def test_empty_link_dump_is_missing():
    assert xdp_mode_from_link([]) == "missing"


@pytest.mark.component
@pytest.mark.parametrize("data,expected", [
    ([{"ifname": "xdpgeneric0"}], "off"),
    ([{"ifname": "xdp0", "xdp": {"mode": 2}}], "generic"),
    ([{"ifname": "eth0", "xdp": {"mode": 1}}], "native"),
    ([{"ifname": "eth0", "xdp": {"mode": 3}}], "offload"),
    ([{"ifname": "eth0", "xdp": {"mode": 4}}], "multi"),
    ([], "missing"),
])
def test_cli_and_tui_share_structured_mode_detection(data, expected):
    with mock.patch("auto_xdp.admin.detect.subprocess.check_output", return_value=json.dumps(data)) as query:
        assert iface_xdp_state("eth0") == expected
        assert query.call_args.args[0] == ["ip", "-j", "-d", "link", "show", "dev", "eth0"]
        displayed = expected if expected == "missing" else f"xdp {expected}"
        assert _xdp_attach_mode("eth0") == displayed


@pytest.mark.component
@pytest.mark.parametrize("output", ["", "2: eth0: xdpgeneric prog/xdp id 77", "not JSON"])
def test_invalid_json_has_no_text_fallback(output):
    with mock.patch("auto_xdp.admin.detect.subprocess.check_output", return_value=output):
        assert iface_xdp_state("eth0") == "unknown"
        assert _xdp_attach_mode("eth0") == "unknown"


@pytest.mark.component
@pytest.mark.parametrize("error,expected", [
    (FileNotFoundError("ip unavailable"), "unknown"),
    (subprocess.CalledProcessError(1, "ip", stderr="Operation not permitted"), "unknown"),
    (subprocess.CalledProcessError(1, "ip", stderr='Device "eth0" does not exist.'), "missing"),
])
def test_query_failure_is_distinct_from_no_attachment(error, expected):
    with mock.patch("auto_xdp.admin.detect.subprocess.check_output", side_effect=error):
        assert iface_xdp_state("eth0") == expected
