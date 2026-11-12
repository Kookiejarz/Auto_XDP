"""Port inventory contracts for the nftables output shared by CLI and TUI."""

import json
import subprocess
from unittest import mock

import pytest

from auto_xdp.admin import ports


pytestmark = pytest.mark.component

# Real nftables 1.1.6 output from assets/readme/capture/tcp-ports.json.
CAPTURED_TCP_SET = b'{"nftables": [{"metainfo": {"version": "1.1.6", "release_name": "Commodore Bullmoose #7", "json_schema_version": 1}}, {"set": {"family": "inet", "name": "tcp_ports", "table": "auto_xdp", "type": "inet_service", "handle": 4, "elem": [8080, 9100]}}]}'


def _read_ports(tcp_output, udp_output):
    with mock.patch.object(ports.shutil, "which", return_value="/usr/sbin/nft"), \
         mock.patch.object(ports.subprocess, "check_output", side_effect=[tcp_output, udp_output]) as run:
        result = ports.read_nft_ports("inet", "auto_xdp")
    assert [call.args[0] for call in run.call_args_list] == [
        ["nft", "-j", "list", "set", "inet", "auto_xdp", "tcp_ports"],
        ["nft", "-j", "list", "set", "inet", "auto_xdp", "udp_ports"],
    ]
    return result


def test_real_nft_116_set_output_includes_tcp_and_udp_ports():
    udp = json.dumps({"nftables": [{"set": {
        "family": "inet", "table": "auto_xdp", "name": "udp_ports",
        "type": "inet_service", "elem": [53, 5353],
    }}]}).encode()

    assert _read_ports(CAPTURED_TCP_SET, udp) == ([8080, 9100], [53, 5353])


@pytest.mark.parametrize("entry_type", ["set", "element"])
def test_supported_formats_sort_deduplicate_and_ignore_invalid_ports(entry_type):
    def output(values):
        return json.dumps({"nftables": [{entry_type: {"elem": values}}]}).encode()

    assert _read_ports(
        output([443, 22, 443, 65535, 0, -1, 65536, "80", 80.5, True, False, None, {}]),
        output([5353, 53, 53, 0, "123", True]),
    ) == ([22, 443, 65535], [53, 5353])


def test_mixed_set_and_legacy_element_records_merge_without_duplicates():
    output = json.dumps({"nftables": [
        {"metainfo": {"json_schema_version": 1}},
        {"set": {"elem": [443, 22]}},
        {"element": {"elem": [8080, 443]}},
    ]}).encode()

    assert _read_ports(output, b'{"nftables": [{"set": {"name": "udp_ports"}}]}') == (
        [22, 443, 8080], [],
    )


@pytest.mark.parametrize("tcp_output", [
    b"not JSON",
    subprocess.CalledProcessError(1, ["nft"]),
    OSError("nft unavailable"),
])
def test_failed_tcp_read_does_not_discard_successful_udp_read(tcp_output):
    assert _read_ports(tcp_output, b'{"nftables": [{"set": {"elem": [53]}}]}') == ([], [53])


def test_missing_nft_command_is_reported():
    with mock.patch.object(ports.shutil, "which", return_value=None):
        with pytest.raises(RuntimeError, match="nft command not found"):
            ports.read_nft_ports("inet", "auto_xdp")
