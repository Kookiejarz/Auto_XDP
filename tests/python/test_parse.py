"""Tests for the production XDP counter dump parser."""

from unittest import mock

import auto_xdp.admin_cli as admin_cli

from tests.python.support import REPO_ROOT


def _counter_enum() -> dict[str, int]:
    values: dict[str, int] = {}
    for line in (REPO_ROOT / "bpf/include/common.h").read_text().splitlines():
        stripped = line.strip()
        if not stripped.startswith("CNT_") or "=" not in stripped:
            continue
        name, _, rest = stripped.partition("=")
        token = rest.split(",", 1)[0].split("//", 1)[0].strip()
        if token.isdigit():
            values[name.strip()] = int(token)
    return values


def test_counter_names_cover_current_drop_reasons():
    enum = _counter_enum()
    names = admin_cli._XDP_COUNTER_NAMES
    assert names[enum["CNT_TCP_NEW_ALLOW"]] == "TCP_NEW_ALLOW"
    assert names[enum["CNT_BOGON_DROP"]] == "BOGON_DROP"
    assert names[enum["CNT_TCP_CONN_LIMIT_DROP"]] == "TCP_CONN_LIMIT_DROP"
    assert names[enum["CNT_TCP_CONN_PREFIX_LIMIT_DROP"]] == "TCP_CONN_PREFIX_LIMIT_DROP"
    assert names[enum["CNT_TCP_CONN_PORT_LIMIT_DROP"]] == "TCP_CONN_PORT_LIMIT_DROP"
    assert names[enum["CNT_ABUSEIPDB_DROP"]] == "ABUSEIPDB_DROP"
    assert len(names) == enum["CNT_MAX"]


def test_read_xdp_rows_uses_named_counters_and_byte_totals(tmp_path):
    pin = tmp_path / "xdp_fw"
    pin.mkdir()
    (pin / "pkt_counters").write_bytes(b"")
    enum = _counter_enum()

    dump = [
        {"key": ["0x01", "0x00", "0x00", "0x00"], "values": [{"cpu": 0, "value": 5}]},
        {"key": enum["CNT_TCP_CONN_LIMIT_DROP"], "values": [{"cpu": 0, "value": 10}]},
        {"key": enum["CNT_ABUSEIPDB_DROP"], "values": [{"cpu": 0, "value": 2}]},
    ]

    with mock.patch.object(admin_cli.shutil, "which", return_value="/usr/sbin/bpftool"), \
         mock.patch.object(admin_cli.subprocess, "check_output", return_value=b"[]"), \
         mock.patch.object(admin_cli.json, "loads", return_value=dump), \
         mock.patch.object(admin_cli, "_read_byte_counters", return_value=(100, 20, 17, 12)):
        rows = admin_cli._read_xdp_rows(str(pin))

    by_name = {name: (packets, nbytes) for name, packets, nbytes in rows}
    assert by_name["TCP_ESTABLISHED"] == (5, -1)
    assert by_name["TCP_CONN_LIMIT_DROP"] == (10, -1)
    assert by_name["ABUSEIPDB_DROP"] == (2, -1)
    assert by_name["XDP_TOTAL"] == (17, 100)
    assert by_name["XDP_DROP_TOTAL"] == (12, 20)
