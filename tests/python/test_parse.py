"""Tests for the production XDP counter dump parser."""

from unittest import mock

import auto_xdp.admin_cli as admin_cli


def test_counter_names_cover_current_drop_reasons():
    names = admin_cli._XDP_COUNTER_NAMES
    assert names[0] == "TCP_NEW_ALLOW"
    assert names[27] == "BOGON_DROP"
    assert "TCP_CONN_LIMIT_DROP" in names
    assert "TCP_CONN_PREFIX_LIMIT_DROP" in names
    assert "TCP_CONN_PORT_LIMIT_DROP" in names
    assert "ABUSEIPDB_DROP" in names
    assert len(names) == 35


def test_read_xdp_rows_uses_named_counters_and_byte_totals(tmp_path):
    pin = tmp_path / "xdp_fw"
    pin.mkdir()
    (pin / "pkt_counters").write_bytes(b"")

    dump = [
        {"key": ["0x01", "0x00", "0x00", "0x00"], "values": [{"cpu": 0, "value": 5}]},
        {"key": 28, "values": [{"cpu": 0, "value": 10}]},
        {"key": 34, "values": [{"cpu": 0, "value": 2}]},
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
