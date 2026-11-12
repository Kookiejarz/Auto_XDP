"""Traffic-total map layouts and their public statistics output."""
import json
import sys
from unittest import mock

import pytest

from auto_xdp.admin import stats


FIELDS = ("total_bytes", "drop_bytes", "total_pkts", "drop_pkts")


def raw_value(*values: int) -> list[str]:
    return [f"0x{byte:02x}" for value in values for byte in value.to_bytes(8, sys.byteorder)]


@pytest.mark.parametrize("encoding", ["raw", "btf", "formatted"])
def test_percpu_struct_totals_include_every_cpu_and_full_u64(encoding):
    cpus = [(2**40 + 300, 200, 3, 2), (1000, 400, 10, 4), (0, 0, 0, 0)]
    values = [{"cpu": cpu, "value": raw_value(*value) if encoding == "raw"
               else dict(zip(FIELDS, value))} for cpu, value in enumerate(cpus)]
    row = {"key": ["0x00"] * 4 if encoding == "raw" else 0, "values": values}
    data = [{"formatted": row}] if encoding == "formatted" else [row]
    assert stats._decode_byte_counters(data) == (2**40 + 1300, 600, 13, 6)


@pytest.mark.parametrize("entries", [2, 4])
@pytest.mark.parametrize("encoding", ["raw", "integer", "hex"])
def test_legacy_maps_remain_readable_during_upgrade(entries, encoding):
    totals = (300, 200, 3, 2)
    data = []
    for index, total in enumerate(totals[:entries]):
        encode = (lambda value: raw_value(value)) if encoding == "raw" else (
            hex if encoding == "hex" else int)
        data.append({"key": index, "values": [
            {"cpu": 0, "value": encode(total - 1)}, {"cpu": 1, "value": encode(1)},
        ]})
    expected = totals if entries == 4 else (300, 200, -1, -1)
    assert stats._decode_byte_counters(data) == expected


def test_zero_struct_totals_are_available():
    assert stats._decode_byte_counters([
        {"key": 0, "values": [{"cpu": 0, "value": dict.fromkeys(FIELDS, 0)}]},
    ]) == (0, 0, 0, 0)


@pytest.mark.parametrize("data", [
    [], {}, None,
    [{"key": 0, "values": []}],
    [{"key": 0, "values": [{"cpu": 0, "value": {"total_bytes": 100}}]}],
    [{"key": 0, "value": ["0x00"] * 24}],
    [{"key": 0, "value": ["invalid"] * 32}],
    [{"key": 1, "value": dict.fromkeys(FIELDS, 0)}],
    [{"key": 0, "values": [
        {"cpu": 0, "value": dict.fromkeys(FIELDS, 0)}, {"cpu": 1, "value": 5},
    ]}],
])
def test_missing_or_invalid_totals_are_unknown_not_zero(data):
    assert stats._decode_byte_counters(data) == (-1, -1, -1, -1)


@pytest.mark.component
def test_stats_rows_use_consolidated_totals(tmp_path):
    for name in ("pkt_counters", "byte_counters"):
        (tmp_path / name).touch()
    dumps = [
        [{"key": 4, "values": [{"cpu": 0, "value": 99}]}],
        [{"key": 0, "values": [
            {"cpu": 0, "value": dict(zip(FIELDS, (300, 200, 3, 2)))},
            {"cpu": 1, "value": dict(zip(FIELDS, (1000, 400, 10, 4)))},
        ]}],
    ]
    with mock.patch.object(stats.shutil, "which", return_value="bpftool"), \
         mock.patch.object(stats.subprocess, "check_output", side_effect=[
             json.dumps(dump).encode() for dump in dumps]):
        rows = {name: (packets, size) for name, packets, size in stats._read_xdp_rows(str(tmp_path))}
    assert rows["XDP_TOTAL"] == (13, 1300)
    assert rows["XDP_DROP_TOTAL"] == (6, 600)
    assert rows["UDP_DROP"] == (99, -1)
