"""Collect backend counters and preserve cumulative totals across map reloads."""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

from auto_xdp.telemetry.events import COUNTER_NAMES


_NFT_CHAIN = "input"


def _decode_byte_counters(data: Any) -> tuple[int, int, int, int]:
    """Decode struct totals and legacy 2/4-entry scalar bpftool dumps."""
    unavailable = (-1, -1, -1, -1)
    fields = ("total_bytes", "drop_bytes", "total_pkts", "drop_pkts")

    def integer(value: Any) -> int:
        if isinstance(value, list):
            raw = bytes(int(v, 0) if isinstance(v, str) else v for v in value)
            return int.from_bytes(raw, sys.byteorder)
        return int(value, 0) if isinstance(value, str) else int(value)

    def record(value: Any) -> tuple[int, ...]:
        if isinstance(value, dict):
            return tuple(integer(value[field]) for field in fields)
        if isinstance(value, list):
            if len(value) == 32:
                return tuple(integer(value[offset:offset + 8]) for offset in range(0, 32, 8))
            if len(value) != 8:
                raise ValueError("unexpected traffic counter value size")
        return (integer(value),)

    if not isinstance(data, list) or not data:
        return unavailable
    scalar_totals: dict[int, int] = {}
    try:
        for raw_row in data:
            row = raw_row.get("formatted", raw_row)
            index = integer(row["key"])
            if "values" in row:
                values = [record(item["value"] if isinstance(item, dict) else item)
                          for item in row["values"]]
            else:
                values = [record(row["value"])]
            if not values:
                return unavailable
            if len(values[0]) == 4:
                if index != 0 or len(data) != 1 or any(len(value) != 4 for value in values):
                    return unavailable
                totals = [sum(value[i] for value in values) for i in range(4)]
                return totals[0], totals[1], totals[2], totals[3]
            if any(len(value) != 1 for value in values):
                return unavailable
            scalar_totals[index] = sum(value[0] for value in values)
    except (AttributeError, KeyError, TypeError, ValueError, OverflowError):
        # Missing or malformed telemetry must not look like a counter reset.
        return unavailable
    return (scalar_totals.get(0, -1), scalar_totals.get(1, -1),
            scalar_totals.get(2, -1), scalar_totals.get(3, -1))


def _read_byte_counters(bpf_pin_dir: str) -> tuple[int, int, int, int]:
    """Return (total_bytes, drop_bytes, total_pkts, drop_pkts); -1 when unavailable."""
    map_path = Path(bpf_pin_dir) / "byte_counters"
    if not map_path.exists():
        return -1, -1, -1, -1
    try:
        out = subprocess.check_output(
            ["bpftool", "-j", "map", "dump", "pinned", str(map_path)],
            stderr=subprocess.DEVNULL,
        )
        data = json.loads(out)
    except (subprocess.CalledProcessError, json.JSONDecodeError, OSError):
        return -1, -1, -1, -1

    return _decode_byte_counters(data)


def _read_xdp_rows(bpf_pin_dir: str) -> list[tuple[str, int, int]]:
    map_path = Path(bpf_pin_dir) / "pkt_counters"
    if not map_path.exists():
        raise RuntimeError(f"XDP counters not found at {map_path}")

    if not shutil.which("bpftool"):
        raise RuntimeError("bpftool not found; cannot read XDP counters")

    try:
        out = subprocess.check_output(
            ["bpftool", "-j", "map", "dump", "pinned", str(map_path)],
            stderr=subprocess.DEVNULL,
        )
        data = json.loads(out)
    except (subprocess.CalledProcessError, json.JSONDecodeError, OSError) as exc:
        hint = ""
        if hasattr(os, "geteuid") and os.geteuid() != 0:
            hint = " (reading pinned BPF maps needs root; try: sudo axdp stats)"
        raise RuntimeError(f"Failed to read XDP counters: {exc}{hint}") from exc

    def _bytelist_to_int(lst: list) -> int:
        try:
            raw = bytes((int(b, 0) if isinstance(b, str) else int(b)) & 0xFF for b in lst)
            return int.from_bytes(raw, "little")
        except (ValueError, TypeError):
            return 0

    def _sum_percpu(v: Any) -> int:
        if isinstance(v, list):
            total = 0
            for e in v:
                if isinstance(e, dict):
                    val = e.get("value", 0)
                    if isinstance(val, list):
                        total += _bytelist_to_int(val)
                    elif isinstance(val, int):
                        total += val
                    elif isinstance(val, str):
                        try:
                            total += int(val, 0)
                        except ValueError:
                            pass
                elif isinstance(e, str):
                    try:
                        total += int(e, 0)
                    except ValueError:
                        pass
                elif isinstance(e, int):
                    total += e
            return total
        if isinstance(v, int):
            return v
        if isinstance(v, str):
            try:
                return int(v, 0)
            except ValueError:
                return 0
        return 0

    def _parse_key(key: Any) -> int:
        if isinstance(key, int):
            return key
        if isinstance(key, str):
            try:
                return int(key, 0)
            except ValueError:
                return -1
        if isinstance(key, list):
            b = bytes((int(b, 0) if isinstance(b, str) else b) & 0xFF for b in key[:4])
            return int.from_bytes(b, "little")
        return -1

    key_packets: dict[int, int] = {}
    for row in data:
        v = row.get("values", row.get("value", 0))
        packets = _sum_percpu(v)
        k = _parse_key(row.get("key", -1))
        if k >= 0:
            key_packets[k] = key_packets.get(k, 0) + packets

    rows: list[tuple[str, int, int]] = []
    for idx in range(len(COUNTER_NAMES)):
        packets = key_packets.get(idx, -1)
        rows.append((COUNTER_NAMES[idx], packets, -1))

    for idx in sorted(key_packets.keys()):
        if idx >= len(COUNTER_NAMES):
            rows.append((f"COUNTER_{idx}", key_packets[idx], -1))

    total_bytes, drop_bytes, total_pkts, drop_pkts = _read_byte_counters(bpf_pin_dir)
    # Diagnostic stages overlap (including telemetry and TC handoff). A missing
    # packet-total map is unknown, never the sum of diagnostic counters.
    rows.append(("XDP_TOTAL", total_pkts, total_bytes))
    rows.append(("XDP_DROP_TOTAL", drop_pkts, drop_bytes))
    return rows


def read_xdp_map_id(bpf_pin_dir: str) -> str:
    map_path = str(Path(bpf_pin_dir) / "pkt_counters")
    try:
        result = subprocess.run(
            ["bpftool", "map", "show", "pinned", map_path],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            return "-"
        first_line = result.stdout.splitlines()[0] if result.stdout.strip() else ""
        m = re.match(r"^(\d+):", first_line)
        if m:
            return m.group(1)
    except OSError:
        pass
    return "-"


def _read_nft_rows(nft_family: str, nft_table: str, nft_chain: str) -> list[tuple[str, int, int]]:
    try:
        result = subprocess.run(
            ["nft", "-a", "list", "chain", nft_family, nft_table, nft_chain],
            capture_output=True,
            text=True,
        )
        text = result.stdout
    except OSError:
        text = ""
    m = re.search(r"counter packets (\d+) bytes (\d+) drop", text)
    if not m:
        return [("NFT_DROP", 0, 0)]
    return [("NFT_DROP", int(m.group(1)), int(m.group(2)))]


def _read_iface_row(iface: str) -> tuple[str, int, int] | None:
    stats_dir = Path(f"/sys/class/net/{iface}/statistics")
    rx_pkt = stats_dir / "rx_packets"
    rx_bytes = stats_dir / "rx_bytes"
    try:
        packets = int(rx_pkt.read_text().strip())
        b = int(rx_bytes.read_text().strip())
        return ("IFACE_RX", packets, b)
    except OSError:
        return None


def _load_stats_state(state_file: Path) -> dict:
    try:
        return json.loads(state_file.read_text())
    except (OSError, json.JSONDecodeError):
        return {}


def _save_stats_state(state_file: Path, data: dict) -> None:
    try:
        state_file.parent.mkdir(parents=True, exist_ok=True)
        tmp = Path(str(state_file) + f".tmp.{os.getpid()}")
        tmp.write_text(json.dumps(data))
        tmp.replace(state_file)
    except OSError:
        pass


def _apply_xdp_accumulator(
    rows: list[tuple[str, int, int]],
    backend: str,
    iface: str,
    map_id: str,
    state_file: Path,
) -> list[tuple[str, int, int]]:
    if backend != "xdp":
        return rows

    # Find current totals
    current_total: int | None = None
    current_drop: int | None = None
    current_total_bytes: int = -1
    current_drop_bytes: int = -1
    for name, packets, b in rows:
        if name == "XDP_TOTAL":
            current_total = packets
            current_total_bytes = b
        elif name == "XDP_DROP_TOTAL":
            current_drop = packets
            current_drop_bytes = b

    if current_total is None or current_drop is None or current_total < 0 or current_drop < 0:
        # Missing telemetry is not a counter reset; preserve the last valid baseline.
        return rows

    state = _load_stats_state(state_file)
    prev_backend = state.get("backend", "")
    prev_iface = state.get("iface", "")
    prev_map_id = state.get("map_id", "")
    prev_raw_total = state.get("raw_total")
    prev_raw_drop = state.get("raw_drop")
    prev_acc_total = state.get("acc_total")
    prev_acc_drop = state.get("acc_drop")
    prev_raw_total_bytes = state.get("raw_total_bytes")
    prev_raw_drop_bytes = state.get("raw_drop_bytes")
    prev_acc_total_bytes = state.get("acc_total_bytes")
    prev_acc_drop_bytes = state.get("acc_drop_bytes")

    acc_total = current_total
    acc_drop = current_drop
    acc_total_bytes = current_total_bytes
    acc_drop_bytes = current_drop_bytes

    same_context = (
        prev_backend == backend
        and prev_iface == iface
        and prev_map_id == map_id
        and prev_map_id != "-"
        and map_id != "-"
        and isinstance(prev_raw_total, int)
        and isinstance(prev_raw_drop, int)
        and isinstance(prev_acc_total, int)
        and isinstance(prev_acc_drop, int)
    )
    # map_id changed (BPF reload) or bpftool failed — preserve history if same iface
    same_iface = (
        prev_backend == backend
        and prev_iface == iface
        and isinstance(prev_acc_total, int)
        and isinstance(prev_acc_drop, int)
    )

    if same_context:
        # same_context already verified these are ints via isinstance above.
        assert isinstance(prev_raw_total, int) and isinstance(prev_acc_total, int)
        assert isinstance(prev_raw_drop, int) and isinstance(prev_acc_drop, int)
        if current_total >= prev_raw_total:
            acc_total = prev_acc_total + (current_total - prev_raw_total)
        else:
            acc_total = prev_acc_total + current_total
        if current_drop >= prev_raw_drop:
            acc_drop = prev_acc_drop + (current_drop - prev_raw_drop)
        else:
            acc_drop = prev_acc_drop + current_drop

        if (
            current_total_bytes >= 0
            and isinstance(prev_raw_total_bytes, int) and prev_raw_total_bytes >= 0
            and isinstance(prev_acc_total_bytes, int) and prev_acc_total_bytes >= 0
        ):
            if current_total_bytes >= prev_raw_total_bytes:
                acc_total_bytes = prev_acc_total_bytes + (current_total_bytes - prev_raw_total_bytes)
            else:
                acc_total_bytes = prev_acc_total_bytes + current_total_bytes

        if (
            current_drop_bytes >= 0
            and isinstance(prev_raw_drop_bytes, int) and prev_raw_drop_bytes >= 0
            and isinstance(prev_acc_drop_bytes, int) and prev_acc_drop_bytes >= 0
        ):
            if current_drop_bytes >= prev_raw_drop_bytes:
                acc_drop_bytes = prev_acc_drop_bytes + (current_drop_bytes - prev_raw_drop_bytes)
            else:
                acc_drop_bytes = prev_acc_drop_bytes + current_drop_bytes

    elif same_iface:
        # map_id changed (BPF reload) or bpftool couldn't get map_id:
        # treat current raw as new counts on top of previous accumulated total
        # same_iface already verified these are ints via isinstance above.
        assert isinstance(prev_acc_total, int) and isinstance(prev_acc_drop, int)
        acc_total = prev_acc_total + current_total
        acc_drop = prev_acc_drop + current_drop

        if (
            current_total_bytes >= 0
            and isinstance(prev_acc_total_bytes, int) and prev_acc_total_bytes >= 0
        ):
            acc_total_bytes = prev_acc_total_bytes + current_total_bytes

        if (
            current_drop_bytes >= 0
            and isinstance(prev_acc_drop_bytes, int) and prev_acc_drop_bytes >= 0
        ):
            acc_drop_bytes = prev_acc_drop_bytes + current_drop_bytes

    # Don't persist state when map_id is unknown — we can't detect future context changes
    if map_id == "-":
        updated = []
        for name, packets, b in rows:
            if name == "XDP_TOTAL":
                updated.append(("XDP_TOTAL", acc_total, acc_total_bytes))
            elif name == "XDP_DROP_TOTAL":
                updated.append(("XDP_DROP_TOTAL", acc_drop, acc_drop_bytes))
            else:
                updated.append((name, packets, b))
        return updated

    _save_stats_state(
        state_file,
        {
            "backend": backend,
            "iface": iface,
            "map_id": map_id,
            "raw_total": current_total,
            "raw_drop": current_drop,
            "acc_total": acc_total,
            "acc_drop": acc_drop,
            "raw_total_bytes": current_total_bytes,
            "raw_drop_bytes": current_drop_bytes,
            "acc_total_bytes": acc_total_bytes,
            "acc_drop_bytes": acc_drop_bytes,
        },
    )

    updated = []
    for name, packets, b in rows:
        if name == "XDP_TOTAL":
            updated.append(("XDP_TOTAL", acc_total, acc_total_bytes))
        elif name == "XDP_DROP_TOTAL":
            updated.append(("XDP_DROP_TOTAL", acc_drop, acc_drop_bytes))
        else:
            updated.append((name, packets, b))
    return updated


def collect_stats_rows(
    backend: str,
    bpf_pin_dir: str,
    iface: str,
    nft_family: str,
    nft_table: str,
    state_file: Path,
) -> tuple[list[tuple[str, int, int]], str]:
    map_id = "-"
    if backend == "xdp":
        rows = _read_xdp_rows(bpf_pin_dir)
        map_id = read_xdp_map_id(bpf_pin_dir)
        iface_row = _read_iface_row(iface)
        rows = _apply_xdp_accumulator(rows, backend, iface, map_id, state_file)
    else:
        rows = _read_nft_rows(nft_family, nft_table, _NFT_CHAIN)
        iface_row = _read_iface_row(iface)

    if iface_row is not None:
        rows = list(rows) + [iface_row]

    return rows, map_id
