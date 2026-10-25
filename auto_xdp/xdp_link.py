"""Decode XDP attachment modes from iproute2's RTM_GETLINK JSON output."""
from __future__ import annotations

import json
import sys


_MODES = {0: "off", 1: "native", 2: "generic", 3: "offload", 4: "multi"}


def xdp_mode_from_link(data: object) -> str:
    """Return the reported mode, keeping missing or unreadable state distinct."""
    if isinstance(data, list):
        if not data:
            return "missing"
        if len(data) != 1:
            return "unknown"
        data = data[0]
    if not isinstance(data, dict) or not any(
        key in data for key in ("ifindex", "ifname", "xdp")
    ):
        return "unknown"
    if "xdp" not in data:
        return "off"
    xdp = data["xdp"]
    if not isinstance(xdp, dict):
        return "unknown"
    mode = xdp.get("mode")
    if type(mode) is not int or mode not in _MODES:
        return "unknown"
    attached = xdp.get("attached", [])
    if not isinstance(attached, list):
        return "unknown"
    for entry in attached:
        if not isinstance(entry, dict) or type(entry.get("mode")) is not int:
            return "unknown"
        entry_mode = entry["mode"]
        if entry_mode not in (1, 2, 3) or (mode != 4 and entry_mode != mode):
            return "unknown"
    return _MODES[mode]


def main() -> int:
    try:
        mode = xdp_mode_from_link(json.load(sys.stdin))
    except (ValueError, OSError):
        mode = "unknown"
    print(mode)
    return int(mode == "unknown")


if __name__ == "__main__":
    raise SystemExit(main())
