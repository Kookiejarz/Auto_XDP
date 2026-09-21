"""Production event decoding and relay-pressure contracts; no Linux required."""
import json
import queue
import socket
import struct
from unittest.mock import Mock

import pytest

import pkt_relay
from auto_xdp.telemetry.events import decode_event, describe_reason, reason_info


def packet(*, family=2, reason=46, verdict=1, version=1):
    source = socket.inet_pton(socket.AF_INET6, "2001:db8::1234") if family == 10 else socket.inet_aton("198.51.100.27")
    destination = socket.inet_pton(socket.AF_INET6, "2001:db8::80") if family == 10 else socket.inet_aton("203.0.113.80")
    data = struct.pack("<Q16s16sHHBBBB", 123456789, source, destination,
                       socket.htons(51234), socket.htons(443), 6, family, verdict, reason)
    if version != 1:
        data += struct.pack("<IIB7x", 7, 74, version)
    return data


@pytest.mark.parametrize("family,source", [(2, "198.51.100.27"), (10, "2001:db8::1234")])
@pytest.mark.parametrize("version", [1, 2])
def test_decodes_real_wire_layout_and_preserves_unknown_metadata(family, source, version):
    event = decode_event(packet(family=family, version=version))
    assert event is not None
    assert (event["src"], event["sport"], event["dport"]) == (source, 51234, 443)
    assert event["reason"] == "PORT_NOT_AUTHORIZED"
    assert event["reason_category"] == "policy"
    assert event["source_evidence"] == "unverified"
    assert event["event_version"] == version
    assert event["ifindex"] == (7 if version == 2 else None)
    assert event["pkt_len"] == (74 if version == 2 else None)


def test_unknown_layout_is_rejected_but_unknown_reason_is_preserved():
    for raw in (b"", packet()[:-1], packet() + b"\0", packet(version=3),
                packet(verdict=3), packet(family=99)):
        assert decode_event(raw) is None
    event = decode_event(packet(reason=255))
    assert event["reason_id"] == 255
    assert event["reason_category"] == "unknown"
    assert "Unknown reason" in event["reason_detail"]
    event = decode_event(packet(family=0))
    assert event["src"] is None and event["dst"] is None and event["family"] == 0


def test_reason_aliases_are_shared_and_cookie_validation_is_not_acceptance():
    assert reason_info("UDP_GBL_DROP") == reason_info(13)
    assert "legacy" in describe_reason("TCP_DROP")
    assert reason_info(47) != reason_info(48)
    event = decode_event(packet(reason=40, verdict=2))
    assert event["source_evidence"] == "cookie_validated"
    assert "not prove application" in event["reason_detail"]
