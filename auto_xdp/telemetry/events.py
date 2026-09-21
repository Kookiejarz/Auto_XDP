"""Shared packet-event wire format and append-only diagnostic counter catalogue.

Counters describe overlapping decisions and processing stages; their sum is
not a packet total. Packet totals belong to the dedicated byte_counters map.
"""
from __future__ import annotations

import socket
import struct
from typing import Any


# Index matches bpf/include/counters.h. Keep old IDs and CLI labels stable.
# Each entry is (wire name, category, explanation).
COUNTERS = (
    ("TCP_NEW_ALLOW", "policy", "New TCP SYN admitted; connection not yet established"),
    ("TCP_PASS", "summary", "TCP packet passed the main policy"),
    ("TCP_DROP", "summary", "TCP packet dropped; legacy event has no specific cause"),
    ("UDP_PASS", "summary", "UDP packet admitted"),
    ("UDP_DROP", "summary", "UDP packet dropped; legacy event has no specific cause"),
    ("IPV4_OTHER", "summary", "IPv4 control or other protocol processing"),
    ("IPV6_OTHER", "summary", "IPv6 control or other protocol processing"),
    ("FRAG_DROP", "packet", "IP fragments are not admitted by this firewall"),
    ("NON_IP", "summary", "Non-IP Ethernet traffic"),
    ("TCP_RESERVED", "reserved", "Reserved legacy counter"),
    ("ICMP_DROP", "rate", "ICMP echo request token bucket exhausted"),
    ("SYN_RATE_DROP", "rate", "Source group SYN allowance exhausted for this port"),
    ("UDP_RATE_DROP", "rate", "Source group UDP packet allowance exhausted for this port"),
    ("UDP_GLOBAL_RATE_DROP", "rate", "Global untrusted UDP byte allowance exhausted"),
    ("TCP_MALFORM_NULL", "packet", "TCP packet has no flags set"),
    ("TCP_MALFORM_XMAS", "packet", "TCP FIN, PSH and URG flags are set together"),
    ("TCP_MALFORM_SYN_FIN", "packet", "TCP SYN and FIN flags are set together"),
    ("TCP_MALFORM_SYN_RST", "packet", "TCP SYN and RST flags are set together"),
    ("TCP_MALFORM_RST_FIN", "packet", "TCP RST and FIN flags are set together"),
    ("TCP_MALFORM_DOFF", "packet", "TCP header length is invalid or truncated"),
    ("TCP_MALFORM_PORT0", "packet", "TCP source or destination port is zero"),
    ("VLAN_DROP", "packet", "VLAN nesting exceeds the supported depth"),
    ("SLOT_CALL", "protocol", "Protocol handler dispatch attempted"),
    ("SLOT_PASS", "protocol", "Unhandled protocol passed by configured policy"),
    ("SLOT_DROP", "protocol", "Protocol rejected by slot or legacy tunnel policy"),
    ("UDP_MALFORM_PORT0", "packet", "UDP source or destination port is zero"),
    ("UDP_MALFORM_LEN", "packet", "UDP length is invalid or exceeds the received packet"),
    ("BOGON_DROP", "source", "Source address rejected by the configured bogon filter"),
    ("RESERVED_28", "reserved", "Reserved legacy counter"),
    ("SYN_AGG_RATE_DROP", "rate", "Source prefix aggregate SYN allowance exhausted"),
    ("UDP_AGG_RATE_DROP", "rate", "Source prefix aggregate UDP byte allowance exhausted"),
    ("HANDLER_BLOCK_DROP", "source", "Source is temporarily blocked by a protocol handler"),
    ("RESERVED_32", "reserved", "Reserved legacy counter"),
    ("RESERVED_33", "reserved", "Reserved legacy counter"),
    ("ABUSEIPDB_DROP", "source", "Source matched the configured AbuseIPDB blocklist"),
    ("PROFILE_UNAVAILABLE_DROP", "protocol", "Required service protection profile is unavailable"),
    ("PROFILE_ALLOW", "protocol", "Packet admitted by the service protection profile"),
    ("PROFILE_DROP", "protocol", "Service protection profile rejected this packet"),
    ("SYN_COOKIE_CHALLENGE", "cookie", "SYN-cookie challenge processing started"),
    ("SYN_COOKIE_SENT", "cookie", "Cookie SYN-ACK returned with XDP_TX"),
    ("SYN_COOKIE_VALID", "cookie", "Cookie ACK validated; this does not prove application acceptance"),
    ("SYN_COOKIE_INVALID", "cookie", "ACK failed SYN-cookie validation"),
    ("SYN_COOKIE_BUDGET_DROP", "summary", "Combined SYN-port and cookie-ACK budget drops"),
    ("SYN_COOKIE_HELPER_ERROR", "cookie", "Kernel SYN-cookie generation helper failed"),
    ("SYN_COOKIE_TAILCALL_MISS", "cookie", "Required SYN-cookie program could not be dispatched"),
    ("SYN_GUARD_SHED_ENTER", "cookie", "Port entered SYN load-shedding state"),
    ("PORT_NOT_AUTHORIZED", "policy", "Destination port is not authorized on this ingress interface"),
    ("SYN_COOKIE_PORT_BUDGET_DROP", "rate", "SYN port guard refused: budget exhausted, shedding cooldown, or budget state unavailable"),
    ("SYN_COOKIE_ACK_BUDGET_DROP", "rate", "Cookie ACK budget refused: source allowance exhausted or budget update failed"),
    ("PACKET_TRUNCATED", "packet", "Packet is too short for the required protocol header"),
    ("IP_HEADER_INVALID", "packet", "IPv4 header length is invalid"),
    ("IPV6_EXTENSION_INVALID", "packet", "IPv6 extension chain is malformed or too deep"),
    ("SYN_COOKIE_PACKET_INVALID", "cookie", "Packet cannot be processed by the SYN-cookie handler"),
    ("SYN_COOKIE_ADJUST_ERROR", "cookie", "Packet resizing for the cookie reply failed"),
    ("SYN_COOKIE_STATE_STORE_ERROR", "cookie", "TCP option handoff state could not be stored; diagnostic only"),
    ("TUNNEL_ENDPOINT_NOT_AUTHORIZED", "policy", "Outer IPv4 source is not an authorized 6in4 endpoint"),
    ("EVENT_EMITTED", "telemetry", "Eligible packet events submitted to the ring buffer"),
    ("EVENT_LOST", "telemetry", "Eligible packet events lost because ring buffer reservation failed"),
    ("EVENT_SUPPRESSED", "telemetry", "Eligible packet events suppressed by the observability switch"),
    ("SYN_COOKIE_HANDOFF_ATTEMPT", "cookie", "TC found handoff state and validated its cookie ACK"),
    ("SYN_COOKIE_HANDOFF_SUCCESS", "cookie", "TC assigned the request socket; not application accept success"),
    ("SYN_COOKIE_HANDOFF_NO_LISTENER", "cookie", "Validated handoff candidate has no usable listening socket"),
    ("SYN_COOKIE_HANDOFF_ERROR", "cookie", "Request-socket conversion or assignment failed"),
    ("GRE_VERSION_INVALID", "protocol", "GRE version is unsupported"),
    ("ESP_SPI_RESERVED", "protocol", "ESP security parameter index is reserved"),
    ("SCTP_PORT_NOT_AUTHORIZED", "policy", "SCTP destination port is not authorized"),
)

_LEGACY_LABELS = {
    5: "IPv4_OTHER", 6: "IPv6_ICMP", 8: "ARP_NON_IP", 13: "UDP_GBL_DROP",
    14: "TCP_NULL", 15: "TCP_XMAS", 16: "TCP_SYN_FIN", 17: "TCP_SYN_RST",
    18: "TCP_RST_FIN", 19: "TCP_BAD_DOFF", 20: "TCP_PORT0",
    25: "UDP_PORT0", 26: "UDP_BAD_LEN",
}
COUNTER_NAMES = [_LEGACY_LABELS.get(index, row[0]) for index, row in enumerate(COUNTERS)]
_REASON_IDS = {row[0]: index for index, row in enumerate(COUNTERS)}
_REASON_IDS.update({name: index for index, name in enumerate(COUNTER_NAMES)})
REASON_NAMES = {index: row[0] for index, row in enumerate(COUNTERS)}
PROTO_NAMES = {1: "ICMP", 6: "TCP", 17: "UDP", 41: "6in4", 47: "GRE", 50: "ESP", 58: "ICMPv6", 132: "SCTP"}

# Summaries and detailed reasons overlap. Only used as legacy classification,
# never as a replacement for dedicated packet/drop totals.
DROP_INDEXES = frozenset({2, 4, 7, 10, 11, 12, 13, *range(14, 22), 24, 25, 26,
                          27, 29, 30, 31, 34, 35, 37, 41, 42, 43, 44, 46, 47,
                          48, 49, 50, 51, 52, 53, 55, 63, 64, 65})


def reason_info(reason: int | str) -> dict[str, str]:
    try:
        index = int(reason)
    except (ValueError, TypeError):
        index = _REASON_IDS.get(str(reason), -1)
    if 0 <= index < len(COUNTERS):
        name, category, description = COUNTERS[index]
    else:
        name, category, description = str(reason), "unknown", "Unknown reason; producer may use a newer event catalogue"
    return {"name": name, "category": category, "description": description}


def describe_reason(reason: int | str) -> str:
    return reason_info(reason)["description"]


PACKET_EVENT_V1_SIZE = 48
PACKET_EVENT_V2_SIZE = 64
PACKET_EVENT_SIZES = (PACKET_EVENT_V1_SIZE, PACKET_EVENT_V2_SIZE)
_PREFIX = struct.Struct("<Q16s16sHHBBBB")
_EXTENSION = struct.Struct("<IIB7x")


def decode_event(raw: bytes) -> dict[str, Any] | None:
    """Decode supported BPF events without guessing unknown layouts or addresses."""
    if len(raw) not in PACKET_EVENT_SIZES:
        return None
    ts_ns, src, dst, sport, dport, proto, family, verdict, reason = _PREFIX.unpack_from(raw)
    if family not in (0, 2, 10) or verdict not in (1, 2):
        return None
    version = 1
    ifindex = pkt_len = None
    if len(raw) == PACKET_EVENT_V2_SIZE:
        ifindex, pkt_len, version = _EXTENSION.unpack_from(raw, PACKET_EVENT_V1_SIZE)
        if version != 2:
            return None
    ip_version = {0: 0, 2: 4, 10: 6}[family]
    if family == 0:
        src_ip = dst_ip = None
    elif family == 2:
        src_ip, dst_ip = socket.inet_ntoa(src[:4]), socket.inet_ntoa(dst[:4])
    else:
        src_ip = socket.inet_ntop(socket.AF_INET6, src)
        dst_ip = socket.inet_ntop(socket.AF_INET6, dst)
    info = reason_info(reason)
    return {
        "ts_ns": ts_ns, "src": src_ip, "dst": dst_ip,
        "sport": socket.ntohs(sport), "dport": socket.ntohs(dport),
        "proto": PROTO_NAMES.get(proto, str(proto)), "family": ip_version,
        "verdict": "ALLOW" if verdict == 2 else "DROP", "verdict_id": verdict,
        "reason": info["name"], "reason_id": reason,
        "reason_category": info["category"], "reason_detail": info["description"],
        "event_version": version, "ifindex": ifindex, "pkt_len": pkt_len,
        "source_evidence": "cookie_validated" if reason == 40 else "unverified",
    }
