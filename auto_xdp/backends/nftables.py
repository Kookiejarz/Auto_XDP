"""nftables fallback backend."""
from __future__ import annotations

import logging
import re
import shutil
import subprocess
from typing import cast

from auto_xdp import config as cfg
from auto_xdp.backends.base import BackendStatus, PortBackend
from auto_xdp.bpf.maps import (
    render_nft_addrs as _render_nft_addrs,
    render_nft_ports as _render_nft_ports,
    run_nft as _run_nft,
)
from auto_xdp.state import AppliedState, DesiredState, ObservedState, ReconcilePlan

log = logging.getLogger(__name__)

_NFT_SCHEMA_MARKER = "policy_schema_v2"
_BOGON_V4 = (
    "0.0.0.0/8",
    "10.0.0.0/8",
    "100.64.0.0/10",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "224.0.0.0/4",
    "240.0.0.0/4",
)
_BOGON_V6 = (
    "::/128",
    "::1/128",
    "::ffff:0:0/96",
    "fc00::/7",
    "fe80::/10",
    "ff00::/8",
)


def _set_block(name: str, value_type: str, elements: list[str], *, interval: bool = False) -> str:
    lines = [f"    set {name} {{", f"        type {value_type}"]
    if interval:
        lines.append("        flags interval")
    if elements:
        lines.append(f"        elements = {{ {', '.join(elements)} }}")
    lines.append("    }")
    return "\n".join(lines)


def _rate(value: int | float) -> int:
    return max(1, int(math.ceil(value)))


def _prefix_mask(family: int, prefix: int) -> str:
    bits = 32 if family == 4 else 128
    prefix = max(0, min(bits, prefix))
    network = ipaddress.ip_network(f"0.0.0.0/{prefix}" if family == 4 else f"::/{prefix}")
    return str(network.netmask)


def _collapse_cidrs(cidrs: list[str]) -> list[str]:
    networks = [ipaddress.ip_network(cidr) for cidr in cidrs]
    v4 = [network for network in networks if isinstance(network, ipaddress.IPv4Network)]
    v6 = [network for network in networks if isinstance(network, ipaddress.IPv6Network)]
    collapsed = list(ipaddress.collapse_addresses(v4))
    # Typeshed exposes only the IPv4 overload here; both families are valid at
    # runtime, and the v4/v6 split above keeps them from being mixed.
    collapsed.extend(
        ipaddress.collapse_addresses(cast(list[ipaddress.IPv4Network], v6))
    )
    return [str(network) for network in collapsed]


def _policy_signature(desired: DesiredState) -> tuple[object, ...]:
    return (
        frozenset(desired.tcp_ports),
        frozenset(desired.udp_ports),
        frozenset(desired.sctp_ports),
        frozenset(desired.trusted_cidrs),
        tuple(sorted(desired.tcp_syn_rate_limits.items())),
        tuple(sorted(desired.tcp_syn_agg_rate_limits.items())),
        tuple(sorted(desired.tcp_conn_limits.items())),
        tuple(sorted(desired.tcp_conn_prefix_limits.items())),
        tuple(sorted(desired.tcp_conn_port_limits.items())),
        tuple(sorted(desired.udp_rate_limits.items())),
        tuple(sorted(desired.udp_agg_rate_limits.items())),
        tuple(sorted((proto, cidr, tuple(sorted(ports))) for (proto, cidr), ports in desired.acl_rules.items())),
        desired.bogon_filter_enabled,
        desired.drop_events_enabled,
        desired.rate_limit_source_prefix_v4,
        desired.rate_limit_source_prefix_v6,
        desired.udp_global_byte_rate,
        tuple(cfg.SIT4_ENDPOINTS),
        cfg.SLOT_DEFAULT_ACTION,
        cfg.NFT_FAMILY,
        cfg.NFT_TABLE,
    )


class NftablesBackend(PortBackend):
    name = cfg.BACKEND_NFTABLES

    @classmethod
    def probe(cls) -> BackendStatus:
        nft_path = shutil.which("nft")
        checks = {"nft": nft_path is not None}
        if nft_path is None:
            return BackendStatus(
                name=cls.name,
                available=False,
                reason="nft command not found",
                details={"nft": "not found"},
                checks=checks,
            )
        return BackendStatus(name=cls.name, available=True, checks=checks)

    def __init__(self) -> None:
        if shutil.which("nft") is None:
            raise RuntimeError("nft command not found")
        self._tcp_cache: set[int] = set()
        self._udp_cache: set[int] = set()
        self._sctp_cache: set[int] = set()
        self._trusted_cache: set[str] = set()
        self._ensure_ruleset()
        self._refresh_caches()

    def _parse_set_elements(self, body: str) -> list[str]:
        match = re.search(r"elements\s*=\s*\{(.*?)\}", body, re.DOTALL)
        if not match:
            return []
        raw = match.group(1).replace("\n", " ").strip()
        if not raw:
            return []
        return [item.strip() for item in raw.split(",") if item.strip()]

    def _list_set_elements(self, set_name: str) -> list[str]:
        result = _run_nft(
            ["list", "set", cfg.NFT_FAMILY, cfg.NFT_TABLE, set_name],
            check=False,
        )
        if result.returncode != 0:
            return []
        return self._parse_set_elements(result.stdout)

    def _refresh_caches(self) -> None:
        self._tcp_cache = {int(item) for item in self._list_set_elements(cfg.NFT_TCP_SET)}
        self._udp_cache = {int(item) for item in self._list_set_elements(cfg.NFT_UDP_SET)}
        self._sctp_cache = {int(item) for item in self._list_set_elements(cfg.NFT_SCTP_SET)}
        self._trusted_cache = set(self._list_set_elements(cfg.NFT_TRUSTED_SET4))
        self._trusted_cache.update(self._list_set_elements(cfg.NFT_TRUSTED_SET6))

    def get_applied_state(self) -> AppliedState:
        return AppliedState(
            tcp_ports=set(self._tcp_cache),
            udp_ports=set(self._udp_cache),
            sctp_ports=set(self._sctp_cache),
            trusted_cidrs=set(self._trusted_cache),
        )

    def _ensure_ruleset(self) -> None:
        result = _run_nft(["list", "table", cfg.NFT_FAMILY, cfg.NFT_TABLE], check=False)
        if result.returncode == 0:
            body = result.stdout
            if all(marker in body for marker in (
                f"set {cfg.NFT_TCP_SET}", f"set {cfg.NFT_UDP_SET}", f"set {cfg.NFT_SCTP_SET}",
                f"set {cfg.NFT_TRUSTED_SET4}", "chain input",
            )):
                return
            _run_nft(["delete", "table", cfg.NFT_FAMILY, cfg.NFT_TABLE], check=True)

        script = f"""table {cfg.NFT_FAMILY} {cfg.NFT_TABLE} {{
    set {cfg.NFT_TCP_SET} {{
        type inet_service
    }}

    set {cfg.NFT_UDP_SET} {{
        type inet_service
    }}

    set {cfg.NFT_SCTP_SET} {{
        type inet_service
    }}

    set {cfg.NFT_TRUSTED_SET4} {{
        type ipv4_addr
        flags interval
    }}

    set {cfg.NFT_TRUSTED_SET6} {{
        type ipv6_addr
        flags interval
    }}

    chain input {{
        type filter hook input priority filter; policy accept;
        iifname "lo" accept
        ct state established,related accept
        ip saddr @{cfg.NFT_TRUSTED_SET4} accept
        ip6 saddr @{cfg.NFT_TRUSTED_SET6} accept
        ip protocol icmp accept
        ip6 nexthdr icmpv6 accept
        tcp flags & (ack | rst | fin) != 0 accept
        tcp flags & (syn | ack) == syn tcp dport @{cfg.NFT_TCP_SET} accept
        udp sport {{ 53, 67, 123, 443, 547 }} accept
        udp dport @{cfg.NFT_UDP_SET} accept
        sctp dport @{cfg.NFT_SCTP_SET} accept
        counter drop
    }}
}}
"""
        _run_nft(["-f", "-"], input_text=script, check=True)

    def _apply_lines(self, lines: list[str], dry_run: bool, error_prefix: str) -> None:
        if not lines:
            return
        script = "\n".join(lines) + "\n"
        if dry_run:
            for line in lines:
                log.info("[DRY] nft %s", line)
            return
        try:
            _run_nft(["-f", "-"], input_text=script, check=True)
        except subprocess.CalledProcessError as exc:
            stderr = exc.stderr.strip() if exc.stderr else str(exc)
            raise RuntimeError(f"{error_prefix}: {stderr}") from exc

    def _port_diff_lines(self, set_name: str, to_add: set[int], to_remove: set[int]) -> list[str]:
        lines: list[str] = []
        if to_remove:
            lines.append(
                f"delete element {cfg.NFT_FAMILY} {cfg.NFT_TABLE} {set_name} {_render_nft_ports(to_remove)}"
            )
        if to_add:
            lines.append(
                f"add element {cfg.NFT_FAMILY} {cfg.NFT_TABLE} {set_name} {_render_nft_ports(to_add)}"
            )
        return lines

    def _trusted_diff_lines(self, to_add: set[str], to_remove: set[str]) -> list[str]:
        lines: list[str] = []
        remove_v4 = {a for a in to_remove if ":" not in a}
        remove_v6 = {a for a in to_remove if ":" in a}
        add_v4 = {a for a in to_add if ":" not in a}
        add_v6 = {a for a in to_add if ":" in a}
        if remove_v4:
            lines.append(
                f"delete element {cfg.NFT_FAMILY} {cfg.NFT_TABLE} {cfg.NFT_TRUSTED_SET4} {_render_nft_addrs(remove_v4)}"
            )
        if remove_v6:
            lines.append(
                f"delete element {cfg.NFT_FAMILY} {cfg.NFT_TABLE} {cfg.NFT_TRUSTED_SET6} {_render_nft_addrs(remove_v6)}"
            )
        if add_v4:
            lines.append(
                f"add element {cfg.NFT_FAMILY} {cfg.NFT_TABLE} {cfg.NFT_TRUSTED_SET4} {_render_nft_addrs(add_v4)}"
            )
        if add_v6:
            lines.append(
                f"add element {cfg.NFT_FAMILY} {cfg.NFT_TABLE} {cfg.NFT_TRUSTED_SET6} {_render_nft_addrs(add_v6)}"
            )
        return lines

    def apply_reconcile_plan(
        self,
        plan: ReconcilePlan,
        dry_run: bool,
        desired_state: DesiredState,
        observed_state: ObservedState | None = None,
    ) -> None:
        changed = False
        _ = observed_state  # kernel conntrack handles established flows natively

        for ip_str in sorted(plan.trusted_cidrs_to_add):
            tag = f" [{cfg.TRUSTED_SRC_IPS[ip_str]}]" if ip_str in cfg.TRUSTED_SRC_IPS else ""
            log.info("TRUST +%s%s", ip_str, tag)
            changed = True
        for ip_str in sorted(plan.trusted_cidrs_to_remove):
            log.info("TRUST -%s  (removed)", ip_str)
            changed = True

        for port in sorted(plan.tcp_ports_to_add):
            tag = f" [{cfg.TCP_PERMANENT[port]}]" if port in cfg.TCP_PERMANENT else ""
            log.info("TCP +%d%s", port, tag)
            changed = True
        for port in sorted(plan.tcp_ports_to_remove):
            log.info("TCP -%d  (stopped)", port)
            changed = True

        for port in sorted(plan.udp_ports_to_add):
            tag = f" [{cfg.UDP_PERMANENT[port]}]" if port in cfg.UDP_PERMANENT else ""
            log.info("UDP +%d%s", port, tag)
            changed = True
        for port in sorted(plan.udp_ports_to_remove):
            log.info("UDP -%d  (stopped)", port)
            changed = True

        for port in sorted(plan.sctp_ports_to_add):
            tag = f" [{cfg.SCTP_PERMANENT[port]}]" if port in cfg.SCTP_PERMANENT else ""
            log.info("SCTP +%d%s", port, tag)
            changed = True
        for port in sorted(plan.sctp_ports_to_remove):
            log.info("SCTP -%d  (stopped)", port)
            changed = True

        self._apply_lines(
            self._port_diff_lines(cfg.NFT_TCP_SET, plan.tcp_ports_to_add, plan.tcp_ports_to_remove)
            + self._port_diff_lines(cfg.NFT_UDP_SET, plan.udp_ports_to_add, plan.udp_ports_to_remove)
            + self._port_diff_lines(cfg.NFT_SCTP_SET, plan.sctp_ports_to_add, plan.sctp_ports_to_remove),
            dry_run,
            "nftables update failed",
        )
        self._apply_lines(
            self._trusted_diff_lines(plan.trusted_cidrs_to_add, plan.trusted_cidrs_to_remove),
            dry_run,
            "nftables trusted-ip update failed",
        )
        if dry_run:
            return
        self._tcp_cache.update(plan.tcp_ports_to_add)
        self._tcp_cache.difference_update(plan.tcp_ports_to_remove)
        self._udp_cache.update(plan.udp_ports_to_add)
        self._udp_cache.difference_update(plan.udp_ports_to_remove)
        self._sctp_cache.update(plan.sctp_ports_to_add)
        self._sctp_cache.difference_update(plan.sctp_ports_to_remove)
        self._trusted_cache.update(plan.trusted_cidrs_to_add)
        self._trusted_cache.difference_update(plan.trusted_cidrs_to_remove)

        if not changed:
            log.debug("Whitelist up-to-date.")
