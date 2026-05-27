"""AbuseIPDB threat-intel integration.

Fetches borestad/blocklist-abuseipdb IPv4 blocklists and syncs them to the
abuseipdb_v4 BPF LPM trie. Upstream does not publish IPv6 lists (SLAAC
privacy churn makes long-window v6 blocklists nearly useless), so this
integration is IPv4-only.

Usage: constructed and started by XdpBackend when [abuseipdb] enabled = true.
"""
from __future__ import annotations

import logging
import socket
import threading
import urllib.error
import urllib.request

from auto_xdp.bpf.maps import BpfBaseMap, BpfLpmMap, BpfRuntimeConfigMap

log = logging.getLogger(__name__)

_SOURCES_V4: dict[str, str] = {
    "s1001d":   "abuseipdb-s100-1d.ipv4",
    "s1003d":   "abuseipdb-s100-3d.ipv4",
    "s1007d":   "abuseipdb-s100-7d.ipv4",
    "s10014d":  "abuseipdb-s100-14d.ipv4",
    "s10030d":  "abuseipdb-s100-30d.ipv4",
    "s10060d":  "abuseipdb-s100-60d.ipv4",
    "s10090d":  "abuseipdb-s100-90d.ipv4",
    "s100120d": "abuseipdb-s100-120d.ipv4",
}

DEFAULT_BASE_URL = "https://raw.githubusercontent.com/borestad/blocklist-abuseipdb/refs/heads/main"
DEFAULT_SOURCES = ["s1003d"]
DEFAULT_REFRESH_SECONDS = 3600.0


def fetch_blocklist(source_key: str, base_url: str) -> list[str]:
    """Fetch one IPv4 blocklist file from borestad/blocklist-abuseipdb.

    Returns IP strings; comments and blank lines are stripped. Returns []
    on any network or lookup error (fail-open).
    """
    filename = _SOURCES_V4.get(source_key)
    if not filename:
        log.warning("AbuseIPDB: unknown source key %r", source_key)
        return []
    url = f"{base_url.rstrip('/')}/{filename}"
    try:
        with urllib.request.urlopen(url, timeout=30) as resp:
            body = resp.read().decode("utf-8", errors="replace")
    except (urllib.error.URLError, OSError) as exc:
        log.warning("AbuseIPDB fetch failed url=%s: %s", url, exc)
        return []
    result = []
    for line in body.splitlines():
        # borestad annotates each IP with " # CC ASN org" metadata; strip
        # any inline comment so the bare address survives.
        comment_at = line.find("#")
        if comment_at != -1:
            line = line[:comment_at]
        stripped = line.strip()
        if stripped:
            result.append(stripped)
    return result


class BpfRiskMaps(BpfBaseMap):
    """Wraps abuseipdb_v4 LPM trie; active flag lives in xdp_runtime_cfg.cfg_flags."""

    def __init__(self, path4: str, runtime_cfg_map: "BpfRuntimeConfigMap") -> None:
        self._map4 = BpfLpmMap(path4, socket.AF_INET)
        self._runtime_cfg = runtime_cfg_map

    def close(self) -> None:
        m = getattr(self, "_map4", None)
        if m is not None:
            m.close()

    def set_active(self, active: bool) -> None:
        from auto_xdp.bpf.maps import XDP_CFG_FLAG_ABUSEIPDB_ENABLED
        flags = self._runtime_cfg.get_cfg_flags() or 0
        if active:
            flags |= XDP_CFG_FLAG_ABUSEIPDB_ENABLED
        else:
            flags &= ~XDP_CFG_FLAG_ABUSEIPDB_ENABLED
        timing = self._runtime_cfg.get() or (0,) * 8
        self._runtime_cfg.set(timing, flags)

    def replace_all(self, ips: list[str]) -> int:
        """Replace all map entries with *ips*, then set the active flag.

        Clears the map first, then writes the new entries. Sets active=1
        when at least one IP was loaded, active=0 otherwise (fail-open while
        the map is empty during an update cycle). IPv6 entries in *ips* are
        ignored.

        Returns the count of v4 entries successfully written.
        """
        for cidr in list(self._map4.active_keys()):
            self._map4.delete(cidr)

        v4 = 0
        overflow_v4 = 0
        v4_seen: set[str] = set()
        for ip in ips:
            ip = ip.strip()
            if not ip or ip.startswith("#"):
                continue
            if ":" in ip:
                continue
            cidr = ip if "/" in ip else f"{ip}/32"
            if cidr in v4_seen:
                continue
            v4_seen.add(cidr)
            if self._map4.set(cidr, 1):
                v4 += 1
            else:
                overflow_v4 += 1

        if overflow_v4:
            log.warning(
                "AbuseIPDB v4 map full: %d entries dropped (loaded=%d). "
                "Increase max_entries in bpf/include/maps.h or use a smaller source window.",
                overflow_v4, v4,
            )

        self.set_active(bool(v4))
        return v4

    def clear_all(self) -> None:
        self.replace_all([])


class AbuseIPDBSyncer:
    """Background thread: periodically fetches blocklists and updates BPF maps."""

    def __init__(
        self,
        risk_maps: BpfRiskMaps,
        *,
        base_url: str = DEFAULT_BASE_URL,
        sources: list[str] | None = None,
        refresh_seconds: float = DEFAULT_REFRESH_SECONDS,
    ) -> None:
        self._maps = risk_maps
        self._base_url = base_url
        self._sources = list(sources) if sources is not None else list(DEFAULT_SOURCES)
        self._refresh_seconds = max(float(refresh_seconds), 60.0)
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        if self._thread is not None and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._run,
            name="abuseipdb-syncer",
            daemon=True,
        )
        self._thread.start()
        log.info(
            "AbuseIPDB syncer started (sources=%s refresh=%ds)",
            self._sources,
            int(self._refresh_seconds),
        )

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=5)
            self._thread = None

    def _run(self) -> None:
        while not self._stop.is_set():
            self._refresh()
            self._stop.wait(self._refresh_seconds)

    def _refresh(self) -> None:
        ips: list[str] = []
        seen: set[str] = set()
        for src in self._sources:
            for ip in fetch_blocklist(src, self._base_url):
                if ip not in seen:
                    seen.add(ip)
                    ips.append(ip)
        if not ips:
            log.warning("AbuseIPDB: no IPs fetched; retaining previous map state")
            return
        try:
            v4 = self._maps.replace_all(ips)
            log.info("AbuseIPDB: loaded %d IPv4 risk IPs", v4)
        except OSError as exc:
            log.error("AbuseIPDB map update failed: %s", exc)
