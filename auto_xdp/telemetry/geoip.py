"""Optional local MMDB enrichment for displayed source addresses.

Readers and the bounded cache belong to the TUI thread. Database replacement
is picked up on the next TUI start; this module never downloads or queries IPs.
"""
from __future__ import annotations

from collections import OrderedDict
from datetime import datetime, timezone
import importlib
import ipaddress
from pathlib import Path
from typing import Any


MAX_CACHE_SIZE = 65_536


def _text(value: Any) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError("database text field is not a string")
    return "".join(char for char in value if char.isprintable())[:160] or None


def _scope(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> str:
    for name in ("unspecified", "loopback", "link_local", "multicast", "reserved", "private"):
        if getattr(address, f"is_{name}"):
            return name
    return "global" if address.is_global else "shared"


class GeoIPResolver:
    def __init__(self, cache_size: int = 4096) -> None:
        self._cache_size = cache_size
        self._cache: OrderedDict[str, dict[str, Any]] = OrderedDict()
        self._readers: dict[str, Any] = {}
        self._versions: dict[str, int] = {}
        self._updated: dict[str, str] = {}
        self._errors: dict[str, str] = {}
        self._enabled = False
        self._closed = False

    @classmethod
    def from_config(cls, config: dict) -> GeoIPResolver:
        if not isinstance(config, dict) or not isinstance(config.get("geoip", {}), dict):
            raise ValueError("geoip must be a table")
        options = config.get("geoip", {})
        enabled = options.get("enabled", False)
        if not isinstance(enabled, bool):
            raise ValueError("geoip.enabled must be a boolean")
        cache_size = options.get("cache_size", 4096)
        if type(cache_size) is not int or not 1 <= cache_size <= MAX_CACHE_SIZE:
            raise ValueError(f"geoip.cache_size must be an integer in 1..{MAX_CACHE_SIZE}")
        paths = {}
        for kind in ("country", "asn"):
            path = options.get(f"{kind}_db", "")
            if not isinstance(path, str) or "\0" in path or (path and not Path(path).is_absolute()):
                raise ValueError(f"geoip.{kind}_db must be an absolute local path or empty")
            if path:
                paths[kind] = path
        resolver = cls(cache_size)
        resolver._enabled = enabled
        if not enabled or not paths:
            return resolver
        try:
            maxminddb = importlib.import_module("maxminddb")
        except (ImportError, OSError) as exc:
            resolver._errors["reader"] = f"optional maxminddb unavailable: {_text(str(exc))}"
            return resolver
        for kind, path in paths.items():
            reader = None
            try:
                reader = maxminddb.open_database(path)
                metadata = reader.metadata()
                if metadata.ip_version not in (4, 6):
                    raise ValueError("invalid database IP version")
                updated = datetime.fromtimestamp(metadata.build_epoch, timezone.utc).isoformat()
                resolver._readers[kind] = reader
                resolver._versions[kind] = metadata.ip_version
                resolver._updated[kind] = updated
            except Exception as exc:
                # Optional database failures must not interrupt packet display.
                resolver._errors[kind] = f"{type(exc).__name__}: {_text(str(exc))}"
                if reader is not None:
                    try:
                        reader.close()
                    except Exception:
                        pass
        return resolver

    @property
    def status(self) -> str:
        if self._closed:
            return "closed"
        if not self._enabled:
            return "disabled"
        if self._errors:
            state = "degraded" if self._readers else "unavailable"
            return state + ": " + "; ".join(f"{kind}: {error}" for kind, error in self._errors.items())
        if self._readers:
            return "ready: " + ", ".join(self._readers)
        return "unavailable: no local databases configured"

    def lookup(self, ip: str) -> dict[str, Any]:
        result: dict[str, Any] = dict.fromkeys(
            ("country_code", "country_name", "asn", "as_org", "network", "db_updated_at")
        )
        result.update(status=self.status, scope="invalid")
        try:
            if not isinstance(ip, str) or "%" in ip:
                raise ValueError("expected an unscoped IP address")
            address = ipaddress.ip_address(ip)
            if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
                address = address.ipv4_mapped
        except ValueError:
            result["status"] = "invalid IP address"
            return result
        scope = _scope(address)
        result["scope"] = scope
        if scope != "global":
            result["status"] = f"not geolocated: {scope} address"
            return result
        if self._closed or not self._readers:
            return result
        key = str(address)
        if key in self._cache:
            self._cache.move_to_end(key)
            return self._cache[key].copy()
        result["db_updated_at"] = "; ".join(f"{kind}={updated}" for kind, updated in self._updated.items())
        errors = []
        for kind, reader in self._readers.items():
            if address.version == 6 and self._versions[kind] == 4:
                errors.append(f"{kind}: database supports IPv4 only")
                continue
            try:
                record, prefix = reader.get_with_prefix_len(key)
                if record is None:
                    continue
                if not isinstance(record, dict) or type(prefix) is not int:
                    raise ValueError("invalid database record")
                network = str(ipaddress.ip_network(f"{key}/{prefix}", strict=False))
                fields: dict[str, Any] = {}
                if kind == "country":
                    country = record.get("country", {})
                    if not isinstance(country, dict) or not isinstance(country.get("names", {}), dict):
                        raise ValueError("invalid country record")
                    fields["country_code"] = _text(country.get("iso_code"))
                    if fields["country_code"] and (
                        len(fields["country_code"]) != 2
                        or not fields["country_code"].isascii()
                        or not fields["country_code"].isalpha()
                    ):
                        raise ValueError("invalid country code")
                    names = country.get("names", {})
                    fields["country_name"] = _text(names.get("en") or names.get("zh-CN"))
                else:
                    asn = record.get("autonomous_system_number")
                    if asn is not None and (type(asn) is not int or not 1 <= asn <= 0xFFFFFFFF):
                        raise ValueError("invalid ASN")
                    fields.update(asn=asn, as_org=_text(record.get("autonomous_system_organization")))
                result.update(fields)
                if any(value is not None for value in fields.values()):
                    # ASN lookup runs last, so network is the ASN's prefix when available.
                    result["network"] = network
            except Exception as exc:
                errors.append(f"{kind}: {type(exc).__name__}: {_text(str(exc))}")
        if errors:
            result["status"] = "lookup degraded: " + "; ".join(errors)
        elif self._errors:
            result["status"] = self.status
        else:
            result["status"] = "ok" if result["network"] else "not found"
        self._cache[key] = result
        if len(self._cache) > self._cache_size:
            self._cache.popitem(last=False)
        return result.copy()

    def close(self) -> None:
        for reader in self._readers.values():
            try:
                reader.close()
            except Exception:
                pass
        self._readers.clear()
        self._cache.clear()
        self._closed = True
