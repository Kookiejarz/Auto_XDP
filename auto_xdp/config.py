from __future__ import annotations

import copy
import ipaddress
import logging
import os
from threading import RLock
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from collections.abc import Mapping
from typing import Any

try:
    import tomllib  # Python 3.11+
except ImportError:
    try:
        import tomli as tomllib
    except ImportError:
        tomllib = None


log = logging.getLogger(__name__)
_CONFIG_LOCK = RLock()


def _freeze(value: Any) -> Any:
    if isinstance(value, Mapping):
        return MappingProxyType({key: _freeze(item) for key, item in value.items()})
    if isinstance(value, (list, tuple)):
        return tuple(_freeze(item) for item in value)
    if isinstance(value, (set, frozenset)):
        return frozenset(value)
    return value


@dataclass(frozen=True)
class ConfigSnapshot:
    """Deeply immutable normalized settings for one reconciliation.

    Settings retain their existing names while legacy CLI consumers migrate;
    snapshot readers never consult or modify the module's compatibility state.
    """

    values: Mapping[str, Any]

    def __post_init__(self) -> None:
        object.__setattr__(self, "values", _freeze(self.values))

    def __getattr__(self, name: str) -> Any:
        try:
            return self.values[name]
        except KeyError:
            raise AttributeError(name) from None


def snapshot_config() -> ConfigSnapshot:
    """Capture normalized compatibility settings without retaining aliases."""
    with _CONFIG_LOCK:
        return ConfigSnapshot({name: globals()[name] for name in _SETTING_NAMES})

TOML_CONFIG_PATH = "/etc/auto_xdp/config.toml"
RINGBUF_SOCKET_PATH = "/var/run/auto_xdp/pkt_events.sock"

BACKEND_AUTO = "auto"
BACKEND_XDP = "xdp"
BACKEND_NFTABLES = "nftables"

# Compiled-in defaults — single source of truth for TOML fallbacks
_BPF_PIN_DIR = "/sys/fs/bpf/xdp_fw"
_NFT_FAMILY = "inet"
_NFT_TABLE = "auto_xdp"

XDP_OBJ_PATH = os.environ.get("XDP_OBJ_PATH", "")

_SYN_RATE_BY_PROC: dict[str, int] = {}
_SYN_RATE_BY_SERVICE: dict[str, int] = {}
_SYN_AGG_RATE_BY_PROC: dict[str, int] = {}
_SYN_AGG_RATE_BY_SERVICE: dict[str, int] = {}
_UDP_RATE_BY_PROC: dict[str, int] = {}
_UDP_RATE_BY_SERVICE: dict[str, int] = {}
_UDP_AGG_BYTES_BY_PROC: dict[str, int] = {}
_UDP_AGG_BYTES_BY_SERVICE: dict[str, int] = {}

# ARRAY_OF_MAPS requires every LRU inner to match the compiled template.
_RATE_MAP_TEMPLATE_ENTRIES_V4 = 16384
_RATE_MAP_TEMPLATE_ENTRIES_V6 = 4096
RATE_MAP_ENTRIES_V4 = _RATE_MAP_TEMPLATE_ENTRIES_V4
RATE_MAP_ENTRIES_V6 = _RATE_MAP_TEMPLATE_ENTRIES_V6
_RATE_MAP_ENTRIES_BY_PROC: dict[str, int] = {}
_RATE_MAP_ENTRIES_BY_SERVICE: dict[str, int] = {}

# Default-on TCP protection knobs — applied when no explicit per-proc/service
# entry exists. See docs/superpowers/specs/2026-05-06-tcp-default-on-protection-design.md.
XDP_SENSITIVE_PORT_THRESHOLD = 5
XDP_DEFAULT_TCP_SYN_RATE_STRICT = 5
XDP_DEFAULT_TCP_SYN_RATE = 100
XDP_DEFAULT_TCP_SYN_AGG_RATE_STRICT = 50
XDP_DEFAULT_TCP_SYN_AGG_RATE = 1000
RATE_LIMIT_SOURCE_PREFIX_V4 = 32
RATE_LIMIT_SOURCE_PREFIX_V6 = 128

BOGON_FILTER_ENABLED = True
ISATTACK_MODE = False
DROP_EVENTS_ENABLED = True
LOG_LEVEL: str = "warning"
DEBOUNCE_SECONDS = 0.4
POLICY_MODE = "audit"
ZONES: dict[str, dict[str, list[str]]] = {}
SUBJECTS: dict[str, dict] = {}
UNKNOWN_SUBJECTS: dict[str, str] = {"public": "deny"}
DISCOVERY_EXCLUDE_LOOPBACK = True
DISCOVERY_EXCLUDE_BIND_CIDRS: list[str] = []
DISCOVERY_EXCLUDE_PORTS: set[int] = set()
PREFERRED_BACKEND = BACKEND_AUTO
XDP_ICMP_BURST_PACKETS = 100
XDP_ICMP_RATE_PPS = 100.0
XDP_UDP_GLOBAL_WINDOW_SECONDS = 1.0
XDP_RATE_WINDOW_SECONDS = 1.0
XDP_UDP_GLOBAL_BYTE_RATE = 0

SYNCOOKIE_MODE_OFF = "off"
SYNCOOKIE_MODE_AUTO = "auto"
SYNCOOKIE_MODE_ALWAYS = "always"
SYNCOOKIE_MODES = frozenset({SYNCOOKIE_MODE_OFF, SYNCOOKIE_MODE_AUTO, SYNCOOKIE_MODE_ALWAYS})
SYNCOOKIE_ENABLED = False
SYNCOOKIE_DEFAULT_MODE = SYNCOOKIE_MODE_AUTO
SYNCOOKIE_ACTIVATION_PERCENT = 90
SYNCOOKIE_AUTO_MAX_PERCENT = 200
SYNCOOKIE_CHALLENGE_COOLDOWN_SECONDS = 5.0
SYNCOOKIE_INVALID_ACK_RATE_PPS = 1000
SYNCOOKIE_PORT_RATE_DEFAULT = 0
_SYNCOOKIE_BY_PROC: dict[str, str] = {}
_SYNCOOKIE_BY_SERVICE: dict[str, str] = {}
_SYNCOOKIE_BY_PORT: dict[int, str] = {}
_SYNCOOKIE_PORT_RATE_BY_PROC: dict[str, int] = {}
_SYNCOOKIE_PORT_RATE_BY_SERVICE: dict[str, int] = {}
_SYNCOOKIE_PORT_RATE_BY_PORT: dict[int, int] = {}

NFT_FAMILY = _NFT_FAMILY
NFT_TABLE = _NFT_TABLE
NFT_TCP_SET = "tcp_ports"
NFT_UDP_SET = "udp_ports"
NFT_SCTP_SET = "sctp_ports"
NFT_TRUSTED_SET4 = "trusted_v4"
NFT_TRUSTED_SET6 = "trusted_v6"

TRUSTED_SRC_IPS: dict[str, str] = {}
ACL_RULES: list[dict] = []
SIT4_ENDPOINTS: list[str] = []

ABUSEIPDB_ENABLED = False
ABUSEIPDB_BASE_URL = "https://raw.githubusercontent.com/borestad/blocklist-abuseipdb/refs/heads/main"
ABUSEIPDB_SOURCES: list[str] = ["s1003d"]
ABUSEIPDB_REFRESH_SECONDS = 3600.0
ABUSEIPDB_RISK_MAP_PATH4 = ""

SLOT_DEFAULT_ACTION = "drop"

ACL_MAX_PORTS = 64
ACL_VAL_SIZE = 4 + ACL_MAX_PORTS * 2

_PACKAGE_DIR = Path(__file__).resolve().parent
_DEFAULT_XDP_REQUIRED_MAP_NAMES = (
    "prog",
    "tcp_whitelist",
    "endpoint_scopes",
    "udp_whitelist",
    "tcp_zone_whitelist",
    "udp_zone_whitelist",
    "sctp_whitelist",
    "trusted_ipv4",
    "trusted_ipv6",
    "tcp_port_policies",
    "tcp_synck_policy",
    "sync_run_cfg",
    "sync_port_rate",
    "sync_port_state",
    "sync_port_limit",
    "sync_handoff4",
    "sync_handoff6",
    "syncookie_prog_array",
    "udp_port_policies",
    "udp_global_rl",
    "xdp_runtime_cfg",
    "udp_percpu_acc",
    "proto_handlers",
    "tcp_profile_handlers",
    "tcp_port_handlers",
    "udp_port_handlers",
    "hblk4",
    "hblk6",
    "udp_hv4",
    "udp_hv6",
    "slot_ctx_map",
    "profile_ctx_map",
    "mc_l7_pending",
    "mc_verified",
    "sit4_endpoints",
    "abuseipdb_v4",
    "syn4",
    "syn6",
    "udprt4",
    "udprt6",
)


def load_required_xdp_map_names() -> tuple[str, ...]:
    candidates = []

    override = os.environ.get("XDP_REQUIRED_MAPS_FILE")
    if override:
        candidates.append(Path(override))

    candidates.append(_PACKAGE_DIR / "xdp_required_maps.txt")

    install_dir = os.environ.get("INSTALL_DIR")
    if install_dir:
        candidates.append(Path(install_dir) / "xdp_required_maps.txt")

    for path in candidates:
        try:
            with path.open("r", encoding="utf-8") as fh:
                names = []
                for raw_line in fh:
                    line = raw_line.split("#", 1)[0].strip()
                    if line:
                        names.append(line)
        except FileNotFoundError:
            continue
        except OSError as exc:
            log.warning("Failed to load %s: %s", path, exc)
            continue
        if names:
            return tuple(names)

    return _DEFAULT_XDP_REQUIRED_MAP_NAMES


REQUIRED_XDP_MAP_NAMES = load_required_xdp_map_names()

# Map paths derived from BPF_PIN_DIR. Declared here so they are visible at
# module scope; the real values are filled in by _set_bpf_pin_dir() below.
BPF_PIN_DIR = ""
TCP_MAP_PATH = ""
ENDPOINT_SCOPE_MAP_PATH = ""
UDP_MAP_PATH = ""
TCP_ZONE_MAP_PATH = ""
UDP_ZONE_MAP_PATH = ""
SCTP_MAP_PATH = ""
TRUSTED_IPS_MAP_PATH4 = ""
TRUSTED_IPS_MAP_PATH6 = ""
TCP_PORT_POLICY_MAP_PATH = ""
TCP_SYNCOOKIE_POLICY_MAP_PATH = ""
SYNCOOKIE_RUNTIME_CFG_MAP_PATH = ""
SYNCOOKIE_PORT_RATE_MAP_PATH = ""
UDP_PORT_POLICY_MAP_PATH = ""
TCP_PROFILE_HANDLER_MAP_PATH = ""
UDP_GLOBAL_RL_MAP_PATH = ""
XDP_RUNTIME_CFG_MAP_PATH = ""
TCP_ACL_MAP_PATH4 = ""
TCP_ACL_MAP_PATH6 = ""
UDP_ACL_MAP_PATH4 = ""
UDP_ACL_MAP_PATH6 = ""
SIT4_ENDPOINTS_MAP_PATH = ""
SYN4_MAP_PATH = ""
SYN6_MAP_PATH = ""
UDPRT4_MAP_PATH = ""
UDPRT6_MAP_PATH = ""
REQUIRED_XDP_MAP_PATHS: tuple[str, ...] = ()


def _bpf_pin_paths(pin_dir: str, map_names: tuple[str, ...] | None = None) -> dict[str, Any]:
    """Derive paths for both snapshots and compatibility consumers."""
    paths: dict[str, Any] = {}
    paths["BPF_PIN_DIR"] = pin_dir
    paths["ENDPOINT_SCOPE_MAP_PATH"] = f"{pin_dir}/endpoint_scopes"
    paths["TCP_MAP_PATH"] = f"{pin_dir}/tcp_whitelist"
    paths["UDP_MAP_PATH"] = f"{pin_dir}/udp_whitelist"
    paths["TCP_ZONE_MAP_PATH"] = f"{pin_dir}/tcp_zone_whitelist"
    paths["UDP_ZONE_MAP_PATH"] = f"{pin_dir}/udp_zone_whitelist"
    paths["SCTP_MAP_PATH"] = f"{pin_dir}/sctp_whitelist"
    paths["TRUSTED_IPS_MAP_PATH4"] = f"{pin_dir}/trusted_ipv4"
    paths["TRUSTED_IPS_MAP_PATH6"] = f"{pin_dir}/trusted_ipv6"
    paths["TCP_PORT_POLICY_MAP_PATH"] = f"{pin_dir}/tcp_port_policies"
    paths["TCP_SYNCOOKIE_POLICY_MAP_PATH"] = f"{pin_dir}/tcp_synck_policy"
    paths["SYNCOOKIE_RUNTIME_CFG_MAP_PATH"] = f"{pin_dir}/sync_run_cfg"
    paths["SYNCOOKIE_PORT_RATE_MAP_PATH"] = f"{pin_dir}/sync_port_limit"
    paths["UDP_PORT_POLICY_MAP_PATH"] = f"{pin_dir}/udp_port_policies"
    paths["TCP_PROFILE_HANDLER_MAP_PATH"] = f"{pin_dir}/tcp_profile_handlers"
    paths["UDP_GLOBAL_RL_MAP_PATH"] = f"{pin_dir}/udp_global_rl"
    paths["XDP_RUNTIME_CFG_MAP_PATH"] = f"{pin_dir}/xdp_runtime_cfg"
    paths["TCP_ACL_MAP_PATH4"] = f"{pin_dir}/tcp_acl_v4"
    paths["TCP_ACL_MAP_PATH6"] = f"{pin_dir}/tcp_acl_v6"
    paths["UDP_ACL_MAP_PATH4"] = f"{pin_dir}/udp_acl_v4"
    paths["UDP_ACL_MAP_PATH6"] = f"{pin_dir}/udp_acl_v6"
    paths["SIT4_ENDPOINTS_MAP_PATH"] = f"{pin_dir}/sit4_endpoints"
    paths["SYN4_MAP_PATH"] = f"{pin_dir}/syn4"
    paths["SYN6_MAP_PATH"] = f"{pin_dir}/syn6"
    paths["UDPRT4_MAP_PATH"] = f"{pin_dir}/udprt4"
    paths["UDPRT6_MAP_PATH"] = f"{pin_dir}/udprt6"
    paths["ABUSEIPDB_RISK_MAP_PATH4"] = f"{pin_dir}/abuseipdb_v4"
    paths["REQUIRED_XDP_MAP_PATHS"] = tuple(f"{pin_dir}/{n}" for n in (REQUIRED_XDP_MAP_NAMES if map_names is None else map_names))
    return paths


def _set_bpf_pin_dir(pin_dir: str) -> None:
    globals().update(_bpf_pin_paths(pin_dir))


_set_bpf_pin_dir(_BPF_PIN_DIR)


def normalize_cidr(cidr_str: str) -> str:
    net: ipaddress.IPv4Network | ipaddress.IPv6Network
    if ":" in cidr_str:
        net = ipaddress.IPv6Network(cidr_str, strict=False)
    else:
        net = ipaddress.IPv4Network(cidr_str, strict=False)
    return f"{net.network_address}/{net.prefixlen}"


def load_toml_config(path: str = TOML_CONFIG_PATH, *, strict: bool = False) -> dict:
    if tomllib is None:
        log.debug("tomllib not available; skipping TOML config load.")
        if strict:
            raise RuntimeError("TOML support is unavailable")
        return {}
    try:
        with open(path, "rb") as f:
            return tomllib.load(f)
    except FileNotFoundError:
        if strict:
            raise
        return {}
    except OSError as exc:
        log.warning("Failed to load %s: %s", path, exc)
        if strict:
            raise
        return {}
    except ValueError as exc:
        log.warning("Invalid TOML in %s: %s", path, exc)
        raise




def _coerce_log_level(value: object, default: str = "warning") -> str:
    level = str(value).lower()
    if level not in {"debug", "info", "warning", "error"}:
        log.warning("Invalid daemon.log_level %r; using %s", value, default)
        return default
    return level


def _coerce_backend(value: object, default: str = BACKEND_AUTO) -> str:
    backend = str(value).lower()
    if backend not in {BACKEND_AUTO, BACKEND_XDP, BACKEND_NFTABLES}:
        log.warning("Invalid daemon.preferred_backend %r; using %s", value, default)
        return default
    return backend


def _coerce_positive_float(value: object, path: str, default: float) -> float:
    try:
        parsed = float(value)  # type: ignore[arg-type]  # runtime-coerce arbitrary TOML value
    except (TypeError, ValueError):
        log.warning("Invalid %s %r; using %s", path, value, default)
        return default
    if parsed <= 0:
        log.warning("Invalid %s %r; using %s", path, value, default)
        return default
    return parsed


def _coerce_positive_int(value: object, path: str, default: int) -> int:
    try:
        parsed = int(value)  # type: ignore[call-overload]  # runtime-coerce arbitrary TOML value
    except (TypeError, ValueError):
        log.warning("Invalid %s %r; using %s", path, value, default)
        return default
    if parsed <= 0:
        log.warning("Invalid %s %r; using %s", path, value, default)
        return default
    return parsed


def _coerce_nonnegative_int(value: object, path: str, default: int) -> int:
    try:
        parsed = int(value)  # type: ignore[call-overload]
    except (TypeError, ValueError):
        log.warning("Invalid %s %r; using %s", path, value, default)
        return default
    if parsed < 0:
        log.warning("Invalid %s %r; using %s", path, value, default)
        return default
    return parsed


def _coerce_percent(value: object, path: str, default: int,
                    minimum: int, maximum: int) -> int:
    parsed = _coerce_nonnegative_int(value, path, default)
    if parsed < minimum or parsed > maximum:
        log.warning("Invalid %s %r; using %s", path, value, default)
        return default
    return parsed


def _coerce_nonnegative_float(value: object, path: str, default: float) -> float:
    try:
        parsed = float(value)  # type: ignore[arg-type]  # runtime-coerce arbitrary TOML value
    except (TypeError, ValueError):
        log.warning("Invalid %s %r; using %s", path, value, default)
        return default
    if parsed < 0:
        log.warning("Invalid %s %r; using %s", path, value, default)
        return default
    return parsed


def _coerce_prefix_len(value: object, path: str, default: int, maximum: int) -> int:
    if isinstance(value, str):
        value = value.removeprefix("/")
    try:
        parsed = int(value)  # type: ignore[call-overload]  # runtime-coerce arbitrary TOML value
    except (TypeError, ValueError):
        log.warning("Invalid %s %r; using %s", path, value, default)
        return default
    if parsed < 0 or parsed > maximum:
        log.warning("Invalid %s %r; using %s", path, value, default)
        return default
    return parsed


def _normalize_config(cfg: dict) -> dict[str, Any]:
    settings = copy.deepcopy(_DEFAULT_SETTINGS)

    settings["TRUSTED_SRC_IPS"].clear()
    settings["ACL_RULES"].clear()
    settings["SIT4_ENDPOINTS"].clear()

    settings["_SYN_RATE_BY_PROC"].clear()
    settings["_SYN_RATE_BY_SERVICE"].clear()
    settings["_SYN_AGG_RATE_BY_PROC"].clear()
    settings["_SYN_AGG_RATE_BY_SERVICE"].clear()
    settings["_UDP_RATE_BY_PROC"].clear()
    settings["_UDP_RATE_BY_SERVICE"].clear()
    settings["_UDP_AGG_BYTES_BY_PROC"].clear()
    settings["_UDP_AGG_BYTES_BY_SERVICE"].clear()
    settings["_RATE_MAP_ENTRIES_BY_PROC"].clear()
    settings["_RATE_MAP_ENTRIES_BY_SERVICE"].clear()
    settings["_SYNCOOKIE_BY_PROC"].clear()
    settings["_SYNCOOKIE_BY_SERVICE"].clear()
    settings["_SYNCOOKIE_BY_PORT"].clear()
    settings["_SYNCOOKIE_PORT_RATE_BY_PROC"].clear()
    settings["_SYNCOOKIE_PORT_RATE_BY_SERVICE"].clear()
    settings["_SYNCOOKIE_PORT_RATE_BY_PORT"].clear()
    settings["DISCOVERY_EXCLUDE_BIND_CIDRS"].clear()
    settings["DISCOVERY_EXCLUDE_PORTS"].clear()
    settings["ZONES"] = {}
    settings["SUBJECTS"] = {}
    settings["UNKNOWN_SUBJECTS"] = {"public": "deny"}
    settings["POLICY_MODE"] = "audit"
    settings["RATE_LIMIT_SOURCE_PREFIX_V4"] = 32
    settings["RATE_LIMIT_SOURCE_PREFIX_V6"] = 128
    settings["RATE_MAP_ENTRIES_V4"] = settings["_RATE_MAP_TEMPLATE_ENTRIES_V4"]
    settings["RATE_MAP_ENTRIES_V6"] = settings["_RATE_MAP_TEMPLATE_ENTRIES_V6"]

    legacy_ports = cfg.get("permanent_ports")
    if legacy_ports and (
        not isinstance(legacy_ports, dict) or any(legacy_ports.values())
    ):
        raise ValueError("unsupported exposure configuration; use subjects.*.exposure grants")

    for cidr, label in cfg.get("trusted_ips", {}).items():
        settings["TRUSTED_SRC_IPS"][normalize_cidr(cidr)] = str(label)

    for ep in cfg.get("tunnel", {}).get("sit4_endpoints", []):
        try:
            ip = ipaddress.IPv4Address(str(ep))
            settings["SIT4_ENDPOINTS"].append(str(ip))
        except ValueError:
            log.warning("Invalid tunnel.sit4_endpoints entry %r; skipping.", ep)

    for rule in cfg.get("acl", []):
        settings["ACL_RULES"].append({
            "proto": rule["proto"],
            "cidr": normalize_cidr(rule["cidr"]),
            "ports": [int(p) for p in rule.get("ports", [])],
        })

    rl = cfg.get("rate_limits", {})
    settings["RATE_LIMIT_SOURCE_PREFIX_V4"] = _coerce_prefix_len(
        rl.get("source_cidr_v4", rl.get("source_prefix_v4", 32)),
        "rate_limits.source_cidr_v4",
        32,
        32,
    )
    settings["RATE_LIMIT_SOURCE_PREFIX_V6"] = _coerce_prefix_len(
        rl.get("source_cidr_v6", rl.get("source_prefix_v6", 128)),
        "rate_limits.source_cidr_v6",
        128,
        128,
    )
    for scope, target in (
        ("syn_by_proc", "_SYN_RATE_BY_PROC"), ("syn_by_service", "_SYN_RATE_BY_SERVICE"),
        ("syn_agg_by_proc", "_SYN_AGG_RATE_BY_PROC"), ("syn_agg_by_service", "_SYN_AGG_RATE_BY_SERVICE"),
        ("udp_by_proc", "_UDP_RATE_BY_PROC"), ("udp_by_service", "_UDP_RATE_BY_SERVICE"),
        ("udp_agg_bytes_by_proc", "_UDP_AGG_BYTES_BY_PROC"),
        ("udp_agg_bytes_by_service", "_UDP_AGG_BYTES_BY_SERVICE"),
    ):
        entries = rl.get(scope, {})
        if not isinstance(entries, dict):
            raise ValueError(f"rate_limits.{scope} must be a table")
        for name, value in entries.items():
            if isinstance(value, bool) or not isinstance(value, int):
                raise ValueError(f"rate_limits.{scope}.{name} must be an integer")
            limit = value
            if not 0 <= limit <= 0xFFFFFFFF:
                raise ValueError(f"rate_limits.{scope}.{name} is outside the native u32 range")
            settings[target][str(name)] = limit
    settings["RATE_MAP_ENTRIES_V4"] = int(rl.get("map_entries_v4", settings["_RATE_MAP_TEMPLATE_ENTRIES_V4"]))
    settings["RATE_MAP_ENTRIES_V6"] = int(rl.get("map_entries_v6", settings["_RATE_MAP_TEMPLATE_ENTRIES_V6"]))
    if (
        settings["RATE_MAP_ENTRIES_V4"] != settings["_RATE_MAP_TEMPLATE_ENTRIES_V4"]
        or settings["RATE_MAP_ENTRIES_V6"] != settings["_RATE_MAP_TEMPLATE_ENTRIES_V6"]
        or rl.get("map_entries_by_proc")
        or rl.get("map_entries_by_service")
    ):
        raise ValueError(
            "rate-limit inner map capacities are fixed by the compiled XDP map ABI"
        )

    syncookie = cfg.get("syncookie", {})
    if not isinstance(syncookie, dict):
        raise ValueError("syncookie must be a table")
    settings["SYNCOOKIE_ENABLED"] = bool(syncookie.get("enabled", False))
    settings["SYNCOOKIE_DEFAULT_MODE"] = str(syncookie.get("default_mode", "auto")).lower()
    if settings["SYNCOOKIE_DEFAULT_MODE"] not in settings["SYNCOOKIE_MODES"]:
        raise ValueError("syncookie.default_mode must be off, auto, or always")
    settings["SYNCOOKIE_ACTIVATION_PERCENT"] = _coerce_percent(
        syncookie.get("activation_percent", 90),
        "syncookie.activation_percent", 90, 1, 99,
    )
    settings["SYNCOOKIE_AUTO_MAX_PERCENT"] = _coerce_percent(
        syncookie.get("auto_max_percent", 200),
        "syncookie.auto_max_percent", 200, 100, 10000,
    )
    if settings["SYNCOOKIE_AUTO_MAX_PERCENT"] <= settings["SYNCOOKIE_ACTIVATION_PERCENT"]:
        raise ValueError("syncookie.auto_max_percent must exceed activation_percent")
    settings["SYNCOOKIE_CHALLENGE_COOLDOWN_SECONDS"] = _coerce_nonnegative_float(
        syncookie.get("challenge_cooldown_seconds", 5),
        "syncookie.challenge_cooldown_seconds", 5.0,
    )
    settings["SYNCOOKIE_INVALID_ACK_RATE_PPS"] = _coerce_positive_int(
        syncookie.get("invalid_ack_rate_pps", 1000),
        "syncookie.invalid_ack_rate_pps", 1000,
    )
    settings["SYNCOOKIE_PORT_RATE_DEFAULT"] = _coerce_nonnegative_int(
        syncookie.get("port_rate_default", 0),
        "syncookie.port_rate_default", 0,
    )
    for scope, target in (
        ("port_rate_by_proc", settings["_SYNCOOKIE_PORT_RATE_BY_PROC"]),
        ("port_rate_by_service", settings["_SYNCOOKIE_PORT_RATE_BY_SERVICE"]),
    ):
        values = syncookie.get(scope, {})
        if not isinstance(values, dict):
            raise ValueError(f"syncookie.{scope} must be a table")
        for name, value in values.items():
            target[str(name)] = _coerce_nonnegative_int(
                value, f"syncookie.{scope}.{name}", 0
            )
    port_rates = syncookie.get("port_rate_by_port", {})
    if not isinstance(port_rates, dict):
        raise ValueError("syncookie.port_rate_by_port must be a table")
    for raw_port, value in port_rates.items():
        try:
            port = int(raw_port)
        except (TypeError, ValueError) as exc:
            raise ValueError(
                "syncookie.port_rate_by_port keys must be ports"
            ) from exc
        if not 1 <= port <= 65535:
            raise ValueError("syncookie.port_rate_by_port keys must be ports")
        settings["_SYNCOOKIE_PORT_RATE_BY_PORT"][port] = _coerce_nonnegative_int(
            value, f"syncookie.port_rate_by_port.{port}", 0
        )
    for scope, mode_target in (
        ("by_proc", settings["_SYNCOOKIE_BY_PROC"]),
        ("by_service", settings["_SYNCOOKIE_BY_SERVICE"]),
    ):
        values = syncookie.get(scope, {})
        if not isinstance(values, dict):
            raise ValueError(f"syncookie.{scope} must be a table")
        for name, raw_mode in values.items():
            mode = str(raw_mode).lower()
            if mode not in settings["SYNCOOKIE_MODES"]:
                raise ValueError(f"syncookie.{scope}.{name} has invalid mode")
            mode_target[str(name)] = mode
    by_port = syncookie.get("by_port", {})
    if not isinstance(by_port, dict):
        raise ValueError("syncookie.by_port must be a table")
    for raw_port, raw_mode in by_port.items():
        try:
            port = int(raw_port)
        except (TypeError, ValueError) as exc:
            raise ValueError(
                "syncookie.by_port entries require port and valid mode"
            ) from exc
        mode = str(raw_mode).lower()
        if not 1 <= port <= 65535 or mode not in settings["SYNCOOKIE_MODES"]:
            raise ValueError("syncookie.by_port entries require port and valid mode")
        settings["_SYNCOOKIE_BY_PORT"][port] = mode

    settings["BOGON_FILTER_ENABLED"] = bool(cfg.get("firewall", {}).get("bogon_filter", True))
    ISATTACK = cfg.get("under_attack", {})
    settings["ISATTACK_MODE"] = bool(ISATTACK.get("enabled", False))
    settings["DROP_EVENTS_ENABLED"] = not settings["ISATTACK_MODE"]
    daemon = cfg.get("daemon", {})
    settings["LOG_LEVEL"] = _coerce_log_level(daemon.get("log_level", "warning"))
    settings["DEBOUNCE_SECONDS"] = _coerce_positive_float(
        daemon.get("debounce_seconds", 0.4),
        "daemon.debounce_seconds",
        0.4,
    )
    settings["PREFERRED_BACKEND"] = _coerce_backend(daemon.get("preferred_backend", settings["BACKEND_AUTO"]))

    discovery = cfg.get("discovery", {})
    settings["DISCOVERY_EXCLUDE_LOOPBACK"] = bool(discovery.get("exclude_loopback", True))
    settings["DISCOVERY_EXCLUDE_BIND_CIDRS"].extend(
        normalize_cidr(cidr) for cidr in discovery.get("exclude_bind_cidrs", [])
    )
    settings["DISCOVERY_EXCLUDE_PORTS"].update(
        int(p) for p in discovery.get("exclude_ports", [])
    )

    policy_cfg = cfg.get("policy", {})
    if not isinstance(policy_cfg, dict):
        raise ValueError("policy must be a table")
    settings["POLICY_MODE"] = str(policy_cfg.get("mode", "audit")).lower()
    if settings["POLICY_MODE"] not in {"observe", "audit", "enforce"}:
        raise ValueError("policy.mode must be one of observe, audit, enforce")

    raw_zones = cfg.get("zones", {})
    if not isinstance(raw_zones, dict):
        raise ValueError("zones must be a table")
    interface_zones: dict[str, str] = {}
    for zone_name, zone in raw_zones.items():
        if not isinstance(zone, dict):
            raise ValueError(f"zones.{zone_name} must be a table")
        interfaces = zone.get("interfaces", [])
        if not isinstance(interfaces, list) or not all(isinstance(item, str) for item in interfaces):
            raise ValueError(f"zones.{zone_name}.interfaces must be a list of strings")
        cidrs = zone.get("cidrs", [])
        if not isinstance(cidrs, list) or not all(isinstance(item, str) for item in cidrs):
            raise ValueError(f"zones.{zone_name}.cidrs must be a list of strings")
        for interface in interfaces:
            if interface == "*":
                continue
            previous = interface_zones.setdefault(interface, str(zone_name))
            if previous != str(zone_name):
                raise ValueError(
                    f"interface {interface!r} belongs to both zones {previous!r} and {zone_name!r}"
                )
        settings["ZONES"][str(zone_name)] = {"interfaces": list(interfaces), "cidrs": list(cidrs)}
    settings["ZONES"].setdefault("public", {"interfaces": [], "cidrs": []})

    raw_subjects = cfg.get("subjects", {})
    if not isinstance(raw_subjects, dict):
        raise ValueError("subjects must be a table")
    seen_resolvers: list[tuple[str, dict]] = []
    for subject_name, subject in raw_subjects.items():
        if not isinstance(subject, dict):
            raise ValueError(f"subjects.{subject_name} must be a table")
        resolve = subject.get("resolve", {})
        if not isinstance(resolve, dict):
            raise ValueError(f"subjects.{subject_name}.resolve must be a table")
        resolve_keys = {
            "systemd_unit", "process_name", "container_runtime", "container_id",
            "container_name", "container_label",
        }
        unknown_resolve = set(resolve) - resolve_keys
        if unknown_resolve:
            raise ValueError(
                f"subjects.{subject_name}.resolve has unsupported keys: "
                f"{', '.join(sorted(str(key) for key in unknown_resolve))}"
            )
        container_runtime = resolve.get("container_runtime")
        if container_runtime is not None and str(container_runtime).lower() not in {"docker", "podman"}:
            raise ValueError(f"subjects.{subject_name}.resolve.container_runtime must be docker or podman")
        container_label = resolve.get("container_label")
        if container_label is not None and not isinstance(container_label, (str, dict)):
            raise ValueError(f"subjects.{subject_name}.resolve.container_label must be a string or table")
        container_identity = any(
            bool(resolve.get(key))
            for key in ("container_id", "container_name", "container_label")
        )
        if container_runtime and not container_identity:
            raise ValueError(
                f"subjects.{subject_name}.resolve.container_runtime requires container identity"
            )
        exposure = subject.get("exposure", {})
        if not isinstance(exposure, dict):
            raise ValueError(f"subjects.{subject_name}.exposure must be a table")
        for zone_name, zone_policy in exposure.items():
            if str(zone_name) not in settings["ZONES"]:
                raise ValueError(f"subjects.{subject_name} references unknown zone {zone_name}")
            if not isinstance(zone_policy, dict):
                raise ValueError(f"subjects.{subject_name}.exposure.{zone_name} must be a table")
            for protocol in ("tcp", "udp", "sctp"):
                protocol_policy = zone_policy.get(protocol)
                if protocol_policy is None:
                    continue
                if not isinstance(protocol_policy, dict):
                    raise ValueError(f"subjects.{subject_name}.exposure.{zone_name}.{protocol} must be a table")
                ports = protocol_policy.get("ports", [])
                if not isinstance(ports, list):
                    raise ValueError(f"subjects.{subject_name}.exposure.{zone_name}.{protocol}.ports must be a list")
                try:
                    if any(isinstance(port, bool) or not 1 <= int(port) <= 65535 for port in ports):
                        raise ValueError
                except (TypeError, ValueError):
                    raise ValueError(
                        f"subjects.{subject_name}.exposure.{zone_name}.{protocol}.ports must contain 1..65535"
                    ) from None
        has_policy = any(
            isinstance(zone_policy, dict)
            and (
                zone_policy.get("deny")
                or any(
                    isinstance(zone_policy.get(protocol), dict)
                    and zone_policy[protocol].get("ports")
                    for protocol in ("tcp", "udp", "sctp")
                )
            )
            for zone_policy in exposure.values()
        )
        if resolve and has_policy:
            for previous_name, previous_resolver in seen_resolvers:
                if resolve == previous_resolver:
                    raise ValueError(
                        f"subjects.{subject_name}.resolve duplicates subjects.{previous_name}.resolve"
                    )
            seen_resolvers.append((str(subject_name), resolve))
        settings["SUBJECTS"][str(subject_name)] = copy.deepcopy(subject)

    raw_unknown = cfg.get("unknown_subjects", policy_cfg.get("unknown_subjects", {"public": "deny"}))
    if not isinstance(raw_unknown, dict):
        raise ValueError("unknown_subjects must be a table")
    for zone_name, action in raw_unknown.items():
        if str(action).lower() != "deny":
            raise ValueError("unknown_subjects may only use deny")
        settings["UNKNOWN_SUBJECTS"][str(zone_name)] = "deny"

    xdp = cfg.get("xdp", {})
    settings.update(_bpf_pin_paths(str(xdp.get("bpf_pin_dir", settings["_BPF_PIN_DIR"])).rstrip("/"), settings["REQUIRED_XDP_MAP_NAMES"]))

    nftables = cfg.get("nftables", {})
    settings["NFT_FAMILY"] = str(nftables.get("family", settings["_NFT_FAMILY"]))
    settings["NFT_TABLE"] = str(nftables.get("table", settings["_NFT_TABLE"]))

    xdp_runtime = xdp.get("runtime", {})
    settings["XDP_ICMP_BURST_PACKETS"] = _coerce_positive_int(
        xdp_runtime.get("icmp_burst_packets", 100),
        "xdp.runtime.icmp_burst_packets",
        100,
    )
    settings["XDP_ICMP_RATE_PPS"] = _coerce_nonnegative_float(
        xdp_runtime.get("icmp_rate_pps", 100.0),
        "xdp.runtime.icmp_rate_pps",
        100.0,
    )
    settings["XDP_UDP_GLOBAL_WINDOW_SECONDS"] = _coerce_nonnegative_float(
        xdp_runtime.get("udp_global_window_seconds", 1.0),
        "xdp.runtime.udp_global_window_seconds",
        1.0,
    )
    settings["XDP_RATE_WINDOW_SECONDS"] = _coerce_nonnegative_float(
        xdp_runtime.get("rate_window_seconds", 1.0),
        "xdp.runtime.rate_window_seconds",
        1.0,
    )
    settings["XDP_SENSITIVE_PORT_THRESHOLD"] = _coerce_positive_int(
        xdp_runtime.get("sensitive_port_threshold", 5),
        "xdp.runtime.sensitive_port_threshold", 5,
    )
    settings["XDP_DEFAULT_TCP_SYN_RATE_STRICT"] = _coerce_positive_int(
        xdp_runtime.get("default_tcp_syn_rate_strict", 5),
        "xdp.runtime.default_tcp_syn_rate_strict", 5,
    )
    settings["XDP_DEFAULT_TCP_SYN_RATE"] = _coerce_positive_int(
        xdp_runtime.get("default_tcp_syn_rate", 100),
        "xdp.runtime.default_tcp_syn_rate", 100,
    )
    settings["XDP_DEFAULT_TCP_SYN_AGG_RATE_STRICT"] = _coerce_positive_int(
        xdp_runtime.get("default_tcp_syn_agg_rate_strict", 50),
        "xdp.runtime.default_tcp_syn_agg_rate_strict", 50,
    )
    settings["XDP_DEFAULT_TCP_SYN_AGG_RATE"] = _coerce_positive_int(
        xdp_runtime.get("default_tcp_syn_agg_rate", 1000),
        "xdp.runtime.default_tcp_syn_agg_rate", 1000,
    )
    _udp_global_byte_rate_mbps = _coerce_nonnegative_float(
        xdp_runtime.get("udp_global_byte_rate_mbps", 0.0),
        "xdp.runtime.udp_global_byte_rate_mbps",
        0.0,
    )
    settings["XDP_UDP_GLOBAL_BYTE_RATE"] = int(_udp_global_byte_rate_mbps * 1_000_000 / 8)

    _slots = cfg.get("slots", {})
    _slot_default = str(_slots.get("default_action", "drop")).lower()
    settings["SLOT_DEFAULT_ACTION"] = "drop" if _slot_default == "drop" else "pass"

    _ab = cfg.get("abuseipdb", {})
    settings["ABUSEIPDB_ENABLED"] = bool(_ab.get("enabled", False))
    settings["ABUSEIPDB_BASE_URL"] = str(_ab.get(
        "base_url",
        "https://raw.githubusercontent.com/borestad/blocklist-abuseipdb/refs/heads/main",
    ))
    _raw_sources = _ab.get("sources", ["s1003d"])
    settings["ABUSEIPDB_SOURCES"] = [str(s) for s in _raw_sources] if isinstance(_raw_sources, list) else ["s1003d"]
    settings["ABUSEIPDB_REFRESH_SECONDS"] = _coerce_positive_float(
        _ab.get("refresh_seconds", 3600.0),
        "abuseipdb.refresh_seconds",
        3600.0,
    )

    return settings


def parse_toml_config(raw: dict) -> ConfigSnapshot:
    """Validate and normalize a candidate without publishing any settings."""
    return ConfigSnapshot(_normalize_config(raw))


def apply_toml_config(raw: dict) -> ConfigSnapshot:
    """Publish a fully validated candidate; retain legacy container aliases."""
    values = _normalize_config(raw)
    candidate = ConfigSnapshot(values)
    with _CONFIG_LOCK:
        for name, value in values.items():
            original = globals()[name]
            if isinstance(original, dict):
                original.clear()
                original.update(value)
            elif isinstance(original, list):
                original[:] = value
            elif isinstance(original, set):
                original.clear()
                original.update(value)
            else:
                globals()[name] = value
    return candidate


_SETTING_NAMES = tuple(name for name in globals() if name.isupper() and name != "_CONFIG_LOCK")
_DEFAULT_SETTINGS = copy.deepcopy({name: globals()[name] for name in _SETTING_NAMES})
