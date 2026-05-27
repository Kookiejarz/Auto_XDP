from __future__ import annotations

import ipaddress
import logging
import os
from pathlib import Path

try:
    import tomllib  # Python 3.11+
except ImportError:
    try:
        import tomli as tomllib  # type: ignore[no-redef]
    except ImportError:
        tomllib = None  # type: ignore[assignment]


log = logging.getLogger(__name__)

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
TC_OBJ_PATH = os.environ.get("TC_OBJ_PATH", "")

_SYN_RATE_BY_PROC: dict[str, int] = {}
_SYN_RATE_BY_SERVICE: dict[str, int] = {}
_SYN_AGG_RATE_BY_PROC: dict[str, int] = {}
_SYN_AGG_RATE_BY_SERVICE: dict[str, int] = {}
_TCP_CONN_BY_PROC: dict[str, int] = {}
_TCP_CONN_BY_SERVICE: dict[str, int] = {}
_TCP_CONN_PREFIX_BY_PROC: dict[str, int] = {}
_TCP_CONN_PREFIX_BY_SERVICE: dict[str, int] = {}
_TCP_CONN_PORT_BY_PROC: dict[str, int] = {}
_TCP_CONN_PORT_BY_SERVICE: dict[str, int] = {}
_UDP_RATE_BY_PROC: dict[str, int] = {}
_UDP_RATE_BY_SERVICE: dict[str, int] = {}
_UDP_AGG_BYTES_BY_PROC: dict[str, int] = {}
_UDP_AGG_BYTES_BY_SERVICE: dict[str, int] = {}

# Default-on TCP protection knobs — applied when no explicit per-proc/service
# entry exists. See docs/superpowers/specs/2026-05-06-tcp-default-on-protection-design.md.
XDP_SENSITIVE_PORT_THRESHOLD = 5
XDP_DEFAULT_TCP_SYN_RATE_STRICT = 5
XDP_DEFAULT_TCP_SYN_RATE = 100
XDP_DEFAULT_TCP_SYN_AGG_RATE_STRICT = 50
XDP_DEFAULT_TCP_SYN_AGG_RATE = 1000
XDP_DEFAULT_TCP_ESTABLISHED_PER_SRC_STRICT = 5
XDP_DEFAULT_TCP_ESTABLISHED_PER_SRC = 50
XDP_DEFAULT_TCP_ESTABLISHED_PER_PREFIX_STRICT = 20
XDP_DEFAULT_TCP_ESTABLISHED_PER_PREFIX = 200
XDP_DEFAULT_TCP_ESTABLISHED_PER_PORT_STRICT = 200
XDP_DEFAULT_TCP_ESTABLISHED_PER_PORT = 5000
RATE_LIMIT_SOURCE_PREFIX_V4 = 32
RATE_LIMIT_SOURCE_PREFIX_V6 = 128

BOGON_FILTER_ENABLED = True
ISATTACK_MODE = False
DROP_EVENTS_ENABLED = True
LOG_LEVEL: str = "warning"
DEBOUNCE_SECONDS = 0.4
DISCOVERY_EXCLUDE_LOOPBACK = True
DISCOVERY_EXCLUDE_BIND_CIDRS: list[str] = []
PREFERRED_BACKEND = BACKEND_AUTO
XDP_CONNTRACK_STALE_RECONCILES = 2
XDP_TCP_TIMEOUT_SECONDS = 300.0
XDP_UDP_TIMEOUT_SECONDS = 60.0
XDP_CONNTRACK_REFRESH_SECONDS = 30.0
XDP_CONNTRACK_GC_INTERVAL_SECONDS = 300.0
XDP_ICMP_BURST_PACKETS = 100
XDP_ICMP_RATE_PPS = 100.0
XDP_UDP_GLOBAL_WINDOW_SECONDS = 1.0
XDP_RATE_WINDOW_SECONDS = 1.0
XDP_SYN_TIMEOUT_SECONDS = 30.0
XDP_UDP_GLOBAL_BYTE_RATE = 0

NFT_FAMILY = _NFT_FAMILY
NFT_TABLE = _NFT_TABLE
NFT_TCP_SET = "tcp_ports"
NFT_UDP_SET = "udp_ports"
NFT_SCTP_SET = "sctp_ports"
NFT_TRUSTED_SET4 = "trusted_v4"
NFT_TRUSTED_SET6 = "trusted_v6"

TCP_PERMANENT: dict[int, str] = {}
UDP_PERMANENT: dict[int, str] = {}
SCTP_PERMANENT: dict[int, str] = {}
TRUSTED_SRC_IPS: dict[str, str] = {}
ACL_RULES: list[dict] = []
SIT4_ENDPOINTS: list[str] = []

ABUSEIPDB_ENABLED = False
ABUSEIPDB_BASE_URL = "https://raw.githubusercontent.com/borestad/blocklist-abuseipdb/refs/heads/main"
ABUSEIPDB_SOURCES: list[str] = ["s1003d"]
ABUSEIPDB_REFRESH_SECONDS = 3600.0
ABUSEIPDB_RISK_MAP_PATH4 = ""
ABUSEIPDB_CFG_MAP_PATH = ""

ACL_MAX_PORTS = 64
ACL_VAL_SIZE = 4 + ACL_MAX_PORTS * 2

_PACKAGE_DIR = Path(__file__).resolve().parent
_DEFAULT_XDP_REQUIRED_MAP_NAMES = (
    "prog",
    "tcp_whitelist",
    "udp_whitelist",
    "sctp_whitelist",
    "tcp_ct4",
    "tcp_ct6",
    "udp_ct4",
    "udp_ct6",
    "sctp_conntrack",
    "trusted_ipv4",
    "trusted_ipv6",
    "tcp_port_policies",
    "udp_port_policies",
    "udp_global_rl",
    "xdp_runtime_cfg",
    "udp_percpu_acc",
    "proto_handlers",
    "tcp_port_handlers",
    "udp_port_handlers",
    "tcp_pd4",
    "tcp_pd6",
    "hblk4",
    "hblk6",
    "udp_hv4",
    "udp_hv6",
    "slot_ctx_map",
    "sit4_endpoints",
    "tsc_pfx4",
    "tsc_pfx6",
    "tsc_port",
    "abuseipdb_v4",
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

TSC_PFX4_MAP_PATH = ""
TSC_PFX6_MAP_PATH = ""
TSC_PORT_MAP_PATH = ""


def _set_bpf_pin_dir(pin_dir: str) -> None:
    """Update BPF_PIN_DIR and every derived map-path global in one place."""
    global BPF_PIN_DIR
    global TCP_MAP_PATH, UDP_MAP_PATH, SCTP_MAP_PATH
    global TCP_CONNTRACK_MAP_PATH4, TCP_CONNTRACK_MAP_PATH6
    global UDP_CONNTRACK_MAP_PATH4, UDP_CONNTRACK_MAP_PATH6
    global TRUSTED_IPS_MAP_PATH4, TRUSTED_IPS_MAP_PATH6
    global TCP_PORT_POLICY_MAP_PATH, UDP_PORT_POLICY_MAP_PATH
    global UDP_GLOBAL_RL_MAP_PATH, XDP_RUNTIME_CFG_MAP_PATH
    global BOGON_CFG_MAP_PATH, OBSERVABILITY_CFG_MAP_PATH
    global TCP_ACL_MAP_PATH4, TCP_ACL_MAP_PATH6
    global UDP_ACL_MAP_PATH4, UDP_ACL_MAP_PATH6
    global SIT4_ENDPOINTS_MAP_PATH
    global TSC_PFX4_MAP_PATH, TSC_PFX6_MAP_PATH, TSC_PORT_MAP_PATH
    global REQUIRED_XDP_MAP_PATHS
    global ABUSEIPDB_RISK_MAP_PATH4, ABUSEIPDB_CFG_MAP_PATH
    BPF_PIN_DIR = pin_dir
    TCP_MAP_PATH = f"{pin_dir}/tcp_whitelist"
    UDP_MAP_PATH = f"{pin_dir}/udp_whitelist"
    SCTP_MAP_PATH = f"{pin_dir}/sctp_whitelist"
    TCP_CONNTRACK_MAP_PATH4 = f"{pin_dir}/tcp_ct4"
    TCP_CONNTRACK_MAP_PATH6 = f"{pin_dir}/tcp_ct6"
    UDP_CONNTRACK_MAP_PATH4 = f"{pin_dir}/udp_ct4"
    UDP_CONNTRACK_MAP_PATH6 = f"{pin_dir}/udp_ct6"
    TRUSTED_IPS_MAP_PATH4 = f"{pin_dir}/trusted_ipv4"
    TRUSTED_IPS_MAP_PATH6 = f"{pin_dir}/trusted_ipv6"
    TCP_PORT_POLICY_MAP_PATH = f"{pin_dir}/tcp_port_policies"
    UDP_PORT_POLICY_MAP_PATH = f"{pin_dir}/udp_port_policies"
    UDP_GLOBAL_RL_MAP_PATH = f"{pin_dir}/udp_global_rl"
    XDP_RUNTIME_CFG_MAP_PATH = f"{pin_dir}/xdp_runtime_cfg"
    TCP_ACL_MAP_PATH4 = f"{pin_dir}/tcp_acl_v4"
    TCP_ACL_MAP_PATH6 = f"{pin_dir}/tcp_acl_v6"
    UDP_ACL_MAP_PATH4 = f"{pin_dir}/udp_acl_v4"
    UDP_ACL_MAP_PATH6 = f"{pin_dir}/udp_acl_v6"
    SIT4_ENDPOINTS_MAP_PATH = f"{pin_dir}/sit4_endpoints"
    TSC_PFX4_MAP_PATH = f"{pin_dir}/tsc_pfx4"
    TSC_PFX6_MAP_PATH = f"{pin_dir}/tsc_pfx6"
    TSC_PORT_MAP_PATH = f"{pin_dir}/tsc_port"
    ABUSEIPDB_RISK_MAP_PATH4 = f"{pin_dir}/abuseipdb_v4"
    ABUSEIPDB_CFG_MAP_PATH = f"{pin_dir}/abuseipdb_cfg"
    REQUIRED_XDP_MAP_PATHS = tuple(f"{pin_dir}/{n}" for n in REQUIRED_XDP_MAP_NAMES)


_set_bpf_pin_dir(_BPF_PIN_DIR)


def normalize_cidr(cidr_str: str) -> str:
    if ":" in cidr_str:
        net = ipaddress.IPv6Network(cidr_str, strict=False)
    else:
        net = ipaddress.IPv4Network(cidr_str, strict=False)
    return f"{net.network_address}/{net.prefixlen}"


def load_toml_config(path: str = TOML_CONFIG_PATH) -> dict:
    if tomllib is None:
        log.debug("tomllib not available; skipping TOML config load.")
        return {}
    try:
        with open(path, "rb") as f:
            return tomllib.load(f)
    except FileNotFoundError:
        return {}
    except OSError as exc:
        log.warning("Failed to load %s: %s", path, exc)
        return {}




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
        parsed = float(value)
    except (TypeError, ValueError):
        log.warning("Invalid %s %r; using %s", path, value, default)
        return default
    if parsed <= 0:
        log.warning("Invalid %s %r; using %s", path, value, default)
        return default
    return parsed


def _coerce_positive_int(value: object, path: str, default: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        log.warning("Invalid %s %r; using %s", path, value, default)
        return default
    if parsed <= 0:
        log.warning("Invalid %s %r; using %s", path, value, default)
        return default
    return parsed


def _coerce_nonnegative_float(value: object, path: str, default: float) -> float:
    try:
        parsed = float(value)
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
        parsed = int(value)
    except (TypeError, ValueError):
        log.warning("Invalid %s %r; using %s", path, value, default)
        return default
    if parsed < 0 or parsed > maximum:
        log.warning("Invalid %s %r; using %s", path, value, default)
        return default
    return parsed


def apply_toml_config(cfg: dict) -> None:
    global BOGON_FILTER_ENABLED, ISATTACK_MODE, DROP_EVENTS_ENABLED
    global LOG_LEVEL, DEBOUNCE_SECONDS
    global DISCOVERY_EXCLUDE_LOOPBACK, DISCOVERY_EXCLUDE_BIND_CIDRS
    global PREFERRED_BACKEND, XDP_CONNTRACK_STALE_RECONCILES
    global RATE_LIMIT_SOURCE_PREFIX_V4, RATE_LIMIT_SOURCE_PREFIX_V6
    global XDP_TCP_TIMEOUT_SECONDS, XDP_UDP_TIMEOUT_SECONDS
    global XDP_CONNTRACK_REFRESH_SECONDS, XDP_CONNTRACK_GC_INTERVAL_SECONDS
    global XDP_ICMP_BURST_PACKETS, XDP_ICMP_RATE_PPS
    global XDP_UDP_GLOBAL_WINDOW_SECONDS, XDP_RATE_WINDOW_SECONDS
    global XDP_SYN_TIMEOUT_SECONDS, XDP_UDP_GLOBAL_BYTE_RATE
    global NFT_FAMILY, NFT_TABLE
    global XDP_SENSITIVE_PORT_THRESHOLD
    global XDP_DEFAULT_TCP_SYN_RATE_STRICT, XDP_DEFAULT_TCP_SYN_RATE
    global XDP_DEFAULT_TCP_SYN_AGG_RATE_STRICT, XDP_DEFAULT_TCP_SYN_AGG_RATE
    global XDP_DEFAULT_TCP_ESTABLISHED_PER_SRC_STRICT, XDP_DEFAULT_TCP_ESTABLISHED_PER_SRC
    global XDP_DEFAULT_TCP_ESTABLISHED_PER_PREFIX_STRICT, XDP_DEFAULT_TCP_ESTABLISHED_PER_PREFIX
    global XDP_DEFAULT_TCP_ESTABLISHED_PER_PORT_STRICT, XDP_DEFAULT_TCP_ESTABLISHED_PER_PORT

    TCP_PERMANENT.clear()
    UDP_PERMANENT.clear()
    SCTP_PERMANENT.clear()
    TRUSTED_SRC_IPS.clear()
    ACL_RULES.clear()
    SIT4_ENDPOINTS.clear()

    _SYN_RATE_BY_PROC.clear()
    _SYN_RATE_BY_SERVICE.clear()
    _SYN_AGG_RATE_BY_PROC.clear()
    _SYN_AGG_RATE_BY_SERVICE.clear()
    _TCP_CONN_BY_PROC.clear()
    _TCP_CONN_BY_SERVICE.clear()
    _TCP_CONN_PREFIX_BY_PROC.clear()
    _TCP_CONN_PREFIX_BY_SERVICE.clear()
    _TCP_CONN_PORT_BY_PROC.clear()
    _TCP_CONN_PORT_BY_SERVICE.clear()
    _UDP_RATE_BY_PROC.clear()
    _UDP_RATE_BY_SERVICE.clear()
    _UDP_AGG_BYTES_BY_PROC.clear()
    _UDP_AGG_BYTES_BY_SERVICE.clear()
    DISCOVERY_EXCLUDE_BIND_CIDRS.clear()
    RATE_LIMIT_SOURCE_PREFIX_V4 = 32
    RATE_LIMIT_SOURCE_PREFIX_V6 = 128

    perm = cfg.get("permanent_ports", {})
    for p in perm.get("tcp", []):
        TCP_PERMANENT[int(p)] = "config"
    for p in perm.get("udp", []):
        UDP_PERMANENT[int(p)] = "config"
    for p in perm.get("sctp", []):
        SCTP_PERMANENT[int(p)] = "config"

    for cidr, label in cfg.get("trusted_ips", {}).items():
        TRUSTED_SRC_IPS[normalize_cidr(cidr)] = str(label)

    for ep in cfg.get("tunnel", {}).get("sit4_endpoints", []):
        try:
            ip = ipaddress.IPv4Address(str(ep))
            SIT4_ENDPOINTS.append(str(ip))
        except ValueError:
            log.warning("Invalid tunnel.sit4_endpoints entry %r; skipping.", ep)

    for rule in cfg.get("acl", []):
        ACL_RULES.append({
            "proto": rule["proto"],
            "cidr": normalize_cidr(rule["cidr"]),
            "ports": [int(p) for p in rule.get("ports", [])],
        })

    rl = cfg.get("rate_limits", {})
    RATE_LIMIT_SOURCE_PREFIX_V4 = _coerce_prefix_len(
        rl.get("source_cidr_v4", rl.get("source_prefix_v4", 32)),
        "rate_limits.source_cidr_v4",
        32,
        32,
    )
    RATE_LIMIT_SOURCE_PREFIX_V6 = _coerce_prefix_len(
        rl.get("source_cidr_v6", rl.get("source_prefix_v6", 128)),
        "rate_limits.source_cidr_v6",
        128,
        128,
    )
    _SYN_RATE_BY_PROC.update({k: int(v) for k, v in rl.get("syn_by_proc", {}).items()})
    _SYN_RATE_BY_SERVICE.update({k: int(v) for k, v in rl.get("syn_by_service", {}).items()})
    _SYN_AGG_RATE_BY_PROC.update({k: int(v) for k, v in rl.get("syn_agg_by_proc", {}).items()})
    _SYN_AGG_RATE_BY_SERVICE.update({k: int(v) for k, v in rl.get("syn_agg_by_service", {}).items()})
    _TCP_CONN_BY_PROC.update({k: int(v) for k, v in rl.get("tcp_conn_by_proc", {}).items()})
    _TCP_CONN_BY_SERVICE.update({k: int(v) for k, v in rl.get("tcp_conn_by_service", {}).items()})
    _TCP_CONN_PREFIX_BY_PROC.update({k: int(v) for k, v in rl.get("tcp_conn_prefix_by_proc", {}).items()})
    _TCP_CONN_PREFIX_BY_SERVICE.update({k: int(v) for k, v in rl.get("tcp_conn_prefix_by_service", {}).items()})
    _TCP_CONN_PORT_BY_PROC.update({k: int(v) for k, v in rl.get("tcp_conn_port_by_proc", {}).items()})
    _TCP_CONN_PORT_BY_SERVICE.update({k: int(v) for k, v in rl.get("tcp_conn_port_by_service", {}).items()})
    _UDP_RATE_BY_PROC.update({k: int(v) for k, v in rl.get("udp_by_proc", {}).items()})
    _UDP_RATE_BY_SERVICE.update({k: int(v) for k, v in rl.get("udp_by_service", {}).items()})
    _UDP_AGG_BYTES_BY_PROC.update({k: int(v) for k, v in rl.get("udp_agg_bytes_by_proc", {}).items()})
    _UDP_AGG_BYTES_BY_SERVICE.update({k: int(v) for k, v in rl.get("udp_agg_bytes_by_service", {}).items()})

    BOGON_FILTER_ENABLED = bool(cfg.get("firewall", {}).get("bogon_filter", True))
    ISATTACK = cfg.get("under_attack", {})
    ISATTACK_MODE = bool(ISATTACK.get("enabled", False))
    DROP_EVENTS_ENABLED = not ISATTACK_MODE
    daemon = cfg.get("daemon", {})
    LOG_LEVEL = _coerce_log_level(daemon.get("log_level", "warning"))
    DEBOUNCE_SECONDS = _coerce_positive_float(
        daemon.get("debounce_seconds", 0.4),
        "daemon.debounce_seconds",
        0.4,
    )
    PREFERRED_BACKEND = _coerce_backend(daemon.get("preferred_backend", BACKEND_AUTO))

    discovery = cfg.get("discovery", {})
    DISCOVERY_EXCLUDE_LOOPBACK = bool(discovery.get("exclude_loopback", True))
    DISCOVERY_EXCLUDE_BIND_CIDRS.extend(
        normalize_cidr(cidr) for cidr in discovery.get("exclude_bind_cidrs", [])
    )

    xdp = cfg.get("xdp", {})
    _set_bpf_pin_dir(str(xdp.get("bpf_pin_dir", _BPF_PIN_DIR)).rstrip("/"))

    nftables = cfg.get("nftables", {})
    NFT_FAMILY = str(nftables.get("family", _NFT_FAMILY))
    NFT_TABLE = str(nftables.get("table", _NFT_TABLE))

    XDP_CONNTRACK_STALE_RECONCILES = _coerce_positive_int(
        xdp.get("conntrack_stale_reconciles", 2),
        "xdp.conntrack_stale_reconciles",
        2,
    )
    xdp_runtime = xdp.get("runtime", {})
    XDP_TCP_TIMEOUT_SECONDS = _coerce_nonnegative_float(
        xdp_runtime.get("tcp_timeout_seconds", 300.0),
        "xdp.runtime.tcp_timeout_seconds",
        300.0,
    )
    XDP_UDP_TIMEOUT_SECONDS = _coerce_nonnegative_float(
        xdp_runtime.get("udp_timeout_seconds", 60.0),
        "xdp.runtime.udp_timeout_seconds",
        60.0,
    )
    XDP_CONNTRACK_REFRESH_SECONDS = _coerce_nonnegative_float(
        xdp_runtime.get("conntrack_refresh_seconds", 30.0),
        "xdp.runtime.conntrack_refresh_seconds",
        30.0,
    )
    XDP_CONNTRACK_GC_INTERVAL_SECONDS = _coerce_nonnegative_float(
        xdp_runtime.get("conntrack_gc_interval_seconds", 300.0),
        "xdp.runtime.conntrack_gc_interval_seconds",
        300.0,
    )
    XDP_ICMP_BURST_PACKETS = _coerce_positive_int(
        xdp_runtime.get("icmp_burst_packets", 100),
        "xdp.runtime.icmp_burst_packets",
        100,
    )
    XDP_ICMP_RATE_PPS = _coerce_nonnegative_float(
        xdp_runtime.get("icmp_rate_pps", 100.0),
        "xdp.runtime.icmp_rate_pps",
        100.0,
    )
    XDP_UDP_GLOBAL_WINDOW_SECONDS = _coerce_nonnegative_float(
        xdp_runtime.get("udp_global_window_seconds", 1.0),
        "xdp.runtime.udp_global_window_seconds",
        1.0,
    )
    XDP_RATE_WINDOW_SECONDS = _coerce_nonnegative_float(
        xdp_runtime.get("rate_window_seconds", 1.0),
        "xdp.runtime.rate_window_seconds",
        1.0,
    )
    XDP_SYN_TIMEOUT_SECONDS = _coerce_nonnegative_float(
        xdp_runtime.get("syn_timeout_seconds", 30.0),
        "xdp.runtime.syn_timeout_seconds",
        30.0,
    )
    XDP_SENSITIVE_PORT_THRESHOLD = _coerce_positive_int(
        xdp_runtime.get("sensitive_port_threshold", 5),
        "xdp.runtime.sensitive_port_threshold", 5,
    )
    XDP_DEFAULT_TCP_SYN_RATE_STRICT = _coerce_positive_int(
        xdp_runtime.get("default_tcp_syn_rate_strict", 5),
        "xdp.runtime.default_tcp_syn_rate_strict", 5,
    )
    XDP_DEFAULT_TCP_SYN_RATE = _coerce_positive_int(
        xdp_runtime.get("default_tcp_syn_rate", 100),
        "xdp.runtime.default_tcp_syn_rate", 100,
    )
    XDP_DEFAULT_TCP_SYN_AGG_RATE_STRICT = _coerce_positive_int(
        xdp_runtime.get("default_tcp_syn_agg_rate_strict", 50),
        "xdp.runtime.default_tcp_syn_agg_rate_strict", 50,
    )
    XDP_DEFAULT_TCP_SYN_AGG_RATE = _coerce_positive_int(
        xdp_runtime.get("default_tcp_syn_agg_rate", 1000),
        "xdp.runtime.default_tcp_syn_agg_rate", 1000,
    )
    XDP_DEFAULT_TCP_ESTABLISHED_PER_SRC_STRICT = _coerce_positive_int(
        xdp_runtime.get("default_tcp_established_per_src_strict", 5),
        "xdp.runtime.default_tcp_established_per_src_strict", 5,
    )
    XDP_DEFAULT_TCP_ESTABLISHED_PER_SRC = _coerce_positive_int(
        xdp_runtime.get("default_tcp_established_per_src", 50),
        "xdp.runtime.default_tcp_established_per_src", 50,
    )
    XDP_DEFAULT_TCP_ESTABLISHED_PER_PREFIX_STRICT = _coerce_positive_int(
        xdp_runtime.get("default_tcp_established_per_prefix_strict", 20),
        "xdp.runtime.default_tcp_established_per_prefix_strict", 20,
    )
    XDP_DEFAULT_TCP_ESTABLISHED_PER_PREFIX = _coerce_positive_int(
        xdp_runtime.get("default_tcp_established_per_prefix", 200),
        "xdp.runtime.default_tcp_established_per_prefix", 200,
    )
    XDP_DEFAULT_TCP_ESTABLISHED_PER_PORT_STRICT = _coerce_positive_int(
        xdp_runtime.get("default_tcp_established_per_port_strict", 200),
        "xdp.runtime.default_tcp_established_per_port_strict", 200,
    )
    XDP_DEFAULT_TCP_ESTABLISHED_PER_PORT = _coerce_positive_int(
        xdp_runtime.get("default_tcp_established_per_port", 5000),
        "xdp.runtime.default_tcp_established_per_port", 5000,
    )
    _udp_global_byte_rate_mbps = _coerce_nonnegative_float(
        xdp_runtime.get("udp_global_byte_rate_mbps", 0.0),
        "xdp.runtime.udp_global_byte_rate_mbps",
        0.0,
    )
    XDP_UDP_GLOBAL_BYTE_RATE = int(_udp_global_byte_rate_mbps * 1_000_000 / 8)

    global ABUSEIPDB_ENABLED, ABUSEIPDB_BASE_URL, ABUSEIPDB_SOURCES, ABUSEIPDB_REFRESH_SECONDS
    _ab = cfg.get("abuseipdb", {})
    ABUSEIPDB_ENABLED = bool(_ab.get("enabled", False))
    ABUSEIPDB_BASE_URL = str(_ab.get(
        "base_url",
        "https://raw.githubusercontent.com/borestad/blocklist-abuseipdb/refs/heads/main",
    ))
    _raw_sources = _ab.get("sources", ["s1003d"])
    ABUSEIPDB_SOURCES = [str(s) for s in _raw_sources] if isinstance(_raw_sources, list) else ["s1003d"]
    ABUSEIPDB_REFRESH_SECONDS = _coerce_positive_float(
        _ab.get("refresh_seconds", 3600.0),
        "abuseipdb.refresh_seconds",
        3600.0,
    )
