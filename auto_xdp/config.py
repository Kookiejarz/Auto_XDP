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

BACKEND_AUTO = "auto"
BACKEND_XDP = "xdp"
BACKEND_NFTABLES = "nftables"

TCP_MAP_PATH = "/sys/fs/bpf/xdp_fw/tcp_whitelist"
UDP_MAP_PATH = "/sys/fs/bpf/xdp_fw/udp_whitelist"
SCTP_MAP_PATH = "/sys/fs/bpf/xdp_fw/sctp_whitelist"
TCP_CONNTRACK_MAP_PATH4 = "/sys/fs/bpf/xdp_fw/tcp_ct4"
TCP_CONNTRACK_MAP_PATH6 = "/sys/fs/bpf/xdp_fw/tcp_ct6"
UDP_CONNTRACK_MAP_PATH4 = "/sys/fs/bpf/xdp_fw/udp_ct4"
UDP_CONNTRACK_MAP_PATH6 = "/sys/fs/bpf/xdp_fw/udp_ct6"
TRUSTED_IPS_MAP_PATH4 = "/sys/fs/bpf/xdp_fw/trusted_ipv4"
TRUSTED_IPS_MAP_PATH6 = "/sys/fs/bpf/xdp_fw/trusted_ipv6"
TCP_PORT_POLICY_MAP_PATH = "/sys/fs/bpf/xdp_fw/tcp_port_policies"
UDP_PORT_POLICY_MAP_PATH = "/sys/fs/bpf/xdp_fw/udp_port_policies"
UDP_GLOBAL_RL_MAP_PATH = "/sys/fs/bpf/xdp_fw/udp_global_rl"
XDP_RUNTIME_CFG_MAP_PATH = "/sys/fs/bpf/xdp_fw/xdp_runtime_cfg"
BOGON_CFG_MAP_PATH = "/sys/fs/bpf/xdp_fw/bogon_cfg"
OBSERVABILITY_CFG_MAP_PATH = "/sys/fs/bpf/xdp_fw/observability_cfg"
TCP_ACL_MAP_PATH4 = "/sys/fs/bpf/xdp_fw/tcp_acl_v4"
TCP_ACL_MAP_PATH6 = "/sys/fs/bpf/xdp_fw/tcp_acl_v6"
UDP_ACL_MAP_PATH4 = "/sys/fs/bpf/xdp_fw/udp_acl_v4"
UDP_ACL_MAP_PATH6 = "/sys/fs/bpf/xdp_fw/udp_acl_v6"
XDP_OBJ_PATH = os.environ.get("XDP_OBJ_PATH", "")
TC_OBJ_PATH = os.environ.get("TC_OBJ_PATH", "")

_SYN_RATE_BY_PROC: dict[str, int] = {}
_SYN_RATE_BY_SERVICE: dict[str, int] = {}
_SYN_AGG_RATE_BY_PROC: dict[str, int] = {}
_SYN_AGG_RATE_BY_SERVICE: dict[str, int] = {}
_TCP_CONN_BY_PROC: dict[str, int] = {}
_TCP_CONN_BY_SERVICE: dict[str, int] = {}
_UDP_RATE_BY_PROC: dict[str, int] = {}
_UDP_RATE_BY_SERVICE: dict[str, int] = {}
_UDP_AGG_BYTES_BY_PROC: dict[str, int] = {}
_UDP_AGG_BYTES_BY_SERVICE: dict[str, int] = {}
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
XDP_ICMP_BURST_PACKETS = 100
XDP_ICMP_RATE_PPS = 100.0
XDP_UDP_GLOBAL_WINDOW_SECONDS = 1.0
XDP_RATE_WINDOW_SECONDS = 1.0

NFT_FAMILY = "inet"
NFT_TABLE = "auto_xdp"
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
    "bogon_cfg",
    "observability_cfg",
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
    "slot_def_action",
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
REQUIRED_XDP_MAP_PATHS = tuple(f"/sys/fs/bpf/xdp_fw/{name}" for name in REQUIRED_XDP_MAP_NAMES)


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
    global XDP_CONNTRACK_REFRESH_SECONDS, XDP_ICMP_BURST_PACKETS, XDP_ICMP_RATE_PPS
    global XDP_UDP_GLOBAL_WINDOW_SECONDS, XDP_RATE_WINDOW_SECONDS

    TCP_PERMANENT.clear()
    UDP_PERMANENT.clear()
    SCTP_PERMANENT.clear()
    TRUSTED_SRC_IPS.clear()
    ACL_RULES.clear()

    _SYN_RATE_BY_PROC.clear()
    _SYN_RATE_BY_SERVICE.clear()
    _SYN_AGG_RATE_BY_PROC.clear()
    _SYN_AGG_RATE_BY_SERVICE.clear()
    _TCP_CONN_BY_PROC.clear()
    _TCP_CONN_BY_SERVICE.clear()
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
