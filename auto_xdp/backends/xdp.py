"""XDP/BPF backend — syncs port whitelist and rate-limit maps directly."""
from __future__ import annotations

from dataclasses import replace
import hashlib
import struct
import ipaddress
import json
import logging
import os
from pathlib import Path
import socket
import secrets
import shutil
import subprocess
import sys
from typing import Mapping

from auto_xdp import config as cfg
from auto_xdp.install_state import atomic_write_json
from auto_xdp.backends.base import BackendStatus, PortBackend
from auto_xdp.abuseipdb import AbuseIPDBSyncer, BpfRiskMaps
from auto_xdp.bpf.syscall import map_id, obj_get, probe_inner_map_support
from auto_xdp.bpf.maps import (
    BpfAclMaps,
    BpfEndpointScopeMap,
    XDP_CFG_FLAG_ENDPOINT_POLICY,
    BpfArrayMap,
    BpfGlobalRlMap,
    BpfPortPolicyMap,
    BpfPortPolicyViewMap,
    BpfRateOuterMap,
    BpfRuntimeConfigMap,
    BpfSyncookieRuntimeMap,
    BpfSit4EndpointsMap,
    BpfSynRatePortsMap,
    BpfTrustedMaps,
    BpfZonePortMap,
    XDP_CFG_FLAG_ABUSEIPDB_ENABLED,
    XDP_CFG_FLAG_BOGON_DISABLED,
    XDP_CFG_FLAG_DROP_EVENTS_DISABLED,
    XDP_CFG_FLAG_SLOT_DROP,
)
from auto_xdp.policy import rate_map_entries_v6
from auto_xdp.discovery.services import service_name
from auto_xdp.state import (AppliedState, BackendProjection, DesiredState, ObservedState, ReconcilePlan,
                            ApplyResult, ApplyFailure, ApplyOperation, EndpointKey,
                            project_endpoint_policies, endpoint_scope, EndpointPolicy)

log = logging.getLogger(__name__)

# A rate-limit map slot holds either the standalone SYN-rate map or a per-field
# view over the shared port-policy map; both expose active()/set()/delete().
RateLimitMap = BpfSynRatePortsMap | BpfPortPolicyViewMap

_MINECRAFT_PROFILE = "minecraft"
_PROFILE_IDS = {_MINECRAFT_PROFILE: 1}
_PROFILE_STATE_DIR = "profile-handlers"
_POLICY_GENERATION_STATE = "policy-generations.json"
_TCP_ENDPOINT_VALUE_FORMAT = "=IIQQ"
_TCP_ALLOW = 1


def _compute_cfg_flags(desired: BackendProjection) -> int:
    flags = XDP_CFG_FLAG_ENDPOINT_POLICY if desired.endpoint_policy_enabled else 0
    if not desired.bogon_filter_enabled:
        flags |= XDP_CFG_FLAG_BOGON_DISABLED
    if not desired.drop_events_enabled:
        flags |= XDP_CFG_FLAG_DROP_EVENTS_DISABLED
    if desired.config.ABUSEIPDB_ENABLED:
        flags |= XDP_CFG_FLAG_ABUSEIPDB_ENABLED
    if desired.config.SLOT_DEFAULT_ACTION == "drop":
        flags |= XDP_CFG_FLAG_SLOT_DROP
    return flags


def _cfg_flag_bogon(m: BpfRuntimeConfigMap | None) -> bool | None:
    if m is None:
        return None
    flags = m.get_cfg_flags()
    return None if flags is None else not bool(flags & XDP_CFG_FLAG_BOGON_DISABLED)


def _cfg_flag_drop_events(m: BpfRuntimeConfigMap | None) -> bool | None:
    if m is None:
        return None
    flags = m.get_cfg_flags()
    return None if flags is None else not bool(flags & XDP_CFG_FLAG_DROP_EVENTS_DISABLED)


class XdpBackend(PortBackend):
    name = cfg.BACKEND_XDP

    @classmethod
    def probe(cls, config: cfg.ConfigSnapshot | None = None) -> BackendStatus:
        config = cfg.snapshot_config() if config is None else config
        checks: dict[str, bool] = {}
        details: dict[str, str] = {}

        bpftool_path = shutil.which("bpftool")
        checks["bpftool"] = bpftool_path is not None
        if bpftool_path is None:
            details["bpftool"] = "not found"
            return BackendStatus(
                name=cls.name,
                available=False,
                reason="bpftool not found",
                details=details,
                checks=checks,
            )

        missing_maps = [path for path in config.REQUIRED_XDP_MAP_PATHS if not os.path.exists(path)]
        checks["required_maps"] = not missing_maps
        if missing_maps:
            details["missing_maps"] = ", ".join(missing_maps)
            return BackendStatus(
                name=cls.name,
                available=False,
                reason="required XDP maps missing",
                details=details,
                checks=checks,
            )

        if config.XDP_OBJ_PATH:
            checks["xdp_obj"] = os.path.exists(config.XDP_OBJ_PATH)
            if not checks["xdp_obj"]:
                details["xdp_obj_path"] = config.XDP_OBJ_PATH
                return BackendStatus(
                    name=cls.name,
                    available=False,
                    reason="configured XDP object file missing",
                    details=details,
                    checks=checks,
                )

        try:
            checks["inner_map_support"] = probe_inner_map_support()
        except PermissionError:
            checks["inner_map_support"] = False
            details["inner_map_support"] = "BPF map creation denied (EPERM)"
            return BackendStatus(
                name=cls.name,
                available=False,
                reason="insufficient privileges to create BPF maps (run as root)",
                details=details,
                checks=checks,
            )
        if not checks["inner_map_support"]:
            details["inner_map_support"] = "map-in-map probe failed"
            return BackendStatus(
                name=cls.name,
                available=False,
                reason="kernel lacks ARRAY_OF_MAPS map-in-map support (need 5.10+)",
                details=details,
                checks=checks,
            )

        return BackendStatus(name=cls.name, available=True, checks=checks)

    def __init__(self, config: cfg.ConfigSnapshot | None = None) -> None:
        self._config = cfg.snapshot_config() if config is None else config
        self.endpoint_map = BpfEndpointScopeMap(self.config.ENDPOINT_SCOPE_MAP_PATH)
        self._endpoint_cache: dict[EndpointKey, EndpointPolicy] = {}
        self._apply_result: ApplyResult | None = None
        self.tcp_map = BpfArrayMap(self.config.TCP_MAP_PATH, _TCP_ENDPOINT_VALUE_FORMAT)
        self.udp_map = BpfArrayMap(self.config.UDP_MAP_PATH)
        self.tcp_zone_map = BpfZonePortMap(self.config.TCP_ZONE_MAP_PATH, _TCP_ENDPOINT_VALUE_FORMAT)
        self.udp_zone_map = BpfZonePortMap(self.config.UDP_ZONE_MAP_PATH)
        self.tcp_profile_map = BpfArrayMap(self.config.TCP_PROFILE_HANDLER_MAP_PATH)
        self._policy_generations = self._load_policy_generations()
        self._persisted_policy_generations = dict(self._policy_generations)
        self.trusted_map = BpfTrustedMaps(self.config.TRUSTED_IPS_MAP_PATH4, self.config.TRUSTED_IPS_MAP_PATH6)
        self._tcp_policy_map: BpfPortPolicyMap | None = None
        self._udp_policy_map: BpfPortPolicyMap | None = None
        self.syn_rate_map: RateLimitMap | None = None
        self.syn_agg_rate_map: RateLimitMap | None = None
        self.udp_rate_map: RateLimitMap | None = None
        self.udp_agg_rate_map: RateLimitMap | None = None
        self.acl_maps: BpfAclMaps | None = None
        self.runtime_config_map: BpfRuntimeConfigMap | None = None
        self.tcp_syncookie_mode_map: BpfArrayMap | None = None
        self.tcp_syncookie_rate_map: BpfArrayMap | None = None
        self.syncookie_runtime_map: BpfSyncookieRuntimeMap | None = None
        self.global_rl_map: BpfGlobalRlMap | None = None
        self.sctp_map: BpfArrayMap | None = None
        try:
            self._tcp_policy_map = BpfPortPolicyMap(self.config.TCP_PORT_POLICY_MAP_PATH)
            self.syn_rate_map = BpfPortPolicyViewMap(self._tcp_policy_map, 0, self.config.TCP_PORT_POLICY_MAP_PATH)
            self.syn_agg_rate_map = BpfPortPolicyViewMap(self._tcp_policy_map, 1, self.config.TCP_PORT_POLICY_MAP_PATH)
            log.debug("tcp_port_policies map opened; TCP per-port policy active.")
        except OSError as exc:
            log.debug("tcp_port_policies map unavailable (%s); TCP per-port policy inactive.", exc)
        try:
            self._udp_policy_map = BpfPortPolicyMap(self.config.UDP_PORT_POLICY_MAP_PATH)
            self.udp_rate_map = BpfPortPolicyViewMap(self._udp_policy_map, 0, self.config.UDP_PORT_POLICY_MAP_PATH)
            self.udp_agg_rate_map = BpfPortPolicyViewMap(self._udp_policy_map, 1, self.config.UDP_PORT_POLICY_MAP_PATH)
            log.debug("udp_port_policies map opened; UDP per-port policy active.")
        except OSError as exc:
            log.debug("udp_port_policies map unavailable (%s); UDP per-port policy inactive.", exc)
        try:
            self.acl_maps = BpfAclMaps(
                self.config.TCP_ACL_MAP_PATH4, self.config.TCP_ACL_MAP_PATH6,
                self.config.UDP_ACL_MAP_PATH4, self.config.UDP_ACL_MAP_PATH6,
            )
            log.debug("ACL maps opened; per-CIDR port ACL active.")
        except OSError as exc:
            log.debug("ACL maps unavailable (%s); per-CIDR ACL inactive.", exc)
        try:
            self.runtime_config_map = BpfRuntimeConfigMap(self.config.XDP_RUNTIME_CFG_MAP_PATH)
            log.debug("xdp_runtime_cfg map opened; runtime tuning active.")
        except OSError as exc:
            log.debug("xdp_runtime_cfg map unavailable (%s); runtime tuning inactive.", exc)
        try:
            self.tcp_syncookie_mode_map = BpfArrayMap(
                self.config.TCP_SYNCOOKIE_POLICY_MAP_PATH
            )
            self.tcp_syncookie_rate_map = BpfArrayMap(
                self.config.SYNCOOKIE_PORT_RATE_MAP_PATH
            )
            self.syncookie_runtime_map = BpfSyncookieRuntimeMap(
                self.config.SYNCOOKIE_RUNTIME_CFG_MAP_PATH
            )
            log.debug("SYN-cookie policy maps opened.")
        except OSError as exc:
            log.debug("SYN-cookie policy maps unavailable (%s).", exc)
            for map_obj in (self.tcp_syncookie_mode_map,
                            self.tcp_syncookie_rate_map,
                            self.syncookie_runtime_map):
                if map_obj is not None:
                    map_obj.close()
            self.tcp_syncookie_mode_map = None
            self.tcp_syncookie_rate_map = None
            self.syncookie_runtime_map = None
        try:
            self.global_rl_map = BpfGlobalRlMap(self.config.UDP_GLOBAL_RL_MAP_PATH)
            log.debug("udp_global_rl map opened; global UDP rate limit control active.")
        except OSError as exc:
            log.debug("udp_global_rl map unavailable (%s); global UDP rate limit inactive.", exc)
        try:
            self.sctp_map = BpfArrayMap(self.config.SCTP_MAP_PATH)
            log.debug("sctp_whitelist map opened; SCTP whitelist sync active.")
        except OSError as exc:
            log.debug("sctp_whitelist map unavailable (%s); SCTP whitelist sync inactive.", exc)
        self.sit4_map: BpfSit4EndpointsMap | None = None
        try:
            self.sit4_map = BpfSit4EndpointsMap(self.config.SIT4_ENDPOINTS_MAP_PATH)
            log.debug("sit4_endpoints map opened; 6in4 tunnel endpoint control active.")
        except OSError as exc:
            log.debug("sit4_endpoints map unavailable (%s); 6in4 tunnel endpoint sync inactive.", exc)
        self.syn4_outer: BpfRateOuterMap | None = None
        self.syn6_outer: BpfRateOuterMap | None = None
        self.udprt4_outer: BpfRateOuterMap | None = None
        self.udprt6_outer: BpfRateOuterMap | None = None
        try:
            self.syn4_outer = BpfRateOuterMap(
                self.config.SYN4_MAP_PATH, 4, 8, self.config.RATE_MAP_ENTRIES_V4, "s4_"
            )
            self.syn6_outer = BpfRateOuterMap(
                self.config.SYN6_MAP_PATH, 16, 8, self.config.RATE_MAP_ENTRIES_V6, "s6_"
            )
            self.udprt4_outer = BpfRateOuterMap(
                self.config.UDPRT4_MAP_PATH, 4, 8, self.config.RATE_MAP_ENTRIES_V4, "u4_"
            )
            self.udprt6_outer = BpfRateOuterMap(
                self.config.UDPRT6_MAP_PATH, 16, 8, self.config.RATE_MAP_ENTRIES_V6, "u6_"
            )
            log.debug("rate outer maps opened; per-port rate-limit isolation active.")
        except OSError as exc:
            log.debug("rate outer maps unavailable (%s); per-port rate-limit isolation inactive.", exc)
        self._risk_maps: BpfRiskMaps | None = None
        self._abuseipdb_syncer: AbuseIPDBSyncer | None = None
        try:
            if self.runtime_config_map is not None:
                self._risk_maps = BpfRiskMaps(
                    self.config.ABUSEIPDB_RISK_MAP_PATH4,
                    self.runtime_config_map,
                )
            if self.config.ABUSEIPDB_ENABLED and self._risk_maps is not None:
                self._abuseipdb_syncer = AbuseIPDBSyncer(
                    self._risk_maps,
                    base_url=self.config.ABUSEIPDB_BASE_URL,
                    sources=self.config.ABUSEIPDB_SOURCES,
                    refresh_seconds=self.config.ABUSEIPDB_REFRESH_SECONDS,
                )
                self._abuseipdb_syncer.start()
            log.debug("AbuseIPDB risk maps opened.")
        except OSError as exc:
            log.debug("AbuseIPDB maps unavailable (%s); AbuseIPDB blocking inactive.", exc)

    def _desired_udp_zone_values(self, desired: BackendProjection) -> dict[tuple[int, int], int]:
        values: dict[tuple[int, int], int] = {}
        for zone, ports in desired.zone_udp_ports.items():
            for interface in desired.config.ZONES.get(zone, {}).get("interfaces", []):
                if interface == "*":
                    continue
                try:
                    ifindex = socket.if_nametoindex(interface)
                except OSError:
                    log.warning("Configured zone interface does not exist: %s", interface)
                    continue
                values.update(((ifindex, port), 1) for port in ports)
        for zone, spec in desired.config.ZONES.items():
            for interface in spec.get("interfaces", []):
                if interface == "*":
                    continue
                try:
                    ifindex = socket.if_nametoindex(interface)
                except OSError:
                    continue
                for port in desired.udp_ports:
                    values.setdefault((ifindex, port), 0)
        return values

    def _policy_fingerprint(
        self, desired: BackendProjection, endpoint: tuple[str, int], profile: str
    ) -> str:
        zone, port = endpoint
        material = [
            (
                item.endpoint.host_address,
                item.endpoint.bind_scope,
                item.endpoint.attribution_state,
                item.endpoint.attribution_source,
                item.endpoint.container_runtime,
                item.endpoint.container_id,
                item.endpoint.instance_id,
                item.subject,
                item.protection_profile,
            )
            for item in desired.exposure_decisions
            if item.action == "allow"
            and item.endpoint.protocol == "tcp"
            and item.endpoint.ingress_zone == zone
            and item.endpoint.host_port == port
        ]
        endpoint_acl = sorted(
            (protocol, cidr, tuple(sorted(ports)))
            for (protocol, cidr), ports in desired.acl_rules.items()
            if protocol == "tcp" and port in ports
        )
        payload = (
            zone,
            port,
            profile,
            tuple(desired.config.ZONES.get(zone, {}).get("interfaces", [])),
            desired.tcp_syn_rate_limits.get(port),
            desired.tcp_syn_agg_rate_limits.get(port),
            desired.tcp_syncookie_modes.get(port),
            desired.tcp_syncookie_rate_limits.get(port),
            endpoint_acl,
            desired.bogon_filter_enabled,
            sorted(material),
            tuple(sorted((key, value) for key, value in desired.endpoint_policies.items()
                         if key[0] == "tcp" and key[2] == port and key[3] == zone)),
        )
        return hashlib.sha256(repr(payload).encode()).hexdigest()

    def _endpoint_generation(
        self, desired: BackendProjection, endpoint: tuple[str, int], profile: str
    ) -> int:
        fingerprint = self._policy_fingerprint(desired, endpoint, profile)
        current = self._policy_generations.get(endpoint)
        if current is not None and current[0] == fingerprint:
            return current[1]
        generation = secrets.randbits(64) or 1
        self._policy_generations[endpoint] = (fingerprint, generation)
        return generation

    @staticmethod
    def _profile_generation(object_path: Path) -> int:
        digest = hashlib.sha256(object_path.read_bytes()).digest()
        return int.from_bytes(digest[:8], "little") or 1

    def _tcp_endpoint_value(
        self,
        desired: BackendProjection,
        endpoint: tuple[str, int],
        profile_generation: int,
    ) -> tuple[int, int, int, int]:
        profile = desired.tcp_protection_profiles.get(endpoint, "")
        if not profile:
            return (_TCP_ALLOW, 0, 0, 0)
        return (
            _TCP_ALLOW,
            _PROFILE_IDS[profile],
            self._endpoint_generation(desired, endpoint, profile),
            profile_generation,
        )

    def _desired_tcp_values(
        self, desired: BackendProjection, profile_generation: int
    ) -> tuple[dict[int, tuple[int, int, int, int]], dict[tuple[int, int], tuple[int, int, int, int]]]:
        active_endpoints = set(desired.tcp_protection_profiles)
        for endpoint in set(self._policy_generations) - active_endpoints:
            self._policy_generations.pop(endpoint, None)

        global_values = {
            port: self._tcp_endpoint_value(
                desired, ("public", port), profile_generation
            )
            for port in desired.tcp_ports
        }
        zone_values: dict[tuple[int, int], tuple[int, int, int, int]] = {}
        for zone, ports in desired.zone_tcp_ports.items():
            for interface in desired.config.ZONES.get(zone, {}).get("interfaces", []):
                if interface == "*":
                    continue
                try:
                    ifindex = socket.if_nametoindex(interface)
                except OSError:
                    log.warning("Configured zone interface does not exist: %s", interface)
                    continue
                for port in ports:
                    zone_values[(ifindex, port)] = self._tcp_endpoint_value(
                        desired, (zone, port), profile_generation
                    )
        for zone, spec in desired.config.ZONES.items():
            for interface in spec.get("interfaces", []):
                if interface == "*":
                    continue
                try:
                    ifindex = socket.if_nametoindex(interface)
                except OSError:
                    continue
                for port in desired.tcp_ports:
                    zone_values.setdefault((ifindex, port), (0, 0, 0, 0))
        return global_values, zone_values

    def _zone_state(self, zone_map: BpfZonePortMap) -> dict[str, set[int]]:
        active = zone_map.active_entries()
        result: dict[str, set[int]] = {}
        for zone, spec in self.config.ZONES.items():
            indices = set()
            for interface in spec.get("interfaces", []):
                if interface == "*":
                    continue
                try:
                    indices.add(socket.if_nametoindex(interface))
                except OSError:
                    continue
            ports = {port for ifindex, port in active if ifindex in indices}
            if ports:
                result[zone] = ports
        return result

    def _apply_zone_delta(
        self,
        zone_map: BpfZonePortMap,
        desired_values: Mapping[tuple[int, int], int | tuple[int, ...]],
        dry_run: bool,
        additions: bool,
    ) -> None:
        current = zone_map.entries()
        desired_entries = set(desired_values)
        changed = {
            key for key in current & desired_entries
            if hasattr(zone_map, "value")
            and zone_map.value(*key)
            != (
                (desired_values[key],)
                if isinstance(desired_values[key], int)
                else desired_values[key]
            )
        }
        entries = ((desired_entries - current) | changed) if additions else (current - desired_entries)
        for ifindex, port in sorted(entries):
            ok = (
                self._map_operation(zone_map, "set", ifindex, port, desired_values[(ifindex, port)], dry_run)
                if additions
                else self._map_operation(zone_map, "delete", ifindex, port, dry_run)
            )
            if ok and not dry_run:
                log.debug("%s zone port %s %d", "+" if additions else "-", ifindex, port)

    @staticmethod
    def _profile_install_dir() -> Path:
        python_root = os.environ.get("PYTHON_LIB_DIR")
        if python_root:
            return Path(python_root).resolve().parent
        return Path(__file__).resolve().parents[2]

    @staticmethod
    def _profile_marker() -> Path:
        run_dir = Path(os.environ.get("RUN_STATE_DIR", "/run/auto_xdp"))
        return run_dir / _PROFILE_STATE_DIR / "tcp" / _MINECRAFT_PROFILE

    @staticmethod
    def _policy_generation_state_path() -> Path:
        return Path(os.environ.get("RUN_STATE_DIR", "/run/auto_xdp")) / _POLICY_GENERATION_STATE

    def _load_policy_generations(self) -> dict[tuple[str, int], tuple[str, int]]:
        try:
            data = json.loads(self._policy_generation_state_path().read_text(encoding="utf-8"))
            if data.get("schema") != 1 or not isinstance(data.get("entries"), list):
                return {}
            result: dict[tuple[str, int], tuple[str, int]] = {}
            for item in data["entries"]:
                zone = str(item["zone"])
                port = int(item["port"])
                fingerprint = str(item["fingerprint"])
                generation = int(item["generation"])
                if zone and 1 <= port <= 65535 and fingerprint and generation > 0:
                    result[(zone, port)] = (fingerprint, generation)
            return result
        except (AttributeError, KeyError, OSError, TypeError, ValueError, json.JSONDecodeError):
            return {}

    def _save_policy_generations(self) -> None:
        if self._policy_generations == getattr(
            self, "_persisted_policy_generations", self._policy_generations
        ):
            return
        try:
            atomic_write_json(
                self._policy_generation_state_path(),
                {
                    "schema": 1,
                    "entries": [
                        {
                            "zone": zone,
                            "port": port,
                            "fingerprint": fingerprint,
                            "generation": generation,
                        }
                        for (zone, port), (fingerprint, generation)
                        in sorted(self._policy_generations.items())
                    ],
                },
                mode=0o600,
            )
            self._persisted_policy_generations = dict(self._policy_generations)
        except OSError as exc:
            log.warning("Cannot persist policy generations: %s", exc)

    @staticmethod
    def _pinned_program_id(pin: Path) -> int | None:
        if not pin.exists():
            return None
        try:
            result = subprocess.run(
                ["bpftool", "-j", "prog", "show", "pinned", str(pin)],
                capture_output=True,
                text=True,
            )
        except OSError:
            return None
        if result.returncode != 0:
            return None
        try:
            value = json.loads(result.stdout)
            if isinstance(value, list):
                value = value[0]
            return int(value["id"])
        except (KeyError, IndexError, TypeError, ValueError, json.JSONDecodeError):
            return None

    def _profile_command(self, action: str, profile_id: int, object_path: Path | None = None) -> bool:
        install_dir = self._profile_install_dir()
        command = [
            sys.executable,
            "-m",
            "auto_xdp.admin.cli",
            "--config",
            self.config.TOML_CONFIG_PATH,
            "--bpf-pin-dir",
            self.config.BPF_PIN_DIR,
            "--install-dir",
            str(install_dir),
            "profile-handler",
            action,
            str(profile_id),
        ]
        if object_path is not None:
            command.append(str(object_path))
        try:
            result = subprocess.run(command, capture_output=True, text=True)
        except OSError as exc:
            self._profile_error = str(exc)
            log.error("Cannot run Minecraft profile handler command: %s", exc)
            return False
        if result.returncode == 0:
            return True
        detail = result.stderr.strip() or result.stdout.strip() or "unknown error"
        self._profile_error = detail
        log.error("Minecraft profile handler %s failed for profile %d: %s", action, profile_id, detail)
        return False

    def _managed_profile_handler(self) -> tuple[int, int] | None:
        try:
            value = json.loads(self._profile_marker().read_text(encoding="utf-8"))
            if (
                value["profile"] != _MINECRAFT_PROFILE
                or int(value["profile_id"]) != _PROFILE_IDS[_MINECRAFT_PROFILE]
            ):
                return None
            program_id = int(value["program_id"])
            profile_generation = int(value["profile_generation"])
            if program_id <= 0 or profile_generation <= 0:
                return None
            return program_id, profile_generation
        except (KeyError, OSError, TypeError, ValueError, json.JSONDecodeError):
            return None

    def _ensure_profile_handlers(
        self,
        desired: dict[tuple[str, int], str],
        profile_generation: int,
        dry_run: bool,
    ) -> tuple[set[tuple[str, int]], int]:
        failures: set[tuple[str, int]] = set()
        install_dir = self._profile_install_dir()
        object_path = install_dir / "handlers" / f"{_MINECRAFT_PROFILE}_handler.o"
        for endpoint, profile in desired.items():
            if profile != _MINECRAFT_PROFILE:
                log.error("Unsupported TCP protection profile %r on %s/%d", profile, *endpoint)
                failures.add(endpoint)
        if failures:
            return set(desired), 0
        if not desired:
            return set(), 0
        if not object_path.is_file():
            self._profile_error = f"Minecraft profile object is missing: {object_path}"
            log.error("Minecraft profile object is missing: %s", object_path)
            return set(desired), 0

        profile_id = _PROFILE_IDS[_MINECRAFT_PROFILE]
        live_pin = Path(self.config.BPF_PIN_DIR) / "profile_handlers" / "tcp" / str(profile_id) / "prog"
        live_id = self._pinned_program_id(live_pin)
        managed = self._managed_profile_handler()
        self.tcp_profile_map.verify()
        array_value = self.tcp_profile_map.value(profile_id)
        array_id = array_value[0] if array_value else None
        if managed == (live_id, profile_generation) and array_id == live_id:
            return failures, profile_generation
        if dry_run:
            log.info("Would load Minecraft profile handler ID %d", profile_id)
            return failures, profile_generation
        if not self._profile_command("load", profile_id, object_path):
            return set(desired), 0
        live_id = self._pinned_program_id(live_pin)
        self.tcp_profile_map.refresh()
        array_value = self.tcp_profile_map.value(profile_id)
        if live_id is None or array_value is None or array_value[0] != live_id:
            self._profile_command("unload", profile_id)
            return set(desired), 0
        marker = self._profile_marker()
        try:
            atomic_write_json(
                marker,
                {
                    "profile": _MINECRAFT_PROFILE,
                    "profile_id": profile_id,
                    "program_id": live_id,
                    "profile_generation": profile_generation,
                },
                mode=0o600,
            )
        except OSError as exc:
            log.error("Cannot record Minecraft profile ownership: %s", exc)
            self._profile_command("unload", profile_id)
            return set(desired), 0
        log.info("Minecraft protection profile %d enabled", profile_id)
        return failures, profile_generation

    def _remove_stale_profile_handlers(
        self, desired: dict[tuple[str, int], str], dry_run: bool
    ) -> None:
        result = self._execution_result(dry_run)
        if desired:
            return
        profile_map = getattr(self, "tcp_profile_map", None)
        if profile_map is None:
            return
        profile_id = _PROFILE_IDS[_MINECRAFT_PROFILE]
        live_pin = Path(self.config.BPF_PIN_DIR) / "profile_handlers" / "tcp" / str(profile_id) / "prog"
        live_id = self._pinned_program_id(live_pin)
        profile_map.verify()
        array_value = profile_map.value(profile_id)
        array_id = array_value[0] if array_value else None
        if live_id is None and array_id is None:
            try:
                self._profile_marker().unlink()
            except FileNotFoundError:
                pass
            except OSError as exc:
                log.warning("Cannot remove stale profile marker: %s", exc)
                result.failures.append(ApplyFailure(ApplyOperation("cleanup", "profiles", "remove marker"), str(exc)))
                return
            return
        if live_id is None or array_id != live_id:
            log.error("Cannot safely remove inconsistent Minecraft profile handler state")
            result.failures.append(ApplyFailure(ApplyOperation("cleanup", "profiles", "unload"), "inconsistent pinned profile handler state"))
            return
        if dry_run:
            log.info("Would unload stale Minecraft profile handler ID %d", profile_id)
            return
        if not self._profile_command("unload", profile_id):
            result.failures.append(ApplyFailure(ApplyOperation("cleanup", "profiles", "unload"), getattr(self, "_profile_error", "profile unload failed")))
            return
        profile_map.refresh()
        try:
            self._profile_marker().unlink()
        except FileNotFoundError:
            pass
        except OSError as exc:
            log.warning("Cannot remove stale profile marker: %s", exc)
            result.failures.append(ApplyFailure(ApplyOperation("cleanup", "profiles", "remove marker"), str(exc)))
            return
        log.info("Minecraft protection profile %d disabled", profile_id)
        return

    def is_stale(self) -> bool:
        """Return True if the pinned tcp_whitelist map has been replaced since init."""
        try:
            fd = obj_get(self.config.TCP_MAP_PATH)
            try:
                pinned_id = map_id(fd)
            finally:
                os.close(fd)
            return pinned_id != self.tcp_map.map_id()
        except OSError:
            return False

    def close(self) -> None:
        if hasattr(self, "endpoint_map"):
            self.endpoint_map.close()
        self.tcp_map.close()
        self.udp_map.close()
        if hasattr(self, "tcp_profile_map"):
            self.tcp_profile_map.close()
        for zone_map in (getattr(self, "tcp_zone_map", None), getattr(self, "udp_zone_map", None)):
            if zone_map is not None:
                zone_map.close()
        self.trusted_map.close()
        if self._tcp_policy_map is not None:
            self._tcp_policy_map.close()
        if self._udp_policy_map is not None:
            self._udp_policy_map.close()
        if self.acl_maps is not None:
            self.acl_maps.close()
        if self.runtime_config_map is not None:
            self.runtime_config_map.close()
        for map_obj in (getattr(self, "tcp_syncookie_mode_map", None),
                        getattr(self, "tcp_syncookie_rate_map", None),
                        getattr(self, "syncookie_runtime_map", None)):
            if map_obj is not None:
                map_obj.close()
        if self.global_rl_map is not None:
            self.global_rl_map.close()
        if self.sctp_map is not None:
            self.sctp_map.close()
        if self.sit4_map is not None:
            self.sit4_map.close()
        for outer in (self.syn4_outer, self.syn6_outer, self.udprt4_outer, self.udprt6_outer):
            if outer is not None:
                outer.close()
        if self._abuseipdb_syncer is not None:
            self._abuseipdb_syncer.stop()
        if self._risk_maps is not None:
            self._risk_maps.close()

    def get_applied_state(self) -> AppliedState:
        return AppliedState(
            endpoint_policies=dict(getattr(self, "_endpoint_cache", {})),
            evidence={"endpoint_policies": "cached", "maps": "cached"},
            tcp_ports=self.tcp_map.active_ports(),
            udp_ports=self.udp_map.active_ports(),
            zone_tcp_ports=self._zone_state(self.tcp_zone_map) if hasattr(self, "tcp_zone_map") else {},
            zone_udp_ports=self._zone_state(self.udp_zone_map) if hasattr(self, "udp_zone_map") else {},
            sctp_ports=self.sctp_map.active_ports() if self.sctp_map is not None else set(),
            trusted_cidrs=self.trusted_map.active_keys(),
            tcp_syn_rate_limits=self.syn_rate_map.active() if self.syn_rate_map is not None else {},
            tcp_syn_agg_rate_limits=self.syn_agg_rate_map.active() if self.syn_agg_rate_map is not None else {},
            tcp_syncookie_modes={
                port: {1: "auto", 2: "always"}.get(value, "off")
                for port, value in (
                    getattr(self, "tcp_syncookie_mode_map").active_values().items()
                    if getattr(self, "tcp_syncookie_mode_map", None) is not None else ()
                )
            },
            tcp_syncookie_rate_limits=(
                getattr(self, "tcp_syncookie_rate_map").active_values()
                if getattr(self, "tcp_syncookie_rate_map", None) is not None else {}
            ),
            udp_rate_limits=self.udp_rate_map.active() if self.udp_rate_map is not None else {},
            udp_agg_rate_limits=self.udp_agg_rate_map.active() if self.udp_agg_rate_map is not None else {},
            acl_rules=self.acl_maps.active_entries() if self.acl_maps is not None else {},
            bogon_filter_enabled=_cfg_flag_bogon(self.runtime_config_map),
            drop_events_enabled=_cfg_flag_drop_events(self.runtime_config_map),
            udp_global_byte_rate=self.global_rl_map.get() if self.global_rl_map is not None else None,
            xdp_runtime_config=self.runtime_config_map.get() if self.runtime_config_map is not None else None,
        )

    @property
    def last_apply_failures(self) -> int:
        """Compatibility count derived from the structured execution result."""
        result = getattr(self, "_apply_result", None) or self.last_apply_result
        return len(result.failures) if result is not None else 0

    def _execution_result(self, dry_run: bool = False) -> ApplyResult:
        result = getattr(self, "_apply_result", None)
        if result is None:
            result = self._apply_result = ApplyResult(dry_run=dry_run)
        return result

    def _map_operation(self, resource, method: str, *args, **kwargs) -> bool:
        operation = ApplyOperation(getattr(self, "_apply_stage", "prepare"),
                                   getattr(resource, "path", type(resource).__name__),
                                   f"{method} {args!r}")
        try:
            ok = getattr(resource, method)(*args, **kwargs)
            reason = getattr(resource, "last_error", "map operation returned failure")
        except (OSError, ValueError, OverflowError, struct.error) as exc:
            ok, reason = False, str(exc)
        result = self._execution_result()
        if not ok:
            result.failures.append(ApplyFailure(operation, reason))
        elif not result.dry_run:
            result.succeeded.append(operation)
        return ok

    def _scope_values(self, desired: DesiredState) -> tuple[dict[bytes, int], dict[EndpointKey, str]]:
        values: dict[bytes, int] = {}
        blocked: dict[EndpointKey, str] = {}
        for key, policy in desired.endpoint_policies.items():
            try:
                interfaces, families, address = endpoint_scope(key, desired.config)
                indexes = [socket.if_nametoindex(name) for name in interfaces] if interfaces else [0]
            except (OSError, ValueError) as exc:
                if policy.allow:
                    blocked[key] = str(exc)
                continue
            for family in families:
                packed = ipaddress.ip_address(address).packed.ljust(16, b"\0") if address else bytes(16)
                for index in indexes:
                    raw = struct.pack("=IHBB16s", index, key[2], {"tcp": 6, "udp": 17, "sctp": 132}[key[0]],
                                      2 if family == 4 else 10, packed)
                    # A deny on the same native key always wins.
                    values[raw] = min(values.get(raw, 1), int(policy.allow))
        # Public fallback must never grant admission on a named private NIC.
        for raw in list(values):
            index, port, proto, family, address = struct.unpack("=IHBB16s", raw)
            if index != 0:
                continue
            for zone, spec in desired.config.ZONES.items():
                if zone == "public":
                    continue
                for interface in spec.get("interfaces", ()):
                    if interface == "*":
                        continue
                    try:
                        ifindex = socket.if_nametoindex(interface)
                    except OSError:
                        continue
                    deny = struct.pack("=IHBB16s", ifindex, port, proto, family, bytes(16))
                    values.setdefault(deny, 0)
        return values, blocked

    @staticmethod
    def _unresolved_scope_closed(
        key: EndpointKey, config: cfg.ConfigSnapshot, active: Mapping[bytes, int],
    ) -> bool:
        """Prove default-deny closure when no native scope key can be emitted.

        The caller must first confirm the scope map and enabled endpoint gate.
        Any potentially matching allow keeps an unresolved scope unconfirmed.
        """
        protocol, address, port, zone = key
        interfaces = tuple(name for name in config.ZONES.get(zone, {}).get("interfaces", ()) if name != "*")
        indexes = None
        if interfaces:
            try:
                indexes = {index for index, name in socket.if_nameindex() if name in interfaces}
            except OSError:
                return False
            if not indexes:
                return True  # This named zone currently has no ingress interface.
        ip = None if address == "*" else ipaddress.ip_address(address.split("%", 1)[0])
        families = (2, 10) if ip is None else (2 if ip.version == 4 else 10,)
        packed = None if ip is None or ip.is_unspecified else ip.packed.ljust(16, b"\0")
        proto = {"tcp": 6, "udp": 17, "sctp": 132}[protocol]
        for raw, allow in active.items():
            if not allow:
                continue
            raw_index, raw_port, raw_proto, raw_family, raw_address = struct.unpack("=IHBB16s", raw)
            if raw_port != port or raw_proto != proto or raw_family not in families:
                continue
            if indexes is not None and raw_index != 0 and raw_index not in indexes:
                continue
            if packed is None or raw_address in (bytes(16), packed):
                return False
        return True

    def verify_kernel_state(self) -> int:
        """Re-read userspace-owned config maps from the kernel and repair caches.

        Returns the total number of discrepancies found (0 = kernel matches cache).
        """
        total = 0
        total += self.tcp_map.verify()
        total += self.udp_map.verify()
        if hasattr(self, "tcp_profile_map"):
            total += self.tcp_profile_map.verify()
        for zone_map in (getattr(self, "tcp_zone_map", None), getattr(self, "udp_zone_map", None)):
            if zone_map is not None:
                total += zone_map.verify()
        if self.sctp_map is not None:
            total += self.sctp_map.verify()
        total += self.trusted_map.verify()
        if self._tcp_policy_map is not None:
            total += self._tcp_policy_map.verify()
        if self._udp_policy_map is not None:
            total += self._udp_policy_map.verify()
        if self.acl_maps is not None:
            total += self.acl_maps.verify()
        if self.sit4_map is not None:
            total += self.sit4_map.verify()
        for outer in (self.syn4_outer, self.syn6_outer, self.udprt4_outer, self.udprt6_outer):
            if outer is not None:
                total += outer.verify()
        for cookie_map in (
            getattr(self, "tcp_syncookie_mode_map", None),
            getattr(self, "tcp_syncookie_rate_map", None),
        ):
            if cookie_map is not None:
                total += cookie_map.verify()
        if total:
            log.warning(
                "Kernel state verification found %d drifted map entr%s; caches repaired, corrective sync recommended.",
                total, "y" if total == 1 else "ies",
            )
        return total

    def apply_reconcile_plan(
        self,
        plan: ReconcilePlan,
        dry_run: bool,
        desired_state: DesiredState,
        observed_state: ObservedState | None = None,
    ) -> None:
        if not isinstance(desired_state, BackendProjection):
            desired_state, _ = project_endpoint_policies(desired_state)
        if not getattr(self, "_defer_global_admission", False):
            self._apply_result = ApplyResult(dry_run=dry_run, plan=plan)
        changed = False
        for port in sorted(plan.tcp_ports_to_remove):
            if self._map_operation(self.tcp_map, 'set', port, 0, dry_run):
                log.debug("TCP -%d  (stopped)", port)
                changed = True

        for port in sorted(plan.udp_ports_to_remove):
            if self._map_operation(self.udp_map, 'set', port, 0, dry_run):
                log.debug("UDP -%d  (stopped)", port)
                changed = True

        if self.sctp_map is not None:
            for port in sorted(plan.sctp_ports_to_add if not desired_state.endpoint_policy_enabled else set()):
                if self._map_operation(self.sctp_map, 'set', port, 1, dry_run):
                    log.info("SCTP +%d", port)
                    changed = True

            for port in sorted(plan.sctp_ports_to_remove):
                if self._map_operation(self.sctp_map, 'set', port, 0, dry_run):
                    log.info("SCTP -%d  (stopped)", port)
                    changed = True

        if desired_state.endpoint_policy_enabled and self.last_apply_failures:
            log.warning("Revocation failed; preserving protection state and skipping admission")
            return

        # HASH maps need delete, not write-zero, when trust entries disappear.
        for ip_str in sorted(plan.trusted_cidrs_to_add):
            tag = f" [{desired_state.config.TRUSTED_SRC_IPS[ip_str]}]" if ip_str in desired_state.config.TRUSTED_SRC_IPS else ""
            if self._map_operation(self.trusted_map, 'set', ip_str, 1, dry_run):
                log.info("TRUST +%s%s", ip_str, tag)
                changed = True

        for ip_str in sorted(plan.trusted_cidrs_to_remove):
            if self._map_operation(self.trusted_map, 'delete', ip_str, dry_run):
                log.info("TRUST -%s  (removed)", ip_str)
                changed = True

        if not changed:
            log.debug("Whitelist up-to-date.")

        if self.syn_rate_map is not None:
            self._apply_rate_map_delta(
                self.syn_rate_map,
                plan.tcp_syn_rate_limits_to_upsert,
                plan.tcp_syn_rate_limits_to_remove,
                dry_run,
                "tcp",
                {} if observed_state is None else observed_state.tcp_processes,
            )

        if self.syn_agg_rate_map is not None:
            self._apply_rate_map_delta(
                self.syn_agg_rate_map,
                plan.tcp_syn_agg_rate_limits_to_upsert,
                plan.tcp_syn_agg_rate_limits_to_remove,
                dry_run,
                "tcp_syn_agg",
            )

        cookie_mode_map = getattr(self, "tcp_syncookie_mode_map", None)
        if cookie_mode_map is not None:
            mode_values = {"off": 0, "auto": 1, "always": 2}
            for port, mode in sorted(plan.tcp_syncookie_modes_to_upsert.items()):
                self._map_operation(cookie_mode_map, 'set', port, mode_values[mode], dry_run)
            for port in sorted(plan.tcp_syncookie_modes_to_remove):
                self._map_operation(cookie_mode_map, 'delete', port, dry_run)

        cookie_rate_map = getattr(self, "tcp_syncookie_rate_map", None)
        if cookie_rate_map is not None:
            for port, rate in sorted(
                plan.tcp_syncookie_rate_limits_to_upsert.items()
            ):
                self._map_operation(cookie_rate_map, 'set', port, rate, dry_run)
            for port in sorted(plan.tcp_syncookie_rate_limits_to_remove):
                self._map_operation(cookie_rate_map, 'delete', port, dry_run)

        cookie_runtime_map = getattr(self, "syncookie_runtime_map", None)
        if cookie_runtime_map is not None:
            active = desired_state.config.SYNCOOKIE_ENABLED and (
                Path(desired_state.config.BPF_PIN_DIR) / "syncookie_prog"
            ).exists()
            self._map_operation(cookie_runtime_map, 'set', active, desired_state.config.SYNCOOKIE_ACTIVATION_PERCENT, desired_state.config.SYNCOOKIE_AUTO_MAX_PERCENT, desired_state.config.SYNCOOKIE_INVALID_ACK_RATE_PPS, int(desired_state.config.SYNCOOKIE_CHALLENGE_COOLDOWN_SECONDS * 1_000_000_000), dry_run)

        if self.udp_rate_map is not None:
            self._apply_rate_map_delta(
                self.udp_rate_map,
                plan.udp_rate_limits_to_upsert,
                plan.udp_rate_limits_to_remove,
                dry_run,
                "udp",
                {} if observed_state is None else observed_state.udp_processes,
            )

        if self.udp_agg_rate_map is not None:
            self._apply_rate_map_delta(
                self.udp_agg_rate_map,
                plan.udp_agg_rate_limits_to_upsert,
                plan.udp_agg_rate_limits_to_remove,
                dry_run,
                "udp_agg",
            )

        tcp_entries = desired_state.tcp_rate_map_entries
        udp_entries = desired_state.udp_rate_map_entries
        if self.syn4_outer is not None:
            self._apply_rate_outer_delta(self.syn4_outer, tcp_entries, dry_run)
        if self.syn6_outer is not None:
            self._apply_rate_outer_delta(
                self.syn6_outer,
                {p: rate_map_entries_v6(c, config=desired_state.config) for p, c in tcp_entries.items()},
                dry_run,
            )
        if self.udprt4_outer is not None:
            self._apply_rate_outer_delta(self.udprt4_outer, udp_entries, dry_run)
        if self.udprt6_outer is not None:
            self._apply_rate_outer_delta(
                self.udprt6_outer,
                {p: rate_map_entries_v6(c, config=desired_state.config) for p, c in udp_entries.items()},
                dry_run,
            )

        if self._tcp_policy_map is not None:
            tcp_policy_ports = (
                set(desired_state.tcp_syn_rate_limits)
                | set(desired_state.tcp_syn_agg_rate_limits)
            )
            self._tcp_policy_map.ensure_prefixes(
                tcp_policy_ports,
                desired_state.rate_limit_source_prefix_v4,
                desired_state.rate_limit_source_prefix_v6,
                dry_run,
            )

        if self._udp_policy_map is not None:
            udp_policy_ports = set(desired_state.udp_rate_limits) | set(desired_state.udp_agg_rate_limits)
            self._udp_policy_map.ensure_prefixes(
                udp_policy_ports,
                desired_state.rate_limit_source_prefix_v4,
                desired_state.rate_limit_source_prefix_v6,
                dry_run,
            )

        if self.acl_maps is not None:
            self._apply_acl_delta(plan, dry_run)

        if self.runtime_config_map is not None:
            cfg_flags = _compute_cfg_flags(desired_state)
            current = self.runtime_config_map.get()
            current_flags = self.runtime_config_map.get_cfg_flags() or 0
            if desired_state.xdp_runtime_config != current or cfg_flags != current_flags:
                self._map_operation(self.runtime_config_map, 'set', desired_state.xdp_runtime_config, cfg_flags, dry_run)

        if self.global_rl_map is not None and plan.udp_global_byte_rate_update is not None:
            rate = plan.udp_global_byte_rate_update
            if self._map_operation(self.global_rl_map, 'set', rate, dry_run):
                if rate:
                    log.info("UDP global rate limit set to %d bytes/s", rate)
                else:
                    log.info("UDP global rate limit disabled")

        if self.sit4_map is not None:
            desired_sit4 = set(desired_state.config.SIT4_ENDPOINTS)
            current_sit4 = self.sit4_map.active_keys()
            for ip_str in sorted(desired_sit4 - current_sit4):
                if self._map_operation(self.sit4_map, 'set', ip_str, dry_run):
                    log.info("SIT4 +%s (6in4 tunnel endpoint added)", ip_str)
            for ip_str in sorted(current_sit4 - desired_sit4):
                if self._map_operation(self.sit4_map, 'delete', ip_str, dry_run):
                    log.info("SIT4 -%s (6in4 tunnel endpoint removed)", ip_str)

        # BPF maps do not provide a transaction.  Prepare all protection state
        # first, then expose new TCP/UDP ports only if that preparation passed.
        # A failed map update leaves the port closed and is retried next round.
        if self.last_apply_failures:
            if plan.tcp_ports_to_add or plan.udp_ports_to_add:
                log.warning(
                    "Keeping new TCP/UDP ports closed because protection setup "
                    "failed (%d map update failure(s)).",
                    self.last_apply_failures,
                )
        elif not getattr(self, "_defer_global_admission", False):
            self._apply_global_admission(plan, dry_run)

        if self.last_apply_failures and not dry_run:
            log.warning(
                "%d BPF map update%s failed this reconcile; kernel state may lag desired state.",
                self.last_apply_failures,
                "" if self.last_apply_failures == 1 else "s",
            )

    def _apply_global_admission(self, plan: ReconcilePlan, dry_run: bool) -> None:
        tcp_values = getattr(self, "_desired_tcp_global_values", {})
        for port in sorted(plan.tcp_ports_to_add):
            value = tcp_values.get(port, (_TCP_ALLOW, 0, 0, 0))
            if self._map_operation(self.tcp_map, 'set', port, value, dry_run):
                log.debug("TCP +%d", port)
        for port in sorted(plan.udp_ports_to_add):
            if self._map_operation(self.udp_map, 'set', port, 1, dry_run):
                log.debug("UDP +%d", port)

    def reconcile(
        self,
        desired_state: DesiredState,
        dry_run: bool,
        observed_state: ObservedState | None = None,
    ) -> ApplyResult:
        original = desired_state
        result = ApplyResult(dry_run=dry_run)
        self._apply_result = result
        if hasattr(self, "_config") and self.config.BPF_PIN_DIR != desired_state.config.BPF_PIN_DIR:
            raise RuntimeError("BPF pin directory changed; reopen the backend")
        self._config = desired_state.config
        projection, blocked = project_endpoint_policies(desired_state)
        result.plan = self.build_reconcile_plan(projection, self.get_applied_state())
        result.plan.target = original
        result.blocked_endpoints.update(blocked)
        scope_values, scope_blocked = self._scope_values(projection) if projection.endpoint_policy_enabled else ({}, {})
        result.blocked_endpoints.update(scope_blocked)
        for endpoint_key, policy in projection.endpoint_policies.items():
            if not policy.allow:
                continue
            required = []
            if endpoint_key[0] == "sctp":
                required.append("sctp_map")
            if policy.syn_rate:
                required.extend(("syn_rate_map", "syn4_outer", "syn6_outer"))
            if policy.syn_aggregate_rate:
                required.append("syn_agg_rate_map")
            if policy.udp_rate:
                required.extend(("udp_rate_map", "udprt4_outer", "udprt6_outer"))
            if policy.udp_byte_rate:
                required.append("udp_agg_rate_map")
            if endpoint_key[0] == "udp" and projection.udp_global_byte_rate:
                required.append("global_rl_map")
            if policy.syncookie_mode != "off":
                required.extend(("tcp_syncookie_mode_map", "tcp_syncookie_rate_map", "syncookie_runtime_map"))
                if not (Path(projection.config.BPF_PIN_DIR) / "syncookie_prog").exists():
                    scope_blocked[endpoint_key] = "SYN-cookie program is unavailable"
            missing = [name for name in required if getattr(self, name, None) is None]
            if missing:
                scope_blocked[endpoint_key] = "required protection unavailable: " + ", ".join(missing)
        result.blocked_endpoints.update(scope_blocked)
        if scope_blocked:
            projection = replace(projection, endpoint_policies={
                key: replace(policy, allow=False, reason=scope_blocked[key]) if key in scope_blocked else policy
                for key, policy in projection.endpoint_policies.items()})
            projection, _ = project_endpoint_policies(projection)
            scope_values, _ = self._scope_values(projection)
        if not hasattr(self, "_policy_generations"):
            self._policy_generations = {}
        if not hasattr(self, "_persisted_policy_generations"):
            self._persisted_policy_generations = dict(self._policy_generations)

        scope_map = getattr(self, "endpoint_map", None)
        tentative_profile_generation = 0
        tcp_zone_values: dict[tuple[int, int], tuple[int, int, int, int]] = {}
        udp_zone_values: dict[tuple[int, int], int] = {}
        tcp_zone_map = getattr(self, "tcp_zone_map", None)
        udp_zone_map = getattr(self, "udp_zone_map", None)

        def revoke() -> None:
            nonlocal projection, tentative_profile_generation
            if projection.endpoint_policy_enabled:
                if scope_map is None or self.runtime_config_map is None:
                    result.failures.append(ApplyFailure(ApplyOperation("prepare", "endpoint_scopes", "open"),
                                                       "canonical endpoint admission maps are unavailable"))
                    projection = replace(projection, tcp_ports=set(), udp_ports=set(), sctp_ports=set(),
                                            zone_tcp_ports={}, zone_udp_ports={})
                if scope_map is not None:
                    try:
                        scope_map.verify()
                    except (OSError, RuntimeError) as exc:
                        result.failures.append(ApplyFailure(ApplyOperation("revoke", "endpoint_scopes", "read"), str(exc)))
                    changed = getattr(self, "_endpoint_cache", {}) != projection.endpoint_policies
                    for raw, value in scope_map.active().items():
                        if value and (changed or scope_values.get(raw) != value):
                            self._map_operation(scope_map, "set", raw, 0, dry_run)
                    for raw, value in scope_values.items():
                        if not value and scope_map.active().get(raw) != 0:
                            self._map_operation(scope_map, "set", raw, 0, dry_run)

            install_dir = self._profile_install_dir()
            profile_object = install_dir / "handlers" / f"{_MINECRAFT_PROFILE}_handler.o"
            tentative_profile_generation = (
                self._profile_generation(profile_object) if profile_object.is_file() else 0
            )
            desired_global, desired_zone = self._desired_tcp_values(
                projection, tentative_profile_generation
            )
            desired_udp_zone = self._desired_udp_zone_values(projection)

            # Policy/profile replacement is close-before-open.  Removing the old
            # admission also guarantees the base reconcile sees the endpoint as an
            # addition and writes the complete new generation atomically.
            for port in self.tcp_map.active_ports() & set(desired_global):
                current = self.tcp_map.value(port) if hasattr(self.tcp_map, "value") else None
                if current is not None and current != desired_global[port]:
                    self._map_operation(self.tcp_map, 'set', port, (0, 0, 0, 0), dry_run)
            tcp_zone_map = getattr(self, "tcp_zone_map", None)
            if tcp_zone_map is not None:
                for key in tcp_zone_map.entries() & set(desired_zone):
                    current = tcp_zone_map.value(*key) if hasattr(tcp_zone_map, "value") else None
                    if current is not None and current != desired_zone[key]:
                        self._map_operation(tcp_zone_map, 'set', *key, (0, 0, 0, 0), dry_run=dry_run)
                for key, tcp_value in desired_zone.items():
                    if tcp_zone_map.value(*key) != tcp_value and key[1] in desired_global:
                        self._map_operation(self.tcp_map, 'set', key[1], (0, 0, 0, 0), dry_run)
            udp_zone_map = getattr(self, "udp_zone_map", None)
            if udp_zone_map is not None:
                for key in udp_zone_map.entries() & set(desired_udp_zone):
                    current = udp_zone_map.value(*key) if hasattr(udp_zone_map, "value") else None
                    if current is not None and current != (desired_udp_zone[key],):
                        self._map_operation(udp_zone_map, 'set', *key, 0, dry_run=dry_run)
                for key, udp_value in desired_udp_zone.items():
                    if udp_zone_map.value(*key) != (udp_value,) and key[1] in projection.udp_ports:
                        self._map_operation(self.udp_map, 'set', key[1], 0, dry_run)

        def prepare() -> None:
            nonlocal tcp_zone_values, udp_zone_values
            failed_profile_endpoints, profile_generation = self._ensure_profile_handlers(
                projection.tcp_protection_profiles,
                tentative_profile_generation,
                dry_run,
            )
            if failed_profile_endpoints:
                result.blocked_endpoints.update({key: "protection profile installation failed"
                    for key, policy in projection.endpoint_policies.items()
                    if policy.allow and (key[3], key[2]) in failed_profile_endpoints})
                result.failures.append(ApplyFailure(ApplyOperation("prepare", "profiles", "install"),
                                                   getattr(self, "_profile_error", "protection profile installation failed")))
                return

            self._desired_tcp_global_values, tcp_zone_values = self._desired_tcp_values(
                projection, profile_generation
            )
            udp_zone_values = self._desired_udp_zone_values(projection)

            if tcp_zone_map is not None:
                self._apply_zone_delta(
                    tcp_zone_map, tcp_zone_values, dry_run, additions=False
                )
            if udp_zone_map is not None:
                self._apply_zone_delta(
                    udp_zone_map, udp_zone_values, dry_run, additions=False
                )
            if projection.endpoint_policy_enabled and result.failures:
                return
            self._defer_global_admission = True
            try:
                physical_plan = self.build_reconcile_plan(projection, self.get_applied_state())
                self.apply_reconcile_plan(physical_plan, dry_run, projection, observed_state)
            finally:
                self._defer_global_admission = False

        def admit() -> None:
            if not self.last_apply_failures:
                if tcp_zone_map is not None:
                    self._apply_zone_delta(
                        tcp_zone_map, tcp_zone_values, dry_run, additions=True
                    )
                if udp_zone_map is not None:
                    self._apply_zone_delta(
                        udp_zone_map, udp_zone_values, dry_run, additions=True
                    )
            if not self.last_apply_failures and projection.endpoint_policy_enabled and self.sctp_map is not None:
                for port in projection.sctp_ports - self.sctp_map.active_ports():
                    self._map_operation(self.sctp_map, "set", port, 1, dry_run)
            if not self.last_apply_failures:
                admission_plan = ReconcilePlan(
                    tcp_ports_to_add=projection.tcp_ports - self.tcp_map.active_ports(),
                    udp_ports_to_add=projection.udp_ports - self.udp_map.active_ports(),
                )
                self._apply_global_admission(admission_plan, dry_run)
            if projection.endpoint_policy_enabled and scope_map is not None and not self.last_apply_failures:
                for raw, value in scope_values.items():
                    if value and scope_map.active().get(raw) != value:
                        self._map_operation(scope_map, "set", raw, value, dry_run)

        def cleanup() -> None:
            if scope_map is not None and not self.last_apply_failures:
                for raw in set(scope_map.active()) - set(scope_values):
                    self._map_operation(scope_map, "delete", raw, dry_run)
            if not self.last_apply_failures:
                self._remove_stale_profile_handlers(
                    projection.tcp_protection_profiles,
                    dry_run,
                )

        stages = {"revoke": revoke, "prepare": prepare, "admit": admit, "cleanup": cleanup}
        completed: set[str] = set()
        for step in result.plan.steps:
            if not set(step.depends_on).issubset(completed):
                result.unconfirmed[step.operation] = "required reconciliation stage failed"
                continue
            self._apply_stage = step.operation
            try:
                stages[step.operation]()
            except (OSError, RuntimeError) as exc:
                result.failures.append(ApplyFailure(ApplyOperation(step.operation, "xdp", "execute stage"), str(exc)))
            if not result.failures:
                completed.add(step.operation)

        if not dry_run:
            self._save_policy_generations()

        return self._finish_apply(original, projection, result, dry_run, scope_map)

    def _finish_apply(
        self, original: DesiredState, desired_state: BackendProjection,
        result: ApplyResult, dry_run: bool, scope_map: BpfEndpointScopeMap | None,
    ) -> ApplyResult:
        if self.last_apply_failures:
            if scope_map is not None:
                for raw, value in scope_map.active().items():
                    if value:
                        self._map_operation(scope_map, "set", raw, 0, dry_run)
            for key, policy in original.endpoint_policies.items():
                if policy.allow:
                    result.blocked_endpoints.setdefault(key, "target admission blocked after apply failure; existing state requires confirmation")
            result.unconfirmed["maps"] = "one or more backend operations failed; retained admissions require readback"
        if not dry_run and not self.last_apply_failures and not result.unconfirmed:
            self._endpoint_cache = {
                key: replace(policy, allow=False, reason=result.blocked_endpoints[key]) if key in result.blocked_endpoints else policy
                for key, policy in desired_state.endpoint_policies.items()
            }
        result.applied = self.get_applied_state()
        if dry_run:
            result.unconfirmed["maps"] = "dry run did not write or confirm kernel state"
        else:
            for name in ("endpoint_map", "tcp_map", "udp_map", "tcp_zone_map", "udp_zone_map",
                         "tcp_profile_map", "_tcp_policy_map", "_udp_policy_map", "sctp_map",
                         "trusted_map", "acl_maps", "sit4_map", "tcp_syncookie_mode_map",
                         "tcp_syncookie_rate_map", "syn4_outer", "syn6_outer", "udprt4_outer", "udprt6_outer"):
                resource = getattr(self, name, None)
                if resource is None:
                    continue
                if not hasattr(resource, "verify"):
                    result.applied.evidence[name] = "cached"
                    result.unconfirmed[name] = "resource does not support kernel readback"
                    continue
                try:
                    drift = resource.verify()
                    result.applied.evidence[name] = "confirmed"
                    if drift:
                        result.unconfirmed[name] = f"kernel readback differs in {drift} entries"
                except (OSError, RuntimeError) as exc:
                    result.applied.evidence[name] = "unknown"
                    result.unconfirmed[name] = str(exc)
        evidence = dict(result.applied.evidence)
        result.applied = self.get_applied_state()
        result.applied.evidence.update(evidence)
        if not dry_run and self.runtime_config_map is not None:
            timing = self.runtime_config_map.get()
            flags = self.runtime_config_map.get_cfg_flags()
            if timing == desired_state.xdp_runtime_config and flags == _compute_cfg_flags(desired_state):
                result.applied.evidence["runtime_config"] = "confirmed"
            else:
                result.applied.evidence["runtime_config"] = "unknown"
                result.unconfirmed["runtime_config"] = "runtime config/gate flags could not be confirmed"
        if not dry_run and self.global_rl_map is not None:
            rate = self.global_rl_map.get()
            if rate == desired_state.udp_global_byte_rate:
                result.applied.evidence["udp_global_rate"] = "confirmed"
            else:
                result.applied.evidence["udp_global_rate"] = "unknown"
                result.unconfirmed["udp_global_rate"] = "global UDP rate could not be confirmed"
        if not dry_run and scope_map is not None and result.applied.evidence.get("endpoint_map") == "confirmed" and result.applied.evidence.get("runtime_config") == "confirmed":
            checked_policies = {**result.applied.endpoint_policies, **desired_state.endpoint_policies}
            for key, policy in checked_policies.items():
                if key in result.blocked_endpoints:
                    policy = replace(policy, allow=False)
                values, errors = self._scope_values(replace(desired_state, endpoint_policies={key: policy}))
                known = bool(values) and key not in errors and all(scope_map.active().get(raw) == value or
                    (not value and raw not in scope_map.active() and not any(scope_map.active().values()))
                    for raw, value in values.items())
                if not values and not policy.allow and desired_state.endpoint_policy_enabled:
                    known = self._unresolved_scope_closed(key, desired_state.config, scope_map.active())
                admitted = known and policy.allow
                if admitted:
                    proto, _, port, zone = key
                    map_name = {"tcp": "tcp_map", "udp": "udp_map", "sctp": "sctp_map"}[proto]
                    admitted = result.applied.evidence.get(map_name) == "confirmed"
                    interfaces = desired_state.config.ZONES.get(zone, {}).get("interfaces", ())
                    if proto in {"tcp", "udp"} and interfaces:
                        zone_map = getattr(self, f"{proto}_zone_map", None)
                        admitted = admitted and result.applied.evidence.get(f"{proto}_zone_map") == "confirmed"
                        for interface in interfaces:
                            try:
                                zone_value = zone_map.value(socket.if_nametoindex(interface), port) if zone_map is not None else None
                            except OSError:
                                zone_value = None
                            admitted = admitted and bool(zone_value and zone_value[0])
                    else:
                        admitted = admitted and port in getattr(result.applied, f"{proto}_ports")
                result.applied.endpoint_admission[key] = "admitted" if admitted else "closed" if known and not policy.allow else "unknown"
                if known and not policy.allow:
                    result.closed_endpoints.add(key)
                if result.applied.endpoint_admission[key] == "unknown":
                    result.unconfirmed[str(key)] = "endpoint admission could not be confirmed"
        self.last_apply_result = result
        self._apply_result = None
        return result

    def _apply_acl_delta(self, plan: ReconcilePlan, dry_run: bool) -> None:
        if self.acl_maps is None:
            return
        for (proto, cidr), ports in plan.acl_rules_to_upsert.items():
            if self._map_operation(self.acl_maps, 'set', proto, cidr, sorted(ports), dry_run):
                log.info("ACL %s %s ports %s", proto.upper(), cidr, sorted(ports))

        for (proto, cidr) in plan.acl_rules_to_remove:
            if self._map_operation(self.acl_maps, 'delete', proto, cidr, dry_run):
                log.info("ACL %s %s removed", proto.upper(), cidr)

    def _apply_rate_outer_delta(
        self,
        outer: BpfRateOuterMap,
        desired: dict[int, int],
        dry_run: bool,
    ) -> None:
        current = outer.active()
        for port, capacity in desired.items():
            if current.get(port) != capacity:
                self._map_operation(outer, 'set', port, capacity, dry_run)
        for port in set(current) - set(desired):
            self._map_operation(outer, 'delete', port, dry_run)

    def _apply_rate_map_delta(
        self,
        rate_map: RateLimitMap,
        upserts: dict[int, int],
        removals: set[int],
        dry_run: bool,
        kind: str,
        port_procs: dict[int, str] | None = None,
    ) -> None:
        port_procs = {} if port_procs is None else port_procs
        for port, rate_max in upserts.items():
            if self._map_operation(rate_map, 'set', port, rate_max, dry_run):
                if kind == "tcp":
                    svc = port_procs.get(port) or service_name(port, "tcp") or "unknown"
                    log.info("SYN rate port %d (%s) rate_max=%d/s", port, svc, rate_max)
                elif kind == "tcp_syn_agg":
                    log.info("SYN aggregate port %d rate_max=%d/s", port, rate_max)
                elif kind == "udp":
                    svc = port_procs.get(port) or service_name(port, "udp") or "unknown"
                    log.info("UDP rate port %d (%s) rate_max=%d/s", port, svc, rate_max)
                elif kind == "udp_agg":
                    log.info("UDP aggregate port %d byte_rate_max=%d/s", port, rate_max)

        for port in removals:
            if self._map_operation(rate_map, 'delete', port, dry_run):
                if kind == "tcp":
                    log.info("SYN rate port %d removed (port no longer whitelisted)", port)
                elif kind == "tcp_syn_agg":
                    log.info("SYN aggregate port %d removed", port)
                elif kind == "udp":
                    log.info("UDP rate port %d removed (port no longer whitelisted)", port)
                elif kind == "udp_agg":
                    log.info("UDP aggregate port %d removed", port)
