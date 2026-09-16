import json
import socket
import struct
import subprocess
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

import pytest

from auto_xdp.discovery import (
    DiscoveryError,
    _bind_ip_is_exposed,
    _discovery_exclude_networks,
)
from auto_xdp.bpf.maps import render_nft_ports as _render_nft_ports
from auto_xdp import config as cfg
import auto_xdp.backends as backends_mod
import auto_xdp.backends.xdp as xdp_backend_mod
import auto_xdp.backends.nftables as nftables_mod
import auto_xdp.bpf.maps as bpf_maps_mod
import auto_xdp.proc_events as proc_events_mod
import auto_xdp.syncer as syncer_mod
import auto_xdp.discovery as discovery_mod
import auto_xdp.cli as cli_mod
import auto_xdp.policy as policy_mod
import auto_xdp.services as services_mod
import auto_xdp.state as state_mod


def make_addr(ip: str, port: int):
    return types.SimpleNamespace(ip=ip, port=port)


def make_conn(
    *,
    family,
    conn_type,
    status,
    laddr,
    raddr=None,
    pid=None,
):
    return types.SimpleNamespace(
        family=family,
        type=conn_type,
        status=status,
        laddr=laddr,
        raddr=raddr,
        pid=pid,
    )


class FakeDiagSocket:
    def __init__(self, payload):
        self.payload = payload
        self.read = False

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def bind(self, address):
        return None

    def sendall(self, data):
        return None

    def recv_into(self, buf):
        if self.read:
            return 0
        self.read = True
        buf[:len(self.payload)] = self.payload
        return len(self.payload)


class FakePortMap:
    def __init__(self, active=None):
        self._active = set(active or [])
        self.ops = []
        self.closed = False

    def active_ports(self):
        return set(self._active)

    def value(self, port):
        for op_port, value, dry_run in reversed(self.ops):
            if op_port == port and not dry_run and isinstance(value, tuple):
                return value
        return None

    def set(self, port, val, dry_run=False):
        self.ops.append((port, val, dry_run))
        active = val[0] if isinstance(val, tuple) else val
        if active:
            self._active.add(port)
        else:
            self._active.discard(port)
        return True

    def close(self):
        self.closed = True


class FakeProfileMap:
    def __init__(self, program_id=None):
        self.program_id = program_id
        self.closed = False

    def verify(self):
        return 0

    def refresh(self):
        return None

    def value(self, _profile_id):
        return None if self.program_id is None else (self.program_id,)

    def close(self):
        self.closed = True


class FakeTrustedMap:
    def __init__(self, active=None):
        self._active = set(active or [])
        self.set_ops = []
        self.delete_ops = []
        self.closed = False

    def active_keys(self):
        return set(self._active)

    def set(self, key, val, dry_run=False):
        self.set_ops.append((key, val, dry_run))
        if val:
            self._active.add(key)
        return True

    def delete(self, key, dry_run=False):
        self.delete_ops.append((key, dry_run))
        self._active.discard(key)
        return True

    def close(self):
        self.closed = True


class FakeSynRateMap:
    def __init__(self, active=None):
        self._active = dict(active or {})
        self.fail_set = False
        self.set_ops = []
        self.delete_ops = []
        self.closed = False

    def active(self):
        return dict(self._active)

    def set(self, port, rate_max, dry_run=False):
        self.set_ops.append((port, rate_max, dry_run))
        if self.fail_set:
            return False
        self._active[port] = rate_max
        return True

    def delete(self, port, dry_run=False):
        self.delete_ops.append((port, dry_run))
        self._active.pop(port, None)
        return True

    def close(self):
        self.closed = True


class FakeUdpPortMap(FakeSynRateMap):
    pass


class FakeRuntimeConfigMap:
    def __init__(self, active=None, cfg_flags=0):
        self._active = active
        self._cfg_flags = cfg_flags
        self.ops = []
        self.closed = False

    def get(self):
        return self._active

    def get_cfg_flags(self):
        return self._cfg_flags

    def set(self, fields, cfg_flags=0, dry_run=False):
        self.ops.append((fields, cfg_flags, dry_run))
        self._active = fields
        self._cfg_flags = cfg_flags
        return True

    def close(self):
        self.closed = True


class FakeGlobalRlMap:
    def __init__(self, active=0):
        self._active = active
        self.ops = []
        self.closed = False

    def get(self):
        return self._active

    def set(self, byte_rate_max, dry_run=False):
        self.ops.append((byte_rate_max, dry_run))
        self._active = byte_rate_max
        return True

    def close(self):
        self.closed = True


class FakeRateOuterMap:
    def __init__(self, initial=None):
        self._active = dict(initial or {})
        self.ops = []
        self.closed = False

    def active(self):
        return dict(self._active)

    def set(self, port, capacity, dry_run=False):
        self.ops.append(("set", port, capacity, dry_run))
        if not dry_run:
            self._active[port] = capacity
        return True

    def delete(self, port, dry_run=False):
        self.ops.append(("delete", port, dry_run))
        if not dry_run:
            self._active.pop(port, None)
        return True

    def verify(self):
        return 0

    def close(self):
        self.closed = True


def make_proc_event_message(what: int) -> bytes:
    payload = struct.pack("I", what)
    cn = struct.pack("IIIIHH", proc_events_mod._CN_IDX_PROC, 1, 0, 0, len(payload), 0) + payload
    msg_len = proc_events_mod._NLMSG_HDRLEN + len(cn)
    hdr = struct.pack("IHHII", msg_len, proc_events_mod._NLMSG_MIN_TYPE, 0, 0, 0)
    padded_len = (msg_len + 3) & ~3
    return hdr + cn + (b"\x00" * (padded_len - msg_len))


class DiscoveryDumpTests(unittest.TestCase):
    def test_nldiag_error_is_not_treated_as_empty_dump(self):
        payload = struct.pack("=IHHIIi", 20, 2, 0, 1, 0, -22)
        with mock.patch.object(discovery_mod.socket, "AF_NETLINK", 16, create=True), \
             mock.patch.object(discovery_mod.socket, "socket", return_value=FakeDiagSocket(payload)):
            with self.assertRaises(DiscoveryError):
                list(discovery_mod._nldiag_dump(socket.AF_INET, socket.IPPROTO_TCP, 1))

    def test_nldiag_truncated_dump_is_rejected(self):
        payload = struct.pack("=IHHII", 24, 20, 0, 1, 0)
        with mock.patch.object(discovery_mod.socket, "AF_NETLINK", 16, create=True), \
             mock.patch.object(discovery_mod.socket, "socket", return_value=FakeDiagSocket(payload)):
            with self.assertRaises(DiscoveryError):
                list(discovery_mod._nldiag_dump(socket.AF_INET, socket.IPPROTO_TCP, 1))

    def test_nldiag_empty_complete_dump_is_valid(self):
        payload = struct.pack("=IHHII", 16, 3, 0, 1, 0)
        with mock.patch.object(discovery_mod.socket, "AF_NETLINK", 16, create=True), \
             mock.patch.object(discovery_mod.socket, "socket", return_value=FakeDiagSocket(payload)):
            self.assertEqual(
                list(discovery_mod._nldiag_dump(socket.AF_INET, socket.IPPROTO_TCP, 1)),
                [],
            )

    def test_nldiag_valid_listen_message_is_parsed(self):
        src = socket.inet_pton(socket.AF_INET6, "::ffff:203.0.113.10")
        dst = bytes(16)
        msg = discovery_mod._NLMSGHDR.pack(
            discovery_mod._NLMSGHDR_SZ + discovery_mod._DIAG_MSG_SZ,
            discovery_mod._SOCK_DIAG_BY_FAMILY,
            0, 1, 0,
        ) + discovery_mod._DIAG_MSG.pack(
            socket.AF_INET, 10, 0, 0,
            socket.htons(443), 0, src, dst,
            0, 0, 0, 0, 0, 0, 101, 4242,
        ) + discovery_mod._NLMSGHDR.pack(16, 3, 0, 1, 0)
        with mock.patch.object(discovery_mod.socket, "AF_NETLINK", 16, create=True), \
             mock.patch.object(discovery_mod.socket, "socket", return_value=FakeDiagSocket(msg)):
            rows = list(discovery_mod._nldiag_dump(socket.AF_INET, socket.IPPROTO_TCP, 1))
        self.assertEqual(rows, [(443, 0, src, dst, 4242, 0)])


class XdpPortSyncTests(unittest.TestCase):
    def test_bpf_endpoint_maps_reject_wrong_kernel_value_size(self):
        patches = (
            mock.patch.object(bpf_maps_mod, "obj_get", return_value=9),
            mock.patch.object(bpf_maps_mod, "map_max_entries", return_value=65536),
            mock.patch.object(bpf_maps_mod, "map_value_size", return_value=4),
            mock.patch.object(bpf_maps_mod.os, "close"),
        )
        with patches[0], patches[1], patches[2], patches[3] as close:
            with self.assertRaisesRegex(OSError, "value_size=4, expected 24"):
                bpf_maps_mod.BpfArrayMap("/tmp/tcp_whitelist", "=IIQQ")
            with self.assertRaisesRegex(OSError, "value_size=4, expected 24"):
                bpf_maps_mod.BpfZonePortMap("/tmp/tcp_zone_whitelist", "=IIQQ")
        self.assertEqual(close.call_count, 2)

    def test_minecraft_profile_handler_is_loaded_and_removed_with_workload(self):
        backend = backends_mod.XdpBackend.__new__(backends_mod.XdpBackend)
        backend.tcp_profile_map = FakeProfileMap(42)
        with tempfile.TemporaryDirectory() as root_raw:
            root = Path(root_raw)
            install_dir = root / "install"
            pin_dir = root / "bpf"
            run_dir = root / "run"
            object_path = install_dir / "handlers" / "minecraft_handler.o"
            object_path.parent.mkdir(parents=True)
            object_path.touch()

            with mock.patch.dict(
                "os.environ",
                {"PYTHON_LIB_DIR": str(install_dir / "python"), "RUN_STATE_DIR": str(run_dir)},
            ), mock.patch.object(cfg, "BPF_PIN_DIR", str(pin_dir)), \
                 mock.patch.object(backend, "_pinned_program_id", side_effect=[None, 42]), \
                 mock.patch.object(backend, "_profile_command", return_value=True) as command:
                self.assertEqual(
                    backend._ensure_profile_handlers({
                        ("public", 25565): "minecraft",
                        ("public", 25566): "minecraft",
                    }, backend._profile_generation(object_path), dry_run=False)[0],
                    set(),
                )

            marker = run_dir / "profile-handlers" / "tcp" / "minecraft"
            marker_value = json.loads(marker.read_text())
            self.assertEqual(marker_value["profile"], "minecraft")
            self.assertEqual(marker_value["profile_id"], 1)
            self.assertEqual(marker_value["program_id"], 42)
            self.assertEqual(marker_value["profile_generation"], backend._profile_generation(object_path.resolve()))
            command.assert_called_once_with("load", 1, object_path.resolve())
            marker.unlink()

            with mock.patch.dict("os.environ", {"RUN_STATE_DIR": str(run_dir)}), \
                 mock.patch.object(cfg, "BPF_PIN_DIR", str(pin_dir)), \
                 mock.patch.object(backend, "_pinned_program_id", return_value=42), \
                 mock.patch.object(backend, "_profile_command", return_value=True) as command:
                self.assertEqual(backend._remove_stale_profile_handlers({}, dry_run=False), 0)

            command.assert_called_once_with("unload", 1)
            self.assertFalse(marker.exists())

            with mock.patch.dict("os.environ", {"RUN_STATE_DIR": str(run_dir)}), \
                 mock.patch.object(cfg, "BPF_PIN_DIR", str(pin_dir)), \
                 mock.patch.object(backend, "_pinned_program_id", return_value=77), \
                 mock.patch.object(backend, "_profile_command") as command:
                self.assertEqual(
                    backend._ensure_profile_handlers(
                        {("public", 25565): "minecraft"},
                        backend._profile_generation(object_path),
                        dry_run=False,
                    )[0],
                    {("public", 25565)},
                )
            self.assertEqual([call.args[0] for call in command.call_args_list], ["load", "unload"])

    def test_profile_command_uses_profile_handler_cli_contract(self):
        backend = backends_mod.XdpBackend.__new__(backends_mod.XdpBackend)
        with mock.patch.object(cfg, "TOML_CONFIG_PATH", "/etc/auto_xdp/config.toml"), \
             mock.patch.object(cfg, "BPF_PIN_DIR", "/sys/fs/bpf/xdp_fw"), \
             mock.patch.object(backend, "_profile_install_dir", return_value=Path("/opt/auto_xdp")), \
             mock.patch.object(subprocess, "run", return_value=subprocess.CompletedProcess([], 0)) as run:
            self.assertTrue(
                backend._profile_command(
                    "load", 1, Path("/opt/auto_xdp/handlers/minecraft_handler.o")
                )
            )

        command = run.call_args.args[0]
        self.assertEqual(command[-4:], [
            "profile-handler", "load", "1",
            "/opt/auto_xdp/handlers/minecraft_handler.o",
        ])
        self.assertNotIn("--no-config-update", command)

    def test_missing_profile_marker_is_rebuilt_from_official_object(self):
        backend = backends_mod.XdpBackend.__new__(backends_mod.XdpBackend)
        backend.tcp_profile_map = FakeProfileMap(42)
        with tempfile.TemporaryDirectory() as root_raw:
            root = Path(root_raw)
            install_dir = root / "install"
            object_path = install_dir / "handlers" / "minecraft_handler.o"
            object_path.parent.mkdir(parents=True)
            object_path.write_bytes(b"profile-v1")

            def command(action, _profile_id, _object_path=None):
                if action == "load":
                    backend.tcp_profile_map.program_id = 43
                return True

            with mock.patch.dict("os.environ", {
                "PYTHON_LIB_DIR": str(install_dir / "python"),
                "RUN_STATE_DIR": str(root / "run"),
            }), mock.patch.object(cfg, "BPF_PIN_DIR", str(root / "bpf")), \
                 mock.patch.object(backend, "_pinned_program_id", side_effect=[42, 43]), \
                 mock.patch.object(backend, "_profile_command", side_effect=command):
                failed, generation = backend._ensure_profile_handlers(
                    {("public", 25565): "minecraft"},
                    backend._profile_generation(object_path),
                    dry_run=False,
                )

            self.assertEqual(failed, set())
            self.assertGreater(generation, 0)
            marker = root / "run" / "profile-handlers" / "tcp" / "minecraft"
            self.assertEqual(json.loads(marker.read_text())["program_id"], 43)

    def test_config_rejects_interface_shared_by_two_zones(self):
        old_zones = cfg.ZONES
        try:
            with self.assertRaisesRegex(ValueError, "belongs to both zones"):
                cfg.apply_toml_config({
                    "zones": {
                        "public": {"interfaces": ["eth0"]},
                        "trusted": {"interfaces": ["eth0"]},
                    }
                })
        finally:
            cfg.ZONES = old_zones

    def test_global_admission_installs_known_zone_deny_tombstones(self):
        backend = backends_mod.XdpBackend.__new__(backends_mod.XdpBackend)
        backend._policy_generations = {}
        desired = state_mod.DesiredState(tcp_ports={25565}, udp_ports={19132})

        with mock.patch.object(cfg, "ZONES", {
            "public": {"interfaces": []},
            "trusted": {"interfaces": ["wg0"]},
        }), mock.patch.object(socket, "if_nametoindex", return_value=7):
            _, tcp_zone = backend._desired_tcp_values(desired, 0)
            udp_zone = backend._desired_udp_zone_values(desired)

        self.assertEqual(tcp_zone, {(7, 25565): (0, 0, 0, 0)})
        self.assertEqual(udp_zone, {(7, 19132): 0})

    def test_endpoint_generation_is_stable_then_bumps_after_deactivation(self):
        backend = backends_mod.XdpBackend.__new__(backends_mod.XdpBackend)
        backend._policy_generations = {}
        endpoint = state_mod.RuntimeEndpoint(
            "tcp", "0.0.0.0", 25565, "wildcard", "public",
            "minecraft.service", "exact", "systemd-cgroup",
            instance_id="old-socket-inode",
        )
        decision = state_mod.ExposureDecision(
            endpoint, "allow", "matched", "minecraft", "minecraft"
        )
        desired = state_mod.DesiredState(
            tcp_ports={25565},
            tcp_protection_profiles={("public", 25565): "minecraft"},
            exposure_decisions=[decision],
        )

        first, _ = backend._desired_tcp_values(desired, 0)
        unchanged, _ = backend._desired_tcp_values(desired, 0)
        changed_policy = state_mod.DesiredState(
            tcp_ports={25565},
            tcp_syn_rate_limits={25565: 99},
            tcp_protection_profiles={("public", 25565): "minecraft"},
            exposure_decisions=[decision],
        )
        changed, _ = backend._desired_tcp_values(changed_policy, 0)
        restarted = state_mod.DesiredState(
            tcp_ports={25565},
            tcp_syn_rate_limits={25565: 99},
            tcp_protection_profiles={("public", 25565): "minecraft"},
            exposure_decisions=[state_mod.ExposureDecision(
                state_mod.RuntimeEndpoint(
                    "tcp", "0.0.0.0", 25565, "wildcard", "public",
                    "minecraft.service", "exact", "systemd-cgroup",
                    instance_id="new-socket-inode",
                ),
                "allow", "matched", "minecraft", "minecraft",
            )],
        )
        restarted_value, _ = backend._desired_tcp_values(restarted, 0)
        backend._desired_tcp_values(state_mod.DesiredState(), 0)
        reactivated, _ = backend._desired_tcp_values(desired, 0)

        self.assertEqual(first[25565], unchanged[25565])
        self.assertNotEqual(first[25565][2], changed[25565][2])
        self.assertNotEqual(changed[25565][2], restarted_value[25565][2])
        self.assertNotEqual(first[25565][2], reactivated[25565][2])

    def test_generic_endpoint_does_not_allocate_policy_generation(self):
        backend = backends_mod.XdpBackend.__new__(backends_mod.XdpBackend)
        backend._policy_generations = {}

        global_values, _ = backend._desired_tcp_values(
            state_mod.DesiredState(tcp_ports={8080}), 0
        )

        self.assertEqual(global_values[8080], (1, 0, 0, 0))
        self.assertEqual(backend._policy_generations, {})

    def test_policy_generation_state_survives_backend_restart(self):
        backend = backends_mod.XdpBackend.__new__(backends_mod.XdpBackend)
        backend._policy_generations = {
            ("public", 25565): ("policy-fingerprint", 123456789)
        }
        backend._persisted_policy_generations = {}

        with tempfile.TemporaryDirectory() as root_raw, mock.patch.dict(
            "os.environ", {"RUN_STATE_DIR": root_raw}
        ):
            backend._save_policy_generations()
            restarted = backends_mod.XdpBackend.__new__(backends_mod.XdpBackend)
            restored = restarted._load_policy_generations()

        self.assertEqual(restored, backend._policy_generations)

    def test_new_port_stays_closed_when_protection_setup_fails(self):
        backend = backends_mod.XdpBackend.__new__(backends_mod.XdpBackend)
        backend.tcp_map = FakePortMap()
        backend.udp_map = FakePortMap()
        backend.sctp_map = None
        backend.trusted_map = FakeTrustedMap()
        backend.syn_rate_map = FakeSynRateMap()
        backend.syn_rate_map.fail_set = True
        backend.syn_agg_rate_map = None
        backend.udp_rate_map = None
        backend.udp_agg_rate_map = None
        backend.acl_maps = None
        backend.runtime_config_map = None
        backend.global_rl_map = None
        backend.sit4_map = None
        backend.syn4_outer = None
        backend.syn6_outer = None
        backend.udprt4_outer = None
        backend.udprt6_outer = None
        backend._tcp_policy_map = None
        backend._udp_policy_map = None

        plan = state_mod.ReconcilePlan(
            tcp_ports_to_add={443},
            tcp_syn_rate_limits_to_upsert={443: 1},
        )
        backend.apply_reconcile_plan(
            plan,
            dry_run=False,
            desired_state=state_mod.DesiredState(tcp_ports={443}),
        )

        self.assertEqual(backend.tcp_map.ops, [])
        self.assertEqual(backend.last_apply_failures, 1)

    def test_apply_toml_config_supports_extended_runtime_options(self):
        old_values = {
            "log_level": cfg.LOG_LEVEL,
            "debounce_seconds": cfg.DEBOUNCE_SECONDS,
            "preferred_backend": cfg.PREFERRED_BACKEND,
            "exclude_loopback": cfg.DISCOVERY_EXCLUDE_LOOPBACK,
            "exclude_bind_cidrs": list(cfg.DISCOVERY_EXCLUDE_BIND_CIDRS),
            "drop_events_enabled": cfg.DROP_EVENTS_ENABLED,
            "syn_agg_by_proc": dict(cfg._SYN_AGG_RATE_BY_PROC),
            "syn_agg_by_service": dict(cfg._SYN_AGG_RATE_BY_SERVICE),
            "udp_agg_bytes_by_proc": dict(cfg._UDP_AGG_BYTES_BY_PROC),
            "udp_agg_bytes_by_service": dict(cfg._UDP_AGG_BYTES_BY_SERVICE),
            "rate_limit_source_prefix_v4": cfg.RATE_LIMIT_SOURCE_PREFIX_V4,
            "rate_limit_source_prefix_v6": cfg.RATE_LIMIT_SOURCE_PREFIX_V6,
            "xdp_icmp_burst_packets": cfg.XDP_ICMP_BURST_PACKETS,
            "xdp_icmp_rate_pps": cfg.XDP_ICMP_RATE_PPS,
            "xdp_udp_global_window_seconds": cfg.XDP_UDP_GLOBAL_WINDOW_SECONDS,
            "xdp_rate_window_seconds": cfg.XDP_RATE_WINDOW_SECONDS,
            "xdp_udp_global_byte_rate": cfg.XDP_UDP_GLOBAL_BYTE_RATE,
        }
        try:
            cfg.apply_toml_config({
                "daemon": {
                    "log_level": "debug",
                    "debounce_seconds": 1.25,
                    "preferred_backend": "nftables",
                },
                "discovery": {
                    "exclude_loopback": False,
                    "exclude_bind_cidrs": ["10.0.0.0/8", "fd00::/8"],
                },
                "rate_limits": {
                    "source_cidr_v4": 24,
                    "source_cidr_v6": "/64",
                    "syn_agg_by_proc": {"sshd": 16},
                    "syn_agg_by_service": {"ssh": 12},
                    "udp_agg_bytes_by_proc": {"dnsmasq": 6000000},
                    "udp_agg_bytes_by_service": {"domain": 7000000},
                },
                "under_attack": {
                    "enabled": True,
                },
                "xdp": {
                    "runtime": {
                        "icmp_burst_packets": 200,
                        "icmp_rate_pps": 50,
                        "udp_global_window_seconds": 2,
                        "rate_window_seconds": 0.5,
                        "udp_global_byte_rate_mbps": 997,
                    },
                },
            })

            self.assertEqual(cfg.LOG_LEVEL, "debug")
            self.assertEqual(cfg.DEBOUNCE_SECONDS, 1.25)
            self.assertEqual(cfg.PREFERRED_BACKEND, cfg.BACKEND_NFTABLES)
            self.assertFalse(cfg.DISCOVERY_EXCLUDE_LOOPBACK)
            self.assertEqual(
                cfg.DISCOVERY_EXCLUDE_BIND_CIDRS,
                ["10.0.0.0/8", "fd00::/8"],
            )
            self.assertEqual(cfg._SYN_AGG_RATE_BY_PROC, {"sshd": 16})
            self.assertEqual(cfg._SYN_AGG_RATE_BY_SERVICE, {"ssh": 12})
            self.assertEqual(cfg._UDP_AGG_BYTES_BY_PROC, {"dnsmasq": 6000000})
            self.assertEqual(cfg._UDP_AGG_BYTES_BY_SERVICE, {"domain": 7000000})
            self.assertEqual(cfg.RATE_LIMIT_SOURCE_PREFIX_V4, 24)
            self.assertEqual(cfg.RATE_LIMIT_SOURCE_PREFIX_V6, 64)
            self.assertEqual(cfg.XDP_ICMP_BURST_PACKETS, 200)
            self.assertEqual(cfg.XDP_ICMP_RATE_PPS, 50)
            self.assertEqual(cfg.XDP_UDP_GLOBAL_WINDOW_SECONDS, 2)
            self.assertEqual(cfg.XDP_RATE_WINDOW_SECONDS, 0.5)
            self.assertEqual(cfg.XDP_UDP_GLOBAL_BYTE_RATE, 124_625_000)
            self.assertFalse(cfg.DROP_EVENTS_ENABLED)
        finally:
            cfg.LOG_LEVEL = old_values["log_level"]
            cfg.DEBOUNCE_SECONDS = old_values["debounce_seconds"]
            cfg.PREFERRED_BACKEND = old_values["preferred_backend"]
            cfg.DISCOVERY_EXCLUDE_LOOPBACK = old_values["exclude_loopback"]
            cfg.DISCOVERY_EXCLUDE_BIND_CIDRS[:] = old_values["exclude_bind_cidrs"]
            cfg.DROP_EVENTS_ENABLED = old_values["drop_events_enabled"]
            cfg._SYN_AGG_RATE_BY_PROC.clear()
            cfg._SYN_AGG_RATE_BY_PROC.update(old_values["syn_agg_by_proc"])
            cfg._SYN_AGG_RATE_BY_SERVICE.clear()
            cfg._SYN_AGG_RATE_BY_SERVICE.update(old_values["syn_agg_by_service"])
            cfg._UDP_AGG_BYTES_BY_PROC.clear()
            cfg._UDP_AGG_BYTES_BY_PROC.update(old_values["udp_agg_bytes_by_proc"])
            cfg._UDP_AGG_BYTES_BY_SERVICE.clear()
            cfg._UDP_AGG_BYTES_BY_SERVICE.update(old_values["udp_agg_bytes_by_service"])
            cfg.RATE_LIMIT_SOURCE_PREFIX_V4 = old_values["rate_limit_source_prefix_v4"]
            cfg.RATE_LIMIT_SOURCE_PREFIX_V6 = old_values["rate_limit_source_prefix_v6"]
            cfg.XDP_ICMP_BURST_PACKETS = old_values["xdp_icmp_burst_packets"]
            cfg.XDP_ICMP_RATE_PPS = old_values["xdp_icmp_rate_pps"]
            cfg.XDP_UDP_GLOBAL_WINDOW_SECONDS = old_values["xdp_udp_global_window_seconds"]
            cfg.XDP_RATE_WINDOW_SECONDS = old_values["xdp_rate_window_seconds"]
            cfg.XDP_UDP_GLOBAL_BYTE_RATE = old_values["xdp_udp_global_byte_rate"]

    def test_udp_malformed_drop_only_rejects_port_zero(self):
        source = (Path(__file__).resolve().parents[2] / "bpf" / "include" / "parse.h").read_text()
        self.assertRegex(
            source,
            r"if\s*\(\s*udp->source\s*==\s*0\s*\|\|\s*udp->dest\s*==\s*0\s*\)",
        )
        self.assertNotIn("udp->source == udp->dest", source)

    def test_udp_malformed_rejects_oversized_len_field(self):
        source = (Path(__file__).resolve().parents[2] / "bpf" / "include" / "parse.h").read_text()
        # Signature must accept a pre-computed integer instead of a packet pointer
        # so the verifier does not lose range tracking on subsequent ALU ops.
        self.assertRegex(
            source,
            r"udp_malformed_reason\s*\(\s*struct\s+udphdr\s*\*\s*udp\s*,\s*__u32\s+l4_avail\s*\)",
        )
        # Upper-bound: udp->len must not exceed available bytes from UDP header to data_end.
        # The check may be written via a local variable (ulen) to avoid calling bpf_ntohs twice.
        self.assertRegex(source, r"bpf_ntohs\s*\(\s*udp->len\s*\)")
        self.assertRegex(source, r"ulen\s*>\s*l4_avail")

    def test_render_nft_ports_sorts_ports(self):
        self.assertEqual(_render_nft_ports({443, 22, 80}), "{ 22, 80, 443 }")

    def test_port_rate_limit_prefers_process_name_then_service_name(self):
        import auto_xdp.policy as policy
        # Use a rate above the sensitive threshold (5) so the service entry is
        # returned as-is rather than triggering the strict default tier.
        with mock.patch.object(policy, "service_name", side_effect=lambda port, proto: "ssh" if port == 22 else "http"), \
             mock.patch.object(policy.cfg, "_SYN_RATE_BY_PROC", {"sshd": 2}), \
             mock.patch.object(policy.cfg, "_SYN_RATE_BY_SERVICE", {"ssh": 10}):
            self.assertEqual(policy._port_rate_limit(2222, "sshd"), 2)  # explicit proc
            self.assertEqual(policy._port_rate_limit(22), 10)            # explicit service (above threshold)
            self.assertEqual(policy._port_rate_limit(80), cfg.XDP_DEFAULT_TCP_SYN_RATE)  # normal default

    def test_policy_uses_rebound_config_dicts_not_import_time_aliases(self):
        import auto_xdp.policy as policy
        old_proc = policy.cfg._SYN_RATE_BY_PROC
        old_service = policy.cfg._SYN_RATE_BY_SERVICE
        try:
            policy.cfg._SYN_RATE_BY_PROC = {"sshd": 3}
            # Use rate above sensitive threshold (5) to test that the rebound
            # service dict is read (not import-time alias).
            policy.cfg._SYN_RATE_BY_SERVICE = {"ssh": 10}
            with mock.patch.object(policy, "service_name", return_value="ssh"):
                self.assertEqual(policy._port_rate_limit(2222, "sshd"), 3)
                self.assertEqual(policy._port_rate_limit(22), 10)
        finally:
            policy.cfg._SYN_RATE_BY_PROC = old_proc
            policy.cfg._SYN_RATE_BY_SERVICE = old_service

    def test_bind_ip_is_exposed_keeps_wildcard_but_filters_loopback_and_private(self):
        with mock.patch("auto_xdp.config.DISCOVERY_EXCLUDE_LOOPBACK", True), \
             mock.patch("auto_xdp.config.DISCOVERY_EXCLUDE_BIND_CIDRS", ["10.0.0.0/8", "fd00::/8"]):
            exclude_nets = _discovery_exclude_networks()

        self.assertTrue(_bind_ip_is_exposed("0.0.0.0", exclude_nets))
        self.assertTrue(_bind_ip_is_exposed("::", exclude_nets))
        self.assertFalse(_bind_ip_is_exposed("127.0.0.1", exclude_nets))
        self.assertFalse(_bind_ip_is_exposed("::1", exclude_nets))
        self.assertFalse(_bind_ip_is_exposed("10.1.2.3", exclude_nets))
        self.assertFalse(_bind_ip_is_exposed("fd00::1234", exclude_nets))
        self.assertTrue(_bind_ip_is_exposed("203.0.113.10", exclude_nets))

    def test_get_listening_ports_filters_loopback_and_configured_bind_cidrs(self):
        fake_psutil = types.SimpleNamespace(CONN_LISTEN="LISTEN", CONN_ESTABLISHED="ESTABLISHED")
        fake_connections = [
            make_conn(
                family=socket.AF_INET,
                conn_type=socket.SOCK_STREAM,
                status="LISTEN",
                laddr=make_addr("0.0.0.0", 22),
            ),
            make_conn(
                family=socket.AF_INET,
                conn_type=socket.SOCK_STREAM,
                status="LISTEN",
                laddr=make_addr("127.0.0.1", 8080),
            ),
            make_conn(
                family=socket.AF_INET6,
                conn_type=socket.SOCK_STREAM,
                status="LISTEN",
                laddr=make_addr("::1", 8443),
            ),
            make_conn(
                family=socket.AF_INET,
                conn_type=socket.SOCK_STREAM,
                status="LISTEN",
                laddr=make_addr("10.0.0.5", 9000),
            ),
            make_conn(
                family=socket.AF_INET6,
                conn_type=socket.SOCK_STREAM,
                status="LISTEN",
                laddr=make_addr("fd00::5", 9443),
            ),
            make_conn(
                family=socket.AF_INET,
                conn_type=socket.SOCK_STREAM,
                status="LISTEN",
                laddr=make_addr("203.0.113.10", 443),
            ),
            make_conn(
                family=socket.AF_INET,
                conn_type=socket.SOCK_STREAM,
                status="ESTABLISHED",
                laddr=make_addr("203.0.113.10", 443),
                raddr=make_addr("198.51.100.10", 50000),
            ),
            make_conn(
                family=socket.AF_INET,
                conn_type=socket.SOCK_DGRAM,
                status="",
                laddr=make_addr("0.0.0.0", 53),
                raddr=None,
            ),
            make_conn(
                family=socket.AF_INET,
                conn_type=socket.SOCK_DGRAM,
                status="",
                laddr=make_addr("127.0.0.1", 5353),
                raddr=None,
            ),
            make_conn(
                family=socket.AF_INET,
                conn_type=socket.SOCK_DGRAM,
                status="",
                laddr=make_addr("10.0.0.10", 9999),
                raddr=None,
            ),
        ]

        # Force the psutil fallback path; on Linux the netlink fast path would
        # read the real host sockets and ignore these fakes.
        with mock.patch("auto_xdp.discovery._IS_LINUX", False), \
             mock.patch("auto_xdp.discovery.psutil", fake_psutil), \
             mock.patch("auto_xdp.discovery._net_connections", return_value=fake_connections), \
             mock.patch("auto_xdp.config.DISCOVERY_EXCLUDE_LOOPBACK", True), \
             mock.patch("auto_xdp.config.DISCOVERY_EXCLUDE_BIND_CIDRS", ["10.0.0.0/8", "fd00::/8"]):
            state = discovery_mod.get_listening_ports()

        self.assertEqual(state.tcp, {22, 443})
        self.assertEqual(state.udp, {53})

    def test_get_listening_ports_filters_configured_exclude_ports(self):
        fake_psutil = types.SimpleNamespace(CONN_LISTEN="LISTEN", CONN_ESTABLISHED="ESTABLISHED")
        fake_connections = [
            make_conn(
                family=socket.AF_INET,
                conn_type=socket.SOCK_STREAM,
                status="LISTEN",
                laddr=make_addr("0.0.0.0", 22),
            ),
            make_conn(
                family=socket.AF_INET,
                conn_type=socket.SOCK_STREAM,
                status="LISTEN",
                laddr=make_addr("0.0.0.0", 8080),
            ),
            make_conn(
                family=socket.AF_INET,
                conn_type=socket.SOCK_DGRAM,
                status="",
                laddr=make_addr("0.0.0.0", 53),
                raddr=None,
            ),
        ]
        with mock.patch("auto_xdp.discovery._IS_LINUX", False), \
             mock.patch("auto_xdp.discovery.psutil", fake_psutil), \
             mock.patch("auto_xdp.discovery._net_connections", return_value=fake_connections), \
             mock.patch("auto_xdp.config.DISCOVERY_EXCLUDE_PORTS", {8080, 53}):
            state = discovery_mod.get_listening_ports()
        self.assertEqual(state.tcp, {22})
        self.assertEqual(state.udp, set())

    def test_netlink_preserves_exact_systemd_unit_subject(self):
        address = socket.inet_aton("0.0.0.0")

        def fake_dump(family, protocol, _states):
            if family == socket.AF_INET and protocol == socket.IPPROTO_TCP:
                return iter([(8080, 0, address, b"", 101, 0)])
            return iter(())

        with mock.patch.object(discovery_mod, "_nldiag_dump", side_effect=fake_dump), \
             mock.patch.object(discovery_mod, "_build_inode_pid", return_value={101: 42}), \
             mock.patch.object(discovery_mod, "_pid_comm", return_value="gunicorn"), \
             mock.patch.object(discovery_mod, "_pid_systemd_unit", return_value="my-web.service"), \
             mock.patch.object(discovery_mod, "_container_from_pid", return_value=None), \
             mock.patch.object(discovery_mod, "_container_for_endpoint", return_value=None), \
             mock.patch.object(discovery_mod, "_parse_proc_udp", return_value={}):
            state = discovery_mod._get_listening_ports_netlink()

        self.assertEqual(state.endpoints[0].subject, "my-web.service")
        self.assertEqual(state.endpoints[0].attribution_source, "systemd-cgroup")

    def test_netlink_keeps_each_udp_owner_for_shared_port_policy(self):
        wildcard = socket.inet_aton("0.0.0.0")
        specific = socket.inet_aton("192.0.2.10")

        def fake_dump(family, protocol, _states):
            if family == socket.AF_INET and protocol == socket.IPPROTO_UDP:
                return iter([
                    (5353, 0, wildcard, b"", 101, 0),
                    (5353, 0, specific, b"", 202, 0),
                ])
            return iter(())

        with mock.patch.object(discovery_mod, "_nldiag_dump", side_effect=fake_dump), \
             mock.patch.object(discovery_mod, "_build_inode_pid", return_value={101: 42}), \
             mock.patch.object(discovery_mod, "_pid_comm", return_value="dns-a"), \
             mock.patch.object(discovery_mod, "_pid_systemd_unit", return_value=""), \
             mock.patch.object(discovery_mod, "_container_from_pid", return_value=None), \
             mock.patch.object(discovery_mod, "_container_for_endpoint", return_value=None), \
             mock.patch.object(discovery_mod, "_parse_proc_udp", return_value={}):
            state = discovery_mod._get_listening_ports_netlink()

        endpoints = [item for item in state.endpoints if item.protocol == "udp"]
        self.assertEqual(len(endpoints), 2)
        self.assertEqual(
            {(item.subject, item.attribution_state) for item in endpoints},
            {("dns-a", "shared"), ("", "ambiguous")},
        )

    def test_sync_once_keeps_existing_policy_when_discovery_fails(self):
        backend = mock.Mock()
        with mock.patch.object(
            syncer_mod, "get_listening_ports", side_effect=DiscoveryError("truncated dump")
        ):
            with self.assertRaises(DiscoveryError):
                syncer_mod.sync_once(backend, dry_run=False)
        backend.reconcile.assert_not_called()

    def test_port_protection_policy_resolves_observed_ports(self):
        observed = state_mod.ObservedState(
            tcp={80, 2222},
            udp={53},
            sctp={2905},
            tcp_processes={2222: "sshd"},
            udp_processes={53: "named"},
        )

        def fake_service_name(port, proto):
            services = {
                (22, "tcp"): "ssh",
                (53, "udp"): "domain",
                (123, "udp"): "ntp",
            }
            if (port, proto) not in services:
                return ""
            return services[(port, proto)]

        with mock.patch.object(policy_mod, "service_name", side_effect=fake_service_name), \
             mock.patch.multiple(
                 policy_mod.cfg,
                 _SYN_RATE_BY_PROC={"sshd": 2},
                 _SYN_RATE_BY_SERVICE={"ssh": 2},
                 _UDP_RATE_BY_PROC={"named": 5000},
                 _UDP_RATE_BY_SERVICE={"domain": 5000},
                 TRUSTED_SRC_IPS={"203.0.113.8/32": "office"},
                 ACL_RULES=[{"proto": "tcp", "cidr": "203.0.113.0/24", "ports": [22, 443]}],
                 BOGON_FILTER_ENABLED=True,
                 RATE_LIMIT_SOURCE_PREFIX_V4=24,
                 RATE_LIMIT_SOURCE_PREFIX_V6=64,
                 XDP_ICMP_BURST_PACKETS=200,
                 XDP_ICMP_RATE_PPS=50.0,
                 XDP_UDP_GLOBAL_WINDOW_SECONDS=2.0,
                 XDP_RATE_WINDOW_SECONDS=0.5,
                 XDP_UDP_GLOBAL_BYTE_RATE=124_625_000,
             ):
            desired = policy_mod._desired_state_for_ports(observed)

        self.assertEqual(desired.tcp_ports, {80, 2222})
        self.assertEqual(desired.udp_ports, {53})
        self.assertEqual(desired.sctp_ports, {2905})
        self.assertEqual(desired.trusted_cidrs, {"203.0.113.8/32"})
        # Port 2222 has an explicit process limit; port 80 uses the default tier.
        self.assertEqual(desired.tcp_syn_rate_limits.get(2222), 2)
        self.assertEqual(desired.tcp_syn_rate_limits.get(80), cfg.XDP_DEFAULT_TCP_SYN_RATE)
        self.assertEqual(desired.udp_rate_limits.get(53), 5000)
        self.assertEqual(desired.acl_rules, {("tcp", "203.0.113.0/24"): frozenset({22, 443})})
        self.assertTrue(desired.bogon_filter_enabled)
        self.assertEqual(desired.rate_limit_source_prefix_v4, 24)
        self.assertEqual(desired.rate_limit_source_prefix_v6, 64)
        self.assertEqual(desired.udp_global_byte_rate, 124_625_000)
        self.assertEqual(
            desired.xdp_runtime_config,
            (
                0,
                0,
                0,
                200,
                20_000_000,
                2_000_000_000,
                500_000_000,
                0,
            ),
        )

    def test_xdp_backend_reconcile_adds_and_removes_runtime_state(self):
        backend = backends_mod.XdpBackend.__new__(backends_mod.XdpBackend)
        backend.tcp_map = FakePortMap({22, 80})
        backend.udp_map = FakePortMap({53, 9999})
        backend.sctp_map = FakePortMap({3868, 9899})
        backend.trusted_map = FakeTrustedMap({"203.0.113.1/32"})
        backend.syn_rate_map = FakeSynRateMap({22: 1})
        backend.syn_agg_rate_map = FakeSynRateMap()
        backend.udp_rate_map = FakeUdpPortMap()
        backend.udp_agg_rate_map = FakeUdpPortMap()
        backend.acl_maps = None
        backend.runtime_config_map = FakeRuntimeConfigMap()
        backend.global_rl_map = FakeGlobalRlMap()
        backend.sit4_map = None
        backend.syn4_outer = FakeRateOuterMap()
        backend.syn6_outer = FakeRateOuterMap()
        backend.udprt4_outer = FakeRateOuterMap()
        backend.udprt6_outer = FakeRateOuterMap()
        backend._tcp_policy_map = None
        backend._udp_policy_map = None
        runtime_cfg = (
            0,
            120_000_000_000,
            45_000_000_000,
            200,
            20_000_000,
            2_000_000_000,
            500_000_000,
            30_000_000_000,
        )
        desired = state_mod.DesiredState(
            tcp_ports={22, 443},
            udp_ports={53},
            sctp_ports={3868, 2905},
            trusted_cidrs={"198.51.100.5/32"},
            tcp_syn_rate_limits={22: 2},
            tcp_syn_agg_rate_limits={22: 16},
            udp_rate_limits={53: 5000},
            udp_agg_rate_limits={53: 6000000},
            drop_events_enabled=False,
            udp_global_byte_rate=124_625_000,
            xdp_runtime_config=runtime_cfg,
        )
        observed = state_mod.ObservedState(tcp_processes={22: "sshd"}, udp_processes={53: "named"})

        with mock.patch.object(cfg, "SLOT_DEFAULT_ACTION", "pass"), \
             mock.patch.object(cfg, "TRUSTED_SRC_IPS", {"198.51.100.5/32": "office"}):
            backend.reconcile(desired, dry_run=False, observed_state=observed)

        self.assertEqual(backend.tcp_map.ops[0], (80, 0, False))
        self.assertEqual(backend.tcp_map.ops[1][0], 443)
        self.assertEqual(backend.tcp_map.ops[1][1][0:2], (1, 0))
        self.assertEqual(backend.tcp_map.ops[1][1][2:], (0, 0))
        self.assertEqual(backend.tcp_map.ops[1][1][3], 0)
        self.assertEqual(backend.udp_map.ops, [(9999, 0, False)])
        self.assertEqual(backend.sctp_map.ops, [(2905, 1, False), (9899, 0, False)])
        self.assertEqual(backend.trusted_map.set_ops, [("198.51.100.5/32", 1, False)])
        self.assertEqual(backend.trusted_map.delete_ops, [("203.0.113.1/32", False)])
        self.assertEqual(backend.syn_rate_map.set_ops, [(22, 2, False)])
        self.assertEqual(backend.syn_agg_rate_map.set_ops, [(22, 16, False)])
        self.assertEqual(backend.udp_rate_map.set_ops, [(53, 5000, False)])
        self.assertEqual(backend.udp_agg_rate_map.set_ops, [(53, 6000000, False)])
        # bogon_filter_enabled=False (default) → BOGON_DISABLED(1), drop_events_enabled=False → DROP_EVENTS_DISABLED(4)
        self.assertEqual(backend.runtime_config_map.ops, [(runtime_cfg, 5, False)])
        self.assertEqual(backend.global_rl_map.ops, [(124_625_000, False)])

    def test_listening_port_processes_reuses_pid_lookup_cache(self):
        calls = []

        class FakePsutil:
            CONN_LISTEN = "LISTEN"

            @staticmethod
            def Process(pid):
                calls.append(pid)
                return types.SimpleNamespace(name=lambda: {77: "sshd", 88: "named"}[pid])

        conns = [
            make_conn(
                family=socket.AF_INET,
                conn_type=socket.SOCK_STREAM,
                status="LISTEN",
                laddr=make_addr("0.0.0.0", 22),
                pid=77,
            ),
            make_conn(
                family=socket.AF_INET,
                conn_type=socket.SOCK_STREAM,
                status="LISTEN",
                laddr=make_addr("0.0.0.0", 2222),
                pid=77,
            ),
            make_conn(
                family=socket.AF_INET,
                conn_type=socket.SOCK_DGRAM,
                status="",
                laddr=make_addr("0.0.0.0", 53),
                pid=88,
            ),
        ]

        # Force the psutil fallback path; on Linux the netlink fast path would
        # read the real host sockets and ignore these fakes.
        with mock.patch.object(discovery_mod, "_IS_LINUX", False), \
             mock.patch.object(discovery_mod, "psutil", FakePsutil), \
             mock.patch.object(discovery_mod, "_net_connections", object()):
            state = discovery_mod.get_listening_ports(cached_conns=conns)

        self.assertEqual(state.tcp_processes, {22: "sshd", 2222: "sshd"})
        self.assertEqual(state.udp_processes, {53: "named"})
        self.assertEqual(calls, [77, 88])

    def test_service_name_reads_local_services_file_once(self):
        services_mod._service_map.cache_clear()

        fake_services = "ssh 22/tcp\nhttp 80/tcp\nntp 123/udp\n"
        open_mock = mock.mock_open(read_data=fake_services)

        with mock.patch("builtins.open", open_mock):
            self.assertEqual(services_mod.service_name(22, "tcp"), "ssh")
            self.assertEqual(services_mod.service_name(123, "udp"), "ntp")
            self.assertEqual(services_mod.service_name(9999, "tcp"), "")
            self.assertEqual(services_mod.service_name(80, "tcp"), "http")

        open_mock.assert_called_once_with("/etc/services", "r", encoding="utf-8", errors="ignore")

    def test_bpf_map_dry_run_does_not_mutate_cached_state(self):
        array_map = bpf_maps_mod.BpfArrayMap.__new__(bpf_maps_mod.BpfArrayMap)
        array_map.path = "/tmp/tcp_whitelist"
        array_map._cache = {22}
        array_map.set(80, 1, dry_run=True)
        array_map.set(22, 0, dry_run=True)
        self.assertEqual(array_map._cache, {22})

        lpm_map = bpf_maps_mod.BpfLpmMap.__new__(bpf_maps_mod.BpfLpmMap)
        lpm_map.path = "/tmp/trusted_ipv4"
        lpm_map._cache = {"203.0.113.1/32"}
        lpm_map.set("198.51.100.5/32", 1, dry_run=True)
        lpm_map.delete("203.0.113.1/32", dry_run=True)
        self.assertEqual(lpm_map._cache, {"203.0.113.1/32"})

        acl_map = bpf_maps_mod.BpfAclMap.__new__(bpf_maps_mod.BpfAclMap)
        acl_map.path = "/tmp/tcp_acl_v4"
        acl_map._family = socket.AF_INET
        acl_map._cache = {"203.0.113.0/24": frozenset({22})}
        acl_map.set("198.51.100.0/24", [443], dry_run=True)
        acl_map.delete("203.0.113.0/24", dry_run=True)
        self.assertEqual(acl_map._cache, {"203.0.113.0/24": frozenset({22})})

        rate_map = bpf_maps_mod.BpfSynRatePortsMap.__new__(bpf_maps_mod.BpfSynRatePortsMap)
        rate_map.path = "/tmp/syn_rate_ports"
        rate_map._cache = {22: 2}
        rate_map.set(80, 10, dry_run=True)
        rate_map.delete(22, dry_run=True)
        self.assertEqual(rate_map._cache, {22: 2})

    def test_xdp_backend_apply_rate_map_delta_applies_precomputed_syn_limits(self):
        backend = backends_mod.XdpBackend.__new__(backends_mod.XdpBackend)
        backend.syn_rate_map = FakeSynRateMap({22: 1, 8080: 5})

        def fake_service_name(port, proto):
            services = {22: "ssh", 80: "http"}
            if port not in services:
                return ""
            return services[port]

        with mock.patch.object(xdp_backend_mod, "service_name", side_effect=fake_service_name):
            backend._apply_rate_map_delta(
                backend.syn_rate_map,
                {22: 2, 2222: 2},
                {8080},
                dry_run=False,
                kind="tcp",
                port_procs={2222: "sshd"},
            )

        self.assertCountEqual(
            backend.syn_rate_map.set_ops,
            [(22, 2, False), (2222, 2, False)],
        )
        self.assertEqual(backend.syn_rate_map.delete_ops, [(8080, False)])

    def test_udp_port_rate_limit_prefers_process_name_then_service_name(self):
        import auto_xdp.policy as policy
        def fake_service_name(port, proto):
            services = {53: "domain", 123: "ntp"}
            if port not in services:
                return ""
            return services[port]

        with mock.patch.object(policy, "service_name", side_effect=fake_service_name), \
             mock.patch.object(policy.cfg, "_UDP_RATE_BY_PROC", {"named": 5000}), \
             mock.patch.object(policy.cfg, "_UDP_RATE_BY_SERVICE", {"domain": 5000, "ntp": 500}):
            self.assertEqual(policy._udp_port_rate_limit(5353, "named"), 5000)
            self.assertEqual(policy._udp_port_rate_limit(53), 5000)
            self.assertEqual(policy._udp_port_rate_limit(123), 500)
            self.assertEqual(policy._udp_port_rate_limit(12345), 0)

    def test_syn_aggregate_uses_default_tiers(self):
        import auto_xdp.policy as policy
        with mock.patch.object(policy, "service_name", side_effect=lambda port, proto: "ssh" if port == 22 else "http"), \
             mock.patch.object(policy.cfg, "_SYN_RATE_BY_SERVICE", {"ssh": 2}), \
             mock.patch.object(policy.cfg, "_SYN_AGG_RATE_BY_SERVICE", {}), \
             mock.patch.object(policy.cfg, "_SYN_RATE_BY_PROC", {}), \
             mock.patch.object(policy.cfg, "_SYN_AGG_RATE_BY_PROC", {}):
            self.assertEqual(policy._syn_aggregate_rate_limit(22), cfg.XDP_DEFAULT_TCP_SYN_AGG_RATE_STRICT)
            self.assertEqual(policy._syn_aggregate_rate_limit(80), cfg.XDP_DEFAULT_TCP_SYN_AGG_RATE)

    def test_udp_aggregate_byte_limit_uses_explicit_or_derived_values(self):
        import auto_xdp.policy as policy
        def fake_service_name(port, proto):
            services = {53: "domain", 123: "ntp"}
            if port not in services:
                return ""
            return services[port]

        with mock.patch.object(policy, "service_name", side_effect=fake_service_name), \
             mock.patch.object(policy.cfg, "_UDP_RATE_BY_SERVICE", {"domain": 5000, "ntp": 500}), \
             mock.patch.object(policy.cfg, "_UDP_AGG_BYTES_BY_SERVICE", {"ntp": 900000}):
            self.assertEqual(policy._udp_aggregate_byte_limit(53), 6000000)
            self.assertEqual(policy._udp_aggregate_byte_limit(123), 900000)
            self.assertEqual(policy._udp_aggregate_byte_limit(9999), 0)

    def test_xdp_backend_apply_rate_map_delta_sets_rates_for_udp_ports(self):
        backend = backends_mod.XdpBackend.__new__(backends_mod.XdpBackend)
        backend.udp_rate_map = FakeUdpPortMap({53: 1000, 9999: 5})

        def fake_service_name(port, proto):
            services = {53: "domain", 123: "ntp"}
            if port not in services:
                return ""
            return services[port]

        with mock.patch.object(xdp_backend_mod, "service_name", side_effect=fake_service_name):
            backend._apply_rate_map_delta(
                backend.udp_rate_map,
                {53: 5000, 123: 500},
                {9999},
                dry_run=False,
                kind="udp",
            )

        self.assertCountEqual(
            backend.udp_rate_map.set_ops,
            [(53, 5000, False), (123, 500, False)],
        )
        self.assertEqual(backend.udp_rate_map.delete_ops, [(9999, False)])

    def test_xdp_backend_apply_rate_map_delta_sets_byte_limits_for_udp_ports(self):
        backend = backends_mod.XdpBackend.__new__(backends_mod.XdpBackend)
        backend.udp_agg_rate_map = FakeUdpPortMap({53: 1000, 9999: 5})

        backend._apply_rate_map_delta(
            backend.udp_agg_rate_map,
            {53: 6000000, 123: 900000},
            {9999},
            dry_run=False,
            kind="udp_agg",
        )

        self.assertCountEqual(
            backend.udp_agg_rate_map.set_ops,
            [(53, 6000000, False), (123, 900000, False)],
        )
        self.assertEqual(backend.udp_agg_rate_map.delete_ops, [(9999, False)])

    def test_xdp_backend_close_closes_all_maps(self):
        backend = backends_mod.XdpBackend.__new__(backends_mod.XdpBackend)
        backend.tcp_map = FakePortMap()
        backend.udp_map = FakePortMap()
        backend.sctp_map = FakePortMap()
        backend.trusted_map = FakeTrustedMap()
        backend._tcp_policy_map = None
        backend._udp_policy_map = None
        backend.syn_rate_map = FakeSynRateMap()
        backend.syn_agg_rate_map = FakeSynRateMap()
        backend.udp_rate_map = FakeUdpPortMap()
        backend.udp_agg_rate_map = FakeUdpPortMap()
        backend.acl_maps = None
        backend.runtime_config_map = FakeRuntimeConfigMap()
        backend.sit4_map = None
        backend.syn4_outer = FakeRateOuterMap()
        backend.syn6_outer = FakeRateOuterMap()
        backend.udprt4_outer = FakeRateOuterMap()
        backend.udprt6_outer = FakeRateOuterMap()
        backend.global_rl_map = FakeGlobalRlMap()
        backend._abuseipdb_syncer = None
        backend._risk_maps = None

        backend.close()

        self.assertTrue(backend.tcp_map.closed)
        self.assertTrue(backend.udp_map.closed)
        self.assertTrue(backend.sctp_map.closed)
        self.assertTrue(backend.trusted_map.closed)
        self.assertTrue(backend.syn4_outer.closed)
        self.assertTrue(backend.syn6_outer.closed)
        self.assertTrue(backend.udprt4_outer.closed)
        self.assertTrue(backend.udprt6_outer.closed)
        self.assertTrue(backend.runtime_config_map.closed)
        self.assertTrue(backend.global_rl_map.closed)


class TcpDefaultOnSmokeTests(unittest.TestCase):
    """End-to-end: default-on SYN protection reaches the plan layer."""

    def test_unconfigured_port_produces_plan_entries_for_syn_layers(self):
        observed = state_mod.ObservedState(
            tcp={8080},
            tcp_processes={8080: "myapp"},
        )
        desired = policy_mod._desired_state_for_ports(observed)

        # L1 SYN rate — Bug 1 fix
        self.assertEqual(desired.tcp_syn_rate_limits.get(8080), cfg.XDP_DEFAULT_TCP_SYN_RATE)
        # L2 SYN agg rate — Bug 1 fix
        self.assertEqual(desired.tcp_syn_agg_rate_limits.get(8080), cfg.XDP_DEFAULT_TCP_SYN_AGG_RATE)
        # Both stateless SYN layers must propagate into a fresh reconcile plan.
        applied = state_mod.AppliedState()
        plan = state_mod.compute_reconcile_plan(desired, applied)
        self.assertIn(8080, plan.tcp_syn_rate_limits_to_upsert)
        self.assertIn(8080, plan.tcp_syn_agg_rate_limits_to_upsert)


class RateMapEntriesPolicyTests(unittest.TestCase):
    """Per-port rate-limit inner map capacity resolution."""

    def test_nftables_keeps_minecraft_profile_port_closed(self):
        backend = backends_mod.NftablesBackend.__new__(backends_mod.NftablesBackend)
        backend._policy_signature = None
        desired = state_mod.DesiredState(
            tcp_ports={443, 25565},
            zone_tcp_ports={"public": {443, 25565}, "trusted": {25565}},
            tcp_protection_profiles={("public", 25565): "minecraft"},
        )

        with mock.patch.object(backend, "_install_ruleset") as install, \
             mock.patch.object(backend, "_remember_desired") as remember:
            backend.apply_reconcile_plan(
                state_mod.ReconcilePlan(),
                dry_run=False,
                desired_state=desired,
            )

        effective = install.call_args.args[0]
        self.assertEqual(effective.tcp_ports, {443})
        self.assertEqual(
            effective.zone_tcp_ports,
            {"public": {443}, "trusted": {25565}},
        )
        remember.assert_called_once_with(effective)

    def _resolve(self, **cfg_overrides):
        observed = state_mod.ObservedState(
            tcp={2222},
            udp={5353},
            tcp_processes={2222: "sshd"},
            udp_processes={5353: "avahi"},
        )
        base = dict(
            _SYN_RATE_BY_PROC={"sshd": 10},
            _SYN_RATE_BY_SERVICE={},
            _UDP_RATE_BY_PROC={"avahi": 50},
            _UDP_RATE_BY_SERVICE={},
            _RATE_MAP_ENTRIES_BY_PROC={},
            _RATE_MAP_ENTRIES_BY_SERVICE={},
        )
        base.update(cfg_overrides)
        with mock.patch.object(policy_mod, "service_name", return_value=""), \
             mock.patch.multiple(policy_mod.cfg, **base):
            return policy_mod._desired_state_for_ports(observed)

    def test_default_capacity_for_rate_limited_ports(self):
        desired = self._resolve()
        self.assertEqual(desired.tcp_rate_map_entries.get(2222),
                         cfg.RATE_MAP_ENTRIES_V4)
        self.assertEqual(desired.udp_rate_map_entries.get(5353),
                         cfg.RATE_MAP_ENTRIES_V4)

    def test_no_capacity_entry_when_rate_zero(self):
        desired = self._resolve(_SYN_RATE_BY_PROC={"sshd": 0},
                                _UDP_RATE_BY_PROC={})
        self.assertNotIn(2222, desired.tcp_rate_map_entries)
        self.assertNotIn(5353, desired.udp_rate_map_entries)

    def test_config_rejects_dynamic_inner_map_capacity(self):
        with self.assertRaisesRegex(ValueError, "fixed by the compiled XDP map ABI"):
            cfg.apply_toml_config({
                "rate_limits": {"map_entries_by_proc": {"sshd": 2048}},
            })

    def test_v6_derivation_helper(self):
        self.assertEqual(policy_mod.rate_map_entries_v6(16384), 4096)
        self.assertEqual(policy_mod.rate_map_entries_v6(100), 4096)

    def test_nftables_backend_ensure_ruleset_keeps_existing_complete_ruleset(self):
        backend = backends_mod.NftablesBackend.__new__(backends_mod.NftablesBackend)
        existing = subprocess.CompletedProcess(
            ["nft"],
            0,
            stdout=(
                "set policy_schema_v2\n"
                f"set {cfg.NFT_TCP_SET}\n"
                f"set {cfg.NFT_UDP_SET}\n"
                f"set {cfg.NFT_SCTP_SET}\n"
                f"set {cfg.NFT_TRUSTED_SET4}\n"
                "chain input\n"
            ),
        )

        with mock.patch.object(nftables_mod, "_run_nft", return_value=existing) as run_nft:
            backend._ensure_ruleset()

        run_nft.assert_called_once_with(["list", "table", cfg.NFT_FAMILY, cfg.NFT_TABLE], check=False)

    def test_nftables_backend_ensure_ruleset_recreates_incomplete_ruleset(self):
        backend = backends_mod.NftablesBackend.__new__(backends_mod.NftablesBackend)
        existing = subprocess.CompletedProcess(
            ["nft"],
            0,
            stdout=(
                "table inet auto_xdp {\n"
                "  set tcp_ports {\n    type inet_service\n    elements = { 22, 443 }\n  }\n"
                "  set udp_ports {\n    type inet_service\n    elements = { 53 }\n  }\n"
                "  set sctp_ports {\n    type inet_service\n    elements = { 3868 }\n  }\n"
                "  set trusted_v4 {\n    type ipv4_addr\n    elements = { 198.51.100.0/24 }\n  }\n"
                "  set trusted_v6 {\n    type ipv6_addr\n    elements = { 2001:db8::/64 }\n  }\n"
                "}\n"
            ),
        )
        created = subprocess.CompletedProcess(["nft"], 0, stdout="")

        with mock.patch.object(nftables_mod, "_run_nft", side_effect=[existing, created]) as run_nft:
            backend._ensure_ruleset()

        self.assertEqual(run_nft.call_count, 2)
        create_call = run_nft.call_args_list[1]
        self.assertEqual(create_call.args[0], ["-f", "-"])
        self.assertIn(f"delete table {cfg.NFT_FAMILY} {cfg.NFT_TABLE}", create_call.kwargs["input_text"])
        self.assertIn(f"set {cfg.NFT_TCP_SET}", create_call.kwargs["input_text"])
        self.assertIn("set policy_schema_v2", create_call.kwargs["input_text"])
        self.assertIn("elements = { 22, 443 }", create_call.kwargs["input_text"])
        self.assertIn("elements = { 53 }", create_call.kwargs["input_text"])
        self.assertIn("elements = { 3868 }", create_call.kwargs["input_text"])
        self.assertIn("elements = { 198.51.100.0/24 }", create_call.kwargs["input_text"])
        self.assertIn("elements = { 2001:db8::/64 }", create_call.kwargs["input_text"])

    def test_nftables_backend_refreshes_caches_from_existing_sets(self):
        backend = backends_mod.NftablesBackend.__new__(backends_mod.NftablesBackend)
        backend._tcp_cache = set()
        backend._udp_cache = set()
        backend._sctp_cache = set()
        backend._trusted_cache = set()

        with mock.patch.object(
            nftables_mod,
            "_run_nft",
            side_effect=[
                subprocess.CompletedProcess(["nft"], 0, stdout="elements = { 22, 443 }"),
                subprocess.CompletedProcess(["nft"], 0, stdout="elements = { 53 }"),
                subprocess.CompletedProcess(["nft"], 0, stdout="elements = { 3868 }"),
                subprocess.CompletedProcess(["nft"], 0, stdout="elements = { 198.51.100.0/24 }"),
                subprocess.CompletedProcess(["nft"], 0, stdout="elements = { 2001:db8::/64 }"),
            ],
        ):
            backend._refresh_caches()

        self.assertEqual(backend._tcp_cache, {22, 443})
        self.assertEqual(backend._udp_cache, {53})
        self.assertEqual(backend._sctp_cache, {3868})
        self.assertEqual(backend._trusted_cache, {"198.51.100.0/24", "2001:db8::/64"})

    def test_nftables_backend_apply_reconcile_plan_replaces_complete_policy_atomically(self):
        backend = backends_mod.NftablesBackend.__new__(backends_mod.NftablesBackend)
        backend._tcp_cache = {22, 80}
        backend._udp_cache = {53, 9999}
        backend._sctp_cache = {3868, 9899}
        backend._trusted_cache = {"203.0.113.1/32"}
        backend._reset_policy_cache()

        plan = state_mod.ReconcilePlan(
            tcp_ports_to_add={443},
            tcp_ports_to_remove={80},
            udp_ports_to_remove={9999},
            sctp_ports_to_add={2905},
            sctp_ports_to_remove={9899},
            trusted_cidrs_to_add={"198.51.100.5/32"},
            trusted_cidrs_to_remove={"203.0.113.1/32"},
        )

        desired = state_mod.DesiredState(
            tcp_ports={22, 443},
            udp_ports={53},
            sctp_ports={2905, 3868},
            trusted_cidrs={"198.51.100.5/32"},
            tcp_syn_rate_limits={22: 5, 443: 100},
            tcp_syn_agg_rate_limits={22: 50, 443: 1000},
            udp_rate_limits={53: 100},
            udp_agg_rate_limits={53: 120000},
            acl_rules={("tcp", "203.0.113.0/24"): frozenset({8443})},
            bogon_filter_enabled=True,
            rate_limit_source_prefix_v4=24,
            rate_limit_source_prefix_v6=64,
            udp_global_byte_rate=1_000_000,
        )

        completed = subprocess.CompletedProcess(["nft"], 0)
        with mock.patch.object(nftables_mod, "_run_nft", return_value=completed) as run_nft:
            backend.apply_reconcile_plan(
                plan,
                dry_run=False,
                desired_state=desired,
            )

        run_nft.assert_called_once()
        script = run_nft.call_args.kwargs["input_text"]
        self.assertIn("delete table inet auto_xdp\ntable inet auto_xdp", script)
        self.assertIn("elements = { 22, 443 }", script)
        self.assertIn("ip saddr @bogon_v4 counter drop", script)
        self.assertIn("ip saddr 203.0.113.0/24 tcp flags", script)
        self.assertIn("meter ts4_22", script)
        self.assertIn("meter tp4_443", script)
        self.assertIn("limit rate over 1000000 bytes/second", script)
        self.assertNotIn("udp sport { 53, 67, 123, 443, 547 } accept", script)
        self.assertNotIn("tcp flags & (ack | rst | fin) != 0 accept", script)
        self.assertEqual(backend._tcp_cache, {22, 443})
        self.assertEqual(backend._policy_signature, nftables_mod._policy_signature(desired))

    def test_nftables_backend_dry_run_does_not_mutate_caches(self):
        backend = backends_mod.NftablesBackend.__new__(backends_mod.NftablesBackend)
        backend._tcp_cache = {22, 80}
        backend._udp_cache = {53, 9999}
        backend._sctp_cache = {3868, 9899}
        backend._trusted_cache = {"203.0.113.1/32"}
        backend._reset_policy_cache()

        plan = state_mod.ReconcilePlan(
            tcp_ports_to_add={443},
            tcp_ports_to_remove={80},
            udp_ports_to_remove={9999},
            sctp_ports_to_add={2905},
            sctp_ports_to_remove={9899},
            trusted_cidrs_to_add={"198.51.100.5/32"},
            trusted_cidrs_to_remove={"203.0.113.1/32"},
        )

        with mock.patch.object(nftables_mod, "_run_nft"):
            backend.apply_reconcile_plan(plan, dry_run=True, desired_state=state_mod.DesiredState())

        self.assertEqual(backend._tcp_cache, {22, 80})
        self.assertEqual(backend._udp_cache, {53, 9999})
        self.assertEqual(backend._sctp_cache, {3868, 9899})
        self.assertEqual(backend._trusted_cache, {"203.0.113.1/32"})
        self.assertIsNone(backend._policy_signature)

    def test_nftables_backend_skips_identical_policy_transaction(self):
        backend = backends_mod.NftablesBackend.__new__(backends_mod.NftablesBackend)
        backend._tcp_cache = set()
        backend._udp_cache = set()
        backend._sctp_cache = set()
        backend._trusted_cache = set()
        backend._reset_policy_cache()
        desired = state_mod.DesiredState(tcp_ports={443})
        backend._remember_desired(desired)

        with mock.patch.object(nftables_mod, "_run_nft") as run_nft:
            backend.apply_reconcile_plan(
                state_mod.ReconcilePlan(),
                dry_run=False,
                desired_state=desired,
            )

        run_nft.assert_not_called()

    def test_open_backend_validates_requested_backend(self):
        status = backends_mod.BackendStatus(
            "xdp",
            False,
            "required XDP maps missing",
            {"missing_maps": "/sys/fs/bpf/xdp_fw/tcp_whitelist"},
            {"bpftool": True, "required_maps": False},
        )
        with mock.patch.object(backends_mod.XdpBackend, "probe", return_value=status):
            with self.assertRaisesRegex(RuntimeError, "failed checks: required_maps"):
                syncer_mod.open_backend(syncer_mod.BACKEND_XDP)

        with self.assertRaisesRegex(RuntimeError, "Unsupported backend"):
            syncer_mod.open_backend("invalid")

    def test_open_backend_prefers_xdp_and_falls_back_to_nftables(self):
        with mock.patch.object(syncer_mod, "XdpBackend") as xdp_backend:
            xdp_backend.probe.return_value = backends_mod.BackendStatus("xdp", True)
            xdp_backend.return_value = "xdp-backend"
            backend = syncer_mod.open_backend(syncer_mod.BACKEND_AUTO)
        self.assertEqual(backend, "xdp-backend")
        xdp_backend.assert_called_once_with()

        with mock.patch.object(syncer_mod, "XdpBackend") as xdp_backend, \
             mock.patch.object(syncer_mod, "NftablesBackend") as nft_backend:
            xdp_backend.probe.return_value = backends_mod.BackendStatus("xdp", False, "required XDP maps missing")
            nft_backend.probe.return_value = backends_mod.BackendStatus("nftables", True)
            nft_backend.return_value = "nft-backend"
            backend = syncer_mod.open_backend(syncer_mod.BACKEND_AUTO)
        self.assertEqual(backend, "nft-backend")
        nft_backend.assert_called_once_with()

    def test_xdp_probe_checks_runtime_prerequisites(self):
        with mock.patch.object(xdp_backend_mod.shutil, "which", return_value=None):
            status = xdp_backend_mod.XdpBackend.probe()
        self.assertFalse(status.available)
        self.assertEqual(status.reason, "bpftool not found")
        self.assertEqual(status.failed_checks, ["bpftool"])
        self.assertEqual(status.details["bpftool"], "not found")

        with mock.patch.object(xdp_backend_mod.shutil, "which", return_value="/usr/sbin/bpftool"), \
             mock.patch.object(xdp_backend_mod.os.path, "exists", return_value=False):
            status = xdp_backend_mod.XdpBackend.probe()
        self.assertFalse(status.available)
        self.assertEqual(status.reason, "required XDP maps missing")
        self.assertEqual(status.failed_checks, ["required_maps"])
        self.assertIn(cfg.TCP_MAP_PATH, status.details["missing_maps"])

        def fake_exists(path):
            return path in cfg.REQUIRED_XDP_MAP_PATHS

        with mock.patch.object(xdp_backend_mod.shutil, "which", return_value="/usr/sbin/bpftool"), \
             mock.patch.object(xdp_backend_mod.os.path, "exists", side_effect=fake_exists), \
             mock.patch.object(cfg, "XDP_OBJ_PATH", "/tmp/xdp_firewall.o"):
            status = xdp_backend_mod.XdpBackend.probe()
        self.assertFalse(status.available)
        self.assertEqual(status.reason, "configured XDP object file missing")
        self.assertEqual(status.failed_checks, ["xdp_obj"])
        self.assertEqual(status.details["xdp_obj_path"], "/tmp/xdp_firewall.o")

    def test_backend_status_formats_reason_checks_and_details(self):
        status = backends_mod.BackendStatus(
            "xdp",
            False,
            "required XDP maps missing",
            {"missing_maps": "/sys/fs/bpf/xdp_fw/tcp_whitelist"},
            {"bpftool": True, "required_maps": False},
        )

        self.assertEqual(
            status.format_message(),
            "required XDP maps missing; failed checks: required_maps; "
            "missing_maps=/sys/fs/bpf/xdp_fw/tcp_whitelist",
        )

    def test_drain_proc_events_detects_exec_and_exit_notifications(self):
        payload = make_proc_event_message(proc_events_mod._PROC_EVENT_EXEC)

        class FakeSocket:
            def recv(self, size):
                return payload

        fake_sock = FakeSocket()
        with mock.patch.object(proc_events_mod.select, "select", side_effect=[([fake_sock], [], []), ([], [], [])]):
            triggered = proc_events_mod.drain_proc_events(fake_sock)

        self.assertTrue(triggered)

    def test_main_runs_one_sync_and_closes_backend(self):
        backend = mock.MagicMock()
        backend.__enter__.return_value = backend
        backend.__exit__.side_effect = lambda *args: backend.close()
        trusted_ips = {}

        with mock.patch.object(sys, "argv", [
            "xdp_port_sync.py",
            "--backend",
            "nftables",
            "--trusted-ip",
            "198.51.100.8",
            "office",
            "--log-level",
            "debug",
        ]), mock.patch.object(cfg, "TRUSTED_SRC_IPS", trusted_ips), \
             mock.patch.object(cli_mod, "open_backend", return_value=backend) as open_backend, \
             mock.patch.object(cli_mod, "sync_once") as sync_once:
            cli_mod.main()

        open_backend.assert_called_once_with("nftables")
        sync_once.assert_called_once_with(backend, False)
        backend.close.assert_called_once_with()
        self.assertEqual(trusted_ips, {"198.51.100.8/32": "office"})

    def test_main_watch_mode_delegates_to_watch(self):
        with mock.patch.object(sys, "argv", [
            "xdp_port_sync.py",
            "--watch",
            "--dry-run",
            "--backend",
            "auto",
        ]), mock.patch.object(cli_mod, "watch") as watch:
            cli_mod.main()

        watch.assert_called_once_with(
            True, "auto", cfg.TOML_CONFIG_PATH, {}, cli_log_level=None
        )

    def test_main_uses_configured_preferred_backend_as_default(self):
        backend = mock.MagicMock()
        backend.__enter__.return_value = backend
        with mock.patch.object(sys, "argv", [
            "xdp_port_sync.py",
            "--config",
            "/tmp/test.toml",
        ]), mock.patch.object(
            cli_mod,
            "load_toml_config",
            return_value={"daemon": {"preferred_backend": "nftables"}},
        ), mock.patch.object(cli_mod, "open_backend", return_value=backend) as open_backend, \
             mock.patch.object(cli_mod, "sync_once") as sync_once:
            old_backend = cfg.PREFERRED_BACKEND
            try:
                cli_mod.main()
            finally:
                cfg.PREFERRED_BACKEND = old_backend

        open_backend.assert_called_once_with("nftables")
        sync_once.assert_called_once_with(backend, False)

    def test_main_watch_mode_passes_custom_config_to_watch(self):
        with mock.patch.object(sys, "argv", [
            "xdp_port_sync.py",
            "--watch",
            "--config",
            "/tmp/test.toml",
        ]), mock.patch.object(cli_mod, "watch") as watch:
            cli_mod.main()

        watch.assert_called_once_with(
            mock.ANY, mock.ANY, "/tmp/test.toml", {},
            cli_log_level=None,
        )

    def test_main_watch_mode_passes_cli_trusted_ips_to_watch(self):
        with mock.patch.object(sys, "argv", [
            "xdp_port_sync.py",
            "--watch",
            "--trusted-ip", "1.2.3.4", "myhost",
            "--trusted-ip", "10.0.0.0/8", "internal",
        ]), mock.patch.object(cli_mod, "watch") as watch:
            cli_mod.main()

        watch.assert_called_once_with(
            mock.ANY, mock.ANY, mock.ANY,
            {"1.2.3.4/32": "myhost", "10.0.0.0/8": "internal"},
            cli_log_level=None,
        )


class FailingPortMap(FakePortMap):
    def set(self, port, val, dry_run=False):
        super().set(port, val, dry_run)
        return dry_run  # real maps short-circuit True on dry-run; fail otherwise


class FailingTrustedMap(FakeTrustedMap):
    def set(self, key, val, dry_run=False):
        super().set(key, val, dry_run)
        return dry_run

    def delete(self, key, dry_run=False):
        super().delete(key, dry_run)
        return dry_run


class FailingSynRateMap(FakeSynRateMap):
    def set(self, port, rate_max, dry_run=False):
        super().set(port, rate_max, dry_run)
        return dry_run

    def delete(self, port, dry_run=False):
        super().delete(port, dry_run)
        return dry_run


class FailingRuntimeConfigMap(FakeRuntimeConfigMap):
    def set(self, fields, cfg_flags=0, dry_run=False):
        super().set(fields, cfg_flags, dry_run)
        return dry_run


class FailingGlobalRlMap(FakeGlobalRlMap):
    def set(self, byte_rate_max, dry_run=False):
        super().set(byte_rate_max, dry_run)
        return dry_run


class FailingAclMaps:
    def __init__(self):
        self._active = {}
        self.set_ops = []
        self.delete_ops = []

    def active_entries(self):
        return dict(self._active)

    def set(self, proto, cidr, ports, dry_run=False):
        self.set_ops.append((proto, cidr, tuple(ports), dry_run))
        self._active[(proto, cidr)] = frozenset(ports)
        return dry_run

    def delete(self, proto, cidr, dry_run=False):
        self.delete_ops.append((proto, cidr, dry_run))
        self._active.pop((proto, cidr), None)
        return dry_run

    def close(self):
        pass


class FailingSit4Map:
    def __init__(self, active=None):
        self._active = set(active or [])
        self.set_ops = []
        self.delete_ops = []

    def active_keys(self):
        return set(self._active)

    def set(self, ip_str, dry_run=False):
        self.set_ops.append((ip_str, dry_run))
        self._active.add(ip_str)
        return dry_run

    def delete(self, ip_str, dry_run=False):
        self.delete_ops.append((ip_str, dry_run))
        self._active.discard(ip_str)
        return dry_run

    def close(self):
        pass


class FailingRateOuterMap(FakeRateOuterMap):
    def set(self, port, capacity, dry_run=False):
        self.ops.append(("set", port, capacity, dry_run))
        self._active[port] = capacity
        return dry_run

    def delete(self, port, dry_run=False):
        self.ops.append(("delete", port, dry_run))
        self._active.pop(port, None)
        return dry_run


def _make_failing_backend():
    backend = backends_mod.XdpBackend.__new__(backends_mod.XdpBackend)
    backend.tcp_map = FailingPortMap({22, 80})
    backend.udp_map = FailingPortMap({53, 9999})
    backend.sctp_map = FailingPortMap({3868, 9899})
    backend.trusted_map = FailingTrustedMap({"203.0.113.1/32"})
    backend.syn_rate_map = FailingSynRateMap()
    backend.syn_agg_rate_map = FailingSynRateMap()
    backend.udp_rate_map = FailingSynRateMap()
    backend.udp_agg_rate_map = FailingSynRateMap()
    backend.acl_maps = FailingAclMaps()
    backend.runtime_config_map = FailingRuntimeConfigMap()
    backend.global_rl_map = FailingGlobalRlMap()
    backend.sit4_map = FailingSit4Map({"192.0.2.9"})
    backend.syn4_outer = FailingRateOuterMap()
    backend.syn6_outer = FailingRateOuterMap()
    backend.udprt4_outer = FailingRateOuterMap()
    backend.udprt6_outer = FailingRateOuterMap()
    backend._tcp_policy_map = None
    backend._udp_policy_map = None
    return backend


def _failing_desired_state():
    return state_mod.DesiredState(
        tcp_ports={22, 443},
        udp_ports={53},
        sctp_ports={3868, 2905},
        trusted_cidrs={"198.51.100.5/32"},
        tcp_syn_rate_limits={22: 2},
        tcp_syn_agg_rate_limits={22: 16},
        udp_rate_limits={53: 5000},
        udp_agg_rate_limits={53: 6000000},
        tcp_rate_map_entries={22: 16384},
        udp_rate_map_entries={53: 16384},
        acl_rules={("tcp", "203.0.113.0/24"): frozenset({22, 443})},
        udp_global_byte_rate=124_625_000,
        xdp_runtime_config=(1, 2, 3, 4, 5, 6, 7),
    )


@pytest.mark.component
class ApplyFailureCountingTests(unittest.TestCase):
    def _reconcile(self, backend, dry_run):
        desired = _failing_desired_state()
        with mock.patch.object(cfg, "TRUSTED_SRC_IPS", {}), \
             mock.patch.object(cfg, "SIT4_ENDPOINTS", ["198.51.100.77"]):
            backend.reconcile(desired, dry_run=dry_run, observed_state=state_mod.ObservedState())

    def _total_ops(self, backend):
        return (
            len(backend.tcp_map.ops)
            + len(backend.udp_map.ops)
            + len(backend.sctp_map.ops)
            + len(backend.trusted_map.set_ops)
            + len(backend.trusted_map.delete_ops)
            + sum(
                len(m.set_ops) + len(m.delete_ops)
                for m in (
                    backend.syn_rate_map,
                    backend.syn_agg_rate_map,
                    backend.udp_rate_map,
                    backend.udp_agg_rate_map,
                )
            )
            + len(backend.runtime_config_map.ops)
            + len(backend.global_rl_map.ops)
            + len(backend.acl_maps.set_ops)
            + len(backend.acl_maps.delete_ops)
            + len(backend.sit4_map.set_ops)
            + len(backend.sit4_map.delete_ops)
            + sum(
                len(o.ops)
                for o in (
                    backend.syn4_outer,
                    backend.syn6_outer,
                    backend.udprt4_outer,
                    backend.udprt6_outer,
                )
            )
        )

    def test_counts_every_failed_map_update_and_warns(self):
        backend = _make_failing_backend()
        with self.assertLogs("auto_xdp.backends.xdp", level="WARNING") as logs:
            self._reconcile(backend, dry_run=False)

        total = self._total_ops(backend)
        self.assertEqual(backend.last_apply_failures, total)
        # Every operation class must have been exercised, so a missing _ok()
        # wrapper in any of them would make the count diverge.
        self.assertTrue(backend.tcp_map.ops)
        self.assertTrue(backend.udp_map.ops)
        self.assertTrue(backend.sctp_map.ops)
        self.assertTrue(backend.trusted_map.set_ops)
        self.assertTrue(backend.trusted_map.delete_ops)
        self.assertTrue(backend.syn_rate_map.set_ops)
        self.assertTrue(backend.udp_rate_map.set_ops)
        self.assertTrue(backend.runtime_config_map.ops)
        self.assertTrue(backend.global_rl_map.ops)
        self.assertTrue(backend.acl_maps.set_ops)
        self.assertTrue(backend.sit4_map.set_ops)
        self.assertTrue(backend.sit4_map.delete_ops)
        self.assertTrue(backend.syn4_outer.ops)
        self.assertTrue(backend.syn6_outer.ops)
        self.assertTrue(backend.udprt4_outer.ops)
        self.assertTrue(backend.udprt6_outer.ops)
        self.assertTrue(
            any("failed this reconcile" in line for line in logs.output),
            logs.output,
        )

    def test_dry_run_counts_no_failures(self):
        backend = _make_failing_backend()
        self._reconcile(backend, dry_run=True)
        self.assertEqual(backend.last_apply_failures, 0)

    def test_counter_resets_on_clean_round(self):
        backend = _make_failing_backend()
        self._reconcile(backend, dry_run=False)
        self.assertGreater(backend.last_apply_failures, 0)
        # Fakes updated their local state despite returning False, so the next
        # round has nothing to apply and the counter must reset to zero.
        backend.tcp_map.set = lambda port, val, dry_run=False: FakePortMap.set(
            backend.tcp_map, port, val, dry_run
        )
        self._reconcile(backend, dry_run=False)
        self.assertEqual(backend.last_apply_failures, 0)


def _make_outer_backend():
    backend = backends_mod.XdpBackend.__new__(backends_mod.XdpBackend)
    backend.tcp_map = FakePortMap()
    backend.udp_map = FakePortMap()
    backend.sctp_map = FakePortMap()
    backend.trusted_map = FakeTrustedMap()
    backend.syn_rate_map = None
    backend.syn_agg_rate_map = None
    backend.udp_rate_map = None
    backend.udp_agg_rate_map = None
    backend.acl_maps = None
    backend.sit4_map = None
    backend.runtime_config_map = None
    backend.global_rl_map = None
    backend.syn4_outer = FakeRateOuterMap()
    backend.syn6_outer = FakeRateOuterMap()
    backend.udprt4_outer = FakeRateOuterMap()
    backend.udprt6_outer = FakeRateOuterMap()
    backend._tcp_policy_map = None
    backend._udp_policy_map = None
    return backend


@pytest.mark.component
class RateOuterReconcileTests(unittest.TestCase):
    def _reconcile(self, backend, desired, dry_run=False):
        with mock.patch.object(cfg, "TRUSTED_SRC_IPS", {}):
            backend.reconcile(desired, dry_run=dry_run, observed_state=state_mod.ObservedState())

    def test_reconcile_creates_inner_for_rate_limited_ports(self):
        backend = _make_outer_backend()
        desired = state_mod.DesiredState(
            tcp_ports={443},
            udp_ports={5353},
            tcp_syn_rate_limits={443: 100},
            tcp_rate_map_entries={443: 16384},
            udp_rate_limits={5353: 50},
            udp_rate_map_entries={5353: 16384},
        )
        self._reconcile(backend, desired)
        self.assertEqual(backend.syn4_outer.active(), {443: 16384})
        self.assertEqual(backend.syn6_outer.active(), {443: 4096})
        self.assertEqual(backend.udprt4_outer.active(), {5353: 16384})
        self.assertEqual(backend.udprt6_outer.active(), {5353: 4096})

    def test_reconcile_removes_stale_inner(self):
        backend = _make_outer_backend()
        for outer in (backend.syn4_outer, backend.syn6_outer,
                      backend.udprt4_outer, backend.udprt6_outer):
            outer._active = {22: 16384}
        self._reconcile(backend, state_mod.DesiredState())
        for outer in (backend.syn4_outer, backend.syn6_outer,
                      backend.udprt4_outer, backend.udprt6_outer):
            self.assertIn(("delete", 22, False), outer.ops)
            self.assertEqual(outer.active(), {})


@pytest.mark.component
class ProbeInnerMapSupportTests(unittest.TestCase):
    def test_probe_unavailable_without_inner_map_support(self):
        with mock.patch.object(xdp_backend_mod.shutil, "which", return_value="/usr/sbin/bpftool"), \
             mock.patch.object(cfg, "REQUIRED_XDP_MAP_PATHS", ()), \
             mock.patch.object(cfg, "XDP_OBJ_PATH", ""), \
             mock.patch.object(xdp_backend_mod, "probe_inner_map_support", return_value=False):
            status = backends_mod.XdpBackend.probe()
        self.assertFalse(status.available)
        self.assertIn("5.10", status.reason)


@pytest.mark.component
class VerifyKernelStateTests(unittest.TestCase):
    def _backend_with_verifiers(self, values):
        backend = backends_mod.XdpBackend.__new__(backends_mod.XdpBackend)
        backend.tcp_map = types.SimpleNamespace(verify=lambda: values.get("tcp", 0))
        backend.udp_map = types.SimpleNamespace(verify=lambda: values.get("udp", 0))
        backend.sctp_map = None
        backend.trusted_map = types.SimpleNamespace(verify=lambda: values.get("trusted", 0))
        backend._tcp_policy_map = types.SimpleNamespace(verify=lambda: values.get("tcp_policy", 0))
        backend._udp_policy_map = None
        backend.acl_maps = types.SimpleNamespace(verify=lambda: values.get("acl", 0))
        backend.sit4_map = None
        backend.syn4_outer = types.SimpleNamespace(verify=lambda: values.get("syn4", 0))
        backend.syn6_outer = types.SimpleNamespace(verify=lambda: values.get("syn6", 0))
        backend.udprt4_outer = None
        backend.udprt6_outer = types.SimpleNamespace(verify=lambda: values.get("udprt6", 0))
        return backend

    def test_sums_discrepancies_and_warns(self):
        backend = self._backend_with_verifiers(
            {"tcp": 2, "udp": 0, "trusted": 1, "tcp_policy": 3, "acl": 1,
             "syn4": 1, "udprt6": 2}
        )
        with self.assertLogs("auto_xdp.backends.xdp", level="WARNING") as logs:
            total = backend.verify_kernel_state()
        self.assertEqual(total, 10)
        self.assertTrue(any("drifted" in line for line in logs.output), logs.output)

    def test_zero_drift_is_silent_and_skips_missing_maps(self):
        backend = self._backend_with_verifiers({})
        with mock.patch.object(xdp_backend_mod.log, "warning") as warn:
            self.assertEqual(backend.verify_kernel_state(), 0)
        warn.assert_not_called()


@pytest.mark.component
class MapVerifyTests(unittest.TestCase):
    def _make_map(self, cache):
        m = object.__new__(bpf_maps_mod.BpfSynRatePortsMap)
        m.path = "/sys/fs/bpf/xdp_fw/tcp_syn_rate_ports"
        m._cache = dict(cache)
        return m

    def test_verify_returns_zero_when_kernel_matches_cache(self):
        m = self._make_map({22: 2, 80: 5})
        m._read_kernel = lambda: {22: 2, 80: 5}
        self.assertEqual(m.verify(), 0)
        self.assertEqual(m._cache, {22: 2, 80: 5})

    def test_verify_counts_drift_and_repairs_cache(self):
        m = self._make_map({22: 2, 80: 5})
        # 22 changed value, 80 missing from kernel, 443 extra in kernel: 3 diffs.
        m._read_kernel = lambda: {22: 9, 443: 1}
        with self.assertLogs("auto_xdp.bpf.maps", level="WARNING") as logs:
            self.assertEqual(m.verify(), 3)
        self.assertEqual(m._cache, {22: 9, 443: 1})
        self.assertTrue(any("drift" in line for line in logs.output), logs.output)


@pytest.mark.component
class SyncerVerifyTriggerTests(unittest.TestCase):
    def _run_watch(self, backend, select_effects):
        nl = mock.MagicMock()
        with mock.patch.object(syncer_mod, "open_backend", return_value=backend), \
             mock.patch.object(syncer_mod, "open_proc_connector", return_value=nl), \
             mock.patch.object(syncer_mod, "_open_relay_client", return_value=None), \
             mock.patch.object(syncer_mod, "drain_proc_events", return_value=True), \
             mock.patch.object(syncer_mod, "sync_once") as sync_once, \
             mock.patch.object(syncer_mod.select, "select", side_effect=select_effects), \
             mock.patch.object(cfg, "DEBOUNCE_SECONDS", 0.0):
            syncer_mod.watch(
                dry_run=False,
                backend_name="xdp",
                monotonic=lambda: 100.0,
                mode="enforce",
            )
        return sync_once

    def test_failed_apply_triggers_verify_and_corrective_sync(self):
        backend = mock.MagicMock()
        backend.last_apply_failures = 3
        backend.is_stale.return_value = False
        backend.verify_kernel_state.return_value = 0

        sync_once = self._run_watch(
            backend,
            [([mock.ANY], [], []), ([], [], []), KeyboardInterrupt()],
        )

        # init sync + event sync + debounce-armed corrective sync
        self.assertEqual(sync_once.call_count, 3)
        self.assertTrue(backend.verify_kernel_state.called)

    def test_periodic_stale_check_verifies_kernel_state(self):
        backend = mock.MagicMock()
        backend.last_apply_failures = 0
        backend.is_stale.return_value = False
        backend.verify_kernel_state.return_value = 0

        nl = mock.MagicMock()
        with mock.patch.object(syncer_mod, "open_backend", return_value=backend), \
             mock.patch.object(syncer_mod, "open_proc_connector", return_value=nl), \
             mock.patch.object(syncer_mod, "_open_relay_client", return_value=None), \
             mock.patch.object(syncer_mod, "drain_proc_events", return_value=True), \
             mock.patch.object(syncer_mod, "sync_once"), \
             mock.patch.object(
                 syncer_mod.select,
                 "select",
                 side_effect=[([], [], []), KeyboardInterrupt()],
             ), \
             mock.patch.object(cfg, "DEBOUNCE_SECONDS", 0.0):
            syncer_mod.watch(
                dry_run=False,
                backend_name="xdp",
                monotonic=lambda: 100.0,
                mode="enforce",
            )

        backend.is_stale.assert_called_once()
        backend.verify_kernel_state.assert_called_once()

    def test_netlink_unavailable_does_not_block_relay_sync(self):
        backend = mock.MagicMock()
        backend.last_apply_failures = 0
        backend.is_stale.return_value = False
        backend.verify_kernel_state.return_value = 0
        relay = mock.MagicMock()

        with mock.patch.object(syncer_mod, "open_backend", return_value=backend), \
             mock.patch.object(syncer_mod, "open_proc_connector", return_value=None), \
             mock.patch.object(syncer_mod, "_open_relay_client", return_value=relay) as open_relay, \
             mock.patch.object(syncer_mod, "_drain_relay_lines", return_value=True), \
             mock.patch.object(syncer_mod, "sync_once") as sync_once, \
             mock.patch.object(
                 syncer_mod.select,
                 "select",
                 side_effect=[([relay], [], []), KeyboardInterrupt()],
             ):
            syncer_mod.watch(dry_run=False, backend_name="xdp", mode="enforce")

        open_relay.assert_called()
        # Initial reconcile plus the relay-triggered reconcile.
        self.assertEqual(sync_once.call_count, 2)

    def test_periodic_reconcile_runs_without_event_sources(self):
        backend = mock.MagicMock()
        backend.last_apply_failures = 0
        backend.is_stale.return_value = False
        backend.verify_kernel_state.return_value = 0

        with mock.patch.object(syncer_mod, "open_backend", return_value=backend), \
             mock.patch.object(syncer_mod, "open_proc_connector", return_value=None), \
             mock.patch.object(syncer_mod, "_open_relay_client", return_value=None), \
             mock.patch.object(syncer_mod, "sync_once") as sync_once, \
             mock.patch.object(syncer_mod.time, "sleep", side_effect=[None, KeyboardInterrupt()]), \
             mock.patch.object(syncer_mod, "FULL_RECONCILE_INTERVAL_SECONDS", 0.0):
            syncer_mod.watch(dry_run=False, backend_name="xdp", mode="enforce")

        # Initial reconcile plus a timer-triggered full reconcile.
        self.assertEqual(sync_once.call_count, 2)

    def test_discovery_error_keeps_existing_policy_and_backend(self):
        backend = mock.MagicMock()
        backend.last_apply_failures = 0
        backend.is_stale.return_value = False
        backend.verify_kernel_state.return_value = 0
        with mock.patch.object(syncer_mod, "open_backend", return_value=backend), \
             mock.patch.object(syncer_mod, "open_proc_connector", return_value=None), \
             mock.patch.object(syncer_mod, "_open_relay_client", return_value=None), \
             mock.patch.object(
                 syncer_mod,
                 "sync_once",
                 side_effect=[None, DiscoveryError("truncated dump"), KeyboardInterrupt()],
             ), \
             mock.patch.object(syncer_mod.time, "sleep", return_value=None), \
             mock.patch.object(syncer_mod, "FULL_RECONCILE_INTERVAL_SECONDS", 0.0):
            with self.assertLogs("auto_xdp.syncer", level="ERROR") as logs:
                syncer_mod.watch(dry_run=False, backend_name="xdp", mode="enforce")
        # Discovery failures must not tear down a working backend mid-loop.
        # The only close() is the shutdown path in watch()'s finally block.
        self.assertEqual(backend.close.call_count, 1)
        self.assertTrue(any("keeping existing policy" in line for line in logs.output), logs.output)


@pytest.mark.component
class ConfigReloadTests(unittest.TestCase):
    def test_invalid_sighup_config_keeps_last_known_good_state(self):
        cfg.apply_toml_config({"policy": {"mode": "audit"}})
        with tempfile.NamedTemporaryFile(mode="wb") as config_file:
            config_file.write(b"[daemon\n")
            config_file.flush()
            with self.assertLogs("auto_xdp.syncer", level="ERROR") as logs:
                self.assertFalse(syncer_mod._reload_config(config_file.name))
        self.assertEqual(cfg.POLICY_MODE, "audit")
        self.assertTrue(any("retaining previous" in line for line in logs.output))


if __name__ == "__main__":
    unittest.main(verbosity=2)
