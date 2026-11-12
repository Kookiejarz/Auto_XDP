import tempfile
import unittest
import subprocess
from pathlib import Path
from unittest import mock

import pytest

from auto_xdp import install_state


pytestmark = pytest.mark.component


def _link(name, *, kind="ether", flags=("BROADCAST", "UP"), operstate="UP"):
    value = {"ifname": name, "flags": list(flags), "operstate": operstate}
    if kind:
        value["linkinfo"] = {"info_kind": kind}
    return value


class InstallStateTests(unittest.TestCase):
    def test_auto_selection_excludes_loopback_and_container_plumbing(self):
        selected, excluded = install_state.select_interfaces(
            [
                _link("lo", kind="loopback", flags=("LOOPBACK", "UP")),
                _link("eth0"),
                _link("ens6"),
                _link("docker0", kind="bridge"),
                _link("veth42", kind="veth"),
                _link("cni0", kind="bridge"),
                _link("br-public", kind="bridge"),
                _link("bond0", kind="bond"),
            ]
        )

        self.assertEqual(selected, ["bond0", "br-public", "cni0", "docker0", "ens6", "eth0"])
        self.assertEqual(excluded["lo"], "loopback")
        self.assertEqual(excluded["veth42"], "virtual veth")

    def test_names_never_override_kernel_types(self):
        selected, excluded = install_state.select_interfaces([
            _link("uplink", kind="veth"), _link("wan", kind="dummy"),
            _link("docker0"), _link("veth42", kind="bond"),
            _link("cni0", kind="vlan"), _link("cali-uplink", kind=""),
            _link("unknown-device", kind="future-driver"),
        ])
        self.assertEqual(selected, ["cali-uplink", "cni0", "docker0", "unknown-device", "veth42"])
        self.assertEqual(excluded, {"uplink": "virtual veth", "wan": "virtual dummy"})

    def test_tun_tap_and_wireguard_are_classified_by_packet_format(self):
        tun = _link("sample-a", kind="tun")
        tun["linkinfo"]["info_data"] = {"type": "tun"}
        tap = _link("sample-b", kind="tun")
        tap["linkinfo"]["info_data"] = {"type": "tap"}
        wg = _link("sample-c", kind="wireguard")
        selected, excluded = install_state.select_interfaces([tun, tap, wg])
        self.assertEqual(selected, ["sample-b"])
        self.assertEqual(set(excluded), {"sample-a", "sample-c"})
        self.assertEqual(install_state.interface_details(tap)["kind"], "tap")
        for link in (tun, wg):
            with self.assertRaisesRegex(ValueError, "requires Ethernet"):
                install_state.select_interfaces([link], explicit=[link["ifname"]], allow_container=True)
        layer3_netkit = _link("netkit-l3", kind="netkit")
        layer3_netkit["link_type"] = "none"
        with self.assertRaisesRegex(ValueError, "requires Ethernet"):
            install_state.select_interfaces([layer3_netkit], explicit=["netkit-l3"], allow_container=True)

    def test_kernel_device_metadata_does_not_claim_physical_or_trusted(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            device = root / "sample" / "device"
            device.mkdir(parents=True)
            (device / "driver").symlink_to("/sys/bus/pci/drivers/ixgbe")
            (device / "subsystem").symlink_to("/sys/bus/pci")
            details = install_state.interface_details(
                {"ifname": "sample", "link_type": "ether", "parentdev": "0000:01:00.0"},
                sys_class_net=root,
            )
            self.assertEqual(details, {"kind": "ether", "link_type": "ether",
                                      "parentdev": "0000:01:00.0", "driver": "ixgbe", "bus": "pci"})

    def test_failed_or_malformed_enumeration_is_not_an_empty_inventory(self):
        cases = [
            subprocess.CompletedProcess([], 1, "", "permission denied"),
            subprocess.CompletedProcess([], 0, "not json", ""),
            subprocess.CompletedProcess([], 0, '{}', ""),
            subprocess.CompletedProcess([], 0, '[{"ifindex":1}]', ""),
        ]
        for result in cases:
            with self.subTest(result=result), mock.patch.object(install_state.subprocess, "run", return_value=result):
                with self.assertRaises(ValueError):
                    install_state.read_system_links()

    def test_persistent_inventory_includes_excluded_types(self):
        links = [_link("renamed", kind="veth"), _link("wan", kind="vlan")]
        selected, excluded = install_state.select_interfaces(links)
        state = install_state.merge_machine_state({}, selected, excluded, selection="auto", links=links)
        self.assertEqual(state["interface_details"]["renamed"]["kind"], "veth")
        self.assertEqual(state["interface_details"]["wan"]["kind"], "vlan")

    def test_explicit_container_requires_opt_in_and_loopback_is_always_rejected(self):
        links = [_link("lo", kind="loopback", flags=("LOOPBACK", "UP")), _link("veth9", kind="veth")]
        with self.assertRaisesRegex(ValueError, "allow_container"):
            install_state.select_interfaces(links, explicit=["veth9"])
        selected, _ = install_state.select_interfaces(
            links, explicit=["veth9"], allow_container=True
        )
        self.assertEqual(selected, ["veth9"])
        with self.assertRaisesRegex(ValueError, "Loopback"):
            install_state.select_interfaces(links, explicit=["lo"], allow_container=True)

    def test_configured_exclusion_wins_during_auto_selection(self):
        selected, excluded = install_state.select_interfaces(
            [_link("eth0"), _link("eth1")], excluded_names=["eth1"]
        )
        self.assertEqual(selected, ["eth0"])
        self.assertEqual(excluded["eth1"], "configured exclusion")

    def test_unknown_operstate_does_not_override_administratively_down(self):
        selected, excluded = install_state.select_interfaces([
            _link("down", flags=("BROADCAST",), operstate="UNKNOWN"),
            _link("up", flags=("BROADCAST", "UP"), operstate="UNKNOWN"),
        ])
        self.assertEqual(selected, ["up"])
        self.assertEqual(excluded, {"down": "interface down"})

    def test_machine_state_preserves_each_interfaces_previous_mode(self):
        previous = {
            "interfaces": {
                "eth0": {"xdp_mode": "native", "last_program_id": 41},
                "eth1": {"xdp_mode": "generic", "last_program_id": 42},
            }
        }
        state = install_state.merge_machine_state(
            previous, ["eth0", "eth1", "eth2"], {"lo": "loopback"}, selection="auto"
        )
        self.assertEqual(state["interfaces"]["eth0"]["xdp_mode"], "native")
        self.assertEqual(state["interfaces"]["eth1"]["xdp_mode"], "generic")
        self.assertEqual(state["interfaces"]["eth2"]["xdp_mode"], "auto")
        self.assertEqual(state["excluded"], {"lo": "loopback"})

    def test_atomic_json_write_round_trips(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "machine-state.json"
            install_state.atomic_write_json(path, {"schema": 1, "interfaces": {}})
            self.assertEqual(install_state.load_json(path)["schema"], 1)
            self.assertFalse(list(path.parent.glob(f".{path.name}.*")))

    def test_atomic_symlink_replaces_regular_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            link = root / "current"
            link.write_text("legacy")
            install_state.atomic_symlink("releases/new", link)
            self.assertTrue(link.is_symlink())
            self.assertEqual(link.readlink(), Path("releases/new"))

    def test_runtime_state_reports_mixed_xdp_mode(self):
        state = install_state.runtime_state(
            requested_backend="auto",
            active_backend="xdp",
            interfaces={
                "eth0": {"xdp_mode": "native"},
                "eth1": {"xdp_mode": "generic"},
            },
            generation="verified",
        )
        self.assertEqual(state["xdp_mode"], "mixed")

    def test_record_updates_per_interface_modes_and_runtime_health(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            machine = root / "machine-state.json"
            runtime = root / "runtime-state.json"
            install_state.atomic_write_json(
                machine,
                {"schema": 1, "interfaces": {"eth0": {"xdp_mode": "generic"}}},
            )
            rc = install_state.main(
                [
                    "record",
                    "--machine-state", str(machine),
                    "--runtime-state", str(runtime),
                    "--requested-backend", "auto",
                    "--active-backend", "xdp",
                    "--interface-state", "eth0=native:41",
                    "--interface-state", "eth1=generic:41",
                ]
            )
            self.assertEqual(rc, 0)
            self.assertEqual(install_state.load_json(machine)["interfaces"]["eth0"]["xdp_mode"], "native")
            saved = install_state.load_json(runtime)
            self.assertTrue(saved["healthy"])
            self.assertEqual(saved["xdp_mode"], "mixed")


if __name__ == "__main__":
    unittest.main()
