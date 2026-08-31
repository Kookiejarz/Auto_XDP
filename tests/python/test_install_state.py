import tempfile
import unittest
from pathlib import Path

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

        self.assertEqual(selected, ["bond0", "br-public", "ens6", "eth0"])
        self.assertEqual(excluded["lo"], "loopback")
        self.assertEqual(excluded["docker0"], "container interface")
        self.assertEqual(excluded["veth42"], "virtual veth")
        self.assertEqual(excluded["cni0"], "container interface")

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

    def test_machine_state_preserves_each_interfaces_previous_mode(self):
        previous = {
            "interfaces": {
                "eth0": {"xdp_mode": "native", "last_program_id": 41, "tc_egress": True},
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
                    "--interface-state", "eth0=native:41:attached",
                    "--interface-state", "eth1=generic:41:attached",
                ]
            )
            self.assertEqual(rc, 0)
            self.assertEqual(install_state.load_json(machine)["interfaces"]["eth0"]["xdp_mode"], "native")
            saved = install_state.load_json(runtime)
            self.assertTrue(saved["healthy"])
            self.assertEqual(saved["xdp_mode"], "mixed")


if __name__ == "__main__":
    unittest.main()
