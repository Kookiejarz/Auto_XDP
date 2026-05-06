"""Tests for default-on TCP protection (Bug 1 + Bug 2 fix).

Layered into three sections:
1. Config loading
2. Userspace resolver (policy.py)
3. BPF helper Python ports (counter timing, cap checks)
"""
import unittest

from auto_xdp import config as cfg


class ConfigLoadDefaultsTests(unittest.TestCase):
    def setUp(self):
        # Save and restore module-level globals so tests do not leak.
        self._saved = {}
        for name in (
            "XDP_DEFAULT_TCP_SYN_RATE",
            "XDP_DEFAULT_TCP_SYN_RATE_STRICT",
            "XDP_DEFAULT_TCP_SYN_AGG_RATE",
            "XDP_DEFAULT_TCP_SYN_AGG_RATE_STRICT",
            "XDP_DEFAULT_TCP_ESTABLISHED_PER_SRC",
            "XDP_DEFAULT_TCP_ESTABLISHED_PER_SRC_STRICT",
            "XDP_DEFAULT_TCP_ESTABLISHED_PER_PREFIX",
            "XDP_DEFAULT_TCP_ESTABLISHED_PER_PREFIX_STRICT",
            "XDP_DEFAULT_TCP_ESTABLISHED_PER_PORT",
            "XDP_DEFAULT_TCP_ESTABLISHED_PER_PORT_STRICT",
            "XDP_SENSITIVE_PORT_THRESHOLD",
        ):
            self._saved[name] = getattr(cfg, name, None)

    def tearDown(self):
        for name, value in self._saved.items():
            if value is not None:
                setattr(cfg, name, value)

    def test_defaults_have_built_in_fallback(self):
        """Without [xdp.runtime] keys, hard-coded defaults apply."""
        self.assertEqual(cfg.XDP_DEFAULT_TCP_SYN_RATE, 100)
        self.assertEqual(cfg.XDP_DEFAULT_TCP_SYN_RATE_STRICT, 5)
        self.assertEqual(cfg.XDP_DEFAULT_TCP_SYN_AGG_RATE, 1000)
        self.assertEqual(cfg.XDP_DEFAULT_TCP_SYN_AGG_RATE_STRICT, 50)
        self.assertEqual(cfg.XDP_DEFAULT_TCP_ESTABLISHED_PER_SRC, 50)
        self.assertEqual(cfg.XDP_DEFAULT_TCP_ESTABLISHED_PER_SRC_STRICT, 5)
        self.assertEqual(cfg.XDP_DEFAULT_TCP_ESTABLISHED_PER_PREFIX, 200)
        self.assertEqual(cfg.XDP_DEFAULT_TCP_ESTABLISHED_PER_PREFIX_STRICT, 20)
        self.assertEqual(cfg.XDP_DEFAULT_TCP_ESTABLISHED_PER_PORT, 5000)
        self.assertEqual(cfg.XDP_DEFAULT_TCP_ESTABLISHED_PER_PORT_STRICT, 200)
        self.assertEqual(cfg.XDP_SENSITIVE_PORT_THRESHOLD, 5)

    def test_load_overrides_defaults_from_toml(self):
        """[xdp.runtime] keys override the built-in defaults."""
        cfg.apply_toml_config({
            "xdp": {
                "runtime": {
                    "default_tcp_syn_rate": 250,
                    "default_tcp_syn_rate_strict": 7,
                    "default_tcp_established_per_port": 9999,
                    "sensitive_port_threshold": 3,
                }
            }
        })

        self.assertEqual(cfg.XDP_DEFAULT_TCP_SYN_RATE, 250)
        self.assertEqual(cfg.XDP_DEFAULT_TCP_SYN_RATE_STRICT, 7)
        self.assertEqual(cfg.XDP_DEFAULT_TCP_ESTABLISHED_PER_PORT, 9999)
        self.assertEqual(cfg.XDP_SENSITIVE_PORT_THRESHOLD, 3)


if __name__ == "__main__":
    unittest.main()
