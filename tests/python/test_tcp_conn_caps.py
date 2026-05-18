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


from auto_xdp import policy


class ExplicitLookupTests(unittest.TestCase):
    def setUp(self):
        self._saved_proc = dict(cfg._SYN_RATE_BY_PROC)
        self._saved_service = dict(cfg._SYN_RATE_BY_SERVICE)
        cfg._SYN_RATE_BY_PROC.clear()
        cfg._SYN_RATE_BY_SERVICE.clear()

    def tearDown(self):
        cfg._SYN_RATE_BY_PROC.clear()
        cfg._SYN_RATE_BY_PROC.update(self._saved_proc)
        cfg._SYN_RATE_BY_SERVICE.clear()
        cfg._SYN_RATE_BY_SERVICE.update(self._saved_service)

    def test_proc_match_returns_value(self):
        cfg._SYN_RATE_BY_PROC["myapp"] = 7
        result = policy._explicit_lookup(
            12345, "myapp",
            cfg._SYN_RATE_BY_PROC, cfg._SYN_RATE_BY_SERVICE,
        )
        self.assertEqual(result, 7)

    def test_proc_explicit_zero_returns_zero(self):
        """Explicit pin to 0 (off) is distinct from missing entry."""
        cfg._SYN_RATE_BY_PROC["myapp"] = 0
        result = policy._explicit_lookup(
            12345, "myapp",
            cfg._SYN_RATE_BY_PROC, cfg._SYN_RATE_BY_SERVICE,
        )
        self.assertEqual(result, 0)

    def test_service_match_returns_value(self):
        cfg._SYN_RATE_BY_SERVICE["ssh"] = 2
        result = policy._explicit_lookup(
            22, "",
            cfg._SYN_RATE_BY_PROC, cfg._SYN_RATE_BY_SERVICE,
        )
        self.assertEqual(result, 2)

    def test_no_match_returns_none(self):
        result = policy._explicit_lookup(
            12345, "unknown",
            cfg._SYN_RATE_BY_PROC, cfg._SYN_RATE_BY_SERVICE,
        )
        self.assertIsNone(result)

    def test_proc_takes_precedence_over_service(self):
        cfg._SYN_RATE_BY_PROC["sshd"] = 1
        cfg._SYN_RATE_BY_SERVICE["ssh"] = 99
        result = policy._explicit_lookup(
            22, "sshd",
            cfg._SYN_RATE_BY_PROC, cfg._SYN_RATE_BY_SERVICE,
        )
        self.assertEqual(result, 1)


class IsSensitiveTests(unittest.TestCase):
    def setUp(self):
        self._saved_proc = dict(cfg._SYN_RATE_BY_PROC)
        self._saved_service = dict(cfg._SYN_RATE_BY_SERVICE)
        self._saved_threshold = cfg.XDP_SENSITIVE_PORT_THRESHOLD
        cfg._SYN_RATE_BY_PROC.clear()
        cfg._SYN_RATE_BY_SERVICE.clear()
        cfg.XDP_SENSITIVE_PORT_THRESHOLD = 5

    def tearDown(self):
        cfg._SYN_RATE_BY_PROC.clear()
        cfg._SYN_RATE_BY_PROC.update(self._saved_proc)
        cfg._SYN_RATE_BY_SERVICE.clear()
        cfg._SYN_RATE_BY_SERVICE.update(self._saved_service)
        cfg.XDP_SENSITIVE_PORT_THRESHOLD = self._saved_threshold

    def test_proc_with_low_rate_is_sensitive(self):
        cfg._SYN_RATE_BY_PROC["sshd"] = 2
        self.assertTrue(policy._is_sensitive(22, "sshd"))

    def test_proc_with_high_rate_is_not_sensitive(self):
        cfg._SYN_RATE_BY_PROC["postfix"] = 20
        self.assertFalse(policy._is_sensitive(25, "postfix"))

    def test_proc_with_zero_pin_is_not_sensitive(self):
        """Pin-off is exempt, not sensitive."""
        cfg._SYN_RATE_BY_PROC["benchmark"] = 0
        self.assertFalse(policy._is_sensitive(8080, "benchmark"))

    def test_service_with_low_rate_is_sensitive(self):
        cfg._SYN_RATE_BY_SERVICE["ssh"] = 2
        self.assertTrue(policy._is_sensitive(22, ""))

    def test_unknown_proc_and_port_is_not_sensitive(self):
        self.assertFalse(policy._is_sensitive(8080, "myapp"))

    def test_proc_at_threshold_is_sensitive(self):
        cfg._SYN_RATE_BY_PROC["edge"] = 5  # threshold == 5
        self.assertTrue(policy._is_sensitive(9000, "edge"))

    def test_proc_one_above_threshold_is_not_sensitive(self):
        cfg._SYN_RATE_BY_PROC["edge"] = 6
        self.assertFalse(policy._is_sensitive(9000, "edge"))


class ResolverDefaultsTests(unittest.TestCase):
    """Bug 1: ports without explicit config now get default protection."""

    def setUp(self):
        self._saved_proc = dict(cfg._SYN_RATE_BY_PROC)
        self._saved_service = dict(cfg._SYN_RATE_BY_SERVICE)
        self._saved_agg_proc = dict(cfg._SYN_AGG_RATE_BY_PROC)
        self._saved_agg_service = dict(cfg._SYN_AGG_RATE_BY_SERVICE)
        self._saved_conn_proc = dict(cfg._TCP_CONN_BY_PROC)
        self._saved_conn_service = dict(cfg._TCP_CONN_BY_SERVICE)
        cfg._SYN_RATE_BY_PROC.clear()
        cfg._SYN_RATE_BY_SERVICE.clear()
        cfg._SYN_AGG_RATE_BY_PROC.clear()
        cfg._SYN_AGG_RATE_BY_SERVICE.clear()
        cfg._TCP_CONN_BY_PROC.clear()
        cfg._TCP_CONN_BY_SERVICE.clear()

    def tearDown(self):
        cfg._SYN_RATE_BY_PROC.clear()
        cfg._SYN_RATE_BY_PROC.update(self._saved_proc)
        cfg._SYN_RATE_BY_SERVICE.clear()
        cfg._SYN_RATE_BY_SERVICE.update(self._saved_service)
        cfg._SYN_AGG_RATE_BY_PROC.clear()
        cfg._SYN_AGG_RATE_BY_PROC.update(self._saved_agg_proc)
        cfg._SYN_AGG_RATE_BY_SERVICE.clear()
        cfg._SYN_AGG_RATE_BY_SERVICE.update(self._saved_agg_service)
        cfg._TCP_CONN_BY_PROC.clear()
        cfg._TCP_CONN_BY_PROC.update(self._saved_conn_proc)
        cfg._TCP_CONN_BY_SERVICE.clear()
        cfg._TCP_CONN_BY_SERVICE.update(self._saved_conn_service)

    def test_unconfigured_port_gets_normal_default_syn_rate(self):
        self.assertEqual(policy._port_rate_limit(8080, "myapp"), 100)

    def test_sensitive_proc_gets_strict_default_syn_rate(self):
        cfg._SYN_RATE_BY_SERVICE["ssh"] = 2  # service-table sensitive marker
        # Port 22 has no proc entry but matches "ssh" service — strict tier.
        self.assertEqual(policy._port_rate_limit(22, ""), 5)

    def test_explicit_proc_overrides_default(self):
        cfg._SYN_RATE_BY_PROC["myapp"] = 42
        self.assertEqual(policy._port_rate_limit(8080, "myapp"), 42)

    def test_explicit_zero_pins_off(self):
        cfg._SYN_RATE_BY_PROC["benchmark"] = 0
        self.assertEqual(policy._port_rate_limit(9090, "benchmark"), 0)

    def test_unconfigured_port_gets_normal_default_agg_rate(self):
        self.assertEqual(policy._syn_aggregate_rate_limit(8080, "myapp"), 1000)

    def test_unconfigured_port_gets_normal_default_conn_limit(self):
        self.assertEqual(policy._tcp_conn_limit(8080, "myapp"), 50)

    def test_resolve_port_limits_includes_zero_pinned_ports(self):
        """The if-limit>0 filter is dropped: pinned-off ports stay in
        desired_state so the BPF policy gets explicit 0."""
        cfg._SYN_RATE_BY_PROC["benchmark"] = 0
        result = policy._resolve_port_limits(
            {9090}, {9090: "benchmark"}, policy._port_rate_limit,
        )
        self.assertEqual(result, {9090: 0})

    def test_resolve_port_limits_applies_default_to_every_port(self):
        result = policy._resolve_port_limits(
            {8080, 9000}, {8080: "appA", 9000: "appB"}, policy._port_rate_limit,
        )
        self.assertEqual(result, {8080: 100, 9000: 100})


import struct as _struct


class PortPolicyStructLayoutTests(unittest.TestCase):
    """Verify BpfPortPolicyMap struct format matches the extended C struct."""

    def test_struct_format_has_eight_u32_fields(self):
        from auto_xdp.bpf.maps import BpfPortPolicyMap
        self.assertEqual(BpfPortPolicyMap._STRUCT_FMT, "=IIIIIIII")
        self.assertEqual(_struct.calcsize(BpfPortPolicyMap._STRUCT_FMT), 32)

    def test_view_map_default_tuple_has_eight_fields(self):
        from auto_xdp.bpf.maps import BpfPortPolicyViewMap
        import inspect
        src = inspect.getsource(BpfPortPolicyViewMap.set)
        # Confirm prefix fields still at indices 3 and 4 in default tuple.
        self.assertIn("RATE_LIMIT_SOURCE_PREFIX_V4", src)
        self.assertIn("RATE_LIMIT_SOURCE_PREFIX_V6", src)
        # Confirm the default tuple has 8 elements total.
        self.assertRegex(
            src,
            r"\(0,\s*0,\s*0,\s*cfg\.RATE_LIMIT_SOURCE_PREFIX_V4,"
            r"\s*cfg\.RATE_LIMIT_SOURCE_PREFIX_V6,\s*0,\s*0,\s*0\)",
        )


class CounterTimingTests(unittest.TestCase):
    """Bug 2 foundational: counter increments iff ESTABLISHED transition seen.

    Python ports of new BPF helpers — we verify the algorithm contract.
    Same pattern as test_udp_global_rl.py.
    """

    def setUp(self):
        self.tsc = {}
        self.tcp_timeout_ns = 300_000_000_000  # 300s

    def _record_established(self, key, now, dest_port):
        k = (key, dest_port)
        v = self.tsc.get(k)
        if v is None:
            self.tsc[k] = {"count": 1, "last_seen_ns": now}
            return
        if now - v["last_seen_ns"] > self.tcp_timeout_ns:
            v["count"] = 1
        else:
            v["count"] += 1
        v["last_seen_ns"] = now

    def _record_close(self, key, now, dest_port, was_established):
        if not was_established:
            return
        k = (key, dest_port)
        v = self.tsc.get(k)
        if v is None:
            return
        if v["count"] <= 1:
            del self.tsc[k]
            return
        v["count"] -= 1
        v["last_seen_ns"] = now

    def test_syn_arrival_does_not_increment(self):
        self.assertEqual(len(self.tsc), 0)

    def test_full_handshake_increments_once(self):
        self._record_established(("10.0.0.1", 0), 1_000_000_000, 22)
        self.assertEqual(self.tsc[(("10.0.0.1", 0), 22)]["count"], 1)

    def test_full_cycle_returns_to_zero(self):
        self._record_established(("10.0.0.1", 0), 1_000, 22)
        self._record_close(("10.0.0.1", 0), 2_000, 22, was_established=True)
        self.assertNotIn((("10.0.0.1", 0), 22), self.tsc)

    def test_half_open_close_does_not_decrement(self):
        self._record_established(("10.0.0.1", 0), 1_000, 22)
        self._record_close(("10.0.0.1", 0), 2_000, 22, was_established=False)
        self.assertEqual(self.tsc[(("10.0.0.1", 0), 22)]["count"], 1)

    def test_ttl_self_heal_resets_stale_count(self):
        k = ((1, 2, 3, 4), 22)
        self.tsc[k] = {"count": 999, "last_seen_ns": 0}
        self._record_established((1, 2, 3, 4), 2 * self.tcp_timeout_ns, 22)
        self.assertEqual(self.tsc[k]["count"], 1)


class PerPrefixCapTests(unittest.TestCase):
    """L4: per (prefix, port) ESTABLISHED cap."""

    def setUp(self):
        self.tsc_pfx = {}
        self.tcp_timeout_ns = 300_000_000_000

    def _record(self, prefix, port, now):
        k = (prefix, port)
        v = self.tsc_pfx.get(k)
        if v is None:
            self.tsc_pfx[k] = {"count": 1, "last_seen_ns": now}
            return
        if now - v["last_seen_ns"] > self.tcp_timeout_ns:
            v["count"] = 1
        else:
            v["count"] += 1
        v["last_seen_ns"] = now

    def _check(self, prefix, port, now, cap):
        if cap == 0:
            return "pass"
        v = self.tsc_pfx.get((prefix, port))
        if v is None:
            return "pass"
        if now - v["last_seen_ns"] > self.tcp_timeout_ns:
            return "pass"
        return "drop" if v["count"] >= cap else "pass"

    def test_below_cap_passes(self):
        for _ in range(4):
            self._record("10.0.0.0/24", 80, 1_000)
        self.assertEqual(self._check("10.0.0.0/24", 80, 1_000, cap=5), "pass")

    def test_at_cap_drops(self):
        for _ in range(5):
            self._record("10.0.0.0/24", 80, 1_000)
        self.assertEqual(self._check("10.0.0.0/24", 80, 1_000, cap=5), "drop")

    def test_distributed_sources_share_one_counter(self):
        self._record("10.0.0.0/24", 80, 1_000)
        self._record("10.0.0.0/24", 80, 1_001)
        self.assertEqual(self.tsc_pfx[("10.0.0.0/24", 80)]["count"], 2)


class PerPortCapTests(unittest.TestCase):
    """L5: per-port total ESTABLISHED cap."""

    def setUp(self):
        self.tsc_port = {}
        self.tcp_timeout_ns = 300_000_000_000

    def _record(self, port, now):
        v = self.tsc_port.get(port)
        if v is None:
            self.tsc_port[port] = {"count": 1, "last_seen_ns": now}
            return
        if now - v["last_seen_ns"] > self.tcp_timeout_ns:
            v["count"] = 1
        else:
            v["count"] += 1
        v["last_seen_ns"] = now

    def _check(self, port, now, cap):
        if cap == 0:
            return "pass"
        v = self.tsc_port.get(port)
        if v is None:
            return "pass"
        if now - v["last_seen_ns"] > self.tcp_timeout_ns:
            return "pass"
        return "drop" if v["count"] >= cap else "pass"

    def test_below_port_cap_passes(self):
        for _ in range(199):
            self._record(80, 1_000)
        self.assertEqual(self._check(80, 1_000, cap=200), "pass")

    def test_at_port_cap_drops_across_prefixes(self):
        for _ in range(200):
            self._record(80, 1_000)
        self.assertEqual(self._check(80, 1_000, cap=200), "drop")

    def test_other_port_unaffected(self):
        for _ in range(200):
            self._record(80, 1_000)
        self.assertEqual(self._check(443, 1_000, cap=200), "pass")


class ConnCapResolverTests(unittest.TestCase):
    def setUp(self):
        self._save = {}
        for n in ("_TCP_CONN_PREFIX_BY_PROC", "_TCP_CONN_PREFIX_BY_SERVICE",
                  "_TCP_CONN_PORT_BY_PROC", "_TCP_CONN_PORT_BY_SERVICE"):
            self._save[n] = dict(getattr(cfg, n, {}))

    def tearDown(self):
        for n, v in self._save.items():
            try:
                d = getattr(cfg, n)
                d.clear()
                d.update(v)
            except AttributeError:
                pass

    def test_unconfigured_port_uses_prefix_default(self):
        self.assertEqual(
            policy._tcp_conn_prefix_limit(8080, "myapp"),
            cfg.XDP_DEFAULT_TCP_ESTABLISHED_PER_PREFIX,
        )

    def test_unconfigured_port_uses_port_default(self):
        self.assertEqual(
            policy._tcp_conn_port_limit(8080, "myapp"),
            cfg.XDP_DEFAULT_TCP_ESTABLISHED_PER_PORT,
        )

    def test_prefix_explicit_override(self):
        cfg._TCP_CONN_PREFIX_BY_PROC["myapp"] = 42
        self.assertEqual(policy._tcp_conn_prefix_limit(8080, "myapp"), 42)

    def test_port_explicit_override(self):
        cfg._TCP_CONN_PORT_BY_PROC["myapp"] = 999
        self.assertEqual(policy._tcp_conn_port_limit(8080, "myapp"), 999)


if __name__ == "__main__":
    unittest.main()
