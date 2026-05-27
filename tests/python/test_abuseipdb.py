"""Tests for auto_xdp.abuseipdb: fetch, map management, syncer lifecycle."""
from __future__ import annotations

import threading
import unittest
from unittest import mock
from urllib.error import URLError


class FakeLpmMap:
    def __init__(self):
        self._entries: dict[str, int] = {}
        self.closed = False
        self.capacity: int | None = None

    def active_keys(self) -> set[str]:
        return set(self._entries)

    def set(self, cidr: str, val: int, dry_run: bool = False) -> bool:
        if self.capacity is not None and cidr not in self._entries and len(self._entries) >= self.capacity:
            return False
        self._entries[cidr] = val
        return True

    def delete(self, cidr: str, dry_run: bool = False) -> bool:
        self._entries.pop(cidr, None)
        return True

    def close(self) -> None:
        self.closed = True


_ABUSEIPDB_FLAG = 1 << 1  # XDP_CFG_FLAG_ABUSEIPDB_ENABLED


class FakeRuntimeCfgMap:
    def __init__(self):
        self._timing = (0,) * 8
        self._cfg_flags = 0
        self.closed = False

    def get(self):
        return self._timing

    def get_cfg_flags(self):
        return self._cfg_flags

    def set(self, timing, flags=0, dry_run=False):
        self._timing = timing
        self._cfg_flags = flags
        return True

    def close(self):
        self.closed = True


# ---------------------------------------------------------------------------
# fetch_blocklist
# ---------------------------------------------------------------------------

class TestFetchBlocklist(unittest.TestCase):
    def _import(self):
        from auto_xdp.abuseipdb import fetch_blocklist
        return fetch_blocklist

    def test_returns_ips_skipping_comments_and_blanks(self):
        fetch_blocklist = self._import()
        body = "# comment\n1.2.3.4\n\n5.6.7.8\n# another\n9.10.11.12\n"
        with mock.patch("urllib.request.urlopen") as m:
            m.return_value.__enter__ = lambda s: s
            m.return_value.__exit__ = mock.Mock(return_value=False)
            m.return_value.read.return_value = body.encode()
            result = fetch_blocklist("s10030d", "https://example.com")
        self.assertEqual(result, ["1.2.3.4", "5.6.7.8", "9.10.11.12"])

    def test_returns_empty_on_url_error(self):
        fetch_blocklist = self._import()
        with mock.patch("urllib.request.urlopen", side_effect=URLError("timeout")):
            result = fetch_blocklist("s10030d", "https://example.com")
        self.assertEqual(result, [])

    def test_returns_empty_for_unknown_source_key(self):
        fetch_blocklist = self._import()
        result = fetch_blocklist("nonexistent_key", "https://example.com")
        self.assertEqual(result, [])

    def test_uses_correct_filename(self):
        fetch_blocklist = self._import()
        with mock.patch("urllib.request.urlopen") as m:
            m.return_value.__enter__ = lambda s: s
            m.return_value.__exit__ = mock.Mock(return_value=False)
            m.return_value.read.return_value = b""
            fetch_blocklist("s10030d", "https://base.example.com")
            called_url = m.call_args[0][0]
        self.assertIn("abuseipdb-s100-30d.ipv4", called_url)
        self.assertTrue(called_url.startswith("https://base.example.com"))

    def test_strips_inline_comments_after_ips(self):
        # borestad lists annotate each IP: "1.0.164.165      # TH  AS23969   TOT ..."
        fetch_blocklist = self._import()
        body = (
            "1.0.164.165      # TH  AS23969   TOT Public Company Limited\n"
            "# full-line comment\n"
            "2.3.4.5\t# inline tab\n"
            "\n"
            "6.7.8.9\n"
        )
        with mock.patch("urllib.request.urlopen") as m:
            m.return_value.__enter__ = lambda s: s
            m.return_value.__exit__ = mock.Mock(return_value=False)
            m.return_value.read.return_value = body.encode()
            result = fetch_blocklist("s10030d", "https://example.com")
        self.assertEqual(result, ["1.0.164.165", "2.3.4.5", "6.7.8.9"])

    def test_strips_whitespace_from_lines(self):
        fetch_blocklist = self._import()
        body = "  1.2.3.4  \n\t5.6.7.8\t\n"
        with mock.patch("urllib.request.urlopen") as m:
            m.return_value.__enter__ = lambda s: s
            m.return_value.__exit__ = mock.Mock(return_value=False)
            m.return_value.read.return_value = body.encode()
            result = fetch_blocklist("s10030d", "https://example.com")
        self.assertEqual(result, ["1.2.3.4", "5.6.7.8"])


# ---------------------------------------------------------------------------
# BpfRiskMaps
# ---------------------------------------------------------------------------

class TestBpfRiskMaps(unittest.TestCase):
    def _make(self):
        from auto_xdp import abuseipdb as mod
        map4 = FakeLpmMap()
        cfg_map = FakeRuntimeCfgMap()
        with mock.patch.object(mod, "BpfLpmMap", return_value=map4):
            rm = mod.BpfRiskMaps("/fake/v4", cfg_map)
        return rm, map4, cfg_map

    def test_replace_all_writes_v4_with_slash32(self):
        rm, map4, _ = self._make()
        rm.replace_all(["1.2.3.4"])
        self.assertIn("1.2.3.4/32", map4._entries)

    def test_replace_all_skips_v6_addresses(self):
        rm, map4, _ = self._make()
        v4 = rm.replace_all(["1.2.3.4", "2001:db8::1", "5.6.7.8"])
        self.assertEqual(v4, 2)
        self.assertEqual(set(map4._entries), {"1.2.3.4/32", "5.6.7.8/32"})

    def test_replace_all_preserves_existing_cidr_notation(self):
        rm, map4, _ = self._make()
        rm.replace_all(["10.0.0.0/8"])
        self.assertIn("10.0.0.0/8", map4._entries)

    def test_replace_all_clears_previous_entries(self):
        rm, map4, _ = self._make()
        rm.replace_all(["1.2.3.4"])
        rm.replace_all(["5.6.7.8"])
        self.assertNotIn("1.2.3.4/32", map4._entries)
        self.assertIn("5.6.7.8/32", map4._entries)

    def test_replace_all_sets_active_flag_when_ips_loaded(self):
        rm, _, cfg_map = self._make()
        rm.replace_all(["1.2.3.4"])
        self.assertTrue(cfg_map._cfg_flags & _ABUSEIPDB_FLAG)

    def test_replace_all_clears_active_flag_on_empty_list(self):
        rm, _, cfg_map = self._make()
        rm.replace_all(["1.2.3.4"])
        rm.replace_all([])
        self.assertFalse(cfg_map._cfg_flags & _ABUSEIPDB_FLAG)

    def test_replace_all_skips_comments_and_blanks(self):
        rm, _, _ = self._make()
        v4 = rm.replace_all(["# comment", "", "1.2.3.4"])
        self.assertEqual(v4, 1)

    def test_replace_all_dedupes_repeated_v4(self):
        rm, map4, _ = self._make()
        v4 = rm.replace_all(["1.2.3.4", "1.2.3.4", "5.6.7.8"])
        self.assertEqual(v4, 2)
        self.assertEqual(set(map4._entries), {"1.2.3.4/32", "5.6.7.8/32"})

    def test_replace_all_logs_warning_when_v4_overflows(self):
        rm, map4, _ = self._make()
        map4.capacity = 2
        with self.assertLogs("auto_xdp.abuseipdb", level="WARNING") as cm:
            v4 = rm.replace_all(["1.1.1.1", "2.2.2.2", "3.3.3.3", "4.4.4.4"])
        self.assertEqual(v4, 2)
        log_output = "\n".join(cm.output)
        self.assertIn("v4", log_output.lower())
        self.assertIn("2", log_output)  # 2 overflow entries

    def test_replace_all_no_warning_when_no_overflow(self):
        rm, _, _ = self._make()
        with self.assertNoLogs("auto_xdp.abuseipdb", level="WARNING"):
            rm.replace_all(["1.1.1.1", "5.6.7.8"])

    def test_clear_all_empties_maps_and_clears_flag(self):
        rm, map4, cfg_map = self._make()
        rm.replace_all(["1.2.3.4"])
        rm.clear_all()
        self.assertEqual(len(map4._entries), 0)
        self.assertFalse(cfg_map._cfg_flags & _ABUSEIPDB_FLAG)

    def test_close_closes_inner_maps(self):
        rm, map4, _ = self._make()
        rm.close()
        self.assertTrue(map4.closed)


# ---------------------------------------------------------------------------
# AbuseIPDBSyncer
# ---------------------------------------------------------------------------

class TestAbuseIPDBSyncer(unittest.TestCase):
    def _make_syncer(self, sources=None, refresh_seconds=3600.0):
        from auto_xdp import abuseipdb as mod
        map4 = FakeLpmMap()
        cfg_map = FakeRuntimeCfgMap()
        with mock.patch.object(mod, "BpfLpmMap", return_value=map4):
            risk_maps = mod.BpfRiskMaps("/fake/v4", cfg_map)
        syncer = mod.AbuseIPDBSyncer(
            risk_maps,
            base_url="https://example.com",
            sources=sources or ["s10030d"],
            refresh_seconds=refresh_seconds,
        )
        return syncer, risk_maps, map4

    def test_refresh_calls_fetch_once_per_source(self):
        syncer, _, _ = self._make_syncer(sources=["s1003d", "s10030d"])
        with mock.patch("auto_xdp.abuseipdb.fetch_blocklist", return_value=[]) as m:
            syncer._refresh()
        self.assertEqual(m.call_count, 2)

    def test_refresh_deduplicates_ips_across_sources(self):
        syncer, _, map4 = self._make_syncer(sources=["s1003d", "s10030d"])
        with mock.patch("auto_xdp.abuseipdb.fetch_blocklist", return_value=["1.2.3.4"]):
            syncer._refresh()
        self.assertEqual(len([k for k in map4._entries if "1.2.3.4" in k]), 1)

    def test_refresh_retains_previous_state_when_no_ips_fetched(self):
        syncer, _, map4 = self._make_syncer()
        map4._entries["1.2.3.4/32"] = 1
        with mock.patch("auto_xdp.abuseipdb.fetch_blocklist", return_value=[]):
            syncer._refresh()
        self.assertIn("1.2.3.4/32", map4._entries)

    def test_start_and_stop_thread(self):
        syncer, _, _ = self._make_syncer(refresh_seconds=3600.0)
        with mock.patch.object(syncer, "_refresh"):
            syncer.start()
            self.assertIsNotNone(syncer._thread)
            self.assertTrue(syncer._thread.is_alive())
            syncer.stop()
            self.assertTrue(syncer._thread is None or not syncer._thread.is_alive())

    def test_start_is_idempotent(self):
        syncer, _, _ = self._make_syncer(refresh_seconds=3600.0)
        with mock.patch.object(syncer, "_refresh"):
            syncer.start()
            t1 = syncer._thread
            syncer.start()
            t2 = syncer._thread
            self.assertIs(t1, t2)
            syncer.stop()

    def test_refresh_seconds_clamped_to_minimum_60(self):
        from auto_xdp.abuseipdb import AbuseIPDBSyncer
        from unittest.mock import MagicMock
        syncer = AbuseIPDBSyncer(MagicMock(), refresh_seconds=10.0)
        self.assertEqual(syncer._refresh_seconds, 60.0)


# ---------------------------------------------------------------------------
# Config parsing
# ---------------------------------------------------------------------------

class TestAbuseIPDBConfig(unittest.TestCase):
    def test_apply_toml_config_sets_enabled(self):
        import auto_xdp.config as cfg_mod
        cfg_mod.apply_toml_config({"abuseipdb": {"enabled": True}})
        self.assertTrue(cfg_mod.ABUSEIPDB_ENABLED)
        cfg_mod.apply_toml_config({})
        self.assertFalse(cfg_mod.ABUSEIPDB_ENABLED)

    def test_apply_toml_config_sets_sources(self):
        import auto_xdp.config as cfg_mod
        cfg_mod.apply_toml_config({"abuseipdb": {"sources": ["s1001d", "s10030d"]}})
        self.assertEqual(cfg_mod.ABUSEIPDB_SOURCES, ["s1001d", "s10030d"])

    def test_apply_toml_config_defaults_sources(self):
        import auto_xdp.config as cfg_mod
        cfg_mod.apply_toml_config({})
        self.assertEqual(cfg_mod.ABUSEIPDB_SOURCES, ["s1003d"])

    def test_apply_toml_config_sets_refresh_seconds(self):
        import auto_xdp.config as cfg_mod
        cfg_mod.apply_toml_config({"abuseipdb": {"refresh_seconds": 7200}})
        self.assertEqual(cfg_mod.ABUSEIPDB_REFRESH_SECONDS, 7200.0)

    def test_map_paths_derived_from_bpf_pin_dir(self):
        import auto_xdp.config as cfg_mod
        pin_dir = cfg_mod.BPF_PIN_DIR
        self.assertEqual(cfg_mod.ABUSEIPDB_RISK_MAP_PATH4, f"{pin_dir}/abuseipdb_v4")
        self.assertEqual(cfg_mod.ABUSEIPDB_CFG_MAP_PATH, f"{pin_dir}/abuseipdb_cfg")


if __name__ == "__main__":
    unittest.main()
