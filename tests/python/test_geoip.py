import unittest
from types import SimpleNamespace
from unittest import mock

from auto_xdp.telemetry.geoip import GeoIPResolver


class GeoIPTests(unittest.TestCase):
    def _reader(self, record=None, prefix=24, version=6):
        reader = mock.Mock()
        reader.metadata.return_value = SimpleNamespace(ip_version=version, build_epoch=0)
        reader.get_with_prefix_len.return_value = (record, prefix)
        return reader

    def _resolver(self, readers, **options):
        config = {"enabled": True, **{f"{kind}_db": f"/{kind}.mmdb" for kind in readers}, **options}
        module = mock.Mock()
        module.open_database.side_effect = list(readers.values())
        with mock.patch("auto_xdp.telemetry.geoip.importlib.import_module", return_value=module):
            return GeoIPResolver.from_config({"geoip": config})

    def test_disabled_and_missing_database_paths_need_no_dependency(self):
        with mock.patch("auto_xdp.telemetry.geoip.importlib.import_module") as importer:
            disabled = GeoIPResolver.from_config({})
            empty = GeoIPResolver.from_config({"geoip": {"enabled": True}})
        importer.assert_not_called()
        self.assertEqual(disabled.status, "disabled")
        self.assertEqual(disabled.lookup("8.8.8.8")["status"], "disabled")
        self.assertIn("no local databases", empty.status)
        self.assertEqual(set(disabled.lookup("8.8.8.8")), {
            "country_code", "country_name", "asn", "as_org", "network",
            "status", "scope", "db_updated_at",
        })

    def test_configuration_rejects_nonboolean_invalid_paths_and_unbounded_cache(self):
        invalid = [
            {"geoip": []}, {"geoip": {"enabled": "false"}},
            *({"geoip": {"cache_size": value}} for value in (True, 0, -1, 65_537, 2.5, "5")),
            *({"geoip": {"country_db": value}} for value in (None, 1, "relative.mmdb", "/bad\0path", "https://example.com/db")),
        ]
        for config in invalid:
            with self.subTest(config=config), self.assertRaises(ValueError):
                GeoIPResolver.from_config(config)

    def test_missing_dependency_and_open_error_are_readable(self):
        with mock.patch("auto_xdp.telemetry.geoip.importlib.import_module", side_effect=ImportError("not installed")):
            resolver = GeoIPResolver.from_config({"geoip": {"enabled": True, "country_db": "/missing.mmdb"}})
        self.assertIn("maxminddb unavailable", resolver.status)
        self.assertIn("unavailable", resolver.lookup("8.8.8.8")["status"])
        missing = self._resolver({"country": FileNotFoundError("missing database")})
        self.assertIn("FileNotFoundError", missing.status)

    def test_country_asn_network_and_build_times(self):
        country = self._reader({"country": {"iso_code": "US", "names": {"en": "United States"}}}, 16)
        asn = self._reader({"autonomous_system_number": 15169, "autonomous_system_organization": "Example\nOrg"}, 24)
        resolver = self._resolver({"country": country, "asn": asn})
        data = resolver.lookup("8.8.8.8")
        self.assertEqual(data, {
            "country_code": "US", "country_name": "United States", "asn": 15169,
            "as_org": "ExampleOrg", "network": "8.8.8.0/24", "scope": "global", "status": "ok",
            "db_updated_at": "country=1970-01-01T00:00:00+00:00; asn=1970-01-01T00:00:00+00:00",
        })

    def test_ipv6_and_canonical_address_cache(self):
        reader = self._reader({"autonomous_system_number": 15169}, 32)
        resolver = self._resolver({"asn": reader})
        first = resolver.lookup("2001:4860:4860:0000:0000:0000:0000:8888")
        second = resolver.lookup("2001:4860:4860::8888")
        self.assertEqual(first["network"], "2001:4860::/32")
        self.assertEqual(first, second)
        reader.get_with_prefix_len.assert_called_once_with("2001:4860:4860::8888")

    def test_mapped_ipv4_and_ipv4_database_on_ipv6(self):
        reader = self._reader({"autonomous_system_number": 15169}, version=4)
        resolver = self._resolver({"asn": reader})
        self.assertEqual(resolver.lookup("::ffff:8.8.8.8")["network"], "8.8.8.0/24")
        reader.get_with_prefix_len.assert_called_once_with("8.8.8.8")
        self.assertIn("IPv4 only", resolver.lookup("2001:4860:4860::8888")["status"])
        self.assertEqual(reader.get_with_prefix_len.call_count, 1)

    def test_special_and_invalid_addresses_are_not_queried(self):
        reader = self._reader()
        resolver = self._resolver({"country": reader})
        for ip, scope in (("127.0.0.1", "loopback"), ("::1", "loopback"),
                          ("10.0.0.1", "private"), ("100.64.0.1", "shared"),
                          ("169.254.1.1", "link_local"), ("ff02::1", "multicast"),
                          ("240.0.0.1", "reserved"), ("::", "unspecified"),
                          ("broken", "invalid"), ("fe80::1%eth0", "invalid"), (1234, "invalid")):
            with self.subTest(ip=ip):
                self.assertEqual(resolver.lookup(ip)["scope"], scope)
        reader.get_with_prefix_len.assert_not_called()

    def test_lru_is_bounded_and_return_values_cannot_corrupt_cache(self):
        reader = self._reader({"autonomous_system_number": 15169})
        resolver = self._resolver({"asn": reader}, cache_size=2)
        resolver.lookup("8.8.8.8")["asn"] = "changed"
        resolver.lookup("1.1.1.1")
        self.assertEqual(resolver.lookup("8.8.8.8")["asn"], 15169)
        resolver.lookup("9.9.9.9")
        resolver.lookup("8.8.8.8")
        self.assertEqual(reader.get_with_prefix_len.call_count, 3)
        resolver.lookup("1.1.1.1")
        self.assertEqual(reader.get_with_prefix_len.call_count, 4)

    def test_missing_records_and_corrupt_lookup_do_not_break_other_database(self):
        missing = self._resolver({"country": self._reader()})
        self.assertEqual(missing.lookup("8.8.8.8")["status"], "not found")
        for invalid in (([], 24), ({"country": "bad"}, 24), ({"country": {"iso_code": "USA"}}, 24)):
            country = self._reader()
            country.get_with_prefix_len.return_value = invalid
            resolver = self._resolver({"country": country, "asn": self._reader({"autonomous_system_number": 15169})})
            data = resolver.lookup("8.8.8.8")
            self.assertEqual(data["asn"], 15169)
            self.assertIsNone(data["country_code"])
            self.assertIn("lookup degraded", data["status"])
        reader = self._reader()
        reader.get_with_prefix_len.side_effect = RuntimeError("corrupt record")
        self.assertIn("corrupt record", self._resolver({"country": reader}).lookup("8.8.8.8")["status"])

    def test_metadata_failure_closes_reader_and_partial_load_stays_usable(self):
        country = self._reader()
        country.metadata.side_effect = RuntimeError("corrupt metadata")
        asn = self._reader({"autonomous_system_number": 15169})
        resolver = self._resolver({"country": country, "asn": asn})
        country.close.assert_called_once()
        self.assertIn("degraded", resolver.status)
        self.assertEqual(resolver.lookup("8.8.8.8")["asn"], 15169)
        self.assertIn("corrupt metadata", resolver.lookup("8.8.8.8")["status"])

    def test_close_releases_all_readers_and_prevents_cached_reads(self):
        country, asn = self._reader(), self._reader()
        country.close.side_effect = OSError("close failed")
        resolver = self._resolver({"country": country, "asn": asn})
        resolver.lookup("8.8.8.8")
        resolver.close()
        resolver.close()
        country.close.assert_called_once()
        asn.close.assert_called_once()
        self.assertEqual(resolver.lookup("8.8.8.8")["status"], "closed")


if __name__ == "__main__":
    unittest.main()
