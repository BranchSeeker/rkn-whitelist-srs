"""Unit tests for the whitelist parser (no network or sing-box required)."""

from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("whitelist_build", ROOT / "scripts" / "build.py")
assert SPEC is not None and SPEC.loader is not None
build = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(build)


class CleanLineTests(unittest.TestCase):
    def test_comments_and_attributes(self) -> None:
        self.assertEqual(build.clean_line("# comment"), "")
        self.assertEqual(build.clean_line("// comment"), "")
        self.assertEqual(build.clean_line("domain:example.com # note"), "domain:example.com")
        self.assertEqual(build.clean_line("domain:example.com @cn"), "domain:example.com")
        self.assertEqual(build.clean_line("  domain:example.com  "), "domain:example.com")

    def test_regex_with_slashes_survives(self) -> None:
        self.assertEqual(build.clean_line(r"regexp:^https?://"), r"regexp:^https?://")


class DomainTests(unittest.TestCase):
    def test_normalize(self) -> None:
        self.assertEqual(build.normalize_domain("Example.COM."), "example.com")
        self.assertEqual(build.normalize_domain("*.example.com", allow_wildcard=True), "example.com")
        self.assertEqual(build.normalize_domain("*.example.com"), None)
        self.assertEqual(build.normalize_domain("münich.example"), "xn--mnich-kva.example")

    def test_parse_directives(self) -> None:
        text = """
        # comment
        domain:Example.COM
        full:exact.example
        keyword:tracker
        regexp:^ads\\.
        plain.example
        include:other-list
        domain:bad domain
        """
        rules, stats, unknown = build.parse_geosite(text, min_domains=1)
        self.assertEqual(rules["domain_suffix"], ["example.com", "plain.example"])
        self.assertEqual(rules["domain"], ["exact.example"])
        self.assertEqual(rules["domain_keyword"], ["tracker"])
        self.assertEqual(rules["domain_regex"], [r"^ads\."])
        self.assertEqual(unknown, {})
        self.assertEqual(stats["invalid"], 1)
        self.assertEqual(stats["include_skipped"], 1)

    def test_plain_line_is_suffix(self) -> None:
        rules, _stats, _unknown = build.parse_geosite("example.org\n", min_domains=1)
        self.assertEqual(rules, {"domain_suffix": ["example.org"]})

    def test_threshold_fails_loudly(self) -> None:
        with self.assertRaises(build.BuildError):
            build.parse_geosite("example.org\n", min_domains=10)


class CidrTests(unittest.TestCase):
    def test_normalize_dedupe_and_skip(self) -> None:
        text = """
        # comment
        192.0.2.1
        192.0.2.0/24
        192.0.2.0/24
        2001:db8::1/128
        not-a-cidr
        """
        cidrs, stats = build.parse_cidr(text, min_cidrs=1)
        self.assertEqual(cidrs, ["192.0.2.0/24", "192.0.2.1/32", "2001:db8::1/128"])
        self.assertEqual(stats["invalid"], 1)
        self.assertEqual(stats["unique"], 3)

    def test_threshold_fails_loudly(self) -> None:
        with self.assertRaises(build.BuildError):
            build.parse_cidr("192.0.2.0/24\n", min_cidrs=10)


class SourceJsonTests(unittest.TestCase):
    def test_domain_source_shape(self) -> None:
        source = build.make_domain_source(
            {
                "domain": ["exact.example"],
                "domain_suffix": ["example.com"],
                "domain_keyword": ["tracker"],
                "domain_regex": [r"^ads\\."],
            }
        )
        self.assertEqual(source["version"], 3)
        self.assertEqual(source["rules"][0]["domain"], ["exact.example"])
        self.assertEqual(source["rules"][0]["domain_suffix"], ["example.com"])

    def test_empty_domain_source(self) -> None:
        self.assertEqual(build.make_domain_source({}), {"version": 3, "rules": []})

    def test_ip_source_shape(self) -> None:
        self.assertEqual(
            build.make_ip_source(["192.0.2.0/24"]),
            {"version": 3, "rules": [{"ip_cidr": ["192.0.2.0/24"]}]},
        )


if __name__ == "__main__":
    unittest.main()
