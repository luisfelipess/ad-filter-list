"""Tests for merge.py — covers readers, load_list_file,
remove_subdomains, and end-to-end merge output."""

import gzip
import json
import os
import sys
import tempfile
import unittest

# ensure repo root is on the path when running from tests/
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import merge as m
from readers import normalize_domain
from readers.hosts import HostsReader
from readers.domain import DomainReader
from readers.adblock import AdblockReader


# ── readers + normalize_domain ────────────────────────────────────────────────

def _extract(reader, line):
    result = reader.extract(line.strip())
    if result is None:
        return None
    raw, _ = result
    return normalize_domain(raw) if raw else None


def _extract_wc(reader, line):
    """Return (domain, is_wildcard) or None."""
    result = reader.extract(line.strip())
    if result is None:
        return None
    raw, is_wildcard = result
    dom = normalize_domain(raw) if raw else None
    return (dom, is_wildcard) if dom else None


class TestHostsReader(unittest.TestCase):
    def setUp(self):
        self.r = HostsReader()

    def test_0000(self):
        self.assertEqual(_extract(self.r, "0.0.0.0 example.com"), "example.com")

    def test_127(self):
        self.assertEqual(_extract(self.r, "127.0.0.1 example.com"), "example.com")

    def test_ipv6(self):
        self.assertEqual(_extract(self.r, "::1 example.com"), "example.com")

    def test_uppercase_normalised(self):
        self.assertEqual(_extract(self.r, "0.0.0.0 EXAMPLE.COM"), "example.com")

    def test_rejects_localhost(self):
        self.assertIsNone(_extract(self.r, "0.0.0.0 localhost"))

    def test_rejects_arbitrary_ip(self):
        self.assertIsNone(_extract(self.r, "1.2.3.4 example.com"))

    def test_detect(self):
        self.assertTrue(self.r.detect(["0.0.0.0 example.com"]))
        self.assertFalse(self.r.detect(["example.com"]))


class TestDomainReader(unittest.TestCase):
    def setUp(self):
        self.r = DomainReader()

    def test_bare_domain(self):
        self.assertEqual(_extract(self.r, "example.com"), "example.com")

    def test_uppercase_normalised(self):
        self.assertEqual(_extract(self.r, "EXAMPLE.COM"), "example.com")

    def test_rejects_ip(self):
        self.assertIsNone(_extract(self.r, "1.2.3.4"))

    def test_detect(self):
        self.assertTrue(self.r.detect(["example.com"]))
        self.assertFalse(self.r.detect(["0.0.0.0 example.com"]))

    def test_wildcard_line(self):
        self.assertEqual(_extract(self.r, "*.example.com"), "example.com")

    def test_wildcard_is_flagged(self):
        self.assertEqual(_extract_wc(self.r, "*.example.com"), ("example.com", True))

    def test_exact_not_flagged(self):
        self.assertEqual(_extract_wc(self.r, "example.com"), ("example.com", False))

    def test_classify_plain_returns_domain_only(self):
        sample = ["example.com", "other.org", "third.net"]
        self.assertEqual(self.r.classify(sample), "domain-only")

    def test_classify_all_wildcards_returns_wildcard_domain(self):
        sample = ["*.a.com", "*.b.com", "*.c.com"]
        self.assertEqual(self.r.classify(sample), "wildcard-domain")

    def test_classify_near_pure_wildcard_returns_wildcard_domain(self):
        # 10/11 wildcards (>90%) → wildcard-domain
        sample = ["*.a.com"] * 10 + ["plain.com"]
        self.assertEqual(self.r.classify(sample), "wildcard-domain")

    def test_classify_mixed_returns_mixed_domain(self):
        sample = ["*.a.com", "*.b.com", "plain.com", "other.org"]  # 50% wildcards
        self.assertEqual(self.r.classify(sample), "mixed-domain")

    def test_classify_ignores_comment_lines(self):
        sample = ["# header", "*.a.com", "*.b.com", "*.c.com"]
        self.assertEqual(self.r.classify(sample), "wildcard-domain")


class TestAdblockReader(unittest.TestCase):
    def setUp(self):
        self.r = AdblockReader()

    def test_adblock_line(self):
        self.assertEqual(_extract(self.r, "||example.com^"), "example.com")

    def test_rejects_non_adblock(self):
        self.assertIsNone(_extract(self.r, "example.com"))

    def test_detect(self):
        self.assertTrue(self.r.detect(["||example.com^"]))
        self.assertFalse(self.r.detect(["example.com"]))


class TestNormalizeDomain(unittest.TestCase):
    def test_strips_quotes(self):
        self.assertEqual(normalize_domain('"example.com"'), "example.com")

    def test_rejects_localhost(self):
        self.assertIsNone(normalize_domain("localhost"))

    def test_rejects_plain_ip(self):
        self.assertIsNone(normalize_domain("1.2.3.4"))

    def test_rejects_empty(self):
        self.assertIsNone(normalize_domain(""))

    def test_rejects_ipv6(self):
        self.assertIsNone(normalize_domain("2001:db8::1"))

    def test_rejects_ipv6_loopback(self):
        self.assertIsNone(normalize_domain("::1"))

    def test_rejects_bare_label(self):
        self.assertIsNone(normalize_domain("nodot"))

    def test_rejects_long_label(self):
        self.assertIsNone(normalize_domain("a" * 64 + ".com"))

    def test_rejects_invalid_chars(self):
        self.assertIsNone(normalize_domain("foo_bar.com"))

    def test_rejects_label_leading_hyphen(self):
        self.assertIsNone(normalize_domain("-bad.com"))

    def test_rejects_label_trailing_hyphen(self):
        self.assertIsNone(normalize_domain("bad-.com"))

    def test_idn_to_punycode(self):
        self.assertEqual(normalize_domain("münchen.de"), "xn--mnchen-3ya.de")


# ── load_list_file / allowlist / blocklist ────────────────────────────────────

class TestLoadListFile(unittest.TestCase):

    def test_loads_exact_domains(self):
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as f:
            f.write("# comment\nexample.com\ngood.org\n")
            path = f.name
        try:
            result = m.load_list_file(path)
            self.assertEqual(result.exact, {"example.com", "good.org"})
            self.assertEqual(result.wildcards, set())
        finally:
            os.unlink(path)

    def test_missing_file_returns_empty(self):
        result = m.load_list_file("/nonexistent/list.txt")
        self.assertEqual(result.exact, set())
        self.assertEqual(result.wildcards, set())

    def test_ignores_comment_prefixes(self):
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as f:
            f.write("! exclaim\n; semicolon\n# hash\nkeep.com\n")
            path = f.name
        try:
            result = m.load_list_file(path)
            self.assertEqual(result.exact, {"keep.com"})
        finally:
            os.unlink(path)

    def test_strips_inline_comment(self):
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as f:
            f.write("keep.com  # reason\n")
            path = f.name
        try:
            self.assertEqual(m.load_list_file(path).exact, {"keep.com"})
        finally:
            os.unlink(path)

    def test_normalises_to_lowercase(self):
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as f:
            f.write("UPPER.COM\n")
            path = f.name
        try:
            self.assertIn("upper.com", m.load_list_file(path).exact)
        finally:
            os.unlink(path)

    def test_wildcard_splits_to_base(self):
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as f:
            f.write("*.example.com\nplain.org\n")
            path = f.name
        try:
            result = m.load_list_file(path)
            self.assertEqual(result.exact, {"plain.org"})
            self.assertEqual(result.wildcards, {"example.com"})
        finally:
            os.unlink(path)


class TestListEntriesMatches(unittest.TestCase):
    """*.example.com matches subdomains only, not the apex unless listed exactly."""

    def setUp(self):
        self.entries = m.ListEntries(exact={"example.com"}, wildcards={"allowed.com"})

    def test_exact_match(self):
        self.assertTrue(self.entries.matches("example.com"))

    def test_wildcard_matches_subdomain(self):
        self.assertTrue(self.entries.matches("sub.allowed.com"))
        self.assertTrue(self.entries.matches("a.b.allowed.com"))

    def test_wildcard_does_not_match_apex(self):
        self.assertFalse(self.entries.matches("allowed.com"))

    def test_unrelated_domain(self):
        self.assertFalse(self.entries.matches("other.org"))


class TestSubdomainMatchesWildcards(unittest.TestCase):
    def test_matches_proper_subdomain(self):
        self.assertTrue(m.subdomain_matches_wildcards("ads.example.com", {"example.com"}))

    def test_does_not_match_apex(self):
        self.assertFalse(m.subdomain_matches_wildcards("example.com", {"example.com"}))


class TestLoadAllowlist(unittest.TestCase):

    def test_load_allowlist_delegates_to_load_list_file(self):
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as f:
            f.write("*.safe.com\n")
            path = f.name
        try:
            result = m.load_allowlist(path)
            self.assertEqual(result.wildcards, {"safe.com"})
        finally:
            os.unlink(path)


class TestLoadBlocklist(unittest.TestCase):

    def test_load_blocklist_delegates_to_load_list_file(self):
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as f:
            f.write("block.com\n")
            path = f.name
        try:
            result = m.load_blocklist(path)
            self.assertEqual(result.exact, {"block.com"})
        finally:
            os.unlink(path)


# ── remove_subdomains ─────────────────────────────────────────────────────────

class TestRemoveSubdomains(unittest.TestCase):

    def test_removes_subdomain_when_parent_present(self):
        result = m.remove_subdomains(["example.com", "ads.example.com"])
        self.assertIn("example.com", result)
        self.assertNotIn("ads.example.com", result)

    def test_removes_deep_subdomain(self):
        result = m.remove_subdomains(["example.com", "a.b.example.com"])
        self.assertNotIn("a.b.example.com", result)

    def test_keeps_unrelated_domains(self):
        result = m.remove_subdomains(["example.com", "other.org"])
        self.assertIn("other.org", result)

    def test_keeps_subdomain_when_parent_absent(self):
        result = m.remove_subdomains(["ads.example.com"])
        self.assertIn("ads.example.com", result)

    def test_empty_list(self):
        self.assertEqual(m.remove_subdomains([]), [])

    def test_no_redundancy(self):
        domains = ["alpha.com", "beta.org", "gamma.net"]
        self.assertEqual(sorted(m.remove_subdomains(domains)), sorted(domains))

    def test_does_not_remove_sibling(self):
        # ads.example.com and track.example.com are siblings — neither removes the other
        result = m.remove_subdomains(["ads.example.com", "track.example.com"])
        self.assertIn("ads.example.com", result)
        self.assertIn("track.example.com", result)

    def test_wildcard_base_does_not_remove_covered_exact(self):
        # wildcard base (ads.example.com from *.ads.example.com) must NOT cause
        # tracker.ads.example.com to be removed — only truly explicit parent entries
        # (non-wildcard-derived) trigger subdomain removal.
        result = m.remove_subdomains(
            ["ads.example.com", "tracker.ads.example.com"],
            wildcard_domains={"ads.example.com"}
        )
        self.assertIn("tracker.ads.example.com", result)


# ── end-to-end merge ──────────────────────────────────────────────────────────

class TestMergeEndToEnd(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.raw_dir = os.path.join(self.tmp, "raw")
        self.out_dir = os.path.join(self.tmp, "processed")
        os.makedirs(self.raw_dir)
        os.makedirs(self.out_dir)
        self.out_path = os.path.join(self.out_dir, "blocklist.txt")
        self.map_path = os.path.join(self.raw_dir, "sources.map")

    def _write_source(self, fname, content):
        path = os.path.join(self.raw_dir, fname)
        with open(path, "w") as f:
            f.write(content)
        with open(self.map_path, "a") as mf:
            mf.write(f"{fname} http://example.com/{fname}\n")

    def _write_allowlist(self, content):
        path = os.path.join(self.tmp, "allowlist.txt")
        with open(path, "w") as f:
            f.write(content)
        return path

    def _read_hosts(self):
        if not os.path.exists(self.out_path):
            return []
        with open(self.out_path) as f:
            return [
                line.split()[1]
                for line in f
                if line.strip() and not line.startswith("#")
            ]

    def test_basic_deduplication(self):
        self._write_source("01_a.txt", "0.0.0.0 dup.com\n0.0.0.0 dup.com\n0.0.0.0 other.com\n")
        m.merge(self.raw_dir, self.map_path, self.out_path, optimize_subdomains=False)
        domains = self._read_hosts()
        self.assertEqual(domains.count("dup.com"), 1)

    def test_allowlist_filters_domain(self):
        self._write_source("01_a.txt", "0.0.0.0 blocked.com\n0.0.0.0 safe.com\n")
        al = self._write_allowlist("safe.com\n")
        m.merge(self.raw_dir, self.map_path, self.out_path,
                allowlist_path=al, optimize_subdomains=False)
        domains = self._read_hosts()
        self.assertIn("blocked.com", domains)
        self.assertNotIn("safe.com", domains)

    def _read_report_summary(self):
        report_path = os.path.join(self.tmp, "reports", "blocklist-report.json")
        with open(report_path) as f:
            return json.loads(f.read())["summary"]

    def test_allowlist_wildcard_supersedes_source_subdomain(self):
        """*.youtube.com allowlist drops ads.youtube.com from sources (allowlist wins)."""
        self._write_source(
            "01_a.txt",
            "0.0.0.0 ads.youtube.com\n0.0.0.0 other.com\n",
        )
        al = self._write_allowlist("*.youtube.com\n")
        m.merge(self.raw_dir, self.map_path, self.out_path,
                allowlist_path=al, optimize_subdomains=False)
        domains = self._read_hosts()
        self.assertNotIn("ads.youtube.com", domains)
        self.assertIn("other.com", domains)
        summary = self._read_report_summary()
        self.assertEqual(summary["matched_allowlisted"], 1)
        self.assertEqual(summary["added_by_blocklist_override"], 0)

    def test_matched_allowlisted_counts_unique_domains_only(self):
        self._write_source(
            "01_a.txt",
            "0.0.0.0 skip.com\n0.0.0.0 skip.com\n0.0.0.0 keep.com\n",
        )
        al = self._write_allowlist("skip.com\n")
        m.merge(self.raw_dir, self.map_path, self.out_path,
                allowlist_path=al, optimize_subdomains=False)
        summary = self._read_report_summary()
        self.assertEqual(summary["matched_allowlisted"], 1)

    def test_added_by_blocklist_override_in_report(self):
        self._write_source("01_a.txt", "0.0.0.0 other.com\n")
        bl = os.path.join(self.tmp, "blocklist.txt")
        with open(bl, "w") as f:
            f.write("forced.com\n*.wildcard-forced.com\n")
        m.merge(self.raw_dir, self.map_path, self.out_path,
                blocklist_path=bl, allowlist_path=self._write_allowlist(""),
                optimize_subdomains=False)
        summary = self._read_report_summary()
        self.assertEqual(summary["added_by_blocklist_override"], 2)
        self.assertEqual(summary["matched_allowlisted"], 0)

    def test_allowlist_wildcard_filters_subdomains_not_apex(self):
        self._write_source(
            "01_a.txt",
            "0.0.0.0 example.com\n0.0.0.0 safe.com\n"
            "0.0.0.0 sub.safe.com\n0.0.0.0 deep.sub.safe.com\n",
        )
        al = self._write_allowlist("*.safe.com\n")
        m.merge(self.raw_dir, self.map_path, self.out_path,
                allowlist_path=al, optimize_subdomains=False)
        domains = self._read_hosts()
        self.assertIn("example.com", domains)
        self.assertIn("safe.com", domains)
        self.assertNotIn("sub.safe.com", domains)
        self.assertNotIn("deep.sub.safe.com", domains)

    def test_allowlist_wildcard_apex_requires_explicit_entry(self):
        self._write_source("01_a.txt", "0.0.0.0 safe.com\n0.0.0.0 sub.safe.com\n")
        al = self._write_allowlist("*.safe.com\nsafe.com\n")
        m.merge(self.raw_dir, self.map_path, self.out_path,
                allowlist_path=al, optimize_subdomains=False)
        domains = self._read_hosts()
        self.assertNotIn("safe.com", domains)
        self.assertNotIn("sub.safe.com", domains)

    def test_blocklist_wildcard_forces_subdomain_coverage(self):
        self._write_source("01_a.txt", "0.0.0.0 other.com\n")
        bl = os.path.join(self.tmp, "blocklist.txt")
        with open(bl, "w") as f:
            f.write("*.forced.com\n")
        m.merge(self.raw_dir, self.map_path, self.out_path,
                blocklist_path=bl, allowlist_path=self._write_allowlist(""),
                optimize_subdomains=False)
        domains = self._read_hosts()
        self.assertIn("forced.com", domains)
        adblock_path = os.path.join(self.out_dir, "blocklist-adblock.txt")
        with open(adblock_path) as f:
            content = f.read()
        self.assertIn("||*.forced.com^", content)

    def test_blocklist_forces_domain(self):
        self._write_source("01_a.txt", "0.0.0.0 blocked.com\n")
        bl = os.path.join(self.tmp, "blocklist.txt")
        with open(bl, "w") as f:
            f.write("forceblock.com\n")
        m.merge(self.raw_dir, self.map_path, self.out_path,
                blocklist_path=bl, allowlist_path=self._write_allowlist(""), optimize_subdomains=False)
        domains = self._read_hosts()
        self.assertIn("blocked.com", domains)
        self.assertIn("forceblock.com", domains)

    def test_blocklist_does_not_override_allowlist(self):
        self._write_source("01_a.txt", "0.0.0.0 blocked.com\n")
        al = self._write_allowlist("forceblock.com\n")
        bl = os.path.join(self.tmp, "blocklist.txt")
        with open(bl, "w") as f:
            f.write("forceblock.com\n")
        m.merge(self.raw_dir, self.map_path, self.out_path,
                blocklist_path=bl, allowlist_path=al, optimize_subdomains=False)
        domains = self._read_hosts()
        self.assertIn("blocked.com", domains)
        self.assertNotIn("forceblock.com", domains)

    def test_subdomain_optimizer_removes_redundant_in_dns_formats(self):
        # Hosts file always keeps every unique entry; DNS formats (dnsmasq/unbound/etc.)
        # drop subdomains whose parent is already present.
        self._write_source("01_a.txt", "0.0.0.0 example.com\n0.0.0.0 ads.example.com\n")
        m.merge(self.raw_dir, self.map_path, self.out_path,
                allowlist_path=self._write_allowlist(""), optimize_subdomains=True)
        hosts_domains = self._read_hosts()
        self.assertIn("example.com", hosts_domains)
        self.assertIn("ads.example.com", hosts_domains)  # hosts never optimizes
        dnsmasq_path = os.path.join(self.out_dir, "blocklist-dnsmasq.conf")
        with open(dnsmasq_path) as f:
            dnsmasq = f.read()
        self.assertIn("address=/example.com/#", dnsmasq)
        self.assertNotIn("address=/ads.example.com/#", dnsmasq)  # removed by optimizer

    def test_subdomain_optimizer_disabled(self):
        # With optimize_subdomains=False, DNS formats also keep every unique entry.
        self._write_source("01_a.txt", "0.0.0.0 example.com\n0.0.0.0 ads.example.com\n")
        m.merge(self.raw_dir, self.map_path, self.out_path,
                allowlist_path=self._write_allowlist(""), optimize_subdomains=False)
        hosts_domains = self._read_hosts()
        self.assertIn("example.com", hosts_domains)
        self.assertIn("ads.example.com", hosts_domains)
        dnsmasq_path = os.path.join(self.out_dir, "blocklist-dnsmasq.conf")
        with open(dnsmasq_path) as f:
            dnsmasq = f.read()
        self.assertIn("address=/example.com/#", dnsmasq)
        self.assertIn("address=/ads.example.com/#", dnsmasq)

    def test_adblock_output_written(self):
        self._write_source("01_a.txt", "0.0.0.0 example.com\n")
        m.merge(self.raw_dir, self.map_path, self.out_path,
                allowlist_path=self._write_allowlist(""), optimize_subdomains=False)
        adblock_path = os.path.join(self.out_dir, "blocklist-adblock.txt")
        self.assertTrue(os.path.exists(adblock_path))
        with open(adblock_path) as f:
            content = f.read()
        self.assertIn("||example.com^", content)

    def test_rpz_output_written_and_valid(self):
        self._write_source("01_a.txt", "0.0.0.0 example.com\n")
        m.merge(self.raw_dir, self.map_path, self.out_path,
                allowlist_path=self._write_allowlist(""), optimize_subdomains=False)
        rpz_path = os.path.join(self.out_dir, "blocklist-bind9.zone.gz")
        self.assertTrue(os.path.exists(rpz_path))
        content = gzip.open(rpz_path, "rt").read()
        self.assertIn("ns.rpz.local.", content)
        self.assertIn("ns IN A 127.0.0.1", content)
        self.assertIn("example.com IN CNAME .", content)
        self.assertIn("*.example.com IN CNAME .", content)

    def test_json_report_written(self):
        self._write_source("01_a.txt", "0.0.0.0 example.com\n")
        m.merge(self.raw_dir, self.map_path, self.out_path,
                allowlist_path=self._write_allowlist(""), optimize_subdomains=False)
        report_path = os.path.join(self.tmp, "reports", "blocklist-report.json")
        self.assertTrue(os.path.exists(report_path))
        with open(report_path) as f:
            report = json.loads(f.read())
        self.assertIn("summary", report)
        self.assertIn("sources", report)
        self.assertIn("matched_allowlisted", report["summary"])
        self.assertIn("added_by_blocklist_override", report["summary"])

    def test_wildcard_domain_source_classified_correctly(self):
        """A file whose lines are all *.domain must be classified as wildcard-domain."""
        self._write_source("01_wc.txt", "*.example.com\n*.other.org\n*.third.net\n")
        m.merge(self.raw_dir, self.map_path, self.out_path,
                allowlist_path=self._write_allowlist(""), optimize_subdomains=False)
        report_path = os.path.join(self.tmp, "reports", "blocklist-report.json")
        with open(report_path) as f:
            report = json.loads(f.read())
        self.assertEqual(report["sources"]["01_wc.txt"]["format"], "wildcard-domain")

    def test_json_report_has_both_reduction_breakdowns(self):
        # Both dedup-only (hosts/domains) and subdomain-optimized (DNS) stats must be present.
        self._write_source("01_a.txt", "0.0.0.0 example.com\n0.0.0.0 ads.example.com\n")
        m.merge(self.raw_dir, self.map_path, self.out_path,
                allowlist_path=self._write_allowlist(""), optimize_subdomains=True)
        summary = self._read_report_summary()
        self.assertIn("unique_deduped", summary)
        self.assertIn("reduction_pct_deduped", summary)
        self.assertIn("unique_optimized", summary)
        self.assertIn("reduction_pct_optimized", summary)
        # dedup-only count must be >= optimized count
        self.assertGreaterEqual(summary["unique_deduped"], summary["unique_optimized"])

    def test_domain_only_source_format(self):
        self._write_source("01_a.txt", "example.com\nother.org\n")
        m.merge(self.raw_dir, self.map_path, self.out_path,
                allowlist_path=self._write_allowlist(""), optimize_subdomains=False)
        domains = self._read_hosts()
        self.assertIn("example.com", domains)
        self.assertIn("other.org", domains)

    def test_dnsmasq_output_written(self):
        self._write_source("01_a.txt", "0.0.0.0 example.com\n")
        m.merge(self.raw_dir, self.map_path, self.out_path,
                allowlist_path=self._write_allowlist(""), optimize_subdomains=False)
        path = os.path.join(self.out_dir, "blocklist-dnsmasq.conf")
        self.assertTrue(os.path.exists(path))
        with open(path) as f:
            content = f.read()
        self.assertIn("address=/example.com/#", content)

    def test_unbound_output_written(self):
        self._write_source("01_a.txt", "0.0.0.0 example.com\n")
        m.merge(self.raw_dir, self.map_path, self.out_path,
                allowlist_path=self._write_allowlist(""), optimize_subdomains=False)
        path = os.path.join(self.out_dir, "blocklist-unbound.conf")
        self.assertTrue(os.path.exists(path))
        with open(path) as f:
            content = f.read()
        self.assertIn('local-zone: "example.com." always_nxdomain', content)

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp)


class TestIanaTldValidation(unittest.TestCase):
    """IANA TLD filter tests — use _valid_tlds to avoid network calls."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.raw_dir = os.path.join(self.tmp, "raw")
        self.out_dir = os.path.join(self.tmp, "processed")
        os.makedirs(self.raw_dir)
        os.makedirs(self.out_dir)
        self.out_path = os.path.join(self.out_dir, "blocklist.txt")
        self.map_path = os.path.join(self.raw_dir, "sources.map")

    def _write_source(self, fname, content):
        path = os.path.join(self.raw_dir, fname)
        with open(path, "w") as f:
            f.write(content)
        with open(self.map_path, "a") as mf:
            mf.write(f"{fname} http://example.com/{fname}\n")

    def _read_hosts(self):
        with open(self.out_path) as f:
            return [line.split()[1] for line in f if line.strip() and not line.startswith("#")]

    def _read_report(self):
        with open(os.path.join(self.tmp, "reports", "blocklist-report.json")) as f:
            return json.loads(f.read())["summary"]

    def test_valid_tld_accepted(self):
        self._write_source("01.txt", "0.0.0.0 example.com\n")
        m.merge(self.raw_dir, self.map_path, self.out_path,
                _valid_tlds={"com", "org", "net"}, optimize_subdomains=False)
        self.assertIn("example.com", self._read_hosts())

    def test_invalid_tld_rejected(self):
        self._write_source("01.txt", "0.0.0.0 example.invalid\n0.0.0.0 keep.com\n")
        m.merge(self.raw_dir, self.map_path, self.out_path,
                _valid_tlds={"com", "org", "net"}, optimize_subdomains=False)
        domains = self._read_hosts()
        self.assertNotIn("example.invalid", domains)
        self.assertIn("keep.com", domains)

    def test_tld_rejected_counted_in_report(self):
        self._write_source("01.txt", "0.0.0.0 example.fake\n0.0.0.0 keep.com\n")
        m.merge(self.raw_dir, self.map_path, self.out_path,
                _valid_tlds={"com"}, optimize_subdomains=False)
        self.assertEqual(self._read_report()["tld_rejected"], 1)

    def test_skip_iana_check_accepts_any_tld(self):
        self._write_source("01.txt", "0.0.0.0 example.fake\n")
        m.merge(self.raw_dir, self.map_path, self.out_path,
                skip_iana_check=True, optimize_subdomains=False)
        self.assertIn("example.fake", self._read_hosts())

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp)


class TestTiers(unittest.TestCase):
    """Tests for multi-tier output support."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.raw_dir = os.path.join(self.tmp, "raw")
        self.out_dir = os.path.join(self.tmp, "processed")
        os.makedirs(self.raw_dir)
        os.makedirs(self.out_dir)
        self.out_path = os.path.join(self.out_dir, "blocklist.txt")
        self.map_path = os.path.join(self.raw_dir, "sources.map")
        self.tiers_conf = os.path.join(self.tmp, "tiers.conf")

    def _write_tiers(self, content: str) -> str:
        with open(self.tiers_conf, "w") as f:
            f.write(content)
        return self.tiers_conf

    def _write_source(self, fname: str, content: str, tier: str = "") -> None:
        with open(os.path.join(self.raw_dir, fname), "w") as f:
            f.write(content)
        with open(self.map_path, "a") as mf:
            line = f"{fname} http://example.com/{fname} {tier}" if tier else f"{fname} http://example.com/{fname}"
            mf.write(line + "\n")

    def _read_hosts(self, path: str | None = None) -> list[str]:
        p = path or self.out_path
        with open(p) as f:
            return [ln.split()[1] for ln in f if ln.strip() and not ln.startswith("#")]

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp)

    def test_no_tiers_conf_single_default_tier(self):
        # When tiers.conf is absent the pipeline runs exactly as before.
        self._write_source("01_a.txt", "0.0.0.0 example.com\n")
        m.merge(self.raw_dir, self.map_path, self.out_path,
                skip_iana_check=True, optimize_subdomains=False,
                tiers_config=os.path.join(self.tmp, "missing-tiers.conf"))
        self.assertIn("example.com", self._read_hosts())
        # No subdirectories created
        subdirs = [d for d in os.listdir(self.out_dir) if os.path.isdir(os.path.join(self.out_dir, d))]
        self.assertEqual(subdirs, [])

    def test_default_tier_outputs_at_root(self):
        # Default tier (good *) writes to processed/ root, not a subdirectory.
        self._write_tiers("light\ngood *\naggressive\n")
        self._write_source("01_a.txt", "0.0.0.0 example.com\n", tier="good")
        m.merge(self.raw_dir, self.map_path, self.out_path,
                skip_iana_check=True, optimize_subdomains=False,
                tiers_config=self.tiers_conf)
        self.assertIn("example.com", self._read_hosts())
        self.assertFalse(os.path.isdir(os.path.join(self.out_dir, "good")))

    def test_empty_tier_dir_not_created(self):
        # light dir must NOT be created when no light-tagged sources exist
        # (good sources propagate up to aggressive, not down to light).
        self._write_tiers("light\ngood *\naggressive\n")
        self._write_source("01_a.txt", "0.0.0.0 example.com\n", tier="good")
        m.merge(self.raw_dir, self.map_path, self.out_path,
                skip_iana_check=True, optimize_subdomains=False,
                tiers_config=self.tiers_conf)
        self.assertFalse(os.path.isdir(os.path.join(self.out_dir, "light")))
        # aggressive IS created — good sources propagate up to it
        self.assertTrue(os.path.isdir(os.path.join(self.out_dir, "aggressive")))

    def test_tier_filtering_cumulative(self):
        # light source → light, good, aggressive
        # good source  → good, aggressive only
        # aggressive source → aggressive only
        self._write_tiers("light\ngood *\naggressive\n")
        self._write_source("01_a.txt", "0.0.0.0 light-only.com\n", tier="light")
        self._write_source("02_b.txt", "0.0.0.0 good-domain.com\n", tier="good")
        self._write_source("03_c.txt", "0.0.0.0 aggressive-only.com\n", tier="aggressive")
        m.merge(self.raw_dir, self.map_path, self.out_path,
                skip_iana_check=True, optimize_subdomains=False,
                tiers_config=self.tiers_conf)

        light_path = os.path.join(self.out_dir, "light", "blocklist.txt")
        good_path = self.out_path  # default tier → root
        aggressive_path = os.path.join(self.out_dir, "aggressive", "blocklist.txt")

        light_domains = self._read_hosts(light_path)
        good_domains = self._read_hosts(good_path)
        aggressive_domains = self._read_hosts(aggressive_path)

        # light tier: only light-tagged source
        self.assertIn("light-only.com", light_domains)
        self.assertNotIn("good-domain.com", light_domains)
        self.assertNotIn("aggressive-only.com", light_domains)

        # good tier: light + good sources
        self.assertIn("light-only.com", good_domains)
        self.assertIn("good-domain.com", good_domains)
        self.assertNotIn("aggressive-only.com", good_domains)

        # aggressive tier: all sources
        self.assertIn("light-only.com", aggressive_domains)
        self.assertIn("good-domain.com", aggressive_domains)
        self.assertIn("aggressive-only.com", aggressive_domains)

    def test_domain_shared_by_multiple_tiers_uses_lowest(self):
        # shared.com appears in both light and good sources → should appear in light tier.
        self._write_tiers("light\ngood *\naggressive\n")
        self._write_source("01_a.txt", "0.0.0.0 shared.com\n", tier="light")
        self._write_source("02_b.txt", "0.0.0.0 shared.com\n0.0.0.0 good-only.com\n", tier="good")
        m.merge(self.raw_dir, self.map_path, self.out_path,
                skip_iana_check=True, optimize_subdomains=False,
                tiers_config=self.tiers_conf)
        light_path = os.path.join(self.out_dir, "light", "blocklist.txt")
        self.assertIn("shared.com", self._read_hosts(light_path))
        self.assertNotIn("good-only.com", self._read_hosts(light_path))

    def test_untagged_source_defaults_to_default_tier(self):
        # Untagged sources default to good (the * tier) and appear in good + aggressive.
        self._write_tiers("light\ngood *\naggressive\n")
        self._write_source("01_a.txt", "0.0.0.0 example.com\n")  # no tier tag
        m.merge(self.raw_dir, self.map_path, self.out_path,
                skip_iana_check=True, optimize_subdomains=False,
                tiers_config=self.tiers_conf)
        # Appears in root (good tier)
        self.assertIn("example.com", self._read_hosts())
        # light tier has no sources → no dir
        self.assertFalse(os.path.isdir(os.path.join(self.out_dir, "light")))

    def test_json_report_has_tier_metadata(self):
        self._write_tiers("light\ngood *\naggressive\n")
        self._write_source("01_a.txt", "0.0.0.0 example.com\n", tier="light")
        m.merge(self.raw_dir, self.map_path, self.out_path,
                skip_iana_check=True, optimize_subdomains=False,
                tiers_config=self.tiers_conf)
        with open(os.path.join(self.tmp, "reports", "blocklist-report.json")) as f:
            report = json.load(f)
        self.assertEqual(report["default_tier"], "good")
        self.assertEqual(report["tiers"], ["light", "good", "aggressive"])
        # light is a non-default tier with output → in tier_summaries
        self.assertIn("tier_summaries", report["summary"])
        self.assertIn("light", report["summary"]["tier_summaries"])
        # light source propagates up → aggressive also has the domain
        self.assertEqual(report["summary"]["tier_summaries"].get("aggressive", {}).get("unique_deduped", 0), 1)


class TestSourceHealth(unittest.TestCase):
    """Unit tests for _source_health — no file I/O needed."""

    def _stats(self, scanned=100, accepted=100, rejected=0, net_new=50, skipped=False):
        return {
            "scanned": scanned,
            "accepted": accepted,
            "rejected": rejected,
            "net_new": net_new,
            "skipped": skipped,
        }

    def test_ok(self):
        status, _ = m._source_health(self._stats())
        self.assertEqual(status, "ok")

    def test_failed(self):
        status, reason = m._source_health(self._stats(skipped=True))
        self.assertEqual(status, "failed")
        self.assertIn("failed", reason)

    def test_empty(self):
        status, reason = m._source_health(self._stats(accepted=0, net_new=0))
        self.assertEqual(status, "empty")
        self.assertIn("accepted", reason)

    def test_redundant(self):
        status, reason = m._source_health(self._stats(net_new=0))
        self.assertEqual(status, "redundant")
        self.assertIn("covered", reason)

    def test_high_rejection(self):
        status, reason = m._source_health(self._stats(scanned=100, accepted=40, rejected=60, net_new=10))
        self.assertEqual(status, "high_rejection")
        self.assertIn("rejected", reason)

    def test_low_value(self):
        # 1 net_new out of 200 accepted = 0.5% < 1% threshold
        status, reason = m._source_health(self._stats(scanned=200, accepted=200, rejected=0, net_new=1))
        self.assertEqual(status, "low_value")
        self.assertIn("net-new", reason)

    def test_ok_boundary_net_new_rate(self):
        # Exactly 1% net_new rate — should be ok (threshold is strictly less than)
        status, _ = m._source_health(self._stats(scanned=100, accepted=100, rejected=0, net_new=1))
        self.assertEqual(status, "ok")

    def test_failed_takes_precedence_over_empty(self):
        status, _ = m._source_health(self._stats(accepted=0, net_new=0, skipped=True))
        self.assertEqual(status, "failed")


class TestSourceHealthInReport(unittest.TestCase):
    """Integration: health fields must appear in the JSON report after merge()."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.raw_dir = os.path.join(self.tmp, "raw")
        self.out_dir = os.path.join(self.tmp, "processed")
        os.makedirs(self.raw_dir)
        os.makedirs(self.out_dir)
        self.out_path = os.path.join(self.out_dir, "blocklist.txt")
        self.map_path = os.path.join(self.raw_dir, "sources.map")

    def _write_source(self, fname, content):
        path = os.path.join(self.raw_dir, fname)
        with open(path, "w") as f:
            f.write(content)
        with open(self.map_path, "a") as mf:
            mf.write(f"{fname} http://example.com/{fname}\n")

    def _read_report(self):
        with open(os.path.join(self.tmp, "reports", "blocklist-report.json")) as f:
            return json.loads(f.read())

    def test_ok_source_has_health_ok(self):
        self._write_source("01_a.txt", "0.0.0.0 unique.com\n")
        m.merge(self.raw_dir, self.map_path, self.out_path,
                skip_iana_check=True, optimize_subdomains=False)
        report = self._read_report()
        self.assertEqual(report["sources"]["01_a.txt"]["health"], "ok")
        self.assertNotIn("health_reason", report["sources"]["01_a.txt"])

    def test_redundant_source_has_health_redundant(self):
        # Source 1 supplies unique.com; source 2 supplies the same domain — fully redundant.
        self._write_source("01_a.txt", "0.0.0.0 unique.com\n")
        self._write_source("02_b.txt", "0.0.0.0 unique.com\n")
        m.merge(self.raw_dir, self.map_path, self.out_path,
                skip_iana_check=True, optimize_subdomains=False)
        report = self._read_report()
        self.assertEqual(report["sources"]["02_b.txt"]["health"], "redundant")
        self.assertIn("health_reason", report["sources"]["02_b.txt"])

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp)


if __name__ == "__main__":
    unittest.main()
