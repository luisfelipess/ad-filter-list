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

    def test_json_report_has_both_reduction_breakdowns(self):
        # Both dedup-only (hosts/domains) and subdomain-optimized (DNS) stats must be present.
        self._write_source("01_a.txt", "0.0.0.0 example.com\n0.0.0.0 ads.example.com\n")
        m.merge(self.raw_dir, self.map_path, self.out_path,
                allowlist_path=self._write_allowlist(""), optimize_subdomains=True)
        summary = self._read_report_summary()
        self.assertIn("unique_all", summary)
        self.assertIn("reduction_pct_all", summary)
        self.assertIn("unique", summary)
        self.assertIn("reduction_pct", summary)
        # dedup-only count must be >= optimized count
        self.assertGreaterEqual(summary["unique_all"], summary["unique"])

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


if __name__ == "__main__":
    unittest.main()
