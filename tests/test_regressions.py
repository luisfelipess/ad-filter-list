"""Coverage and tier regressions identified in the October audit."""

import gzip
import json
from pathlib import Path
import tempfile
import unittest

import merge
from readers.adblock import AdblockReader


class TestCoverage(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.raw = self.root / "raw"
        self.out = self.root / "processed"
        self.raw.mkdir()
        self.out.mkdir()
        (self.root / "tiers").write_text("light\ngood *\naggressive\n")
        (self.root / "allow").write_text("")
        (self.root / "block").write_text("")
        (self.raw / "sources.map").write_text("")

    def source(self, text, tier="good"):
        name = f"{len(list(self.raw.glob('*.txt')))}.txt"
        (self.raw / name).write_text(text)
        with (self.raw / "sources.map").open("a") as mapping:
            mapping.write(f"{name} https://example.org/{name} {tier}\n")

    def build(self, **kwargs):
        merge.merge(str(self.raw), str(self.raw / "sources.map"),
                    str(self.out / "blocklist.txt"),
                    allowlist_path=str(self.root / "allow"),
                    blocklist_path=str(self.root / "block"),
                    tiers_config=str(self.root / "tiers"),
                    skip_iana_check=True, **kwargs)

    def text(self, name, tier="good"):
        path = (self.out if tier == "good" else self.out / tier) / name
        if name.endswith(".gz"):
            with gzip.open(path, "rt") as stream:
                return stream.read()
        return path.read_text()

    def test_allowed_child_removes_parent_coverage_but_keeps_safe_children(self):
        self.source("example.com\nsafe.example.com\nads.example.com\n")
        (self.root / "allow").write_text("safe.example.com\n")
        for optimize in (True, False):
            self.build(optimize_subdomains=optimize)
            self.assertIn("0.0.0.0 example.com\n", self.text("blocklist.txt"))
            self.assertNotIn("address=/example.com/#", self.text("blocklist-dnsmasq.conf"))
            self.assertIn("address=/ads.example.com/#", self.text("blocklist-dnsmasq.conf"))
            self.assertNotIn("||example.com^", self.text("blocklist-adblock.txt"))
            self.assertNotIn("\nexample.com IN CNAME .", self.text("blocklist-bind9.zone.gz"))
            self.assertNotIn('local-zone: "example.com."', self.text("blocklist-unbound.conf.gz"))

    def test_wildcard_allowlist_blocks_inclusive_apex_rule(self):
        self.source("example.com\nother.org\n")
        (self.root / "allow").write_text("*.example.com\n")
        self.build()
        self.assertIn("0.0.0.0 example.com\n", self.text("blocklist.txt"))
        self.assertNotIn("address=/example.com/#", self.text("blocklist-dnsmasq.conf"))

    def test_wildcard_provenance_stays_in_its_tier(self):
        self.source("example.com\n", "good")
        self.source("*.example.com\n", "aggressive")
        self.build()
        self.assertNotIn("||*.example.com^", self.text("blocklist-adblock.txt"))
        self.assertIn("||example.com^", self.text("blocklist-adblock.txt", "aggressive"))
        report = json.loads((self.root / "reports" / "blocklist-report.json").read_text())
        self.assertEqual(report["summary"]["wildcards"], 0)
        self.assertEqual(report["summary"]["tier_summaries"]["aggressive"]["wildcards"], 1)

    def test_heavier_exact_entry_does_not_promote_lighter_wildcard_apex(self):
        self.source("*.example.com\n", "light")
        self.source("example.com\n", "aggressive")
        self.build()
        self.assertIn("\n||*.example.com^\n", self.text("blocklist-adblock.txt", "light"))
        self.assertNotIn("\n||example.com^\n", self.text("blocklist-adblock.txt", "light"))
        self.assertIn("\n||example.com^\n", self.text("blocklist-adblock.txt", "aggressive"))
        self.assertNotIn("\n||*.example.com^\n", self.text("blocklist-adblock.txt", "aggressive"))

    def test_native_rules_are_unique_and_wildcard_apex_provenance_is_preserved(self):
        self.source("example.com\n*.example.com\n*.only.org\nchild.example.com\n")
        self.build()
        for name, prefix in [("blocklist-dnsmasq.conf", "address="),
                             ("blocklist-unbound.conf.gz", "local-zone:"),
                             ("blocklist-bind9.zone.gz", "example.com IN")]:
            rules = [line for line in self.text(name).splitlines() if line.startswith(prefix)]
            self.assertEqual(len(rules), len(set(rules)), name)
        adblock = self.text("blocklist-adblock.txt")
        self.assertIn("\n||example.com^\n", adblock)
        self.assertNotIn("\n||*.example.com^\n", adblock)
        self.assertIn("\n||*.only.org^\n", adblock)
        self.assertNotIn("\n||only.org^\n", adblock)

    def test_source_exceptions_and_badfilter_do_not_become_blocks(self):
        self.source("||example.com^\n@@||safe.example.com^\n||ads.example.com^\n"
                    "||disabled.org^\n||disabled.org^$badfilter\n||scoped.org^$third-party\n")
        self.build()
        hosts = self.text("blocklist.txt")
        self.assertNotIn("0.0.0.0 example.com\n", hosts)
        self.assertNotIn("0.0.0.0 disabled.org\n", hosts)
        self.assertNotIn("0.0.0.0 scoped.org\n", hosts)
        self.assertIn("0.0.0.0 ads.example.com\n", hosts)

    def test_scoped_source_exception_is_conservatively_preserved(self):
        self.source("||example.com^\n@@||safe.example.com^$domain=other.org\n||ads.example.com^\n")
        self.build()
        self.assertNotIn("0.0.0.0 example.com\n", self.text("blocklist.txt"))
        self.assertIn("0.0.0.0 ads.example.com\n", self.text("blocklist.txt"))

    def test_unsupported_adblock_modifiers_are_rejected(self):
        reader = AdblockReader()
        for suffix in ("$third-party", "$badfilter", "$domain=other.org", "$important"):
            self.assertIsNone(reader.extract("||example.com^" + suffix))

    def test_nondefault_tier_drop_aborts_before_any_output_changes(self):
        self.source("one.com\ntwo.com\n", "light")
        self.source("other.org\n", "good")
        self.build()
        baseline = {str(path): path.read_bytes() for path in self.out.rglob("*") if path.is_file()}
        (self.raw / "0.txt").write_text("# broken source\n")
        with self.assertRaises(SystemExit):
            self.build()
        self.assertTrue(all(Path(path).read_bytes() == data for path, data in baseline.items()))

    def test_configured_empty_source_aborts_first_build(self):
        self.source("# no usable data\n", "light")
        self.source("other.org\n", "good")
        with self.assertRaises(SystemExit):
            self.build()
        self.assertFalse((self.out / "blocklist.txt").exists())

    def test_empty_rejection_log_does_not_keep_previous_rejections(self):
        self.source("example.com\ninvalid\n")
        self.build()
        (self.raw / "0.txt").write_text("example.com\n")
        self.build()
        self.assertNotIn("invalid", (self.root / "reports" / "rejected-entries.txt").read_text())
