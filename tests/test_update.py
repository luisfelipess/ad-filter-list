"""Compatibility forwarding and pipeline stage handoff tests."""

import tempfile
import json
import unittest
from pathlib import Path
from unittest.mock import patch

import run
import update


class TestUpdate(unittest.TestCase):
    def test_forwards_arguments_and_exit_code(self):
        with patch("run.main", return_value=7) as main:
            self.assertEqual(update.main(["--skip-download"]), 7)
        main.assert_called_once_with(["--skip-download"])

    def test_skip_download_skips_fetch_and_passes_map(self):
        with tempfile.TemporaryDirectory() as tmp:
            raw = str(Path(tmp) / "raw")
            out = str(Path(tmp) / "processed" / "blocklist.txt")
            with patch("fetch.main") as fetch_main, patch("merge.main", return_value=0) as merge_main:
                rc = run.main(["--skip-download", "--raw", raw, "--out", out, "--no-post-run"])
            self.assertEqual(rc, 0)
            fetch_main.assert_not_called()
            args = merge_main.call_args.args[0]
            self.assertEqual(args[args.index("--map") + 1], str(Path(raw) / "sources.map"))

    def test_fetch_failure_stops_merge(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch("fetch.main", return_value=1), patch("merge.main") as merge_main:
                self.assertEqual(run.main(["--raw", tmp, "--out", str(Path(tmp) / "out")]), 1)
            merge_main.assert_not_called()

    def test_degraded_full_pipeline_updates_healthy_source_and_reports_stale_source(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sources = root / "sources.conf"
            sources.write_text("https://one.example/list.txt\nhttps://two.example/list.txt\n")
            args = ["--sources", str(sources), "--raw", str(root / "raw"),
                    "--out", str(root / "processed" / "blocklist.txt"),
                    "--tiers-config", str(root / "missing"),
                    "--allowlist", str(root / "missing"), "--blocklist", str(root / "missing"),
                    "--workers", "1", "--no-iana-tld-check", "--no-post-run",
                    "--max-stale-pct", "50"]
            with patch("fetch.fetch", side_effect=[(b"one.example\n", None, None),
                                                   (b"two.example\n", None, None)]):
                self.assertEqual(run.main(args), 0)
            with patch("fetch.fetch", side_effect=[OSError("offline"),
                                                   (b"new.example\n", None, None)]):
                self.assertEqual(run.main(args), 0)
            report = json.loads((root / "reports" / "blocklist-report.json").read_text())
            self.assertTrue(report["fetch"]["degraded"])
            self.assertEqual(report["fetch"]["stale_sources"], 1)
            domains = (root / "processed" / "blocklist-domains.txt").read_text()
            self.assertIn("\none.example\n", domains)
            self.assertIn("\nnew.example\n", domains)
            self.assertNotIn("\ntwo.example\n", domains)
