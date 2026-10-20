"""Regression tests for fallback downloads."""

import gzip
import json
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

import fetch


class TestFallbackDownload(unittest.TestCase):
    def download(self, raw_dir):
        return fetch.download_one(
            1, "https://primary.example/list.txt",
            "https://fallback.example/list.txt.gz", raw_dir, 1, 1,
        )

    def test_unexpected_304_preserves_existing_file(self):
        with tempfile.TemporaryDirectory() as raw_dir:
            dest = Path(raw_dir) / "01_list.txt"
            dest.write_bytes(b"existing content")
            with patch("fetch.fetch", side_effect=[
                OSError("primary unavailable"), (None, None, None),
            ]):
                result = self.download(raw_dir)
            self.assertFalse(result[2])
            self.assertIn("fallback returned 304", result[3])
            self.assertEqual(dest.read_bytes(), b"existing content")

    def test_compressed_fallback_is_written(self):
        with tempfile.TemporaryDirectory() as raw_dir:
            content = b"ads.example.com\n"
            with patch("fetch.fetch", side_effect=[
                OSError("primary unavailable"), (gzip.compress(content), None, None),
            ]):
                result = self.download(raw_dir)
            self.assertTrue(result[2])
            self.assertIsNone(result[3])
            self.assertEqual((Path(raw_dir) / "01_list.txt").read_bytes(), content)


class TestSourceCache(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.sources = self.root / "sources.conf"
        self.raw = self.root / "raw"
        self.urls = ["https://one.example/list.txt", "https://two.example/list.txt"]
        self.sources.write_text("\n".join(self.urls))

    def run_fetch(self, *extra):
        return fetch.main(["--sources", str(self.sources), "--raw", str(self.raw),
                           "--workers", "1", "--retries", "1", *extra])

    def seed(self):
        with patch("fetch.fetch", side_effect=[(b"one.example\n", "one-etag", None),
                                                (b"two.example\n", "two-etag", None)]):
            self.assertEqual(self.run_fetch(), 0)

    def test_tier_tags_in_comments_do_not_change_source_tiers(self):
        self.sources.write_text(self.urls[0] + " # consider tier=aggressive later\n")
        self.assertEqual(fetch.read_sources(str(self.sources)), [(self.urls[0], None, "")])

    def test_outage_reuses_recent_content_and_records_degraded_run(self):
        self.seed()
        with patch("fetch.fetch", side_effect=[OSError("offline"), (b"new.example\n", None, None)]):
            self.assertEqual(self.run_fetch("--max-stale-pct", "50"), 0)
        self.assertEqual((self.raw / "01_list.txt").read_bytes(), b"one.example\n")
        self.assertEqual((self.raw / "02_list.txt").read_bytes(), b"new.example\n")
        status = json.loads((self.raw / "fetch-status.json").read_text())
        self.assertTrue(status["degraded"])
        self.assertEqual(status["stale_sources"], 1)

    def test_stale_limit_and_expiry_keep_mapped_files_intact(self):
        self.seed()
        baseline = (self.raw / "sources.map").read_bytes()
        with patch("fetch.fetch", side_effect=[OSError("offline"), (b"new.example\n", None, None)]):
            self.assertEqual(self.run_fetch(), 1)
        self.assertEqual((self.raw / "sources.map").read_bytes(), baseline)
        self.assertEqual((self.raw / "02_list.txt").read_bytes(), b"two.example\n")
        cache_path = self.raw / ".fetch-cache.json"
        cache = json.loads(cache_path.read_text())
        for entry in cache.values():
            entry["last_success"] = time.time() - 8 * 86400
        cache_path.write_text(json.dumps(cache))
        with patch("fetch.fetch", side_effect=OSError("offline")):
            self.assertEqual(self.run_fetch("--max-stale-pct", "100"), 1)

    def test_source_reordering_uses_url_identity_for_304(self):
        self.seed()
        self.sources.write_text("\n".join(reversed(self.urls)))
        with patch("fetch.fetch", return_value=(None, None, None)) as download:
            self.assertEqual(self.run_fetch("--incremental"), 0)
        self.assertEqual((self.raw / "01_list.txt").read_bytes(), b"two.example\n")
        self.assertEqual((self.raw / "02_list.txt").read_bytes(), b"one.example\n")
        self.assertEqual(download.call_args_list[0].args[3], "two-etag")

    def test_fallback_and_validatorless_success_clear_primary_etag(self):
        self.seed()
        self.sources.write_text(self.urls[0] + " , https://mirror.example/list.txt\n" + self.urls[1])
        with patch("fetch.fetch", side_effect=[OSError("primary down"),
                                               (b"mirror.example\n", "mirror-etag", None),
                                               (b"two.example\n", None, None)]):
            self.assertEqual(self.run_fetch("--incremental"), 0)
        cache = json.loads((self.raw / ".fetch-cache.json").read_text())
        self.assertNotIn("etag", cache[self.urls[0]])
        self.assertNotIn("etag", cache[self.urls[1]])
        with patch("fetch.fetch", return_value=(b"fresh.example\n", None, None)) as download:
            self.assertEqual(self.run_fetch("--incremental"), 0)
        self.assertIsNone(download.call_args_list[0].args[3])

    def test_corrupt_cache_is_never_used_for_outage(self):
        self.seed()
        fetch.cache_file(str(self.raw), self.urls[0]).write_bytes(b"tampered.example\n")
        with patch("fetch.fetch", side_effect=[OSError("offline"), (b"two.example\n", None, None)]):
            self.assertEqual(self.run_fetch("--max-stale-pct", "100"), 1)

    def test_html_or_empty_success_uses_fallback(self):
        self.sources.write_text(self.urls[0] + " , https://mirror.example/list.txt")
        for data in (b"", b"<!DOCTYPE html><html>temporary error</html>"):
            with patch("fetch.fetch", side_effect=[(data, None, None), (b"valid.example\n", None, None)]):
                self.assertEqual(self.run_fetch(), 0)
            self.assertEqual((self.raw / "01_list.txt").read_bytes(), b"valid.example\n")


if __name__ == "__main__":
    unittest.main()
