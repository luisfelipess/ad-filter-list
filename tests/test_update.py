"""Tests for update.py — skip-download and merge handoff."""

import io
import os
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import update


class TestUpdateSkipDownload(unittest.TestCase):
    @patch("update._invoke_merge", return_value=0)
    @patch("update.ThreadPoolExecutor")
    def test_skip_download_skips_fetch(self, mock_pool, mock_merge):
        with tempfile.TemporaryDirectory() as tmp:
            raw = os.path.join(tmp, "raw")
            os.makedirs(raw)
            out = os.path.join(tmp, "processed", "blocklist.txt")
            os.makedirs(os.path.dirname(out))
            map_path = os.path.join(raw, "sources.map")
            with open(map_path, "w", encoding="utf-8") as mf:
                mf.write("01_hosts.txt http://example.com/hosts\n")
            with open(os.path.join(raw, "01_hosts.txt"), "w", encoding="utf-8") as hf:
                hf.write("0.0.0.0 ads.example.com\n")

            rc = update.main(
                ["--skip-download", "--raw", raw, "--out", out, "--sources", os.path.join(tmp, "none.conf")]
            )

            self.assertEqual(rc, 0)
            mock_pool.assert_not_called()
            mock_merge.assert_called_once()
            args, map_arg = mock_merge.call_args[0]
            self.assertEqual(map_arg, map_path)
            self.assertEqual(args.raw, raw)
            self.assertEqual(args.out, out)

    def test_skip_download_flag_in_help(self):
        buf = io.StringIO()
        with patch.object(sys, "stdout", buf):
            with self.assertRaises(SystemExit) as ctx:
                update.main(["--help"])
        self.assertEqual(ctx.exception.code, 0)
        self.assertIn("--skip-download", buf.getvalue())


if __name__ == "__main__":
    unittest.main()
