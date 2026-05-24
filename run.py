#!/usr/bin/env python3
"""Full blocklist pipeline entry point.

Runs the three pipeline stages in order:
  1. fetch.py    — download sources into raw/
  2. merge.py    — merge, deduplicate, and write processed/ + reports/
  3. post_run.py — update README.md stats block

Usage:
    python3 run.py [--skip-download] [--unsorted] [--no-post-run]
                   [--sources sources.conf] [--raw raw]
                   [--out processed/blocklist.txt]
                   [--allowlist allowlist.txt] [--blocklist blocklist.txt]
                   [--workers 8] [--retries 3] [--timeout 30]
                   [--no-optimize-subdomains] [--writers-config writers.conf]
"""

from __future__ import annotations

import argparse
import os
import sys


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Run the full blocklist pipeline")
    p.add_argument("--sources", default="sources.conf")
    p.add_argument("--raw", default="raw")
    p.add_argument("--out", default="processed/blocklist.txt")
    p.add_argument("--allowlist", default="allowlist.txt")
    p.add_argument("--blocklist", default="blocklist.txt")
    p.add_argument("--unsorted", action="store_true")
    p.add_argument("--skip-download", action="store_true",
                   help="skip fetch stage; merge existing files in --raw")
    p.add_argument("--workers", type=int, default=8)
    p.add_argument("--retries", type=int, default=3)
    p.add_argument("--timeout", type=int, default=30)
    p.add_argument("--no-optimize-subdomains", action="store_true")
    p.add_argument("--writers-config", default="writers.conf")
    p.add_argument("--no-post-run", action="store_true",
                   help="skip the post_run README stats update")
    args = p.parse_args(argv)

    os.makedirs(args.raw, exist_ok=True)
    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)

    map_path = os.path.join(args.raw, "sources.map")

    # ── Stage 1: Fetch ────────────────────────────────────────────────────────
    if args.skip_download:
        print(f"Skipping download; using existing files in {args.raw}/")
        if not os.path.isfile(map_path):
            print(
                f"Note: {map_path} not found; merge will scan {args.raw}/ for files.",
                file=sys.stderr,
            )
    else:
        import fetch
        rc = fetch.main([
            "--sources", args.sources,
            "--raw", args.raw,
            "--workers", str(args.workers),
            "--retries", str(args.retries),
            "--timeout", str(args.timeout),
        ])
        if rc != 0:
            return rc

    # ── Stage 2: Merge ────────────────────────────────────────────────────────
    import merge
    merge_argv = [
        "--raw", args.raw,
        "--map", map_path,
        "--out", args.out,
        "--allowlist", args.allowlist,
        "--blocklist", args.blocklist,
        "--writers-config", args.writers_config,
    ]
    if args.unsorted:
        merge_argv.append("--unsorted")
    if args.no_optimize_subdomains:
        merge_argv.append("--no-optimize-subdomains")
    rc = merge.main(merge_argv)
    if rc != 0:
        return rc

    # ── Stage 3: Post-run ─────────────────────────────────────────────────────
    if not args.no_post_run:
        import post_run
        reports_dir = os.path.normpath(
            os.path.join(os.path.dirname(args.out) or ".", "..", "reports")
        )
        post_run.main([
            "--report", os.path.join(reports_dir, "blocklist-report.json"),
        ])

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
