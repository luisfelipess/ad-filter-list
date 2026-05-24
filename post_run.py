#!/usr/bin/env python3
"""Post-run pipeline step: refresh the README.md stats block.

Reads reports/blocklist-report.json and replaces the content between
  <!-- stats:start -->
  <!-- stats:end -->
markers in README.md with current counts and direct download links.

Run automatically by run.py after each merge.  Can also be run standalone:
    python3 post_run.py [--report reports/blocklist-report.json] [--readme README.md]
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys

_STATS_START = "<!-- stats:start -->"
_STATS_END = "<!-- stats:end -->"


def _raw_base() -> str:
    """Return the raw.githubusercontent.com base URL for this repo, or ''."""
    try:
        out = subprocess.run(
            ["git", "remote", "get-url", "origin"],
            capture_output=True, text=True, timeout=5,
        ).stdout.strip()
        m = re.search(r"github\.com[:/](.+?)(?:\.git)?$", out)
        if m:
            return f"https://raw.githubusercontent.com/{m.group(1)}/main"
    except Exception:
        pass
    return ""


def _build_block(report: dict, raw_base: str) -> str:
    s = report.get("summary", {})
    date = report.get("generated", "")[:10] or "unknown"
    n_sources = len(report.get("sources", {}))
    unique_all = s.get("unique_all", 0)
    unique_opt = s.get("unique", 0)
    wildcards = s.get("wildcards", 0)

    lines = [
        f"**Last run:** {date} &nbsp;·&nbsp; "
        f"**Sources:** {n_sources} &nbsp;·&nbsp; "
        f"**Unique domains:** {unique_all:,} *(hosts/domains)* "
        f"· {unique_opt:,} *(DNS-optimized)* &nbsp;·&nbsp; "
        f"**Wildcards:** {wildcards:,}",
    ]

    if raw_base:
        lines += [
            "",
            "| Format | Download | Domains |",
            "|---|---|---|",
            f"| Hosts (`0.0.0.0 domain`) | [blocklist.txt]({raw_base}/processed/blocklist.txt) | {unique_all:,} |",
            f"| Plain domains | [blocklist-domains.txt]({raw_base}/processed/blocklist-domains.txt) | {unique_all:,} |",
            f"| Adblock syntax | [blocklist-adblock.txt]({raw_base}/processed/blocklist-adblock.txt) | {unique_opt:,} |",
            f"| BIND9 RPZ (gzip) | [blocklist-bind9.zone.gz]({raw_base}/processed/blocklist-bind9.zone.gz) | {unique_opt:,} |",
            f"| dnsmasq | [blocklist-dnsmasq.conf]({raw_base}/processed/blocklist-dnsmasq.conf) | {unique_opt:,} |",
            f"| Unbound | [blocklist-unbound.conf]({raw_base}/processed/blocklist-unbound.conf) | {unique_opt:,} |",
        ]

    return "\n".join(lines)


def _update_readme(readme_path: str, block: str) -> bool:
    with open(readme_path, "r", encoding="utf-8") as fh:
        content = fh.read()

    if _STATS_START not in content or _STATS_END not in content:
        print(f"post_run: stats sentinels not found in {readme_path} — skipping.", file=sys.stderr)
        return False

    pattern = re.compile(
        re.escape(_STATS_START) + r".*?" + re.escape(_STATS_END),
        re.DOTALL,
    )
    replacement = f"{_STATS_START}\n{block}\n{_STATS_END}"
    new_content = pattern.sub(replacement, content)

    if new_content == content:
        print("post_run: README stats unchanged.")
        return False

    with open(readme_path, "w", encoding="utf-8") as fh:
        fh.write(new_content)
    print(f"post_run: updated stats block in {readme_path}")
    return True


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Refresh README.md stats from blocklist report")
    p.add_argument("--report", default="reports/blocklist-report.json")
    p.add_argument("--readme", default="README.md")
    args = p.parse_args(argv)

    if not os.path.exists(args.report):
        print(f"post_run: {args.report} not found — skipping.", file=sys.stderr)
        return 0

    with open(args.report, "r", encoding="utf-8") as fh:
        report = json.load(fh)

    block = _build_block(report, _raw_base())
    _update_readme(args.readme, block)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
