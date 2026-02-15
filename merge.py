#!/usr/bin/env python3
"""Merge and sanitize raw host/block files into a single processed blocklist.

This is a copy adapted for the `ad-filter-list` layout. It additionally writes
a per-source JSON report next to the output file for auditing and CI use.
"""

from __future__ import annotations

import argparse
import json
import os
import re
from datetime import datetime, timezone


LOCAL_SKIP = {"localhost", "localhost.localdomain", "local"}


def read_map(map_path: str) -> list[tuple[str, str]]:
    pairs = []
    if not os.path.exists(map_path):
        return pairs
    with open(map_path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            parts = line.split(None, 1)
            if len(parts) == 2:
                fname, url = parts
            else:
                fname = parts[0]
                url = ""
            pairs.append((fname, url))
    return pairs


IP_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
# allowed leading IPs we accept and normalize to 0.0.0.0
ALLOWED_LEADING_IPS = {"0.0.0.0", "127.0.0.1", "::1", "::"}


def extract_domain(line: str) -> str | None:
    # strip inline comment markers
    for c in ["#", "//", ";"]:
        if c in line:
            line = line.split(c, 1)[0]
    line = line.strip()
    if not line:
        return None
    tokens = line.split()
    if not tokens:
        return None

    # If first token is an IP, only proceed if it's an allowed leading IP
    if IP_RE.match(tokens[0]) or tokens[0] in {"0.0.0.0", "::1", "::"}:
        if tokens[0] not in ALLOWED_LEADING_IPS:
            # skip entries with arbitrary IPs (we only normalize known host-style IPs)
            return None
        for t in tokens[1:]:
            if "." in t and not IP_RE.match(t):
                domain = t
                break
        else:
            return None
    else:
        # find first token that looks like a domain
        domain = None
        for t in tokens:
            if "." in t and not IP_RE.match(t):
                domain = t
                break
        if domain is None:
            return None

    # normalize: lower, trim whitespace, strip surrounding dots and quotes
    domain = domain.lower().strip()
    domain = domain.strip('"\'"')
    domain = domain.strip('.')
    if domain in LOCAL_SKIP:
        return None
    # discard obvious IPs
    if IP_RE.match(domain):
        return None
    return domain


def detect_format(path: str, sample_lines: int = 50) -> tuple[str, str]:
    host_lines = 0
    domain_only_lines = 0
    seen = 0
    if not os.path.exists(path):
        return ("unsupported", "file not found")
    with open(path, "r", encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            s = line.strip()
            if not s or s.lstrip().startswith(('#', '!')):
                continue
            seen += 1
            tokens = s.split()
            if tokens and (IP_RE.match(tokens[0]) or tokens[0] in ALLOWED_LEADING_IPS):
                if len(tokens) > 1 and "." in tokens[1] and not IP_RE.match(tokens[1]):
                    host_lines += 1
            else:
                if len(tokens) == 1 and "." in tokens[0] and not IP_RE.match(tokens[0]):
                    domain_only_lines += 1
            if seen >= sample_lines:
                break

    if host_lines and not domain_only_lines:
        return ("host", "host-style entries detected")
    if domain_only_lines and not host_lines:
        return ("domain-only", "domain-only entries detected")
    if host_lines and domain_only_lines:
        return ("mixed", "mix of host-style and domain-only entries")
    return ("unsupported", "no recognizable host or domain-only entries in sample")


def read_leading_header(path: str) -> list[str]:
    headers = []
    if not os.path.exists(path):
        return headers
    with open(path, "r", encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            s = line.rstrip('\n')
            if s.strip() == "":
                if headers:
                    break
                else:
                    continue
            if s.lstrip().startswith(('#', '!')):
                headers.append(s)
                continue
            break
    return headers


def merge(raw_dir: str, map_path: str, out_path: str, sort_output: bool = True) -> None:
    pairs = read_map(map_path)
    seen: set[str] = set()
    ordered: list[str] = []
    source_infos: list[tuple[str, list[str], str, str]] = []  # (filename, headers, url, format)
    rejected_entries: list[tuple[str, int, str]] = []

    # per-source stats for JSON report
    source_stats: dict[str, dict] = {}

    total_candidates = 0
    if pairs:
        for fname, url in pairs:
            path = os.path.join(raw_dir, fname)
            headers = read_leading_header(path)
            fmt, reason = detect_format(path)
            source_infos.append((fname, headers, url, fmt))
            source_stats[fname] = {
                "url": url,
                "format": fmt,
                "format_reason": reason,
                "scanned": 0,
                "accepted": 0,
                "rejected": 0,
                "skipped": fmt == "unsupported",
            }
            print(f"{fname}: detected format={fmt} ({reason})")
            if fmt == "unsupported":
                rejected_entries.append((fname, 0, f"UNSUPPORTED_FILE: {reason}"))
                print(f"Skipping {fname}: {reason}")
                continue
            if not os.path.exists(path):
                continue
            with open(path, "r", encoding="utf-8", errors="ignore") as fh:
                for lineno, line in enumerate(fh, start=1):
                    stripped = line.strip()
                    if not stripped or stripped.lstrip().startswith(('#', '!')):
                        continue
                    source_stats[fname]["scanned"] += 1
                    dom = extract_domain(line)
                    if not dom:
                        source_stats[fname]["rejected"] += 1
                        rejected_entries.append((fname, lineno, line.rstrip('\n')))
                        continue
                    source_stats[fname]["accepted"] += 1
                    total_candidates += 1
                    if dom not in seen:
                        seen.add(dom)
                        ordered.append(dom)
    else:
        # fallback: scan all files in raw_dir
        for fname in sorted(os.listdir(raw_dir)):
            path = os.path.join(raw_dir, fname)
            if os.path.isdir(path):
                continue
            headers = read_leading_header(path)
            source_infos.append((fname, headers, "", "unknown"))
            source_stats[fname] = {"url": "", "format": "unknown", "scanned": 0, "accepted": 0, "rejected": 0, "skipped": False}
            with open(path, "r", encoding="utf-8", errors="ignore") as fh:
                for lineno, line in enumerate(fh, start=1):
                    stripped = line.strip()
                    if not stripped or stripped.lstrip().startswith(('#', '!')):
                        continue
                    source_stats[fname]["scanned"] += 1
                    dom = extract_domain(line)
                    if not dom:
                        source_stats[fname]["rejected"] += 1
                        rejected_entries.append((fname, lineno, line.rstrip('\n')))
                        continue
                    source_stats[fname]["accepted"] += 1
                    total_candidates += 1
                    if dom not in seen:
                        seen.add(dom)
                        ordered.append(dom)

    # optionally sort output (alphabetical by domain)
    if sort_output:
        ordered = sorted(ordered)

    # prepare previous backup and compute delta vs previous file if exists
    prev_path = out_path
    prev_domains: set[str] = set()
    delta_added = 0
    delta_removed = 0
    if os.path.exists(prev_path):
        # read previous domains
        with open(prev_path, "r", encoding="utf-8", errors="ignore") as pf:
            for line in pf:
                s = line.strip()
                if not s or s.startswith("#"):
                    continue
                parts = s.split()
                if len(parts) >= 2:
                    prev_domains.add(parts[1].lower())
                elif len(parts) == 1:
                    prev_domains.add(parts[0].lower())
        # write a backup copy
        backup_path = prev_path + ".old"
        try:
            with open(backup_path, "w", encoding="utf-8") as bp, open(prev_path, "r", encoding="utf-8", errors="ignore") as pf:
                bp.write(pf.read())
        except Exception:
            pass
        # compute deltas
        new_set = set(d.lower() for d in ordered)
        added_set = new_set - prev_domains
        removed_set = prev_domains - new_set
        delta_added = len(added_set)
        delta_removed = len(removed_set)

    # write output
    total_unique = len(ordered)
    duplicates = max(0, total_candidates - total_unique)
    reduction_pct = (duplicates / total_candidates * 100) if total_candidates else 0.0

    with open(out_path, "w", encoding="utf-8") as out:
        out.write(f"# Processed blocklist - generated: {datetime.now(timezone.utc).isoformat().replace('+00:00','Z')}\n")
        out.write("# Format: 0.0.0.0 domain\n")
        out.write("# Summary: scanned entries: {0}, unique entries: {1}, removed duplicates: {2} ({3:.2f}% reduction)\n".format(total_candidates, total_unique, duplicates, reduction_pct))
        if delta_added or delta_removed:
            out.write(f"# Delta vs previous: added={delta_added} removed={delta_removed}\n")
        out.write("# Sources and original headers (credits):\n\n")

        for fname, headers, url, fmt in source_infos:
            out.write(f"# ----- Source: {url or fname} ({fname}) -----\n")
            out.write(f"# Detected format: {fmt}\n")
            if headers:
                for h in headers:
                    # ensure header lines start with '#'
                    if h.lstrip().startswith('!'):
                        out.write('#' + h + "\n")
                    else:
                        out.write(h + "\n")
            else:
                out.write(f"# (no header in source file)\n")
            out.write("#\n")

        out.write("# ---- merged entries ----\n")
        for d in ordered:
            out.write(f"0.0.0.0 {d}\n")

    # write rejected entries file
    out_dir = os.path.dirname(out_path) or "."
    rejected_path = os.path.join(out_dir, "rejected-entries.txt")
    if rejected_entries:
        with open(rejected_path, "w", encoding="utf-8") as rej:
            rej.write(f"# Rejected entries - generated: {datetime.now(timezone.utc).isoformat().replace('+00:00','Z')}\n")
            rej.write("# Format: source_file line_number : original_line\n\n")
            for fname, lineno, orig in rejected_entries:
                rej.write(f"{fname} {lineno}: {orig}\n")

    # write JSON report with per-source stats
    report = {
        "generated": datetime.now(timezone.utc).isoformat().replace('+00:00','Z'),
        "summary": {
            "scanned": total_candidates,
            "unique": total_unique,
            "duplicates": duplicates,
            "reduction_pct": round(reduction_pct, 4),
            "delta_added": delta_added,
            "delta_removed": delta_removed,
            "rejected_total": len(rejected_entries),
        },
        "sources": source_stats,
    }
    report_path = os.path.join(out_dir, "blocklist-report.json")
    with open(report_path, "w", encoding="utf-8") as rf:
        json.dump(report, rf, indent=2, ensure_ascii=False)

    # also print a short summary to stdout for convenience
    sorted_flag = not (not sort_output)
    print(f"Processed: scanned={total_candidates} unique={total_unique} duplicates={duplicates} reduction={reduction_pct:.2f}% rejected={len(rejected_entries)} sorted={sorted_flag} -> {rejected_path}")


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Merge raw host files into one processed blocklist")
    p.add_argument("--raw", default="raw", help="raw files directory")
    p.add_argument("--map", default="raw/sources.map", help="mapping file produced by update script")
    p.add_argument("--out", default="processed/blocklist.txt", help="output file path")
    p.add_argument("--unsorted", action="store_true", help="keep first-seen order instead of sorting alphabetically")
    args = p.parse_args(argv)

    merge(args.raw, args.map, args.out, sort_output=not args.unsorted)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
