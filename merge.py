#!/usr/bin/env python3
"""Merge and sanitize raw host/block files into a single processed blocklist.

Output formats are handled by pluggable writers in the writers/ package.
Add a new format by creating writers/<name>.py and appending to WRITERS below.
"""

from __future__ import annotations

import argparse
import json
import os
import re
from datetime import datetime, timezone

from writers import WriterMeta
from writers.hosts import HostsWriter
from writers.adblock import AdblockWriter
from writers.rpz import RpzWriter
from writers.dnsmasq import DnsmasqWriter
from writers.unbound import UnboundWriter

# ── Registered writers — add new formats here ────────────────────────────────
WRITERS = [
    HostsWriter(),
    AdblockWriter(),
    RpzWriter(),
    DnsmasqWriter(),
    UnboundWriter(),
]

LOCAL_SKIP = {"localhost", "localhost.localdomain", "local"}


def load_allowlist(path: str) -> set[str]:
    allowed: set[str] = set()
    if not os.path.exists(path):
        return allowed
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line or line[0] in ("#", "!", ";"):
                continue
            domain = line.split("#", 1)[0].strip().lower()
            if domain:
                allowed.add(domain)
    print(f"Allowlist: loaded {len(allowed)} entries from {path}")
    return allowed


def remove_subdomains(domains: list[str]) -> list[str]:
    domain_set = set(domains)
    result = []
    for d in domains:
        parts = d.split(".")
        dominated = any(
            ".".join(parts[i:]) in domain_set
            for i in range(1, len(parts) - 1)
        )
        if not dominated:
            result.append(d)
    removed = len(domains) - len(result)
    if removed:
        print(f"Subdomain optimizer: removed {removed} redundant subdomain entries")
    return result


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
            fname = parts[0]
            url = parts[1] if len(parts) == 2 else ""
            pairs.append((fname, url))
    return pairs


IP_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
ALLOWED_LEADING_IPS = {"0.0.0.0", "127.0.0.1", "::1", "::"}


def extract_domain(line: str) -> str | None:
    for c in ["#", "//", ";"]:
        if c in line:
            line = line.split(c, 1)[0]
    line = line.strip()
    if not line:
        return None
    tokens = line.split()
    if not tokens:
        return None

    if IP_RE.match(tokens[0]) or tokens[0] in {"0.0.0.0", "::1", "::"}:
        if tokens[0] not in ALLOWED_LEADING_IPS:
            return None
        domain = next((t for t in tokens[1:] if "." in t and not IP_RE.match(t)), None)
        if domain is None:
            return None
    else:
        domain = next((t for t in tokens if "." in t and not IP_RE.match(t)), None)
        if domain is None:
            return None

    domain = domain.lower().strip().strip('"\'"').strip('.')
    if domain in LOCAL_SKIP or IP_RE.match(domain):
        return None
    return domain


def detect_format(path: str, sample_lines: int = 50) -> tuple[str, str]:
    host_lines = domain_only_lines = seen = 0
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
            elif len(tokens) == 1 and "." in tokens[0] and not IP_RE.match(tokens[0]):
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
                continue
            if s.lstrip().startswith(('#', '!')):
                headers.append(s)
                continue
            break
    return headers


def _collect_domains(raw_dir, pairs, allowlist, source_stats, source_infos, rejected_entries):
    """Scan source files and return (ordered_domains, total_candidates)."""
    seen: set[str] = set()
    ordered: list[str] = []
    total_candidates = 0

    sources = pairs if pairs else [
        (fname, "")
        for fname in sorted(os.listdir(raw_dir))
        if os.path.isfile(os.path.join(raw_dir, fname))
    ]

    for fname, url in sources:
        path = os.path.join(raw_dir, fname)
        headers = read_leading_header(path)
        fmt, reason = detect_format(path)
        source_infos.append((fname, headers, url, fmt))
        source_stats[fname] = {
            "url": url, "format": fmt, "format_reason": reason,
            "scanned": 0, "accepted": 0, "rejected": 0,
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
                if dom not in seen and dom not in allowlist:
                    seen.add(dom)
                    ordered.append(dom)

    return ordered, total_candidates


def merge(raw_dir: str, map_path: str, out_path: str, sort_output: bool = True,
          allowlist_path: str = "allowlist.txt", optimize_subdomains: bool = True) -> None:
    allowlist = load_allowlist(allowlist_path)
    pairs = read_map(map_path)
    source_infos: list[tuple[str, list[str], str, str]] = []
    rejected_entries: list[tuple[str, int, str]] = []
    source_stats: dict[str, dict] = {}

    ordered, total_candidates = _collect_domains(
        raw_dir, pairs, allowlist, source_stats, source_infos, rejected_entries
    )

    if sort_output:
        ordered = sorted(ordered)
    if optimize_subdomains:
        ordered = remove_subdomains(ordered)

    # delta vs previous hosts file
    out_dir = os.path.dirname(out_path) or "."
    prev_domains: set[str] = set()
    delta_added = delta_removed = 0
    if os.path.exists(out_path):
        with open(out_path, "r", encoding="utf-8", errors="ignore") as pf:
            for line in pf:
                s = line.strip()
                if not s or s.startswith("#"):
                    continue
                parts = s.split()
                prev_domains.add(parts[1].lower() if len(parts) >= 2 else parts[0].lower())
        try:
            with open(out_path + ".old", "w", encoding="utf-8") as bp, \
                 open(out_path, "r", encoding="utf-8", errors="ignore") as pf:
                bp.write(pf.read())
        except Exception:
            pass
        new_set = {d.lower() for d in ordered}
        delta_added = len(new_set - prev_domains)
        delta_removed = len(prev_domains - new_set)

    total_unique = len(ordered)
    duplicates = max(0, total_candidates - total_unique)
    reduction_pct = (duplicates / total_candidates * 100) if total_candidates else 0.0
    now_str = datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')

    meta = WriterMeta(
        now_str=now_str,
        total_candidates=total_candidates,
        total_unique=total_unique,
        duplicates=duplicates,
        reduction_pct=reduction_pct,
        delta_added=delta_added,
        delta_removed=delta_removed,
        source_infos=source_infos,
    )

    # ── run all registered writers ────────────────────────────────────────────
    for writer in WRITERS:
        writer.write(ordered, meta, out_dir)

    # ── rejected entries ──────────────────────────────────────────────────────
    rejected_path = os.path.join(out_dir, "rejected-entries.txt")
    if rejected_entries:
        with open(rejected_path, "w", encoding="utf-8") as rej:
            rej.write(f"# Rejected entries - generated: {now_str}\n")
            rej.write("# Format: source_file line_number : original_line\n\n")
            for fname, lineno, orig in rejected_entries:
                rej.write(f"{fname} {lineno}: {orig}\n")

    # ── JSON report ───────────────────────────────────────────────────────────
    report = {
        "generated": now_str,
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
    with open(os.path.join(out_dir, "blocklist-report.json"), "w", encoding="utf-8") as rf:
        json.dump(report, rf, indent=2, ensure_ascii=False)

    print(f"Processed: scanned={total_candidates} unique={total_unique} "
          f"duplicates={duplicates} reduction={reduction_pct:.2f}% "
          f"rejected={len(rejected_entries)} sorted={sort_output} -> {rejected_path}")


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Merge raw host files into one processed blocklist")
    p.add_argument("--raw", default="raw")
    p.add_argument("--map", default="raw/sources.map")
    p.add_argument("--out", default="processed/blocklist.txt")
    p.add_argument("--unsorted", action="store_true")
    p.add_argument("--allowlist", default="allowlist.txt")
    p.add_argument("--no-optimize-subdomains", action="store_true")
    args = p.parse_args(argv)

    merge(args.raw, args.map, args.out,
          sort_output=not args.unsorted,
          allowlist_path=args.allowlist,
          optimize_subdomains=not args.no_optimize_subdomains)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
