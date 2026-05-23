#!/usr/bin/env python3
"""Merge and sanitize raw host/block files into a single processed blocklist.

Output formats are handled by pluggable writers in the writers/ package.
Add a new format by creating writers/<name>.py and appending to WRITERS below.
"""

from __future__ import annotations

import argparse
import json
import os
from datetime import datetime, timezone

from writers import WriterMeta
from writers.hosts import HostsWriter
from writers.adblock import AdblockWriter
from writers.rpz import RpzWriter
from writers.dnsmasq import DnsmasqWriter
from writers.unbound import UnboundWriter
from writers.domains import DomainsWriter

from readers import normalize_domain, read_leading_header
from readers.hosts import HostsReader
from readers.domain import DomainReader
from readers.adblock import AdblockReader

# ── Registered readers — order matters: first match wins ─────────────────────
READERS = [
    HostsReader(),
    AdblockReader(),   # before DomainReader — adblock lines also look domain-ish
    DomainReader(),
]

# ── Registered writers — add new formats here ────────────────────────────────
WRITERS = [
    HostsWriter(),
    AdblockWriter(),
    RpzWriter(),
    DnsmasqWriter(),
    UnboundWriter(),
    DomainsWriter(),
]

_WRITER_REGISTRY: dict[str, BaseWriter] = {w.__class__.__name__.lower().replace("writer", ""): w for w in WRITERS}


def load_writers_config(path: str = "writers.conf") -> list:
    """Return enabled writers from config file. Falls back to all if file missing."""
    if not os.path.exists(path):
        return WRITERS
    enabled = []
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            name = line.split("#", 1)[0].strip().lower()
            if not name:
                continue
            if name in _WRITER_REGISTRY:
                enabled.append(_WRITER_REGISTRY[name])
            else:
                print(f"writers.conf: unknown writer '{name}' (ignored)")
    print(f"Writers enabled: {[w.__class__.__name__ for w in enabled]}")
    return enabled


class ListEntries:
    """Exact domains plus wildcard bases (*.base stored as base)."""

    __slots__ = ("exact", "wildcards")

    def __init__(self, exact: set[str] | None = None, wildcards: set[str] | None = None):
        self.exact = exact if exact is not None else set()
        self.wildcards = wildcards if wildcards is not None else set()

    def __len__(self) -> int:
        return len(self.exact) + len(self.wildcards)

    def matches(self, domain: str) -> bool:
        return domain in self.exact or subdomain_matches_wildcards(domain, self.wildcards)


def subdomain_matches_wildcards(domain: str, wildcard_bases: set[str]) -> bool:
    """True if domain is a proper subdomain of any *.base entry (apex itself does not match)."""
    parts = domain.split(".")
    return any(
        ".".join(parts[i:]) in wildcard_bases
        for i in range(1, len(parts))
    )


def load_list_file(path: str) -> ListEntries:
    exact: set[str] = set()
    wildcards: set[str] = set()
    if not os.path.exists(path):
        return ListEntries(exact, wildcards)
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line or line[0] in ("#", "!", ";"):
                continue
            token = line.split("#", 1)[0].strip().lower()
            if not token:
                continue
            if token.startswith("*."):
                base = normalize_domain(token[2:])
                if base:
                    wildcards.add(base)
            else:
                dom = normalize_domain(token)
                if dom:
                    exact.add(dom)
    return ListEntries(exact, wildcards)


def load_allowlist(path: str) -> ListEntries:
    allowed = load_list_file(path)
    print(f"Allowlist: loaded {len(allowed)} entries from {path}")
    return allowed


def load_blocklist(path: str) -> ListEntries:
    blocked = load_list_file(path)
    print(f"Blocklist: loaded {len(blocked)} entries from {path}")
    return blocked


def remove_subdomains(domains: list[str], wildcard_domains: set[str] | None = None) -> list[str]:
    domain_set = set(domains)
    wc = wildcard_domains or set()
    result = []
    for d in domains:
        parts = d.split(".")
        # drop if a parent exact-match exists
        dominated = any(
            ".".join(parts[i:]) in domain_set
            for i in range(1, len(parts) - 1)
        )
        # drop if any ancestor is a wildcard entry (*.ancestor covers this domain)
        if not dominated:
            dominated = any(
                ".".join(parts[i:]) in wc
                for i in range(1, len(parts))
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


def _pick_reader(path: str, sample_size: int = 50):
    """Return the first reader that claims this file, or None."""
    sample: list[str] = []
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                s = line.strip()
                if not s or s.lstrip().startswith(('#', '!')):
                    continue
                sample.append(s)
                if len(sample) >= sample_size:
                    break
    except OSError:
        return None, "file not found"

    for reader in READERS:
        if reader.detect(sample):
            return reader, f"{reader.name} format detected"
    return None, "no recognizable format in sample"


def _collect_domains(raw_dir, pairs, allowlist, source_stats, source_infos, rejected_entries):
    """Scan source files and return (ordered_domains, total_candidates, wildcard_domains)."""
    seen: set[str] = set()
    ordered: list[str] = []
    wildcard_domains: set[str] = set()
    total_candidates = 0

    sources = pairs if pairs else [
        (fname, "")
        for fname in sorted(os.listdir(raw_dir))
        if os.path.isfile(os.path.join(raw_dir, fname))
    ]

    for fname, url in sources:
        path = os.path.join(raw_dir, fname)
        headers = read_leading_header(path)
        reader, reason = _pick_reader(path)
        fmt = reader.name if reader else "unsupported"
        source_infos.append((fname, headers, url, fmt))
        source_stats[fname] = {
            "url": url, "format": fmt, "format_reason": reason,
            "scanned": 0, "accepted": 0, "rejected": 0,
            "skipped": reader is None,
        }
        print(f"{fname}: detected format={fmt} ({reason})")
        if reader is None:
            rejected_entries.append((fname, 0, f"UNSUPPORTED_FILE: {reason}"))
            print(f"Skipping {fname}: {reason}")
            continue
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            for lineno, line in enumerate(fh, start=1):
                stripped = line.strip()
                if not stripped or stripped.lstrip().startswith(('#', '!')):
                    continue
                source_stats[fname]["scanned"] += 1
                result = reader.extract(stripped)
                if result is None:
                    source_stats[fname]["rejected"] += 1
                    rejected_entries.append((fname, lineno, line.rstrip('\n')))
                    continue
                raw, is_wildcard = result
                dom = normalize_domain(raw) if raw else None
                if not dom:
                    source_stats[fname]["rejected"] += 1
                    rejected_entries.append((fname, lineno, line.rstrip('\n')))
                    continue
                source_stats[fname]["accepted"] += 1
                total_candidates += 1
                if dom not in seen and not allowlist.matches(dom):
                    seen.add(dom)
                    ordered.append(dom)
                if is_wildcard:
                    wildcard_domains.add(dom)

    return ordered, total_candidates, wildcard_domains


def merge(raw_dir: str, map_path: str, out_path: str, sort_output: bool = True,
          allowlist_path: str = "allowlist.txt", blocklist_path: str = "blocklist.txt",
          optimize_subdomains: bool = True, writers_config: str = "writers.conf") -> None:
    allowlist = load_allowlist(allowlist_path)
    blocklist = load_blocklist(blocklist_path)
    active_writers = load_writers_config(writers_config)
    pairs = read_map(map_path)
    source_infos: list[tuple[str, list[str], str, str]] = []
    rejected_entries: list[tuple[str, int, str]] = []
    source_stats: dict[str, dict] = {}

    ordered, total_candidates, wildcard_domains = _collect_domains(
        raw_dir, pairs, allowlist, source_stats, source_infos, rejected_entries
    )

    if blocklist.exact or blocklist.wildcards:
        conflicts = allowlist.exact & blocklist.exact
        if conflicts:
            print(
                f"Warning: {len(conflicts)} domain(s) present in both allowlist "
                f"and blocklist; allowlist entries will take precedence: "
                f"{', '.join(sorted(conflicts))}"
            )
        added = 0
        seen_set = set(ordered)
        for dom in sorted(blocklist.exact):
            if dom not in seen_set and not allowlist.matches(dom):
                seen_set.add(dom)
                ordered.append(dom)
                added += 1
        for base in sorted(blocklist.wildcards):
            wildcard_domains.add(base)
            if base not in seen_set and not allowlist.matches(base):
                seen_set.add(base)
                ordered.append(base)
                added += 1
        if added:
            print(f"Blocklist: added {added} forced domain(s) from {blocklist_path}")

    if sort_output:
        ordered = sorted(ordered)
    if optimize_subdomains:
        ordered = remove_subdomains(ordered, wildcard_domains)

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
        wildcard_domains=frozenset(wildcard_domains),
    )

    # ── run enabled writers ───────────────────────────────────────────────────
    for writer in active_writers:
        writer.write(ordered, meta, out_dir)

    # ── rejected entries + JSON report → reports/ ─────────────────────────────
    reports_dir = os.path.join(os.path.dirname(out_path) or ".", "..", "reports")
    reports_dir = os.path.normpath(reports_dir)
    os.makedirs(reports_dir, exist_ok=True)

    rejected_path = os.path.join(reports_dir, "rejected-entries.txt")
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
            "wildcards": len(wildcard_domains),
            "duplicates": duplicates,
            "reduction_pct": round(reduction_pct, 4),
            "delta_added": delta_added,
            "delta_removed": delta_removed,
            "rejected_total": len(rejected_entries),
        },
        "sources": source_stats,
    }
    with open(os.path.join(reports_dir, "blocklist-report.json"), "w", encoding="utf-8") as rf:
        json.dump(report, rf, indent=2, ensure_ascii=False)

    print(f"Processed: scanned={total_candidates} unique={total_unique} "
          f"wildcards={len(wildcard_domains)} duplicates={duplicates} reduction={reduction_pct:.2f}% "
          f"rejected={len(rejected_entries)} sorted={sort_output} -> {rejected_path}")


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Merge raw host files into one processed blocklist")
    p.add_argument("--raw", default="raw")
    p.add_argument("--map", default="raw/sources.map")
    p.add_argument("--out", default="processed/blocklist.txt")
    p.add_argument("--unsorted", action="store_true")
    p.add_argument("--allowlist", default="allowlist.txt")
    p.add_argument("--blocklist", default="blocklist.txt")
    p.add_argument("--no-optimize-subdomains", action="store_true")
    p.add_argument("--writers-config", default="writers.conf")
    args = p.parse_args(argv)

    merge(args.raw, args.map, args.out,
          sort_output=not args.unsorted,
          allowlist_path=args.allowlist,
          blocklist_path=args.blocklist,
          optimize_subdomains=not args.no_optimize_subdomains,
          writers_config=args.writers_config)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
