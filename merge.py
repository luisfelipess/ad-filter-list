#!/usr/bin/env python3
"""Merge and sanitize raw host/block files into a single processed blocklist.

Output formats are handled by pluggable writers in the writers/ package.
Add a new format by creating writers/<name>.py and appending to WRITERS below.
"""

from __future__ import annotations

import argparse
import json
import os
import time
import urllib.request
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
    # Wildcard bases entered domain_set via _collect_domains but they are NOT explicit
    # host-blocking entries — only truly explicit entries should trigger parent domination.
    # Using the wildcard base as a parent would incorrectly remove subdomains that are
    # only covered by a wildcard pattern (*.base), not by the base domain itself.
    explicit_set = domain_set - wc
    result = []
    for d in domains:
        parts = d.split(".")
        # drop if a non-wildcard-derived parent exact-match exists
        dominated = any(
            ".".join(parts[i:]) in explicit_set
            for i in range(1, len(parts) - 1)
        )
        if not dominated:
            result.append(d)
    removed = len(domains) - len(result)
    if removed:
        print(f"Subdomain optimizer: removed {removed} redundant subdomain entries")
    return result


def _load_iana_tlds(cache_path: str = ".iana-tlds.cache") -> set[str] | None:
    """Download and cache the IANA root-zone TLD list. Returns lowercase TLD set, or None on failure."""
    max_age = 7 * 24 * 3600  # refresh weekly
    if os.path.exists(cache_path) and time.time() - os.path.getmtime(cache_path) < max_age:
        with open(cache_path, encoding="utf-8") as f:
            return {ln.strip().lower() for ln in f if ln.strip() and not ln.startswith('#')}
    try:
        with urllib.request.urlopen(
            "https://data.iana.org/TLD/tlds-alpha-by-domain.txt", timeout=10
        ) as resp:
            data = resp.read().decode("utf-8")
        with open(cache_path, "w", encoding="utf-8") as f:
            f.write(data)
        return {ln.strip().lower() for ln in data.splitlines() if ln.strip() and not ln.startswith('#')}
    except Exception as exc:
        print(f"Warning: could not fetch IANA TLD list ({exc}) — TLD validation skipped")
        return None


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


_HEALTH_LOW_VALUE_THRESHOLD = 0.01    # net_new / accepted < 1%
_HEALTH_HIGH_REJECTION_THRESHOLD = 0.50  # rejected / scanned > 50%


def _source_health(stats: dict) -> tuple[str, str]:
    """Return (status, reason) for a source based on its single-run stats.

    Statuses: ok | failed | empty | redundant | high_rejection | low_value
    """
    if stats["skipped"]:
        return "failed", "download failed or unsupported format"
    if stats["accepted"] == 0:
        return "empty", "no entries accepted"
    if stats["net_new"] == 0:
        return "redundant", "all entries already covered by earlier sources"
    rejection_rate = stats["rejected"] / stats["scanned"] if stats["scanned"] else 0.0
    if rejection_rate > _HEALTH_HIGH_REJECTION_THRESHOLD:
        return "high_rejection", f"{rejection_rate:.0%} of scanned entries rejected"
    net_new_rate = stats["net_new"] / stats["accepted"]
    if net_new_rate < _HEALTH_LOW_VALUE_THRESHOLD:
        return "low_value", (
            f"{stats['net_new']} net-new of {stats['accepted']} accepted "
            f"({net_new_rate:.1%})"
        )
    return "ok", ""


def _pick_reader(path: str, sample_size: int = 50):
    """Return (reader, fmt, reason) for the first reader that claims this file."""
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
        return None, "unsupported", "file not found"

    for reader in READERS:
        if reader.detect(sample):
            fmt = reader.classify(sample)
            return reader, fmt, f"{fmt} format detected"
    return None, "unsupported", "no recognizable format in sample"


def _collect_domains(raw_dir, pairs, allowlist, source_stats, source_infos, rejected_entries, valid_tlds=None):
    """Scan source files and return (ordered, total_candidates, wildcard_domains, matched_allowlisted, tld_rejected)."""
    seen: set[str] = set()
    allowlisted_skipped: set[str] = set()
    ordered: list[str] = []
    wildcard_domains: set[str] = set()
    total_candidates = 0
    matched_allowlisted = 0
    tld_rejected = 0

    sources = pairs if pairs else [
        (fname, "")
        for fname in sorted(os.listdir(raw_dir))
        if os.path.isfile(os.path.join(raw_dir, fname))
    ]

    for fname, url in sources:
        path = os.path.join(raw_dir, fname)
        headers = read_leading_header(path)
        reader, fmt, reason = _pick_reader(path)
        source_infos.append((fname, headers, url, fmt))
        source_stats[fname] = {
            "url": url, "format": fmt, "format_reason": reason,
            "scanned": 0, "accepted": 0, "rejected": 0, "net_new": 0,
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
                tld = dom.rsplit('.', 1)[-1]
                if valid_tlds is not None and tld not in valid_tlds:
                    source_stats[fname]["rejected"] += 1
                    rejected_entries.append((fname, lineno, f"INVALID_TLD({tld}): {line.rstrip()}"))
                    tld_rejected += 1
                    continue
                source_stats[fname]["accepted"] += 1
                total_candidates += 1
                if allowlist.matches(dom):
                    if dom not in allowlisted_skipped:
                        allowlisted_skipped.add(dom)
                        matched_allowlisted += 1
                elif dom not in seen:
                    seen.add(dom)
                    ordered.append(dom)
                    source_stats[fname]["net_new"] += 1
                if is_wildcard:
                    wildcard_domains.add(dom)

    return ordered, total_candidates, wildcard_domains, matched_allowlisted, tld_rejected


def merge(raw_dir: str, map_path: str, out_path: str, sort_output: bool = True,
          allowlist_path: str = "allowlist.txt", blocklist_path: str = "blocklist.txt",
          optimize_subdomains: bool = True, writers_config: str = "writers.conf",
          skip_iana_check: bool = False, _valid_tlds: set[str] | None = None,
          max_drop_pct: float = 50.0) -> None:
    allowlist = load_allowlist(allowlist_path)
    blocklist = load_blocklist(blocklist_path)
    active_writers = load_writers_config(writers_config)
    pairs = read_map(map_path)
    source_infos: list[tuple[str, list[str], str, str]] = []
    rejected_entries: list[tuple[str, int, str]] = []
    source_stats: dict[str, dict] = {}

    if _valid_tlds is not None:
        valid_tlds = _valid_tlds                 # test/caller-supplied override
    elif skip_iana_check:
        valid_tlds = None
    else:
        valid_tlds = _load_iana_tlds()

    ordered, total_candidates, wildcard_domains, matched_allowlisted, tld_rejected = _collect_domains(
        raw_dir, pairs, allowlist, source_stats, source_infos, rejected_entries, valid_tlds
    )

    added_by_blocklist_override = 0
    if blocklist.exact or blocklist.wildcards:
        conflicts = allowlist.exact & blocklist.exact
        if conflicts:
            print(
                f"Warning: {len(conflicts)} domain(s) present in both allowlist "
                f"and blocklist; allowlist entries will take precedence: "
                f"{', '.join(sorted(conflicts))}"
            )
        seen_set = set(ordered)
        for dom in sorted(blocklist.exact):
            if dom not in seen_set and not allowlist.matches(dom):
                seen_set.add(dom)
                ordered.append(dom)
                added_by_blocklist_override += 1
        for base in sorted(blocklist.wildcards):
            wildcard_domains.add(base)
            if base not in seen_set and not allowlist.matches(base):
                seen_set.add(base)
                ordered.append(base)
                added_by_blocklist_override += 1
        if added_by_blocklist_override:
            print(
                f"Blocklist: added {added_by_blocklist_override} forced domain(s) "
                f"from {blocklist_path}"
            )

    if sort_output:
        ordered = sorted(ordered)

    # ordered_deduped: all unique entries after exact dedup only (hosts / domains files)
    ordered_deduped = list(ordered)
    total_unique_deduped = len(ordered_deduped)
    duplicates_deduped = max(0, total_candidates - total_unique_deduped)
    reduction_pct_deduped = (duplicates_deduped / total_candidates * 100) if total_candidates else 0.0

    # ordered_optimized: after subdomain optimization (DNS resolver formats)
    if optimize_subdomains:
        ordered_optimized = remove_subdomains(ordered_deduped, wildcard_domains)
    else:
        ordered_optimized = ordered_deduped
    total_unique_optimized = len(ordered_optimized)
    duplicates_optimized = max(0, total_candidates - total_unique_optimized)
    reduction_pct_optimized = (duplicates_optimized / total_candidates * 100) if total_candidates else 0.0

    # delta vs previous hosts file (compare against the full dedup-only list)
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
        new_set = {d.lower() for d in ordered_deduped}
        delta_added = len(new_set - prev_domains)
        delta_removed = len(prev_domains - new_set)

    if prev_domains and max_drop_pct < 100.0:
        threshold = len(prev_domains) * (1.0 - max_drop_pct / 100.0)
        if len(ordered_deduped) < threshold:
            drop_pct = (1.0 - len(ordered_deduped) / len(prev_domains)) * 100.0
            raise SystemExit(
                f"ABORT: domain count dropped {drop_pct:.1f}% "
                f"({len(prev_domains):,} → {len(ordered_deduped):,}), "
                f"exceeds --max-drop-pct={max_drop_pct:.0f}%. "
                f"Possible download failure. processed/ left untouched."
            )

    now_str = datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')

    meta = WriterMeta(
        now_str=now_str,
        total_candidates=total_candidates,
        total_unique_optimized=total_unique_optimized,
        duplicates_optimized=duplicates_optimized,
        reduction_pct_optimized=reduction_pct_optimized,
        total_unique_deduped=total_unique_deduped,
        duplicates_deduped=duplicates_deduped,
        reduction_pct_deduped=reduction_pct_deduped,
        delta_added=delta_added,
        delta_removed=delta_removed,
        source_infos=source_infos,
        wildcard_domains=frozenset(wildcard_domains),
    )

    # ── run enabled writers ───────────────────────────────────────────────────
    output_sizes: dict[str, int] = {}
    for writer in active_writers:
        # hosts/domains writers get the full dedup-only list; DNS resolver writers
        # get the subdomain-optimized list
        domains_for_writer = ordered_deduped if not writer.optimize_subdomains else ordered_optimized
        written_path = writer.write(domains_for_writer, meta, out_dir)
        if not domains_for_writer and written_path and os.path.exists(written_path):
            os.remove(written_path)
            print(f"Removed empty output: {written_path}")
        elif written_path and os.path.exists(written_path):
            output_sizes[os.path.basename(written_path)] = os.path.getsize(written_path)

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

    # ── source health ─────────────────────────────────────────────────────────
    health_issues: list[tuple[str, str, str]] = []
    for fname, stats in source_stats.items():
        status, reason = _source_health(stats)
        stats["health"] = status
        if reason:
            stats["health_reason"] = reason
        if status != "ok":
            health_issues.append((fname, status, reason))
    if health_issues:
        print(f"\nSource health ({len(health_issues)} issue(s)):")
        for fname, status, reason in health_issues:
            print(f"  {status.upper():<16} {fname}: {reason}")

    # ── JSON report ───────────────────────────────────────────────────────────
    report = {
        "generated": now_str,
        "summary": {
            "scanned": total_candidates,
            # dedup-only stats (hosts / plain-domains files)
            "unique_deduped": total_unique_deduped,
            "duplicates_deduped": duplicates_deduped,
            "reduction_pct_deduped": round(reduction_pct_deduped, 4),
            # subdomain-optimized stats (RPZ / dnsmasq / unbound / adblock)
            "unique_optimized": total_unique_optimized,
            "wildcards": len(wildcard_domains),
            "duplicates_optimized": duplicates_optimized,
            "reduction_pct_optimized": round(reduction_pct_optimized, 4),
            "delta_added": delta_added,
            "delta_removed": delta_removed,
            "rejected_total": len(rejected_entries),
            "tld_rejected": tld_rejected,
            "matched_allowlisted": matched_allowlisted,
            "added_by_blocklist_override": added_by_blocklist_override,
            "output_sizes": output_sizes,
        },
        "sources": source_stats,
    }
    with open(os.path.join(reports_dir, "blocklist-report.json"), "w", encoding="utf-8") as rf:
        json.dump(report, rf, indent=2, ensure_ascii=False)

    print(f"Processed: scanned={total_candidates} "
          f"→ deduped={total_unique_deduped} (-{reduction_pct_deduped:.2f}%, hosts/domains) "
          f"→ dns-optimized={total_unique_optimized} (-{reduction_pct_optimized:.2f}%, adblock/rpz/dnsmasq/unbound) "
          f"| wildcards={len(wildcard_domains)} "
          f"rejected={len(rejected_entries)} tld_rejected={tld_rejected} matched_allowlisted={matched_allowlisted} "
          f"added_by_blocklist_override={added_by_blocklist_override} "
          f"sorted={sort_output} → {rejected_path}")


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Merge raw host files into one processed blocklist")
    p.add_argument("--raw", default="raw")
    p.add_argument("--map", default="raw/sources.map")
    p.add_argument("--out", default="processed/blocklist.txt")
    p.add_argument("--unsorted", action="store_true")
    p.add_argument("--allowlist", default="allowlist.txt")
    p.add_argument("--blocklist", default="blocklist.txt")
    p.add_argument("--no-optimize-subdomains", action="store_true")
    p.add_argument("--no-iana-tld-check", action="store_true",
                   help="skip IANA TLD validation (useful when offline)")
    p.add_argument("--writers-config", default="writers.conf")
    p.add_argument("--max-drop-pct", type=float, default=50.0,
                   help="abort if domain count drops by more than this %% vs previous run (default: 50)")
    args = p.parse_args(argv)

    merge(args.raw, args.map, args.out,
          sort_output=not args.unsorted,
          allowlist_path=args.allowlist,
          blocklist_path=args.blocklist,
          optimize_subdomains=not args.no_optimize_subdomains,
          skip_iana_check=args.no_iana_tld_check,
          writers_config=args.writers_config,
          max_drop_pct=args.max_drop_pct)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
