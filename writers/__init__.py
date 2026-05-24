"""writers/ — pluggable output format writers for merge.py.

Each writer implements BaseWriter.write(domains, meta, out_dir).
Register new formats by adding a module here and appending to WRITERS in merge.py.
"""

from __future__ import annotations

from abc import ABC, abstractmethod


class WriterMeta:
    """Shared metadata passed to every writer."""
    __slots__ = (
        "now_str", "total_candidates",
        "total_unique_optimized", "duplicates_optimized", "reduction_pct_optimized",  # DNS formats
        "total_unique_deduped", "duplicates_deduped", "reduction_pct_deduped",        # hosts/domains
        "delta_added", "delta_removed", "source_infos",
        "wildcard_domains",
    )

    def __init__(self, now_str, total_candidates,
                 total_unique_optimized, duplicates_optimized, reduction_pct_optimized,
                 total_unique_deduped, duplicates_deduped, reduction_pct_deduped,
                 delta_added, delta_removed, source_infos,
                 wildcard_domains=frozenset()):
        self.now_str = now_str
        self.total_candidates = total_candidates
        self.total_unique_optimized = total_unique_optimized
        self.duplicates_optimized = duplicates_optimized
        self.reduction_pct_optimized = reduction_pct_optimized
        self.total_unique_deduped = total_unique_deduped
        self.duplicates_deduped = duplicates_deduped
        self.reduction_pct_deduped = reduction_pct_deduped
        self.delta_added = delta_added
        self.delta_removed = delta_removed
        self.source_infos = source_infos
        self.wildcard_domains = wildcard_domains  # frozenset[str]


class BaseWriter(ABC):
    # Subclasses that do NOT support wildcard/parent-domain blocking (e.g. hosts,
    # plain-domains) should set this to False so they receive the full unique list
    # rather than the subdomain-optimized one.
    optimize_subdomains: bool = True

    @abstractmethod
    def write(self, domains: list[str], meta: WriterMeta, out_dir: str) -> str:
        """Write output file(s) and return the primary output path."""


def format_header_line(line: str, comment_char: str) -> str:
    """Re-prefix a source header line with the given comment character."""
    clean = line.lstrip()
    if clean and clean[0] in ("#", "!", ";") and clean[0] != comment_char:
        return comment_char + clean[1:]
    if clean and clean[0] != comment_char:
        return comment_char + " " + clean
    return line


def write_source_credits(fh, source_infos, comment_char: str) -> None:
    """Write per-source header credits block."""
    for fname, headers, url, fmt in source_infos:
        fh.write(f"{comment_char} ----- Source: {url or fname} ({fname}) -----\n")
        fh.write(f"{comment_char} Detected format: {fmt}\n")
        if headers:
            for h in headers:
                fh.write(format_header_line(h, comment_char) + "\n")
        else:
            fh.write(f"{comment_char} (no header in source file)\n")
        fh.write(f"{comment_char}\n")


def split_wildcard_domains(domains: list[str], wildcard_domains: frozenset) -> tuple[list[str], list[str]]:
    """Split domains into (exact_only, wildcards).

    exact_only: domains not covered by any wildcard entry.
    wildcards:  domains that should be emitted as wildcard records (*.domain).
    Exact domains whose ancestor is in wildcard_domains are dropped entirely.
    """
    exact = []
    for d in domains:
        parts = d.split(".")
        covered = any(
            ".".join(parts[i:]) in wildcard_domains
            for i in range(1, len(parts) + 1)
        )
        if not covered:
            exact.append(d)
    # wildcards are emitted in sorted order
    wildcards = sorted(wildcard_domains & set(domains))
    return exact, wildcards


def summary_line(meta: WriterMeta, comment_char: str, optimized: bool = True) -> list[str]:
    if optimized:
        unique, dupes, pct = meta.total_unique_optimized, meta.duplicates_optimized, meta.reduction_pct_optimized
    else:
        unique, dupes, pct = meta.total_unique_deduped, meta.duplicates_deduped, meta.reduction_pct_deduped
    lines = [
        f"{comment_char} Summary: scanned={meta.total_candidates} unique={unique}"
        f" duplicates={dupes} ({pct:.2f}% reduction)\n",
    ]
    if meta.delta_added or meta.delta_removed:
        lines.append(
            f"{comment_char} Delta vs previous: added={meta.delta_added} removed={meta.delta_removed}\n"
        )
    return lines
