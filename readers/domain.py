"""Domain-only reader: bare domain per line, or *.domain wildcard entries."""

from __future__ import annotations

from readers import BaseReader, IP_RE


class DomainReader(BaseReader):
    name = "domain-only"

    def detect(self, sample_lines: list[str]) -> bool:
        for line in sample_lines:
            t = line.lstrip("*.")
            tokens = t.split()
            if (len(tokens) == 1
                    and "." in tokens[0]
                    and not IP_RE.match(tokens[0])
                    and not tokens[0].startswith("||")):
                return True
        return False

    def classify(self, sample_lines: list[str]) -> str:
        """Classify sample as 'wildcard-domain', 'domain-only', or 'mixed-domain'."""
        total = wildcard = 0
        for line in sample_lines:
            stripped = line.strip()
            if not stripped or stripped[0] in ("#", "!", ";"):
                continue
            total += 1
            if stripped.startswith("*."):
                wildcard += 1
        if not total:
            return "domain-only"
        ratio = wildcard / total
        if ratio > 0.9:
            return "wildcard-domain"
        if ratio < 0.1:
            return "domain-only"
        return "mixed-domain"

    def extract(self, line: str) -> tuple[str, bool] | None:
        is_wildcard = line.startswith("*.")
        raw = line[2:] if is_wildcard else line
        tokens = raw.split()
        if len(tokens) == 1 and "." in tokens[0] and not IP_RE.match(tokens[0]):
            return tokens[0], is_wildcard
        return None
