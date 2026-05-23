"""Domain-only reader: bare domain per line (no leading IP)."""

from __future__ import annotations

from readers import BaseReader, IP_RE


class DomainReader(BaseReader):
    name = "domain-only"

    def detect(self, sample_lines: list[str]) -> bool:
        hits = 0
        for line in sample_lines:
            tokens = line.split()
            if (len(tokens) == 1
                    and "." in tokens[0]
                    and not IP_RE.match(tokens[0])
                    and not tokens[0].startswith("||")):
                hits += 1
        return hits > 0

    def extract(self, line: str) -> str | None:
        tokens = line.split()
        if len(tokens) == 1 and "." in tokens[0] and not IP_RE.match(tokens[0]):
            return tokens[0]
        return None
