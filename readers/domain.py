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

    def extract(self, line: str) -> tuple[str, bool] | None:
        is_wildcard = line.startswith("*.")
        raw = line[2:] if is_wildcard else line
        tokens = raw.split()
        if len(tokens) == 1 and "." in tokens[0] and not IP_RE.match(tokens[0]):
            return tokens[0], is_wildcard
        return None
