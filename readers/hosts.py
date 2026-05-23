"""Hosts-format reader: 0.0.0.0 domain / 127.0.0.1 domain / ::1 domain."""

from __future__ import annotations

from readers import BaseReader, IP_RE

_ALLOWED = {"0.0.0.0", "127.0.0.1", "::1", "::"}


class HostsReader(BaseReader):
    name = "host"

    def detect(self, sample_lines: list[str]) -> bool:
        hits = 0
        for line in sample_lines:
            tokens = line.split()
            if (tokens and (tokens[0] in _ALLOWED or IP_RE.match(tokens[0]))
                    and tokens[0] in _ALLOWED
                    and len(tokens) > 1
                    and "." in tokens[1]
                    and not IP_RE.match(tokens[1])):
                hits += 1
        return hits > 0

    def extract(self, line: str) -> str | None:
        tokens = line.split()
        if len(tokens) < 2 or tokens[0] not in _ALLOWED:
            return None
        return next((t for t in tokens[1:] if "." in t and not IP_RE.match(t)), None)
