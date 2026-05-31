"""Adblock reader: ||domain^ format (some sources publish in this syntax)."""

from __future__ import annotations

import re
from readers import BaseReader

_ADBLOCK_RE = re.compile(r"^\|\|(\*\.)?([^/^*]+)\^")


class AdblockReader(BaseReader):
    name = "adblock"

    def detect(self, sample_lines: list[str]) -> bool:
        return any(_ADBLOCK_RE.match(line) for line in sample_lines)

    def extract(self, line: str) -> tuple[str, bool] | None:
        m = _ADBLOCK_RE.match(line.strip())
        if not m:
            return None
        is_wildcard = m.group(1) is not None  # True for ||*.domain^
        return m.group(2), is_wildcard
