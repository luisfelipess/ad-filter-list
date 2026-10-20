"""Read the unconditional domain subset of Adblock syntax.

Scoped rules are deliberately rejected; DNS cannot represent their conditions.
"""

from __future__ import annotations

import re
from readers import BaseReader

_ADBLOCK_RE = re.compile(r"^\|\|(\*\.)?([^/^*$|]+)\^$")


class AdblockReader(BaseReader):
    name = "adblock"

    def detect(self, sample_lines: list[str]) -> bool:
        return any(line.startswith(("||", "@@||")) for line in sample_lines)

    def extract(self, line: str) -> tuple[str, bool] | None:
        m = _ADBLOCK_RE.fullmatch(line.strip())
        if not m:
            return None
        return m.group(2), m.group(1) is not None

    def exception(self, line: str) -> tuple[str, bool] | None:
        # Widen scoped domain exceptions conservatively: DNS has no request
        # context, so preserving their parent block could overblock traffic.
        if not line.startswith("@@") or line.endswith("$badfilter"):
            return None
        return self.extract(line[2:].split("$", 1)[0])

    def disabled(self, line: str) -> tuple[str, bool] | None:
        suffix = "$badfilter"
        return self.extract(line[:-len(suffix)]) if line.endswith(suffix) else None
