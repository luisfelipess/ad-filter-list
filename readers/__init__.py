"""readers/ — pluggable source format readers for merge.py.

Each reader implements:
  detect(lines)       -> bool   (True if this reader owns the format)
  extract(line)       -> str|None  (raw domain from one line, pre-normalisation)

merge.py calls detect() on a sample, picks the first matching reader, then
calls extract() line-by-line.  normalize_domain() is shared post-processing.

Add a new source format: create readers/<name>.py, add to READERS in merge.py.
"""

from __future__ import annotations

import re
from abc import ABC, abstractmethod

IP_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
_LOCAL_SKIP = {"localhost", "localhost.localdomain", "local"}


def normalize_domain(raw: str) -> str | None:
    """Lowercase, strip quotes/dots, reject IPs and local names."""
    d = raw.lower().strip().strip('"\'"').strip('.')
    if not d or d in _LOCAL_SKIP or IP_RE.match(d):
        return None
    return d


def read_leading_header(path: str) -> list[str]:
    """Return the leading comment block from a source file."""
    headers: list[str] = []
    try:
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
    except OSError:
        pass
    return headers


class BaseReader(ABC):
    name: str = ""          # used in format detection output and source_stats

    @abstractmethod
    def detect(self, sample_lines: list[str]) -> bool:
        """Return True if this reader recognises the format from a sample."""

    @abstractmethod
    def extract(self, line: str) -> tuple[str, bool] | None:
        """Extract (domain, is_wildcard) from one line, or None to reject."""
