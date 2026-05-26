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
_LABEL_RE = re.compile(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?$")
_LOCAL_SKIP = {"localhost", "localhost.localdomain", "local"}


def normalize_domain(raw: str) -> str | None:
    """Lowercase, strip, convert IDN to punycode, reject IPs and invalid syntax."""
    d = raw.lower().strip().strip('"\'').strip('.')
    if not d or d in _LOCAL_SKIP:
        return None
    if IP_RE.match(d) or ':' in d:          # IPv4 or IPv6
        return None
    if not d.isascii():
        try:
            d = d.encode('idna').decode('ascii')
        except (UnicodeError, ValueError):
            return None
    if len(d) > 253 or '.' not in d:        # bare label or over length limit
        return None
    if not all(_LABEL_RE.match(lbl) and len(lbl) <= 63 for lbl in d.split('.')):
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

    def classify(self, sample_lines: list[str]) -> str:
        """Return a specific format label for this sample (defaults to self.name).

        Override when a single reader handles multiple sub-formats that should be
        reported distinctly (e.g. domain-only vs wildcard-domain).
        """
        return self.name

    @abstractmethod
    def extract(self, line: str) -> tuple[str, bool] | None:
        """Extract (domain, is_wildcard) from one line, or None to reject."""
