#!/usr/bin/env python3
"""Concurrent blocklist source downloader.

Downloads all URLs from sources.conf in parallel into raw/ and writes
raw/sources.map.  Supports gzip/zip sources transparently.

This module only downloads — merging is handled by merge.py.
To run the full pipeline (download + merge + post-run), use run.py.

Usage:
    python3 fetch.py [--sources sources.conf] [--raw raw]
                     [--workers 8] [--retries 3] [--timeout 30]
                     [--incremental]
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import tempfile
from pathlib import Path
import io
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
import zipfile
from concurrent.futures import ThreadPoolExecutor, as_completed

_TIER_RE = re.compile(r'\btier=(\w+)\b')


def read_sources(path: str) -> list[tuple[str, str | None, str]]:
    """Return list of (primary_url, fallback_url|None, tier).

    Each non-comment line may contain one or two URLs separated by a comma
    and an optional tier tag:
        https://primary.example.com/list.txt tier=good
        https://primary.example.com/list , https://fallback.example.com/list tier=light
    The tier tag is an empty string when not specified.
    """
    entries: list[tuple[str, str | None, str]] = []
    if not os.path.exists(path) and path == "sources.conf" and os.path.exists("sources.txt"):
        path = "sources.txt"
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line or line[0] in ("#", ";", "!"):
                continue
            line = line.split("#", 1)[0].strip()
            tier_m = _TIER_RE.search(line)
            tier = tier_m.group(1) if tier_m else ""
            line = _TIER_RE.sub("", line)
            parts = [p.strip() for p in line.split(",", 1)]
            primary = parts[0]
            fallback = parts[1] if len(parts) > 1 and parts[1] else None
            if primary:
                entries.append((primary, fallback, tier))
    return entries


def fetch(
    url: str,
    retries: int,
    timeout: int,
    etag: str | None = None,
    last_modified: str | None = None,
) -> tuple[bytes | None, str | None, str | None]:
    """Fetch url and return (data, etag, last_modified).

    Returns data=None when the server responds 304 Not Modified.
    Sends If-None-Match / If-Modified-Since when etag / last_modified are
    provided (incremental mode only).
    """
    headers: dict[str, str] = {"User-Agent": "ad-filter-list/fetch.py"}
    if etag:
        headers["If-None-Match"] = etag
    elif last_modified:
        headers["If-Modified-Since"] = last_modified

    last_exc: Exception = RuntimeError("no attempts made")
    for attempt in range(1, retries + 1):
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return (
                    resp.read(),
                    resp.headers.get("ETag"),
                    resp.headers.get("Last-Modified"),
                )
        except urllib.error.HTTPError as exc:
            if exc.code == 304:
                return None, etag, last_modified
            last_exc = exc
            if attempt < retries:
                time.sleep(2 ** (attempt - 1))
        except Exception as exc:
            last_exc = exc
            if attempt < retries:
                time.sleep(2 ** (attempt - 1))
    raise last_exc


def decompress(data: bytes, url: str) -> bytes:
    if data[:2] == b"\x1f\x8b" or url.endswith(".gz"):
        return gzip.decompress(data)
    if data[:2] == b"PK" or url.endswith(".zip"):
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            return zf.read(zf.namelist()[0])
    return data


def validate_data(data: bytes) -> None:
    """Reject empty/error pages before replacing any cached source."""
    from readers import normalize_domain
    from readers.adblock import AdblockReader
    from readers.domain import DomainReader
    from readers.hosts import HostsReader

    if b"<html" in data[:1024].lower() or b"<!doctype html" in data[:1024].lower():
        raise ValueError("download is an HTML page")
    readers = (HostsReader(), AdblockReader(), DomainReader())
    for line in data.decode("utf-8", errors="replace").splitlines()[:10000]:
        line = line.strip()
        if not line or line.startswith(("#", "!", ";", "[")):
            continue
        for reader in readers:
            item = reader.extract(line)
            if item and normalize_domain(item[0]):
                return
    raise ValueError("download contains no supported domain entries")


def cache_file(raw_dir: str, url: str) -> Path:
    return Path(raw_dir) / ".source-cache" / (hashlib.sha256(url.encode()).hexdigest() + ".txt")


def atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(dir=path.parent, prefix=".download-")
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def download_one(
    index: int, url: str, fallback: str | None, raw_dir: str,
    retries: int, timeout: int, cache: dict | None = None,
    max_stale_days: float = 7, incremental: bool = True,
    cache_dir: str | None = None,
) -> tuple[str, str, bool, str | None, bool, dict]:
    """Return filename, URL, fallback flag, error, 304 flag, complete cache metadata.

    Cache content is bound to the primary URL and verified by SHA256. Only a
    successful primary response can supply primary conditional validators.
    """
    base = os.path.basename(url.split("?", 1)[0]) or "source"
    fname = f"{index:02d}_{base}"
    dest = Path(raw_dir) / fname
    cached_path = cache_file(cache_dir or raw_dir, url)
    cached = (cache or {}).get(url, {})
    old_data = None
    if cached.get("content_sha256") and cached_path.is_file():
        candidate = cached_path.read_bytes()
        if hashlib.sha256(candidate).hexdigest() == cached["content_sha256"]:
            old_data = candidate
    etag = cached.get("etag") if incremental and old_data is not None else None
    last_modified = cached.get("last_modified") if incremental and old_data is not None else None

    def success(data, etag=None, modified=None, origin=None):
        validate_data(data)
        atomic_write(dest, data)
        metadata = {"content_sha256": hashlib.sha256(data).hexdigest(),
                    "last_success": time.time(), "origin": origin or url}
        if etag:
            metadata["etag"] = etag
        if modified:
            metadata["last_modified"] = modified
        return metadata

    try:
        data, new_etag, new_lm = fetch(url, retries, timeout, etag, last_modified)
        if data is None:
            if old_data is None or not (etag or last_modified):
                raise ValueError("primary returned 304 without a validated cached response")
            metadata = success(old_data, etag, last_modified)
            return fname, url, False, None, True, metadata
        metadata = success(decompress(data, url), new_etag, new_lm)
        return fname, url, False, None, False, metadata
    except Exception as exc:
        error = f"primary: {exc}"

    if fallback:
        print(f"  WARN   {error}, trying fallback: {fallback}", file=sys.stderr)
        try:
            data, _, _ = fetch(fallback, retries, timeout)
            if data is None:
                raise ValueError("fallback returned 304 Not Modified without a cached response")
            metadata = success(decompress(data, fallback), origin=fallback)
            return fname, url, True, None, False, metadata
        except Exception as exc:
            error += f"; fallback: {exc}"

    age = time.time() - cached.get("last_success", 0)
    if old_data is not None and 0 <= age <= max_stale_days * 86400:
        atomic_write(dest, old_data)
        metadata = {**cached, "stale": True, "error": error}
        return fname, url, False, None, False, metadata
    return fname, url, False, error, False, {}


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Download blocklist sources into raw/")
    p.add_argument("--sources", default="sources.conf")
    p.add_argument("--raw", default="raw")
    p.add_argument("--workers", type=int, default=8)
    p.add_argument("--retries", type=int, default=3)
    p.add_argument("--timeout", type=int, default=30)
    p.add_argument("--incremental", action="store_true")
    p.add_argument("--max-stale-days", type=float, default=7,
                   help="maximum cached-source age after a download failure (default: 7)")
    p.add_argument("--max-stale-pct", type=float, default=25,
                   help="maximum percentage of sources reused after failures (default: 25)")
    args = p.parse_args(argv)
    if min(args.workers, args.retries, args.timeout) <= 0:
        p.error("workers, retries, and timeout must be positive")
    if not 0 <= args.max_stale_pct <= 100 or args.max_stale_days < 0:
        p.error("max-stale-pct must be 0..100 and max-stale-days must be nonnegative")

    sources = read_sources(args.sources)
    if not sources:
        print("No sources found.", file=sys.stderr)
        return 1
    os.makedirs(args.raw, exist_ok=True)
    cache_path = Path(args.raw) / ".fetch-cache.json"
    cache = {}
    if cache_path.is_file():
        try:
            cache = json.loads(cache_path.read_text(encoding="utf-8"))
            if not isinstance(cache, dict):
                cache = {}
        except (ValueError, OSError):
            print("Warning: invalid fetch cache metadata; downloading without cache", file=sys.stderr)
    cache = {url: entry for url, entry in cache.items() if isinstance(entry, dict)}

    print(f"Downloading {len(sources)} source(s) with {args.workers} workers…")
    # Indexed files and sources.map stay intact until every source is accounted for.
    with tempfile.TemporaryDirectory(prefix=".fetch-", dir=args.raw) as staged:
        results = []
        with ThreadPoolExecutor(max_workers=args.workers) as pool:
            futures = {
                pool.submit(download_one, i + 1, url, fallback, staged,
                            args.retries, args.timeout, cache, args.max_stale_days,
                            args.incremental, args.raw): (i + 1, url, tier)
                for i, (url, fallback, tier) in enumerate(sources)
            }
            for future in as_completed(futures):
                i, url, tier = futures[future]
                try:
                    result = future.result()
                except Exception as exc:
                    result = ("", url, False, str(exc), False, {})
                results.append((i, tier, result))
        results.sort(key=lambda item: item[0])
        statuses = []
        for _, tier, (fname, url, fallback, error, unchanged, metadata) in results:
            state = ("failed" if error else "stale" if metadata.get("stale") else
                     "cached" if unchanged else "fallback" if fallback else "fresh")
            statuses.append({"url": url, "tier": tier, "status": state,
                             "last_success": metadata.get("last_success"),
                             "origin": metadata.get("origin"),
                             "error": error or metadata.get("error")})
            print(f"  {state.upper():<9} {url}" + (f" — {error or metadata.get('error')}" if state in ("failed", "stale") else ""))
            if not error:
                # Store successful downloads even if another source blocks this run.
                atomic_write(cache_file(args.raw, url), (Path(staged) / fname).read_bytes())
                cache[url] = metadata
        active = {url for url, _, _ in sources}
        atomic_write(cache_path, json.dumps({u: v for u, v in cache.items() if u in active}, indent=2).encode())
        stale_count = sum(item["status"] == "stale" for item in statuses)
        failed_count = sum(item["status"] == "failed" for item in statuses)
        blocked = bool(failed_count or stale_count / len(sources) * 100 > args.max_stale_pct)
        status = {"generated": time.time(), "degraded": bool(stale_count),
                  "stale_sources": stale_count, "failed_sources": failed_count,
                  "blocked": blocked, "sources": statuses}
        atomic_write(Path(args.raw) / "fetch-status.json", json.dumps(status, indent=2).encode())
        if blocked:
            print("Aborting: missing sources or stale-source limit exceeded; processed/ and mapped raw files unchanged.", file=sys.stderr)
            return 1
        rows = []
        for _, tier, (fname, url, _, _, _, _) in results:
            os.replace(Path(staged) / fname, Path(args.raw) / fname)
            rows.append(f"{fname} {url}" + (f" {tier}" if tier else ""))
        atomic_write(Path(args.raw) / "sources.map", ("\n".join(rows) + "\n").encode())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
