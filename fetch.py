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
import io
import json
import os
import sys
import time
import urllib.error
import urllib.request
import zipfile
from concurrent.futures import ThreadPoolExecutor, as_completed


def read_sources(path: str) -> list[tuple[str, str | None]]:
    """Return list of (primary_url, fallback_url|None).

    Each non-comment line may contain one or two URLs separated by a comma:
        https://primary.example.com/list.txt , https://fallback.example.com/list.txt
    """
    entries: list[tuple[str, str | None]] = []
    if not os.path.exists(path) and path == "sources.conf" and os.path.exists("sources.txt"):
        path = "sources.txt"
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line or line[0] in ("#", ";", "!"):
                continue
            line = line.split("#", 1)[0].strip()
            parts = [p.strip() for p in line.split(",", 1)]
            primary = parts[0]
            fallback = parts[1] if len(parts) > 1 and parts[1] else None
            if primary:
                entries.append((primary, fallback))
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


def download_one(
    index: int,
    url: str,
    fallback: str | None,
    raw_dir: str,
    retries: int,
    timeout: int,
    cache: dict | None = None,
) -> tuple[str, str, bool, str | None, bool, dict]:
    """Return (fname, primary_url, fallback_used, error_or_None, not_modified, cache_patch).

    cache_patch is a {url: {etag, last_modified}} dict for updating the fetch
    cache after a successful 200 response.  Empty dict when nothing to update.
    not_modified is True when the server returned 304.
    """
    base = os.path.basename(url.split("?", 1)[0]) or "source"
    fname = f"{index:02d}_{base}"
    dest = os.path.join(raw_dir, fname)

    # Only send conditional headers when we have a cached entry AND the raw
    # file still exists on disk (guards against manual deletions).
    cached = (cache or {}).get(url, {})
    etag = cached.get("etag") if cache and os.path.exists(dest) else None
    last_modified = cached.get("last_modified") if cache and os.path.exists(dest) else None

    primary_exc: Exception | None = None
    try:
        data, new_etag, new_lm = fetch(url, retries, timeout, etag, last_modified)
        if data is None:
            # 304 Not Modified — existing raw file is still valid
            return fname, url, False, None, True, {}
        data = decompress(data, url)
        with open(dest, "wb") as fh:
            fh.write(data)
        patch: dict = {}
        if new_etag:
            patch["etag"] = new_etag
        if new_lm:
            patch["last_modified"] = new_lm
        return fname, url, False, None, False, patch
    except Exception as exc:
        primary_exc = exc

    # Try fallback — no conditional headers (different URL, no cached entry)
    if fallback:
        print(f"  WARN   primary failed ({primary_exc}), trying fallback: {fallback}",
              file=sys.stderr)
        try:
            data, _, _ = fetch(fallback, retries, timeout)
            data = decompress(data, fallback)
            with open(dest, "wb") as fh:
                fh.write(data)
            return fname, url, True, None, False, {}
        except Exception as fb_exc:
            return fname, url, False, f"primary: {primary_exc}; fallback: {fb_exc}", False, {}

    return fname, url, False, str(primary_exc), False, {}


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Download blocklist sources into raw/")
    p.add_argument("--sources", default="sources.conf")
    p.add_argument("--raw", default="raw")
    p.add_argument("--workers", type=int, default=8)
    p.add_argument("--retries", type=int, default=3)
    p.add_argument("--timeout", type=int, default=30)
    p.add_argument("--incremental", action="store_true",
                   help="skip sources unchanged since last run (ETag / If-Modified-Since)")
    args = p.parse_args(argv)

    os.makedirs(args.raw, exist_ok=True)
    map_path = os.path.join(args.raw, "sources.map")
    cache_path = os.path.join(args.raw, ".fetch-cache.json")

    # Load ETag/Last-Modified cache from previous run
    cache: dict[str, dict] = {}
    if args.incremental and os.path.exists(cache_path):
        with open(cache_path, encoding="utf-8") as cf:
            cache = json.load(cf)

    # In normal mode wipe raw/ so stale files never bleed into merge.
    # In incremental mode we keep existing files for sources that return 304.
    if not args.incremental:
        for f in os.listdir(args.raw):
            fp = os.path.join(args.raw, f)
            if os.path.isfile(fp):
                os.remove(fp)

    sources = read_sources(args.sources)
    if not sources:
        print("No sources found.", file=sys.stderr)
        return 1

    # Expected raw filenames for the current sources.conf — used for orphan cleanup.
    expected_fnames = {
        f"{i + 1:02d}_{os.path.basename(url.split('?', 1)[0]) or 'source'}"
        for i, (url, _) in enumerate(sources)
    }

    results: list[tuple[int, str, str, bool, str | None, bool, dict]] = []
    print(f"Downloading {len(sources)} source(s) with {args.workers} workers…")
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = {
            pool.submit(
                download_one, i + 1, url, fallback, args.raw, args.retries, args.timeout,
                cache if args.incremental else None,
            ): (i + 1, url)
            for i, (url, fallback) in enumerate(sources)
        }
        for future in as_completed(futures):
            i, url = futures[future]
            fname, _, fb_used, err, not_modified, cache_patch = future.result()
            results.append((i, fname, url, fb_used, err, not_modified, cache_patch))

    results.sort(key=lambda r: r[0])
    failures = [(url, err) for _, _, url, _, err, _, _ in results if err]
    if failures:
        for url, err in failures:
            print(f"  FAILED {url}: {err}", file=sys.stderr)
        print(
            f"\nAborting: {len(failures)} source(s) failed after {args.retries} retries. "
            "processed/ is unchanged.",
            file=sys.stderr,
        )
        return 1

    not_modified_count = 0
    for _, fname, url, fb_used, _, not_modified, cache_patch in results:
        if not_modified:
            not_modified_count += 1
            tag = "CACHED"
        else:
            tag = "FALLBACK" if fb_used else "OK"
        print(f"  {tag:<8} {url} -> {args.raw}/{fname}")
        if args.incremental and cache_patch:
            cache[url] = cache_patch

    if args.incremental:
        if not_modified_count:
            print(
                f"Incremental: {not_modified_count} source(s) unchanged (304), "
                f"{len(sources) - not_modified_count} refreshed"
            )
        with open(cache_path, "w", encoding="utf-8") as cf:
            json.dump(cache, cf, indent=2)

        # Remove files that no longer correspond to any source in sources.conf.
        _ignored = {"sources.map", ".fetch-cache.json"}
        for f in os.listdir(args.raw):
            fp = os.path.join(args.raw, f)
            if os.path.isfile(fp) and f not in expected_fnames and f not in _ignored:
                os.remove(fp)

    with open(map_path, "w", encoding="utf-8") as mf:
        for _, fname, url, _, _, _, _ in results:
            mf.write(f"{fname} {url}\n")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
