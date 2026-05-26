#!/usr/bin/env python3
"""Concurrent blocklist source downloader.

Downloads all URLs from sources.conf in parallel into raw/ and writes
raw/sources.map.  Supports gzip/zip sources transparently.

This module only downloads — merging is handled by merge.py.
To run the full pipeline (download + merge + post-run), use run.py.

Usage:
    python3 fetch.py [--sources sources.conf] [--raw raw]
                     [--workers 8] [--retries 3] [--timeout 30]
"""

from __future__ import annotations

import argparse
import gzip
import io
import os
import sys
import time
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


def fetch(url: str, retries: int, timeout: int) -> bytes:
    last_exc: Exception = RuntimeError("no attempts made")
    for attempt in range(1, retries + 1):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "ad-filter-list/fetch.py"})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return resp.read()
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
    index: int, url: str, fallback: str | None, raw_dir: str, retries: int, timeout: int
) -> tuple[str, str, bool, str | None]:
    """Return (fname, primary_url, fallback_used, error_or_None)."""
    base = os.path.basename(url.split("?", 1)[0]) or "source"
    fname = f"{index:02d}_{base}"
    dest = os.path.join(raw_dir, fname)

    # Try primary
    primary_exc: Exception | None = None
    try:
        data = fetch(url, retries, timeout)
        data = decompress(data, url)
        with open(dest, "wb") as fh:
            fh.write(data)
        return fname, url, False, None
    except Exception as exc:
        primary_exc = exc

    # Try fallback
    if fallback:
        print(f"  WARN   primary failed ({primary_exc}), trying fallback: {fallback}",
              file=sys.stderr)
        try:
            data = fetch(fallback, retries, timeout)
            data = decompress(data, fallback)
            with open(dest, "wb") as fh:
                fh.write(data)
            return fname, url, True, None
        except Exception as fb_exc:
            return fname, url, False, f"primary: {primary_exc}; fallback: {fb_exc}"

    return fname, url, False, str(primary_exc)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Download blocklist sources into raw/")
    p.add_argument("--sources", default="sources.conf")
    p.add_argument("--raw", default="raw")
    p.add_argument("--workers", type=int, default=8)
    p.add_argument("--retries", type=int, default=3)
    p.add_argument("--timeout", type=int, default=30)
    args = p.parse_args(argv)

    os.makedirs(args.raw, exist_ok=True)
    map_path = os.path.join(args.raw, "sources.map")

    for f in os.listdir(args.raw):
        fp = os.path.join(args.raw, f)
        if os.path.isfile(fp):
            os.remove(fp)

    sources = read_sources(args.sources)
    if not sources:
        print("No sources found.", file=sys.stderr)
        return 1

    results: list[tuple[int, str, str, bool, str | None]] = []
    print(f"Downloading {len(sources)} source(s) with {args.workers} workers…")
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = {
            pool.submit(
                download_one, i + 1, url, fallback, args.raw, args.retries, args.timeout
            ): (i + 1, url)
            for i, (url, fallback) in enumerate(sources)
        }
        for future in as_completed(futures):
            i, url = futures[future]
            fname, _, fb_used, err = future.result()
            results.append((i, fname, url, fb_used, err))

    results.sort(key=lambda r: r[0])
    failures = [(url, err) for _, _, url, _, err in results if err]
    if failures:
        for url, err in failures:
            print(f"  FAILED {url}: {err}", file=sys.stderr)
        print(
            f"\nAborting: {len(failures)} source(s) failed after {args.retries} retries. "
            "processed/ is unchanged.",
            file=sys.stderr,
        )
        return 1

    with open(map_path, "w", encoding="utf-8") as mf:
        for _, fname, url, fb_used, _ in results:
            tag = "FALLBACK" if fb_used else "OK"
            print(f"  {tag:<8} {url} -> {args.raw}/{fname}")
            mf.write(f"{fname} {url}\n")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
