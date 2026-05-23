#!/usr/bin/env python3
"""Concurrent blocklist downloader — replaces the curl loop in update.sh.

Reads sources.txt, downloads all URLs in parallel, writes raw/ files and
raw/sources.map, then invokes merge.py.  Supports gzip/zip sources natively.

Usage:
    python3 update.py [--unsorted] [--skip-download] [--sources sources.txt]
                      [--raw raw] [--out processed/blocklist.txt]
                      [--workers 8] [--retries 3] [--timeout 30]
"""

from __future__ import annotations

import argparse
import gzip
import io
import os
import shutil
import sys
import time
import urllib.request
import zipfile
from concurrent.futures import ThreadPoolExecutor, as_completed


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def read_sources(path: str) -> list[str]:
    urls = []
    if not os.path.exists(path) and path == "sources.conf" and os.path.exists("sources.txt"):
        path = "sources.txt"
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line or line[0] in ("#", ";", "!"):
                continue
            url = line.split("#", 1)[0].strip()
            if url:
                urls.append(url)
    return urls


def fetch(url: str, retries: int, timeout: int) -> bytes:
    last_exc: Exception = RuntimeError("no attempts made")
    for attempt in range(1, retries + 1):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "ad-filter-list/update.py"})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return resp.read()
        except Exception as exc:
            last_exc = exc
            if attempt < retries:
                time.sleep(2 ** (attempt - 1))  # 1s, 2s, …
    raise last_exc


def decompress(data: bytes, url: str) -> bytes:
    """Transparently decompress gzip or zip payloads."""
    # gzip magic bytes
    if data[:2] == b"\x1f\x8b" or url.endswith(".gz"):
        return gzip.decompress(data)
    # zip magic bytes
    if data[:2] == b"PK" or url.endswith(".zip"):
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            # take the first file in the archive
            name = zf.namelist()[0]
            return zf.read(name)
    return data


def download_one(
    index: int, url: str, raw_dir: str, retries: int, timeout: int
) -> tuple[str, str, str | None]:
    """Returns (fname, url, error_or_None)."""
    base = os.path.basename(url.split("?", 1)[0]) or "source"
    fname = f"{index:02d}_{base}"
    dest = os.path.join(raw_dir, fname)
    try:
        data = fetch(url, retries, timeout)
        data = decompress(data, url)
        with open(dest, "wb") as fh:
            fh.write(data)
        return fname, url, None
    except Exception as exc:
        return fname, url, str(exc)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def _invoke_merge(args: argparse.Namespace, map_path: str) -> int:
    import merge  # local module

    merge_argv = [
        "--raw", args.raw,
        "--map", map_path,
        "--out", args.out,
        "--blocklist", args.blocklist,
    ]
    if args.unsorted:
        merge_argv.append("--unsorted")
    return merge.main(merge_argv)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Concurrent blocklist downloader")
    p.add_argument("--sources", default="sources.conf")
    p.add_argument("--raw", default="raw")
    p.add_argument("--out", default="processed/blocklist.txt")
    p.add_argument("--unsorted", action="store_true")
    p.add_argument(
        "--skip-download",
        action="store_true",
        help="skip downloading; merge existing files in --raw",
    )
    p.add_argument("--workers", type=int, default=8)
    p.add_argument("--retries", type=int, default=3)
    p.add_argument("--timeout", type=int, default=30)
    p.add_argument("--blocklist", default="blocklist.txt")
    args = p.parse_args(argv)

    os.makedirs(args.raw, exist_ok=True)
    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)

    map_path = os.path.join(args.raw, "sources.map")
    if args.skip_download:
        print(f"Skipping download; using existing files in {args.raw}/")
        if not os.path.isfile(map_path):
            print(
                f"Note: {map_path} not found; merge will scan {args.raw}/ for files.",
                file=sys.stderr,
            )
        return _invoke_merge(args, map_path)

    # clear previous raw files
    for f in os.listdir(args.raw):
        fp = os.path.join(args.raw, f)
        if os.path.isfile(fp):
            os.remove(fp)

    urls = read_sources(args.sources)
    if not urls:
        print("No sources found.", file=sys.stderr)
        return 1

    results: list[tuple[int, str, str, str | None]] = []

    print(f"Downloading {len(urls)} source(s) with {args.workers} workers…")
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = {
            pool.submit(download_one, i + 1, url, args.raw, args.retries, args.timeout): (i + 1, url)
            for i, url in enumerate(urls)
        }
        for future in as_completed(futures):
            i, url = futures[future]
            fname, _, err = future.result()
            results.append((i, fname, url, err))

    # write sources.map in original order (sorted by index)
    results.sort(key=lambda r: r[0])
    failures = [(url, err) for _, _, url, err in results if err]
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
        for _, fname, url, err in results:
            print(f"  OK     {url} -> {args.raw}/{fname}")
            mf.write(f"{fname} {url}\n")

    return _invoke_merge(args, map_path)


if __name__ == "__main__":
    raise SystemExit(main())
