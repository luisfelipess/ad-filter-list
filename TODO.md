# ad-filter-list Roadmap & Tasks

This document outlines the planned improvements for the `ad-filter-list` tool to extend its performance, format compatibility, and automation.

---

## 🎯 High-Level Objective
Fully automated blocklist compiler that fetches DNS/ad-block lists daily, compiles and deduplicates them, and publishes **five output formats** to the repository via GitHub Actions:
1. **Hosts** (`0.0.0.0 domain`) — MikroTik, Pi-hole, generic hosts
2. **BIND9 RPZ** — `response-policy` zone file (gzip)
3. **Adblock/uBlock** — `||domain^` syntax
4. **dnsmasq** — `address=/domain/#` (OpenWrt, DD-WRT)
5. **Unbound** — `local-zone: always_nxdomain`

Output writers live in `writers/`. Adding a new format = one new file + one line in `merge.py`.

---

## 📋 Roadmap & Tasks

### ✅ Phase 1: Support for Multiple Output Formats
`merge.py` now writes three output formats alongside the standard hosts file:

- [x] **BIND9 Response Policy Zone (RPZ) Format**
  - **Path**: `processed/blocklist-bind9.zone.gz` (gzip-compressed to keep repo size manageable)
  - **Syntax**: Standard DNS zone file with SOA/NS header, mapping domains using CNAMEs to `.` (NXDOMAIN).
- [x] **Adblock/uBlock Filter Syntax**
  - **Path**: `processed/blocklist-adblock.txt`
  - **Syntax**: `||domain.com^` format compatible with uBlock Origin and similar extensions.

### ✅ Phase 2: Daily Automation via GitHub Actions
Hands-free compilation workflow implemented at `.github/workflows/update.yml`.

- [x] **GitHub Actions Workflow** (`.github/workflows/update.yml`)
  - **Schedule**: Daily at 03:00 UTC + manual trigger (`workflow_dispatch`).
  - **Steps**: checkout → setup Python → run `update.sh` → commit & push `processed/` back to the repository with `[skip ci]`.
- [x] **Provide a BIND9 Client Integration Script** (`client-scripts/bind9-update-rpz.sh`)
  - Fetches `blocklist-bind9.zone.gz` from the raw GitHub URL, validates with `named-checkzone`, installs to `/etc/bind/db.rpz.local`, and runs `rndc reload rpz.local`.
  - See [`client-scripts/README.md`](client-scripts/README.md) for setup and cron instructions.

### ✅ Phase 3: Python-based Downloader & Performance
Downloading logic ported to `update.py`; `update.sh` kept as a legacy reference/fallback.

- [x] **Parallel Downloader in Python** (`update.py`)
  - Concurrent downloads via `ThreadPoolExecutor` (default 8 workers).
  - Retry with exponential backoff (default 3 attempts), configurable timeout.
  - Parses `sources.txt` (skips comments/blank lines, strips inline comments).
  - Writes `raw/sources.map` and invokes `merge.py` directly as a module.
- [x] **Compressed File Support**
  - Transparently decompresses gzip (magic bytes or `.gz`) and zip (magic bytes or `.zip`) responses before writing to `raw/`.

### ✅ Phase 4: Smart Filtering & Allowlisting

- [x] **Allowlist Support** (`allowlist.txt`)
  - `merge.py` loads `allowlist.txt` at merge time and silently drops any matching domain.
  - Configurable via `--allowlist <path>` flag. Missing file is silently ignored.
- [x] **Subdomain Redundancy Optimizer**
  - After deduplication, any domain whose parent is already blocked is removed.
  - e.g. if `example.com` is blocked, `ads.example.com` is dropped automatically.
  - Disabled with `--no-optimize-subdomains`. Typically removes 30–40% of entries.
- [x] **Abort on download failure**
  - `update.py` exits non-zero if any source fails all retries; `processed/` is left untouched.
- [x] **Regression test suite** (`tests/test_merge.py`)
  - 32 tests covering `extract_domain`, `load_allowlist`, `remove_subdomains`, and end-to-end merge output (hosts, adblock, RPZ, JSON report).
