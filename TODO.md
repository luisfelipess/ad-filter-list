# ad-filter-list Roadmap & Tasks

This document outlines the planned improvements for the `ad-filter-list` tool to extend its performance, format compatibility, and automation.

---

## 🎯 High-Level Objective
Transform this tool into a highly optimized, fully automated blocklist compiler. It will fetch DNS/ad-block lists daily, compile them, deduplicate them, and output **three distinct formats** directly to the repository using GitHub Actions:
1. **MikroTik/Standard Hosts (Canonical)**: `0.0.0.0 domain` (remains in `processed/blocklist.txt`)
2. **BIND9 RPZ Zone File**: Response Policy Zone (RPZ) format (e.g., `processed/blocklist-bind9.zone`) for seamless BIND9 integration.
3. **Adblock/uBlock Syntax**: Standard ad-blocking rule format (e.g., `processed/blocklist-adblock.txt`) with `||domain.com^`.

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
- [ ] **Provide a BIND9 Client Integration Script**
  - Write a helper/setup guide or script (`bind9/update-rpz.sh`) that a remote BIND9 server can run daily via a cron job to:
    1. Fetch `blocklist-bind9.zone.gz` directly from the raw GitHub URL.
    2. Reload BIND9 (`rndc reload` or `rndc reload rpz.local`) to apply the blocklist seamlessly.

### Phase 3: Python-based Downloader & Performance
Reduce dependencies on shell commands (`curl`, `bash`, `sed`) to make the compiler robust, cross-platform, and fast.

- [ ] **Parallel Downloader in Python**
  - Port downloading logic from `update.sh` into Python (either inside `merge.py` or a dedicated `download.py`).
  - Implement concurrent downloading using asynchronous programming (`asyncio`/`httpx`) or multi-threading (`ThreadPoolExecutor`).
  - Add download retry policies, connection timeouts, and proper exception handling.
- [ ] **Compressed File Support**
  - Support downloading and parsing gzip (`.gz`) or zip (`.zip`) files automatically to conserve remote server bandwidth.

### Phase 4: Smart Filtering & Allowlisting
Avoid blocking critical services or generating redundant rules.

- [ ] **Allowlist Support**
  - Support a local `allowlist.txt` file containing domains/wildcards that should never be blocked.
  - Filter out these domains during the merge process.
- [ ] **Subdomain Redundancy Optimizer**
  - If a top-level domain is blocked (e.g., `example.com`), strip any of its subdomains (e.g., `ads.example.com`, `tracking.sub.example.com`) from the final compiled lists. This greatly reduces total rule count and resource usage on routers and DNS servers.
