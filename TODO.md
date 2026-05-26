# ad-filter-list Roadmap & Tasks

---

## 🎯 High-Level Objective

Fully automated blocklist compiler that fetches DNS/ad-block lists daily, compiles and deduplicates them, and publishes **six output formats** to the repository via GitHub Actions:

1. **Hosts** (`0.0.0.0 domain`) — MikroTik, Pi-hole, generic hosts
2. **Plain domains** (one per line) — generic use
3. **BIND9 RPZ** — `response-policy` zone file (gzip)
4. **Adblock/uBlock** — `||domain^` syntax
5. **dnsmasq** — `address=/domain/#` (OpenWrt, DD-WRT)
6. **Unbound** — `local-zone: always_nxdomain`

Output writers live in `writers/`. Adding a new format = one new file + one line in `merge.py`.

---

## ✅ Phase 1: Multiple Output Formats

- [x] BIND9 RPZ (`processed/blocklist-bind9.zone.gz`)
- [x] Adblock/uBlock (`processed/blocklist-adblock.txt`)
- [x] dnsmasq (`processed/blocklist-dnsmasq.conf`)
- [x] Unbound (`processed/blocklist-unbound.conf`)
- [x] Plain domains (`processed/blocklist-domains.txt`)
- [x] Pluggable writer architecture — new format = one file in `writers/`

## ✅ Phase 2: Daily Automation via GitHub Actions

- [x] Workflow at `.github/workflows/update.yml` — daily 03:00 UTC + manual trigger
- [x] BIND9 client integration script (`client-scripts/bind9-update-rpz.sh`)

## ✅ Phase 3: Python Downloader & Performance

- [x] `fetch.py` — concurrent downloads via `ThreadPoolExecutor`, retry with exponential backoff, gzip/zip decompression
- [x] `--skip-download` flag for fast local iteration without re-fetching

## ✅ Phase 4: Smart Filtering & Allowlisting

- [x] Allowlist (`allowlist.txt`) with `*.domain` wildcard support
- [x] Blocklist override (`blocklist.txt`) with `*.domain` wildcard support
- [x] Subdomain redundancy optimizer (`remove_subdomains`) — typically removes 20–30% of entries for DNS formats
- [x] Abort on download failure — `processed/` left untouched
- [x] Regression test suite (`tests/test_merge.py`)

## ✅ Phase 5: Wildcard Source Support & Format-Aware Deduplication

- [x] `DomainReader` parses `*.domain` wildcard entries, flags `is_wildcard=True`
- [x] `wildcard_domains` set tracked through merge; wildcard-capable writers emit `||*.domain^`, `*.domain IN CNAME .`, etc.
- [x] **Two-list deduplication**: hosts/domains writers receive all unique entries (exact dedup only); DNS resolver writers receive the subdomain-optimized list
- [x] `BaseWriter.optimize_subdomains` flag routes each writer to the correct list
- [x] `WriterMeta` carries both stat sets (`_all` for hosts/domains, optimized for DNS formats)
- [x] Fixed `remove_subdomains` bug: wildcard bases excluded from `explicit_set` so they don't act as parents
- [x] `summary_line(optimized=True/False)` — each writer's header reports the correct counts

## ✅ Phase 6: Source Classification

- [x] `BaseReader.classify(sample)` — returns specific format label beyond `name`
- [x] `DomainReader.classify()` — `domain-only` / `wildcard-domain` / `mixed-domain` based on 10/90% thresholds
- [x] Format label flows through to `source_stats`, JSON report, and per-file console output

## ✅ Phase 7: Pipeline Restructure & Dynamic README

- [x] `run.py` — unified pipeline entry point (fetch → merge → post_run)
- [x] `fetch.py` — pure downloader, no merge coupling
- [x] `post_run.py` — updates `<!-- stats:start/end -->` block in README.md with current counts and direct download links after every run
- [x] `update.py` / `update.sh` deprecated as shims forwarding to `run.py`
- [x] `compare.sh` and `trigger-update-workflow.sh` moved to `scripts/`; `compare.sh` now uses git history instead of a stale `.old` file
- [x] `blocklist.txt.old` backup removed — git history is the source of truth
- [x] GitHub Actions workflow commits `processed/`, `reports/`, and `README.md` each run

---

## 🔭 Ideas / Future

- [ ] **Source health dashboard** — flag sources that consistently produce 0 accepted entries or high rejection rates
- [ ] **Incremental downloads** — `If-Modified-Since` / ETag support to skip unchanged sources
- [ ] **Per-format delta tracking** — currently delta is computed only against the hosts file
- [ ] **AdGuard Host Lists Registry** — `https://adguardteam.github.io/HostlistsRegistry/assets/filters.json` is a curated JSON meta-index of trusted filter lists; could be used to discover and pull sources automatically rather than maintaining `sources.conf` by hand; needs a JSON source resolver in `fetch.py` and a way to select which lists to include
- [ ] **Source version/last-modified propagation** — extract `! Version:` and `! Last modified:` from upstream source headers and surface them in the JSON report and output file credits (raw header text is already propagated but not parsed)
