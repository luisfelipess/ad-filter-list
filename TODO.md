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
- [x] `WriterMeta` carries both stat sets (`_deduped` for hosts/domains, `_optimized` for DNS formats)
- [x] Fixed `remove_subdomains` bug: wildcard bases excluded from `explicit_set` so they don't act as parents
- [x] `summary_line(optimized=True/False)` — each writer's header reports the correct counts

## ✅ Phase 6: Source Classification

- [x] `BaseReader.classify(sample)` — returns specific format label beyond `name`
- [x] `DomainReader.classify()` — `domain-only` / `wildcard-domain` / `mixed-domain` based on 10/90% thresholds
- [x] Format label flows through to `source_stats`, JSON report, and per-file console output

## ✅ Phase 7: Pipeline Restructure & Dynamic README

- [x] `run.py` — unified pipeline entry point (fetch → merge → post_run)
- [x] `fetch.py` — pure downloader, no merge coupling
- [x] `post_run.py` — updates `<!-- stats:start/end -->` block in README.md with current counts, file sizes, and direct download links after every run
- [x] `update.py` / `update.sh` deprecated as shims forwarding to `run.py`
- [x] `compare.sh` and `trigger-update-workflow.sh` moved to `scripts/`; `compare.sh` now uses git history instead of a stale `.old` file
- [x] `blocklist.txt.old` backup removed — git history is the source of truth
- [x] GitHub Actions workflow commits `processed/`, `reports/`, and `README.md` each run

## ✅ Phase 8: Quality, Resilience & Observability

- [x] `normalize_domain()` — IPv6 rejection, IDN→punycode conversion, full label syntax validation
- [x] IANA TLD validation — weekly-cached root zone list; `--no-iana-tld-check` to skip
- [x] Primary + fallback URL per source in `sources.conf` (`primary , fallback` syntax)
- [x] Domain drop regression guard — `--max-drop-pct` (default 50%) aborts merge if count drops too far; `processed/` left untouched
- [x] Empty output file removal — writers that produce no domains clean up after themselves
- [x] Per-source `net_new` count — how many domains each source contributed that no earlier source had; stored in `sources[fname].net_new` in JSON report
- [x] File sizes in JSON report and README stats table — `summary.output_sizes` keyed by filename; Size column in download table
- [x] GitHub Actions: `persist-credentials: false`, step summary table, richer commit message with domain count and delta
- [x] Repository topics set for discoverability (`mikrotik-adlist`, `blocklist`, `dns-blocklist`, etc.)

---

## 🔭 Ideas / Future

### Documentation

- [x] **MikroTik RouterOS integration guide** — expand the thin MikroTik section in README with actual RouterOS 7 commands: `/ip/dns/adlist add url=...`, cache-size guidance keyed to list size (~20 MiB for 400K domains, ~40 MiB for 900K, ~200 MiB for 1.4M), RouterOS 7.15 minimum version requirement, IPv6 bypass warning (clients on IPv6 can skip router DNS — need `dns-static` filtering or outbound DoH/DoT blocking)

### Output & reporting

- [ ] **Per-format delta tracking** — currently delta is computed only against the hosts file; each writer could compare against its own previous output

- [ ] **Source health dashboard** — flag sources that consistently produce 0 accepted entries or high rejection rates across runs; `09_hosts` currently contributes 0 `net_new` domains (fully redundant) — a health dashboard would surface this automatically

- [ ] **Incremental downloads** — `If-Modified-Since` / ETag support to skip re-downloading unchanged sources

### Tiered outputs

- [ ] **Source tier tagging in `sources.conf`** — allow each source line to carry a tier label (`small`, `medium`, `large`); sources without a label default to `large`; tag semantics are cumulative: `small` sources go into all tiers, `medium` into medium+large, `large` into large only; syntax sketch (backward-compatible):
  ```
  https://hagezi/pro.txt tier=small , https://fallback/pro.txt
  https://stevenblack/hosts tier=medium
  https://hagezi/pro-plus.txt  # tier=large (default)
  ```

- [ ] **Multi-tier merge** — run `_collect_domains` once per tier using the filtered source subset; produces three domain pools (small ⊆ medium ⊆ large); avoids re-downloading; add `--tiers small,medium,large` flag to `merge.py`

- [ ] **Tiered host-format outputs** — emit `processed/blocklist-small.txt`, `processed/blocklist-medium.txt`, `processed/blocklist-large.txt` (hosts `0.0.0.0 domain` format); `processed/blocklist.txt` stays as-is and maps to the large tier (backward-compatible); other formats (RPZ, dnsmasq, adblock, unbound) continue to emit a single merged file from all sources — tiers are primarily motivated by MikroTik / Pi-hole RAM constraints, which don't apply the same way to server-side DNS resolvers

- [ ] **README stats table extended for tiers** — `post_run.py` emits one row per tier for the hosts format, showing domain count and file size; DNS-format rows stay as single entries

  Sketch of what the table would look like:
  ```
  | Hosts (small)  | blocklist-small.txt  | ~136K | ~2 MB  | MikroTik low-RAM (<32 MiB cache) |
  | Hosts (medium) | blocklist-medium.txt | ~400K | ~5 MB  | MikroTik mid-range               |
  | Hosts (large)  | blocklist.txt        | ~906K | ~12 MB | MikroTik high-end, Pi-hole       |
  ```

  Tier boundaries depend on which sources are tagged; the current single merged pool becomes the large tier by default.

### Source discovery

- [ ] **AdGuard Host Lists Registry** — `https://adguardteam.github.io/HostlistsRegistry/assets/filters.json` is a curated JSON meta-index of trusted filter lists; could be used to discover and pull sources automatically rather than maintaining `sources.conf` by hand; needs a JSON source resolver in `fetch.py` and a way to select which lists to include

- [ ] **Source version/last-modified propagation** — extract `! Version:` and `! Last modified:` from upstream source headers and surface them in the JSON report and output file credits (raw header text is already propagated but not parsed)
