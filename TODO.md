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

- [x] **Per-format delta tracking** — per-tier `delta_domains_deduped`, `delta_domains_optimized`, and `delta_sizes` (per output file, bytes) tracked against the previous run's JSON report; null on first run, populated on every subsequent run; mirrored into `summary` for the default tier; console shows net deduped delta vs prev alongside the existing vs-lighter-tier delta

- [x] **Source health dashboard** — flag sources that consistently produce 0 accepted entries or high rejection rates across runs; `09_hosts` currently contributes 0 `net_new` domains (fully redundant) — a health dashboard would surface this automatically

- [x] **Incremental downloads** — `If-Modified-Since` / ETag support to skip re-downloading unchanged sources

### Tiered outputs

- [x] **Source tier tagging in `sources.conf`** — `tier=<name>` tag syntax on each source line; sources without a tag default to the `*` tier in `tiers.conf` (currently `good`); cumulative: light sources go into light+good+aggressive, good into good+aggressive
- [x] **Multi-tier merge** — single `_collect_domains` pass tracking `domain_min_rank` per domain; per-tier outputs filtered at write time; `tiers.conf` defines hierarchy and default tier
- [x] **Tiered outputs** — all six formats written to `processed/<tier>/` for non-default tiers; default tier (`good`) writes to `processed/` root for backward compatibility
- [x] **README stats table extended for tiers** — `post_run.py` appends per-tier rows when non-default tier output exists; default tier rows labeled with tier name

  Next step: tag each source in `sources.conf` with the appropriate tier (light/good/aggressive).

### net_new ordering bias

- [x] **Sort sources by tier rank before processing** — `pairs_with_ranks` is stable-sorted by tier rank before `_collect_domains`, so lights are always processed before goods, goods before aggressives, preserving `sources.conf` order within each tier. `net_new` is now unambiguous: a lighter source always gets first-seen credit over a heavier one regardless of file position. Untagged sources default to `default_rank` from `tiers.conf`.

### Reader correctness

- [x] **`[Adblock Plus]` header line treated as rejected entry** — files starting with `[Adblock Plus]` caused `read_leading_header` to stop before reaching `! Version:` / `! Last modified:` lines (returning empty headers), and the main loop counted the bracket line as a rejected domain; fixed by treating `[` as a comment/header prefix in all three places (`read_leading_header`, `_pick_reader` sample builder, `_collect_domains` main loop)

- [x] **`||*.domain^` wildcard entries silently dropped** — `AdblockReader` regex `[^/^*]+` excluded `*` so `||*.domain^` lines never matched and were counted as rejected; updated regex to capture optional `*.` prefix and return `is_wildcard=True`, consistent with how `DomainReader` handles `*.domain` lines

### Documentation & source annotation

- [x] **Download table "Use case" column expanded** — each format now lists specific tools with version requirements (e.g. dnsmasq v2.86+, Blocky < v0.23, Brave aggressive mode only); generated by `post_run.py` so all tier tables stay in sync

- [x] **`sources.conf` annotated with registry cross-references** — all 31 sources mapped against AdGuard HostlistsRegistry; registry IDs added, wrong label on `filter_3.txt` corrected, redundant/low-value sources flagged with health status, 25 candidate registry lists documented in commented section at the bottom

### Source discovery

- [ ] **AdGuard Host Lists Registry auto-discovery** — `https://adguardteam.github.io/HostlistsRegistry/assets/filters.json` is a curated JSON meta-index of 64 trusted filter lists; registry has been explored and all 31 current sources annotated with registry IDs in `sources.conf`, with 25 candidate lists documented in a commented section; auto-discovery feature (JSON resolver in `fetch.py` + selection mechanism) not yet implemented

- [x] **Source version/last-modified propagation** — `! Version:` and `! Last modified:` headers parsed from each source file and stored in `reports/blocklist-report.json` under `sources[fname].version` and `.last_modified` (null if absent); `content_sha1` always computed from raw file bytes; `last_changed` carries forward across runs when SHA1 is unchanged, enabling staleness detection even for sources with no version headers; `[Adblock Plus]` preamble line fixed so it no longer breaks header parsing
