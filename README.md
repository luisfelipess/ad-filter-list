# ad-filter-list

[![Update blocklists](https://github.com/luisfelipess/ad-filter-list/actions/workflows/update.yml/badge.svg)](https://github.com/luisfelipess/ad-filter-list/actions/workflows/update.yml)

Automated blocklist compiler. Fetches DNS/ad-block lists from multiple sources daily, combines and deduplicates entries, makes DNS output inclusive of subdomains by dropping redundant entries when a parent domain already covers them, and publishes six output formats directly to this repository via GitHub Actions.

- **Daily updates** — rebuilt automatically every day via GitHub Actions
- **Multi-format** — hosts, plain domains, adblock, RPZ, dnsmasq, and unbound in one pipeline
- **Quality filtered** — deduped, subdomain-optimized, IANA TLD validated, IPs and invalid syntax stripped
- **Resilient fetching** — primary + fallback URLs per source, retries with exponential backoff
- **Transparent** — per-source stats, rejected entries log, and delta tracking on every run

---

## Design tenets

**One combined list, done well.**
The output of this project is a single merged, quality-filtered blocklist per format — not individual per-source conversions. The value is in the pipeline: cross-source deduplication, subdomain optimization, IANA TLD validation, and syntax filtering that make the combined result better than any individual source on its own.

**Other approaches are equally valid.**
Some projects convert upstream lists individually to specific formats without merging them. That's a legitimate and useful approach. This project simply takes a different position: if a domain appears in three sources, you should see it once, optimized, and clean — not three times across three files. If you want the individual upstream lists in a specific format, the upstream maintainers often already publish them directly.

**Custom configurations are a first-class local use case.**
Want only certain sources? Different combinations? A more aggressive or more conservative set? `sources.conf`, `allowlist.txt`, and `blocklist.txt` are designed for exactly that. Clone the repo, edit the config, run `python3 run.py`. The pipeline is self-contained and requires no external dependencies beyond Python 3.8.

**Pre-built flavours are on the radar, not the roadmap.**
Different pre-built variants (light, standard, aggressive) combining different source subsets are an interesting future direction. We don't have a clean implementation path for them yet and they're not a current priority — see the TODO.

---

<!-- stats:start -->
**Last run:** 2026-05-27 &nbsp;·&nbsp; **Sources:** 6 &nbsp;·&nbsp; **Unique domains:** 905,946 *(hosts/domains)* · 673,520 *(DNS-optimized)* &nbsp;·&nbsp; **Wildcards:** 80,444

| Format | Download | Domains | Use case |
|---|---|---|---|
| Hosts (`0.0.0.0 domain`) | [blocklist.txt](https://raw.githubusercontent.com/luisfelipess/ad-filter-list/main/processed/blocklist.txt) | 905,946 | MikroTik adlists, Pi-hole, generic hosts |
| Plain domains | [blocklist-domains.txt](https://raw.githubusercontent.com/luisfelipess/ad-filter-list/main/processed/blocklist-domains.txt) | 905,946 | Generic use, custom DNS resolvers |
| Adblock syntax | [blocklist-adblock.txt](https://raw.githubusercontent.com/luisfelipess/ad-filter-list/main/processed/blocklist-adblock.txt) | 673,520 | uBlock Origin, AdGuard, browser extensions |
| BIND9 RPZ (gzip) | [blocklist-bind9.zone.gz](https://raw.githubusercontent.com/luisfelipess/ad-filter-list/main/processed/blocklist-bind9.zone.gz) | 673,520 | BIND9 `response-policy` |
| dnsmasq | [blocklist-dnsmasq.conf](https://raw.githubusercontent.com/luisfelipess/ad-filter-list/main/processed/blocklist-dnsmasq.conf) | 673,520 | OpenWrt, DD-WRT, Pi-hole (dnsmasq mode) |
| Unbound | [blocklist-unbound.conf](https://raw.githubusercontent.com/luisfelipess/ad-filter-list/main/processed/blocklist-unbound.conf) | 673,520 | Unbound resolver |
<!-- stats:end -->

Run diagnostics are committed alongside the output on every run:

| File | Contents |
|---|---|
| [`reports/blocklist-report.json`](reports/blocklist-report.json) | Per-source stats plus run summary (`matched_allowlisted`, `added_by_blocklist_override`, deltas, wildcards) |
| [`reports/rejected-entries.txt`](reports/rejected-entries.txt) | Lines that could not be parsed, with source file, line number, and rejection reason |

---

## Quick start

```bash
git clone https://github.com/luisfelipess/ad-filter-list.git
cd ad-filter-list
python3 run.py
```

Outputs land in `processed/`. Raw downloaded files go to `raw/` (gitignored).

### Local testing workflow

When tuning `allowlist.txt` or `blocklist.txt`, avoid re-downloading on every edit:

1. **Full run once** — `python3 run.py` downloads all sources into `raw/` and writes `processed/` + `reports/`.
2. **Iterate fast** — edit allowlist/blocklist, then `python3 run.py --skip-download` (add `--unsorted` to preserve first-seen order).
3. **Note** — `--skip-download` reuses whatever is in `raw/` from a prior download. An empty `raw/` means only blocklist overrides will appear.

### Options

| Flag | Effect |
|---|---|
| *(default)* | Download sources, merge, update README stats |
| `--skip-download` | Skip fetch stage; merge existing files in `raw/` |
| `--unsorted` | Preserve first-seen domain order instead of sorting alphabetically |
| `--no-optimize-subdomains` | Disable subdomain optimization — every unique domain is written to all output files |
| `--no-iana-tld-check` | Skip IANA TLD validation (useful when offline) |
| `--max-drop-pct N` | Abort if domain count drops more than N% vs previous run (default: 50) |
| `--no-post-run` | Skip the README stats update step |
| `--workers N` | Parallel download threads (default 8) |
| `--retries N` | Per-URL retry count (default 3) |
| `--timeout N` | Per-request timeout in seconds (default 30) |

```bash
python3 run.py                            # full pipeline
python3 run.py --skip-download            # merge only (fast iteration)
python3 run.py --skip-download --unsorted
python3 run.py --no-post-run              # skip README stats update
```

### Running stages individually

```bash
python3 fetch.py [--sources sources.conf] [--raw raw] [--workers 8] [--retries 3] [--timeout 30]
python3 merge.py [--raw raw] [--map raw/sources.map] [--out processed/blocklist.txt]
                 [--unsorted] [--allowlist allowlist.txt] [--blocklist blocklist.txt]
                 [--no-optimize-subdomains] [--no-iana-tld-check] [--max-drop-pct 50]
                 [--writers-config writers.conf]
python3 post_run.py [--report reports/blocklist-report.json] [--readme README.md]
```

---

## Requirements

- Python 3.8+ (stdlib only — no pip installs needed)
- BIND9 client script additionally requires: `curl`, `gzip`, `named-checkzone`

---

## Configuration

### Sources (`sources.conf`)

Edit `sources.conf` — one URL per line. Lines starting with `#`, `;`, or `!` are ignored. Inline comments are supported. For backward compatibility, `sources.txt` is still accepted if `sources.conf` is missing.

```
https://example.com/hosts.txt               # optional comment
# https://disabled-source.com/list          # commented out
```

To specify a fallback URL for resilient fetching, separate primary and fallback with a comma:

```
https://primary.example.com/list , https://fallback.example.com/list
```

The fallback is tried only if the primary fails after all retries. The primary URL is always used for deduplication and reporting.

Supported source formats are auto-detected: hosts-style (`0.0.0.0 domain` / `127.0.0.1 domain`), domain-only (including `*.domain` wildcard entries), and adblock (`||domain^`). Gzip (`.gz`) and zip (`.zip`) sources are decompressed automatically.

### Output formats (`writers.conf`)

Edit `writers.conf` — one writer name per line. Comment out a line to disable that format. If the file is missing, all formats are produced.

```
hosts
adblock
rpz
# dnsmasq    ← disabled
unbound
domains
```

Override the config path with `--writers-config /path/to/other.conf`.

### Allowlist and blocklist

Two optional files at the repository root adjust the merged output without editing upstream source URLs:

| File | Purpose |
|---|---|
| `allowlist.txt` | Domains that must **never** be blocked, even if they appear in downloaded lists |
| `blocklist.txt` | Domains that must **always** be blocked, even if no source lists them |

One domain per line. Lines starting with `#`, `!`, or `;` are ignored. Inline comments after `#` are supported (`domain.com  # reason`).

| Entry | What it matches |
|---|---|
| `example.com` | The apex host only |
| `*.example.com` | All **proper** subdomains (`www.example.com`, `cdn.ads.example.com`) — **not** `example.com` itself unless you add that explicitly |

**Precedence during merge:**

1. Domains are collected from everything in `raw/`.
2. Any collected domain that matches the allowlist is dropped. Allowlist wins over source entries.
3. Blocklist entries are merged in afterward: exact domains and wildcard bases (`*.foo` → base `foo`) are added if missing and not allowlisted. On overlap, allowlist still wins (a warning is printed if the same apex appears in both files).

**Run metrics** — after merge, check the terminal `Processed:` line or `reports/blocklist-report.json` → `summary`:

| Field | Meaning |
|---|---|
| `scanned` | Total domain entries extracted from all sources (before dedup) |
| `unique_deduped` | Unique domains after exact deduplication — what `blocklist.txt` and `blocklist-domains.txt` contain |
| `reduction_pct_deduped` | Reduction percentage for hosts/domains files (exact dedup only) |
| `unique_optimized` | Unique domains after subdomain optimization — what DNS resolver formats (RPZ, dnsmasq, unbound, adblock) contain |
| `reduction_pct_optimized` | Reduction percentage for DNS formats (exact dedup + subdomain optimization) |
| `wildcards` | Number of wildcard base entries (`*.domain`) in the optimized set |
| `tld_rejected` | Domains rejected because their TLD is not in the IANA root zone |
| `matched_allowlisted` | Unique source domains removed because they matched the allowlist |
| `added_by_blocklist_override` | Domains (or wildcard bases) forced into the output solely from `blocklist.txt` |

`unique_deduped` ≥ `unique_optimized` — the gap is the count of entries that DNS formats omit because a parent domain already covers them. When `--no-optimize-subdomains` is passed, both values are equal.

Example `Processed:` line:
```
Processed: scanned=989104 → deduped=815804 (-16.95%, hosts/domains) → dns-optimized=589557 (-39.98%, adblock/rpz/dnsmasq/unbound) | wildcards=90060 …
```

---

## How it works

```
sources.conf
    │
    ▼
fetch.py  ───── concurrent downloads (ThreadPoolExecutor)
    │             primary + fallback URL per source
    │             retry with exponential backoff
    │             transparent gzip/zip decompression
    │
    ▼
raw/  (gitignored)
    │
    ▼
merge.py  ──── format detection per source  (readers/)
    │           domain extraction & normalisation
    │           allowlist filter + blocklist override
    │           exact deduplication
    │           │
    │           ├── dedup-only list  (hosts / domains — all unique entries)
    │           └── optimized list   (subdomain optimizer applied)
    │                                 (skipped with --no-optimize-subdomains)
    │           delta vs previous run
    │
    ├── writers/ (controlled by writers.conf)
    │     hosts.py      → processed/blocklist.txt          (dedup-only)
    │     domains.py    → processed/blocklist-domains.txt  (dedup-only)
    │     adblock.py    → processed/blocklist-adblock.txt  (optimized)
    │     rpz.py        → processed/blocklist-bind9.zone.gz (optimized)
    │     dnsmasq.py    → processed/blocklist-dnsmasq.conf (optimized)
    │     unbound.py    → processed/blocklist-unbound.conf (optimized)
    │
    └── reports/
          blocklist-report.json
          rejected-entries.txt
```

---

## Data quality pipeline

Every entry from every source passes through a multi-stage quality pipeline before appearing in any output file:

| Step | What happens |
|---|---|
| **Combine** | All sources merged into a single stream |
| **Normalize** | Lowercase; leading/trailing dots and quotes stripped |
| **IDN → punycode** | Internationalized domain names converted to ASCII-compatible encoding (e.g. `münchen.de` → `xn--mnchen-3ya.de`) |
| **Reject IPs** | IPv4 and IPv6 addresses discarded — DNS blocklists operate on names, not addresses |
| **Syntax filter** | Invalid labels (wrong characters, leading/trailing hyphens, label > 63 chars, total > 253 chars) rejected |
| **IANA TLD check** | Domains whose TLD is not in the [IANA root zone](https://data.iana.org/TLD/tlds-alpha-by-domain.txt) rejected (e.g. `.invalid`, `.local`, made-up TLDs from malformed sources) |
| **Exact dedup** | Duplicate domains collapsed to one entry |
| **Subdomain optimization** | DNS-format outputs made inclusive of subdomains: `ads.example.com` dropped when `example.com` is already an explicit blocking entry — blocking the parent covers all children |
| **Wildcard handling** | `*.domain` entries handled format-appropriately per writer (emitted as wildcard patterns or degraded to exact, never promoted) |
| **Allowlist/blocklist** | Override layer applied last — allowlist always wins |

Rejected entries are logged to [`reports/rejected-entries.txt`](reports/rejected-entries.txt) each run with the source file, line number, and rejection reason.

### Wildcard handling and deduplication

Some sources publish wildcard entries (`*.domain`) meaning "block this domain and all subdomains". The pipeline handles these with format-aware logic across two stages.

**Stage 1 — Detection and collection**

`DomainReader` recognises `*.domain` lines and flags them as wildcards (stripping the `*.` prefix so the base domain enters the collected set). `HostsReader` always produces exact entries — a hosts-file line is never promoted to a wildcard.

Source files are classified by the proportion of wildcard lines in a 50-line sample:

| `"format"` in report | Condition |
|---|---|
| `domain-only` | < 10 % of sample lines are `*.domain` |
| `wildcard-domain` | > 90 % of sample lines are `*.domain` |
| `mixed-domain` | 10 – 90 % (genuinely mixed file) |
| `host` | Lines match `0.0.0.0 domain` / `127.0.0.1 domain` |
| `adblock` | Lines match `\|\|domain^` |

**Stage 2 — Format-aware deduplication**

The pipeline produces two domain lists with different deduplication levels:

| List | Used by | What's removed |
|---|---|---|
| **Dedup-only** (`unique_deduped`) | `hosts`, `domains` | Exact duplicates only — every unique domain is kept |
| **Optimized** (`unique_optimized`) | `adblock`, `rpz`, `dnsmasq`, `unbound` | Exact duplicates **+** redundant subdomains — `sub.example.com` dropped when `example.com` is already an explicit blocking entry |

The subdomain optimizer makes DNS-format output **inclusive of subdomains**: `ads.example.com` is dropped when `example.com` is an explicit blocking entry, because a DNS resolver blocking `example.com` already covers all its subdomains. It does **not** remove entries solely because they are under a wildcard base (a wildcard base like `ads.example.com` from `*.ads.example.com` does not count as an explicit parent apex).

To disable subdomain optimization for DNS formats (both lists become identical), pass `--no-optimize-subdomains`.

**Per-format wildcard output:**

| Format | Entry list | Wildcard handling |
|---|---|---|
| `hosts` | Dedup-only | No wildcard syntax; `*.domain` sources contribute only the base exact match (`0.0.0.0 domain`) |
| `domains` | Dedup-only | Same as hosts |
| `adblock` | Optimized | Wildcard entries emit `\|\|*.domain^`; exact entries covered by a wildcard ancestor are dropped |
| `rpz` | Optimized | Wildcard entries emit both `domain IN CNAME .` and `*.domain IN CNAME .` |
| `dnsmasq` | Optimized | `address=/domain/#` natively covers all subdomains; exact entries covered by a wildcard ancestor are dropped |
| `unbound` | Optimized | `local-zone: "domain." always_nxdomain` natively covers all subdomains; covered exact entries are dropped |

The direction is strictly one-way: wildcards degrade to exact for formats that don't support them, but exact entries from hosts sources are never promoted to wildcards.

---

## GitHub Actions automation

The workflow at `.github/workflows/update.yml` runs daily at **03:00 UTC** and on manual trigger (`workflow_dispatch`). No secrets or tokens are required beyond the default `GITHUB_TOKEN` — the workflow uses `permissions: contents: write`.

Steps:
1. Check out repository (`persist-credentials: false`)
2. Set up Python
3. Run `python3 run.py` (full pipeline: fetch → merge → post_run)
4. Write a step summary table to the Actions UI with per-run stats
5. Commit `processed/`, `reports/`, and `README.md` back to `main` with `[skip ci]`; commit message includes the domain count and delta (e.g. `Update blocklists: 905,946 domains (+1,204/-87) [skip ci]`)
6. Upload `processed/` and `reports/` as workflow artifacts (only when files changed)

To trigger the workflow from your machine:

```bash
./scripts/trigger-update-workflow.sh          # trigger and print the latest run URL
./scripts/trigger-update-workflow.sh --watch  # wait until the run finishes
```

---

## Integration guides

### BIND9 RPZ

See [`client-scripts/`](client-scripts/) for the full setup guide and script.

#### named.conf

Add a `zone` block to `named.conf` (or a file it includes):

```
zone "rpz.local" {
    type master;
    file "db.rpz.local";   // relative to BIND's directory option — see client-scripts/README.md
    allow-query { none; };
};
```

Add `response-policy` inside your existing `options {}` block — **not** alongside the zone block:

```
options {
    // ... your existing options ...
    response-policy { zone "rpz.local"; };
};
```

#### Automated daily fetch

On your BIND9 server, download the script directly:

```bash
curl -fsSL https://raw.githubusercontent.com/luisfelipess/ad-filter-list/main/client-scripts/bind9-update-rpz.sh \
    -o /usr/local/sbin/bind9-update-rpz.sh
chmod +x /usr/local/sbin/bind9-update-rpz.sh
```

Bootstrap and schedule. The script reads `named.conf` to discover the zone file path automatically:

```bash
# run once to bootstrap
/usr/local/sbin/bind9-update-rpz.sh

# cron — runs at 04:00 UTC, after the GitHub Actions job at 03:00 UTC
echo "0 4 * * * /usr/local/sbin/bind9-update-rpz.sh >> /var/log/rpz-update.log 2>&1" | crontab -
```

The script auto-detects the zone file path from `named.conf`, the BIND service name (`named`/`bind9`), and the bind group. Pass the zone file path as an argument if auto-detection fails.

### MikroTik adlists

The hosts-format output (`0.0.0.0 domain`) is directly compatible with MikroTik adlists. Point your RouterOS adlist URL at the raw `blocklist.txt` download link from the table above.

---

## Repository layout

```
run.py                           pipeline entry point (fetch → merge → post_run)
fetch.py                         concurrent source downloader
merge.py                         merge, deduplicate, and write all output formats
post_run.py                      update README.md stats block after each run
update.sh                        DEPRECATED wrapper — calls run.py (kept for compat)
update.py                        DEPRECATED shim  — calls run.py (kept for compat)
readers/                         pluggable source format readers
  __init__.py                    BaseReader, normalize_domain, read_leading_header
  hosts.py                       0.0.0.0/127.0.0.1 domain format
  domain.py                      bare domain-only / wildcard-domain lists
  adblock.py                     ||domain^ sources
writers/                         pluggable output format writers
  __init__.py                    BaseWriter, WriterMeta, shared helpers
  hosts.py                       0.0.0.0 domain (MikroTik, Pi-hole)  [dedup-only]
  domains.py                     plain domain-per-line               [dedup-only]
  adblock.py                     ||domain^ (uBlock Origin, AdGuard)  [optimized]
  rpz.py                         BIND9 RPZ gzip zone file            [optimized]
  dnsmasq.py                     address=/domain/# (OpenWrt, DD-WRT) [optimized]
  unbound.py                     local-zone: always_nxdomain         [optimized]
scripts/
  compare.sh                     diff current blocklist against last git-committed version
  trigger-update-workflow.sh     trigger the GitHub Actions workflow via gh CLI
sources.conf                     source URL list (one URL per line; primary , fallback supported)
allowlist.txt                    domains that are never blocked
blocklist.txt                    domains always blocked, even if absent from sources
writers.conf                     enable/disable output writers
client-scripts/
  bind9-update-rpz.sh            BIND9 RPZ fetch-and-reload script
  README.md                      BIND9 setup guide
processed/                       compiled output (committed by CI)
reports/                         run diagnostics (committed by CI)
raw/                             downloaded source files (gitignored)
.github/workflows/update.yml     daily automation workflow
tests/
  test_merge.py                  regression test suite
```

---

## Terminology

This project uses **blocklist** as the preferred neutral term. The same concept is also commonly referred to as *blacklist*, *denylist*, or *filterlist* in other projects and search engines.

---

## License

The pipeline scripts, automation, and documentation in this project are licensed under the **MIT License** — see [LICENSE](LICENSE) for details.

The compiled blocklists are derived from various upstream sources, each with their own licensing terms. While the transformation and formatting are provided under the MIT license, the original filter data remains subject to its respective source licenses. Users should review individual source licenses if redistribution or commercial use is intended.
