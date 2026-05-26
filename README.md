# ad-filter-list

Automated blocklist compiler. Fetches DNS/ad-block lists from multiple sources daily, merges and deduplicates them, and publishes five output formats directly to this repository via GitHub Actions.

<!-- stats:start -->
**Last run:** 2026-05-26 &nbsp;·&nbsp; **Sources:** 6 &nbsp;·&nbsp; **Unique domains:** 901,363 *(hosts/domains)* · 672,388 *(DNS-optimized)* &nbsp;·&nbsp; **Wildcards:** 87,384

| Format | Download | Domains |
|---|---|---|
| Hosts (`0.0.0.0 domain`) | [blocklist.txt](https://raw.githubusercontent.com/luisfelipess/ad-filter-list/main/processed/blocklist.txt) | 901,363 |
| Plain domains | [blocklist-domains.txt](https://raw.githubusercontent.com/luisfelipess/ad-filter-list/main/processed/blocklist-domains.txt) | 901,363 |
| Adblock syntax | [blocklist-adblock.txt](https://raw.githubusercontent.com/luisfelipess/ad-filter-list/main/processed/blocklist-adblock.txt) | 672,388 |
| BIND9 RPZ (gzip) | [blocklist-bind9.zone.gz](https://raw.githubusercontent.com/luisfelipess/ad-filter-list/main/processed/blocklist-bind9.zone.gz) | 672,388 |
| dnsmasq | [blocklist-dnsmasq.conf](https://raw.githubusercontent.com/luisfelipess/ad-filter-list/main/processed/blocklist-dnsmasq.conf) | 672,388 |
| Unbound | [blocklist-unbound.conf](https://raw.githubusercontent.com/luisfelipess/ad-filter-list/main/processed/blocklist-unbound.conf) | 672,388 |
<!-- stats:end -->

## Output formats

| File | Format | Use case |
|---|---|---|
| `processed/blocklist.txt` | `0.0.0.0 domain` hosts format | MikroTik adlists, Pi-hole, generic hosts |
| `processed/blocklist-bind9.zone.gz` | BIND9 RPZ zone file (gzip) | BIND9 `response-policy` |
| `processed/blocklist-adblock.txt` | `\|\|domain^` adblock syntax | uBlock Origin, AdGuard, browser extensions |
| `processed/blocklist-dnsmasq.conf` | `address=/domain/#` dnsmasq config | OpenWrt, DD-WRT, Pi-hole (dnsmasq mode) |
| `processed/blocklist-unbound.conf` | `local-zone: always_nxdomain` | Unbound resolver |

Run diagnostics land in `reports/`:

| File | Contents |
|---|---|
| `reports/blocklist-report.json` | Per-source stats plus run summary (`matched_allowlisted`, `added_by_blocklist_override`, deltas, wildcards) |
| `reports/rejected-entries.txt` | Lines that could not be parsed, for debugging source quality |

All files are committed back to the repository automatically after each run.

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

For merge-only experiments (no download):

```bash
python3 merge.py --raw raw --map raw/sources.map --out processed/blocklist.txt
```

### Options

| Flag | Effect |
|---|---|
| *(default)* | Download sources, merge, update README stats |
| `--skip-download` | Skip fetch stage; merge existing files in `raw/` |
| `--unsorted` | Preserve first-seen domain order instead of sorting alphabetically |
| `--no-optimize-subdomains` | Disable subdomain optimization for DNS formats — every unique domain is written to all output files |
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

Individual stages can also be called directly:

```bash
python3 fetch.py [--sources sources.conf] [--raw raw] [--workers 8] [--retries 3] [--timeout 30]
python3 merge.py [--raw raw] [--map raw/sources.map] [--out processed/blocklist.txt]
                 [--unsorted] [--allowlist allowlist.txt] [--blocklist blocklist.txt]
                 [--no-optimize-subdomains] [--writers-config writers.conf]
python3 post_run.py [--report reports/blocklist-report.json] [--readme README.md]
```

---

## Adding or removing sources

Edit `sources.conf` — one URL per line. Lines starting with `#`, `;`, or `!` are ignored. Inline comments are supported. For backward compatibility, `sources.txt` is still accepted if `sources.conf` is missing.

```
https://example.com/hosts.txt        # optional comment
# https://disabled-source.com/list   # commented out
```

Supported source formats are auto-detected: hosts-style (`0.0.0.0 domain` / `127.0.0.1 domain`), domain-only, and mixed. Gzip (`.gz`) and zip (`.zip`) sources are decompressed automatically.

---

## Enabling or disabling output formats

Edit `writers.conf` — one writer name per line. Comment out a line to disable that format. If the file is missing, all formats are produced.

```
hosts
adblock
rpz
# dnsmasq    ← disabled
unbound
```

Override the config path with `--writers-config /path/to/other.conf`.

---

## Allowlist and blocklist

Two optional files at the repository root adjust the merged output without editing upstream source URLs:

| File | Purpose |
|---|---|
| `allowlist.txt` | Domains that must **never** be blocked, even if they appear in downloaded lists |
| `blocklist.txt` | Domains that must **always** be blocked, even if no source lists them |

One domain per line. Lines starting with `#`, `!`, or `;` are ignored. Inline comments after `#` are supported (`domain.com  # reason`).

| Entry | What it matches |
|---|---|
| `example.com` | The apex host only |
| `*.example.com` | All **proper** subdomains (`www.example.com`, `cdn.ads.example.com`) — **not** `example.com` unless you add that name explicitly |

Wildcard semantics match domain-only sources and the pipeline’s `*.domain` handling (see [Wildcard handling](#wildcard-handling-and-deduplication) below).

**Precedence during merge:**

1. Domains are collected from everything in `raw/`.
2. Any collected domain that matches the allowlist is dropped. Allowlist wins over source entries.
3. Blocklist entries are merged in afterward: exact domains and wildcard bases (`*.foo` → base `foo`) are added if missing and not allowlisted. On overlap, allowlist still wins (a warning is printed if the same apex appears in both files).

**Run metrics** — after merge, check the terminal `Processed:` line or `reports/blocklist-report.json` → `summary`:

| Field | Meaning |
|---|---|
| `scanned` | Total domain entries extracted from all sources (before dedup) |
| `unique_all` | Unique domains after exact deduplication — what `blocklist.txt` and `blocklist-domains.txt` contain |
| `reduction_pct_all` | Reduction percentage for hosts/domains files (exact dedup only) |
| `unique` | Unique domains after subdomain optimization — what DNS resolver formats (RPZ, dnsmasq, unbound, adblock) contain |
| `reduction_pct` | Reduction percentage for DNS formats (exact dedup + subdomain optimization) |
| `wildcards` | Number of wildcard base entries (`*.domain`) in the optimized set |
| `matched_allowlisted` | Unique source domains removed because they matched the allowlist |
| `added_by_blocklist_override` | Domains (or wildcard bases) forced into the output solely from `blocklist.txt` |

`unique_all` ≥ `unique` — the gap is the count of entries that DNS formats omit because a parent domain already covers them. When `--no-optimize-subdomains` is passed, both values are equal.

Example `Processed:` line:
```
Processed: scanned=989104 → deduped=815804 (-16.95%, hosts/domains) → dns-optimized=589557 (-39.98%, adblock/rpz/dnsmasq/unbound) | wildcards=90060 …
```

---

## Wildcard handling and deduplication

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
| **Dedup-only** (`unique_all`) | `hosts`, `domains` | Exact duplicates only — every unique domain is kept |
| **Optimized** (`unique`) | `adblock`, `rpz`, `dnsmasq`, `unbound` | Exact duplicates **+** subdomains whose non-wildcard-derived parent is already in the list |

The subdomain optimizer drops `ads.example.com` when `example.com` is an explicit blocking entry — because DNS resolvers that handle `example.com` also cover all its subdomains. It does **not** remove entries solely because they are under a wildcard base (a wildcard base like `ads.example.com` from `*.ads.example.com` does not count as an explicit parent).

To disable subdomain optimization for DNS formats (both lists become identical), pass `--no-optimize-subdomains`.

**Per-format output:**

| Format | Entry list | Wildcard handling |
|---|---|---|
| `hosts` | Dedup-only — all unique entries | No wildcard syntax; `*.domain` sources contribute only the base exact match (`0.0.0.0 domain`) |
| `domains` | Dedup-only — all unique entries | Same as hosts |
| `adblock` | Optimized | Wildcard entries emit `\|\|*.domain^`; exact entries covered by a wildcard ancestor are dropped |
| `rpz` | Optimized | Wildcard entries emit both `domain IN CNAME .` and `*.domain IN CNAME .` |
| `dnsmasq` | Optimized | `address=/domain/#` natively covers all subdomains; exact entries covered by a wildcard ancestor are dropped |
| `unbound` | Optimized | `local-zone: "domain." always_nxdomain` natively covers all subdomains; covered exact entries are dropped |

The direction is strictly one-way: wildcards degrade to exact for formats that don't support them, but exact entries from hosts sources are never promoted to wildcards.

The `wildcards=N` field in the pipeline summary shows how many wildcard entries were collected. The gap between `unique_all` and `unique` in the JSON report shows how many entries are suppressed in DNS formats due to parent-domain coverage.

Allowlist and blocklist wildcards follow the same `*.domain` rules; see [Allowlist and blocklist](#allowlist-and-blocklist).

---

## How it works

```
sources.conf
    │
    ▼
fetch.py  ───── concurrent downloads (ThreadPoolExecutor)
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

## GitHub Actions automation

The workflow at `.github/workflows/update.yml` runs daily at **03:00 UTC** and on manual trigger (`workflow_dispatch`).

Steps:
1. Checkout repository
2. Set up Python
3. Run `./update.sh` (which calls `update.py`)
4. Commit and push `processed/` back with `[skip ci]`
5. Upload `processed/` as a workflow artifact (only when files changed)

No secrets or tokens required beyond the default `GITHUB_TOKEN` — the workflow uses `permissions: contents: write`.

To trigger the same workflow from your machine (uses your existing `gh auth login` session, no repo secrets):

```bash
./scripts/trigger-update-workflow.sh          # trigger and print the latest run URL
./scripts/trigger-update-workflow.sh --watch  # wait until the run finishes
```

---

## BIND9 RPZ integration

See [`client-scripts/`](client-scripts/) for the full setup guide and script.

### named.conf

#### Step 1 — declare the RPZ zone

Add a `zone` block to `named.conf` (or a file it includes):

```
zone "rpz.local" {
    type master;
    file "db.rpz.local";   // relative to BIND's directory option — see client-scripts/README.md
    allow-query { none; };
};
```

#### Step 2 — enable response-policy

Add `response-policy` inside your existing `options {}` block — **not** alongside the zone block:

```
options {
    // ... your existing options ...
    response-policy { zone "rpz.local"; };
};
```

### Automated daily fetch

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

---

## MikroTik

The hosts-format output (`0.0.0.0 domain`) is directly compatible with MikroTik adlists. See `mikrotik-adlist/` for companion import scripts.

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
sources.conf                     source URL list (one URL per line)
sources.txt                      legacy source URL list (fallback if sources.conf missing)
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

## Requirements

- Python 3.8+ (stdlib only — no pip installs needed)
- `curl` only required for `--legacy` mode
- BIND9 client script additionally requires: `curl`, `gzip`, `named-checkzone`
