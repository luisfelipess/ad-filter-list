# ad-filter-list

Automated blocklist compiler. Fetches DNS/ad-block lists from multiple sources daily, merges and deduplicates them, and publishes five output formats directly to this repository via GitHub Actions.

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
# clone and run
git clone https://github.com/luisfelipess/ad-filter-list.git
cd ad-filter-list
./update.sh
```

Outputs land in `processed/`. Raw downloaded files go to `raw/` (gitignored).

### Local testing workflow

When tuning `allowlist.txt` or `blocklist.txt`, avoid re-downloading on every edit:

1. **Full run once** — `./update.sh` fetches all sources into `raw/` and writes `processed/` + `reports/`.
2. **Iterate on lists** — edit allowlist/blocklist, then `./update.sh --skip-download` (add `--unsorted` if you need first-seen order preserved).
3. **Prerequisite** — `--skip-download` reuses whatever is already in `raw/` from a prior download. An empty `raw/` means no source data to merge; only blocklist overrides (if any) will appear in the output.

For merge-only experiments (no download at all):

```bash
python3 merge.py --raw raw --map raw/sources.map --out processed/blocklist.txt
```

### Options

| Flag | `update.sh` | `update.py` | Effect |
|---|---|---|---|
| *(default)* | yes | yes | Download sources, then merge |
| `--skip-download` | yes | yes | Skip network fetch; merge existing files in `raw/` |
| `--unsorted` | yes | yes | Preserve first-seen domain order instead of sorting |
| `--no-optimize-subdomains` | yes | yes | Disable subdomain optimization for DNS formats — every unique domain is written to all output files (useful when you want a flat list with no implicit parent-domain coverage) |
| `--legacy` | yes | — | Use curl-based downloader instead of `update.py` (no `--skip-download`) |
| `--workers N` | — | yes | Parallel download threads (default 8) |
| `--retries N` | — | yes | Per-URL retry count (default 3) |
| `--timeout N` | — | yes | Per-request timeout in seconds (default 30) |

```bash
./update.sh                              # download + merge
./update.sh --skip-download              # merge only (fast iteration)
./update.sh --skip-download --unsorted
./update.sh --legacy                     # curl downloader (fallback)
./update.sh --legacy --unsorted
```

### Direct Python usage

```bash
python3 update.py [--unsorted] [--skip-download] [--workers 8] [--retries 3] [--timeout 30]
                  [--sources sources.conf] [--raw raw] [--out processed/blocklist.txt]
                  [--blocklist blocklist.txt]
```

With `--skip-download`, `update.py` does not clear `raw/`; it runs `merge.py` against the files already there. If `raw/sources.map` is missing, merge still scans `raw/` for downloaded files.

`merge.py` can also be run standalone if raw files are already downloaded:

```bash
python3 merge.py [--raw raw] [--map raw/sources.map] [--out processed/blocklist.txt]
                 [--unsorted] [--allowlist allowlist.txt] [--blocklist blocklist.txt]
                 [--no-optimize-subdomains] [--writers-config writers.conf]
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
sources.txt
    │
    ▼
update.py  ──── concurrent downloads (ThreadPoolExecutor)
    │            retry with exponential backoff
    │            transparent gzip/zip decompression
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
./trigger-update-workflow.sh          # trigger and print the latest run URL
./trigger-update-workflow.sh --watch  # wait until the run finishes
```

---

## BIND9 RPZ integration

See [`client-scripts/`](client-scripts/) for a ready-to-use integration script.

### named.conf

```
zone "rpz.local" {
    type master;
    file "/etc/bind/db.rpz.local";
    allow-query { none; };
};

options {
    response-policy { zone "rpz.local"; };
};
```

### Automated daily fetch

```bash
# copy to your BIND9 server
scp client-scripts/bind9-update-rpz.sh root@your-server:/etc/bind/
chmod +x /etc/bind/bind9-update-rpz.sh

# bootstrap
/etc/bind/bind9-update-rpz.sh

# cron — runs at 04:00, after the GitHub Actions job at 03:00 UTC
echo "0 4 * * * /etc/bind/bind9-update-rpz.sh >> /var/log/rpz-update.log 2>&1" | crontab -
```

The script fetches `blocklist-bind9.zone.gz`, validates it with `named-checkzone`, installs it, and runs `rndc reload rpz.local`.

---

## MikroTik

The hosts-format output (`0.0.0.0 domain`) is directly compatible with MikroTik adlists. See `mikrotik-adlist/` for companion import scripts.

---

## Repository layout

```
update.sh                        entry point (delegates to update.py by default)
update.py                        concurrent Python downloader
merge.py                         parser, deduplicator, writer orchestrator
readers/                         pluggable source format readers
  __init__.py                    BaseReader, normalize_domain, read_leading_header
  hosts.py                       0.0.0.0/127.0.0.1 domain format
  domain.py                      bare domain-only lists
  adblock.py                     ||domain^ sources
writers/                         pluggable output format writers
  __init__.py                    BaseWriter, WriterMeta, shared helpers
  hosts.py                       0.0.0.0 domain (MikroTik, Pi-hole)  [dedup-only]
  domains.py                     plain domain-per-line               [dedup-only]
  adblock.py                     ||domain^ (uBlock Origin, AdGuard)  [optimized]
  rpz.py                         BIND9 RPZ gzip zone file            [optimized]
  dnsmasq.py                     address=/domain/# (OpenWrt, DD-WRT) [optimized]
  unbound.py                     local-zone: always_nxdomain         [optimized]
sources.conf                     preferred source URL list
sources.txt                      legacy source URL list (fallback for compatibility)
allowlist.txt                    domains that are never blocked (`example.com` exact, `*.example.com` all subdomains)
blocklist.txt                    domains always blocked, even if absent from sources (same `*.domain` syntax)
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
- BIND9 client script additionally requires: `named-checkzone`, `rndc`
