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
| `reports/blocklist-report.json` | Per-source stats (scanned, accepted, rejected, delta) |
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

### Options

```bash
./update.sh              # default: Python concurrent downloader (update.py)
./update.sh --unsorted   # preserve first-seen order instead of alphabetical sort
./update.sh --legacy     # use original curl-based downloader (fallback)
./update.sh --legacy --unsorted
```

### Direct Python usage

```bash
python3 update.py [--unsorted] [--workers 8] [--retries 3] [--timeout 30]
                  [--sources sources.conf] [--raw raw] [--out processed/blocklist.txt]
```

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

## Wildcard handling and deduplication

Some sources publish wildcard entries (`*.domain`) meaning "block this domain and all subdomains". The pipeline handles these with format-aware logic:

**Detection** — `DomainReader` recognises `*.domain` lines and flags them as wildcards. `HostsReader` always produces exact entries (`is_wildcard=False`) — a hosts file entry is never promoted to a wildcard.

**Deduplication** — after collection, the subdomain optimizer runs two passes:
1. Drop any exact domain whose parent is already in the exact-match set (e.g. `ads.example.com` is redundant if `example.com` is blocked).
2. Drop any exact domain covered by a wildcard ancestor (e.g. `tracker.ads.example.com` is redundant if `*.ads.example.com` is in the wildcard set).

**Per-format output:**

| Format | Wildcard handling |
|---|---|
| `hosts` | Wildcards degrade to exact match (`0.0.0.0 domain`) — best effort, no wildcard syntax exists |
| `adblock` | Wildcard entries emit `\|\|*.domain^`; covered exact entries are dropped |
| `rpz` | Wildcard entries emit both `domain IN CNAME .` and `*.domain IN CNAME .`; covered exact entries still get both records |
| `dnsmasq` | `address=/domain/#` natively matches all subdomains; covered exact entries are dropped |
| `unbound` | `local-zone: "domain." always_nxdomain` natively matches all subdomains; covered exact entries are dropped |
| `domains` | Same as hosts — exact match only |

The direction is strictly one-way: wildcards degrade to exact for formats that don't support them, but exact entries from hosts sources are never promoted to wildcards. If a domain appears as both an exact entry (from a hosts source) and a wildcard entry (from a wildcard source), wildcard-capable writers drop the redundant exact entry while the hosts writer keeps it — harmless duplication, best effort.

The `wildcards=N` field in the pipeline summary shows how many wildcard entries were collected, giving a sense of how much coverage relies on wildcard semantics vs exact matching.

**Allowlist / blocklist** — `allowlist.txt` and `blocklist.txt` use the same `*.domain` syntax as domain-only sources: `*.example.com` applies to all proper subdomains (`sub.example.com`, `a.b.example.com`), not the apex `example.com` unless that name is listed explicitly.

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
    │           allowlist filtering
    │           deduplication + subdomain optimizer
    │           delta vs previous run
    │
    ├── writers/ (controlled by writers.conf)
    │     hosts.py      → processed/blocklist.txt
    │     adblock.py    → processed/blocklist-adblock.txt
    │     rpz.py        → processed/blocklist-bind9.zone.gz
    │     dnsmasq.py    → processed/blocklist-dnsmasq.conf
    │     unbound.py    → processed/blocklist-unbound.conf
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
  hosts.py                       0.0.0.0 domain (MikroTik, Pi-hole)
  adblock.py                     ||domain^ (uBlock Origin, AdGuard)
  rpz.py                         BIND9 RPZ gzip zone file
  dnsmasq.py                     address=/domain/# (OpenWrt, DD-WRT)
  unbound.py                     local-zone: always_nxdomain
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
