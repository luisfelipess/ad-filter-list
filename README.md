# ad-filter-list

Automated blocklist compiler. Fetches DNS/ad-block lists from multiple sources daily, merges and deduplicates them, and publishes three output formats directly to this repository via GitHub Actions.

## Output formats

| File | Format | Use case |
|---|---|---|
| `processed/blocklist.txt` | `0.0.0.0 domain` hosts format | MikroTik adlists, Pi-hole, generic hosts |
| `processed/blocklist-bind9.zone.gz` | BIND9 RPZ zone file (gzip) | BIND9 `response-policy` |
| `processed/blocklist-adblock.txt` | `\|\|domain^` adblock syntax | uBlock Origin, AdGuard, browser extensions |
| `processed/blocklist-report.json` | Per-source JSON stats | Auditing, CI checks |
| `processed/rejected-entries.txt` | Unparseable lines | Debugging source quality |

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
                  [--sources sources.txt] [--raw raw] [--out processed/blocklist.txt]
```

`merge.py` can also be run standalone if raw files are already downloaded:

```bash
python3 merge.py [--raw raw] [--map raw/sources.map] [--out processed/blocklist.txt] [--unsorted]
```

---

## Adding or removing sources

Edit `sources.txt` — one URL per line. Lines starting with `#`, `;`, or `!` are ignored. Inline comments are supported:

```
https://example.com/hosts.txt        # optional comment
# https://disabled-source.com/list   # commented out
```

Supported source formats are auto-detected: hosts-style (`0.0.0.0 domain` / `127.0.0.1 domain`), domain-only, and mixed. Gzip (`.gz`) and zip (`.zip`) sources are decompressed automatically.

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
merge.py  ──── format detection per source
    │           domain extraction & normalisation
    │           deduplication
    │           delta vs previous run
    │
    ▼
processed/
  blocklist.txt
  blocklist-bind9.zone.gz
  blocklist-adblock.txt
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
merge.py                         parser, deduplicator, multi-format writer
sources.txt                      list of source URLs
client-scripts/
  bind9-update-rpz.sh            BIND9 RPZ fetch-and-reload script
  README.md                      BIND9 setup guide
processed/                       compiled output (committed by CI)
raw/                             downloaded source files (gitignored)
.github/workflows/update.yml     daily automation workflow
```

---

## Requirements

- Python 3.8+ (stdlib only — no pip installs needed)
- `curl` only required for `--legacy` mode
- BIND9 client script additionally requires: `named-checkzone`, `rndc`
