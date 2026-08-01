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

**Multiple tiers, one pipeline.**
Sources are tagged `light`, `good`, or `aggressive` in `sources.conf`. The pipeline produces a separate output set per tier — all six formats, in `processed/` (good, default) and `processed/aggressive/`. Tiers are cumulative: a `light` source appears in every tier; a `good` source appears in good and aggressive; `aggressive`-only sources are isolated. The hierarchy is defined in `tiers.conf` and is fully configurable.

---

<!-- stats:start -->
**Last run:** 2026-08-01 &nbsp;·&nbsp; **Sources:** 30 &nbsp;·&nbsp; **Unique domains:** 930,119 *(hosts/domains)* · 723,457 *(DNS-optimized)* &nbsp;·&nbsp; **Wildcards:** 442,772

### Light tier

| Format | Download | Domains | Size | Est. RAM | Use case |
|---|---|---|---|---|---|
| Hosts (`0.0.0.0 domain`) | [blocklist.txt](https://raw.githubusercontent.com/luisfelipess/ad-filter-list/main/processed/light/blocklist.txt) | 0 | 281 B | — | MikroTik adlists (RouterOS 7.15+), Pi-hole, AdAway, uMatrix, OpenSnitch, DNS66, NetGuard |
| Plain domains | [blocklist-domains.txt](https://raw.githubusercontent.com/luisfelipess/ad-filter-list/main/processed/light/blocklist-domains.txt) | 0 | 296 B | — | Blocky (older than v0.23), Diversion (older than v5), PersonalBlocklist, pfBlockerNG |
| Adblock syntax | [blocklist-adblock.txt](https://raw.githubusercontent.com/luisfelipess/ad-filter-list/main/processed/light/blocklist-adblock.txt) | 0 | 325 B | — | Pi-hole, AdGuard, AdGuard Home, eBlocker, uBlock Origin, Brave (aggressive mode only), AdNauseam, Little Snitch Mini |
| BIND9 RPZ (gzip) | [blocklist-bind9.zone.gz](https://raw.githubusercontent.com/luisfelipess/ad-filter-list/main/processed/light/blocklist-bind9.zone.gz) | 0 | 404 B | — | BIND9, Knot, PowerDNS — any RFC 5782 response-policy zone implementation |
| dnsmasq | [blocklist-dnsmasq.conf](https://raw.githubusercontent.com/luisfelipess/ad-filter-list/main/processed/light/blocklist-dnsmasq.conf) | 0 | 325 B | — | dnsmasq (v2.86 or newer), Diversion (v5 or newer), OpenWrt, DD-WRT |
| Unbound (gzip) | [blocklist-unbound.conf.gz](https://raw.githubusercontent.com/luisfelipess/ad-filter-list/main/processed/light/blocklist-unbound.conf.gz) | 0 | 300 B | — | Unbound resolver (native `local-zone` directives) |

### Good tier *(default)*

| Format | Download | Domains | Size | Est. RAM | Use case |
|---|---|---|---|---|---|
| Hosts (`0.0.0.0 domain`) | [blocklist.txt](https://raw.githubusercontent.com/luisfelipess/ad-filter-list/main/processed/blocklist.txt) | 930,119 | 30.5 MB | ~47 MB | MikroTik adlists (RouterOS 7.15+), Pi-hole, AdAway, uMatrix, OpenSnitch, DNS66, NetGuard |
| Plain domains | [blocklist-domains.txt](https://raw.githubusercontent.com/luisfelipess/ad-filter-list/main/processed/blocklist-domains.txt) | 930,119 | 23.0 MB | ~47 MB | Blocky (older than v0.23), Diversion (older than v5), PersonalBlocklist, pfBlockerNG |
| Adblock syntax | [blocklist-adblock.txt](https://raw.githubusercontent.com/luisfelipess/ad-filter-list/main/processed/blocklist-adblock.txt) | 723,457 | 22.5 MB | ~36 MB | Pi-hole, AdGuard, AdGuard Home, eBlocker, uBlock Origin, Brave (aggressive mode only), AdNauseam, Little Snitch Mini |
| BIND9 RPZ (gzip) | [blocklist-bind9.zone.gz](https://raw.githubusercontent.com/luisfelipess/ad-filter-list/main/processed/blocklist-bind9.zone.gz) | 723,457 | 9.7 MB | ~36 MB | BIND9, Knot, PowerDNS — any RFC 5782 response-policy zone implementation |
| dnsmasq | [blocklist-dnsmasq.conf](https://raw.githubusercontent.com/luisfelipess/ad-filter-list/main/processed/blocklist-dnsmasq.conf) | 723,457 | 29.6 MB | ~36 MB | dnsmasq (v2.86 or newer), Diversion (v5 or newer), OpenWrt, DD-WRT |
| Unbound (gzip) | [blocklist-unbound.conf.gz](https://raw.githubusercontent.com/luisfelipess/ad-filter-list/main/processed/blocklist-unbound.conf.gz) | 723,457 | 7.2 MB | ~36 MB | Unbound resolver (native `local-zone` directives) |

### Aggressive tier

| Format | Download | Domains | Size | Est. RAM | Use case |
|---|---|---|---|---|---|
| Hosts (`0.0.0.0 domain`) | [blocklist.txt](https://raw.githubusercontent.com/luisfelipess/ad-filter-list/main/processed/aggressive/blocklist.txt) | 1,504,317 | 48.8 MB | ~75 MB | MikroTik adlists (RouterOS 7.15+), Pi-hole, AdAway, uMatrix, OpenSnitch, DNS66, NetGuard |
| Plain domains | [blocklist-domains.txt](https://raw.githubusercontent.com/luisfelipess/ad-filter-list/main/processed/aggressive/blocklist-domains.txt) | 1,504,317 | 36.7 MB | ~75 MB | Blocky (older than v0.23), Diversion (older than v5), PersonalBlocklist, pfBlockerNG |
| Adblock syntax | [blocklist-adblock.txt](https://raw.githubusercontent.com/luisfelipess/ad-filter-list/main/processed/aggressive/blocklist-adblock.txt) | 1,239,122 | 34.5 MB | ~62 MB | Pi-hole, AdGuard, AdGuard Home, eBlocker, uBlock Origin, Brave (aggressive mode only), AdNauseam, Little Snitch Mini |
| BIND9 RPZ (gzip) | [blocklist-bind9.zone.gz](https://raw.githubusercontent.com/luisfelipess/ad-filter-list/main/processed/aggressive/blocklist-bind9.zone.gz) | 1,239,122 | 14.7 MB | ~62 MB | BIND9, Knot, PowerDNS — any RFC 5782 response-policy zone implementation |
| dnsmasq | [blocklist-dnsmasq.conf](https://raw.githubusercontent.com/luisfelipess/ad-filter-list/main/processed/aggressive/blocklist-dnsmasq.conf) | 1,239,122 | 45.5 MB | ~62 MB | dnsmasq (v2.86 or newer), Diversion (v5 or newer), OpenWrt, DD-WRT |
| Unbound (gzip) | [blocklist-unbound.conf.gz](https://raw.githubusercontent.com/luisfelipess/ad-filter-list/main/processed/aggressive/blocklist-unbound.conf.gz) | 1,239,122 | 10.9 MB | ~62 MB | Unbound resolver (native `local-zone` directives) |
<!-- stats:end -->

Run diagnostics are committed alongside the output on every run:

| File | Contents |
|---|---|
| [`reports/blocklist-report.json`](reports/blocklist-report.json) | Per-source stats (`scanned`, `accepted`, `net_new`, `content_sha1`, `version`, `last_modified`, `last_changed`, `health`) plus run summary (`matched_allowlisted`, `added_by_blocklist_override`, deltas, wildcards) |
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
| `--incremental` | Skip re-downloading sources unchanged since last run (ETag / If-Modified-Since) |
| `--tiers-config FILE` | Tier hierarchy config file (default: `tiers.conf`) |
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
                 [--incremental]
python3 merge.py [--raw raw] [--map raw/sources.map] [--out processed/blocklist.txt]
                 [--unsorted] [--allowlist allowlist.txt] [--blocklist blocklist.txt]
                 [--no-optimize-subdomains] [--no-iana-tld-check] [--max-drop-pct 50]
                 [--writers-config writers.conf] [--tiers-config tiers.conf]
python3 post_run.py [--report reports/blocklist-report.json] [--readme README.md]
```

---

## Requirements

- Python 3.8+ (stdlib only — no pip installs needed)
- BIND9 client script additionally requires: `curl`, `gzip`, `named-checkzone`
- Unbound client script additionally requires: `curl`, `gzip`

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

To assign a source to a tier, add a `tier=` tag:

```
https://example.com/aggressive-list.txt tier=aggressive
https://example.com/safe-list.txt tier=light , https://fallback.example.com/safe-list.txt
```

Sources without a `tier=` tag default to the tier marked `*` in `tiers.conf` (currently `good`). Tier semantics are cumulative: a `light` source appears in every tier's output; a `good` source in `good` and `aggressive`; an `aggressive` source only in `aggressive`. The tier hierarchy is defined in `tiers.conf` — see the repository layout below.

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

**Per-source fields** — `reports/blocklist-report.json` → `sources[filename]`:

| Field | Meaning |
|---|---|
| `scanned` | Lines processed from this source (before extraction and normalisation) |
| `accepted` | Domains successfully extracted and normalised |
| `rejected` | Lines that could not be parsed or failed validation |
| `net_new` | Domains this source contributed that no earlier source had already seen |
| `tier_exclusive` | Domains from this source not covered by any lighter tier |
| `format` | Detected format (`host`, `adblock`, `domain-only`, `wildcard-domain`, `mixed-domain`) |
| `tier` | Tier this source belongs to (`light`, `good`, `aggressive`) |
| `health` | Source health: `ok`, `failed`, `empty`, `redundant`, `high_rejection`, `low_value` |
| `content_sha1` | SHA1 of the raw downloaded file — use this to detect whether the source changed between runs |
| `version` | Value of the `! Version:` / `# Version:` header from the source file, or `null` if absent |
| `last_modified` | Value of the `! Last modified:` header from the source file, or `null` if absent |
| `last_changed` | ISO timestamp of the last run in which the file's SHA1 changed — unchanged across runs when the source content is identical; use this to detect stale sources that stopped updating |

`unique_deduped` ≥ `unique_optimized` — the gap is the count of entries that DNS formats omit because a parent domain already covers them. When `--no-optimize-subdomains` is passed, both values are equal.

Example `Processed:` line:
```
Processed: scanned=989104 → deduped=815804 (-16.95%, hosts/domains) → dns-optimized=589557 (-39.98%, adblock/rpz/dnsmasq/unbound) | wildcards=90060 …
```

---

## How it works

```
sources.conf  ←  tier tags (tier=light / tier=good / tier=aggressive)
tiers.conf    ←  tier hierarchy and default tier
    │
    ▼
fetch.py  ───── concurrent downloads (ThreadPoolExecutor)
    │             primary + fallback URL per source
    │             retry with exponential backoff
    │             transparent gzip/zip decompression
    │             incremental mode (ETag / If-Modified-Since)
    │
    ▼
raw/  (gitignored)
    │
    ▼
merge.py  ──── format detection per source  (readers/)
    │           domain extraction & normalisation
    │           allowlist filter + blocklist override
    │           exact deduplication + domain_min_rank tracking
    │           │
    │           ├── dedup-only list  (hosts / domains — all unique entries)
    │           └── optimized list   (subdomain optimizer applied)
    │                                 (skipped with --no-optimize-subdomains)
    │           delta vs previous run
    │
    ├── writers/ (controlled by writers.conf) — run once per tier
    │     hosts.py      → processed/blocklist.txt               (good tier, dedup-only)
    │     domains.py    → processed/blocklist-domains.txt       (good tier, dedup-only)
    │     adblock.py    → processed/blocklist-adblock.txt       (good tier, optimized)
    │     rpz.py        → processed/blocklist-bind9.zone.gz     (good tier, optimized)
    │     dnsmasq.py    → processed/blocklist-dnsmasq.conf      (good tier, optimized)
    │     unbound.py    → processed/blocklist-unbound.conf.gz   (good tier, optimized)
    │     (same writers) → processed/aggressive/blocklist.txt … (aggressive tier)
    │     (same writers) → processed/light/blocklist.txt …      (light tier)
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

RouterOS 7.15+ natively supports DNS adlists in hosts format (`0.0.0.0 domain`). The hosts-format output from this project loads directly — no conversion needed.

#### Requirements

- **RouterOS 7.15 or later** — adlist support with hosts-format parsing
- Enough free RAM for the DNS cache (see cache-size guidance below)

#### Add the adlist

In an SSH or Winbox terminal — use the tier that fits your router's RAM:

```
# Good tier (default) — ~953K domains, ~30 MB hosts file
/ip/dns/adlist/add url="https://raw.githubusercontent.com/luisfelipess/ad-filter-list/main/processed/blocklist.txt" name="ad-filter-list"

# Aggressive tier — includes DoH/VPN bypass blocklists in addition to the good tier
/ip/dns/adlist/add url="https://raw.githubusercontent.com/luisfelipess/ad-filter-list/main/processed/aggressive/blocklist.txt" name="ad-filter-list-aggressive"
```

Verify it loaded:

```
/ip/dns/adlist/print
```

RouterOS fetches the list on boot and periodically refreshes it based on the HTTP cache headers from GitHub's CDN.

#### Set DNS cache size

RouterOS defaults to a 2 MiB DNS cache, which is far too small for a list of this size. Set `cache-size` based on the number of domains you intend to load:

| Approximate domains | Recommended cache-size | Command |
|---|---|---|
| ~400 K | 20 MiB | `/ip/dns/set cache-size=20480KiB` |
| ~900 K *(current list)* | 40 MiB | `/ip/dns/set cache-size=40960KiB` |
| ~1.4 M | 200 MiB | `/ip/dns/set cache-size=204800KiB` |

RouterOS stores adlist entries in the DNS cache, so the cache must be large enough to hold all entries plus headroom for normal query caching. If the list silently fails to load, an undersized cache is the most common cause — check `/ip/dns/adlist/print` for an error status.

#### IPv6 bypass warning

Clients with IPv6 connectivity can resolve DNS directly through their ISP's resolvers, bypassing the router entirely — the adlist has no effect on those queries.

To close the bypass:

1. **Block outbound port-53 on IPv6** — drop forwarded UDP/TCP port 53 from your LAN prefix to the WAN:
   ```
   /ipv6/firewall/filter/add chain=forward protocol=udp dst-port=53 \
       src-address=<LAN-prefix> out-interface=<WAN-interface> action=drop comment="block IPv6 DNS bypass"
   /ipv6/firewall/filter/add chain=forward protocol=tcp dst-port=53 \
       src-address=<LAN-prefix> out-interface=<WAN-interface> action=drop comment="block IPv6 DNS bypass"
   ```
   Alternatively use `dst-nat` to redirect all outbound port-53 back to the router's DNS.

2. **Block encrypted DNS (DoH/DoT)** — encrypted DNS on port 853 cannot be transparently redirected; block outbound port 853 and consider an IP blocklist for well-known DoH resolver addresses (8.8.8.8, 1.1.1.1, etc.) to prevent clients from bypassing the router's resolver entirely.

> **Note:** IPv6 DNS enforcement is more involved than IPv4 because all addresses are globally routable and clients can contact any resolver directly. A complete lockdown requires both port-53 blocking and DoH/DoT mitigation.

### Unbound

The Unbound output is a gzip-compressed file of `local-zone: "domain." always_nxdomain` directives. Unbound's `local-zone` natively blocks all subdomains, so the file uses the subdomain-optimized list.

#### unbound.conf

Add an `include` directive inside your `server:` block:

```
server:
    # ... your existing options ...
    include: "/etc/unbound/conf.d/*.conf"
```

Create the directory if needed:

```bash
mkdir -p /etc/unbound/conf.d
```

#### Automated daily fetch

Download the script:

```bash
curl -fsSL https://raw.githubusercontent.com/luisfelipess/ad-filter-list/main/client-scripts/unbound-update.sh \
    -o /usr/local/sbin/unbound-update.sh
chmod +x /usr/local/sbin/unbound-update.sh
```

Bootstrap and schedule:

```bash
# run once to bootstrap
/usr/local/sbin/unbound-update.sh

# cron — runs at 04:00 UTC, after the GitHub Actions job at 03:00 UTC
echo "0 4 * * * /usr/local/sbin/unbound-update.sh >> /var/log/unbound-update.log 2>&1" | crontab -
```

The script decompresses the `.conf.gz`, validates the entry count, installs to `/etc/unbound/conf.d/blocklist-unbound.conf`, and reloads Unbound via `unbound-control reload` (or `systemctl reload unbound` as fallback). Pass an explicit path as the first argument if your include directory differs.

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
sources.conf                     source URL list (one URL per line; primary , fallback; tier= tag supported)
tiers.conf                       tier hierarchy (light / good * / aggressive); * marks the default
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
