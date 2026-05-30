# client-scripts

Helper scripts for consuming the compiled blocklists on client machines.

| Script | Target | Format |
|---|---|---|
| `bind9-update-rpz.sh` | BIND9 with response-policy | RPZ zone (gzip) |
| `unbound-update.sh` | Unbound resolver | `local-zone` conf (gzip) |

---

## bind9-update-rpz.sh

Fetches the latest `blocklist-bind9.zone.gz`, validates it with `named-checkzone`,
and installs it to the zone file path configured in your `named.conf`. Then reloads
BIND9 via `systemctl`.

### Prerequisites

- `curl`, `gzip`, `named-checkzone`
- BIND9 configured with the RPZ zone and `response-policy` stanza (see below)

### named.conf

#### Step 1 — declare the RPZ zone

Add a `zone` block to `named.conf` (or a file it includes):

```
zone "rpz.local" {
    type master;
    file "db.rpz.local";   // relative to BIND's directory option, or use an absolute path
    allow-query { none; };
};
```

The zone file path varies by distro:

| Distro family            | BIND `directory` option  | Typical zone file path           |
|--------------------------|--------------------------|----------------------------------|
| Debian / Ubuntu          | `/var/cache/bind`        | `/var/cache/bind/db.rpz.local`   |
| RHEL / Rocky / AlmaLinux | `/var/named`             | `/var/named/db.rpz.local`        |
| openSUSE / SLES          | `/var/lib/named`         | `/var/lib/named/db.rpz.local`    |

Use the relative filename in the `file` directive and let BIND resolve it against
its `directory` option — or use an absolute path if you prefer.

#### Step 2 — enable response-policy

Add `response-policy` inside the `options {}` block that already exists in your
config — **not** alongside the `zone` block:

```
options {
    // ... your existing options ...
    response-policy { zone "rpz.local"; };
};
```

### Setup

**On your BIND9 server**, download the script directly:

```bash
curl -fsSL https://raw.githubusercontent.com/luisfelipess/ad-filter-list/main/client-scripts/bind9-update-rpz.sh \
    -o /usr/local/sbin/bind9-update-rpz.sh
chmod +x /usr/local/sbin/bind9-update-rpz.sh
```

**Run once to bootstrap.** The script reads your `named.conf` to discover the
zone file path automatically:

```bash
/usr/local/sbin/bind9-update-rpz.sh
```

If auto-detection fails (e.g. your zone is defined in a nested include file),
pass the path explicitly:

```bash
/usr/local/sbin/bind9-update-rpz.sh /var/named/db.rpz.local
```

The script also auto-detects the BIND service name (`named` or `bind9`) and the
bind group (`bind` or `named`). Override via env vars if needed:

```bash
BIND_SERVICE=named BIND_GROUP=named /usr/local/sbin/bind9-update-rpz.sh
```

**Add to root crontab** for daily updates (runs at 04:00 UTC, after the GitHub
Actions job at 03:00 UTC):

```bash
crontab -e

# add this line:
0 4 * * * /usr/local/sbin/bind9-update-rpz.sh >> /var/log/rpz-update.log 2>&1
```

---

## unbound-update.sh

Fetches the latest `blocklist-unbound.conf.gz`, decompresses it, installs it
to Unbound's include directory, and reloads Unbound.

### Prerequisites

- `curl`, `gzip`
- Unbound configured to include conf files from its include directory (see below)

### unbound.conf

Add an `include` directive to your `/etc/unbound/unbound.conf` (inside the
`server:` block):

```
server:
    # ... your existing options ...
    include: "/etc/unbound/conf.d/*.conf"
```

Create the directory if it does not exist:

```bash
mkdir -p /etc/unbound/conf.d
```

### Setup

**On your Unbound server**, download the script:

```bash
curl -fsSL https://raw.githubusercontent.com/luisfelipess/ad-filter-list/main/client-scripts/unbound-update.sh \
    -o /usr/local/sbin/unbound-update.sh
chmod +x /usr/local/sbin/unbound-update.sh
```

**Run once to bootstrap:**

```bash
/usr/local/sbin/unbound-update.sh
```

The script installs to `/etc/unbound/conf.d/blocklist-unbound.conf` by default.
Pass an explicit path if your setup differs:

```bash
/usr/local/sbin/unbound-update.sh /etc/unbound/local.d/blocklist.conf
```

Unbound is reloaded via `unbound-control reload` if available, otherwise via
`systemctl reload unbound`.

**Add to root crontab** for daily updates (04:00 UTC, after GitHub Actions at 03:00 UTC):

```bash
crontab -e

# add this line:
0 4 * * * /usr/local/sbin/unbound-update.sh >> /var/log/unbound-update.log 2>&1
```
