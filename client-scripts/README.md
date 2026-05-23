# client-scripts

Helper scripts for consuming the compiled blocklists on client machines.

## bind9-update-rpz.sh

Fetches the latest `blocklist-bind9.zone.gz` from this repo, validates it with
`named-checkzone`, installs it, and reloads BIND9.

### Prerequisites

- `curl`, `gzip`, `named-checkzone`, `rndc`
- BIND9 configured with the RPZ zone and `response-policy` stanza (see below)

### named.conf snippet

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

### Setup

```bash
# copy script to your server
scp client-scripts/bind9-update-rpz.sh root@your-server:/etc/bind/

chmod +x /etc/bind/bind9-update-rpz.sh

# run once to bootstrap
/etc/bind/bind9-update-rpz.sh

# add to root crontab for daily updates (runs at 04:00 local time,
# after the GitHub Actions job at 03:00 UTC)
echo "0 4 * * * /etc/bind/bind9-update-rpz.sh >> /var/log/rpz-update.log 2>&1" | crontab -
```
