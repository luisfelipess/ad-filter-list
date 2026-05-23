#!/usr/bin/env bash
# bind9-update-rpz.sh — fetch the latest RPZ blocklist and reload BIND9
#
# Usage: run manually or via cron, e.g.:
#   0 4 * * * /etc/bind/client-scripts/bind9-update-rpz.sh
#
# Requirements: curl, gzip, named-checkzone, rndc

set -euo pipefail

RPZ_URL="https://raw.githubusercontent.com/luisfelipess/ad-filter-list/main/processed/blocklist-bind9.zone.gz"
ZONE_FILE="/etc/bind/db.rpz.local"
ZONE_NAME="rpz.local"
TMP_FILE="$(mktemp /tmp/rpz.XXXXXX.zone)"

cleanup() { rm -f "$TMP_FILE"; }
trap cleanup EXIT

echo "[$(date -u +%FT%TZ)] Fetching RPZ zone..."
curl -fsSL "$RPZ_URL" | gzip -dc > "$TMP_FILE"

echo "[$(date -u +%FT%TZ)] Validating zone..."
named-checkzone "$ZONE_NAME" "$TMP_FILE"

echo "[$(date -u +%FT%TZ)] Installing zone file..."
cp "$TMP_FILE" "$ZONE_FILE"
chown root:bind "$ZONE_FILE"
chmod 640 "$ZONE_FILE"

echo "[$(date -u +%FT%TZ)] Reloading BIND9..."
rndc reload "$ZONE_NAME"

echo "[$(date -u +%FT%TZ)] Done."
