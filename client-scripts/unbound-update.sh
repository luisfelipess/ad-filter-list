#!/usr/bin/env bash
# unbound-update.sh — fetch the latest Unbound blocklist and reload Unbound
#
# Usage: unbound-update.sh [CONF_FILE]
#
#   CONF_FILE  full path where the decompressed conf should be installed.
#              Defaults to /etc/unbound/conf.d/blocklist-unbound.conf.
#              Pass explicitly if your include path differs.
#
# Examples:
#   unbound-update.sh                                          # default path
#   unbound-update.sh /etc/unbound/local.d/blocklist.conf     # explicit path
#
# Override detection via env vars if needed:
#   UNBOUND_SERVICE=unbound unbound-update.sh
#
# Requirements: curl, gzip
#
# Cron example (04:00 UTC, after the GitHub Actions job at 03:00 UTC):
#   0 4 * * * /usr/local/sbin/unbound-update.sh >> /var/log/unbound-update.log 2>&1

set -euo pipefail

BLOCKLIST_URL="https://raw.githubusercontent.com/luisfelipess/ad-filter-list/main/processed/blocklist-unbound.conf.gz"
DEFAULT_CONF_FILE="/etc/unbound/conf.d/blocklist-unbound.conf"
TMP_FILE="$(mktemp /tmp/unbound-blocklist.XXXXXX.conf)"

cleanup() { rm -f "$TMP_FILE"; }
trap cleanup EXIT

log() { echo "[$(date -u +%FT%TZ)] $*"; }
die() { echo "ERROR: $*" >&2; exit 1; }

# Detect Unbound service name
detect_service() {
    for svc in unbound unbound-daemon; do
        if systemctl cat "$svc.service" &>/dev/null; then
            echo "$svc"
            return
        fi
    done
    die "Cannot detect Unbound service name. Set UNBOUND_SERVICE env var."
}

# --- Resolve conf file path ---
CONF_FILE="${1:-$DEFAULT_CONF_FILE}"
UNBOUND_SERVICE="${UNBOUND_SERVICE:-$(detect_service)}"

log "Target: ${CONF_FILE}  service=${UNBOUND_SERVICE}"

# Ensure target directory exists
CONF_DIR="$(dirname "$CONF_FILE")"
if [[ ! -d "$CONF_DIR" ]]; then
    log "Creating directory ${CONF_DIR}..."
    mkdir -p "$CONF_DIR"
fi

log "Fetching blocklist..."
curl -fsSL "$BLOCKLIST_URL" | gzip -dc > "$TMP_FILE"

# Basic sanity check
entry_count=$(grep -c '^local-zone:' "$TMP_FILE" || true)
if [[ "$entry_count" -eq 0 ]]; then
    die "Downloaded file contains no local-zone entries — aborting."
fi
log "Validated: ${entry_count} local-zone entries"

# Skip install if nothing changed
if [[ -f "$CONF_FILE" ]] && cmp -s "$TMP_FILE" "$CONF_FILE"; then
    log "Already up to date — nothing to do."
    exit 0
fi

log "Installing ${CONF_FILE}..."
cp "$TMP_FILE" "$CONF_FILE"
chmod 644 "$CONF_FILE"

log "Reloading Unbound..."
if command -v unbound-control &>/dev/null; then
    unbound-control reload
else
    systemctl reload "$UNBOUND_SERVICE"
fi

log "Done. ${entry_count} domains active."
