#!/usr/bin/env bash
# bind9-update-rpz.sh — fetch the latest RPZ blocklist and reload BIND9
#
# Usage: bind9-update-rpz.sh [ZONE_FILE]
#
#   ZONE_FILE  full path where the zone file should be installed.
#              If omitted, the script reads named.conf to discover it
#              from the zone "rpz.local" block and the directory option.
#              Pass explicitly if your zone is defined in an include file
#              or if auto-detection fails.
#
# Examples:
#   bind9-update-rpz.sh                              # auto-detect from named.conf
#   bind9-update-rpz.sh /var/named/db.rpz.local      # pass explicitly
#
# Override detection via env vars if needed:
#   BIND_SERVICE=named BIND_GROUP=named bind9-update-rpz.sh
#
# Requirements: curl, gzip, named-checkzone
#
# Cron example (04:00 UTC, after the GitHub Actions job at 03:00 UTC):
#   0 4 * * * /usr/local/sbin/bind9-update-rpz.sh >> /var/log/rpz-update.log 2>&1

set -euo pipefail

RPZ_URL="https://raw.githubusercontent.com/luisfelipess/ad-filter-list/main/processed/blocklist-bind9.zone.gz"
ZONE_NAME="rpz.local"
TMP_FILE="$(mktemp /tmp/rpz.XXXXXX.zone)"

cleanup() { rm -f "$TMP_FILE"; }
trap cleanup EXIT

log() { echo "[$(date -u +%FT%TZ)] $*"; }
die() { echo "ERROR: $*" >&2; exit 1; }

# Parse named.conf (and one level of includes) to find the zone file path
# for ZONE_NAME. Resolves relative paths against BIND's 'directory' option.
detect_zone_file() {
    local conf=""
    for f in /etc/named.conf /etc/bind/named.conf /usr/local/etc/named.conf; do
        [[ -f "$f" ]] && { conf="$f"; break; }
    done
    [[ -z "$conf" ]] && return 1

    # Build combined content: main conf + first-level includes
    local content
    content="$(cat "$conf")"
    while IFS= read -r inc; do
        [[ -f "$inc" ]] && content+=$'\n'"$(cat "$inc")"
    done < <(sed -n 's/.*include[[:space:]]*"\([^"]*\)".*/\1/p' "$conf")

    # Strip // and # comments, drop blank lines
    content=$(printf '%s\n' "$content" \
        | sed 's|[[:space:]]//.*||; s|[[:space:]]#.*||' \
        | grep -v '^[[:space:]]*[/#]' \
        | grep -v '^[[:space:]]*$')

    # Extract BIND's working directory from options {}
    local dir
    dir=$(printf '%s\n' "$content" | awk '
        /options[[:space:]]*\{/ { in_opts=1 }
        in_opts && /directory/ {
            line=$0; sub(/.*directory[[:space:]]*"/, "", line); sub(/".*/, "", line)
            print line; in_opts=0
        }
        in_opts && /\}/ { in_opts=0 }
    ')

    # Extract file path from zone "rpz.local" {}
    local file
    file=$(printf '%s\n' "$content" | awk -v zone="$ZONE_NAME" '
        $0 ~ ("zone[[:space:]]*\"" zone "\"") { in_zone=1 }
        in_zone && /[[:space:]]file[[:space:]]/ {
            line=$0; sub(/.*file[[:space:]]*"/, "", line); sub(/".*/, "", line)
            print line; in_zone=0
        }
        in_zone && /\}/ { in_zone=0 }
    ')

    [[ -z "$file" ]] && return 1

    # Resolve relative path against BIND's working directory
    if [[ "$file" != /* && -n "$dir" ]]; then
        echo "${dir%/}/$file"
    else
        echo "$file"
    fi
}

# Detect BIND service name (named on RHEL-family, bind9 on Debian/Ubuntu)
detect_service() {
    for svc in named bind9; do
        if systemctl cat "$svc.service" &>/dev/null; then
            echo "$svc"
            return
        fi
    done
    die "Cannot detect BIND9 service name (tried 'named' and 'bind9'). Set BIND_SERVICE env var."
}

# Detect bind group (bind on Debian/Ubuntu, named on RHEL-family)
detect_group() {
    for grp in bind named; do
        if getent group "$grp" &>/dev/null; then
            echo "$grp"
            return
        fi
    done
    echo "bind"
}

# --- Resolve zone file path ---
if [[ -n "${1:-}" ]]; then
    ZONE_FILE="$1"
else
    log "No zone file specified — reading named.conf to discover zone path..."
    if ZONE_FILE=$(detect_zone_file 2>/dev/null); then
        log "Discovered zone file: $ZONE_FILE"
    else
        die "Cannot determine the zone file path for '$ZONE_NAME'.
Possible reasons: named.conf not found, zone not configured yet, or defined in a nested include.

Fix one of:
  1. Add a 'zone \"$ZONE_NAME\"' block to named.conf first (see README), then re-run.
  2. Pass the path as an argument:
       $0 /var/named/db.rpz.local"
    fi
fi

BIND_SERVICE="${BIND_SERVICE:-$(detect_service)}"
BIND_GROUP="${BIND_GROUP:-$(detect_group)}"

log "Detected: service=${BIND_SERVICE}  group=${BIND_GROUP}  zone_file=${ZONE_FILE}"

log "Fetching RPZ zone..."
curl -fsSL "$RPZ_URL" | gzip -dc > "$TMP_FILE"

log "Validating zone..."
named-checkzone "$ZONE_NAME" "$TMP_FILE"

log "Installing zone file..."
cp "$TMP_FILE" "$ZONE_FILE"
chown "root:${BIND_GROUP}" "$ZONE_FILE"
chmod 640 "$ZONE_FILE"

log "Reloading BIND9 (systemctl reload ${BIND_SERVICE})..."
systemctl reload "$BIND_SERVICE"

log "Done."
