#!/usr/bin/env bash
# DEPRECATED — kept for backward compatibility only.
#
# The pipeline entry point is now run.py:
#
#   python3 run.py [--skip-download] [--unsorted] [--workers N] ...
#
# This script delegates to run.py so existing CI/cron jobs continue to
# work unchanged.  The original curl-based downloader (--legacy) is
# preserved below as historical reference.
set -euo pipefail

cd "$(dirname "$0")"

echo "Warning: update.sh is deprecated. Use: python3 run.py" >&2

# ── argument parsing ────────────────────────────────────────────────────────
LEGACY=false
PASSTHROUGH_FLAGS=""
for arg in "$@"; do
  case "$arg" in
    --legacy)        LEGACY=true ;;
    --unsorted)      PASSTHROUGH_FLAGS="$PASSTHROUGH_FLAGS --unsorted" ;;
    --skip-download) PASSTHROUGH_FLAGS="$PASSTHROUGH_FLAGS --skip-download" ;;
  esac
done

# ── default path: delegate to run.py ────────────────────────────────────────
if [ "$LEGACY" = false ]; then
  # shellcheck disable=SC2086
  exec python3 run.py $PASSTHROUGH_FLAGS
fi

# ── legacy path: original curl loop ─────────────────────────────────────────
# Kept as historical reference only — superseded by fetch.py / run.py.
echo "Running legacy curl-based downloader…" >&2
mkdir -p raw processed
rm -f raw/*

if [ -f sources.conf ]; then
  SOURCES_FILE="sources.conf"
elif [ -f sources.txt ]; then
  SOURCES_FILE="sources.txt"
else
  echo "No sources.conf or sources.txt found." >&2
  exit 1
fi

i=0
while IFS= read -r line || [ -n "$line" ]; do
  line="$(echo "$line" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
  case "$line" in
    ''|\#*|\;*|\!*) continue ;;
  esac
  url="${line%%#*}"
  url="$(echo "$url" | sed 's/[[:space:]]*$//')"
  [ -z "$url" ] && continue
  i=$((i+1))
  base=$(basename "${url%%\?*}")
  fname=$(printf "%02d_%s" "$i" "$base")
  echo "Fetching $url -> raw/$fname"
  if curl -fsSL "$url" -o "raw/$fname"; then
    echo "$fname $url" >> raw/sources.map
  else
    echo "Warning: failed fetching $url" >&2
  fi
done < "$SOURCES_FILE"

python3 merge.py --raw raw --map raw/sources.map --out processed/blocklist.txt $PASSTHROUGH_FLAGS
echo "Done (legacy mode)."
