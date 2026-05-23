#!/usr/bin/env bash
# update.sh — main entry point for the blocklist pipeline.
#
# Default: delegates to update.py (concurrent, retry, gzip/zip support).
# Legacy:  ./update.sh --legacy [--unsorted]  — original curl-based loop.
set -euo pipefail

cd "$(dirname "$0")"

# ── argument parsing ────────────────────────────────────────────────────────
LEGACY=false
UNSORTED_FLAG=""
for arg in "$@"; do
  case "$arg" in
    --legacy)   LEGACY=true ;;
    --unsorted) UNSORTED_FLAG="--unsorted" ;;
  esac
done

# ── default path: Python downloader ────────────────────────────────────────
if [ "$LEGACY" = false ]; then
  exec python3 update.py $UNSORTED_FLAG
fi

# ── legacy path: original curl loop ────────────────────────────────────────
echo "Running legacy curl-based downloader…"
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

python3 merge.py --raw raw --map raw/sources.map --out processed/blocklist.txt $UNSORTED_FLAG
echo "Done (legacy mode)."
