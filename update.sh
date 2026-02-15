#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"
mkdir -p raw processed
rm -f raw/*

# accept optional --unsorted flag and forward it to merge.py
UNSORTED_FLAG=""
if [ "${1-}" = "--unsorted" ]; then
  UNSORTED_FLAG="--unsorted"
fi

i=0
while IFS= read -r line || [ -n "$line" ]; do
  # trim
  line="$(echo "$line" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
  # skip empty or comment lines (starting with #, ; or !)
  case "$line" in
    ''|\#*|\;*|\!*)
      continue
      ;;
  esac
  # strip inline comment starting with # (if present)
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
done < sources.txt

python3 merge.py --raw raw --map raw/sources.map --out processed/blocklist.txt $UNSORTED_FLAG

echo "Wrote processed-blocklist.txt (unsorted=${UNSORTED_FLAG:+true})"
