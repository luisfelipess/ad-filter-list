#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"
OUTDIR=processed
NEW=$OUTDIR/blocklist.txt
OLD=$OUTDIR/blocklist.txt.old

if [ ! -f "$NEW" ]; then
  echo "New blocklist not found: $NEW" >&2
  exit 1
fi

if [ ! -f "$OLD" ]; then
  echo "Old blocklist not found: $OLD" >&2
  exit 1
fi

grep -v '^#' "$NEW" | awk '{print $2}' | sort > "$OUTDIR/.new_domains.txt"
grep -v '^#' "$OLD" | awk '{print $2}' | sort > "$OUTDIR/.old_domains.txt"

echo "Computing differences..."
comm -23 "$OUTDIR/.new_domains.txt" "$OUTDIR/.old_domains.txt" > "$OUTDIR/added.txt"
comm -13 "$OUTDIR/.new_domains.txt" "$OUTDIR/.old_domains.txt" > "$OUTDIR/removed.txt"

echo "Added: $(wc -l < "$OUTDIR/added.txt")"
echo "Removed: $(wc -l < "$OUTDIR/removed.txt")"

echo "Added sample (first 20):"
head -n 20 "$OUTDIR/added.txt" || true
echo
echo "Removed sample (first 20):"
head -n 20 "$OUTDIR/removed.txt" || true

rm -f "$OUTDIR/.new_domains.txt" "$OUTDIR/.old_domains.txt"

echo "Diff files: $OUTDIR/added.txt, $OUTDIR/removed.txt"
