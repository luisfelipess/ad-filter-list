#!/usr/bin/env bash
# Compare processed/blocklist.txt against the last committed version.
# Quick delta counts are also in reports/blocklist-report.json (delta_added / delta_removed).
set -euo pipefail

cd "$(dirname "$0")/.."

NEW=processed/blocklist.txt

if [ ! -f "$NEW" ]; then
  echo "Blocklist not found: $NEW" >&2
  exit 1
fi

if ! git show HEAD:processed/blocklist.txt > /tmp/.bl_prev 2>/dev/null; then
  echo "No previously committed version found in git history." >&2
  exit 1
fi

domains() { grep -v '^#' "$1" | awk 'NF>=2{print $2} NF==1{print $1}' | sort; }

domains "$NEW"          > /tmp/.bl_new
domains /tmp/.bl_prev   > /tmp/.bl_old_sorted

comm -23 /tmp/.bl_new /tmp/.bl_old_sorted > processed/added.txt
comm -13 /tmp/.bl_new /tmp/.bl_old_sorted > processed/removed.txt

echo "Added:   $(wc -l < processed/added.txt)"
echo "Removed: $(wc -l < processed/removed.txt)"
echo ""
echo "Added sample (first 20):"
head -n 20 processed/added.txt || true
echo ""
echo "Removed sample (first 20):"
head -n 20 processed/removed.txt || true

rm -f /tmp/.bl_prev /tmp/.bl_new /tmp/.bl_old_sorted

echo ""
echo "Full diff: processed/added.txt, processed/removed.txt"
