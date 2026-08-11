#!/usr/bin/env bash
# Regenerate the blocklists and publish them in a single step.
#
# Local equivalent of the "Update blocklists" GitHub Actions workflow:
# runs the pipeline (processed/ + reports/ + README stats), then commits and
# force-pushes the outputs.
#
# Publishing model — "squash-in-place": the generated outputs are large and
# rebuilt on every run, so we keep only ONE rolling data commit at the tip
# instead of stacking a new commit each time (which previously bloated .git to
# ~5 GB). If the tip is already a rolling data commit we amend it; otherwise we
# add a fresh one. The force-push therefore only ever rewrites that single data
# commit — never a code commit beneath it.
#
# No identity is hardcoded here: commits use your existing `git config`
# user.name / user.email, and the rolling data commit is detected by its
# content (message prefix + only generated paths), not by author.
set -euo pipefail

cd "$(dirname "$0")/.."

REMOTE="origin"
BRANCH="$(git rev-parse --abbrev-ref HEAD)"
DRY_RUN=false
PASSTHROUGH=()

usage() {
  cat <<EOF
Usage: $(basename "$0") [--dry-run] [run.py flags...]

Rebuild the blocklists and publish them to $REMOTE/<current branch> as a single
rolling data commit (squash-in-place).

Options:
  --dry-run   Build and commit locally, but do NOT push.
  -h, --help  Show this help.

Any other flag is passed straight through to run.py, e.g.:
  $(basename "$0") --skip-download --unsorted
EOF
}

# ── args ────────────────────────────────────────────────────────────────────
# Script owns --dry-run/--help; everything else is forwarded to run.py.
while [ $# -gt 0 ]; do
  case "$1" in
    --dry-run) DRY_RUN=true; shift ;;
    -h|--help) usage; exit 0 ;;
    *)         PASSTHROUGH+=("$1"); shift ;;
  esac
done

# Paths this script is allowed to commit — the pipeline's generated outputs.
GENERATED=(processed reports README.md)

# ── 1. regenerate ───────────────────────────────────────────────────────────
echo "==> Running pipeline: python3 run.py ${PASSTHROUGH[*]:-}"
python3 run.py "${PASSTHROUGH[@]+"${PASSTHROUGH[@]}"}"

# ── 2. stage only the generated outputs ─────────────────────────────────────
git add -- "${GENERATED[@]}"

if git diff --staged --quiet -- "${GENERATED[@]}"; then
  echo "==> No changes to publish. Done."
  exit 0
fi

# ── 3. commit message from the run report ───────────────────────────────────
REPORT=reports/blocklist-report.json
if [ -f "$REPORT" ] && command -v jq >/dev/null 2>&1; then
  DEDUPED=$(jq '.summary.unique_deduped' "$REPORT")
  DELTA_A=$(jq '.summary.delta_added'    "$REPORT")
  DELTA_R=$(jq '.summary.delta_removed'  "$REPORT")
  MSG="Update blocklists: ${DEDUPED} domains (+${DELTA_A}/-${DELTA_R}) [skip ci]"
else
  MSG="Update blocklists [skip ci]"
fi

# ── 4. squash-in-place: amend the rolling data commit, else create one ───────
# The tip is a rolling data commit when its subject has the Update-blocklists
# prefix AND it changed only generated paths. Purely content-based, so it works
# regardless of who authored it (you locally or the Actions bot).
is_rolling_data_commit() {
  case "$(git log -1 --format='%s')" in
    "Update blocklists"*) ;;
    *) return 1 ;;
  esac
  local other
  other="$(git show --name-only --format='' HEAD \
           | grep -vE '^(processed/|reports/|README\.md$)' | grep -v '^$' || true)"
  [ -z "$other" ]
}

if is_rolling_data_commit; then
  echo "==> Amending existing rolling data commit"
  git commit --amend -m "$MSG" -- "${GENERATED[@]}"
else
  echo "==> Creating new rolling data commit"
  git commit -m "$MSG" -- "${GENERATED[@]}"
fi

# ── 5. publish ──────────────────────────────────────────────────────────────
if [ "$DRY_RUN" = true ]; then
  echo "==> --dry-run: committed locally, not pushing."
  echo "    Publish manually with:  git push --force $REMOTE $BRANCH"
  exit 0
fi

echo "==> Force-pushing to $REMOTE/$BRANCH (rewrites only the rolling data commit)"
git push --force "$REMOTE" "$BRANCH"
echo "==> Done."
