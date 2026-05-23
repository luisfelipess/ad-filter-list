#!/usr/bin/env bash
# trigger-update-workflow.sh — run the "Update blocklists" GitHub Actions workflow
# via your local gh session (no tokens in this repo).
set -euo pipefail

cd "$(dirname "$0")"

WORKFLOW_FILE=".github/workflows/update.yml"
WORKFLOW_NAME="Update blocklists"
WATCH=false

usage() {
  cat <<EOF
Usage: $(basename "$0") [--watch]

Trigger the "$WORKFLOW_NAME" workflow on GitHub (same job as ./update.sh in CI).

Options:
  --watch   Wait until the run finishes (gh run watch)

Requires: gh CLI installed and authenticated (gh auth login).
EOF
}

for arg in "$@"; do
  case "$arg" in
    --watch|-w) WATCH=true ;;
    -h|--help)  usage; exit 0 ;;
    *)
      echo "Unknown option: $arg" >&2
      usage >&2
      exit 1
      ;;
  esac
done

if ! command -v gh >/dev/null 2>&1; then
  echo "error: gh (GitHub CLI) is not installed. See https://cli.github.com/" >&2
  exit 1
fi

if ! gh auth status >/dev/null 2>&1; then
  echo "error: gh is not authenticated. Run: gh auth login" >&2
  exit 1
fi

if ! gh repo view --json nameWithOwner >/dev/null 2>&1; then
  echo "error: cannot access this repository with gh (wrong directory or no access)." >&2
  exit 1
fi

echo "Triggering workflow: $WORKFLOW_NAME"
gh workflow run "$WORKFLOW_FILE"

# Brief pause so the new run appears in the list.
sleep 2

RUN_ID="$(gh run list --workflow="$WORKFLOW_FILE" --limit=1 --json databaseId --jq '.[0].databaseId')"
if [ -z "$RUN_ID" ] || [ "$RUN_ID" = "null" ]; then
  echo "Workflow triggered. Check runs with: gh run list --workflow=$WORKFLOW_FILE"
  exit 0
fi

gh run view "$RUN_ID" --web=false
echo
echo "Open in browser: $(gh run view "$RUN_ID" --json url --jq .url)"

if [ "$WATCH" = true ]; then
  echo "Watching run $RUN_ID…"
  gh run watch "$RUN_ID"
fi
