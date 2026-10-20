#!/usr/bin/env bash
# Compare the remote ref with the SHA captured before building.
set -euo pipefail
if [ "$#" -ne 3 ]; then
  echo "Usage: $0 REMOTE BRANCH EXPECTED_REMOTE_SHA" >&2
  exit 2
fi
remote="$1"
branch="$2"
expected="$3"
git check-ref-format "refs/heads/$branch"
if [[ ! "$expected" =~ ^[0-9a-f]{40}$ && ! "$expected" =~ ^[0-9a-f]{64}$ ]]; then
  echo "Expected a full remote commit SHA" >&2
  exit 2
fi
git push "--force-with-lease=refs/heads/$branch:$expected" "$remote" "HEAD:refs/heads/$branch"
