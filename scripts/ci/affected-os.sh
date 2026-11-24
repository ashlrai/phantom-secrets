#!/usr/bin/env bash
# Affected cargo check and one-failure nextest for a pull request or merge queue.
# The full daily suite stays on the Test job. CI Gate does not call this.
set -euo pipefail
base="${1:?base sha}"
head="${2:?head sha}"
fs="$(bash scripts/ci/affected-filterset.sh "$base" "$head" || echo 'all()')"
echo "nextest filterset: $fs"
if [ "$fs" = "none()" ]; then
  echo "No affected crates." >> "${GITHUB_STEP_SUMMARY:-/dev/null}"
  exit 0
fi
if ! printf '%s' "$fs" | grep -Eq '^(all\(\)|rdeps\(=[A-Za-z0-9_-]+\)( \| rdeps\(=[A-Za-z0-9_-]+\))*)$'; then
  echo "::error::refusing unexpected nextest filterset"
  exit 1
fi
log="${RUNNER_TEMP:-/tmp}/affected-os.txt"
set +e
cargo check --workspace --all-targets --locked > "$log" 2>&1
status=$?
set -e
if [ "$status" != 0 ]; then
  node scripts/ci/first-failure.mjs --status "$status" --log "$log"
fi
set +e
cargo nextest run --workspace --all-targets --locked --max-fail 1 -E "$fs" > "$log" 2>&1
status=$?
set -e
node scripts/ci/first-failure.mjs --status "$status" --log "$log"
