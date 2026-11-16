#!/usr/bin/env bash
# Prints rust=true|false for the Rust/CLI suites. Shared by Classify changes and Lint.
# pull_request and merge_group use the same three-dot name list Classify diffs
# (BASE...HEAD). Every other event runs the Rust suites.
set -euo pipefail
if [ "${EVENT:-}" != "pull_request" ] && [ "${EVENT:-}" != "merge_group" ]; then
  echo "rust=true"
  exit 0
fi
files="$(git diff --name-only "${BASE:?}...${HEAD:?}")"
docs='^(docs/|[^/]*\.md$|.*/README\.md$|LICENSE|\.github/ISSUE_TEMPLATE/|\.github/PULL_REQUEST_TEMPLATE)'
rust=false
if printf '%s\n' "$files" | grep -Ev "$docs" | grep -Ev '^(apps/web/|scripts/supabase/|scripts/seo/|video/)' | grep -q .; then rust=true; fi
if printf '%s\n' "$files" | grep -Eq '^\.github/workflows/'; then rust=true; fi
echo "rust=$rust"
