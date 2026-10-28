#!/usr/bin/env bash
# Usage: affected-crates.sh [BASE [HEAD]]. Output package names, or --workspace.
# With no arguments, include staged, unstaged and untracked changes against HEAD.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
if (($# > 2)); then echo 'usage: affected-crates.sh [BASE [HEAD]]' >&2; exit 2; fi
if (($# == 2)); then
    git diff --name-only -z --no-renames "$1...$2" > "$tmp/paths"
elif (($# == 1)); then
    git diff --name-only -z --no-renames "$1" > "$tmp/paths"
    git ls-files --others --exclude-standard -z >> "$tmp/paths"
else
    git diff --name-only -z --no-renames HEAD > "$tmp/paths"
    git ls-files --others --exclude-standard -z >> "$tmp/paths"
fi
cargo metadata --format-version 1 --no-deps --locked > "$tmp/metadata"
python3 scripts/affected-crates.py "$tmp/metadata" < "$tmp/paths"
