#!/usr/bin/env bash
# Usage: fast-check.sh [BASE [HEAD]]. An empty diff performs workspace checks.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
tmp=$(mktemp)
trap 'rm -f "$tmp"' EXIT
scripts/affected-crates.sh "$@" > "$tmp"
packages=()
while IFS= read -r name; do
    if [[ "$name" == --workspace ]]; then packages=(--workspace); break; fi
    packages+=(-p "$name")
done < "$tmp"
((${#packages[@]})) || packages=(--workspace)
PYTHONDONTWRITEBYTECODE=1 python3 scripts/affected-crates.test.py
cargo fmt --all -- --check
cargo check --all-targets --locked "${packages[@]}"
cargo clippy --all-targets --locked "${packages[@]}" -- -D warnings
# Always run the dedicated security integration test.
cargo test --locked -p phantom-secrets --test copy_security_test
# Full fallback includes all workspace security and required-check tests.
cargo test --all-targets --locked --no-fail-fast "${packages[@]}"
