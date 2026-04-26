#!/usr/bin/env bash
#
# Publish all Phantom crates to crates.io in dependency order.
#
# Prerequisites:
#   1. Have a crates.io account linked to GitHub (https://crates.io/login)
#   2. Generate an API token: https://crates.io/me
#   3. Run `cargo login <token>` once (stores in ~/.cargo/credentials.toml)
#      OR set CARGO_REGISTRY_TOKEN in this shell before running
#
# Usage:
#   ./scripts/publish-crates.sh           # Publish all 5 crates
#   DRY_RUN=1 ./scripts/publish-crates.sh # Just verify packages, don't push
#
# After each publish there is a short delay so the index can update before
# the next dependent crate is published.

set -euo pipefail

# Dependency order: leaves first, then crates that depend on them.
#
#   phantom-secrets-core
#     ├── phantom-secrets-vault   (depends on -core)
#     ├── phantom-secrets-proxy   (depends on -core)
#     │     └── phantom-secrets   (CLI; depends on -core, -vault, -proxy)
#     └── phantom-secrets-mcp     (depends on -core, -vault)
CRATES=(
  "phantom-secrets-core"
  "phantom-secrets-vault"
  "phantom-secrets-proxy"
  "phantom-secrets-mcp"
  "phantom-secrets"  # CLI binary — published last so all deps are visible.
)

DRY_RUN="${DRY_RUN:-}"

cd "$(dirname "$0")/.."

if [[ -n "$DRY_RUN" ]]; then
  echo "DRY_RUN=1 — packaging only, no upload."
fi

for crate in "${CRATES[@]}"; do
  echo
  echo "── $crate ──────────────────────────────────────────────"
  if [[ -n "$DRY_RUN" ]]; then
    cargo package -p "$crate"
  else
    # --no-verify skips a redundant compile against the just-uploaded
    # version of the previous crate, which would fail until the index
    # propagates. We've already verified the workspace builds.
    cargo publish -p "$crate" --no-verify
    echo "Published $crate. Sleeping 30s for crates.io index to update…"
    sleep 30
  fi
done

echo
echo "All crates published. Verify with:"
echo "  cargo search phantom-secrets --limit 5"
echo
echo "Users can now install with:"
echo "  cargo install phantom-secrets"
