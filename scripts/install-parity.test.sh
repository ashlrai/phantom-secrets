#!/usr/bin/env bash
# Isolated shell check: scripts/install.sh and apps/web/public/install.sh must
# stay byte-identical except for the one reviewed difference, the
# CANDIDATE_TAG line (source targets the candidate, public copy stays on the
# verified release). Any other drift fails. Also proves the check can fail by
# mutating a throwaway copy. No node, network, or repo writes.
# Usage: bash scripts/install-parity.test.sh [source-installer [public-installer]]
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source_copy="${1:-$here/install.sh}"
public_copy="${2:-$here/../apps/web/public/install.sh}"
root="$(mktemp -d)"
trap 'rm -rf "$root"' EXIT

# Mask the reviewed CANDIDATE_TAG value; everything else is compared as-is.
mask() { sed -E 's/^CANDIDATE_TAG="[^"]*"$/CANDIDATE_TAG="<reviewed>"/' "$1"; }
parity() { # left right -> 0 when identical outside the reviewed line
  mask "$1" > "$root/l"
  mask "$2" > "$root/r"
  cmp -s "$root/l" "$root/r"
}
# Each copy must carry exactly one candidate line, or masking hides nothing real.
tag_lines() { grep -c '^CANDIDATE_TAG="[^"]*"$' "$1" || true; }

fail=0
for f in "$source_copy" "$public_copy"; do
  [ -f "$f" ] || { echo "FAIL: missing $f" >&2; exit 1; }
  [ "$(tag_lines "$f")" = 1 ] || { echo "FAIL: $f needs exactly one CANDIDATE_TAG line" >&2; fail=1; }
done

if parity "$source_copy" "$public_copy"; then
  echo "ok   installer copies match outside CANDIDATE_TAG"
else
  echo "FAIL installer copies differ outside CANDIDATE_TAG:" >&2
  diff -u "$root/l" "$root/r" >&2 || true
  fail=1
fi

# Negative control: a drifted copy must be caught.
cp "$public_copy" "$root/drift.sh"
printf '# drift\n' >> "$root/drift.sh"
if parity "$source_copy" "$root/drift.sh"; then
  echo "FAIL parity check did not detect an added line" >&2
  fail=1
else
  echo "ok   parity check detects drift"
fi

exit "$fail"
