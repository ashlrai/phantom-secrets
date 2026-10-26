#!/usr/bin/env bash
# First-run scorecard: time from the documented release download to the first
# successful `phantom exec` with one wrapped fake secret. Each run uses a fresh
# HOME, encrypted-file vault, and project directory. A random per-run fake value
# is piped to `phantom add --stdin` and never printed. Method follows
# README.md (download archive and .sha256 sidecar, verify, extract).
# This measures CI file-vault onboarding, not interactive OS-keychain onboarding.
#
# Usage: scripts/bench/first-run.sh [runs]   (env: PHANTOM_VERSION, default v0.7.9)
set -euo pipefail
umask 077

RUNS="${1:-10}"
VERSION="${PHANTOM_VERSION:-v0.7.9}"
if [ "$#" -gt 1 ] || ! [[ "$RUNS" =~ ^[1-9][0-9]?$|^100$ ]]; then
  echo "usage: $0 [runs: 1-100]" >&2; exit 1
fi
if ! [[ "$VERSION" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "PHANTOM_VERSION must be a release tag (vMAJOR.MINOR.PATCH)" >&2; exit 1
fi
# An isolated HOME does not isolate macOS Keychain. Do not silently override
# an operator's keychain-only policy to run this file-vault benchmark.
case "${PHANTOM_REQUIRE_KEYCHAIN:-}" in
  1|[Tt][Rr][Uu][Ee]) echo "first-run scorecard requires an ephemeral file vault; PHANTOM_REQUIRE_KEYCHAIN is set" >&2; exit 1 ;;
esac
BASE="https://github.com/ashlrai/phantom-secrets/releases/download/${VERSION}"

case "$(uname -s)-$(uname -m)" in
  Linux-x86_64) TARGET=x86_64-unknown-linux-gnu ;;
  Linux-aarch64) TARGET=aarch64-unknown-linux-gnu ;;
  Darwin-arm64) TARGET=aarch64-apple-darwin ;;
  Darwin-x86_64) TARGET=x86_64-apple-darwin ;;
  *) echo "unsupported platform $(uname -s)-$(uname -m)" >&2; exit 1 ;;
esac
ASSET="phantom-${TARGET}.tar.gz"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
RESULTS="$WORK/results.txt"
: > "$RESULTS"; : > "$RESULTS.exec"

for i in $(seq 1 "$RUNS"); do
  RUN="$WORK/run$i"
  mkdir -p "$RUN/home" "$RUN/bin" "$RUN/proj"
  # Clear inherited credentials and storage/proxy overrides before generating
  # synthetic vault material. No passphrase is passed through process argv.
  env -i HOME="$RUN/home" PATH="$PATH" TMPDIR="$WORK" \
    bash -s -- "$RUN" "$BASE" "$ASSET" "$RESULTS" "$i" <<'BASH'
    set -Eeuo pipefail
    RUN="$1"; BASE="$2"; ASSET="$3"; RESULTS="$4"; i="$5"
    sha256_check() {
      if command -v sha256sum >/dev/null; then sha256sum -c "$1" >/dev/null
      else shasum -a 256 -c "$1" >/dev/null; fi
    }
    digest() {
      if command -v sha256sum >/dev/null; then sha256sum | cut -d' ' -f1
      else shasum -a 256 | cut -d' ' -f1; fi
    }
    now() { python3 -c 'import time; print(f"{time.monotonic():.6f}")'; }
    FAKE="fake_$(head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n')"
    PHANTOM_VAULT_PASSPHRASE="$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')"
    if ! [[ "$PHANTOM_VAULT_PASSPHRASE" =~ ^[0-9a-f]{64}$ ]]; then
      echo "run $i: could not generate an ephemeral vault passphrase" >&2; exit 1
    fi
    export PHANTOM_VAULT_PASSPHRASE
    FAKE_SHA="$(printf %s "$FAKE" | digest)"
    cd "$RUN"
    # Never fall through to a preinstalled phantom if the archive is incomplete.
    phantom() {
      if ! "$RUN/bin/phantom" "$@" >/dev/null 2>&1; then
        echo "run $i: $stage failed (runtime output withheld)" >&2; exit 1
      fi
    }
    stage="download"
    trap 'echo "run $i: $stage failed (runtime output withheld)" >&2; exit 1' ERR
    t0="$(now)"
    curl -fsSL -o "$ASSET" "$BASE/$ASSET"
    curl -fsSL -o "$ASSET.sha256" "$BASE/$ASSET.sha256"
    sha256_check "$ASSET.sha256"
    tar -xzf "$ASSET" -C bin
    export PATH="$RUN/bin:$PATH"
    cd proj
    git init -q
    stage="init"
    phantom init --empty
    stage="add"
    printf %s "$FAKE" | phantom add FAKE_API_KEY --stdin
    # The child must see a phm_ session token, never the vault value.
    stage="wrapped exec"
    phantom exec -- python3 -c 'import hashlib, os, pathlib; v = os.environ.get("FAKE_API_KEY", ""); pathlib.Path("../child.out").write_text(v.partition("_")[0] + " " + hashlib.sha256(v.encode()).hexdigest())'
    out="$(cat ../child.out)"
    t1="$(now)"
    child_sha="${out##* }"
    if ! [[ "$out" =~ ^phm\ [0-9a-f]{64}$ ]] || [ "$child_sha" = "$FAKE_SHA" ]; then
      echo "run $i: wrapped exec check failed (evidence withheld)" >&2
      exit 1
    fi
    stage="project scan"
    scan_status=0
    grep -rqF "$FAKE" "$RUN/proj" 2>/dev/null || scan_status=$?
    if [ "$scan_status" -ne 1 ]; then
      echo "run $i: project scan found a fake value or could not complete" >&2; exit 1
    fi
    python3 -c "print(f'{$t1-$t0:.4f}')" >> "$RESULTS"
    # Preserve the original scorecard's informational warm-exec comparison.
    stage="warm exec"
    e0="$(now)"; phantom exec -- true; e1="$(now)"
    python3 -c "print(f'{$e1-$e0:.4f}')" >> "$RESULTS.exec"
BASH
  rm -rf "$RUN"
done

python3 - "$RESULTS" "$TARGET" "$VERSION" <<'PY'
import math, os, statistics, sys
vals = sorted(float(x) for x in open(sys.argv[1]) if x.strip())
ex = statistics.median(float(x) for x in open(sys.argv[1] + ".exec") if x.strip())
SOPS = 0.0203
def pct(p):
    k = max(0, math.ceil(p / 100 * len(vals)) - 1)
    return vals[k]
p50, p95 = statistics.median(vals), pct(95)
lines = [
    f"### First run: {sys.argv[3]} on {sys.argv[2]}",
    "",
    f"Runs: {len(vals)}. Download through first wrapped `phantom exec`, using an ephemeral encrypted-file vault (no OS keychain).",
    "",
    "| p50 | p95 | min | max | target |",
    "|---|---|---|---|---|",
    f"| {p50:.3f} s | {p95:.3f} s | {vals[0]:.3f} s | {vals[-1]:.3f} s | p95 <= 5 s: {'pass' if p95 <= 5 else 'FAIL'} |",
    "",
    f"Warm `phantom exec -- true` median: {ex:.4f} s (original reference baseline {SOPS} s: {'pass' if ex < SOPS else 'FAIL'}; comparison only, baseline not remeasured). Includes one python3 startup from the timer, so it overstates exec time.",
    "",
    "Samples (sorted): " + ", ".join(f"{v:.3f}" for v in vals),
]
text = "\n".join(lines) + "\n"
print(text)
summary = os.environ.get("GITHUB_STEP_SUMMARY")
if summary:
    open(summary, "a").write(text)
sys.exit(0 if p95 <= 5 else 1)
PY
