#!/usr/bin/env bash
# First-run scorecard: time from the documented release download to the first
# successful `phantom exec` with one wrapped fake secret. Each run uses a fresh
# HOME and project directory. Only a random per-run fake value is used; it is
# piped to `phantom add --stdin` and never printed. Method follows
# docs/BENCHMARKS.md (download archive and .sha256 sidecar, verify, extract).
#
# Usage: scripts/bench/first-run.sh [runs]   (env: PHANTOM_VERSION, default v0.7.9)
set -euo pipefail

RUNS="${1:-10}"
VERSION="${PHANTOM_VERSION:-v0.7.9}"
BASE="https://github.com/ashlrai/phantom-secrets/releases/download/${VERSION}"

case "$(uname -s)-$(uname -m)" in
  Linux-x86_64) TARGET=x86_64-unknown-linux-gnu ;;
  Linux-aarch64) TARGET=aarch64-unknown-linux-gnu ;;
  Darwin-arm64) TARGET=aarch64-apple-darwin ;;
  Darwin-x86_64) TARGET=x86_64-apple-darwin ;;
  *) echo "unsupported platform $(uname -s)-$(uname -m)" >&2; exit 1 ;;
esac
ASSET="phantom-${TARGET}.tar.gz"

sha256_check() {
  if command -v sha256sum >/dev/null; then sha256sum -c "$1" >/dev/null
  else shasum -a 256 -c "$1" >/dev/null; fi
}
digest() {
  if command -v sha256sum >/dev/null; then sha256sum | cut -d' ' -f1
  else shasum -a 256 | cut -d' ' -f1; fi
}
now() { python3 -c 'import time; print(f"{time.monotonic():.6f}")'; }

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
RESULTS="$WORK/results.txt"
: > "$RESULTS"; : > "$RESULTS.exec"

for i in $(seq 1 "$RUNS"); do
  RUN="$WORK/run$i"
  mkdir -p "$RUN/home" "$RUN/bin" "$RUN/proj"
  FAKE="fake_$(head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n')"
  FAKE_SHA="$(printf %s "$FAKE" | digest)"
  (
    cd "$RUN"
    export HOME="$RUN/home"
    t0="$(now)"
    curl -fsSL -o "$ASSET" "$BASE/$ASSET"
    curl -fsSL -o "$ASSET.sha256" "$BASE/$ASSET.sha256"
    sha256_check "$ASSET.sha256"
    tar -xzf "$ASSET" -C bin
    export PATH="$RUN/bin:$PATH"
    cd proj
    git init -q
    phantom init --empty >/dev/null 2>&1
    printf %s "$FAKE" | phantom add FAKE_API_KEY --stdin >/dev/null 2>&1
    # The child must see a phm_ session token, never the vault value.
    phantom exec -- sh -c 'v="$FAKE_API_KEY"; printf "%s %s\n" "${v%%_*}" "$(printf %s "$v" | { sha256sum 2>/dev/null || shasum -a 256; } | cut -d" " -f1)" > ../child.out' >/dev/null 2>&1
    out="$(cat ../child.out)"
    t1="$(now)"
    prefix="${out%% *}"; child_sha="${out##* }"
    if [ "$prefix" != "phm" ] || [ "$child_sha" = "$FAKE_SHA" ]; then
      echo "run $i: wrapped exec check failed (prefix=$prefix, value_leaked=$([ "$child_sha" = "$FAKE_SHA" ] && echo yes || echo no))" >&2
      exit 1
    fi
    if grep -rqF "$FAKE" "$RUN/proj" 2>/dev/null; then
      echo "run $i: fake value found in project files" >&2; exit 1
    fi
    python3 -c "print(f'{$t1-$t0:.4f}')" >> "$RESULTS"
    # Guardrail: warm exec time, compared with SOPS 0.0203 s in docs/BENCHMARKS.md.
    e0="$(now)"; phantom exec -- true >/dev/null 2>&1; e1="$(now)"
    python3 -c "print(f'{$e1-$e0:.4f}')" >> "$RESULTS.exec"
  )
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
    f"Runs: {len(vals)}. Download through first wrapped `phantom exec`.",
    "",
    "| p50 | p95 | min | max | target |",
    "|---|---|---|---|---|",
    f"| {p50:.3f} s | {p95:.3f} s | {vals[0]:.3f} s | {vals[-1]:.3f} s | p95 <= 5 s: {'pass' if p95 <= 5 else 'FAIL'} |",
    "",
    f"Warm `phantom exec -- true` median: {ex:.4f} s (guardrail: under SOPS {SOPS} s: {'pass' if ex < SOPS else 'FAIL'}). Includes one python3 startup from the timer, so it overstates exec time.",
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
