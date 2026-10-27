#!/usr/bin/env bash
# test-docs-agents.sh — doc test for docs/agents.md.
#
# Every fenced ```sh block in the guide is extracted and executed verbatim,
# in order, inside a scratch project: fresh HOME, encrypted-file vault via
# PHANTOM_VAULT_PASSPHRASE, and a PATH whose `phantom` is the workspace
# debug binary. Each block runs under `bash -e -o pipefail`; the guide's `!`
# prefixes turn expected refusals into assertions (a refusal that stops
# refusing fails the block).
#
# After the run, the assertions below pin the claims the page makes:
# placeholders rather than values on disk, a session token (not the real
# key) in the child's environment, each refusal's message, and — the point
# of the page — the demo key never appearing in any output an agent sees.
#
# Overridable:
#   PHANTOM_BIN   path to the phantom binary (default: target/debug/phantom,
#                 built with cargo when missing)

set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
DOC="$ROOT/docs/agents.md"
# Demo values written by the guide's blocks. They are intentionally
# low-entropy placeholders; the test proves they never reach any output.
CANARIES=(
    'sk-proj-doc-demo-not-a-real-key'
    'doc-demo-signing-key-not-real'
    'sk-mistral-doc-demo-not-real'
    'postgres://doc-demo:doc-demo@localhost:5432/docdb'
)

say()  { printf '%s\n' "$*"; }
fail() { say "FAIL: $*" >&2; exit 1; }

[[ -f $DOC ]] || fail "missing $DOC"

# --- phantom binary -------------------------------------------------------

if [[ -n ${PHANTOM_BIN:-} ]]; then
    [[ -x $PHANTOM_BIN || -x $PHANTOM_BIN.exe ]] \
        || fail "PHANTOM_BIN is not executable: $PHANTOM_BIN"
else
    PHANTOM_BIN="$ROOT/target/debug/phantom"
    if [[ ! -x $PHANTOM_BIN && ! -x $PHANTOM_BIN.exe ]]; then
        CARGO=$(command -v cargo || true)
        CARGO=${CARGO:-"$HOME/.cargo/bin/cargo"}
        [[ -x $CARGO ]] || command -v "$CARGO" >/dev/null 2>&1 \
            || fail "phantom binary missing and cargo not found"
        say "-> building phantom (cargo build --bin phantom)"
        (cd "$ROOT" && "$CARGO" build --bin phantom)
    fi
fi
# Prefer the .exe when only it exists (Windows builds), then resolve to an
# absolute path so its directory can lead the sandbox PATH.
[[ -x $PHANTOM_BIN ]] || [[ ! -x $PHANTOM_BIN.exe ]] || PHANTOM_BIN+=.exe
PHANTOM_BIN=$(command -v "$PHANTOM_BIN") || fail "cannot resolve $PHANTOM_BIN"
say "-> phantom binary: $PHANTOM_BIN"

# --- sandbox ---------------------------------------------------------------

BASE_PATH=$PATH
SANDBOX=$(mktemp -d "${TMPDIR:-/tmp}/phantom-agents-doc.XXXXXX")
SANDBOX=$(cd "$SANDBOX" && pwd -P)   # canonical: Phantom refuses lexical aliases
WORK=$SANDBOX/project
HOMED=$SANDBOX/home
BLOCKS=$SANDBOX/blocks
LOGS=$SANDBOX/logs
mkdir -p "$WORK" "$HOMED" "$BLOCKS" "$LOGS"
cleanup() {
    rm -rf "$SANDBOX"
}
trap cleanup EXIT

# --- extract every ```sh block, in doc order --------------------------------

awk -v out="$BLOCKS" '
    /^[[:space:]]*```sh[[:space:]]*$/ { n++; inblock = 1; next }
    /^[[:space:]]*```/               { inblock = 0; next }
    inblock                          { print > (out "/block-" sprintf("%02d", n) ".sh") }
    END                              { print n + 0 > (out "/count") }
' "$DOC"

NBLOCKS=$(cat "$BLOCKS/count")
(( NBLOCKS >= 8 )) || fail "extracted only $NBLOCKS sh block(s) from $DOC — extraction broken or doc gutted"
say "-> extracted $NBLOCKS sh block(s) from docs/agents.md"

# --- run every block ---------------------------------------------------------

# env -i keeps ambient variables (including any real secrets in the caller's
# environment) out of the demo entirely: a stray DATABASE_URL would make
# `phantom exec` refuse, and a real key has no business near a doc test.
run_block() {
    (
        cd "$WORK"
        env -i \
            "HOME=$HOMED" \
            "TMPDIR=${TMPDIR:-/tmp}" \
            "PHANTOM_VAULT_PASSPHRASE=phantom-agents-doc-test" \
            "NO_COLOR=1" \
            "TERM=dumb" \
            "PATH=$(dirname "$PHANTOM_BIN"):$BASE_PATH" \
            bash -e -o pipefail "$1"
    )
}

failures=0
for f in "$BLOCKS"/block-*.sh; do
    name=$(basename "$f" .sh)
    if run_block "$f" >"$LOGS/$name.log" 2>&1; then
        say "ok   $name"
    else
        say "FAIL $name — output:"
        sed 's/^/     | /' "$LOGS/$name.log" >&2
        failures=$((failures + 1))
    fi
done
(( failures == 0 )) || fail "$failures doc block(s) failed"

# --- assertions ---------------------------------------------------------------

assert_count=0

# assert_output '<literal command line in the doc>' '<extended regex its log must match>'
assert_output() {
    local needle=$1 pattern=$2 block log
    block=$(grep -lF -- "$needle" "$BLOCKS"/block-*.sh | head -n 1 || true)
    if [[ -z $block ]]; then
        say "FAIL assert: no doc block contains: $needle" >&2
        assert_count=$((assert_count + 1))
        return 1
    fi
    log="$LOGS/$(basename "$block" .sh).log"
    if grep -Eq -- "$pattern" "$log"; then
        assert_count=$((assert_count + 1))
        return 0
    fi
    say "FAIL assert: output of \`$needle\` lacks /$pattern/" >&2
    assert_count=$((assert_count + 1))
    return 1
}

say "-> asserting documented outcomes"
ASSERT_FAILS=0

# Placeholders on disk, values gone.
grep -Eq '^OPENAI_API_KEY=phm_[0-9a-f]{64}$' "$WORK/.env" \
    || { say "FAIL assert: .env lacks a phm_ placeholder for OPENAI_API_KEY" >&2; ASSERT_FAILS=$((ASSERT_FAILS + 1)); }
assert_count=$((assert_count + 1))

for canary in "${CANARIES[@]}"; do
    if grep -rFq "$canary" "$WORK" "$LOGS" 2>/dev/null; then
        say "FAIL assert: demo value leaked into project files or command output" >&2
        ASSERT_FAILS=$((ASSERT_FAILS + 1))
    fi
    # The vault is encrypted at rest; the plaintext must not sit in HOME either.
    if grep -rFq "$canary" "$HOMED" 2>/dev/null; then
        say "FAIL assert: demo value stored unencrypted under HOME" >&2
        ASSERT_FAILS=$((ASSERT_FAILS + 1))
    fi
    assert_count=$((assert_count + 1))
done

# Behaviour each block demonstrated.
assert_output 'phantom init --from .env'                   'secret\(s\) (are )?now protected|Rewrote'        || ASSERT_FAILS=$((ASSERT_FAILS + 1))
assert_output 'phantom list'                               'OPENAI_API_KEY'                                 || ASSERT_FAILS=$((ASSERT_FAILS + 1))
assert_output 'phantom why OPENAI_API_KEY'                 'proxied'                                        || ASSERT_FAILS=$((ASSERT_FAILS + 1))
assert_output 'phantom why INTERNAL_SIGNING_KEY'           'no route'                                       || ASSERT_FAILS=$((ASSERT_FAILS + 1))
assert_output 'phantom exec -- printenv OPENAI_API_KEY'    '^phm_[0-9a-f]{64}$'                             || ASSERT_FAILS=$((ASSERT_FAILS + 1))
assert_output 'phantom exec -- printenv OPENAI_BASE_URL'   'http://127\.0\.0\.1:[0-9]+/openai/'             || ASSERT_FAILS=$((ASSERT_FAILS + 1))
assert_output 'PHANTOM_VAULT_PASSPHRASE:-<unset>'          'PHANTOM_VAULT_PASSPHRASE=<unset>'               || ASSERT_FAILS=$((ASSERT_FAILS + 1))
assert_output 'phantom exec -- false'                      'exited with code 1'                             || ASSERT_FAILS=$((ASSERT_FAILS + 1))
assert_output 'phantom add BACKUP_KEY'                     'Positional secret values are disabled'          || ASSERT_FAILS=$((ASSERT_FAILS + 1))
assert_output 'phantom add MISTRAL_API_KEY --stdin'        'value never printed|Stored MISTRAL_API_KEY'     || ASSERT_FAILS=$((ASSERT_FAILS + 1))
assert_output 'phantom reveal OPENAI_API_KEY'              'Refusing to reveal'                             || ASSERT_FAILS=$((ASSERT_FAILS + 1))
assert_output 'services.my_gateway'                        'not approved for agentic execution|Refusing unapproved repository-controlled proxy routing' || ASSERT_FAILS=$((ASSERT_FAILS + 1))
assert_output 'DATABASE_URL=postgres'                      'Refusing to expose connection-string'           || ASSERT_FAILS=$((ASSERT_FAILS + 1))
assert_output 'phantom check'                              'No unprotected secrets'                         || ASSERT_FAILS=$((ASSERT_FAILS + 1))
assert_output 'phantom doctor'                             'All checks passed'                              || ASSERT_FAILS=$((ASSERT_FAILS + 1))

(( ASSERT_FAILS == 0 )) || fail "$ASSERT_FAILS assertion(s) failed"
say "ok   all done: $NBLOCKS doc block(s) executed, $assert_count assertion(s) passed"
