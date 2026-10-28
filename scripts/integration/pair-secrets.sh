#!/usr/bin/env bash
# pair-secrets: phantom-secrets side of the phantom + phantom-secrets
# integration test. Runs in merge_group only (see
# .github/workflows/pair-secrets.yml). Fails closed: any missing tool,
# missing artifact, or unimplemented assertion is a failure, except the
# posture assertion, which is skipped with a notice until `phantom posture
# --json` exists on main and becomes required as soon as it does.
#
# Inputs (env):
#   PHANTOM_SECRETS_BIN  directory holding the release-built `phantom` CLI
#   PHANTOM_PAIR_BIN     path to the ashlrai/phantom CLI (receipts), from the
#                        release cache. Phantom Core owns this side.
set -euo pipefail

fail() { echo "::error::pair-secrets: $*" >&2; exit 1; }
digest() { sha256sum | cut -d' ' -f1; }

[ -x "${PHANTOM_SECRETS_BIN:-}/phantom" ] || fail "phantom-secrets binary missing at PHANTOM_SECRETS_BIN"
export PATH="$PHANTOM_SECRETS_BIN:$PATH"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
export HOME="$WORK/home"
LOG="$WORK/all.log"
mkdir -p "$HOME" "$WORK/proj"
cd "$WORK/proj"
git init -q

# Random fake value for this run only. Never printed, never on a command line.
FAKE="pairfake_$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')"
FAKE_SHA="$(printf %s "$FAKE" | digest)"

{
  phantom init --empty
  printf %s "$FAKE" | phantom add PAIR_FAKE_API_KEY --stdin
} >>"$LOG" 2>&1 || fail "init/add failed"

# 1. Exec injection. On v0.7.9 the child receives a phm_ session token in
# place of the vault value, so the check is: the variable is present, it is a
# phm_ token, and its hash never equals the fake value's hash.
phantom exec -- sh -c 'v="$PAIR_FAKE_API_KEY"; printf "%s %s %s\n" "${#v}" "${v%%_*}" "$(printf %s "$v" | sha256sum | cut -d" " -f1)" > ../child.out' >>"$LOG" 2>&1 \
  || fail "phantom exec failed"
read -r child_len child_prefix child_sha < ../child.out || fail "child wrote no output"
[ "$child_len" -gt 0 ] || fail "child did not receive PAIR_FAKE_API_KEY"
[ "$child_prefix" = "phm" ] || fail "child did not receive a phm_ session token"
[ "$child_sha" != "$FAKE_SHA" ] || fail "child received the raw vault value"
echo "exec: child received phm_ token (len $child_len), raw value withheld"

# 2. Receipt from the phantom side: wrapped=true and one secret name.
# TODO(Phantom Core): wire PHANTOM_PAIR_BIN and the receipt read command.
# Until then this fails closed, which is safe because the job only runs in
# merge_group and merge_group is not enabled on phantom-secrets yet.
[ -x "${PHANTOM_PAIR_BIN:-}" ] || fail "phantom (receipts) binary not provided; Phantom Core wiring pending"
RECEIPT="$WORK/receipt.json"
"$PHANTOM_PAIR_BIN" receipts last --json >"$RECEIPT" 2>>"$LOG" || fail "could not read phantom receipt"
python3 - "$RECEIPT" <<'PY' || fail "receipt assertions failed"
import json, sys
r = json.load(open(sys.argv[1]))
assert r.get("wrapped") is True, "wrapped is not true"
names = r.get("secret_names") or r.get("secrets") or []
count = r.get("secret_name_count", len(names))
assert count == 1, f"secret-name count {count} != 1"
PY
RECEIPT_PROJECT="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("project",""))' "$RECEIPT")"
[ -n "$RECEIPT_PROJECT" ] || fail "receipt has no project id"

# 3. Posture counts match the receipt by shared project id.
# TODO: `phantom posture --json` is not on main yet (#465). Skipped with a
# notice until the subcommand exists; required from then on.
if phantom posture --help >/dev/null 2>&1; then
  POSTURE="$WORK/posture.json"
  phantom posture --json >"$POSTURE" 2>>"$LOG" || fail "phantom posture --json failed"
  python3 - "$POSTURE" "$RECEIPT_PROJECT" <<'PY' || fail "posture does not match receipt"
import json, sys
p = json.load(open(sys.argv[1]))
assert p.get("project") == sys.argv[2], "project id differs from receipt"
assert p.get("wrapped", 0) >= 1, "posture shows no wrapped secret"
PY
else
  echo "::notice::pair-secrets: phantom posture --json not available yet; posture assertion skipped (TODO, #465)"
fi

# 4. Byte scan: the fake value must not appear in logs, receipts, posture
# JSON, phantom-secrets state, or project files (except the vault backend).
for f in "$LOG" "$WORK"/*.json "$WORK/child.out"; do
  [ -e "$f" ] || continue
  ! grep -qF "$FAKE" "$f" || fail "fake value found in $(basename "$f")"
done
! grep -rqF "$FAKE" "$WORK/proj" "$HOME" 2>/dev/null || fail "fake value found on disk outside the vault"
echo "byte scan: fake value absent from logs, receipt, posture and state"
echo "pair-secrets: pass"
