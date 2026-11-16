#!/usr/bin/env bash
# Isolated shell check: when the directory that must hold scripts/install.sh's
# private staging directory is not writable, the installer exits nonzero,
# never creates (or disturbs) the destination, starts no download, and leaves
# no stage, backup, or lock entry behind.
#
# The failure is real, not shimmed: the destination's parent is chmod 555, or
# its own parent is, so the shipped installer runs end-to-end under env -i —
# no node, no network, no installer overrides, and no real dotfiles. A curl
# shim records any download attempt.
# Usage: bash scripts/install-temp.test.sh [installer]
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
installer="${1:-$here/install.sh}"
[ -f "$installer" ] || { echo "missing installer: $installer" >&2; exit 1; }

if [ "$(id -u)" = 0 ]; then
  # Root ignores directory permissions, so the failure cannot be produced.
  echo "NOTE: running as root; directory permissions are not enforced, nothing to check"
  exit 0
fi

root="$(mktemp -d)"
root="$(cd "$root" && pwd -P)"
cleanup() { chmod -R u+rwx "$root" 2>/dev/null || true; rm -rf "$root"; }
trap cleanup EXIT

mkdir -p "$root/shims"
cat > "$root/shims/curl" <<'SHIM'
#!/bin/sh
printf '%s\n' "$*" >> "$T_CURL_LOG"
exit 22
SHIM
chmod 755 "$root/shims/curl"

fail=0
RUN_RC=0
note()    { printf '%s\n' "$*"; }
fail_at() { note "FAIL $1: $2"; fail=1; }

# run_install NAME INSTALL_DIR: one installer run with a short lock wait,
# because an unwritable parent can never take the install lock.
run_install() {
  local name="$1" install="$2"
  mkdir -p "$root/$name/home"
  RUN_RC=0
  env -i \
    HOME="$root/$name/home" \
    SHELL="/bin/bash" \
    PATH="$root/shims:/usr/bin:/bin" \
    PHANTOM_INSTALL_DIR="$install" \
    PHANTOM_INSTALL_LOCK_WAIT_SECONDS=1 \
    T_CURL_LOG="$root/$name/curl.log" \
    /bin/bash "$installer" > "$root/$name/out.log" 2> "$root/$name/err.log" \
    || RUN_RC=$?
}

# expect_refused NAME: nonzero exit, an error on stderr, no download.
expect_refused() {
  local name="$1" log="$root/$1"
  [ "$RUN_RC" != 0 ] \
    || { fail_at "$name" "installer must exit nonzero"; return 1; }
  [ -s "$log/err.log" ] \
    || { fail_at "$name" "installer failed without a diagnostic"; return 1; }
  ! grep -qE "downloading|checksum" "$log/out.log" \
    || { fail_at "$name" "installer started a download before failing"; return 1; }
  [ ! -e "$log/curl.log" ] \
    || { fail_at "$name" "curl ran although staging was impossible"; return 1; }
  [ -z "$(ls -A "$log/home")" ] \
    || { fail_at "$name" "HOME was modified"; return 1; }
}

# 1. Existing read-only parent, no destination: nothing may appear in it.
check_readonly_parent() {
  local name="readonly-parent" parent="$root/readonly-parent-dir"
  mkdir -p "$parent"
  chmod 555 "$parent"
  run_install "$name" "$parent/bin"
  chmod 755 "$parent"
  expect_refused "$name" || return 0
  [ ! -e "$parent/bin" ] || { fail_at "$name" "destination was created"; return 0; }
  [ -z "$(ls -A "$parent")" ] \
    || { fail_at "$name" "stage or lock entry left in the parent"; return 0; }
  note "ok $name"
}

# 2. Read-only parent holding a previous install: it survives untouched.
check_readonly_parent_with_install() {
  local name="readonly-existing" parent="$root/readonly-existing-dir"
  mkdir -p "$parent/bin"
  printf 'preserve-me\n' > "$parent/bin/old-install"
  chmod 555 "$parent"
  run_install "$name" "$parent/bin"
  chmod 755 "$parent"
  expect_refused "$name" || return 0
  [ "$(cat "$parent/bin/old-install")" = "preserve-me" ] \
    || { fail_at "$name" "previous install was disturbed"; return 0; }
  [ "$(ls -A "$parent")" = "bin" ] \
    || { fail_at "$name" "stage or lock entry left in the parent"; return 0; }
  note "ok $name"
}

# 3. Parent cannot be created because its own parent is read-only.
check_uncreatable_parent() {
  local name="uncreatable-parent" base="$root/readonly-base"
  mkdir -p "$base"
  chmod 555 "$base"
  run_install "$name" "$base/missing/bin"
  chmod 755 "$base"
  expect_refused "$name" || return 0
  [ -z "$(ls -A "$base")" ] \
    || { fail_at "$name" "directories were created under the read-only base"; return 0; }
  note "ok $name"
}

check_readonly_parent
check_readonly_parent_with_install
check_uncreatable_parent
exit "$fail"
