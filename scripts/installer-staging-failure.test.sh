#!/usr/bin/env bash
# Isolated shell check: when scripts/install.sh cannot finish creating its
# private staging directory it must exit nonzero, keep a preexisting
# destination byte-for-byte intact, and release the install lock — with no
# download attempted and no stage, backup, or lock sibling left beside the
# destination.
#
# PATH shims inject one staging-creation failure at a time: mktemp -d
# refusing the .<name>.install.XXXXXX template, the stage failing chmod 700,
# the staging subdirectories failing halfway, or mktemp reporting success
# for a directory that does not exist. Each shim records the exact mktemp -d
# argv (NUL-delimited, so a word-split template shows up as extra fields) and
# delegates every other call to the real tool, so the shipped installer runs
# end-to-end under env -i — no node, no network, no test-only installer
# overrides, and no real dotfiles.
# Usage: bash scripts/installer-staging-failure.test.sh [installer]
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
installer="${1:-$here/install.sh}"
[ -f "$installer" ] || { echo "missing installer: $installer" >&2; exit 1; }

real_mktemp="$(command -v mktemp || true)"
[ -n "$real_mktemp" ] || { echo "FAIL: mktemp is required" >&2; exit 1; }

# /var on macOS and CI tmpdirs can be symlinked: the installer stages beneath
# the resolved physical parent, so every expectation here is resolved too.
root="$(mktemp -d)"
root="$(cd "$root" && pwd -P)"
trap 'rm -rf "$root"' EXIT

shims="$root/shims"
mkdir -p "$shims"

# The mktemp shim records every -d argv, then applies the named seam only to
# the staging template; other mktemp calls delegate to the real tool.
cat > "$shims/mktemp" <<'EOF'
#!/bin/sh
if [ "${1:-}" = "-d" ]; then
  printf '%s\0' "$@" >> "$T_MKTEMP_LOG" || exit 1
fi
for arg do
  case "$arg" in
    *.install.XXXXXX)
      case "$T_FAIL_SEAM" in
        mktemp)
          printf 'mktemp: injected staging-directory failure\n' >&2
          exit 1
          ;;
        missing)
          printf '%s\n' "${arg%.install.XXXXXX}.install.missing-stage"
          exit 0
          ;;
      esac
      ;;
  esac
done
exec "$T_REAL_MKTEMP" "$@"
EOF

# The chmod shim fails only `chmod 700` aimed at the staging path; the lock
# owner chmod (mode 600) and every other call delegate to the real tool.
cat > "$shims/chmod" <<'EOF'
#!/bin/sh
if [ "$T_FAIL_SEAM" = chmod ] && [ "${1:-}" = '700' ]; then
  case "${2:-}" in
    *.install.*)
      printf 'chmod: injected staging-directory failure\n' >&2
      exit 1
      ;;
  esac
fi
exec /bin/chmod "$@"
EOF

# The mkdir shim reproduces mkdir's left-to-right behavior: it creates
# `download` and then fails on `candidate`, leaving a partially created stage
# tree that the cleanup trap must still remove.
cat > "$shims/mkdir" <<'EOF'
#!/bin/sh
if [ "$T_FAIL_SEAM" = mkdir ]; then
  staging=0
  for arg do
    case "$arg" in */download|*/candidate) staging=1 ;; esac
  done
  if [ "$staging" -eq 1 ]; then
    for arg do
      case "$arg" in
        */download) /bin/mkdir -m 700 "$arg" || exit 1 ;;
        */candidate)
          printf 'mkdir: injected staging-directory failure\n' >&2
          exit 1
          ;;
      esac
    done
  fi
fi
exec /bin/mkdir "$@"
EOF

# A download must never be attempted; the shim's argv would land in the log.
cat > "$shims/curl" <<'EOF'
#!/bin/sh
printf '%s\n' "$*" >> "$T_CURL_LOG"
exit 22
EOF
chmod 755 "$shims"/*

fail=0
RUN_RC=0
note()     { printf '%s\n' "$*"; }
fail_at()  { note "FAIL $1: $2"; fail=1; }
tail_err() { head -n 15 "$root/$1/err.log" | sed 's/^/    | /'; }

# run_install NAME INSTALL_DIR SEAM: one end-to-end installer run under
# env -i with the shims first on PATH. TMPDIR is a real empty directory so
# the assertions can prove nothing escaped to the system temp dir.
run_install() {
  local name="$1" install="$2" seam="$3"
  mkdir -p "$root/$name/home" "$root/$name/other tmp"
  RUN_RC=0
  env -i \
    HOME="$root/$name/home" \
    SHELL="/bin/bash" \
    PATH="$shims:/usr/bin:/bin" \
    TMPDIR="$root/$name/other tmp" \
    PHANTOM_INSTALL_DIR="$install" \
    T_FAIL_SEAM="$seam" \
    T_MKTEMP_LOG="$root/$name/mktemp.log" \
    T_CURL_LOG="$root/$name/curl.log" \
    T_REAL_MKTEMP="$real_mktemp" \
    /bin/bash "$installer" > "$root/$name/out.log" 2> "$root/$name/err.log" \
    || RUN_RC=$?
}

# expect_failed_staging NAME SEAM PARENT: the run died creating its private
# stage — nonzero exit, the failed step and the injected marker named on
# stderr, the real installer having reached the staging step, no download
# attempted, and exactly one mktemp -d call under the physical parent.
expect_failed_staging() {
  local name="$1" seam="$2" parent="$3" log="$root/$1"
  [ "$RUN_RC" != 0 ] \
    || { fail_at "$name" "installer must exit nonzero when staging creation fails"; return 1; }
  case "$seam" in
    mktemp)
      grep -qF "could not create a private staging directory in $parent" "$log/err.log" \
        || { fail_at "$name" "missing the staging-creation diagnostic"; tail_err "$name"; return 1; }
      grep -qF "mktemp: injected staging-directory failure" "$log/err.log" \
        || { fail_at "$name" "the injected mktemp failure did not fire"; tail_err "$name"; return 1; }
      ;;
    chmod)
      grep -qF "could not secure the staging directory" "$log/err.log" \
        || { fail_at "$name" "missing the staging-securing diagnostic"; tail_err "$name"; return 1; }
      grep -qF "chmod: injected staging-directory failure" "$log/err.log" \
        || { fail_at "$name" "the injected chmod failure did not fire"; tail_err "$name"; return 1; }
      ;;
    mkdir)
      grep -qF "could not create staging directories" "$log/err.log" \
        || { fail_at "$name" "missing the staging-subdirectory diagnostic"; tail_err "$name"; return 1; }
      grep -qF "mkdir: injected staging-directory failure" "$log/err.log" \
        || { fail_at "$name" "the injected mkdir failure did not fire"; tail_err "$name"; return 1; }
      ;;
    missing)
      grep -qF "could not secure the staging directory" "$log/err.log" \
        || { fail_at "$name" "missing the staging-securing diagnostic"; tail_err "$name"; return 1; }
      grep -qF "missing-stage" "$log/err.log" \
        || { fail_at "$name" "chmod did not report the absent staging directory"; tail_err "$name"; return 1; }
      ;;
  esac
  grep -qF "target: " "$log/out.log" \
    || { fail_at "$name" "the real installer did not reach the staging step"; return 1; }
  ! grep -qE "downloading|checksum" "$log/out.log" \
    || { fail_at "$name" "the installer started a download before failing"; return 1; }
  [ ! -e "$log/curl.log" ] \
    || { fail_at "$name" "curl ran even though no staging directory existed"; return 1; }
  printf '%s\0%s\0' "-d" "$parent/.bin.install.XXXXXX" | cmp -s - "$log/mktemp.log" \
    || { fail_at "$name" "mktemp -d argv was not exactly one call under the parent"; return 1; }
}

# only_entries NAME DIR EXPECTED: the directory holds exactly the whitespace-
# separated names in EXPECTED ("" means empty); nothing is left behind.
only_entries() {
  local name="$1" dir="$2" expected="$3" found
  found="$(find "$dir" -mindepth 1 -maxdepth 1 -exec basename {} \; | sort | tr '\n' ' ' | sed 's/ $//')"
  [ "$found" = "$expected" ] \
    || { fail_at "$name" "unexpected entries under $dir: [$found]"; return 1; }
}

# expect_home_and_tmp_clean NAME: the isolated HOME and TMPDIR received no
# files — staging happened (or failed) entirely beside the destination.
expect_home_and_tmp_clean() {
  local name="$1"
  only_entries "$name" "$root/$name/home" "" \
    && only_entries "$name" "$root/$name/other tmp" ""
}

# expect_destination_preserved NAME PARENT INSTALL: the preexisting
# destination kept its sentinel bytes and the parent holds only the
# destination — no stage, backup, or lock sibling remains.
expect_destination_preserved() {
  local name="$1" parent="$2" install="$3"
  [ "$(cat "$install/old-install")" = "preserve-me" ] \
    || { fail_at "$name" "the preexisting destination was disturbed"; return 1; }
  [ "$(cat "$install/nested/tool")" = "still-here" ] \
    || { fail_at "$name" "nested destination contents were disturbed"; return 1; }
  only_entries "$name" "$parent" "bin" \
    && only_entries "$name" "$install" "nested old-install" \
    && only_entries "$name" "$install/nested" "tool"
}

seed_destination() {
  mkdir -p "$1/nested"
  printf 'preserve-me\n' > "$1/old-install"
  printf 'still-here\n' > "$1/nested/tool"
}

# 1. The core contract: mktemp cannot create the private stage, a previous
#    install occupies the destination — exit nonzero and the destination
#    survives byte-for-byte with no stage, backup, or lock siblings.
check_existing_destination() {
  local name="existing-destination" parent="$root/install parent" install="$root/install parent/bin"
  seed_destination "$install"
  run_install "$name" "$install" mktemp
  if ! expect_failed_staging "$name" mktemp "$parent" \
    || ! expect_destination_preserved "$name" "$parent" "$install" \
    || ! expect_home_and_tmp_clean "$name"; then return; fi
  note "ok $name"
}

# 2. With no preexisting destination the freshly created parent ends
#    completely empty — the lock the installer briefly held is released and
#    no stage or backup sibling remains.
check_fresh_parent() {
  local name="fresh-parent" parent="$root/new parent" install="$root/new parent/bin"
  run_install "$name" "$install" mktemp
  if ! expect_failed_staging "$name" mktemp "$parent" \
    || ! only_entries "$name" "$parent" "" \
    || ! expect_home_and_tmp_clean "$name"; then return; fi
  note "ok $name"
}

# 3. mktemp created the stage but chmod cannot secure it: cleanup must
#    remove the real stage directory along with the lock, and the
#    preexisting destination stays intact.
check_unsecurable_stage() {
  local name="unsecurable-stage" parent="$root/stage parent" install="$root/stage parent/bin"
  seed_destination "$install"
  run_install "$name" "$install" chmod
  if ! expect_failed_staging "$name" chmod "$parent" \
    || ! expect_destination_preserved "$name" "$parent" "$install" \
    || ! expect_home_and_tmp_clean "$name"; then return; fi
  note "ok $name"
}

# 4. The stage exists but its subdirectories cannot all be created: cleanup
#    must remove a partially populated stage tree, not just an empty one,
#    while the preexisting destination stays intact.
check_partial_subdirs() {
  local name="partial-subdirs" parent="$root/subdir parent" install="$root/subdir parent/bin"
  seed_destination "$install"
  run_install "$name" "$install" mkdir
  if ! expect_failed_staging "$name" mkdir "$parent" \
    || ! expect_destination_preserved "$name" "$parent" "$install" \
    || ! expect_home_and_tmp_clean "$name"; then return; fi
  note "ok $name"
}

# 5. mktemp reports success for a directory that does not exist: the
#    installer must stop at the first use of the absent stage instead of
#    downloading into, or promoting from, a path that is not there, and the
#    cleanup guard for a non-directory stage_root must leave no debris.
check_missing_stage() {
  local name="missing-stage" parent="$root/empty parent" install="$root/empty parent/bin"
  seed_destination "$install"
  run_install "$name" "$install" missing
  if ! expect_failed_staging "$name" missing "$parent" \
    || ! expect_destination_preserved "$name" "$parent" "$install" \
    || ! expect_home_and_tmp_clean "$name"; then return; fi
  note "ok $name"
}

check_existing_destination
check_fresh_parent
check_unsecurable_stage
check_partial_subdirs
check_missing_stage
exit "$fail"
