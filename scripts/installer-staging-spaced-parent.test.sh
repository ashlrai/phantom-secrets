#!/usr/bin/env bash
# Isolated shell check: scripts/install.sh keeps its private staging directory
# beneath an installation parent containing spaces — when the installer creates
# that parent itself, when the spaced parent is only reached through a symlink
# (staging lands on the resolved physical path, here carrying an apostrophe
# too), and when a previous install already sits inside that parent.
#
# The offline fixture ships a deliberately wrong checksum, so the installer
# stops right after it created and populated its staging directory — the
# deterministic seam that proves where staging landed on hosts that refuse to
# run stub binaries named `phantom`. PATH shims record the exact mktemp -d
# argv (NUL-delimited, so a word-split template shows up as extra fields) and
# the staged path the installer checksums; the shipped installer runs
# end-to-end under env -i. No node, network, or real dotfiles.
# Usage: bash scripts/installer-staging-spaced-parent.test.sh [installer]
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
installer="${1:-$here/install.sh}"
[ -f "$installer" ] || { echo "missing installer: $installer" >&2; exit 1; }

case "$(uname -s)" in
  Darwin) os="apple-darwin" ;;
  Linux)  os="unknown-linux-gnu" ;;
  *) echo "FAIL: unsupported test OS" >&2; exit 1 ;;
esac
case "$(uname -m)" in
  x86_64|amd64)  arch="x86_64" ;;
  arm64|aarch64) arch="aarch64" ;;
  *) echo "FAIL: unsupported test arch" >&2; exit 1 ;;
esac
archive="phantom-${arch}-${os}.tar.gz"

real_mktemp="$(command -v mktemp || true)"
real_sha256sum="$(command -v sha256sum || true)"
real_shasum="$(command -v shasum || true)"
[ -n "$real_mktemp" ] || { echo "FAIL: mktemp is required" >&2; exit 1; }
[ -n "$real_sha256sum$real_shasum" ] || { echo "FAIL: sha256sum or shasum is required" >&2; exit 1; }

# /var on macOS and CI tmpdirs can be symlinked: the installer stages beneath
# the physical parent, so every expectation here is written in resolved paths.
root="$(mktemp -d)"
root="$(cd "$root" && pwd -P)"
trap 'rm -rf "$root"' EXIT

fixture="$root/release fixture"
payload="$root/payload"
shims="$root/shims"
mkdir -p "$fixture" "$payload" "$shims"

printf 'x\n' > "$payload/phantom"
printf 'x\n' > "$payload/phantom-mcp"
COPYFILE_DISABLE=1 tar -czf "$fixture/$archive" -C "$payload" phantom phantom-mcp
printf '%s  %s\n' "0000000000000000000000000000000000000000000000000000000000000000" \
  "$archive" > "$fixture/$archive.sha256"

# The mktemp shim records every -d argv plus each created path and its
# creation mode; the hash shims record the path the installer checksums, then
# delegate to the real tool so the verified digest is honest.
cat > "$shims/mktemp" <<'EOF'
#!/bin/sh
if [ "${1:-}" = "-d" ]; then
  printf '%s\0' "$@" >> "$T_MKTEMP_LOG" || exit 1
fi
created="$("$T_REAL_MKTEMP" "$@")" || exit $?
if [ "${1:-}" = "-d" ]; then
  printf '%s\n' "$created" >> "$T_CREATED_LOG" || exit 1
  ls -ld "$created" | cut -c1-10 >> "$T_CREATED_LOG" || exit 1
fi
printf '%s\n' "$created"
EOF
for tool in sha256sum shasum; do
  cat > "$shims/$tool" <<'EOF'
#!/bin/sh
last=""
for last in "$@"; do :; done
[ -n "$last" ] || exit 1
printf '%s\n' "$last" >> "$T_HASH_LOG" || exit 1
if [ -n "$T_REAL_SHA256SUM" ]; then
  exec "$T_REAL_SHA256SUM" "$last"
fi
exec "$T_REAL_SHASUM" -a 256 "$last"
EOF
done
chmod 755 "$shims"/*

fail=0
RUN_RC=0
note()     { printf '%s\n' "$*"; }
fail_at()  { note "FAIL $1: $2"; fail=1; }
tail_err() { head -n 15 "$root/$1/err.log" | sed 's/^/    | /'; }

# run_install NAME INSTALL_DIR [EXTRA_ENV...]: one end-to-end installer run
# under env -i with the shims first on PATH. TMPDIR is a real empty directory
# so the assertions can prove staging never leaves the spaced parent for the
# system temp dir.
run_install() {
  local name="$1" install="$2"
  shift 2
  mkdir -p "$root/$name/home" "$root/$name/other tmp"
  RUN_RC=0
  env -i \
    HOME="$root/$name/home" \
    SHELL="/bin/bash" \
    PATH="$shims:/usr/bin:/bin" \
    TMPDIR="$root/$name/other tmp" \
    PHANTOM_INSTALL_DIR="$install" \
    PHANTOM_TEST_ALLOW_INSTALLER_OVERRIDES="1" \
    PHANTOM_TEST_LOCAL_RELEASE_DIR="$fixture" \
    PHANTOM_TAG="v1.2.3" \
    T_MKTEMP_LOG="$root/$name/mktemp.log" \
    T_CREATED_LOG="$root/$name/created.log" \
    T_HASH_LOG="$root/$name/hash.log" \
    T_REAL_MKTEMP="$real_mktemp" \
    T_REAL_SHA256SUM="$real_sha256sum" \
    T_REAL_SHASUM="$real_shasum" \
    "$@" \
    /bin/bash "$installer" > "$root/$name/out.log" 2> "$root/$name/err.log" \
    || RUN_RC=$?
}

# expect_failed_checksum NAME: the fixture checksum drove the installer to its
# deterministic stop after it staged and hashed the download.
expect_failed_checksum() {
  local name="$1"
  [ "$RUN_RC" != 0 ] \
    || { fail_at "$name" "the stub checksum must fail the install"; return 1; }
  grep -qF "SHA-256 mismatch" "$root/$name/err.log" \
    || { fail_at "$name" "the installer did not reach the staged checksum"; tail_err "$name"; return 1; }
  grep -qF "downloading $archive" "$root/$name/out.log" \
    || { fail_at "$name" "the installer did not stage the download"; return 1; }
}

# expect_stage NAME PHYSICAL_PARENT: the installer asked mktemp for exactly
# one -d directory whose template reached it as a single un-split path under
# the spaced parent; one owner-private staging dir was created there, the
# download was hashed inside it, and it was removed before exit.
expect_stage() {
  local name="$1" parent="$2" log created mode
  log="$root/$name"
  printf '%s\0%s\0' "-d" "$parent/.bin.install.XXXXXX" | cmp -s - "$log/mktemp.log" \
    || { fail_at "$name" "mktemp -d argv was not one path under the spaced parent"; return 1; }
  [ -f "$log/created.log" ] \
    && [ "$(wc -l < "$log/created.log" | tr -d ' ')" = "2" ] \
    || { fail_at "$name" "expected exactly one recorded staging directory"; return 1; }
  created="$(sed -n '1p' "$log/created.log")"
  mode="$(sed -n '2p' "$log/created.log")"
  [ "$(dirname "$created")" = "$parent" ] \
    || { fail_at "$name" "staging was not a direct child of the spaced parent"; return 1; }
  case "$(basename "$created")" in
    .bin.install.*) ;;
    *) fail_at "$name" "staging lost its .bin.install. prefix: $created"; return 1 ;;
  esac
  [ "$mode" = "drwx------" ] \
    || { fail_at "$name" "staging was not owner-private: $mode"; return 1; }
  [ -f "$log/hash.log" ] \
    && [ "$(cat "$log/hash.log")" = "$created/download/$archive" ] \
    || { fail_at "$name" "the archive was not hashed inside the staged tree"; return 1; }
  [ ! -e "$created" ] \
    || { fail_at "$name" "staging was left behind: $created"; return 1; }
}

# only_entries NAME DIR EXPECTED: the directory holds exactly the whitespace-
# separated names in EXPECTED ("" means empty); nothing is left behind.
only_entries() {
  local name="$1" dir="$2" expected="$3" found
  found="$(find "$dir" -mindepth 1 -maxdepth 1 -exec basename {} \; | sort | tr '\n' ' ' | sed 's/ $//')"
  [ "$found" = "$expected" ] \
    || { fail_at "$name" "unexpected entries under $dir: [$found]"; return 1; }
}

# 1. The spaced parent does not exist yet: the installer must mkdir -p it,
#    resolve it with pwd -P, and stage under that exact path — never under
#    TMPDIR, which points at another empty directory.
check_new_parent() {
  local name="new-parent" parent="$root/install parent" install="$root/install parent/bin"
  run_install "$name" "$install"
  if ! expect_failed_checksum "$name" || ! expect_stage "$name" "$parent"; then return; fi
  if ! only_entries "$name" "$parent" "" \
    || ! only_entries "$name" "$root/$name/home" "" \
    || ! only_entries "$name" "$root/$name/other tmp" ""; then return; fi
  [ ! -e "$root/install" ] \
    || { fail_at "$name" "a word-split prefix appeared beside the spaced parent"; return; }
  note "ok $name"
}

# 2. The spaced parent is only reachable through a symlink: staging and the
#    whole tree land on the resolved physical path — here carrying an
#    apostrophe too — while the link itself is left alone.
check_link_parent() {
  local name="link-parent" parent="$root/owner's install" link="$root/install link" install="$root/install link/bin"
  mkdir -p "$parent"
  ln -s "$parent" "$link"
  run_install "$name" "$install"
  if ! expect_failed_checksum "$name" || ! expect_stage "$name" "$parent"; then return; fi
  [ -L "$link" ] \
    || { fail_at "$name" "the parent symlink was replaced"; return; }
  if ! only_entries "$name" "$parent" "" \
    || ! only_entries "$name" "$root/$name/other tmp" ""; then return; fi
  [ ! -e "$root/install" ] && [ ! -e "$root/owner's" ] \
    || { fail_at "$name" "a word-split prefix appeared beside the spaced parent"; return; }
  note "ok $name"
}

# 3. The spaced parent and a previous install already exist: the staged
#    failure must not disturb the install, and the parent keeps only the
#    previous bin — no staging, backup, or lock siblings remain.
check_existing() {
  local name="existing" parent="$root/rollback parent" install="$root/rollback parent/bin"
  mkdir -p "$install"
  printf 'preserve-me\n' > "$install/old-install"
  run_install "$name" "$install"
  if ! expect_failed_checksum "$name" || ! expect_stage "$name" "$parent"; then return; fi
  [ "$(cat "$install/old-install")" = "preserve-me" ] \
    || { fail_at "$name" "previous install was disturbed"; return; }
  if ! only_entries "$name" "$parent" "bin" \
    || ! only_entries "$name" "$install" "old-install" \
    || ! only_entries "$name" "$root/$name/other tmp" ""; then return; fi
  note "ok $name"
}

check_new_parent
check_link_parent
check_existing
exit "$fail"
