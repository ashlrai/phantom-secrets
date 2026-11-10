#!/usr/bin/env bash
# Offline check: when add_to_user_path cannot create the candidate PATH-edit
# file, it fails, leaves the user's shell configuration untouched (bytes,
# inode, mode), and removes the first temporary file (.phantom-path.before.*).
# Runs the shipped function from each installer copy in a throwaway HOME; no
# network, node, or real dotfiles.
# Usage: bash scripts/installers.test.sh [installer ...]
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ "$#" -gt 0 ]; then
  installers=("$@")
else
  installers=("$here/install.sh" "$here/../apps/web/public/install.sh")
fi
root="$(mktemp -d)"
trap 'rm -rf "$root"' EXIT
real_mktemp="$(command -v mktemp)"
fail=0

# Pull the shipped function text out of the installer so the real code runs.
fn() { awk -v n="$2" '$0 ~ "^"n"\\(\\)" {p=1} p {print} p && /^}/ {exit}' "$1"; }

run_case() { # label installer
  local label="$1" installer="$2" case_dir="$root/$1"
  local home="$case_dir/home" shims="$case_dir/shims" bin="$case_dir/bin"
  local rc="$home/.bashrc" log="$case_dir/mktemp.log" harness
  mkdir -p "$home" "$shims" "$bin"
  harness="set -euo pipefail; umask 077
$(fn "$installer" say)
$(fn "$installer" file_identity)
$(fn "$installer" file_link_count)
$(fn "$installer" add_to_user_path)
add_to_user_path \"\$1\""

  printf '# existing configuration\nexport EXAMPLE=unchanged\n' > "$rc"
  chmod 600 "$rc"
  cp -p "$rc" "$case_dir/rc.before"
  local ino_before mode_before
  ino_before="$(ls -i "$rc" | awk '{print $1}')"
  mode_before="$(ls -l "$rc" | awk '{print $1}')"

  # mktemp shim: record every template; fail only for the candidate file.
  cat > "$shims/mktemp" <<SHIM
#!/bin/sh
printf '%s\n' "\$*" >> "$log"
case "\$1" in *.phantom-path.candidate.*) exit 1 ;; esac
exec "$real_mktemp" "\$@"
SHIM
  chmod 755 "$shims/mktemp"

  local status=0 out
  out="$(env -i HOME="$home" SHELL=/bin/bash PATH="$shims:/usr/bin:/bin" \
    /bin/bash -c "$harness" t "$bin" </dev/null 2>&1)" || status=$?

  [ "$status" -ne 0 ] \
    || { echo "FAIL $label: add_to_user_path succeeded despite candidate failure"; fail=1; return; }
  # The failure must come from the candidate step, after the first file was made.
  grep -q '\.phantom-path\.before\.' "$log" \
    && grep -q '\.phantom-path\.candidate\.' "$log" \
    || { echo "FAIL $label: candidate creation was not reached"; fail=1; return; }
  cmp -s "$rc" "$case_dir/rc.before" \
    || { echo "FAIL $label: shell configuration changed"; fail=1; return; }
  [ "$(ls -i "$rc" | awk '{print $1}')" = "$ino_before" ] \
    && [ "$(ls -l "$rc" | awk '{print $1}')" = "$mode_before" ] \
    || { echo "FAIL $label: shell configuration was replaced"; fail=1; return; }
  [ "$(ls -A "$home")" = ".bashrc" ] \
    || { echo "FAIL $label: temporary files remain: $(ls -A "$home" | tr '\n' ' ')"; fail=1; return; }
  [ -z "$out" ] || [ "${out#*added }" = "$out" ] \
    || { echo "FAIL $label: reported a PATH update"; fail=1; return; }
  echo "ok $label"
}

# Exercise the complete installer with a synthetic architecture, offline.
run_unsupported_arch_case() {
  local label="$1" installer="$2" case_dir="$root/$1"
  local home="$case_dir/home" shims="$case_dir/shims" dest="$case_dir/dest"
  mkdir -p "$home" "$shims"
  cat > "$shims/uname" <<'SHIM'
#!/bin/sh
case "$1" in
  -s) printf '%s\n' Linux ;;
  -m) printf '%s\n' unsupported-test-processor ;;
  *) exit 1 ;;
esac
SHIM
  cat > "$shims/curl" <<'SHIM'
#!/bin/sh
printf '%s\n' 'unexpected network attempt' >&2
exit 99
SHIM
  chmod 755 "$shims/uname" "$shims/curl"
  local status=0 out
  out="$(env -i HOME="$home" PATH="$shims:/usr/bin:/bin" \
    PHANTOM_INSTALL_DIR="$dest" /bin/bash "$installer" </dev/null 2>&1)" || status=$?
  [ "$status" -ne 0 ] \
    || { echo "FAIL $label: installer succeeded"; fail=1; return; }
  [[ "$out" == *"unsupported arch: unsupported-test-processor"* ]] \
    || { echo "FAIL $label: missing clear architecture error"; fail=1; return; }
  [[ "$out" != *"unexpected network attempt"* ]] \
    || { echo "FAIL $label: attempted network access"; fail=1; return; }
  [ ! -e "$dest/phantom" ] && [ ! -e "$dest/phantom-mcp" ] \
    || { echo "FAIL $label: created a destination executable"; fail=1; return; }
  echo "ok $label"
}

n=0
for installer in "${installers[@]}"; do
  [ -f "$installer" ] || { echo "FAIL missing installer: $installer"; exit 1; }
  n=$((n + 1))
  run_case "candidate-create-failure-$n" "$installer"
  run_unsupported_arch_case "unsupported-arch-$n" "$installer"
done
exit "$fail"
