#!/usr/bin/env bash
# Isolated shell check: the PATH update in apps/web/public/install.sh leaves an
# unrelated shell alias byte-for-byte unchanged across the startup-file
# fallbacks — unset SHELL (bash assigns the login shell at startup), empty
# SHELL and unrecognized shells (sh, dash, tcsh land in .bashrc), and pathless
# names (zsh, fish) that basename maps to their own files. Runs the shipped
# add_to_user_path in a throwaway HOME; no node, network, or real dotfiles.
# Usage: bash scripts/installer-path-alias-fallback.test.sh [installer]
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
installer="${1:-$here/../apps/web/public/install.sh}"
root="$(mktemp -d)"
trap 'rm -rf "$root"' EXIT

# Pull the shipped function text out of the installer so the real code runs.
fn() { awk -v n="$1" '$0 ~ "^"n"\\(\\)" {p=1} p {print} p && /^}/ {exit}' "$installer"; }
harness="set -euo pipefail; umask 077
$(fn say)
$(fn file_identity)
$(fn file_link_count)
$(fn add_to_user_path)
add_to_user_path \"\$1\""

fail=0
check() { # name shell-spec ('-' = unset, '' = empty)
  local name="$1" spec="$2"
  local bin="$root/$name/bin"
  local alias=$'alias gs=\'git status -sb\'\t  '
  mkdir -p "$bin"
  local -a env_args=(HOME="$root/$name" PATH=/usr/bin:/bin)
  if [ "$spec" != '-' ]; then env_args+=("SHELL=$spec"); fi
  # Resolve the startup file exactly as add_to_user_path will: run its own
  # shell-name probe under bash in the same environment, then map it through
  # the same case. Unset SHELL means the login shell, not always bash.
  local resolved rc
  resolved="$(env -i "${env_args[@]}" /bin/bash -c 'basename "${SHELL:-bash}"')"
  case "$resolved" in
    zsh)  rc="$root/$name/.zshrc" ;;
    fish) rc="$root/$name/.config/fish/config.fish" ;;
    *)    rc="$root/$name/.bashrc" ;;
  esac
  mkdir -p "$(dirname "$rc")"
  printf '# user config\n%s\n' "$alias" > "$rc"
  cp "$rc" "$root/$name.before"
  local out
  out="$(env -i "${env_args[@]}" /bin/bash -c "$harness" t "$bin")" \
    || { echo "FAIL $name: PATH update failed"; fail=1; return; }
  # The fallback must report the startup file this case resolved to ...
  printf '%s' "$out" | grep -qF "$rc" \
    || { echo "FAIL $name: wrong startup file"; fail=1; return; }
  # ... the original bytes must remain an exact prefix of the updated file ...
  local size; size="$(wc -c < "$root/$name.before" | tr -d ' ')"
  head -c "$size" "$rc" | cmp -s - "$root/$name.before" \
    || { echo "FAIL $name: existing bytes changed"; fail=1; return; }
  # ... the alias line appears exactly once, unchanged ...
  [ "$(grep -cxF "$alias" "$rc")" = 1 ] \
    || { echo "FAIL $name: alias line missing or duplicated"; fail=1; return; }
  # ... and the PATH entry really was added.
  grep -qxF '# phantom-secrets PATH' "$rc" \
    || { echo "FAIL $name: PATH block not appended"; fail=1; return; }
  echo "ok $name"
}

check unset -
check empty ''
check sh /bin/sh
check dash /usr/bin/dash
check tcsh /bin/tcsh
check zsh-bare zsh
check fish-bare fish
exit "$fail"
