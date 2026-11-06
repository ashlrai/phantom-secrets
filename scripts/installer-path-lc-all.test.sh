#!/usr/bin/env bash
# Isolated shell check: the PATH update in apps/web/public/install.sh leaves an
# unrelated `export LC_ALL` line byte-for-byte unchanged. Runs the shipped
# add_to_user_path in a throwaway HOME; no node, network, or real dotfiles.
# Usage: bash scripts/installer-path-lc-all.test.sh [installer]
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
check() { # name shell rc-relative-path
  local name="$1" shell="$2" lc='export LC_ALL=en_US.UTF-8'
  local rc="$root/$name/$3" bin="$root/$name/bin"
  mkdir -p "$(dirname "$rc")" "$bin"
  printf '# user config\n%s\nalias ll="ls -la"\n' "$lc" > "$rc"
  cp "$rc" "$root/$name.before"
  env -i HOME="$root/$name" SHELL="$shell" PATH=/usr/bin:/bin /bin/bash -c "$harness" t "$bin" >/dev/null
  # The original bytes must remain an exact prefix of the updated file ...
  local size; size="$(wc -c < "$root/$name.before" | tr -d ' ')"
  head -c "$size" "$rc" | cmp -s - "$root/$name.before" \
    || { echo "FAIL $name: existing bytes changed"; fail=1; return; }
  # ... the LC_ALL line appears exactly once, unchanged ...
  [ "$(grep -cxF "$lc" "$rc")" = 1 ] \
    || { echo "FAIL $name: LC_ALL line missing or duplicated"; fail=1; return; }
  # ... and the PATH entry really was added.
  grep -qxF '# phantom-secrets PATH' "$rc" \
    || { echo "FAIL $name: PATH block not appended"; fail=1; return; }
  echo "ok $name"
}

check bash /bin/bash .bashrc
check zsh /bin/zsh .zshrc
check fish /usr/bin/fish .config/fish/config.fish
exit "$fail"
