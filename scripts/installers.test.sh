#!/usr/bin/env bash
# Offline checks for preserving existing shell configuration and for when
# add_to_user_path cannot create the candidate PATH-edit
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

run_preservation_case() { # label installer shell rc-relative-path
  local label="$1" installer="$2" shell="$3" rc_rel="$4"
  local case_dir="$root/$1" home="$root/$1/home" bin="$root/$1/bin"
  local rc="$root/$1/home/$4" harness
  mkdir -p "$(dirname "$rc")" "$bin"
  printf '# unrelated settings\nexport EDITOR=vi\nalias ll="ls -la"\n' > "$rc"
  cp "$rc" "$case_dir/expected"
  if [ "$shell" = fish ]; then
    printf '\n# phantom-secrets PATH\nset -gx PATH "%s" $PATH\n' "$bin" >> "$case_dir/expected"
  else
    printf '\n# phantom-secrets PATH\nexport PATH="%s:$PATH"\n' "$bin" >> "$case_dir/expected"
  fi
  harness="set -euo pipefail; umask 077
$(fn "$installer" say)
$(fn "$installer" file_identity)
$(fn "$installer" file_link_count)
$(fn "$installer" add_to_user_path)
add_to_user_path \"\$1\"
add_to_user_path \"\$1\""
  if ! env -i HOME="$home" SHELL="/bin/$shell" PATH=/usr/bin:/bin \
    /bin/bash -c "$harness" t "$bin" </dev/null >/dev/null; then
    echo "FAIL $label: PATH setup failed"; fail=1; return
  fi
  cmp -s "$rc" "$case_dir/expected" \
    || { echo "FAIL $label: existing content or PATH block differs"; fail=1; return; }
  echo "ok $label"
}

n=0
for installer in "${installers[@]}"; do
  [ -f "$installer" ] || { echo "FAIL missing installer: $installer"; exit 1; }
  n=$((n + 1))
  run_case "candidate-create-failure-$n" "$installer"
  run_preservation_case "preserve-bash-$n" "$installer" bash .bashrc
  run_preservation_case "preserve-zsh-$n" "$installer" zsh .zshrc
  run_preservation_case "preserve-fish-$n" "$installer" fish .config/fish/config.fish
done
exit "$fail"
