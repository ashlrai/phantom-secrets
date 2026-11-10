#!/usr/bin/env bash
# Offline check: when add_to_user_path cannot create the candidate PATH-edit
# file, it fails, leaves the user's shell configuration untouched (bytes,
# inode, mode), and removes the first temporary file (.phantom-path.before.*).
# Also reject incomplete release archives and verify staging cleanup.
# Runs each installer copy in a throwaway HOME; no network, node, or real dotfiles.
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

run_missing_executable_case() { # label installer missing present
  local label="$1" installer="$2" missing="$3" present="$4"
  local case_dir="$root/$1" home="$root/$1/home" shims="$root/$1/shims"
  local release="$root/$1/release" payload="$root/$1/payload" stage_log="$root/$1/stage.log"
  local os arch archive digest status=0 out stage
  case "$(uname -s)" in Darwin) os=apple-darwin ;; Linux) os=unknown-linux-gnu ;; *) echo "FAIL $label: unsupported OS"; fail=1; return ;; esac
  case "$(uname -m)" in x86_64|amd64) arch=x86_64 ;; arm64|aarch64) arch=aarch64 ;; *) echo "FAIL $label: unsupported architecture"; fail=1; return ;; esac
  archive="phantom-${arch}-${os}.tar.gz"
  mkdir -p "$home/.phantom-secrets/bin" "$shims" "$release" "$payload"
  printf 'existing installation\n' > "$home/.phantom-secrets/bin/marker"
  printf '#!/bin/sh\nexit 0\n' > "$payload/$present"
  chmod 755 "$payload/$present"
  tar -czf "$release/$archive" -C "$payload" "$present"
  if command -v sha256sum >/dev/null 2>&1; then
    digest="$(sha256sum "$release/$archive" | awk '{print $1}')"
  else
    digest="$(shasum -a 256 "$release/$archive" | awk '{print $1}')"
  fi
  printf '%s  %s\n' "$digest" "$archive" > "$release/$archive.sha256"
  cat > "$shims/mktemp" <<SHIM
#!/bin/sh
result="\$("$real_mktemp" "\$@")" || exit \$?
printf '%s\n' "\$result" >> "$stage_log"
printf '%s\n' "\$result"
SHIM
  printf '#!/bin/sh\nexit 99\n' > "$shims/curl"
  chmod 755 "$shims/mktemp" "$shims/curl"
  out="$(env -i HOME="$home" PATH="$shims:/usr/bin:/bin" \
    PHANTOM_TEST_ALLOW_INSTALLER_OVERRIDES=1 PHANTOM_TEST_LOCAL_RELEASE_DIR="$release" \
    /bin/bash "$installer" </dev/null 2>&1)" || status=$?
  [ "$status" -ne 0 ] \
    || { echo "FAIL $label: incomplete archive was accepted"; fail=1; return; }
  [[ "$out" == *"checksum verified"* && "$out" == *"release archive must contain exactly phantom and phantom-mcp"* ]] \
    || { echo "FAIL $label: did not report the missing $missing executable after checksum verification"; fail=1; return; }
  [ -f "$stage_log" ] && [ "$(wc -l < "$stage_log" | tr -d '[:space:]')" = 1 ] \
    || { echo "FAIL $label: staging creation was not recorded exactly once"; fail=1; return; }
  stage="$(cat "$stage_log")"
  [ ! -e "$stage" ] && [ ! -L "$stage" ] \
    || { echo "FAIL $label: staging directory remains"; fail=1; return; }
  [ "$(cat "$home/.phantom-secrets/bin/marker")" = 'existing installation' ] \
    || { echo "FAIL $label: existing installation changed"; fail=1; return; }
  echo "ok $label"
}

n=0
for installer in "${installers[@]}"; do
  [ -f "$installer" ] || { echo "FAIL missing installer: $installer"; exit 1; }
  n=$((n + 1))
  run_case "candidate-create-failure-$n" "$installer"
  run_missing_executable_case "missing-phantom-$n" "$installer" phantom phantom-mcp
  run_missing_executable_case "missing-phantom-mcp-$n" "$installer" phantom-mcp phantom
done
exit "$fail"
