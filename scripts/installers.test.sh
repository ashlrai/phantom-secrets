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

run_spaced_install() {
  local label="$1" installer="$2" dir="$root/$1" os arch archive digest
  local home="$root/$1/home" install="$root/$1/install parent/phantom bin"
  mkdir -p "$home" "$dir/release" "$dir/payload"
  case "$(uname -s)" in Darwin) os=apple-darwin ;; Linux) os=unknown-linux-gnu ;; *) echo "FAIL $label: unsupported OS"; fail=1; return ;; esac
  case "$(uname -m)" in x86_64|amd64) arch=x86_64 ;; arm64|aarch64) arch=aarch64 ;; *) echo "FAIL $label: unsupported architecture"; fail=1; return ;; esac
  archive="phantom-$arch-$os.tar.gz"
  printf '%s\n' '#!/bin/sh' 'printf "%s 1.2.3\n" "$(basename "$0")"' > "$dir/payload/phantom"
  cp "$dir/payload/phantom" "$dir/payload/phantom-mcp"
  chmod 755 "$dir/payload/phantom" "$dir/payload/phantom-mcp"
  COPYFILE_DISABLE=1 tar -czf "$dir/release/$archive" -C "$dir/payload" phantom phantom-mcp
  if command -v sha256sum >/dev/null 2>&1; then
    digest="$(sha256sum "$dir/release/$archive" | awk '{print $1}')"
  else
    digest="$(shasum -a 256 "$dir/release/$archive" | awk '{print $1}')"
  fi
  printf '%s  %s\n' "$digest" "$archive" > "$dir/release/$archive.sha256"
  if ! env -i HOME="$home" SHELL=/bin/bash PATH=/usr/bin:/bin \
    PHANTOM_INSTALL_DIR="$install" PHANTOM_TEST_ALLOW_INSTALLER_OVERRIDES=1 \
    PHANTOM_TEST_LOCAL_RELEASE_DIR="$dir/release" PHANTOM_TAG=v1.2.3 \
    /bin/bash "$installer" > "$dir/output" 2>&1; then
    echo "FAIL $label: installer failed"; cat "$dir/output"; fail=1; return
  fi
  if ! cmp -s "$dir/payload/phantom" "$install/phantom" || \
     ! cmp -s "$dir/payload/phantom-mcp" "$install/phantom-mcp" || \
     [ ! -f "$install/.phantom-install-source.json" ]; then
    echo "FAIL $label: installed files missing or incorrect"; fail=1; return
  fi
  if [ -n "$(find "$dir/install parent" -maxdepth 1 -name '.phantom bin.install.*' -print)" ]; then
    echo "FAIL $label: staging directory remains"; fail=1; return
  fi
  echo "ok $label"
}

n=0
for installer in "${installers[@]}"; do
  [ -f "$installer" ] || { echo "FAIL missing installer: $installer"; exit 1; }
  n=$((n + 1))
  run_case "candidate-create-failure-$n" "$installer"
  run_spaced_install "spaced-install-$n" "$installer"
done
exit "$fail"
