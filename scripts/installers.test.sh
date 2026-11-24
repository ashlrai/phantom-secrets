#!/usr/bin/env bash
# Offline checks for each installer copy, in a throwaway HOME. No network,
# node, or real dotfiles.
# - add_to_user_path fails when the candidate PATH file cannot be created,
#   leaves the shell configuration untouched (bytes, inode, mode), and removes
#   the first temporary file (.phantom-path.before.*).
# - PATH updates succeed when the rc directory contains spaces, stay idempotent
#   across a second run, and preserve existing bash, zsh, and fish settings.
# - An unsupported OS or architecture fails before any download or install.
# - A local release installs into a destination whose path contains spaces,
#   replaces an existing executable, rejects an incomplete archive, and removes
#   staging after an extraction failure.
# - installer-staging-failure.test.sh runs against each installer copy.
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

run_spaces_case() { # label installer
  local label="$1" installer="$2" case_dir="$root/$1"
  local home="$case_dir/home with spaces" bin="$case_dir/bin with spaces"
  local rc="$home/.bashrc" harness status=0
  mkdir -p "$home" "$bin"
  printf '# existing configuration\n' > "$rc"
  harness="set -euo pipefail; umask 077
$(fn "$installer" say)
$(fn "$installer" file_identity)
$(fn "$installer" file_link_count)
$(fn "$installer" add_to_user_path)
add_to_user_path \"\$1\""

  env -i HOME="$home" SHELL=/bin/bash PATH=/usr/bin:/bin \
    /bin/bash -c "$harness" t "$bin" </dev/null >/dev/null 2>&1 || status=$?
  [ "$status" -eq 0 ] \
    || { echo "FAIL $label: PATH update failed"; fail=1; return; }
  printf '# existing configuration\n\n# phantom-secrets PATH\nexport PATH="%s:$PATH"\n' "$bin" > "$case_dir/expected"
  cmp -s "$rc" "$case_dir/expected" \
    || { echo "FAIL $label: intended rc file has unexpected contents"; fail=1; return; }
  [ "$(ls -A "$home")" = ".bashrc" ] \
    || { echo "FAIL $label: temporary files remain in rc directory"; fail=1; return; }
  echo "ok $label"
}

run_unsupported_os() { # label installer
  local label="$1" installer="$2" case_dir="$root/$1"
  local home="$case_dir/home" shims="$case_dir/shims" destination="$case_dir/bin/phantom"
  mkdir -p "$home" "$shims"
  cat > "$shims/uname" <<'SHIM'
#!/bin/sh
case "$1" in -s) echo FreeBSD ;; -m) echo x86_64 ;; *) exit 1 ;; esac
SHIM
  cat > "$shims/curl" <<SHIM
#!/bin/sh
touch "$case_dir/network-attempt"
exit 1
SHIM
  chmod 755 "$shims/uname" "$shims/curl"
  local status=0 out
  out="$(env -i HOME="$home" PATH="$shims:/usr/bin:/bin" \
    PHANTOM_INSTALL_DIR="$case_dir/bin" /bin/bash "$installer" </dev/null 2>&1)" || status=$?
  [ "$status" -ne 0 ] && [[ "$out" == *"unsupported OS: FreeBSD"* ]] \
    && [ ! -e "$destination" ] && [ ! -e "$case_dir/network-attempt" ] \
    || { echo "FAIL $label: unsupported OS was not rejected before installation or download"; fail=1; return; }
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

run_repeat_case() { # label installer shell rc-relative-path
  local label="$1" installer="$2" shell="$3"
  local case_dir="$root/$1" home="$root/$1/home" bin="$root/$1/bin"
  local rc="$root/$1/home/$4" harness line
  mkdir -p "$home" "$bin" "$(dirname "$rc")"
  printf '# existing configuration\n' > "$rc"
  case "$shell" in
    fish) line="set -gx PATH \"$bin\" \$PATH" ;;
    *) line="export PATH=\"$bin:\$PATH\"" ;;
  esac
  printf '# existing configuration\n\n# phantom-secrets PATH\n%s\n' "$line" > "$case_dir/expected"
  harness="set -euo pipefail; umask 077
$(fn "$installer" say)
$(fn "$installer" file_identity)
$(fn "$installer" file_link_count)
$(fn "$installer" add_to_user_path)
add_to_user_path \"\$1\""

  local run
  for run in 1 2; do
    if ! env -i HOME="$home" SHELL="/bin/$shell" PATH=/usr/bin:/bin \
      /bin/bash -c "$harness" t "$bin" </dev/null >/dev/null; then
      echo "FAIL $label: PATH setup failed on run $run"; fail=1; return
    fi
    if ! cmp -s "$rc" "$case_dir/expected"; then
      echo "FAIL $label: unexpected PATH configuration after run $run"; fail=1; return
    fi
  done
  echo "ok $label"
}

run_space_case() {
  local label="$1" installer="$2" case_dir="$root/$1"
  local home="$root/$1/home" fixture="$root/$1/release" shims="$root/$1/shims"
  local dest="$root/$1/install directory/bin with spaces" target archive product
  mkdir -p "$home" "$fixture/files" "$shims"
  case "$(uname -s)" in Darwin) target=apple-darwin ;; Linux) target=unknown-linux-gnu ;; *) echo "FAIL $label: unsupported OS"; fail=1; return ;; esac
  case "$(uname -m)" in x86_64|amd64) target="x86_64-$target" ;; arm64|aarch64) target="aarch64-$target" ;; *) echo "FAIL $label: unsupported architecture"; fail=1; return ;; esac
  archive="phantom-$target.tar.gz"
  for product in phantom phantom-mcp; do
    printf '#!/bin/sh\nprintf "%%s\\n" "%s 1.2.3"\n' "$product" > "$fixture/files/$product"
    chmod +x "$fixture/files/$product"
  done
  tar -czf "$fixture/$archive" -C "$fixture/files" phantom phantom-mcp
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$fixture/$archive" | awk -v name="$archive" '{print $1 "  " name}' > "$fixture/$archive.sha256"
  else
    shasum -a 256 "$fixture/$archive" | awk -v name="$archive" '{print $1 "  " name}' > "$fixture/$archive.sha256"
  fi
  printf '#!/bin/sh\ntouch "%s"\nexit 1\n' "$case_dir/network-called" > "$shims/curl"
  chmod +x "$shims/curl"
  if ! env -i HOME="$home" SHELL=/bin/bash PATH="$shims:/usr/bin:/bin" \
    PHANTOM_INSTALL_DIR="$dest" PHANTOM_TEST_ALLOW_INSTALLER_OVERRIDES=1 \
    PHANTOM_TEST_LOCAL_RELEASE_DIR="$fixture" PHANTOM_TAG=v1.2.3 \
    /bin/bash "$installer" > "$case_dir/output" 2>&1; then
    echo "FAIL $label: installer failed"; fail=1; return
  fi
  for product in phantom phantom-mcp; do
    if [ ! -x "$dest/$product" ] || [ "$("$dest/$product" --version)" != "$product 1.2.3" ]; then
      echo "FAIL $label: $product missing or incorrect"; fail=1; return
    fi
  done
  if [ -e "$case_dir/network-called" ]; then
    echo "FAIL $label: network command invoked"; fail=1; return
  fi
  echo "ok $label"
}

run_replacement_case() { # label installer
  local label="$1" installer="$2" case_dir="$root/$1"
  local home="$case_dir/home" bin="$case_dir/home/.phantom-secrets/bin"
  local fixture="$case_dir/fixture" payload="$case_dir/payload" target archive digest product
  mkdir -p "$home" "$bin" "$fixture" "$payload"
  printf '#!/bin/sh\nprintf "old executable\\n"\n' > "$bin/phantom"
  chmod 755 "$bin/phantom"
  for product in phantom phantom-mcp; do
    printf '#!/bin/sh\n[ "$1" = --version ] || exit 2\nprintf "%s 1.2.3\\n"\n' "$product" > "$payload/$product"
    chmod 755 "$payload/$product"
  done
  case "$(uname -s)" in Darwin) target=apple-darwin ;; Linux) target=unknown-linux-gnu ;; *) echo "FAIL $label: unsupported OS"; fail=1; return ;; esac
  case "$(uname -m)" in x86_64|amd64) target="x86_64-$target" ;; arm64|aarch64) target="aarch64-$target" ;; *) echo "FAIL $label: unsupported architecture"; fail=1; return ;; esac
  archive="phantom-$target.tar.gz"
  tar -czf "$fixture/$archive" -C "$payload" phantom phantom-mcp
  if command -v sha256sum >/dev/null 2>&1; then
    digest="$(sha256sum "$fixture/$archive" | awk '{print $1}')"
  else
    digest="$(shasum -a 256 "$fixture/$archive" | awk '{print $1}')"
  fi
  printf '%s  %s\n' "$digest" "$archive" > "$fixture/$archive.sha256"
  if ! env -i HOME="$home" PATH="$bin:/usr/bin:/bin" SHELL=/bin/bash \
    PHANTOM_TEST_ALLOW_INSTALLER_OVERRIDES=1 PHANTOM_TAG=v1.2.3 \
    PHANTOM_TEST_LOCAL_RELEASE_DIR="$fixture" /bin/bash "$installer" > "$case_dir/install.log" 2>&1; then
    echo "FAIL $label: installer failed"; fail=1; return
  fi
  for product in phantom phantom-mcp; do
    if [ ! -x "$bin/$product" ] || [ "$("$bin/$product" --version)" != "$product 1.2.3" ]; then
      echo "FAIL $label: installed $product is not the expected executable"; fail=1; return
    fi
  done
  echo "ok $label"
}

run_extraction_failure() { # label installer
  local label="$1" installer="$2" case_dir="$root/$1"
  local home="$case_dir/home" shims="$case_dir/shims" fixture="$case_dir/fixture"
  local parent="$case_dir/live" payload="$case_dir/payload" archive digest status=0 out
  local os arch real_tar
  case "$(uname -s)" in Darwin) os=apple-darwin ;; Linux) os=unknown-linux-gnu ;; *) echo "FAIL $label: unsupported OS"; fail=1; return ;; esac
  case "$(uname -m)" in x86_64|amd64) arch=x86_64 ;; arm64|aarch64) arch=aarch64 ;; *) echo "FAIL $label: unsupported architecture"; fail=1; return ;; esac
  mkdir -p "$home" "$shims" "$fixture" "$parent/bin" "$payload"
  printf 'preserve me\n' > "$parent/bin/old-install"
  printf 'fixture\n' > "$payload/phantom"
  printf 'fixture\n' > "$payload/phantom-mcp"
  archive="phantom-$arch-$os.tar.gz"
  real_tar="$(command -v tar)"
  "$real_tar" -czf "$fixture/$archive" -C "$payload" phantom phantom-mcp
  if command -v sha256sum >/dev/null 2>&1; then
    digest="$(sha256sum "$fixture/$archive" | awk '{print $1}')"
  else
    digest="$(shasum -a 256 "$fixture/$archive" | awk '{print $1}')"
  fi
  printf '%s  %s\n' "$digest" "$archive" > "$fixture/$archive.sha256"
  cat > "$shims/tar" <<SHIM
#!/bin/sh
if [ "\$1" = --no-same-owner ]; then
  "$real_tar" "\$@" || exit 1
  printf '%s\n' "\$5" > "$case_dir/extracted-to"
  exit 42
fi
exec "$real_tar" "\$@"
SHIM
  chmod 755 "$shims/tar"
  out="$(env -i HOME="$home" PATH="$shims:/usr/bin:/bin" \
    PHANTOM_INSTALL_DIR="$parent/bin" PHANTOM_TEST_ALLOW_INSTALLER_OVERRIDES=1 \
    PHANTOM_TEST_LOCAL_RELEASE_DIR="$fixture" PHANTOM_TAG=v1.2.3 \
    /bin/bash "$installer" </dev/null 2>&1)" || status=$?
  [ "$status" -ne 0 ] && [[ "$out" == *'could not extract release archive'* ]] \
    || { echo "FAIL $label: expected extraction failure"; fail=1; return; }
  [ -s "$case_dir/extracted-to" ] \
    || { echo "FAIL $label: extraction was not reached"; fail=1; return; }
  [ ! -e "$(cat "$case_dir/extracted-to")" ] \
    && [ "$(ls -A "$parent")" = bin ] \
    && [ "$(cat "$parent/bin/old-install")" = 'preserve me' ] \
    || { echo "FAIL $label: staging or lock remains, or existing install changed"; fail=1; return; }
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
  run_spaces_case "rc-parent-spaces-$n" "$installer"
  run_unsupported_os "unsupported-os-$n" "$installer"
  run_unsupported_arch_case "unsupported-arch-$n" "$installer"
  run_spaced_install "spaced-install-$n" "$installer"
  run_repeat_case "repeat-bash-$n" "$installer" bash .bashrc
  run_repeat_case "repeat-zsh-$n" "$installer" zsh .zshrc
  run_repeat_case "repeat-fish-$n" "$installer" fish .config/fish/config.fish
  if ! bash "$here/installer-staging-failure.test.sh" "$installer"; then
    echo "FAIL staging-failure-$n"
    fail=1
  fi
  run_space_case "install-spaces-$n" "$installer"
  run_replacement_case "replace-existing-executable-$n" "$installer"
  run_extraction_failure "extraction-failure-$n" "$installer"
  run_missing_executable_case "missing-phantom-$n" "$installer" phantom phantom-mcp
  run_missing_executable_case "missing-phantom-mcp-$n" "$installer" phantom-mcp phantom
  run_preservation_case "preserve-bash-$n" "$installer" bash .bashrc
  run_preservation_case "preserve-zsh-$n" "$installer" zsh .zshrc
  run_preservation_case "preserve-fish-$n" "$installer" fish .config/fish/config.fish
done
exit "$fail"
