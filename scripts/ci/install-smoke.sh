#!/usr/bin/env bash
# Install the CLI and run the documented first commands.
# README install is the release archive, not an npm package.
# `source` builds with cargo install --path. `release` uses the latest
# published GitHub release for this runner. CI Gate does not call this.
set -euo pipefail

smoke_commands() {
  local bin="$1"
  "$bin" --help >/dev/null
  local everyday empty
  everyday="$(mktemp -d)"
  printf 'PORT=3000\n' > "$everyday/.env"
  (cd "$everyday" && "$bin" init)
  empty="$(mktemp -d)"
  (cd "$empty" && "$bin" init --empty)
}

install_source() {
  local root="${1:?install root}"
  cargo install --path crates/phantom-cli --locked --bin phantom --root "$root" --force >&2
  if [ -x "$root/bin/phantom.exe" ]; then
    printf '%s\n' "$root/bin/phantom.exe"
  else
    printf '%s\n' "$root/bin/phantom"
  fi
}

release_archive() {
  local os arch
  os="$(uname -s)"
  arch="$(uname -m)"
  case "$os-$arch" in
    Linux-x86_64) printf '%s\n' phantom-x86_64-unknown-linux-gnu.tar.gz ;;
    Linux-aarch64) printf '%s\n' phantom-aarch64-unknown-linux-gnu.tar.gz ;;
    Darwin-arm64) printf '%s\n' phantom-aarch64-apple-darwin.tar.gz ;;
    Darwin-x86_64) printf '%s\n' phantom-x86_64-apple-darwin.tar.gz ;;
    *x86_64|*amd64) printf '%s\n' phantom-x86_64-pc-windows-msvc.zip ;;
    *aarch64*|*arm64*) printf '%s\n' phantom-aarch64-pc-windows-msvc.zip ;;
    *) echo "no published archive for $os-$arch" >&2; return 1 ;;
  esac
}

install_release() {
  local root="${1:?install root}"
  local archive tag url dir
  archive="$(release_archive)"
  tag="$(curl --proto '=https' --tlsv1.2 --fail --silent --show-error --retry 3 \
    -H "Accept: application/vnd.github+json" \
    -H "Authorization: Bearer ${GITHUB_TOKEN}" \
    "https://api.github.com/repos/${GITHUB_REPOSITORY}/releases/latest" \
    | node -e 'let s="";process.stdin.on("data",d=>s+=d);process.stdin.on("end",()=>{const j=JSON.parse(s); if(!j.tag_name) process.exit(1); process.stdout.write(j.tag_name);})')"
  url="https://github.com/${GITHUB_REPOSITORY}/releases/download/${tag}/${archive}"
  dir="$(mktemp -d)"
  curl --proto '=https' --tlsv1.2 --fail --location --silent --show-error --retry 3 \
    -o "$dir/$archive" "$url"
  curl --proto '=https' --tlsv1.2 --fail --location --silent --show-error --retry 3 \
    -o "$dir/$archive.sha256" "$url.sha256"
  node --input-type=module -e '
    import { createHash } from "node:crypto";
    import { readFileSync } from "node:fs";
    const expected = readFileSync(process.argv[1], "utf8").trim().split(/\s+/)[0];
    const got = createHash("sha256").update(readFileSync(process.argv[2])).digest("hex");
    if (got !== expected) { process.stderr.write("checksum mismatch\n"); process.exit(1); }
  ' "$dir/$archive.sha256" "$dir/$archive"
  mkdir -p "$root"
  tar -xf "$dir/$archive" -C "$root"
  if [ -x "$root/phantom.exe" ]; then
    printf '%s\n' "$root/phantom.exe"
  else
    printf '%s\n' "$root/phantom"
  fi
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
  mode="${1:?source or release}"
  root="${2:?install root}"
  export PHANTOM_VAULT_PASSPHRASE="${PHANTOM_VAULT_PASSPHRASE:-ci-install-smoke}"
  case "$mode" in
    source) bin="$(install_source "$root")" ;;
    release) bin="$(install_release "$root")" ;;
    *) echo "unknown mode $mode" >&2; exit 2 ;;
  esac
  smoke_commands "$bin"
fi
