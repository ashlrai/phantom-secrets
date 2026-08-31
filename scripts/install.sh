#!/usr/bin/env bash
# Phantom Secrets — checksum-verifying release installer.
#
# Download this script from the reviewed GitHub release, inspect it, and run
# the local file. Do not pipe a network response directly into a shell.
#
# Downloads a release from GitHub, verifies its SHA-256 sidecar and exact
# archive shape, validates both binaries, then promotes a private sibling
# candidate into ~/.phantom-secrets/bin with rollback.

set -euo pipefail
umask 077

say()  { printf "  \033[1;35m▲\033[0m phantom: %s\n" "$1"; }
warn() { printf "  \033[1;33m!\033[0m phantom: %s\n" "$1" >&2; }
die()  { printf "  \033[1;31m✗\033[0m phantom: %s\n" "$1" >&2; exit 1; }

REPO="${PHANTOM_REPO:-ashlrai/phantom-secrets}"
RELEASES_URL="https://github.com/ashlrai/phantom-secrets/releases"
INSTALL_DIR="${PHANTOM_INSTALL_DIR:-$HOME/.phantom-secrets/bin}"
PIN_TAG="${PHANTOM_TAG:-}"
MAX_API_BYTES=1048576
MAX_CHECKSUM_BYTES=1024
MAX_ARCHIVE_BYTES=104857600
stage_root=""
backup_path=""
old_moved=0
new_moved=0

cleanup() {
  local rc=$?
  trap - EXIT HUP INT TERM
  if [ "$rc" -ne 0 ]; then
    if [ "$new_moved" -eq 1 ] && [ -e "$INSTALL_DIR" ]; then
      mv "$INSTALL_DIR" "$stage_root/failed-live" 2>/dev/null || true
    fi
    if [ "$old_moved" -eq 1 ] && [ -e "$backup_path" ] && [ ! -e "$INSTALL_DIR" ]; then
      mv "$backup_path" "$INSTALL_DIR" 2>/dev/null || true
    fi
  fi
  if [ -n "$stage_root" ] && [ -d "$stage_root" ]; then
    rm -rf -- "$stage_root"
  fi
  exit "$rc"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

allowed_download_url() {
  local url="$1" host
  [[ "$url" =~ ^https://([^/]+)/ ]] || return 1
  host="$(printf '%s' "${BASH_REMATCH[1]}" | tr '[:upper:]' '[:lower:]')"
  case "$host" in
    api.github.com|github.com|release-assets.githubusercontent.com|objects.githubusercontent.com)
      return 0 ;;
    *) return 1 ;;
  esac
}

download_file() {
  local url="$1" destination="$2" max_bytes="$3" effective size
  local -a curl_args=(
    --silent --show-error --fail --location
    --proto '=https' --proto-redir '=https'
    --max-redirs 3 --connect-timeout 10 --max-time 120
  )
  allowed_download_url "$url" || die "refusing non-HTTPS or untrusted download URL"
  if curl --help all 2>/dev/null | grep -q -- '--max-filesize'; then
    curl_args+=(--max-filesize "$max_bytes")
  fi
  effective="$(curl "${curl_args[@]}" --output "$destination" \
    --write-out '%{url_effective}' "$url")" \
    || die "download failed or exceeded its redirect, time, or size limit"
  allowed_download_url "$effective" || die "download redirected to an untrusted host"
  size="$(wc -c < "$destination" | tr -d '[:space:]')"
  [ "$size" -le "$max_bytes" ] || die "download exceeded the ${max_bytes}-byte limit"
}

validate_tag() {
  [[ "$1" =~ ^v?[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$ ]]
}

verify_binary_version() {
  local binary="$1" product="$2" expected="$3" output
  [ -f "$binary" ] && [ ! -L "$binary" ] || die "$product is not a regular file"
  output="$("$binary" --version 2>&1)" || die "$product --version failed"
  [ "$output" = "$product $expected" ] || die "$product reported an unexpected version"
}

add_to_user_path() {
  local bin="$1" marker="# phantom-secrets PATH" shell_name rc
  shell_name="$(basename "${SHELL:-bash}")"
  case "$shell_name" in
    zsh)  rc="$HOME/.zshrc" ;;
    fish) rc="$HOME/.config/fish/config.fish" ;;
    *)    rc="$HOME/.bashrc" ;;
  esac
  mkdir -p "$(dirname "$rc")" || return 1
  touch "$rc" || return 1
  if grep -qF "$marker" "$rc" 2>/dev/null; then
    say "$bin already wired into $rc"
    return 0
  fi
  if [ "$shell_name" = "fish" ]; then
    printf '\n%s\nset -gx PATH %s $PATH\n' "$marker" "$bin" >> "$rc" || return 1
  else
    printf '\n%s\nexport PATH="%s:$PATH"\n' "$marker" "$bin" >> "$rc" || return 1
  fi
  say "added $bin to PATH in $rc (open a new shell or run: source $rc)"
}

command -v curl >/dev/null 2>&1 || die "curl is required"
command -v tar >/dev/null 2>&1 || die "tar is required"
[[ "$REPO" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] || die "invalid PHANTOM_REPO"

case "$(uname -s)" in
  Darwin) os="apple-darwin" ;;
  Linux)  os="unknown-linux-gnu" ;;
  *) die "unsupported OS: $(uname -s) — use a checksum-verifiable asset from $RELEASES_URL" ;;
esac
case "$(uname -m)" in
  x86_64|amd64)  arch="x86_64" ;;
  arm64|aarch64) arch="aarch64" ;;
  *) die "unsupported arch: $(uname -m) — use a checksum-verifiable asset from $RELEASES_URL" ;;
esac
target="${arch}-${os}"
say "target: $target"

install_parent="$(dirname "$INSTALL_DIR")"
install_name="$(basename "$INSTALL_DIR")"
[ -n "$install_name" ] && [ "$install_name" != "." ] && [ "$install_name" != ".." ] \
  || die "invalid install directory"
mkdir -p "$install_parent"
install_parent="$(cd "$install_parent" && pwd -P)"
INSTALL_DIR="$install_parent/$install_name"
[ "$INSTALL_DIR" != "/" ] || die "refusing to install into filesystem root"
[ ! -L "$INSTALL_DIR" ] || die "refusing symlink install directory"

stage_root="$(mktemp -d "$install_parent/.${install_name}.install.XXXXXX")"
chmod 700 "$stage_root"
download_dir="$stage_root/download"
candidate_dir="$stage_root/candidate"
mkdir -m 700 "$download_dir" "$candidate_dir"

if [ -n "$PIN_TAG" ]; then
  tag="$PIN_TAG"
else
  say "resolving latest release..."
  release_json="$download_dir/latest.json"
  download_file "https://api.github.com/repos/${REPO}/releases/latest" \
    "$release_json" "$MAX_API_BYTES"
  tag="$(sed -nE 's/^[[:space:]]*"tag_name"[[:space:]]*:[[:space:]]*"([^"]+)"[,]?[[:space:]]*$/\1/p' \
    "$release_json" | head -n 1)"
  [ -n "$tag" ] || die "could not determine latest release tag from GitHub API"
fi
validate_tag "$tag" || die "release tag is not strict semantic version syntax"
expected_version="${tag#v}"
say "release: $tag"

archive="phantom-${target}.tar.gz"
url="https://github.com/${REPO}/releases/download/${tag}/${archive}"
archive_path="$download_dir/$archive"
checksum_path="$download_dir/$archive.sha256"

say "downloading $archive..."
download_file "$url" "$archive_path" "$MAX_ARCHIVE_BYTES"
download_file "$url.sha256" "$checksum_path" "$MAX_CHECKSUM_BYTES"

line_count="$(awk 'END { print NR }' "$checksum_path")"
[ "$line_count" = "1" ] || die "checksum sidecar must contain exactly one line"
checksum_line="$(sed -n '1p' "$checksum_path")"
if [[ ! "$checksum_line" =~ ^([0-9A-Fa-f]{64})[\ ][\ ]([^[:space:]]+)$ ]]; then
  die "checksum sidecar has invalid syntax"
fi
expected="$(printf '%s' "${BASH_REMATCH[1]}" | tr '[:upper:]' '[:lower:]')"
[ "${BASH_REMATCH[2]}" = "$archive" ] || die "checksum sidecar names an unexpected archive"
if command -v sha256sum >/dev/null 2>&1; then
  actual="$(sha256sum "$archive_path" | awk '{print tolower($1)}')"
elif command -v shasum >/dev/null 2>&1; then
  actual="$(shasum -a 256 "$archive_path" | awk '{print tolower($1)}')"
else
  die "sha256sum or shasum is required"
fi
[ "$expected" = "$actual" ] || die "SHA-256 mismatch"
say "checksum verified"

members="$(tar -tzf "$archive_path")" || die "could not list release archive"
if [ "$members" != $'phantom\nphantom-mcp' ] && [ "$members" != $'phantom-mcp\nphantom' ]; then
  die "release archive must contain exactly phantom and phantom-mcp"
fi
member_types="$(tar -tvzf "$archive_path" | awk '{ print substr($1, 1, 1) }')" \
  || die "could not inspect release archive member types"
[ "$member_types" = $'-\n-' ] || die "release archive members must be regular files"

tar -xzf "$archive_path" -C "$candidate_dir" || die "could not extract release archive"
[ "$(find "$candidate_dir" -mindepth 1 -maxdepth 1 -print | wc -l | tr -d '[:space:]')" = "2" ] \
  || die "candidate contains unexpected files"
[ -f "$candidate_dir/phantom" ] && [ ! -L "$candidate_dir/phantom" ] \
  || die "phantom is not a regular file"
[ -f "$candidate_dir/phantom-mcp" ] && [ ! -L "$candidate_dir/phantom-mcp" ] \
  || die "phantom-mcp is not a regular file"
chmod 755 "$candidate_dir/phantom" "$candidate_dir/phantom-mcp"
verify_binary_version "$candidate_dir/phantom" "phantom" "$expected_version"
verify_binary_version "$candidate_dir/phantom-mcp" "phantom-mcp" "$expected_version"
say "archive identity verified"

backup_path="$install_parent/.${install_name}.backup.${stage_root##*.}"
[ ! -e "$backup_path" ] || die "private backup path already exists"
if [ -e "$INSTALL_DIR" ]; then
  [ -d "$INSTALL_DIR" ] || die "install path exists and is not a directory"
  mv "$INSTALL_DIR" "$backup_path"
  old_moved=1
fi
mv "$candidate_dir" "$INSTALL_DIR"
new_moved=1
verify_binary_version "$INSTALL_DIR/phantom" "phantom" "$expected_version"
verify_binary_version "$INSTALL_DIR/phantom-mcp" "phantom-mcp" "$expected_version"
if [ "$old_moved" -eq 1 ]; then
  mv "$backup_path" "$stage_root/previous-live"
  old_moved=0
fi
new_moved=0
say "installed to $INSTALL_DIR"

if ! printf '%s\n' "$PATH" | tr ':' '\n' | grep -qxF "$INSTALL_DIR"; then
  add_to_user_path "$INSTALL_DIR" || warn "could not update your shell PATH; add $INSTALL_DIR manually"
fi
say "done. phantom $expected_version and phantom-mcp $expected_version"
say "open a new shell (or source your shell rc), then try: phantom --help"
