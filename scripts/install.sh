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

CANONICAL_REPO="ashlrai/phantom-secrets"
CANDIDATE_TAG="v0.7.8"
REPO="$CANONICAL_REPO"
RELEASES_URL="https://github.com/ashlrai/phantom-secrets/releases"
INSTALL_DIR="${PHANTOM_INSTALL_DIR:-$HOME/.phantom-secrets/bin}"
PIN_TAG="$CANDIDATE_TAG"
TEST_LOCAL_RELEASE_DIR=""
TEST_FAIL_AFTER_PROMOTION=0
MAX_CHECKSUM_BYTES=1024
MAX_ARCHIVE_BYTES=104857600
stage_root=""
backup_path=""
old_moved=0
new_moved=0
lock_path=""
lock_token=""
lock_owned=0
lock_heartbeat_pid=""

# Production installers are bound to one reviewed repository and release. The
# override seam exists only for the offline installer test harness, including a
# gated post-promotion fault used to prove rollback. Accepting a caller-controlled
# repository, mutable release selector, or fault flag in normal use would defeat
# review of this exact script.
if [ "${PHANTOM_TEST_ALLOW_INSTALLER_OVERRIDES:-}" = "1" ]; then
  REPO="${PHANTOM_REPO:-$CANONICAL_REPO}"
  PIN_TAG="${PHANTOM_TAG:-$CANDIDATE_TAG}"
  TEST_LOCAL_RELEASE_DIR="${PHANTOM_TEST_LOCAL_RELEASE_DIR:-}"
  if [ "${PHANTOM_TEST_FAIL_AFTER_PROMOTION+x}" = "x" ]; then
    [ "$PHANTOM_TEST_FAIL_AFTER_PROMOTION" = "1" ] \
      || die "PHANTOM_TEST_FAIL_AFTER_PROMOTION must be 1 when set"
    TEST_FAIL_AFTER_PROMOTION=1
  fi
elif [ -n "${PHANTOM_REPO:-}" ] || [ -n "${PHANTOM_TAG:-}" ] \
  || [ -n "${PHANTOM_TEST_LOCAL_RELEASE_DIR:-}" ] \
  || [ "${PHANTOM_TEST_FAIL_AFTER_PROMOTION+x}" = "x" ]; then
  die "installer test overrides require PHANTOM_TEST_ALLOW_INSTALLER_OVERRIDES=1"
fi

validate_install_dir_override() {
  local value="$1"
  [ -n "$value" ] && [ "${value#/}" != "$value" ] \
    || die "PHANTOM_INSTALL_DIR must be a non-empty absolute path"
  # The directory is later persisted into shell startup syntax. Keep the
  # override deliberately narrower than the host filesystem grammar so control
  # bytes, quotes, substitutions, and command separators cannot become code.
  [[ "$value" =~ ^[A-Za-z0-9_./\ -]+$ ]] \
    || die "PHANTOM_INSTALL_DIR contains unsafe or shell-significant characters"
}

file_identity() {
  local identity
  if identity="$(stat -c '%d:%i:%h:%f' "$1" 2>/dev/null)"; then
    [[ "$identity" =~ ^[0-9]+:[0-9]+:[0-9]+:[0-9A-Fa-f]+$ ]] || return 1
  else
    identity="$(stat -f '%d:%i:%l:%p' "$1" 2>/dev/null)" || return 1
    [[ "$identity" =~ ^[0-9]+:[0-9]+:[0-9]+:[0-9]+$ ]] || return 1
  fi
  printf '%s\n' "$identity"
}

file_link_count() {
  local count
  if count="$(stat -c '%h' "$1" 2>/dev/null)"; then
    :
  else
    count="$(stat -f '%l' "$1" 2>/dev/null)" || return 1
  fi
  [[ "$count" =~ ^[0-9]+$ ]] || return 1
  printf '%s\n' "$count"
}

release_install_lock() {
  local current=""
  if [ -n "$lock_heartbeat_pid" ]; then
    kill "$lock_heartbeat_pid" 2>/dev/null || true
    wait "$lock_heartbeat_pid" 2>/dev/null || true
    lock_heartbeat_pid=""
  fi
  if [ "$lock_owned" -eq 1 ] && [ -d "$lock_path" ] && [ ! -L "$lock_path" ]; then
    if [ -f "$lock_path/owner" ] && [ ! -L "$lock_path/owner" ]; then
      current="$(sed -n '1p' "$lock_path/owner" 2>/dev/null || true)"
    fi
    if [ "$current" = "$lock_token" ]; then
      rm -rf -- "$lock_path"
    fi
  fi
  lock_owned=0
}

install_lock_is_owned() {
  [ "$lock_owned" -eq 1 ] \
    && [ -d "$lock_path" ] && [ ! -L "$lock_path" ] \
    && [ -f "$lock_path/owner" ] && [ ! -L "$lock_path/owner" ] \
    && [ "$(sed -n '1p' "$lock_path/owner" 2>/dev/null || true)" = "$lock_token" ]
}

assert_install_lock_owned() {
  install_lock_is_owned || die "installer lock ownership was lost"
}

cleanup() {
  local rc=$?
  trap - EXIT HUP INT TERM
  if [ "$rc" -ne 0 ] && install_lock_is_owned; then
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
  release_install_lock
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
    github.com|release-assets.githubusercontent.com|objects.githubusercontent.com)
      return 0 ;;
    *) return 1 ;;
  esac
}

download_file() {
  local url="$1" destination="$2" max_bytes="$3" effective size source
  local -a curl_args=(
    --silent --show-error --fail --location
    --proto '=https' --proto-redir '=https'
    --max-redirs 3 --connect-timeout 10 --max-time 120
  )
  allowed_download_url "$url" || die "refusing non-HTTPS or untrusted download URL"
  if [ -n "$TEST_LOCAL_RELEASE_DIR" ]; then
    [ "${TEST_LOCAL_RELEASE_DIR#/}" != "$TEST_LOCAL_RELEASE_DIR" ] \
      && [ -d "$TEST_LOCAL_RELEASE_DIR" ] && [ ! -L "$TEST_LOCAL_RELEASE_DIR" ] \
      || die "PHANTOM_TEST_LOCAL_RELEASE_DIR must be an absolute regular directory"
    source="$TEST_LOCAL_RELEASE_DIR/${url##*/}"
    [ -f "$source" ] && [ ! -L "$source" ] \
      || die "offline installer fixture is missing or not a regular file"
    size="$(wc -c < "$source" | tr -d '[:space:]')"
    [ "$size" -gt 0 ] && [ "$size" -le "$max_bytes" ] \
      || die "offline installer fixture exceeded its size limit"
    cp -- "$source" "$destination"
    return 0
  fi
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

file_mtime_epoch() {
  local mtime
  if mtime="$(stat -c '%Y' "$1" 2>/dev/null)"; then
    :
  else
    mtime="$(stat -f '%m' "$1" 2>/dev/null)" || return 1
  fi
  [[ "$mtime" =~ ^[0-9]+$ ]] || return 1
  printf '%s\n' "$mtime"
}

acquire_install_lock() {
  local wait_seconds="${PHANTOM_INSTALL_LOCK_WAIT_SECONDS:-30}"
  local stale_seconds="${PHANTOM_INSTALL_LOCK_STALE_SECONDS:-300}"
  local heartbeat_seconds="${PHANTOM_INSTALL_LOCK_HEARTBEAT_SECONDS:-5}"
  local deadline now mtime age stale_path current
  [[ "$wait_seconds" =~ ^[1-9][0-9]*$ ]] || die "install lock wait must be a positive integer"
  [[ "$stale_seconds" =~ ^[1-9][0-9]*$ ]] || die "install lock stale timeout must be a positive integer"
  [[ "$heartbeat_seconds" =~ ^[1-9][0-9]*$ ]] || die "install lock heartbeat must be a positive integer"
  [ "$heartbeat_seconds" -lt "$stale_seconds" ] \
    || die "install lock heartbeat must be shorter than stale timeout"

  lock_path="$install_parent/.${install_name}.install.lock"
  lock_token="$$-$(date +%s)-${RANDOM}-${RANDOM}"
  deadline=$(($(date +%s) + wait_seconds))
  while :; do
    if mkdir -m 700 "$lock_path" 2>/dev/null; then
      printf '%s\n' "$lock_token" > "$lock_path/owner"
      chmod 600 "$lock_path/owner"
      lock_owned=1
      (
        heartbeat_sleep_pid=""
        stop_heartbeat() {
          if [ -n "$heartbeat_sleep_pid" ]; then
            kill "$heartbeat_sleep_pid" 2>/dev/null || true
            wait "$heartbeat_sleep_pid" 2>/dev/null || true
          fi
          exit 0
        }
        trap stop_heartbeat HUP INT TERM
        while :; do
          sleep "$heartbeat_seconds" &
          heartbeat_sleep_pid=$!
          wait "$heartbeat_sleep_pid" || exit 0
          heartbeat_sleep_pid=""
          [ -f "$lock_path/owner" ] && [ ! -L "$lock_path/owner" ] || exit 0
          current="$(sed -n '1p' "$lock_path/owner" 2>/dev/null || true)"
          [ "$current" = "$lock_token" ] || exit 0
          touch "$lock_path/owner" || exit 0
        done
      ) &
      lock_heartbeat_pid=$!
      return 0
    fi

    [ -e "$lock_path" ] || die "could not create install lock"
    [ -d "$lock_path" ] && [ ! -L "$lock_path" ] \
      || die "install lock is not a regular directory"
    if [ -e "$lock_path/owner" ]; then
      [ -f "$lock_path/owner" ] && [ ! -L "$lock_path/owner" ] \
        || die "install lock owner is not a regular file"
      mtime="$(file_mtime_epoch "$lock_path/owner")" \
        || die "could not inspect install lock owner"
    else
      mtime="$(file_mtime_epoch "$lock_path")" \
        || die "could not inspect install lock"
    fi
    now="$(date +%s)"
    age=$((now - mtime))
    if [ "$age" -gt "$stale_seconds" ]; then
      stale_path="$install_parent/.${install_name}.install.lock.stale.${lock_token}"
      if mv "$lock_path" "$stale_path" 2>/dev/null; then
        rm -rf -- "$stale_path"
        continue
      fi
    fi
    [ "$now" -lt "$deadline" ] || die "timed out waiting for another Phantom installer"
    sleep 1
  done
}

add_to_user_path() {
  local bin="$1" marker="# phantom-secrets PATH" shell_name rc rc_parent
  local before_tmp candidate_tmp before_identity after_identity candidate_identity
  [[ "$bin" =~ ^[A-Za-z0-9_./\ -]+$ ]] || return 1
  shell_name="$(basename "${SHELL:-bash}")"
  case "$shell_name" in
    zsh)  rc="$HOME/.zshrc" ;;
    fish) rc="$HOME/.config/fish/config.fish" ;;
    *)    rc="$HOME/.bashrc" ;;
  esac
  rc_parent="$(dirname "$rc")"
  mkdir -p "$rc_parent" || return 1
  rc_parent="$(cd "$rc_parent" && pwd -P)" || return 1
  rc="$rc_parent/$(basename "$rc")"
  before_tmp="$(mktemp "$rc_parent/.phantom-path.before.XXXXXX")" || return 1
  candidate_tmp="$(mktemp "$rc_parent/.phantom-path.candidate.XXXXXX")" \
    || { rm -f -- "$before_tmp"; return 1; }
  if [ -e "$rc" ] || [ -L "$rc" ]; then
    [ -f "$rc" ] && [ ! -L "$rc" ] || {
      rm -f -- "$before_tmp" "$candidate_tmp"
      return 1
    }
    [ "$(file_link_count "$rc")" = "1" ] || {
      rm -f -- "$before_tmp" "$candidate_tmp"
      return 1
    }
    before_identity="$(file_identity "$rc")" || {
      rm -f -- "$before_tmp" "$candidate_tmp"
      return 1
    }
    cp -p "$rc" "$before_tmp" || {
      rm -f -- "$before_tmp" "$candidate_tmp"
      return 1
    }
    after_identity="$(file_identity "$rc")" || after_identity=""
    [ "$after_identity" = "$before_identity" ] || {
      rm -f -- "$before_tmp" "$candidate_tmp"
      return 1
    }
    if grep -qF "$marker" "$before_tmp" 2>/dev/null; then
      rm -f -- "$before_tmp" "$candidate_tmp"
      say "$bin already wired into $rc"
      return 0
    fi
    cp -p "$before_tmp" "$candidate_tmp" || {
      rm -f -- "$before_tmp" "$candidate_tmp"
      return 1
    }
  else
    : > "$before_tmp"
    : > "$candidate_tmp"
    chmod 600 "$before_tmp" "$candidate_tmp" || {
      rm -f -- "$before_tmp" "$candidate_tmp"
      return 1
    }
    before_identity="absent"
  fi
  if [ "$shell_name" = "fish" ]; then
    printf '\n%s\nset -gx PATH "%s" $PATH\n' "$marker" "$bin" >> "$candidate_tmp" || {
      rm -f -- "$before_tmp" "$candidate_tmp"
      return 1
    }
  else
    printf '\n%s\nexport PATH="%s:$PATH"\n' "$marker" "$bin" >> "$candidate_tmp" || {
      rm -f -- "$before_tmp" "$candidate_tmp"
      return 1
    }
  fi
  if [ "$before_identity" = "absent" ]; then
    [ ! -e "$rc" ] && [ ! -L "$rc" ] || {
      rm -f -- "$before_tmp" "$candidate_tmp"
      return 1
    }
  else
    after_identity="$(file_identity "$rc")" || after_identity=""
    [ "$after_identity" = "$before_identity" ] \
      && [ -f "$rc" ] && [ ! -L "$rc" ] \
      && cmp -s "$before_tmp" "$rc" || {
        rm -f -- "$before_tmp" "$candidate_tmp"
        return 1
      }
  fi
  candidate_identity="$(file_identity "$candidate_tmp")" || {
    rm -f -- "$before_tmp" "$candidate_tmp"
    return 1
  }
  mv -f "$candidate_tmp" "$rc" || {
    rm -f -- "$before_tmp" "$candidate_tmp"
    return 1
  }
  rm -f -- "$before_tmp"
  after_identity="$(file_identity "$rc")" || after_identity=""
  if [ "$after_identity" != "$candidate_identity" ] \
    || [ ! -f "$rc" ] || [ -L "$rc" ] \
    || ! grep -qF "$marker" "$rc" 2>/dev/null; then
    return 1
  fi
  say "added $bin to PATH in $rc (open a new shell or run: source $rc)"
}

command -v curl >/dev/null 2>&1 || die "curl is required"
command -v tar >/dev/null 2>&1 || die "tar is required"
[[ "$REPO" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] || die "invalid PHANTOM_REPO"
if [ "${PHANTOM_INSTALL_DIR+x}" = x ]; then
  validate_install_dir_override "$PHANTOM_INSTALL_DIR"
fi

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

acquire_install_lock

stage_root="$(mktemp -d "$install_parent/.${install_name}.install.XXXXXX")"
chmod 700 "$stage_root"
download_dir="$stage_root/download"
candidate_dir="$stage_root/candidate"
mkdir -m 700 "$download_dir" "$candidate_dir"

tag="$PIN_TAG"
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
receipt='{"schema_version":1,"source":"direct","version":"'"$expected_version"'","target":"'"$target"'"}'
printf '%s\n' "$receipt" > "$candidate_dir/.phantom-install-source.json"
chmod 600 "$candidate_dir/.phantom-install-source.json"
say "archive identity verified"

backup_path="$install_parent/.${install_name}.backup.${stage_root##*.}"
[ ! -e "$backup_path" ] || die "private backup path already exists"
assert_install_lock_owned
if [ -e "$INSTALL_DIR" ]; then
  [ -d "$INSTALL_DIR" ] || die "install path exists and is not a directory"
  mv "$INSTALL_DIR" "$backup_path"
  old_moved=1
fi
assert_install_lock_owned
mv "$candidate_dir" "$INSTALL_DIR"
new_moved=1
if [ "$TEST_FAIL_AFTER_PROMOTION" -eq 1 ]; then
  die "test-only injected failure after promotion"
fi
verify_binary_version "$INSTALL_DIR/phantom" "phantom" "$expected_version"
verify_binary_version "$INSTALL_DIR/phantom-mcp" "phantom-mcp" "$expected_version"
[ -f "$INSTALL_DIR/.phantom-install-source.json" ] \
  && [ ! -L "$INSTALL_DIR/.phantom-install-source.json" ] \
  && [ "$(sed -n '1p' "$INSTALL_DIR/.phantom-install-source.json")" = "$receipt" ] \
  || die "install source receipt failed final validation"
assert_install_lock_owned
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
