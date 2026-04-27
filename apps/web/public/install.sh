#!/usr/bin/env bash
# Phantom Secrets — one-liner installer.
#
#   curl -fsSL https://phm.dev/install.sh | bash
#
# Downloads the latest signed release binary from GitHub, verifies SHA-256,
# extracts to ~/.phantom-secrets/bin, and wires it into your shell's PATH.
#
# Honors:
#   PHANTOM_REPO         override repo (default: ashlrai/phantom-secrets)
#   PHANTOM_INSTALL_DIR  override install dir (default: ~/.phantom-secrets/bin)
#   PHANTOM_TAG          pin a specific release tag (default: latest)

set -euo pipefail

say()  { printf "  \033[1;35m▲\033[0m phantom: %s\n" "$1"; }
warn() { printf "  \033[1;33m!\033[0m phantom: %s\n" "$1" >&2; }
die()  { printf "  \033[1;31m✗\033[0m phantom: %s\n" "$1" >&2; exit 1; }

REPO="${PHANTOM_REPO:-ashlrai/phantom-secrets}"
INSTALL_DIR="${PHANTOM_INSTALL_DIR:-$HOME/.phantom-secrets/bin}"
PIN_TAG="${PHANTOM_TAG:-}"

# Idempotently add a directory to the user's PATH by appending an export line
# to their shell's rc file. Detects bash/zsh/fish from $SHELL.
add_to_user_path() {
  local bin="$1"
  local marker="# phantom-secrets PATH"
  local shell_name rc
  shell_name="$(basename "${SHELL:-bash}")"
  case "$shell_name" in
    zsh)  rc="$HOME/.zshrc" ;;
    fish) rc="$HOME/.config/fish/config.fish" ;;
    *)    rc="$HOME/.bashrc" ;;
  esac
  mkdir -p "$(dirname "$rc")"
  touch "$rc"
  if grep -qF "$marker" "$rc" 2>/dev/null; then
    say "$bin already wired into $rc"
    return 0
  fi
  if [ "$shell_name" = "fish" ]; then
    printf '\n%s\nset -gx PATH %s $PATH\n' "$marker" "$bin" >> "$rc"
  else
    printf '\n%s\nexport PATH="%s:$PATH"\n' "$marker" "$bin" >> "$rc"
  fi
  say "added $bin to PATH in $rc (open a new shell or run: source $rc)"
}

# ---------------------------------------------------------------------------
# 1. Detect target.
# ---------------------------------------------------------------------------

case "$(uname -s)" in
  Darwin) os="apple-darwin" ;;
  Linux)  os="unknown-linux-gnu" ;;
  *) die "unsupported OS: $(uname -s) — install from source: cargo install phantom-secrets" ;;
esac
case "$(uname -m)" in
  x86_64|amd64)   arch="x86_64" ;;
  arm64|aarch64)  arch="aarch64" ;;
  *) die "unsupported arch: $(uname -m) — install from source: cargo install phantom-secrets" ;;
esac
target="${arch}-${os}"
say "target: $target"

# ---------------------------------------------------------------------------
# 2. Resolve release tag.
# ---------------------------------------------------------------------------

if [ -n "$PIN_TAG" ]; then
  tag="$PIN_TAG"
else
  say "resolving latest release..."
  # GitHub API redirect-follow + grab tag_name without jq dependency.
  tag="$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
         | grep '"tag_name"' | head -n1 | sed -E 's/.*"tag_name": *"([^"]+)".*/\1/')"
  [ -n "$tag" ] || die "could not determine latest release tag from GitHub API"
fi
say "release: $tag"

archive="phantom-${target}.tar.gz"
url="https://github.com/${REPO}/releases/download/${tag}/${archive}"

# ---------------------------------------------------------------------------
# 3. Download + verify checksum.
# ---------------------------------------------------------------------------

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

say "downloading $archive..."
curl -fsSL "$url" -o "$tmp/$archive" \
  || die "could not download $url (network error or asset missing for this target)"
curl -fsSL "$url.sha256" -o "$tmp/$archive.sha256" \
  || die "could not download checksum sidecar — refusing to install unverified binary"

expected="$(awk '{print $1}' < "$tmp/$archive.sha256")"
if command -v sha256sum >/dev/null 2>&1; then
  actual="$(sha256sum "$tmp/$archive" | awk '{print $1}')"
else
  actual="$(shasum -a 256 "$tmp/$archive" | awk '{print $1}')"
fi
[ "$expected" = "$actual" ] || die "SHA-256 mismatch: expected $expected, got $actual"
say "checksum verified"

# ---------------------------------------------------------------------------
# 4. Extract + install.
# ---------------------------------------------------------------------------

mkdir -p "$INSTALL_DIR"
tar xzf "$tmp/$archive" -C "$INSTALL_DIR"
chmod +x "$INSTALL_DIR/phantom" 2>/dev/null || true
[ -f "$INSTALL_DIR/phantom-mcp" ] && chmod +x "$INSTALL_DIR/phantom-mcp"
say "installed to $INSTALL_DIR"

# ---------------------------------------------------------------------------
# 5. Wire PATH.
# ---------------------------------------------------------------------------

if ! echo "$PATH" | tr ':' '\n' | grep -qx "$INSTALL_DIR"; then
  add_to_user_path "$INSTALL_DIR"
fi

# ---------------------------------------------------------------------------
# 6. Verify.
# ---------------------------------------------------------------------------

if "$INSTALL_DIR/phantom" --version >/dev/null 2>&1; then
  ver="$("$INSTALL_DIR/phantom" --version 2>&1 | head -n1)"
  say "done. $ver"
  say "open a new shell (or 'source' your shell rc), then try: phantom --help"
else
  warn "binary installed but did not run cleanly — try $INSTALL_DIR/phantom --help"
fi
