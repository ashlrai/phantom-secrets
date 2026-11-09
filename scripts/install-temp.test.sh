#!/usr/bin/env bash
# Failure-path tests for the temp files add_to_user_path creates in scripts/install.sh.
# Runs the real function with a fake `mktemp` that fails on chosen templates.
set -u

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
installer="$here/install.sh"
work="$(mktemp -d)"
trap 'rm -rf -- "$work"' EXIT
fails=0

pass() { printf 'ok   %s\n' "$1"; }
fail() { printf 'FAIL %s\n' "$1"; fails=$((fails + 1)); }

# Pull only add_to_user_path out of the installer (the rest downloads things).
awk '/^add_to_user_path\(\) \{/{p=1} p{print} p&&/^}/{exit}' "$installer" > "$work/fn.sh"
[ -s "$work/fn.sh" ] || { echo "could not extract add_to_user_path"; exit 1; }

# $1 = mktemp template fragment that must fail ("before" or "candidate").
run_case() {
  local fail_on="$1" home rc bin shim
  home="$work/home-$fail_on"
  shim="$work/shim-$fail_on"
  bin="$work/bin"
  mkdir -p "$home" "$shim" "$bin"
  rc="$home/.bashrc"
  printf 'export KEEP=1\n# user content\n' > "$rc"
  cp -p "$rc" "$work/rc-orig-$fail_on"
  real_mktemp="$(command -v mktemp)"
  cat > "$shim/mktemp" <<SHIM
#!/bin/sh
case "\$*" in *".phantom-path.$fail_on."*) exit 1 ;; esac
exec "$real_mktemp" "\$@"
SHIM
  chmod +x "$shim/mktemp"

  (
    export HOME="$home" SHELL=/bin/bash PATH="$shim:$PATH"
    say() { :; }
    # shellcheck disable=SC1090
    . "$work/fn.sh"
    add_to_user_path "$bin"
  ) >/dev/null 2>&1
  local status=$?

  [ "$status" -ne 0 ] && pass "$fail_on mktemp failure returns non-zero" \
    || fail "$fail_on mktemp failure returned success"
  cmp -s "$rc" "$work/rc-orig-$fail_on" && pass "$fail_on failure leaves rc unchanged" \
    || fail "$fail_on failure modified rc"
  local left
  left="$(find "$home" -name '.phantom-path.*' | wc -l | tr -d ' ')"
  [ "$left" = "0" ] && pass "$fail_on failure leaves no temp file" \
    || fail "$fail_on failure left $left temp file(s)"
}

run_case before
run_case candidate

[ "$fails" -eq 0 ] || { echo "$fails failure(s)"; exit 1; }
echo "all install-temp tests passed"
