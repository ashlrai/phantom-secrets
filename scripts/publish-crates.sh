#!/usr/bin/env bash
# Publish the complete Phantom Rust workspace to crates.io in dependency order.
#
# This script is deliberately inert unless an explicit mode is selected. It
# never accepts a crates.io token on argv; cargo reads its normal credentials or
# CARGO_REGISTRY_TOKEN environment variable.

# Prevent a caller-supplied `bash -x` from echoing the captured registry token.
set +x
set -euo pipefail

# Do not expose the registry credential to metadata, build scripts, tests,
# linters, packagers, or any other child process. This shell-local value is
# injected only into an individual `cargo publish` subprocess below.
REGISTRY_TOKEN="${CARGO_REGISTRY_TOKEN:-}"
unset CARGO_REGISTRY_TOKEN
PUBLISH_CONFIRMATION="${PHANTOM_PUBLISH_CONFIRM:-}"
unset PHANTOM_PUBLISH_CONFIRM
GITHUB_API_TOKEN="${GH_TOKEN:-${GITHUB_TOKEN:-}}"
unset GH_TOKEN GITHUB_TOKEN

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)" || exit 1
readonly SCRIPT_DIR
REPO_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd -P)" || exit 1
readonly REPO_ROOT
readonly CARGO_BIN="${CARGO:-cargo}"
readonly CURL_BIN="${CURL:-curl}"
readonly GIT_BIN="${GIT:-git}"
readonly GH_BIN="${GH:-gh}"
readonly PYTHON_BIN="${PYTHON:-python3}"
readonly REGISTRY_API="https://crates.io/api/v1"
readonly GITHUB_REPOSITORY="ashlrai/phantom-secrets"

# Leaves precede every in-workspace dependent. Runtime validation below checks
# this list against cargo metadata so adding or rewiring a crate cannot silently
# leave the release pipeline stale.
readonly -a CRATES=(
  "phantom-secrets-authority"
  "phantom-secrets-core"
  "phantom-secrets-broker"
  "phantom-secrets-evidence"
  "phantom-secrets-locus-contract"
  "phantom-secrets-proxy"
  "phantom-secrets-session"
  "phantom-secrets-vault"
  "phantom-secrets-workspace"
  "phantom-secrets-runtime"
  "phantom-secrets-mcp"
  "phantom-secrets"
)
readonly -a CRATE_PATHS=(
  "crates/phantom-authority"
  "crates/phantom-core"
  "crates/phantom-broker"
  "crates/phantom-evidence"
  "crates/phantom-locus-contract"
  "crates/phantom-proxy"
  "crates/phantom-session"
  "crates/phantom-vault"
  "crates/phantom-workspace"
  "crates/phantom-runtime"
  "crates/phantom-mcp"
  "crates/phantom-cli"
)

# `cargo package` normally insists that versioned dependencies already exist in
# the selected registry. Local patches let a pre-tag verification package the
# entire unpublished graph; they are command-local and do not alter the archive
# manifests or the later `cargo publish --registry crates-io` invocation.
declare -a PACKAGE_PATCH_ARGS=()
for patch_index in "${!CRATES[@]}"; do
  PACKAGE_PATCH_ARGS+=(
    --config
    "patch.crates-io.${CRATES[$patch_index]}.path=\"${CRATE_PATHS[$patch_index]}\""
  )
done
readonly PACKAGE_PATCH_ARGS

usage() {
  cat <<'USAGE'
Usage:
  ./scripts/publish-crates.sh --verify-only [--version <semver>] [--allow-dirty]
  ./scripts/publish-crates.sh --dry-run    [--version <semver>] [--allow-dirty]
  ./scripts/publish-crates.sh --publish     --version <semver>

Modes:
  --verify-only  Run source gates and package all crates without publication calls.
  --dry-run      Also query crates.io and report publish/skip decisions; no upload.
  --publish      Publish missing packages and verify their immutable checksums.

Publishing additionally requires:
  * a clean worktree at the exact v<semver> tag;
  * PHANTOM_PUBLISH_CONFIRM=publish-phantom-secrets-<semver>;
  * cargo credentials or CARGO_REGISTRY_TOKEN (never pass a token on argv).

--allow-dirty is accepted only by non-publishing modes.
USAGE
}

die() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"
}

MODE=""
EXPECTED_VERSION=""
ALLOW_DIRTY=0

while (($# > 0)); do
  case "$1" in
    --verify-only|--dry-run|--publish)
      [[ -z "$MODE" ]] || die "select exactly one mode"
      MODE="${1#--}"
      shift
      ;;
    --version)
      (($# >= 2)) || die "--version requires a value"
      EXPECTED_VERSION="$2"
      shift 2
      ;;
    --allow-dirty)
      ALLOW_DIRTY=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      die "unknown argument: $1"
      ;;
  esac
done

[[ -n "$MODE" ]] || { usage >&2; exit 2; }
[[ "$EXPECTED_VERSION" != v* ]] || die "--version must not include the v prefix"
if [[ -n "$EXPECTED_VERSION" ]]; then
  [[ "$EXPECTED_VERSION" =~ ^(0|[1-9][0-9]*)\.[0-9]+\.[0-9]+([+-][0-9A-Za-z.-]+)?$ ]] ||
    die "--version is not valid SemVer: $EXPECTED_VERSION"
fi
if [[ "$MODE" == "publish" ]]; then
  [[ "$ALLOW_DIRTY" -eq 0 ]] || die "--allow-dirty is forbidden with --publish"
  [[ -n "$EXPECTED_VERSION" ]] || die "--publish requires an explicit --version"
fi

require_command "$CARGO_BIN"
require_command "$GIT_BIN"
require_command "$PYTHON_BIN"
if [[ "$MODE" != "verify-only" ]]; then
  require_command "$CURL_BIN"
fi
if [[ "$MODE" == "publish" ]]; then
  require_command "$GH_BIN"
fi

cd -- "$REPO_ROOT"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/phantom-crates-publish.XXXXXXXX")" || die "could not create temporary directory"
readonly TMP_DIR
cleanup() {
  REGISTRY_TOKEN=""
  PUBLISH_CONFIRMATION=""
  GITHUB_API_TOKEN=""
  unset REGISTRY_TOKEN PUBLISH_CONFIRMATION GITHUB_API_TOKEN
  rm -rf -- "$TMP_DIR"
}
trap cleanup EXIT HUP INT TERM

readonly METADATA_FILE="$TMP_DIR/metadata.json"
readonly ORDER_FILE="$TMP_DIR/order.txt"
printf '%s\n' "${CRATES[@]}" >"$ORDER_FILE"
"$CARGO_BIN" metadata --format-version 1 --no-deps --locked >"$METADATA_FILE"

# Validate the complete closed publication set, common version, crates.io
# eligibility, and topological order from Cargo's machine-readable graph.
WORKSPACE_VERSION="$({
  EXPECTED_VERSION="$EXPECTED_VERSION" "$PYTHON_BIN" - "$METADATA_FILE" "$ORDER_FILE" <<'PY'
import json
import os
import pathlib
import re
import sys

metadata = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
order = pathlib.Path(sys.argv[2]).read_text(encoding="utf-8").splitlines()
members = set(metadata["workspace_members"])
packages = [package for package in metadata["packages"] if package["id"] in members]
by_name = {package["name"]: package for package in packages}

if len(by_name) != len(packages):
    raise SystemExit("duplicate workspace package name in cargo metadata")
if set(by_name) != set(order):
    missing = sorted(set(by_name) - set(order))
    stale = sorted(set(order) - set(by_name))
    raise SystemExit(f"publication set mismatch; missing={missing}, stale={stale}")

versions = {package["version"] for package in packages}
if len(versions) != 1:
    raise SystemExit(f"workspace crates do not share one version: {sorted(versions)}")
version = versions.pop()
if not re.fullmatch(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?", version):
    raise SystemExit(f"workspace version is not valid SemVer: {version}")
expected = os.environ.get("EXPECTED_VERSION")
if expected and version != expected:
    raise SystemExit(f"requested version {expected} does not match workspace version {version}")

positions = {name: index for index, name in enumerate(order)}
for name in order:
    package = by_name[name]
    allowed = package.get("publish")
    if allowed != ["crates-io"]:
        raise SystemExit(f"{name} must allow publication only to crates-io")
    for dependency in package.get("dependencies", []):
        dependency_name = dependency["name"]
        if (
            dependency_name in positions
            and dependency_name != name
            and positions[dependency_name] >= positions[name]
        ):
            raise SystemExit(
                f"publication order violation: {dependency_name} must precede {name}"
            )

print(version)
PY
})" || die "workspace publication metadata validation failed"
readonly WORKSPACE_VERSION

remote_tag_sha() {
  local tag="v$WORKSPACE_VERSION"
  local refs="$TMP_DIR/origin-tag-refs.txt"
  "$GIT_BIN" ls-remote --exit-code --tags origin \
    "refs/tags/$tag" "refs/tags/$tag^{}" >"$refs" || die "origin does not expose the exact $tag tag"
  "$PYTHON_BIN" - "$tag" "$refs" <<'PY'
import pathlib
import re
import sys

tag = sys.argv[1]
direct = f"refs/tags/{tag}"
peeled = f"{direct}^{{}}"
refs = {}
for line in pathlib.Path(sys.argv[2]).read_text(encoding="utf-8").splitlines():
    parts = line.split("\t")
    if len(parts) != 2 or not re.fullmatch(r"[0-9a-f]{40}", parts[0]):
        raise SystemExit("origin returned a malformed tag reference")
    if parts[1] in refs:
        raise SystemExit("origin returned a duplicate tag reference")
    refs[parts[1]] = parts[0]
if direct not in refs:
    raise SystemExit(f"origin is missing {direct}")
print(refs.get(peeled, refs[direct]))
PY
}

verify_github_release_receipt() {
  local receipt="$TMP_DIR/github-release.json"
  local tag="v$WORKSPACE_VERSION"
  if [[ -n "$GITHUB_API_TOKEN" ]]; then
    GH_TOKEN="$GITHUB_API_TOKEN" "$GH_BIN" release view "$tag" \
      --repo "$GITHUB_REPOSITORY" \
      --json tagName,isDraft,isPrerelease,assets,url >"$receipt" ||
      die "GitHub release receipt lookup failed for $tag"
  else
    "$GH_BIN" release view "$tag" \
      --repo "$GITHUB_REPOSITORY" \
      --json tagName,isDraft,isPrerelease,assets,url >"$receipt" ||
      die "GitHub release receipt lookup failed for $tag"
  fi
  "$PYTHON_BIN" - "$receipt" "$tag" <<'PY'
import json
import pathlib
import sys

payload = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
tag = sys.argv[2]
archives = [
    "phantom-aarch64-apple-darwin.tar.gz",
    "phantom-x86_64-apple-darwin.tar.gz",
    "phantom-aarch64-unknown-linux-gnu.tar.gz",
    "phantom-x86_64-unknown-linux-gnu.tar.gz",
    "phantom-aarch64-pc-windows-msvc.zip",
    "phantom-x86_64-pc-windows-msvc.zip",
]
expected = ["SHA256SUMS"]
for archive in archives:
    expected.extend([archive, f"{archive}.sha256", f"{archive}.spdx.json"])
assets = payload.get("assets")
if payload.get("tagName") != tag or payload.get("isDraft") is not False:
    raise SystemExit("GitHub release is absent, draft, or bound to the wrong tag")
if payload.get("isPrerelease") is not False:
    raise SystemExit("GitHub release is still marked as a prerelease")
if not isinstance(payload.get("url"), str) or not payload["url"].startswith("https://github.com/"):
    raise SystemExit("GitHub release URL is missing or invalid")
if not isinstance(assets, list) or any(not isinstance(asset, dict) for asset in assets):
    raise SystemExit("GitHub release assets are malformed")
names = [asset.get("name") for asset in assets]
if sorted(names) != sorted(expected):
    missing = sorted(set(expected) - set(names))
    extra = sorted(set(names) - set(expected))
    raise SystemExit(f"GitHub release asset set mismatch; missing={missing}, extra={extra}")
for asset in assets:
    if not isinstance(asset.get("size"), int) or asset["size"] < 1:
        raise SystemExit(f"GitHub release asset has invalid size: {asset.get('name')}")
print(payload["url"])
PY
}

if [[ "$MODE" == "publish" ]]; then
  readonly CONFIRMATION="publish-phantom-secrets-$WORKSPACE_VERSION"
  [[ "$PUBLISH_CONFIRMATION" == "$CONFIRMATION" ]] ||
    die "set PHANTOM_PUBLISH_CONFIRM=$CONFIRMATION to authorize this exact publication"

  TOPLEVEL="$($GIT_BIN rev-parse --show-toplevel)" || die "could not resolve Git worktree"
  readonly TOPLEVEL
  [[ "$TOPLEVEL" == "$REPO_ROOT" ]] || die "script must run from its owning Git worktree"
  ORIGIN_URL="$($GIT_BIN remote get-url origin)" || die "could not resolve origin URL"
  readonly ORIGIN_URL
  case "$ORIGIN_URL" in
    https://github.com/ashlrai/phantom-secrets|https://github.com/ashlrai/phantom-secrets.git|git@github.com:ashlrai/phantom-secrets.git|ssh://git@github.com/ashlrai/phantom-secrets.git) ;;
    *) die "origin is not the canonical $GITHUB_REPOSITORY repository" ;;
  esac
  [[ -z "$($GIT_BIN status --porcelain --untracked-files=all)" ]] ||
    die "publishing requires a clean worktree"
  SOURCE_SHA="$($GIT_BIN rev-parse --verify 'HEAD^{commit}')" || die "could not resolve HEAD"
  readonly SOURCE_SHA
  TAG_SHA="$($GIT_BIN rev-parse --verify "refs/tags/v$WORKSPACE_VERSION^{commit}")" ||
    die "local tag v$WORKSPACE_VERSION is missing"
  readonly TAG_SHA
  [[ "$SOURCE_SHA" == "$TAG_SHA" ]] ||
    die "HEAD is not the exact v$WORKSPACE_VERSION tag"
  REMOTE_TAG_SHA="$(remote_tag_sha)" || die "could not verify origin tag v$WORKSPACE_VERSION"
  readonly REMOTE_TAG_SHA
  [[ "$SOURCE_SHA" == "$REMOTE_TAG_SHA" ]] ||
    die "origin tag v$WORKSPACE_VERSION does not resolve to local HEAD"
  GITHUB_RELEASE_URL="$(verify_github_release_receipt)" ||
    die "could not verify the completed GitHub release for v$WORKSPACE_VERSION"
  readonly GITHUB_RELEASE_URL
  printf 'Authorized crates.io publication: version=%s source=%s release=%s\n' \
    "$WORKSPACE_VERSION" "$SOURCE_SHA" "$GITHUB_RELEASE_URL"
elif [[ "$ALLOW_DIRTY" -eq 0 && -n "$($GIT_BIN status --porcelain --untracked-files=all)" ]]; then
  die "verification requires a clean worktree (or explicit --allow-dirty)"
fi

printf 'Running locked source gates for Phantom %s...\n' "$WORKSPACE_VERSION"
"$CARGO_BIN" fmt --all -- --check
"$CARGO_BIN" clippy --workspace --all-targets --locked -- -D warnings
"$CARGO_BIN" test --workspace --all-targets --locked --no-fail-fast

readonly PACKAGE_DIR="$TMP_DIR/target/package"
mkdir -p -- "$PACKAGE_DIR"

file_sha256() {
  "$PYTHON_BIN" - "$1" <<'PY'
import hashlib
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
digest = hashlib.sha256()
with path.open("rb") as source:
    for chunk in iter(lambda: source.read(1024 * 1024), b""):
        digest.update(chunk)
print(digest.hexdigest())
PY
}

REMOTE_CHECKSUM=""
lookup_remote() {
  local crate="$1"
  local version="$2"
  local response="$TMP_DIR/crates-io-response.json"
  local status
  REMOTE_CHECKSUM=""
  status="$($CURL_BIN --silent --show-error --location \
    --proto '=https' --proto-redir '=https' --max-redirs 3 \
    --connect-timeout 10 --max-time 30 --max-filesize 1048576 \
    --output "$response" --write-out '%{http_code}' \
    "$REGISTRY_API/crates/$crate/$version")" || die "crates.io lookup failed for $crate@$version"
  case "$status" in
    200)
      REMOTE_CHECKSUM="$($PYTHON_BIN - "$response" "$crate" "$version" <<'PY'
import json
import pathlib
import re
import sys

payload = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
version = payload.get("version")
if not isinstance(version, dict):
    raise SystemExit("crates.io response has no version object")
if version.get("crate") != sys.argv[2] or version.get("num") != sys.argv[3]:
    raise SystemExit("crates.io response identity mismatch")
checksum = version.get("checksum", "")
if not re.fullmatch(r"[0-9a-f]{64}", checksum):
    raise SystemExit("crates.io response has an invalid checksum")
print(checksum)
PY
      )" || die "invalid crates.io response for $crate@$version"
      return 0
      ;;
    404)
      return 1
      ;;
    *)
      die "crates.io returned HTTP $status for $crate@$version"
      ;;
  esac
}

wait_for_registry_checksum() {
  local crate="$1"
  local version="$2"
  local checksum="$3"
  local timeout="${PHANTOM_PUBLISH_TIMEOUT_SECONDS:-180}"
  local interval="${PHANTOM_PUBLISH_POLL_INTERVAL_SECONDS:-5}"
  [[ "$timeout" =~ ^[1-9][0-9]*$ ]] || die "PHANTOM_PUBLISH_TIMEOUT_SECONDS must be a positive integer"
  [[ "$interval" =~ ^[1-9][0-9]*$ ]] || die "PHANTOM_PUBLISH_POLL_INTERVAL_SECONDS must be a positive integer"
  local deadline=$(( $(date +%s) + timeout ))
  while (( $(date +%s) <= deadline )); do
    if lookup_remote "$crate" "$version"; then
      [[ "$REMOTE_CHECKSUM" == "$checksum" ]] ||
        die "published checksum mismatch for $crate@$version"
      return 0
    fi
    sleep "$interval"
  done
  die "timed out waiting for crates.io to index $crate@$version"
}

declare -a LOCAL_CHECKSUMS=()
printf 'Packaging the closed %s-crate publication set...\n' "${#CRATES[@]}"
for crate in "${CRATES[@]}"; do
  package_args=(package --registry crates-io --locked --no-verify -p "$crate" "${PACKAGE_PATCH_ARGS[@]}")
  if [[ "$ALLOW_DIRTY" -eq 1 ]]; then
    package_args+=(--allow-dirty)
  fi
  CARGO_TARGET_DIR="$TMP_DIR/target" "$CARGO_BIN" "${package_args[@]}"
  archive="$PACKAGE_DIR/$crate-$WORKSPACE_VERSION.crate"
  [[ -f "$archive" && ! -L "$archive" ]] || die "cargo did not create the expected regular archive: $archive"
  LOCAL_CHECKSUMS+=("$(file_sha256 "$archive")")
done

if [[ "$MODE" == "verify-only" ]]; then
  printf 'Verified %s local crate packages for Phantom %s; publication state was not queried and nothing was published.\n' \
    "${#CRATES[@]}" "$WORKSPACE_VERSION"
  exit 0
fi

publish_count=0
skip_count=0
missing_count=0
for index in "${!CRATES[@]}"; do
  crate="${CRATES[$index]}"
  checksum="${LOCAL_CHECKSUMS[$index]}"
  printf '\n-- %s@%s --\n' "$crate" "$WORKSPACE_VERSION"
  if lookup_remote "$crate" "$WORKSPACE_VERSION"; then
    [[ "$REMOTE_CHECKSUM" == "$checksum" ]] ||
      die "immutable version collision: crates.io checksum differs for $crate@$WORKSPACE_VERSION"
    printf 'Already published with the identical checksum; skipping.\n'
    skip_count=$((skip_count + 1))
    continue
  fi

  if [[ "$MODE" == "dry-run" ]]; then
    printf 'Would publish (version is absent from crates.io).\n'
    missing_count=$((missing_count + 1))
    continue
  fi

  # Reconfirm source identity before every irreversible upload.
  [[ -z "$($GIT_BIN status --porcelain --untracked-files=all)" ]] ||
    die "worktree changed after authorization; refusing to publish $crate"
  [[ "$($GIT_BIN rev-parse --verify 'HEAD^{commit}')" == "$SOURCE_SHA" ]] ||
    die "HEAD changed after authorization; refusing to publish $crate"
  current_remote_tag_sha="$(remote_tag_sha)" ||
    die "origin tag v$WORKSPACE_VERSION became unavailable; refusing to publish $crate"
  [[ "$current_remote_tag_sha" == "$SOURCE_SHA" ]] ||
    die "origin tag v$WORKSPACE_VERSION changed after authorization; refusing to publish $crate"

  publish_args=(publish --registry crates-io --locked --no-verify -p "$crate")
  if [[ -n "$REGISTRY_TOKEN" ]]; then
    if CARGO_REGISTRY_TOKEN="$REGISTRY_TOKEN" "$CARGO_BIN" "${publish_args[@]}"; then
      publish_status=0
    else
      publish_status=$?
    fi
  else
    if "$CARGO_BIN" "${publish_args[@]}"; then
      publish_status=0
    else
      publish_status=$?
    fi
  fi
  if [[ "$publish_status" -eq 0 ]]; then
    wait_for_registry_checksum "$crate" "$WORKSPACE_VERSION" "$checksum"
    printf 'Published and checksum-verified.\n'
    publish_count=$((publish_count + 1))
  else
    # A concurrent publisher may have won the race. Accept that outcome only
    # when crates.io now exposes the exact package bytes we authorized.
    if lookup_remote "$crate" "$WORKSPACE_VERSION" && [[ "$REMOTE_CHECKSUM" == "$checksum" ]]; then
      printf 'A concurrent identical publication completed first; checksum verified.\n'
      skip_count=$((skip_count + 1))
    else
      die "cargo publish failed for $crate@$WORKSPACE_VERSION"
    fi
  fi
done

if [[ "$MODE" == "dry-run" ]]; then
  printf '\nDry run complete: %s identical already published, %s would publish, 0 uploaded.\n' \
    "$skip_count" "$missing_count"
else
  printf '\nPublication complete: %s published, %s identical already present.\n' \
    "$publish_count" "$skip_count"
  printf 'Verify installation separately with: cargo install phantom-secrets --version %s --locked\n' \
    "$WORKSPACE_VERSION"
fi
