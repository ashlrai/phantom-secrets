# MCP Registry publication

This runbook publishes Phantom's server metadata to the official MCP Registry.
It does not publish a native binary or npm wrapper. The manifest points to
`phantom-secrets-mcp@0.7.4`, so the exact accepted npm package and immutable
GitHub Release must be available first.

For `0.7.4`, the required order is:

1. verify the exact canonical source, annotated remote tag, and GitHub Release;
2. complete all staging, integrity/provenance, six-target acceptance, and
   dist-tag gates in the [npm publication runbook](npm-publication.md);
3. query the MCP Registry including deleted versions;
4. separately approve interactive login and exact manifest publication; and
5. reconcile the public active entry before claiming registry publication.

MCP Registry publication is a metadata/discovery effect. It does not prove that
an MCP client installed the package, that the native binary ran on a particular
host, or that any effectful MCP operation was authorized or accepted.

## Authority and authentication boundary

Source checks, local manifest validation, npm reads, and public MCP Registry
queries are inspection steps. Interactive login creates credential state in
the operator's home directory. Publishing writes public registry metadata.
Login and publication are separate effects and require explicit approval for
the exact registry, namespace, version, manifest, source SHA, and npm receipt.

The preferred future posture is a protected, GitHub-hosted OIDC workflow with
`id-token: write`, a required environment reviewer, exact-tag source binding,
and `mcp-publisher login github-oidc --registry=...`. This repository does not
currently contain or prove that MCP publication workflow or its environment
governance. Do not claim MCP Registry OIDC is configured. The current documented
path is an explicitly approved interactive GitHub login in a trusted terminal,
using an ephemeral private home that is logged out and deleted on exit.

Never pass an MCP Registry token, GitHub token, private key, npm credential, or
one-time password on the command line. Never print, tee, trace, or copy one into
logs, source, issues, receipts, or agent context. Keep shell tracing and session
capture disabled.

## Prerequisites

- Work from the exact clean `v0.7.4` checkout used for the immutable GitHub
  Release and accepted npm packages.
- Bind `origin` to `ashlrai/phantom-secrets`, then verify the remote tag is an
  annotated object peeled to local `HEAD` and current remote `main`.
- Verify `mcp-registry/server.json`, `npm-mcp/package.json`, and runtime MCP
  schema all describe `0.7.4`; the release gate performs the deeper stdio/schema
  parity smoke.
- Require `phantom-secrets-mcp@0.7.4` exact integrity, accepted six-target npm
  receipts, and `latest: 0.7.4` before registry login.
- Confirm the trusted operator is authorized for the
  `io.github.ashlrai/*` namespace.
- Use an x86_64 Linux trusted operator host. The repository script pins the
  Linux x64 `mcp-publisher` 1.8.1 archive and digest; it is not a portable macOS
  or Windows installer. Do not substitute a mutable download.
- Require GNU `timeout`, `sha256sum`, `curl`, `jq`, and `cmp` on the trusted
  host.

## Create an ephemeral operator session

Run from the repository root. Each path is created by `mktemp`, made private,
and removed only by the installed trap. `HOME` is overridden only for publisher
authentication subprocesses so credentials cannot enter the operator's normal
home:

```bash
set -euo pipefail

MCP_REGISTRY_URL="https://registry.modelcontextprotocol.io"
MCP_HOME="$(mktemp -d)"
PUBLISHER_DIR="$(mktemp -d)"
MCP_RECEIPT_DIR="$(mktemp -d)"
chmod 700 "${MCP_HOME}" "${PUBLISHER_DIR}" "${MCP_RECEIPT_DIR}"

cleanup_mcp_publish() {
  set +e
  if [ -x "${PUBLISHER_DIR}/mcp-publisher" ]; then
    if ! (
      cd "${MCP_HOME}" || exit 1
      env HOME="${MCP_HOME}" timeout 30s \
        "${PUBLISHER_DIR}/mcp-publisher" logout >/dev/null 2>&1
    ); then
      echo "WARNING: MCP publisher logout failed; record logout_failed=true externally" >&2
    fi
  fi
  rm -rf -- "${MCP_HOME}" "${PUBLISHER_DIR}" "${MCP_RECEIPT_DIR}"
}
trap cleanup_mcp_publish EXIT HUP INT TERM
```

Do not disable or bypass the trap. If the shell terminates before logout,
deleting the ephemeral home remains the local credential-recovery action.
The pinned publisher also removes legacy credential files from its current
working directory during logout, so logout must run from inside `MCP_HOME`,
never the repository. Logout deletes local credential material; it does not
revoke an already issued registry token on the server.
The cleanup emits only the fixed value-free warning above when logout fails;
publisher output remains suppressed. The operator must copy
`logout_failed=true` into the release receipt outside these temporary
directories before closing the trusted terminal. No automatic receipt survives
cleanup.

## Read-only source and registry plan

The canonical-origin case must pass before the remote tag or branch is trusted:

```bash
VERSION=0.7.4
TAG="v${VERSION}"
SOURCE_SHA="$(git rev-parse HEAD)"
ORIGIN_URL="$(git remote get-url origin)"
MCP_VERSION_URL="${MCP_REGISTRY_URL}/v0.1/servers/io.github.ashlrai%2Fphantom-secrets-mcp/versions/${VERSION}?include_deleted=true"
MCP_BODY="${MCP_RECEIPT_DIR}/mcp-version.json"

case "${ORIGIN_URL}" in
  https://github.com/ashlrai/phantom-secrets.git|git@github.com:ashlrai/phantom-secrets.git|ssh://git@github.com/ashlrai/phantom-secrets.git) ;;
  *) echo "origin is not canonical" >&2; exit 1 ;;
esac

test "$(uname -s)-$(uname -m)" = "Linux-x86_64"
test -z "$(git status --porcelain=v1)"
test "${SOURCE_SHA}" = "$(git rev-parse "${TAG}^{commit}")"
node scripts/release/verify-github-tag-binding.mjs "${TAG}" "${SOURCE_SHA}"
node scripts/release/check-version-parity.mjs "${TAG}"
npm view "phantom-secrets-mcp@${VERSION}" \
  version dist.integrity dist.tarball dist.attestations \
  --json --registry=https://registry.npmjs.org/
npm view phantom-secrets-mcp dist-tags \
  --json --registry=https://registry.npmjs.org/

timeout 180s ./scripts/release/install-mcp-publisher.sh "${PUBLISHER_DIR}"
env HOME="${MCP_HOME}" timeout 60s "${PUBLISHER_DIR}/mcp-publisher" \
  validate mcp-registry/server.json
PLANNED_MCP_MANIFEST_SHA256="$(sha256sum mcp-registry/server.json | awk '{print $1}')"

if ! MCP_HTTP_STATUS="$(timeout 45s curl \
  --proto '=https' --tlsv1.2 --silent --show-error \
  --connect-timeout 10 --max-time 30 --max-filesize 1048576 \
  --output "${MCP_BODY}" --write-out '%{http_code}' \
  "${MCP_VERSION_URL}")"; then
  echo "MCP Registry query failed" >&2
  exit 1
fi

case "${MCP_HTTP_STATUS}" in
  200)
    jq -e '.server.name == "io.github.ashlrai/phantom-secrets-mcp" and
      .server.version == "0.7.4"' "${MCP_BODY}" >/dev/null
    echo "version exists; reconcile status and every manifest field"
    ;;
  404)
    jq -e 'type == "object"' "${MCP_BODY}" >/dev/null
    echo "version is absent, including deleted records"
    ;;
  *)
    echo "unexpected MCP Registry HTTP ${MCP_HTTP_STATUS}" >&2
    jq . "${MCP_BODY}" >&2 || true
    exit 1
    ;;
esac
```

The `include_deleted=true` query prevents a deleted `0.7.4` record from looking
available for reuse. An HTTP `200` with active, deprecated, or deleted status
means the version already exists. Compare `server.name`, `server.version`,
repository, package identifier/version/registry, stdio transport, and official
status with the reviewed manifest and receipt. Treat an exact active match as
complete. Conflicting, deprecated, or deleted state blocks a new publish and
requires separate lifecycle review. Only a clean JSON HTTP `404` proves
version absence.

## Human-approved interactive effect

Immediately before login, repeat the npm and MCP exact-version queries. After a
human approves the exact manifest digest, interactive session, and public write,
set the approved digest explicitly, rehash the manifest, and revalidate it with
the pinned publisher. Do not edit the manifest between validation and publish.
Only then authenticate to the explicit official registry and publish with
bounded commands:

```bash
APPROVED_MCP_MANIFEST_SHA256="copy-approved-plan-digest"
test "$(sha256sum mcp-registry/server.json | awk '{print $1}')" = \
  "${APPROVED_MCP_MANIFEST_SHA256}"
test "${PLANNED_MCP_MANIFEST_SHA256}" = "${APPROVED_MCP_MANIFEST_SHA256}"
env HOME="${MCP_HOME}" timeout 60s "${PUBLISHER_DIR}/mcp-publisher" \
  validate mcp-registry/server.json

env HOME="${MCP_HOME}" timeout 300s \
  "${PUBLISHER_DIR}/mcp-publisher" login github \
  --registry="${MCP_REGISTRY_URL}"

test -z "$(git status --porcelain=v1)"
test "${SOURCE_SHA}" = "$(git rev-parse HEAD)"
test "${SOURCE_SHA}" = "$(git rev-parse "${TAG}^{commit}")"
node scripts/release/verify-github-tag-binding.mjs "${TAG}" "${SOURCE_SHA}"
test "$(sha256sum mcp-registry/server.json | awk '{print $1}')" = \
  "${APPROVED_MCP_MANIFEST_SHA256}"
env HOME="${MCP_HOME}" timeout 60s "${PUBLISHER_DIR}/mcp-publisher" \
  validate mcp-registry/server.json
env HOME="${MCP_HOME}" timeout 120s \
  "${PUBLISHER_DIR}/mcp-publisher" publish mcp-registry/server.json
```

Do not replace the browser login with a token argument. A successful login is
not publication evidence. `publish` reads the registry from the credential state
created by the explicit login; it does not accept a registry flag. The exit trap
logs out that stored authentication session and deletes all ephemeral state
whether publication succeeds or fails. Public reconciliation remains bound to
the independently fixed official URL.

## Reconcile the public effect

Repeat the bounded status/body query with `include_deleted=true`; do not mix the
HTTP status into the JSON body:

```bash
if ! MCP_HTTP_STATUS="$(timeout 45s curl \
  --proto '=https' --tlsv1.2 --silent --show-error \
  --connect-timeout 10 --max-time 30 --max-filesize 1048576 \
  --output "${MCP_BODY}" --write-out '%{http_code}' \
  "${MCP_VERSION_URL}")"; then
  echo "MCP Registry reconciliation failed" >&2
  exit 1
fi

case "${MCP_HTTP_STATUS}" in
  200)
    REVIEWED_SERVER_NORMALIZED="${MCP_RECEIPT_DIR}/reviewed-server.normalized.json"
    PUBLIC_SERVER_NORMALIZED="${MCP_RECEIPT_DIR}/public-server.normalized.json"
    jq -S 'del(._meta["io.modelcontextprotocol.registry/official"]) |
      if ._meta? == {} then del(._meta) else . end' \
      mcp-registry/server.json >"${REVIEWED_SERVER_NORMALIZED}"
    jq -S '.server |
      del(._meta["io.modelcontextprotocol.registry/official"]) |
      if ._meta? == {} then del(._meta) else . end' \
      "${MCP_BODY}" >"${PUBLIC_SERVER_NORMALIZED}"
    cmp --silent "${REVIEWED_SERVER_NORMALIZED}" "${PUBLIC_SERVER_NORMALIZED}"
    jq -e '._meta["io.modelcontextprotocol.registry/official"].status == "active"' \
      "${MCP_BODY}" >/dev/null
    ;;
  *)
    echo "expected active MCP Registry 0.7.4, got HTTP ${MCP_HTTP_STATUS}" >&2
    jq . "${MCP_BODY}" >&2 || true
    exit 1
    ;;
esac
```

The sorted deep comparison preserves every reviewed manifest field—including
schema, descriptions, repository identity, complete tool schemas, package
metadata, and any publisher-provided extensions. It removes only the official
registry-generated metadata namespace before comparison, then checks lifecycle
status separately. Do not normalize away unknown fields, array order, or any
publisher-provided metadata.

Independently re-query `phantom-secrets-mcp@0.7.4` and its `latest` dist-tag.
Record the source SHA, annotated tag, GitHub Release URL, npm integrity and
provenance status, MCP server name/version, public JSON response, timestamp,
operator, and pass/fail. Do not record authentication state, credentials,
one-time passwords, or files from the ephemeral home.

An exact MCP Registry receipt proves only that public metadata version. It does
not prove native execution, installation, provider activation, hosted
deployment, or an authenticated user workflow.

## Partial failure and recovery

- If login succeeds but publication does not start, reconcile public state
  before retrying. Authentication success is not publication success.
- If publication times out or loses its response, run the clean status/body
  query. Treat an exact active match as success and do not republish blindly.
- If npm is complete but MCP Registry publication fails, leave immutable npm
  state unchanged. Resolve the registry blocker and resume from inspection.
- If `0.7.4` exists as deleted, deprecated, or conflicting metadata, stop. The
  official registry does not support overwriting that version; prepare a higher
  fix-forward source/npm/MCP version.
- Lifecycle-status changes require a separate approval and are not authorized
  by this runbook.
- If logout fails, preserve the failure in the operator receipt while deleting
  the ephemeral home. The fixed `logout_failed=true` warning is observable but
  is not persisted by the cleanup; record it outside the temporary directories.
  Do not reuse that home or claim clean logout.

The official MCP Registry documents the publisher commands in its
[CLI reference](https://github.com/modelcontextprotocol/registry/blob/main/docs/reference/cli/commands.md)
and the read endpoints in its
[API specification](https://github.com/modelcontextprotocol/registry/blob/main/docs/reference/api/openapi.yaml).
