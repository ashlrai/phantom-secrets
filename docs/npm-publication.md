# npm publication

This runbook stages, reviews, approves, accepts, and promotes Phantom's two thin
native-binary wrappers on the public npm registry. It does not use the direct
publication path or make `latest` point at unaccepted bytes.

For `0.7.4`, the required order is:

1. approve an exact clean source SHA;
2. complete the read-only release rehearsal;
3. create the human-approved annotated `v0.7.4` tag;
4. complete and verify the gated immutable GitHub Release for that tag;
5. recompute both package integrities and stage both versions under
   `release-candidate`;
6. inspect each staged record and downloaded tarball;
7. approve each stage interactively with human 2FA;
8. reconcile exact integrity and provenance;
9. pass exact-version npm acceptance on all six supported targets;
10. separately promote `phantom-secrets-mcp@0.7.4` to `latest`, then promote
    `phantom-secrets@0.7.4` to `latest`;
11. verify both promotions before removing both `release-candidate` tags; and
12. only then consider the separate
    [MCP Registry publication](mcp-registry-publication.md).

The wrappers download their exact-version native binary from the corresponding
GitHub Release on first use. Staging them before that release is complete would
reserve an unusable immutable npm version.

## Authority and authentication boundary

Local tests, `npm pack --dry-run`, public registry queries, stage listing,
stage viewing, and stage download are inspection steps. Staging reserves an
immutable package version in npm but does not make it publicly installable.
Stage approval publishes that version and requires interactive human 2FA.
Dist-tag addition/removal changes what unpinned users install. These are three
separate effect classes and need explicit authorization and receipts.

The maximum-security posture is a protected cloud-hosted OIDC workflow that is
registered as each package's trusted publisher with permission for
`npm stage publish` only, while package publishing access is set to **Require
two-factor authentication and disallow tokens**. npm then uses short-lived OIDC
credentials for staging, emits provenance automatically for a public package
from this public repository, and still requires a maintainer to approve each
stage with 2FA.

This repository does not currently contain or prove that protected npm staging
workflow, trusted-publisher registration, stage-only permission, or package
access setting. Do not claim OIDC or token denial is configured. Fail closed
until that governance is independently configured and verified, or obtain an
explicit exception approving a trusted human operator's authenticated npm
session for these exact two stages. The exception is a weaker posture and must
record that provenance may be absent; it never authorizes a long-lived or
bypass token.

Never put an npm credential or one-time password in source, command arguments,
shell history, an issue, an agent conversation, or a captured log. Keep shell
tracing and session capture disabled. Let `npm stage approve` prompt for 2FA in
the trusted terminal.

## Prerequisites

- Work from the exact clean `v0.7.4` checkout used for the GitHub Release.
- Bind `origin` to `ashlrai/phantom-secrets`, then verify the remote tag is an
  annotated tag object peeled to local `HEAD` and current remote `main`.
- Complete the artifact, attestation, and immutable-release checks in
  [Release and readiness](release-readiness.md).
- Confirm both package names already exist and the operator has write access;
  npm staged publishing does not bootstrap a new package name.
- Use Node.js `22.14.0` or later and npm CLI `11.15.0` or later.
- Require 2FA on the approving maintainer account.
- Confirm both manifests declare public access and
  `https://registry.npmjs.org/` in `publishConfig`.

## Read-only source and package plan

Run from the repository root. The canonical-origin case must pass before any
remote identity is trusted:

```bash
VERSION=0.7.4
TAG="v${VERSION}"
SOURCE_SHA="$(git rev-parse HEAD)"
ORIGIN_URL="$(git remote get-url origin)"

case "${ORIGIN_URL}" in
  https://github.com/ashlrai/phantom-secrets.git|git@github.com:ashlrai/phantom-secrets.git|ssh://git@github.com/ashlrai/phantom-secrets.git) ;;
  *) echo "origin is not canonical" >&2; exit 1 ;;
esac

test -z "$(git status --porcelain=v1)"
test "${SOURCE_SHA}" = "$(git rev-parse "${TAG}^{commit}")"
node scripts/release/verify-github-tag-binding.mjs "${TAG}" "${SOURCE_SHA}"
node scripts/release/check-version-parity.mjs "${TAG}"
gh release view "${TAG}" --repo ashlrai/phantom-secrets \
  --json tagName,isDraft,isPrerelease,isImmutable,assets,url

node --version
npm --version
(cd npm && npm test && npm pack --dry-run --json)
(cd npm-mcp && npm test && npm pack --dry-run --json)

npm view "phantom-secrets@${VERSION}" version dist.integrity dist.tarball \
  --json --registry=https://registry.npmjs.org/
npm view "phantom-secrets-mcp@${VERSION}" version dist.integrity dist.tarball \
  --json --registry=https://registry.npmjs.org/
```

Require Node and npm to meet the minimums; a lexical string comparison is not a
version check. Review each pack result for one package with `entryCount: 5` and
exactly these sorted files: `LICENSE`, `README.md`, `bin/cli.js`, `install.js`,
and `package.json`. Record each approved `integrity` value.

A missing exact public npm version is the expected pre-stage state. An existing
exact version or stage reserves that immutable name/version. Reconcile it and
never attempt to overwrite or re-stage it.

## Recompute and stage both candidates

Staging is an external write. Immediately before authorization, repeat the
clean-source, canonical-origin, annotated-tag, release, version-parity, package
test, and registry-absence checks. Pack each package exactly once into a private
temporary directory, then require its filename, file closure, and integrity to
equal the approved plan. The tarballs from this one pack operation are the only
inputs authorized for staging; do not let `npm stage` silently repack a package
directory.

Replace the two approved-integrity placeholders with the exact SHA-512 SRI
values recorded during planning, then create and validate the stage inputs:

```bash
set -euo pipefail

VERSION=0.7.4
TAG="v${VERSION}"
SOURCE_SHA="$(git rev-parse HEAD)"
APPROVED_PRIMARY_INTEGRITY="sha512-copy-approved-primary-integrity"
APPROVED_MCP_INTEGRITY="sha512-copy-approved-mcp-integrity"

NPM_STAGE_DIR="$(mktemp -d)"
chmod 700 "${NPM_STAGE_DIR}"
cleanup_npm_stage() { rm -rf -- "${NPM_STAGE_DIR}"; }
trap cleanup_npm_stage EXIT HUP INT TERM

PRIMARY_TARBALL="${NPM_STAGE_DIR}/phantom-secrets-${VERSION}.tgz"
MCP_TARBALL="${NPM_STAGE_DIR}/phantom-secrets-mcp-${VERSION}.tgz"
PRIMARY_PACK_RECEIPT="${NPM_STAGE_DIR}/primary-pack.json"
MCP_PACK_RECEIPT="${NPM_STAGE_DIR}/mcp-pack.json"

(cd npm && npm pack --json --pack-destination "${NPM_STAGE_DIR}") \
  >"${PRIMARY_PACK_RECEIPT}"
(cd npm-mcp && npm pack --json --pack-destination "${NPM_STAGE_DIR}") \
  >"${MCP_PACK_RECEIPT}"

node - "${PRIMARY_PACK_RECEIPT}" phantom-secrets "${VERSION}" \
  "${APPROVED_PRIMARY_INTEGRITY}" <<'NODE'
const fs = require("fs");
const [receiptPath, name, version, approvedIntegrity] = process.argv.slice(2);
const packs = JSON.parse(fs.readFileSync(receiptPath, "utf8"));
const expectedFiles = ["LICENSE", "README.md", "bin/cli.js", "install.js", "package.json"];
if (packs.length !== 1 || packs[0].name !== name || packs[0].version !== version ||
    packs[0].filename !== `${name}-${version}.tgz` || packs[0].entryCount !== 5 ||
    JSON.stringify(packs[0].files.map(({path}) => path).sort()) !== JSON.stringify(expectedFiles) ||
    packs[0].integrity !== approvedIntegrity) process.exit(1);
NODE

node - "${MCP_PACK_RECEIPT}" phantom-secrets-mcp "${VERSION}" \
  "${APPROVED_MCP_INTEGRITY}" <<'NODE'
const fs = require("fs");
const [receiptPath, name, version, approvedIntegrity] = process.argv.slice(2);
const packs = JSON.parse(fs.readFileSync(receiptPath, "utf8"));
const expectedFiles = ["LICENSE", "README.md", "bin/cli.js", "install.js", "package.json"];
if (packs.length !== 1 || packs[0].name !== name || packs[0].version !== version ||
    packs[0].filename !== `${name}-${version}.tgz` || packs[0].entryCount !== 5 ||
    JSON.stringify(packs[0].files.map(({path}) => path).sort()) !== JSON.stringify(expectedFiles) ||
    packs[0].integrity !== approvedIntegrity) process.exit(1);
NODE

test -f "${PRIMARY_TARBALL}"
test -f "${MCP_TARBALL}"
```

After packing, recheck the exact clean canonical source, annotated remote tag,
immutable release, and registry absence. Do not edit, generate, install, or pack
again between these checks and staging:

```bash
ORIGIN_URL="$(git remote get-url origin)"
case "${ORIGIN_URL}" in
  https://github.com/ashlrai/phantom-secrets.git|git@github.com:ashlrai/phantom-secrets.git|ssh://git@github.com/ashlrai/phantom-secrets.git) ;;
  *) echo "origin is not canonical" >&2; exit 1 ;;
esac

test -z "$(git status --porcelain=v1)"
test "${SOURCE_SHA}" = "$(git rev-parse HEAD)"
test "${SOURCE_SHA}" = "$(git rev-parse "${TAG}^{commit}")"
node scripts/release/verify-github-tag-binding.mjs "${TAG}" "${SOURCE_SHA}"
node scripts/release/check-version-parity.mjs "${TAG}"
gh release view "${TAG}" --repo ashlrai/phantom-secrets \
  --json tagName,isDraft,isPrerelease,isImmutable,assets,url

assert_unpublished_npm_version() {
  PACKAGE_NAME="$1"
  if npm view "${PACKAGE_NAME}@${VERSION}" version --json \
    --registry=https://registry.npmjs.org/ >/dev/null 2>&1; then
    echo "${PACKAGE_NAME}@${VERSION} is already public" >&2
    return 1
  fi
  ALL_VERSIONS_JSON="$(npm view "${PACKAGE_NAME}" versions --json \
    --registry=https://registry.npmjs.org/)"
  node -e 'const [j,v]=process.argv.slice(1); const x=JSON.parse(j); if((Array.isArray(x)?x:[x]).includes(v)) process.exit(1)' \
    "${ALL_VERSIONS_JSON}" "${VERSION}"
}
assert_unpublished_npm_version phantom-secrets
assert_unpublished_npm_version phantom-secrets-mcp
npm stage list phantom-secrets --json --registry=https://registry.npmjs.org/
npm stage list phantom-secrets-mcp --json --registry=https://registry.npmjs.org/
```

A missing exact public version and absent stage remain required. After the exact
two stage effects are approved, submit the explicit reviewed tarball paths under
the non-default candidate tag:

```bash
npm stage publish "${PRIMARY_TARBALL}" --tag release-candidate \
  --registry=https://registry.npmjs.org/ --access public

npm stage publish "${MCP_TARBALL}" --tag release-candidate \
  --registry=https://registry.npmjs.org/ --access public
```

The pack receipts are the final source-side integrity receipts. They do not
replace inspection of npm's staged tarballs. Do not omit the explicit tarball
argument or tag: a directory input could be repacked and npm's default tag would
otherwise be `latest`.

## Review both stages before approval

List the stages, copy the two exact stage IDs into local shell variables, and
inspect each record. Stage list, view, and download do not require 2FA:

```bash
npm stage list phantom-secrets --json --registry=https://registry.npmjs.org/
npm stage list phantom-secrets-mcp --json --registry=https://registry.npmjs.org/

PRIMARY_STAGE_ID="reviewed-primary-stage-id"
MCP_STAGE_ID="reviewed-mcp-stage-id"
npm stage view "${PRIMARY_STAGE_ID}" --json --registry=https://registry.npmjs.org/
npm stage view "${MCP_STAGE_ID}" --json --registry=https://registry.npmjs.org/

STAGE_REVIEW_DIR="$(mktemp -d)"
(cd "${STAGE_REVIEW_DIR}" && \
  npm stage download "${PRIMARY_STAGE_ID}" --json --registry=https://registry.npmjs.org/)
(cd "${STAGE_REVIEW_DIR}" && \
  npm stage download "${MCP_STAGE_ID}" --json --registry=https://registry.npmjs.org/)
```

Require each stage to name the exact package, `0.7.4`, public access, and
`release-candidate`. Use the download JSON to identify each tarball, calculate
its SHA-512 SRI value, and require it to equal the immediately preceding
pack receipt integrity. For example:

```bash
node -e 'const fs=require("fs"),c=require("crypto"); for(const p of process.argv.slice(1)) console.log(p,"sha512-"+c.createHash("sha512").update(fs.readFileSync(p)).digest("base64"))' \
  "${STAGE_REVIEW_DIR}/downloaded-primary.tgz" \
  "${STAGE_REVIEW_DIR}/downloaded-mcp.tgz"
```

Replace the example filenames with the exact paths reported by the download
commands. Rejecting a bad stage is itself a permanent, 2FA-gated effect. Stop
and request separate rejection authorization rather than improvising a retry.

## Approve each stage with interactive 2FA

Approval publishes the immutable version under `release-candidate`. Re-run
both stage views immediately before approval. After separate human approval of
each exact stage ID and downloaded integrity, use the trusted terminal:

```bash
npm stage approve "${MCP_STAGE_ID}" --registry=https://registry.npmjs.org/
npm stage approve "${PRIMARY_STAGE_ID}" --registry=https://registry.npmjs.org/
```

Do not supply an OTP flag. Enter 2FA only at npm's interactive prompt. If a
command times out or loses its response, query the exact public version and
stage ID before retrying.

## Reconcile integrity and provenance

For both approved versions, require exact agreement between the final pack,
downloaded staged tarball, and public `dist.integrity`:

```bash
npm view phantom-secrets@0.7.4 version dist.integrity dist.tarball dist.attestations \
  --json --registry=https://registry.npmjs.org/
npm view phantom-secrets-mcp@0.7.4 version dist.integrity dist.tarball dist.attestations \
  --json --registry=https://registry.npmjs.org/
npm view phantom-secrets dist-tags --json --registry=https://registry.npmjs.org/
npm view phantom-secrets-mcp dist-tags --json --registry=https://registry.npmjs.org/
```

Both `release-candidate` tags must point to `0.7.4`; neither `latest` tag should
have changed. For the preferred OIDC path, require npm provenance for both
packages and verify the downloaded exact packages with `npm audit signatures`
using the current npm CLI. A manual-session exception may lack provenance;
record that absence and the exact approving exception, and do not describe the
packages as provenance-verified.

Record source SHA, annotated tag, GitHub Release URL, stage ID, final-pack and
downloaded-stage integrity, public integrity/tarball, provenance result,
candidate dist-tag, timestamp, operator, and pass/fail. Never record an npm
credential, OTP, npm configuration file, or credential-bearing output.

## Run six-target exact-version acceptance

Before changing `latest`, run both wrappers from the exact `0.7.4` versions on
fresh disposable hosts for all six targets:

| Target | Required host class |
|---|---|
| macOS x64 | `macos-15-intel` |
| macOS arm64 | `macos-15` |
| GNU Linux x64 | `ubuntu-22.04` |
| GNU Linux arm64 | `ubuntu-22.04-arm` |
| Windows x64 | `windows-latest` |
| Windows arm64 | `windows-11-vs2026-arm` |

On each host, assert the resolved OS and architecture, Node `>=22.14.0`, and npm
`>=11.15.0`, then execute the exact packages from the public registry:

```bash
npm exec --yes --package=phantom-secrets-mcp@0.7.4 \
  --registry=https://registry.npmjs.org/ -- phantom-mcp --version
npm exec --yes --package=phantom-secrets@0.7.4 \
  --registry=https://registry.npmjs.org/ -- phantom --version
```

Require exact `phantom-mcp 0.7.4` and `phantom 0.7.4` output. Fresh hosts are
required so the wrappers exercise first-use archive download, checksum
verification, extraction, cache receipt, and execution rather than accepting a
pre-existing binary. Preserve all six immutable job URLs, resolved runner
images, OS/architecture assertions, npm/Node versions, and command results.
Source tests or GitHub native-archive acceptance are not substitutes for this
npm-channel receipt.

## Promote default tags after acceptance

Dist-tag changes are separate public effects. After all six rows and both
integrity/provenance reconciliations pass, approve and add `latest` to the MCP
wrapper first. Set both previous-version placeholders from the approved
pre-promotion receipt. Immediately before the MCP change, fetch both current
tag maps and require both prior `latest` values plus both candidate values;
stop on any drift:

```bash
set -euo pipefail

PREVIOUS_MCP_LATEST="copy-approved-previous-version"
PREVIOUS_PRIMARY_LATEST="copy-approved-previous-version"
MCP_TAGS_JSON="$(npm view phantom-secrets-mcp dist-tags --json --registry=https://registry.npmjs.org/)"
PRIMARY_TAGS_JSON="$(npm view phantom-secrets dist-tags --json --registry=https://registry.npmjs.org/)"
node -e 'const [m,p,oldM,oldP,v]=process.argv.slice(1); const mt=JSON.parse(m),pt=JSON.parse(p); if(mt.latest!==oldM||pt.latest!==oldP||mt["release-candidate"]!==v||pt["release-candidate"]!==v) process.exit(1)' \
  "${MCP_TAGS_JSON}" "${PRIMARY_TAGS_JSON}" \
  "${PREVIOUS_MCP_LATEST}" "${PREVIOUS_PRIMARY_LATEST}" "${VERSION}"
npm dist-tag add "phantom-secrets-mcp@${VERSION}" latest --registry=https://registry.npmjs.org/
npm view phantom-secrets-mcp dist-tags --json --registry=https://registry.npmjs.org/
```

Only after that query proves `latest: 0.7.4`, separately approve and promote
the primary CLI last. Immediately before its change, re-fetch both tag maps and
require MCP `latest` to be the new version, primary `latest` to remain at the
approved previous version, and both candidate tags to remain exact:

```bash
MCP_TAGS_JSON="$(npm view phantom-secrets-mcp dist-tags --json --registry=https://registry.npmjs.org/)"
PRIMARY_TAGS_JSON="$(npm view phantom-secrets dist-tags --json --registry=https://registry.npmjs.org/)"
node -e 'const [m,p,oldP,v]=process.argv.slice(1); const mt=JSON.parse(m),pt=JSON.parse(p); if(mt.latest!==v||pt.latest!==oldP||mt["release-candidate"]!==v||pt["release-candidate"]!==v) process.exit(1)' \
  "${MCP_TAGS_JSON}" "${PRIMARY_TAGS_JSON}" \
  "${PREVIOUS_PRIMARY_LATEST}" "${VERSION}"
npm dist-tag add "phantom-secrets@${VERSION}" latest --registry=https://registry.npmjs.org/
npm view phantom-secrets dist-tags --json --registry=https://registry.npmjs.org/
```

After both `latest` tags are verified, separately approve removal of the
temporary candidate tags. Immediately before the first removal, re-fetch both
maps and require both `latest` and both candidate tags to remain exact:

```bash
MCP_TAGS_JSON="$(npm view phantom-secrets-mcp dist-tags --json --registry=https://registry.npmjs.org/)"
PRIMARY_TAGS_JSON="$(npm view phantom-secrets dist-tags --json --registry=https://registry.npmjs.org/)"
node -e 'const [m,p,v]=process.argv.slice(1); const mt=JSON.parse(m),pt=JSON.parse(p); if(mt.latest!==v||pt.latest!==v||mt["release-candidate"]!==v||pt["release-candidate"]!==v) process.exit(1)' \
  "${MCP_TAGS_JSON}" "${PRIMARY_TAGS_JSON}" "${VERSION}"
npm dist-tag rm phantom-secrets-mcp release-candidate --registry=https://registry.npmjs.org/

MCP_TAGS_JSON="$(npm view phantom-secrets-mcp dist-tags --json --registry=https://registry.npmjs.org/)"
PRIMARY_TAGS_JSON="$(npm view phantom-secrets dist-tags --json --registry=https://registry.npmjs.org/)"
node -e 'const [m,p,v]=process.argv.slice(1); const mt=JSON.parse(m),pt=JSON.parse(p); if(mt.latest!==v||pt.latest!==v||Object.hasOwn(mt,"release-candidate")||pt["release-candidate"]!==v) process.exit(1)' \
  "${MCP_TAGS_JSON}" "${PRIMARY_TAGS_JSON}" "${VERSION}"
npm dist-tag rm phantom-secrets release-candidate --registry=https://registry.npmjs.org/
npm view phantom-secrets-mcp dist-tags --json --registry=https://registry.npmjs.org/
npm view phantom-secrets dist-tags --json --registry=https://registry.npmjs.org/
```

The second precondition necessarily requires the already removed MCP candidate
to be absent while the primary candidate remains exact. Any other state is
drift; stop rather than deleting another tag.

Require both final maps to retain `latest: 0.7.4` and omit
`release-candidate`. Only then is npm distribution complete.

## Partial failure and recovery

- If only one stage is created, leave it non-public, reconcile its exact ID and
  integrity, fix the other blocker, then resume. Do not re-stage a reserved
  version.
- If only one stage is approved, leave its `release-candidate` tag in place and
  do not promote it. Reconcile the other stage before continuing.
- If stage approval times out, query both the stage and exact public version.
  Matching public integrity means approval completed; do not approve twice.
- If public integrity differs from the approved stage, stop. Publish a higher
  fix-forward version after a new source/tag/GitHub cycle.
- If provenance is required by the selected OIDC posture but absent or invalid,
  stop before native acceptance or promotion. A manual exception must be
  explicit and must not claim provenance.
- If any acceptance row fails, leave both versions under `release-candidate`.
  Do not change `latest`; investigate and fix forward.
- If MCP `latest` changes but primary promotion fails, reconcile the primary
  blocker before retrying. Rolling MCP back is a separate dist-tag effect and
  requires separate approval.
- If candidate-tag removal fails after both promotions, verify both `latest`
  tags remain correct, then retry only the failed removal under authorization.
- Deprecation, stage rejection, unpublication, and rollback are separate
  consequential actions and are not authorized by this runbook.

See npm's official [staged publishing guide](https://docs.npmjs.com/staged-publishing/),
[`npm stage` reference](https://docs.npmjs.com/cli/v11/commands/npm-stage/),
[trusted publishing guide](https://docs.npmjs.com/trusted-publishers/), and
[provenance verification guide](https://docs.npmjs.com/generating-provenance-statements/).
