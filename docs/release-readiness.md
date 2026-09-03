# Release and readiness

This guide records what the current repository automates and what still needs
separate evidence. It does not authorize a tag, package publication, Homebrew
update, signing operation, provider consent, or deployment.

## Current automated release path

A `v*` tag starts `.github/workflows/release.yml`. Its tag-only wrapper delegates
the read-only build and verification graph to
`.github/workflows/release-build.yml`, then retains the gated attestation and
release jobs. Together they:

1. verifies exact `v<semver>` parity across the release metadata surfaces;
2. runs checksum-verified Gitleaks and cargo-deny, locked all-target workspace
   tests, formatting, strict Clippy, installer and wrapper tests, package
   inspections, the full web install/audit/lint/test/build gate, and the MCP
   schema/stdio smoke;
3. builds six targets: macOS, GNU Linux, and Windows on `arm64`/`x64`;
4. creates an archive containing exactly `phantom` and `phantom-mcp`;
5. downloads each named build artifact onto a matching standard GitHub runner
   (`macos-15-intel`, `macos-15`, `ubuntu-22.04`, `ubuntu-22.04-arm`,
   `windows-latest`, or `windows-11-vs2026-arm`), re-verifies the closed archive
   and extracted file set, asserts both the runner and Node runtime OS/architecture,
   checks both binaries' exact tag-bound `--version`, and runs the MCP stdio
   schema smoke against the extracted `phantom-mcp`;
6. runs the real direct installer against that same local archive on every
   matching runner, verifies the installed pair and source receipt, injects a
   test-only failure immediately after candidate promotion, and proves the
   sentinel-bearing accepted installation is restored with no sibling
   transaction residue; it then corrupts the checksum sidecar and proves that
   the pre-transaction failure also preserves the accepted installation;
   Windows acceptance explicitly skips persistent user-PATH mutation while
   preserving the install transaction;
7. downloads the host-specific Syft 1.42.3 release archive, verifies its exact
   SHA-256 from Anchore's official checksum manifest, and invokes that verified
   binary to scan each exact archive into an SPDX 2.3 JSON SBOM;
8. generates a SHA-256 sidecar for every archive plus an aggregate
   `SHA256SUMS`;
9. verifies the exact archive, sidecar, SBOM, aggregate-checksum, member-name,
   and member-type contract;
10. requests one GitHub build-provenance attestation covering the six exact
   archive digests and one SBOM attestation binding each archive to its matching
   SPDX document; and
11. re-verifies the preserved bundle before creating a non-overwriting GitHub
   release.

Third-party actions are pinned. Build jobs use read-only repository permissions;
only the attestation job receives `id-token: write` and `attestations: write`,
and only the release job receives `contents: write`. That write-capable job
targets the GitHub `release` environment. Repository administrators must
configure that environment with a required human reviewer before creating a
release tag; naming an environment in workflow source does not create a review
rule by itself.

The build matrix may cross-compile, but it cannot authorize attestation directly.
A separate six-row native-acceptance matrix downloads each exact build artifact
onto the matching OS and architecture and must complete both archive execution
and the isolated direct-installer transaction before attestation.

## Rehearse the release without a tag

`.github/workflows/release-rehearsal.yml` calls the same reusable source
verification, six-target build, native acceptance, checksum, archive, and SBOM
graph without creating a tag. The caller and `.github/workflows/release-build.yml`
retain `contents: read`; attestation and immutable-release jobs exist only in
the tag-push wrapper and therefore cannot enter a rehearsal run. This is the
preferred way to find release-only platform failures before requesting a
consequential tag.

Starting a hosted rehearsal consumes GitHub Actions capacity and therefore
requires repository authorization. For an approved exact candidate, run:

```bash
gh workflow run release-rehearsal.yml -f release_tag=v0.7.6
```

Retain the workflow URL, source SHA, resolved runner images, six native job
results, and verified-bundle job result. A green rehearsal proves those
candidate build and native checks only. It does not create attestations,
publish a release or package, sign binaries, deploy the website, apply a
migration, activate a provider, or establish customer acceptance.

After the rehearsal succeeds, run the read-only pre-tag gate from the exact
clean candidate worktree. It queries the current remote `main`, proves local
and remote tag absence, re-runs version and release-note checks, binds the
successful rehearsal to the candidate SHA and exact native/bundle jobs, and
re-queries the release environment and tag rulesets:

```bash
node scripts/release/pre-tag-preflight.mjs v0.7.6 REHEARSAL_RUN_ID_OR_URL
```

The script never creates or pushes a tag. Only after every gate passes does it
print the exact annotated-tag and explicit `refs/tags/...` push commands for a
trusted operator to review. Recheck the printed SHA and rehearsal URL before
running them. A pushed `v*` tag is immutable in the current governance model;
if its workflow fails or its release is defective, publish a higher
fix-forward version rather than attempting to move or delete the tag.

The workflow source only requests SBOM and provenance attestations when a tag
run executes successfully. This repository state does **not** prove the native
matrix ran or that an attestation exists, and attestations are not independent
publisher signatures. A successful exact tag workflow supplies the native
archive-execution receipt; source review alone does not. The release workflow
does not perform macOS notarization or Windows Authenticode signing. Those remain
separate gates. The committed signing policy is explicitly disabled; the
[signing and notarization readiness guide](signing-and-notarization.md) records
the readiness-only policy, sanitized receipt contract, and separately governed
future design without enabling it. Repository settings must also allow Actions OIDC/attestation
writes and should protect the tag path; workflow source cannot activate those
controls.

Before creating a `v*` tag, verify both external controls directly: the
`release` environment has a required reviewer and the tag ruleset restricts
creation as well as update and deletion. A ruleset that protects only existing
tags does not govern who may start a new release run. If either control is
missing, the candidate is not publication-ready even when every source gate is
green.

### Live GitHub governance snapshot — 2026-09-01

The repository settings were inspected separately from workflow source on
2026-09-01. At that point:

- the `release` environment required a reviewer and limited deployments to
  tags matching `v*`;
- immutable tag ruleset `21903888` denied update, deletion, and non-fast-forward
  changes with no bypass actor; and
- separate creation ruleset `21997435` governed tag creation with a Mason-only
  bypass.

The creation bypass cannot bypass immutability: update, deletion, and
non-fast-forward operations are evaluated by the separate no-bypass ruleset.
This is a dated operator observation of live repository settings, not a source
guarantee, authorization to create a tag, or evidence that a tag/release exists.
Requery both rulesets and the environment immediately before any release.

## Source-candidate gates

Run these on the exact clean source SHA intended for a release:

```bash
cargo fmt --all -- --check
cargo test --workspace --all-targets --locked --no-fail-fast
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo deny --all-features --locked check --deny warnings advisories licenses bans sources
gitleaks dir . --config .gitleaks.toml --redact --no-banner --max-target-megabytes 5 --timeout 60
cargo build --release --locked -p phantom-secrets --bin phantom
cargo build --release --locked -p phantom-secrets-mcp --bin phantom-mcp
npm --prefix npm test
(cd npm && npm pack --dry-run)
npm --prefix npm-mcp test
(cd npm-mcp && npm pack --dry-run)
npm --prefix apps/web ci
npm --prefix apps/web audit --omit=dev --audit-level=moderate
npm --prefix apps/web run lint
npm --prefix apps/web test
npm --prefix apps/web run build
node --test scripts/installers.test.js
node --test scripts/examples-first-five-minutes.test.mjs
node --test scripts/release/native-installer-acceptance.test.mjs
node --test scripts/release/pre-tag-preflight.test.mjs
node --test scripts/release/release-rehearsal-contract.test.mjs
node --test scripts/publish-crates.test.js
node scripts/check-platform-installers.mjs
node scripts/release/check-version-parity.mjs v0.7.6
git diff --check
```

Also validate that Cargo package versions, both binary `--version` values, npm
package versions, MCP registry metadata, and the intended tag are identical.
The tag path always runs the web gates, not only when `apps/web` changed. The
workflow downloads cargo-deny and Gitleaks at fixed versions and verifies their
release-archive hashes before use. Record ignored, skipped, unavailable, and
externally blocked checks rather than treating them as passed.

Protected native Windows CI must exercise the exact candidate's no-follow,
identity, current-user DACL establishment/preservation, pre-byte permission
ordering, and both anchored effect outcomes. Source-contract tests and workflow
configuration do not establish that native acceptance.

Provider-grant changes must preserve the 0.7.6 universal denial before provider
credential lookup and network access. Exact `cfg(test)` mocks prove only local
transaction scaffolding. Any future activation additionally needs an authorized
throwaway-account acceptance plan; source tests do not prove a provider
application, consent screen, remote credential, renewal, or revoke operation.

## crates.io publication

The canonical crates.io operator entrypoint is
`scripts/publish-crates.sh`. It validates the closed twelve-crate workspace
against `cargo metadata`, requires one common SemVer version, and rejects a
stale package list, a package not restricted to `publish = ["crates-io"]`, or
a dependency-order violation before packaging. The
publication tiers are:

1. `phantom-secrets-authority` and `phantom-secrets-core`;
2. `phantom-secrets-broker`, `phantom-secrets-evidence`,
   `phantom-secrets-locus-contract`, `phantom-secrets-proxy`,
   `phantom-secrets-session`, `phantom-secrets-vault`, and
   `phantom-secrets-workspace`;
3. `phantom-secrets-runtime`;
4. `phantom-secrets-mcp`; and
5. `phantom-secrets`.

Run the non-publishing gate while preparing a candidate:

```bash
./scripts/publish-crates.sh --verify-only --version 0.7.6
```

Use `--allow-dirty` only for local development diagnostics. Before requesting
publication authorization, perform the read-only crates.io reconciliation:

```bash
./scripts/publish-crates.sh --dry-run --version 0.7.6
```

The dry run builds each local `.crate`, queries the exact crates.io package
version over bounded HTTPS, and reports whether it would publish or skip. An
existing version is considered idempotently complete only when its crates.io
SHA-256 equals the local package SHA-256. A different checksum for the same
immutable version aborts.

Pre-publication packaging supplies command-local Cargo patches for the twelve
workspace paths because unpublished same-version internal dependencies are not
yet resolvable from the crates.io index. Those patches affect dependency
resolution for local packaging only; they do not modify the generated package
manifests and are never passed to `cargo publish`.

`--verify-only` does not query publication state or upload packages. Cargo may
still fetch locked build dependencies that are absent from the local cache; use
Cargo's normal offline controls when a fully disconnected run is required.

Publishing is an irreversible external mutation. It requires separate approval
of the exact version and source tag, a clean worktree at `v<version>`, an
annotated canonical `origin` tag whose peeled commit is both local `HEAD` and
current `origin/main`, and an immutable non-prerelease GitHub Release containing
the exact nineteen-asset release contract. Before any upload, the script
downloads that hosted bundle, checks its exact archive/sidecar/SBOM structure
and digests, and verifies both build-provenance and SPDX attestations for every
archive against the release workflow, exact tag ref, and source SHA. Cargo's
normal credentials or `CARGO_REGISTRY_TOKEN` and an exact confirmation value
are also required:

```bash
PHANTOM_PUBLISH_CONFIRM=publish-phantom-secrets-0.7.6 \
  ./scripts/publish-crates.sh --publish --version 0.7.6
```

Do not place the registry token on the command line. The script removes registry
and GitHub tokens from the general child-process environment before metadata,
source gates, or packaging, then scopes each token only to its corresponding
`cargo publish` or GitHub receipt/download/attestation subprocess. It explicitly
selects the `crates-io` Cargo registry, rechecks the source SHA, annotated remote
tag SHA, current `origin/main`, and clean worktree before every upload, polls
crates.io rather than sleeping for a fixed index delay, verifies the published
checksum before moving to a dependent crate, and accepts a concurrent
publication race only if the resulting bytes are identical. A successful script
run proves crates.io package publication only; npm, Homebrew, MCP Registry,
signing, deployment, provider activation, and authenticated acceptance remain
separate.

## npm and MCP Registry publication

The GitHub tag workflow does not publish either npm wrapper or the MCP Registry
entry. After an exact immutable GitHub Release is independently verified, use
the guarded [npm publication runbook](npm-publication.md) to first pack and run
the exact tagged tarballs from fresh caches on all six native hosts while the
npm versions are still absent. Only after that prepublication gate passes,
re-pack both wrappers, stage both under `release-candidate`, inspect the staged
tarballs, approve each stage with interactive 2FA, and reconcile exact integrity
and provenance. Both exact public `0.7.6` packages must then pass the separate
postpublication six-target npm-channel acceptance gate before any default tag changes. Separately promote the MCP
wrapper to `latest` first and the primary CLI to `latest` last; verify both
promotions before removing either candidate tag. Only after all npm gates pass
should an operator use the separate
[MCP Registry publication runbook](mcp-registry-publication.md).

Both runbooks keep public reads and local package inspection separate from
human-approved registry writes. They also define idempotent reconciliation and
fix-forward behavior for partial publication. A successful GitHub Release does
not authorize either registry, a staged package is not public acceptance,
npm publication does not prove MCP Registry publication, and none proves an
authenticated customer workflow.

## Artifact gates before publication

For the current six-target matrix, the release verifier requires exactly:

- four `.tar.gz` archives and two `.zip` archives with the expected target names;
- one matching `.sha256` sidecar for each archive;
- one matching SPDX 2.3 JSON SBOM for each archive; and
- one aggregate `SHA256SUMS` covering those same six archives, with no extras
  or duplicates.

For every archive, enforce the direct installer's 100 MiB ceiling, checksum
syntax, digest, exact member names and types, and absence of traversal, links,
reparse points, nesting, and extras. For every SBOM, verify the exact name,
bounded size, JSON parsing, SPDX
2.3 identity, namespace, creation metadata, and packages-array shape. The
`verify-source` job locally builds and schema-smokes `phantom-mcp`; it does not
build `phantom` or execute either binary's `--version`. Exact tag-bound version
execution for both binaries occurs in the native matrix after extraction from
every build archive. The same rows then run the direct installer against the
exact local archive, validate the installed source receipt, prove restoration
after a test-only post-promotion failure, and separately prove that a checksum
failure preserves the accepted installation without residue. All six rows gate
attestation. Run packaged npm and MCP
stdio smoke against staged local artifacts without downloading or publishing.

## Supply-chain and native blockers

Checksums detect corruption only when obtained through a trusted channel; they
do not identify a publisher. Before a high-assurance release claim, verify:

- all six SPDX release assets and both GitHub provenance and SPDX predicate
  attestations against the downloaded archive digests;
- independently verifiable signatures;
- macOS code signing and notarization;
- Windows Authenticode signing; and
- a successful exact-tag native-acceptance matrix receipt for every supported OS
  and architecture (workflow source alone is not an execution receipt).

The [signing and notarization readiness guide](signing-and-notarization.md)
defines the proposed fail-closed gates. Its policy validator, receipt schema,
and fictional fixtures are source-readiness artifacts only; they do not satisfy
any blocker in this list, change the exact 19-file release bundle, or prove that
a signing provider has been configured.

Linux package-repository metadata, Homebrew formula updates, npm publication,
MCP Registry publication, and website deployment are separate distribution
actions with their own authorization and receipts.

The hosted build environment is not fully hermetic. Both macOS build rows use
the moving `macos-latest` label, while the x64 Windows build and native-acceptance
rows use `windows-latest`; GitHub also refreshes hosted runner images behind
named labels. Preserve the resolved runner image metadata with the exact-tag
workflow receipt. A successful native matrix proves execution on those resolved
hosts, not bit-for-bit reproducibility on future runner images.

GitHub documents the required attestation permissions, SBOM binding inputs,
verification commands, and plan limitations in [Using artifact attestations to
establish provenance for builds](https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/use-artifact-attestations).
GitHub Free, Pro, and Team support attestations only for public repositories;
private or internal repositories require GitHub Enterprise Cloud. The workflow
must be allowed to request an OIDC token and write repository attestations. A
successful tag run must still be followed by `gh attestation verify` for both
the default provenance predicate and the SPDX 2.3 predicate; workflow YAML is
not an execution receipt.

The workflow does not use a mutable installer or SBOM action. It downloads
host-specific assets from the immutable [Syft 1.42.3 release](https://github.com/anchore/syft/releases/tag/v1.42.3),
checks each archive against the exact digest in Anchore's official
`syft_1.42.3_checksums.txt`, rejects an unexpected runner OS or architecture,
extracts only the Syft executable, and invokes it locally. Anchore documents
SPDX JSON as a standards-oriented exchange format and notes that SPDX is
ISO/IEC 5962:2021 in its [output format guide](https://oss.anchore.com/docs/guides/sbom/formats/).
These SBOMs describe what Syft discovers in each exact archive; their presence
does not prove that every statically linked dependency was discoverable or
policy-approved.

The repository's immutable-release setting is enabled. In addition to its
release-absence and no-overwrite preflights, the workflow creates a draft,
attaches the exact 19-file bundle, verifies the hosted draft receipt, and only
then publishes it. It re-reads the published receipt to prove the final state
and exact asset set. GitHub's [immutable release guidance](https://docs.github.com/en/code-security/concepts/supply-chain-security/immutable-releases)
requires this draft-first order because assets cannot be added or replaced
after publication.

## Evidence ladder

Keep these claims separate:

1. source implemented;
2. source gates passed on an exact SHA;
3. archives built and locally verified;
4. exact artifacts passed native archive and installer acceptance;
5. provenance and SBOM attestations verified for the exact archive digests;
6. GitHub/npm/Homebrew/MCP packages published;
7. provider configuration or deployment activated; and
8. an authenticated customer workflow accepted.

Completion of one step does not establish the next.
