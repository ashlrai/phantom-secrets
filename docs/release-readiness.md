# Release and readiness

This guide records what the current repository automates and what still needs
separate evidence. It does not authorize a tag, package publication, Homebrew
update, signing operation, provider consent, or deployment.

## Current automated release path

A `v*` tag starts `.github/workflows/release.yml`. The current workflow:

1. verifies exact `v<semver>` parity across the release metadata surfaces;
2. runs checksum-verified Gitleaks and cargo-deny, locked all-target workspace
   tests, formatting, strict Clippy, installer and wrapper tests, package
   inspections, the full web install/audit/test/build gate, and the MCP
   schema/stdio smoke;
3. builds six targets: macOS, GNU Linux, and Windows on `arm64`/`x64`;
4. creates an archive containing exactly `phantom` and `phantom-mcp`;
5. downloads each named build artifact onto a matching standard GitHub runner
   (`macos-15-intel`, `macos-15`, `ubuntu-22.04`, `ubuntu-22.04-arm`,
   `windows-latest`, or `windows-11-vs2026-arm`), re-verifies the closed archive
   and extracted file set, asserts both the runner and Node runtime OS/architecture,
   checks both binaries' exact tag-bound `--version`, and runs the MCP stdio
   schema smoke against the extracted `phantom-mcp`;
6. downloads the host-specific Syft 1.42.3 release archive, verifies its exact
   SHA-256 from Anchore's official checksum manifest, and invokes that verified
   binary to scan each exact archive into an SPDX 2.3 JSON SBOM;
7. generates a SHA-256 sidecar for every archive plus an aggregate
   `SHA256SUMS`;
8. verifies the exact archive, sidecar, SBOM, aggregate-checksum, member-name,
   and member-type contract;
9. requests one GitHub build-provenance attestation covering the six exact
   archive digests and one SBOM attestation binding each archive to its matching
   SPDX document; and
10. re-verifies the preserved bundle before creating a non-overwriting GitHub
   release.

Third-party actions are pinned. Build jobs use read-only repository permissions;
only the attestation job receives `id-token: write` and `attestations: write`,
and only the release job receives `contents: write`.

The build matrix may cross-compile, but it cannot authorize attestation directly.
A separate six-row native-acceptance matrix downloads each exact build artifact
onto the matching OS and architecture and must complete before attestation.

The workflow source only requests SBOM and provenance attestations when a tag
run executes successfully. This repository state does **not** prove the native
matrix ran or that an attestation exists, and attestations are not independent
publisher signatures. A successful exact tag workflow supplies the native
archive-execution receipt; source review alone does not. The release workflow
does not perform macOS notarization or Windows Authenticode signing. Those remain
separate gates. Repository settings must also allow Actions OIDC/attestation
writes and should protect the tag path; workflow source cannot activate those
controls.

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
npm --prefix npm pack --dry-run
npm --prefix npm-mcp test
npm --prefix npm-mcp pack --dry-run
npm --prefix apps/web ci
npm --prefix apps/web audit --omit=dev --audit-level=moderate
npm --prefix apps/web test
npm --prefix apps/web run build
node --test scripts/installers.test.js
node --test scripts/publish-crates.test.js
node scripts/check-platform-installers.mjs
git diff --check
```

Also validate that Cargo package versions, both binary `--version` values, npm
package versions, MCP registry metadata, and the intended tag are identical.
The tag path always runs the web gates, not only when `apps/web` changed. The
workflow downloads cargo-deny and Gitleaks at fixed versions and verifies their
release-archive hashes before use. Record ignored, skipped, unavailable, and
externally blocked checks rather than treating them as passed.

Provider-grant changes must preserve the 0.7.4 universal denial before provider
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
./scripts/publish-crates.sh --verify-only --version 0.7.4
```

Use `--allow-dirty` only for local development diagnostics. Before requesting
publication authorization, perform the read-only crates.io reconciliation:

```bash
./scripts/publish-crates.sh --dry-run --version 0.7.4
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
of the exact version and source tag, a clean worktree at `v<version>`, exact
local and canonical `origin` tag SHA parity, a completed non-prerelease GitHub
Release containing the exact nineteen-asset release contract, Cargo's normal
credentials or `CARGO_REGISTRY_TOKEN`, and an exact confirmation value:

```bash
PHANTOM_PUBLISH_CONFIRM=publish-phantom-secrets-0.7.4 \
  ./scripts/publish-crates.sh --publish --version 0.7.4
```

Do not place the registry token on the command line. The script removes registry
and GitHub tokens from the general child-process environment before metadata,
source gates, or packaging, then scopes each token only to its corresponding
`cargo publish` or `gh release view` subprocess. It explicitly selects the
`crates-io` Cargo registry, rechecks the source SHA, remote tag SHA, and clean
worktree before every upload, polls crates.io rather than sleeping for a fixed
index delay, verifies the published checksum before moving to a dependent
crate, and accepts a concurrent publication race only if the resulting bytes
are identical. A successful script run proves crates.io package publication
only; npm, Homebrew, MCP Registry, signing, deployment, provider activation, and
authenticated acceptance remain separate.

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
every build archive, and all six rows gate attestation. Run packaged npm and MCP
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
4. provenance and SBOM attestations verified for the exact archive digests;
5. exact artifacts passed native acceptance;
6. GitHub/npm/Homebrew/MCP packages published;
7. provider configuration or deployment activated; and
8. an authenticated customer workflow accepted.

Completion of one step does not establish the next.
