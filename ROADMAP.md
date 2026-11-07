# Roadmap

<!-- phantom-release-version: 0.8.7 -->

This roadmap describes ordered engineering gates, not delivery dates or shipped
capabilities. This opening historical snapshot was verified on 2026-09-29. The immutable
`v0.7.9` GitHub release binds 19 assets to source commit
`7a51ce512ec4aee12cc29ff859036af63fbe93db`; all six native rows and GitHub
provenance and SPDX attestations passed in workflow 34153902556. Homebrew
then published the previous reviewed `v0.7.8`; its `v0.7.9` bump was pending.
Both npm `0.7.4` wrappers were public only under the
failed `release-candidate` track, while npm `latest` was `0.6.0`.
No `0.7.9` npm, crates.io, or MCP Registry publication, hosted-service
commissioning, provider activation, certification, or customer acceptance is
represented by the GitHub release receipt. For later package-channel receipts,
see [distribution status](docs/distribution-status.md).

## Status vocabulary

| Status | Meaning |
|---|---|
| Released | Present in an immutable published release with the named evidence. |
| Staged | Implemented in repository source and still awaiting release evidence. |
| Gated | Intended direction with explicit prerequisites; not available. |
| Exploratory | Research or design work with no compatibility or delivery commitment. |

## Historical milestones

The immutable `v0.8.7` release was verified on 2026-11-06; see
[distribution status](docs/distribution-status.md). The milestones below
retain their original context and do not describe the current release state.

### 0.8.2 publication-truth fix-forward: source candidate

- Keep verified public release links and version output bound to `v0.7.9`.
- Qualify the integrated source, including the earlier installer, CLI,
  dependency, and log-scan changes, under a fresh release identity.
- Preserve every existing tag. A source candidate and a reserved tag are
  not published artifacts.

At that stage, the immutable GitHub release was `v0.7.9`. Publication of `0.8.2`
requires its own successful sanctioned release workflow and artifact receipt.

### 0.8.1 installer hardening and test coverage patch: source candidate

- Harden the installer and release-rehearsal checks: the PowerShell
  candidate pin is derived from source metadata, and `install.sh` has a
  shell syntax check.
- Add CLI exit-code tests for help, unknown commands, and unknown flags,
  and installer failure-path tests.
- Update the dependency set to drop the vulnerable `async-executor`.

This earlier source milestone is included in the `0.8.2` candidate. It is
not a publication receipt. At that stage, the immutable GitHub release was `v0.7.9`.

### 0.8.0 agent log scan and the post-0.7.9 source tranche: staged

- Scan one agent log or transcript with `phantom check --log` and MCP
  `phantom_check` `log_path`. The report names the file, the line, and the
  credential shape. It does not print the value.
- Stage the log scan with the post-`v0.7.9` source rollup described in
  the `0.7.10` changelog section. Reserved tags do not prove publication.

### 0.7.9 agent onboarding and Hub status compatibility — released

- Register Claude project MCP configuration in `.mcp.json` while preserving
  unrelated local permission settings, and diagnose legacy-only registration.
- Provide an explicitly metadata-only `phantom status --json` contract for
  bounded Hub inspection without vault, bearer, or network access.
- Verify the installed CLI and MCP onboarding path in the cross-platform CI
  matrix before publishing a new immutable release identity.

Released as the immutable `v0.7.9` GitHub release (tag-bound workflow
34153902556). That September 29 verification did not establish npm, crates.io,
MCP Registry, or deployment acceptance; its Homebrew snapshot was `v0.7.8`.
Later npm and Homebrew observations are recorded in the distribution status.

### 1. Close the 0.7.8 fix-forward source candidate — released

- Keep local mutations transactional and authority-sensitive operations
  fail-closed.
- Preserve the default-denied provider-issuance boundary.
- Keep public documentation, CLI help, and the generated 54-tool MCP registry
  aligned with runtime behavior.
- Pass locked workspace, dependency-policy, installer, wrapper, web, security,
  and schema gates on one exact clean SHA.

Completed at exact source commit
`f065b13462f9eaf27e0443f8911f021575b7c409`; source completion was a
prerequisite, not publication evidence by itself.

### 2. Produce and accept exact native artifacts — released on GitHub

- Run the tag-bound six-target release workflow.
- Verify each closed archive, checksum, SBOM, provenance binding, binary
  version, and MCP schema on its matching native runner.
- Record skipped or externally unavailable checks and keep notarization,
  Authenticode, and independent signing claims separate.

The tag-bound workflow published the exact 19-asset release set and passed all
six native rows plus provenance and SPDX attestation verification. The
archives remain unsigned and unnotarized; this receipt does not establish
native credential-store, ACL, editor, or every-device acceptance.

### 3. Reconcile remaining distribution tracks — gated

- Preserve the immutable GitHub and Homebrew `v0.7.8` receipts while npm,
  crates.io, and MCP Registry complete their independent publication gates.
- Publish crates.io, npm, MCP Registry, and future Homebrew updates only through
  their separately approved workflows.
- Verify exact version and byte identity for each immutable publication.
- Keep older tracks visibly distinct until their own publication receipts exist.

Publication on one channel does not authorize or prove another.

### 4. Expand network architecture only behind evidence — exploratory

The [Rama-derived design standard](docs/rama-design-standard.md) is an
architectural benchmark, not a runtime dependency. Typed service extraction,
transport fault tests, and a non-default spike must preserve Phantom's closed
route and credential-placement authority before any dependency decision.

### 5. Re-enable provider lifecycle paths only with recovery — gated

Live provider enrollment, issuance, refresh, renewal, rotation, and revocation
remain hard-denied. Re-enabling one provider requires a provider-specific,
durable recovery handle, verified compensation/abort behavior, exact terminal
authority, hermetic tests, and separately authorized provider acceptance.

### 6. Evaluate hosted and enterprise pilots separately — gated

Cloud, team, billing, key portability, centralized policy, SSO/SCIM, support,
and enterprise packaging require deployed-service configuration, migrations,
provider setup, rollback, written scope, and authenticated acceptance. Source
availability or local tests do not commission those capabilities.

## Non-goals

- General-purpose MITM or system-proxy behavior.
- Ambient agent authority to reveal, rotate, deploy, publish, or spend.
- Security, compliance, platform, or support guarantees inferred from source.
- Dates or adoption claims that lack an accountable owner and acceptance evidence.

The earlier DX plan (public key awareness, `.env.example` generation, README
onboarding, pre-commit hook, `wrap`/`unwrap`, `copy`, enhanced `doctor`, CI/CD
detection, `why`, `status --oneline`) has shipped and was removed from the
repository; see git history for it. Current behavior is defined by code,
closed schemas, tests, the [changelog](CHANGELOG.md), and canonical documentation.
