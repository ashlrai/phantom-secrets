# Changelog

Notable user-facing changes are recorded here. Phantom follows [Semantic Versioning](https://semver.org/) while pre-1.0: minor releases may change unstable interfaces, and breaking changes should be called out explicitly.

## [Unreleased]

No user-facing changes have been recorded after 0.7.4.

## [0.7.4] - 2026-08-31

This release hardens local agent setup, transactional secret protection, MCP
effect authorization, and the default-closed hosted-service boundary.
Publication remains gated on protected-branch CI and the tag-triggered
immutable-release workflow. This source section is not evidence that the tag,
release artifacts, Homebrew formula, npm packages, crates.io packages, MCP
Registry entry, database migrations, web deployment, provider integrations, or
customer acceptance exist or are active.

### Breaking changes and migration

- `phantom setup` and initialization no longer generate an unpinned `npx`
  fallback when a local MCP runtime cannot be resolved. After the immutable
  `0.7.4` release receipt exists, install both `phantom` and `phantom-mcp` from
  that same release, then rerun setup; until then, `0.7.3` remains the reviewed
  distribution. Existing legacy registry-backed entries are migrated only when
  the local replacement can be resolved safely.
- Initialization now requires a supported dry-run flag combination, an exact
  canonical executable pre-commit hook, and a transaction that commits the
  managed dotenv file last. Rerun `phantom init` from a trusted terminal to
  repair stale setup. Partial failures roll back only transaction-owned state;
  operators should still keep a separately protected recovery copy.
- Legacy `phantom watch --auto-rotate` and scheduled placeholder-remap paths no
  longer claim provider credential rotation. The MCP compatibility names
  `phantom_secrets_auto_rotate` and `phantom_rotate_with_expiry` perform only
  approved local `phm_` remaps and do not renew credential lifecycle metadata,
  clear incidents, or sync. Use an explicitly configured and approved
  provider-rotation flow for real credential replacement.
- Hosted billing, personal cloud-vault, and team routes now return unavailable
  unless their exact commissioning gates are enabled. Operators must separately
  verify required migrations, environment variables, provider configuration,
  rollback, and authenticated acceptance before enabling those gates.
- Effectful advanced MCP tools are now disabled unless
  `PHANTOM_MCP_EFFECTS=trusted-terminal` is configured outside the requesting
  agent's authority. Approval requires an attached terminal, a displayed
  value-blind effect and exact parameter summary, and a fresh typed challenge.
  A same-user shell or agent-controlled PTY is not human-presence proof; leave
  effects disabled when the approval command or storage is within agent scope.
- Windows rejects `--passphrase-file` before path access because native
  handle-bound owner/DACL verification is not yet implemented. Use the hidden
  trusted-terminal prompt. Unix private regular files remain supported.
- Legacy direct installs sharing the npm installation root may be ambiguous.
  Reinstall with the reviewed direct installer to create a source receipt;
  `phantom upgrade` now fails closed instead of guessing ownership.

### Security

- Serializes the full MCP terminal-approval and one-use consumption critical
  sections across threads and processes, uses collision-safe atomic storage,
  and gives approved tokens a fresh five-minute use window. Concurrent replay
  of one approval now permits exactly one successful consumption.
- Classifies all 54 current MCP tools by effect. Tools that write state,
  retrieve or use credentials, or make provider/network requests require both
  `confirm: true` and a matching out-of-band one-use approval token; conditional
  tools require those gates whenever effectful parameters are supplied.
- Keeps incident reads read-only, removes false auto-rotation behavior, rejects
  unsupported team ownership invitation, and keeps stored secret values out of
  approval and MCP response contracts.
- Removes dummy `phm_cand_` shadow "credential" promotion. Candidate and
  promotion compatibility paths now fail closed until a real provider-backed,
  out-of-band candidate workflow exists.
- Resolves the effective Git hook through Git, including linked worktrees and
  `core.hooksPath`, and requires Phantom's canonical local check to be first and
  executable before readiness passes.
- Makes fallback vault provisioning fail closed unless a generated passphrase
  is durably persisted and verified, serializes keychain index/metadata
  transactions, compensates partial mutations (including legacy plaintext-name
  migration), exposes a fallible public vault constructor, and propagates
  backend errors instead of replacing missing encryption keys or panicking.
- Replaces ambient `kill`/`tasklist` process checks with native OS liveness,
  authenticates graceful proxy shutdown, serializes per-project proxy starts,
  requires authenticated daemon readiness before exporting its bearer token,
  and keeps session PID/bearer state out of Git.

### Reliability and authority boundaries

- Makes initialization recoverable across vault, config, guidance, hook, and
  dotenv updates using compare-and-swap checks, collision-safe atomic writes,
  and rollback that never stores plaintext secret backups or journals.
- Spans initialization and token-remap compare-and-swap checks with
  cross-process project locks so concurrent writers cannot overwrite a newer
  dotenv or vault state between verification and commit. All MCP token-remap
  paths use the same locked before-image discipline.
- Propagates vault inspection, credential-read, and provider-rotation metadata
  failures across MCP and CLI flows instead of rendering an empty vault,
  starting a partially mapped session, overwriting on an unknown destination
  state, or reporting a false rotation success. Non-forced cloud pulls preflight
  every overwrite decision before their first store.
- Scopes competitor-import overwrite approval to the exact existing names the
  user reviewed; a newly appearing duplicate remains untouched unless
  `--force` is explicit.
- Normalizes Pro access from an exact lowercase plan plus a strictly valid,
  timezone-qualified future expiry. Billing lookup exhausts bounded Stripe
  subscription pagination and fails closed on malformed or non-progressing
  pages.
- Keeps generated scripts and hooks on reviewed local executables, and aligns
  current-source package metadata, MCP schemas, and documentation with shipped
  behavior rather than uncommissioned pricing or hosted-service promises.
- Serializes direct and npm installer promotion with owner/stale-recovery
  locks, records distribution ownership transactionally, and verifies the
  reviewed direct binaries before promotion. PowerShell no longer recommends
  piping a network response into execution.
- Builds GNU Linux archives on an explicit Ubuntu 22.04 baseline and rejects
  either binary when ELF requirements exceed `GLIBC_2.35` or cannot be proven.
  This is a symbol ceiling, not native archive acceptance. Shell exports use
  quoted Bash, Fish, PowerShell, or cmd syntax with `PHANTOM_SHELL` available
  for nested-shell overrides.
- The authority, Locus-contract, broker, runtime, session, and evidence crates
  remain fail-closed foundations. This release does not activate a Locus
  verifier, issue broker leases, execute production engineering actions, or
  create externally trusted execution receipts.

## [0.7.3] - 2026-08-31

This is the security fix-forward for `0.7.0`. The protected `0.7.1` and `0.7.2`
tag workflows both stopped before creating a GitHub Release: `0.7.1` failed its
release-note contract, while `0.7.2` exposed and removed a non-hermetic proxy
unit test that depended on public `httpbin.org`. Publication remains gated on
protected-branch CI and the tag-triggered immutable-release workflow. The web
changes also require the included Supabase migration before deployment; source
publication does not imply that migration or the web application is active in
production.

### Breaking security changes

- `phantom exec` and `phantom start` accept only Phantom's exact built-in API
  routes. Repository-defined or altered proxy destinations now fail closed
  until a future trusted-terminal approval format can bind custom routes to a
  machine-local decision.
- `.phantom.toml` keeps its committed project ID as the portable cloud/team
  identity, while local vault, shadow, and scheduler state are namespaced from
  the canonical checkout directory. A clone or move therefore keeps its remote
  identity but starts with isolated local state and cannot select another
  checkout's vault through repository config.
- Protected connection strings such as `DATABASE_URL` are no longer injected
  into an agent child process. These now fail closed pending a protocol-aware
  database broker.
- Runtime mock-rotation and alternate Stripe endpoint environment variables no
  longer activate in shipped binaries. Hermetic mock behavior is compiled only
  into unit tests.

### Security

- Pins Phantom Cloud authentication to `https://phm.dev/api/v1`; runtime API
  origin overrides are rejected before cloud network access.
- Replaces secret-derived response labels with the constant
  `[REDACTED:vault-secret]`, including short and Unicode values.
- Disables upstream redirects, buffers and validates complete bounded request
  bodies before contacting an upstream, and bounds buffered upstream responses
  before redaction.
- Rejects unsafe file-vault project IDs before creating any vault path.
- Makes audit statistics verify the HMAC chain and treats unsigned records
  appended after a signed chain as tampering.
- Makes GitHub login identity immutable to ordinary user updates, resolves team
  invites through a normalized unique identity, and moves device-code issuance
  plus per-client/global rate limiting into one database transaction.
- Removes device codes from OAuth URLs and analytics page-view capture, strictly
  validates team X25519 public keys, and adds browser isolation headers.
- Updates Rust and video dependency graphs to resolve actionable advisories.

### Breaking changes and migration

- Treat `0.7.0` and the unpublished `0.7.1` and `0.7.2` tags as superseded, and
  upgrade to `0.7.3` before using cloud, team,
  proxy, connection-string, provider-rotation, or agent execution workflows.
- Local vault namespaces now use a domain-separated SHA-256 digest of the
  canonical checkout path. The former 64-bit path namespace is deliberately
  not opened automatically because collision compatibility would preserve a
  cross-vault selection risk. Before upgrading an offline-only `0.7.0`
  checkout, create an encrypted backup with `phantom export --output FILE` from
  a trusted terminal; after upgrading, restore it with `phantom import FILE`.
  Cloud/team users can instead repopulate through a normal encrypted pull.
  Never copy plaintext secret values into a repository.

## [0.7.2] - 2026-08-31

The protected tag exists as evidence of a failed-closed release attempt. The
release-note contract passed, but the exact-tag workspace suite exposed a proxy
unit test whose mock route still depended on public `httpbin.org`; a transient
upstream 502 failed the suite before any artifacts or GitHub Release were
created. The test is hermetic in `0.7.3`.

## [0.7.1] - 2026-08-31

The protected tag exists as evidence of a failed-closed release attempt. All
source, platform-build, artifact-set, SBOM, and attestation gates passed, but
the workflow rejected the changelog heading before creating a GitHub Release.
No `0.7.1` release assets were published. Use `0.7.3`.

## [0.7.0] - 2026-08-31

Publication is gated on exact-source CI and the tag-triggered release workflow.
Provider activation, native signing/notarization, and customer acceptance
remain separate evidence gates.

### Breaking changes and migration

- Positional secret values are rejected. Replace `phantom add KEY VALUE` with
  `phantom add KEY` for a hidden trusted-terminal prompt, or pipe one value to
  `phantom add KEY --stdin` from a trusted producer.
- Plaintext backup export is removed. Use `phantom export --output FILE` and a
  hidden passphrase prompt, or `--passphrase-file PRIVATE_FILE` for bounded
  automation; use the same input mode with `phantom import`.
- The former `--passphrase` command-line option is rejected because process
  arguments are observable. Move automation to a private, non-symlink regular
  file with mode `0600` or stricter on Unix.
- Noninteractive reveal through `--yes` is rejected. Run `phantom reveal KEY`
  from a trusted interactive terminal; Phantom copies to the clipboard and
  refuses plaintext stdout fallback.
- `phantom init` no longer leaves plaintext dotenv backup files. Create a
  separately protected recovery copy before upgrading if your operating
  procedure depended on the former backup behavior.

### Added

- Trusted-terminal `phantom grant add`, `list`, and `status` workflows for
  provider credentials, with implemented issuance paths for GitHub App,
  Vercel Integration, Sentry Integration, Supabase OAuth, and Stripe App OAuth.
- Direct-to-vault issuance root storage and value-free provider-grant lifecycle
  output. The current [grant specification](docs/grants-spec.md) is distinct
  from inactive execution-kernel authority grants.
- Value-blind workspace planning and bearerless request handling, with a
  separate trusted-terminal Unix apply transaction.
- Fail-closed authority, Locus-contract, broker, runtime, session, and evidence
  foundations for future governed engineering execution.
- Canonical architecture, platform-support, release-readiness, audit-index,
  security-policy, and repository-contribution documentation.
- Bounded web request parsing and an atomic Stripe billing-event transaction
  with retryable claims, historical subscription bindings, and monotonic
  event ordering.
- Six-target release packaging with exact artifact-set verification,
  archive-specific SPDX 2.3 SBOMs, and GitHub provenance attestations.

### Changed

- The primary npm CLI wrapper now verifies a private cached binary through an
  exact version and checksum manifest, uses bounded allowlisted downloads and
  archive validation, and preserves the prior verified binary across failed
  installation attempts.
- Encrypted backup and restore now use hidden or private-file passphrase input,
  bounded reads, zeroizing buffers, private staging, durable atomic
  no-overwrite publication, and nonzero partial-restore failures.
- `phantom setup` removes only legacy dotenv read grants while preserving all
  unrelated allow and deny rules. `phantom init` no longer creates plaintext
  dotenv backups.

### Security

- Provider issuance uses a closed production endpoint map, names provider
  client secrets by environment variable instead of command-line value, and
  keeps issued roots out of CLI output.
- `phantom grant revoke` fails closed before local mutation while supported
  provider remote revocation remains unwired.
- Production engineering execution remains unavailable: provider grants do not
  become authority grants, broker leases, or execution permits.
- Plaintext backup export, positional secret values, argv passphrases, and
  noninteractive secret reveal bypasses fail closed before project mutation.
- Rust advisories, licenses, duplicate families, and registry sources are
  enforced by cargo-deny; the documented no-fix RSA advisory remains limited
  to a dev-only test dependency.

## [0.6.0] - 2026-05-04

### Added

- Opt-in JSONL audit log with an HMAC-SHA256 integrity chain and `phantom audit verify`.
- Streaming proxy request handling while preserving scoped phantom-token replacement.
- Bundled MCP serving from the main CLI and dedicated MCP package support.
- Multi-project initialization and setup helpers for multiple AI clients.
- Importers for Doppler, Infisical, dotenvx, 1Password, and dotenv files.
- A repository threat model covering assets, actors, mitigations, cryptography, trust boundaries, and known gaps.

For older release notes and downloadable artifacts, see [GitHub Releases](https://github.com/ashlrai/phantom-secrets/releases).

[Unreleased]: https://github.com/ashlrai/phantom-secrets/compare/v0.7.4...HEAD
[0.7.4]: https://github.com/ashlrai/phantom-secrets/compare/v0.7.3...v0.7.4
[0.7.3]: https://github.com/ashlrai/phantom-secrets/compare/v0.7.0...v0.7.3
[0.7.2]: https://github.com/ashlrai/phantom-secrets/compare/v0.7.0...v0.7.2
[0.7.1]: https://github.com/ashlrai/phantom-secrets/compare/v0.7.0...v0.7.1
[0.7.0]: https://github.com/ashlrai/phantom-secrets/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/ashlrai/phantom-secrets/releases/tag/v0.6.0
