# Changelog

Notable user-facing changes are recorded here. Phantom follows [Semantic Versioning](https://semver.org/) while pre-1.0: minor releases may change unstable interfaces, and breaking changes should be called out explicitly.

## [Unreleased]

No unreleased changes are recorded after the `0.7.5` candidate.

## [0.7.5] - 2026-09-02

This patch is a fix-forward release for the npm wrappers. The immutable
`0.7.4` npm versions were published under `release-candidate`, were not
promoted to `latest`, and remain available by exact version. Acceptance found
cross-platform first-use installation defects, so an accepted `0.7.5` release
is intended to supersede those candidates rather than overwrite or withdraw
them. This changelog entry and repository source do not prove that a `v0.7.5` tag, GitHub Release, package,
registry entry, deployment, or customer acceptance exists.

### Fixed

- Open downloaded native binaries read/write before `fsync`, preserving the
  durability barrier on Windows where `FlushFileBuffers` rejects a read-only
  file handle.
- Normalize extracted Unix release binaries from archive mode `0755` to the
  private cache mode `0700` before applying the strict owned-path policy, then
  verify the installed executable retains that private mode.
- Apply the same portability behavior and regression coverage to both the
  `phantom-secrets` and `phantom-secrets-mcp` wrappers.
- Preserve a checksum-matched previous-version cache byte-for-byte until the
  replacement binary and manifest are fully verified and atomically promoted;
  failed downloads, extraction, flushes, or version checks leave no transaction
  debris and never execute the prior binary under the new wrapper version.

### Breaking changes and migration

There are no intentional CLI, MCP, configuration, vault, or network-policy
breaking changes. Users who explicitly installed an npm `0.7.4`
`release-candidate` should install exact `0.7.5` only after its public
integrity and native acceptance receipts are available. Do not rely on an
unpinned dist-tag while the fix-forward candidate is still under review.

## [0.7.4] - 2026-09-02

This release hardens local agent setup, transactional secret protection, MCP
effect authorization, retained filesystem authority, Windows private-file
permissions, and the default-closed hosted-service boundary. Its immutable
GitHub Release and Homebrew formula are published. Its npm packages remain
quarantined under `release-candidate` after cross-platform acceptance failed;
crates.io, MCP Registry, hosted-service commissioning, provider integrations,
and customer acceptance are not represented by this release.

### Security and filesystem integrity

- Project transactions now retain the directory identity acquired with the
  project lock. Before-image reads for governed mutations, compare-and-swap
  writes, unlinks, permission changes, and parent creation resolve relative to
  that retained capability, reject paths outside the governed root, and do not
  follow symlink or Windows reparse-point components.
- Sensitive anchored file updates require a regular, single-link target and an
  exact identity-and-content before-image. This rejects hard-linked targets and
  byte-for-byte replacement inodes, while rename-and-decoy tests verify that a
  swapped ambient project path is not mutated.
- Initialization admission now retains the reviewed project-root identity and
  exact leaf snapshots before vault provisioning. After the project lock is
  acquired, Phantom revalidates that root and each reviewed leaf's identity,
  bytes, and permissions before mutation; a byte-identical rename decoy is
  rejected as concurrent drift.
- Anchored writes, unlinks, and directory creation return explicit effect
  outcomes. `CommittedVerifiedButDurabilityUncertain` is a committed, exactly
  verified success with a value-free warning/receipt when the platform cannot
  prove directory crash durability; callers must not roll it back or retry it.
  `CommittedButUncertain` remains a **Partial** result when post-publish
  verification or durability is unresolved and requires reconciliation. Exact
  creation receipts permit cleanup only of the directory identity Phantom
  created.
- On Windows, new private anchored files and directories establish and verify
  a protected current-user DACL before secret bytes are written. Replacement
  files receive and verify the reviewed file's exact DACL, inheritance state,
  and read-only state before bytes are copied. These are source-level contracts;
  protected native Windows CI acceptance remains pending.
- Governed CLI and MCP project-file mutation paths now use the retained project
  root for initialization, token remapping, wrapping, unwrapping, environment
  selection, agent guidance, doctor repairs, rotation, and workspace
  participation. Read-only check, status, audit, and proposal discovery remains
  observational and is not a sealed mutation snapshot or authority grant.
- Workflows that need both machine-local vault authority and a project lock now
  retain the reviewed project identity, resolve vault/application authority
  (which can take the process-environment guard), and only then acquire the
  project transaction lock. They compare the acquired root identity with the
  reviewed anchor and reread exact config state before use. This removes the
  inverse environment-lock/project-lock order and rejects a same-path root
  replacement during vault resolution.
- Noninteractive `phantom mcp-approve` admission now fails before inspecting
  approval state, generating a challenge, or reading stdin. The denial path
  therefore does not strand a project-lock waiter behind a test or host
  environment guard.
  Rollback restores only verified transaction-owned effects and preserves
  rename-replacement decoys.
- Git-hook installation retains the effective hook parent resolved through
  Git, including linked worktrees and `core.hooksPath`. Project-local hook
  targets use the project capability; externally located hook targets require
  their own explicitly authorized retained root and do not gain project-root
  authority. CLI doctor repairs prepare one exact hook plan and require an
  attached trusted-terminal authorization for global/system hook roots; MCP
  repair refuses those external writes.
- `phantom setup` distinguishes project-local Claude settings from explicitly
  authorized global Cursor, Windsurf, and Codex configuration roots. Global
  parents are traversed or created beneath a retained home-directory anchor,
  exact directory receipts bound rollback, and setup coordination lives under
  retained `~/.phantom` application state instead of an ambient home-root or a
  rollback-owned client directory.

### Architecture and evidence

- Local filesystem authority, effect receipts, operator boundaries, and
  source-contract versus native-platform evidence are now documented across
  the architecture, threat model, platform matrix, audit index, onboarding,
  troubleshooting, and machine-readable documentation surfaces.
- Phantom uses Rama's upstream main snapshot
  [`267e4790c899736e6f60d982c8a0932406d4079e`](https://github.com/plabayo/rama/commit/267e4790c899736e6f60d982c8a0932406d4079e),
  reviewed 2026-09-01, as a benchmark for explicit stacks, modular crates,
  runnable examples, and tiered platform CI. Rama is not a Phantom dependency,
  and this comparison does not claim feature or platform parity.
- Locus verification, broker leases, production engineering execution, and
  externally trusted receipts remain inactive and fail closed. Enterprise
  packaging remains a planned contract/commissioning path, not an activated or
  customer-accepted service.

### Breaking changes and migration

- Rust callers of `phantom-core` must now handle `Result` from
  `DotenvFile::rewrite_with_phantoms` and
  `DotenvFile::generate_example_content`. Mutation and generated-output APIs
  reject malformed or duplicate mappings instead of returning partial output;
  `DotenvFile::upsert_with_phantoms` is the format-preserving API for adding
  prepared mappings. Phantom remains pre-1.0, but this source-level signature
  change is called out explicitly for library consumers.
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
  clear incidents, or sync. Rotate through the provider's trusted interface,
  then store the successor with trusted-terminal `phantom add`.
- `phantom watch --auto` now fails before vault or dotenv mutation. The legacy
  watcher could leave partial state after a concurrent edit or nth write
  failure. Use `phantom watch` for detection, review the change, and run
  transactional `phantom init` from a trusted terminal.
- All live vendor issuance/rotation execution is unavailable in 0.7.4. Batch,
  single-provider CLI, MCP, enrollment exchange, additive issuance, and rolling
  refresh paths fail before provider credential access and network I/O. Source
  adapters and exact `cfg(test)` mocks are local transaction evidence only, not
  provider activation or acceptance. Operators must rotate at the vendor and
  then use Phantom's trusted local secret-entry path.
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
- A live v0.7.3 standalone proxy cannot be stopped by the new binary because
  v0.7.3 did not ship an authenticated remote-shutdown endpoint. Stop it with
  Ctrl-C in its owning v0.7.3 terminal. If that terminal is unavailable, use a
  checksum-verified v0.7.3 binary from a trusted terminal, or independently
  verify that no process/listener owns the legacy record before manually
  removing `.phantom.pid`; v0.7.4 never kills or deletes that state.
- Legacy direct installs sharing the npm installation root may be ambiguous.
  Reinstall with the reviewed direct installer to create a source receipt;
  `phantom upgrade` now fails closed instead of guessing ownership.

### Security

- Dotenv parsing now retains exact source spans and preserves BOM, LF, CRLF,
  lone-CR endings, quotes, comments, spacing, multiline values, and terminal
  newline shape outside explicitly changed values. Every mutating caller fails
  closed on malformed, duplicate, unsafe, or concurrently changed mappings
  before vault, approval, provider, or unrelated repair effects where the
  command contract permits; diagnostics contain locations and fixed categories,
  never source values.
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
- Makes standalone proxy lifecycle foreground-only and three-terminal-gated.
  Its persistent advisory lock is stored in the OS user-data directory, keyed
  by local project identity, contains no PID, port, or bearer, and is not
  listener authentication. Unix permissions are restricted; Windows uses the
  inherited user-data-directory ACL, which Phantom does not independently
  verify. Detached `start --daemon` and all external shutdown fail closed;
  `phantom stop` authenticates legacy v0.7.3 state only to report safe manual
  migration guidance and never kills a process or deletes the record.
- Removes the file-vault passphrase and ambient protected dotenv values from
  both proxied and direct `phantom exec` child environments, inserts only fresh
  session tokens for protected keys, scrubs configured service, connection,
  rotation, sync, proxy-control, and built-in base-URL variables, and refuses
  missing vault mappings or configured connection strings before child launch.
- Persists one strictly validated dotenv-like filename beside `.phantom.toml`,
  migrates conventional legacy dotenv names without path traversal or symlinks,
  and refuses direct launch when protected state has no token-bearing managed file.
- Disables all client-controlled token substitution in request headers and
  bodies. Only the authenticated, exactly matched route injects its configured
  vault value into its fixed authentication header; missing mappings fail before
  any upstream call. Bodies remain byte-preserving under a hard size cap.
  Credential-bearing upstream HTTP disables ambient forward-proxy discovery.

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

[Unreleased]: https://github.com/ashlrai/phantom-secrets/compare/v0.7.5...HEAD
[0.7.5]: https://github.com/ashlrai/phantom-secrets/compare/v0.7.4...v0.7.5
[0.7.4]: https://github.com/ashlrai/phantom-secrets/compare/v0.7.3...v0.7.4
[0.7.3]: https://github.com/ashlrai/phantom-secrets/compare/v0.7.0...v0.7.3
[0.7.2]: https://github.com/ashlrai/phantom-secrets/compare/v0.7.0...v0.7.2
[0.7.1]: https://github.com/ashlrai/phantom-secrets/compare/v0.7.0...v0.7.1
[0.7.0]: https://github.com/ashlrai/phantom-secrets/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/ashlrai/phantom-secrets/releases/tag/v0.6.0
