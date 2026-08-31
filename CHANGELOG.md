# Changelog

Notable user-facing changes are recorded here. Phantom follows [Semantic Versioning](https://semver.org/) while pre-1.0: minor releases may change unstable interfaces, and breaking changes should be called out explicitly.

## [Unreleased]

No user-facing changes have been recorded after 0.7.0.

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

[Unreleased]: https://github.com/ashlrai/phantom-secrets/compare/v0.7.0...HEAD
[0.7.0]: https://github.com/ashlrai/phantom-secrets/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/ashlrai/phantom-secrets/releases/tag/v0.6.0
