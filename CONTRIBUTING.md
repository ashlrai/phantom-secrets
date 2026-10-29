# Contributing to Phantom

Thanks for helping make safe agentic development practical. Phantom accepts focused bug fixes, tests, platform hardening, service integrations, documentation, and carefully scoped feature work.

Please read the [Code of Conduct](CODE_OF_CONDUCT.md), [security policy](SECURITY.md), and [threat model](THREAT_MODEL.md) before changing a trust boundary. Report vulnerabilities privately; do not open a public issue for them.

Current release state changes with every release, so this file does not pin
it. See the [latest GitHub release](https://github.com/ashlrai/phantom-secrets/releases/latest),
the [changelog](CHANGELOG.md), and the [roadmap](ROADMAP.md) for the evidence
gates. A GitHub release receipt alone does not establish an npm, crates.io,
MCP Registry, or Homebrew publication, deployment, provider integration,
hosted entitlement, certification, or customer acceptance.

## Before you start

- Search [existing issues](https://github.com/ashlrai/phantom-secrets/issues) and [discussions](https://github.com/ashlrai/phantom-secrets/discussions).
- Open an issue or discussion before a large architectural change, new network/provider integration, new secret-reveal path, compatibility break, or change to the authority model.
- Keep pull requests reviewable. Separate mechanical refactors from behavioral or security changes.
- Never use production credentials in development, tests, fixtures, screenshots, logs, or issue reports. Use obviously fake values and throwaway accounts.

## Development setup

Prerequisites:

- Git
- Rust `1.95.0` with `rustfmt` and `clippy` (pinned by `rust-toolchain.toml`)
- Node.js 22 and npm when changing npm wrappers or `apps/web`
- A platform keychain only for explicitly ignored/manual keychain tests

```bash
git clone https://github.com/ashlrai/phantom-secrets.git
cd phantom-secrets

cargo build --workspace --locked
cargo test --workspace --all-targets --locked --no-fail-fast
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
```

On a machine where `cargo` is not on `PATH`, invoke the same commands through your rustup installation (for example, `~/.cargo/bin/cargo` on many Unix systems).

## Repository map

| Area | Purpose |
|------|---------|
| `crates/phantom-cli` | Operator CLI and command integration tests. |
| `crates/phantom-core` | Configuration, dotenv handling, cloud/auth clients, audit, validation, shared policy, and test-only provider protocol scaffolding. Production issuance is disabled. |
| `crates/phantom-cli/src/commands/grant` | Value-free grant metadata plus compatibility commands that hard-deny enrollment and remote revocation in 0.7.5. |
| `crates/phantom-vault` | OS-keychain and encrypted-file vault backends. |
| `crates/phantom-proxy` | Authenticated loopback proxy, exact route-owned auth-header injection, inert client headers/bodies, response scrubbing, and streaming. |
| `crates/phantom-mcp` | MCP server, closed parameter schemas, the governed conversation facade, and separately gated compatibility tools. |
| `crates/phantom-workspace` | Value-blind workspace planning and trusted-terminal setup transactions. |
| `crates/phantom-authority` | Closed authority contracts; production verification remains deny-all. |
| `crates/phantom-locus-contract` | Inactive compatibility requirements for a future Locus integration. |
| `crates/phantom-broker` | Inactive broker protocol and durable replay/accounting foundations. |
| `crates/phantom-runtime` | Closed engineering actions and deny-all production execution boundary. |
| `crates/phantom-session` | Inactive crash-explicit session coordination foundation. |
| `crates/phantom-evidence` | Inactive value-free evidence and receipt foundation. |
| `npm`, `npm-mcp` | Native-binary download and launch wrappers. |
| `apps/web` | Next.js application and Phantom Cloud API. |
| `docs` | User guides, integration guides, static site assets, and the [documentation map](docs/README.md). |

Do not infer production activation from a crate's presence. The execution-kernel
foundations must stay fail closed until the activation boundaries in
[`docs/architecture.md`](docs/architecture.md) and
[`THREAT_MODEL.md`](THREAT_MODEL.md) are resolved and accepted.

The word **grant** has two distinct meanings. Historical provider-grant source
models credential and renewal metadata, while an authority grant is an inactive
value-free execution-kernel type. Released 0.7.5 creates no live provider grant:
enrollment and remote revocation hard-deny before credentials or network. A
provider-grant record must never be accepted as a Locus credential, broker
lease, or execution permit. Current behavior is specified in
[`docs/grants-spec.md`](docs/grants-spec.md); the root
[`ISSUANCE_CONTRACT.md`](ISSUANCE_CONTRACT.md) is the original design contract.

## Making a change

1. Create a branch from the current `main`.
2. Find and reuse the existing parsing, filesystem, confirmation, error, and test patterns for the affected surface.
3. Add tests that demonstrate both the intended behavior and important failure modes.
4. Update user, agent, registry, and security documentation when a public contract changes.
5. Run the proportional checks below and record exact commands and results in the pull request.

The project generally uses focused conventional commit subjects such as
`fix:`, `docs:`, `test:`, and `chore:`. Git history is the current convention;
there is no claim that a commit-message bot enforces it.

Security-sensitive code must fail closed. Unexpected input, missing state, unsupported platforms, failed authentication, ambiguous crash recovery, and stale authority should not silently downgrade to permissive behavior.

## Verification

Every Rust change should pass these source gates. The tag release workflow
enforces the same locked all-target test, format, and strict Clippy contract;
contributors should run it before opening a pull request:

```bash
cargo test --workspace --all-targets --locked --no-fail-fast
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
```

On pull requests, CI classifies the changed paths and skips suites a change
cannot affect: docs-only changes skip the Rust and web suites, and Rust tests
run through `cargo nextest` on the touched crates and their dependents. Secret
scanning and the Rust dependency policy always run. The single `CI Gate` job
fails if any selected job did not succeed. Pushes to `main` run everything.

### Keyring advisory exceptions

[`deny.toml`](deny.toml) ignores RUSTSEC-2026-0370 (`zvariant`),
RUSTSEC-2026-0371 (`zbus_names`), and RUSTSEC-2026-0372
(`zvariant_derive`). These are unmaintained-crate advisories, not vulnerability
advisories: keyring 3 pulls the crates through zbus 4 for Linux Secret Service,
and keyring 3 has no release using zbus 6, where they were folded into zbus.
Removal depends on the [keyring migration tracked in #242](https://github.com/ashlrai/phantom-secrets/issues/242)
eliminating these dependencies from the resolved graph; keyring 4 alone does
not necessarily do so. See the [migration scoping note](docs/design/keyring-4-migration-scoping.md)
for backend tradeoffs and verification needed before removing the exceptions.
Run `node --test scripts/keyring-advisory-docs.test.mjs` when changing this note
or the related policy.

The daily full-suite run keeps its complete cross-OS coverage but also gets an
off-peak slot: `scripts/ci/daily-matrix.mjs` computes the affected-only OS
matrix for `Test (${{ matrix.os }})` from a diff (per-leg `cfg` routing, failing
closed to all three legs) and emits the additive off-peak cron from
`scripts/ci/offpeak-schedule.json`. Check names are unchanged — the tool only
ever emits the same `macos-latest`/`ubuntu-latest`/`windows-latest` labels. See
[scripts/ci/daily-matrix.md](scripts/ci/daily-matrix.md) for rules and the
workflow wiring, and run its suite with
`node --test scripts/ci/daily-matrix.test.mjs`.

Run additional checks for the surface you changed:

```bash
# MCP release binary
cargo build --release --locked -p phantom-secrets-mcp --bin phantom-mcp

# MCP catalog: mcp-registry/server.json must match the runtime tools/list
cargo build --locked -p phantom-secrets-mcp --bin phantom-mcp
node scripts/release/mcp-stdio-smoke.mjs target/debug/phantom-mcp 54

# Changelog headings, dates, ordering, and compare links
node scripts/release/lint-changelog.mjs

# Provider hard-denial and exact cfg(test) transaction-scaffolding tests
cargo test --locked -p phantom-secrets --test grant_github_app_test
cargo test --locked -p phantom-secrets --test grant_vercel_integration_test
cargo test --locked -p phantom-secrets --test grant_sentry_test
cargo test --locked -p phantom-secrets --test grant_supabase_test
cargo test --locked -p phantom-secrets --test grant_stripe_test
cargo test --locked -p phantom-secrets --test grant_revoke_test

# npm wrappers
npm --prefix npm test
for test in npm-mcp/test/*.test.js; do node "$test"; done
(cd npm-mcp && npm pack --dry-run)

# Web application
(cd apps/web && npm ci && npm audit --omit=dev --audit-level=moderate && npm test && npm run build)
```

When an MCP catalog intentionally changes, update the server declarations,
closed parameter schemas, generated/mirrored registry surfaces, and packaged
stdio smoke together. After reviewing the runtime effects, regenerate the
registry file with
`node scripts/release/mcp-stdio-smoke.mjs target/debug/phantom-mcp 54 mcp-registry/server.json --write-registry`;
the Linux CI test job runs the same smoke without `--write-registry`. Do not hard-code a catalog count in prose unless release
automation enforces it.

Ignored keychain tests touch the host OS keychain. Run them only on a disposable test identity after reviewing the test:

```bash
cargo test --workspace -- --ignored
```

CI runs the normal Rust suite on macOS, Linux, and Windows. A successful cross-compile or CI matrix does not prove native installer trust, keychain UX, code signing/notarization, shell integration, or end-to-end acceptance on every device; describe exactly what you tested.

## Coding and security guidelines

- Use `thiserror` for reusable library errors and `anyhow` for CLI orchestration where appropriate.
- Keep secret values out of `Debug`, `Display`, serialization, logs, URLs, argv, receipts, MCP responses, telemetry, and error messages.
- Wrap secret-bearing memory in the repository's zeroization patterns and test error/early-return paths.
- Use the hardened filesystem helpers for secret or authority state; defend against symlinks, unsafe permissions, partial writes, and crash recovery.
- Keep proxy listeners loopback-only and authenticate every request before
  route matching. Client-controlled headers and bodies must remain inert; only
  the exact matched route may inject its vault value into its fixed auth header.
- MCP tools must use closed input schemas. A mutation requires the surface's explicit confirmation and out-of-band approval contract; a request ID or digest is not authority.
- `phantom_do` remains proposal-only. Do not connect its reserved `execute` phase to a shell or production executor.
- Do not add a plaintext secret argument to MCP. New values must be collected out of band in a trusted terminal.
- Keep all production provider issuance, enrollment, refresh, renewal,
  rotation, and revocation paths hard-denied before credential access and
  network I/O. Exact `cfg(test)` mocks may exercise local transaction
  scaffolding but are not provider acceptance or activation evidence.
- Keep provider-grant lifecycle separate from authority-grant verification.
  Remote revoke must fail before local mutation until provider revocation is
  implemented and accepted end to end.
- Put focused unit tests near the implementation and end-to-end/integration tests under the crate or application test directory.
- Comment non-obvious invariants and the reason for a safety check, not a narration of the code.

## Documentation guidelines

- Treat code, schemas, tests, and release automation as the source of truth.
- Label active behavior, experimental/fail-closed foundations, and roadmap proposals explicitly.
- Avoid volatile counts or version claims unless a test or release script enforces them.
- Include macOS, Linux, and Windows differences when they affect commands, storage, permissions, shells, packaging, or support.
- Keep links relative inside the repository so they work in forks and release source archives.
- Update the [documentation map](docs/README.md) when adding, moving, or retiring a guide.

## Pull requests

Do not edit `CHANGELOG.md` directly. Add one fragment file to
[`changelog.d/`](changelog.d/README.md) named `<pr-number-or-slug>.md` with a
`### Added|Changed|Fixed|Security (topic)` heading and bullets. Fragments are
folded into the Unreleased section at release time with
`node scripts/changelog-fold.mjs`, so queued pull requests no longer conflict
on the changelog.

When a rebase or merge still stops on `CHANGELOG.md`, `CLAUDE.md`, `README.md`,
or a lockfile, `scripts/resolve-merge-conflicts.sh` resolves those paths
mechanically: `CHANGELOG.md` is union-merged (`.gitattributes` sets
`merge=union`, which GitHub's server-side merge ignores but local and
lane-side merges honor), `CLAUDE.md`/`README.md` take the upstream version and
re-apply the lane's hunks that still apply, and `Cargo.lock`/`bun.lock`/
`package-lock.json` are regenerated by the package manager rather than
hand-merged. Run it, review any reported rejected hunks, then continue the
rebase. Conflicts on any other path remain manual.

Use the pull request template. A strong description explains the user problem, trust-boundary impact, exact verification evidence, platform coverage, and remaining limitations. Screenshots are helpful for UI changes but are not substitutes for behavioral tests.

Project decisions and review authority are described in
[GOVERNANCE.md](GOVERNANCE.md). For a bounded first contribution, improve a
documented example, reproduce an existing issue with a test, or propose a small
documentation correction; the project does not promise that a particular
`good first issue` queue is populated.

By contributing, you confirm that you have the right to submit the work and
agree that your contribution is licensed under the repository's
[MIT License](LICENSE). The project does not currently enforce a Contributor
License Agreement or Developer Certificate of Origin sign-off; adopting either
is a separate maintainer and legal-policy decision, not an implied requirement.

## Questions

Use [GitHub Discussions](https://github.com/ashlrai/phantom-secrets/discussions) for design and usage questions, [GitHub Issues](https://github.com/ashlrai/phantom-secrets/issues) for reproducible defects and accepted work, and [SUPPORT.md](SUPPORT.md) to choose the right public or private route.

### Testing affected Rust packages

`scripts/affected-tests BASE [HEAD]` prints Cargo package names, one per line,
for changed workspace crates and their transitive dependents. It uses Cargo's
resolved graph, including build, development, renamed and optional dependencies.
An empty list means no Rust packages are affected. Workspace configuration
changes, unknown crate paths, and unavailable metadata select `ALL`.

Run `make test-affected BASE=main` to test that selection, or `make test-affected`
to inspect tracked staged and unstaged changes against HEAD. Untracked files are
excluded; add new files to Git before using this shortcut. This is a local
iteration aid; the full workspace checks above remain required before merging.
Cargo and Python 3 must be on PATH. Run the selector's fixture tests with
`python3 scripts/affected-tests.test.py`.
