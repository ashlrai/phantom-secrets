# Phantom release and hosted-readiness security audit — 2026-09-01

## Scope and evidence identity

This review covers the `codex/release-hosted-readiness-20260901` candidate in
`/Users/masonwyatt/.codex/worktrees/phantom-release-hosted-readiness-20260901`.
The work began from exact `origin/main`
`61b57a3696335b27171fd40df3b620596da2bb40`; the first candidate commit was
`357b18d1c2bc7f55f4186cc16689f4c04cc26f97`. Final corrections were reviewed
and tested as a dirty working-tree diff, so this report does not claim an
immutable final candidate SHA.

The scope is the reusable/tag release workflows, direct native installers and
their offline acceptance harness, public web health/readiness routes, Next.js
build/runtime configuration binding, and related tests and documentation. It
does not establish a GitHub-hosted rehearsal, protected-branch result,
attestation, package publication, code signature, deployment, applied database
migration, provider activation, or authenticated customer acceptance.

## Result

No unresolved critical or high-severity source finding was identified in this
scope. Independent reviews found and corrected the following candidate issues:

| ID | Severity before correction | Finding | Correction |
|---|---:|---|---|
| RH-01 | High | A read-only rehearsal called a reusable workflow containing write-permission attestation jobs. | Extracted a reusable `release-build.yml` graph with `contents: read` only. The tag wrapper alone contains job-scoped attestation and human-gated publication authority. |
| RH-02 | High | Runtime-only public Supabase variables could make readiness succeed for a browser bundle built without or for different values. | A non-secret SHA-256 fingerprint now binds the exact validated build-time public configuration to runtime; a two-build production regression proves runtime injection cannot upgrade an unconfigured bundle. |
| RH-03 | High | The initial native harness called a pre-promotion checksum rejection “rollback.” | Both Unix and PowerShell installers now expose an exact-opt-in, test-only fault immediately after promotion. Acceptance proves the sentinel-bearing prior tree is restored without transaction residue, then separately checks checksum-failure preservation. |
| RH-04 | Medium | Public probes exposed exact source/environment, detailed validation failures, and commissioned-service posture. | Anonymous responses now contain only status, service, and release version. Detailed identity and configuration state remain internal to the readiness decision. |
| RH-05 | Medium | Readiness accepted an arbitrary dotted HTTPS Supabase origin, despite a narrower CSP and service-role destination. | Public auth configuration now requires a non-empty `*.supabase.co` hostname and the exact build/runtime fingerprint. |
| RH-06 | Medium | The production-build fixture could copy a developer's dotenv files, weakening hermeticity and duplicating local credentials in temporary storage. | The fixture excludes every `.env*` file except the value-free example and strips relevant inherited variables. |
| RH-07 | Medium | Web lint existed locally but was absent from normal CI and the release graph. | Both workflows now run the deterministic zero-warning ESLint gate after the locked install. |

## Verification

- `cargo test --workspace --all-targets --locked --no-fail-fast`: passed; one
  OS-keychain test remained intentionally ignored for per-platform manual
  execution.
- `cargo fmt --all -- --check` and strict all-workspace/all-target Clippy:
  passed.
- `cargo deny --all-features --locked check --deny warnings advisories licenses bans sources`:
  advisories, bans, licenses, and sources passed.
- Release/publisher contract suite: **49 passed**.
- Direct installer/platform suite: **21 passed**, with the native PowerShell
  parse/runtime test skipped because `pwsh` is unavailable on this macOS host.
- Actual macOS ARM64 `0.7.4` archive installation and injected
  post-promotion rollback: passed.
- Web lint, **101 tests**, production build, and production dependency audit:
  passed; npm reported zero vulnerabilities.
- Version parity: `0.7.4` across **12 surfaces and 12 crates**.
- Gitleaks 8.30.0 scanned the tracked-plus-untracked source mirror
  (approximately 7.01 MB): no leaks found.
- Semgrep community rules scanned 403 source targets with 338 applicable
  rules: zero findings.
- Installer/public mirrors were byte-identical; Bash syntax, workflow YAML,
  and `git diff --check` passed.

## Remaining gates and limitations

- GitHub still needs to parse and execute the exact reusable workflow on the
  PR/rehearsal runner matrix. Local `actionlint` was unavailable.
- Native Windows PowerShell execution, Windows x64/ARM64 archives, Linux
  x64/ARM64 archives, and macOS x64 archives require retained CI receipts.
- macOS Developer ID/notarization, Windows Authenticode, and independent
  installer signature verification remain unavailable.
- Vercel must have access to system environment variables enabled and the
  exact build/runtime configuration supplied. Source cannot
  establish deployed environment state.
- Public readiness is configuration-only. It does not call Supabase, Stripe,
  Vercel, a migration, or an authenticated customer workflow.
- A release rehearsal consumes hosted CI capacity; a tag, attestation, release,
  package publication, deployment, database apply, or provider activation
  remains a separately governed action.

## Decision

Suitable for exact-commit pull-request and protected-branch validation. Not a
production deployment or release decision. Promotion requires green CI and
CodeQL on the final SHA plus separate retained evidence for every external gate
listed above.
