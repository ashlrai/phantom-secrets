# Phantom adoption and cross-platform security audit — 2026-09-03

## Scope and evidence identity

This review covers the uncommitted adoption, documentation, installer, and Linux
vault-migration changes in
`/Users/masonwyatt/.codex/worktrees/phantom-adoption-polish`. The branch is
`codex/phantom-adoption-polish`; its reviewed base is
`fd81100a82ae1eaaaaebb3c24f8d39e65810e677`. Because the final review is of a
dirty working tree, this report does not claim an immutable candidate SHA.

Priority surfaces were the first-party Markdown renderer and document catalog,
structured data, crawler/auth headers, Windows PowerShell and npm installation
paths, Linux keyutils-to-Secret-Service migration, and the resulting dependency
graph. Existing authentication and proxy code was inspected where the changed
surface depended on it; this is not a new full audit of every unchanged route.

## Result

No critical, high, or medium-severity vulnerability remains open in the
reviewed source. No severity-rated finding remains open:

| Severity | Count |
|---|---:|
| Critical | 0 |
| High | 0 |
| Medium | 0 |
| Low | 0 |

The source is suitable for final-SHA CI and native platform acceptance. It is
not evidence that Windows or Linux native jobs, signing/notarization,
publication, deployment, or authenticated production flows have passed.

## Resolved findings

### PA-01 — Resolved — Landing JSON-LD lacked script-safe serialization

**Original evidence.** The landing component placed `JSON.stringify(howTo)` and
`JSON.stringify(faqPage)` directly inside `dangerouslySetInnerHTML`. The current
inputs were repository-owned constants, so no active exploit was present, but a
future externalized string containing `</script>` could have broken out of the
raw JSON-LD script element.

**Correction.** `apps/web/src/components/landing/LandingStructuredData.tsx:55-68`
now routes both JSON-LD objects through one serializer that replaces every `<`
with the JSON escape `\u003c`, matching the first-party docs implementation.
`apps/web/tests/site-shell-seo.test.cjs:86-104` binds both call sites to the
serializer and verifies that a `</script><script>alert(1)</script>` fixture
contains no literal opening or closing script tag after serialization.

**Verification.** The focused site-shell suite passed 9/9; the full web suite
passed 125/125; zero-warning ESLint and the 39-route production build passed.

### PA-04 — Resolved — Root JSON-LD retained raw serialization sinks

**Original evidence.** The three repository-owned JSON-LD objects in
`apps/web/src/app/layout.tsx` still passed raw `JSON.stringify(...)` output to
`dangerouslySetInnerHTML`. Their current fields were constants and therefore
did not provide an active attacker-controlled breakout, but the sink lacked the
script-safe invariant already enforced for landing and documentation JSON-LD.

**Correction.** `apps/web/src/app/layout.tsx:29-31,136-220` now routes all three
objects through `serializeStructuredData`, which escapes every `<` as the JSON
escape `\u003c`. `apps/web/tests/site-shell-seo.test.cjs:106-121` verifies all
three raw-insertion call sites, forbids direct `JSON.stringify` at those sinks,
and checks a malicious closing-script fixture.

**Verification.** The focused site-shell suite passed 10/10; the complete web
suite passed 126 tests; zero-warning ESLint and the 39-route production build
passed.

### PA-02 — Resolved — Linux backend selection could downgrade after marker loss plus reboot

**Original evidence.** Backend selection previously depended on one durable
filesystem marker plus a volatile keyutils sentinel. Loss of the filesystem
marker followed by reboot made a migrated project indistinguishable from an
untouched keyutils project during ambient access.

**Correction.** `crates/phantom-vault/src/keychain.rs:294-329` now classifies two
matching value-blind records. They are published under independently retained,
owner-only ProjectDirs data and config targets (`keychain.rs:436-477`). Both
absent means untouched; both valid and byte-identical means persistent; one
missing, corrupt, wrong-project, unsupported, or divergent fails closed. A
persistent state additionally requires the matching Secret Service sentinel at
`keychain.rs:345-385`. Normal unmarked/headless opens do not probe Secret
Service. The explicit trusted-terminal path may probe it and idempotently repair
a verified prepared state (`keychain.rs:1390-1435`). Publication writes the
config-root corroboration record first and data-root commit record last while
holding the project lock (`keychain.rs:1372-1523`).

**Verification.** The host-independent reboot/keyutils-loss plus primary-marker
loss regression is at `keychain.rs:1820-1849`. Focused keychain tests passed
31/31 with one intentionally ignored native OS-keychain test.

### PA-03 — Resolved — Split Linux precheck could route a newly incomplete migration to fallback

**Original evidence.** `crates/phantom-vault/src/lib.rs:67-74` called
`project_requires_linux_secret_service`, which classifies marker state while
holding the project lock, then released that lock. It separately called
`KeychainVault::new` inside the generic keychain-error fallback.
If another process began migration after the precheck and left a one-marker
intermediate state before the constructor obtained its lock, the constructor
correctly returned the incomplete-state error. The caller then treated that error
as generic keychain unavailability and could select the encrypted-file fallback
instead of preserving the “one missing record denies normal access” invariant.

This required a concurrent migration and an interrupted/intermediate marker
publication, and the fallback emitted a warning. It did not disclose a secret,
but it could change storage posture during the exact state that was intended to
deny normal vault access.

**Required correction.** Make backend classification and construction one
locked, authoritative operation, or return a typed migration-state error that
the outer factory must propagate without entering fallback. Add a deterministic
transition test where the first observation is untouched and the constructor's
observation is incomplete.

**Correction.** `crates/phantom-vault/src/lib.rs:67-100` now retains one
per-project lock across backend selection, the availability probe, and any
implicit encrypted-file fallback provisioning. The split precheck was removed.
`KeychainVault::new_with_project_lock` returns a typed `Authoritative` or
`Unavailable` result (`crates/phantom-vault/src/keychain.rs:118-145,923-972`):
marker-state and Secret Service failures are authoritative and propagate,
whereas only an untouched keyutils/native-keychain probe failure remains
fallback-eligible. The deterministic transition regression at
`keychain.rs:1851-1877` proves an untouched-to-incomplete observation is
classified authoritative rather than fallback-eligible.

**Verification.** Focused keychain tests passed 32/32 with one intentionally
ignored native OS-keychain test. The complete vault library passed 158/158 with
the same one ignored integration test; `git diff --check` passed.

## Corrected during this audit

The initial Linux dependency choice activated `libdbus-sys`, which would have
required undeclared system tooling in release builds and failed the repository's
locked dependency policy. An intermediate pure-Rust graph then introduced
duplicate `syn`, `toml_*`, and `winnow` versions rejected by `cargo-deny`. The
settled candidate uses the pure-Rust `zbus` Secret Service path with compatible
locked proc-macro/serde versions and no new deny exception. The exact locked,
all-features `cargo-deny` command now passes advisories, bans, licenses, and
sources.

The docs implementation was also hardened during review to reject
protocol-relative Markdown links and to escape `<` in document JSON-LD before
raw script insertion. Homepage HowTo/FAQ and root-layout JSON-LD now use the
same script-safe escaping, resolving PA-01 and PA-04 with malicious
closing-script regressions.

The dual local Linux marker scheme resolves PA-02's reboot downgrade after loss
of one marker. PA-03 then removed the caller-level transition race by retaining
one project lock through the only implicit fallback decision and making
migration-state failures non-fallback-eligible.

## Verified controls

- The documentation catalog requires closed slug and filename formats and only
  reads exact allowlisted repository files (`apps/web/src/lib/public-docs.ts:19-49`).
  A traversal-shaped `/docs/%2e%2e%2fSECURITY` request returned a non-disclosing
  404 in the production build.
- Markdown content is rendered as React text/elements rather than raw HTML.
  Explicit-scheme links allow only HTTP, HTTPS, and mailto; other schemes are
  suppressed, and protocol-relative links cannot navigate off-site.
- Homepage, root-layout, and document JSON-LD escape `<` before
  `dangerouslySetInnerHTML`.
- Security headers include HSTS, CSP, `nosniff`, frame denial, COOP, CORP,
  referrer policy, and a restrictive permissions policy. Production responses
  for `/dashboard`, `/device`, and `/integrations/vercel/success` carried
  `X-Robots-Tag: noindex, nofollow`; `robots.txt` allows crawlers to observe
  those page-level directives while excluding `/api/`.
- Windows npm cache selection accepts an explicit drive-absolute native home
  and rejects MSYS-style `/c/...` values. Installer paths retain root,
  symlink/reparse, ownership, archive-shape, checksum, exact-version,
  transaction, and rollback checks.
- The settled candidate manifests, npm wrappers, direct-installer candidate
  defaults, and release-contract tests agree on source version `0.7.7`; public
  marketing metadata remains intentionally bound to the separately verified
  `v0.7.5` release rather than claiming the unpublished candidate is live.
- Linux migration requires attached stdin, stdout, and stderr terminals, an
  exact bounded confirmation, managed-dotenv preflight, a project lock, a
  reviewed value-free index state, conflict refusal, and exact read-after-write
  verification. It publishes the durable Secret Service sentinel and filesystem
  backend marker only after copies verify. Marker-present vault opens require
  the matching durable sentinel and fail closed if Secret Service is
  unavailable.
- Matching owner-only data/config marker records prevent loss of either one
  record plus reboot from appearing unmigrated; incomplete, corrupt, and
  divergent local states fail closed inside the keychain state machine.
- Linux authentication token storage remains explicitly bound to keyutils and
  is not silently switched by Cargo feature unification.
- No reviewed code path logs or returns vault values. The migration receipt is
  value-free and explicitly reports retained source copies.

## Automated and runtime verification

- `semgrep scan --config auto --config p/owasp-top-ten --config p/javascript
  --config p/typescript`: 463 files considered; two findings manually reviewed.
  The docs `dangerouslySetInnerHTML` alert is mitigated by `<` escaping and a
  closed local source. The dynamic-RegExp alert is unchanged code that escapes
  regex metacharacters before translating a closed glob expression
  (`scripts/release/pre-tag-preflight.mjs:277-290`). Semgrep emitted parser
  notices for shell-heavy workflow expressions, one Markdown regex, and a Rust
  file; those areas were covered by manual review plus their native linters or
  tests rather than represented as fully parsed by Semgrep.
- Gitleaks 8.30.0 scanned the final tracked-plus-untracked source mirror
  (approximately 5.54 MB): zero leaks.
- `npm audit --omit=dev --offline` in `apps/web`: zero vulnerabilities across
  42 production and 430 total dependency records. The two minimal npm wrapper
  directories do not carry lockfiles, so a package-local npm audit is not
  available there.
- `cargo deny --all-features --locked check --deny warnings advisories licenses
  bans sources`: all four gates passed on the settled lockfile.
- Vault library tests: 158 passed, zero failed, one intentionally ignored
  OS-keychain integration test. CLI Linux migration confirmation tests: 2
  passed. Formatting and `git diff --check` passed.
- After the PA-02/PA-03 corrections, the focused keychain suite passed 32 tests with
  the same one native OS-keychain integration test intentionally ignored.
- Focused site-shell/structured-data suite: 10 passed, including malicious
  closing-script fixtures for landing and root layout. Full web suite: 126
  passed; ESLint and the Next
  production build passed with 39 routes. Runtime checks returned 200 for public
  docs, health, robots, sitemap, and noindex surfaces, and 404 for
  traversal/unknown docs.
- Fresh installer and release contract subset: 56 passed with one expected
  PowerShell skip because `pwsh` is unavailable on this macOS host. Both full
  npm wrapper suites passed at version `0.7.7`, including cache/version,
  archive-shape, lock, transaction, signal, MCP schema, and release-artifact
  checks.

## OWASP-oriented coverage

| Area | Outcome |
|---|---|
| Access control / auth | No changed-route bypass found; sensitive UI surfaces receive noindex headers. |
| Injection / XSS | No active Markdown injection found; PA-01 and PA-04's conditional JSON-LD breakout paths were corrected and regression-tested. |
| Cryptographic failures / secrets | No leaked credential detected; migration values stay outside receipts and logs. |
| Security misconfiguration | Baseline response headers and crawler boundaries verified in a production server. |
| Vulnerable components | Web production audit and Rust locked dependency policy passed. |
| Integrity / supply chain | Installer checksum, exact-version, archive-shape, transaction, and release-contract tests passed. Native signing remains external. |
| Logging / monitoring | Reviewed audit and receipt changes remain value-free. |
| SSRF / outbound trust | No new arbitrary server-side fetch was introduced by docs or installers; installer hosts remain closed. |

## Remaining gates and limitations

- Native Linux compilation and a real Secret Service/keyutils migration require
  Linux CI or a Linux host. The local macOS cross-check lacks the Linux
  sysroot/C toolchain and cannot establish runtime DBus/keyring behavior.
- Native Windows PowerShell execution, junction/reparse behavior, x64/ARM64
  archive installation, and binary launch require Windows CI. The local
  PowerShell acceptance test was skipped because `pwsh` is unavailable.
- The ignored OS-keychain integration test must be run on each supported native
  platform. Unit tests do not establish desktop unlock/session behavior.
- The CSP still permits inline scripts and styles. This predates the reviewed
  changes and makes script-safe serialization especially important; nonce/hash
  migration should be handled as a separate compatibility project.
- A green source audit does not establish GitHub-hosted workflow execution,
  artifact provenance, macOS notarization, Windows Authenticode, a published
  `v0.7.7` GitHub release, npm promotion, or production deployment.

## Decision

Proceed only to exact-final-SHA CI and the native Linux/Windows/macOS acceptance
matrix. No reviewed source finding remains open, but production release remains
gated on the native and external evidence above.
