### Changed (OS credential store crates)

- The vault, the cloud passphrase, and the cloud key pair now reach the OS
  credential store through `keyring-core` 1 and one store crate per platform,
  replacing `keyring` 3: `apple-native-keyring-store` (macOS Keychain),
  `windows-native-keyring-store` (Windows Credential Manager), and on Linux
  `linux-keyutils-keyring-store` plus `dbus-secret-service-keyring-store`.
  The Linux Secret Service store uses blocking D-Bus with bundled libdbus and
  RustCrypto key exchange, so Linux builds need neither a system libdbus nor
  openssl. Service and account names are unchanged. Reading entries that a
  keyring 3 build wrote has not yet been live-tested on Linux Secret Service or
  Windows Credential Manager; see
  `docs/design/keyring-4-migration-scoping.md`.

### Security (dependency advisories)

- `deny.toml` no longer ignores RUSTSEC-2026-0370 (`zvariant`),
  RUSTSEC-2026-0371 (`zbus_names`), or RUSTSEC-2026-0372 (`zvariant_derive`).
  No zbus version remains in the resolved graph, and `cargo deny check` passes
  without those ignores.

### Changed (MCP SDK)

- `phantom-mcp` builds on `rmcp` 3.9 (was 3.5). The tool catalog and
  `mcp-registry/server.json` are unchanged.

### Added (account-ops engine, library only)

- `phantom_core::account_ops` is a value-free create, rotate, revoke, and
  status engine. It ships with a GitHub App installation-token adapter. Each
  operation checks the `~/.ashlr/KILL` switch, binds the secret name to the
  adapter's namespace, and defaults to a dry run. Operations are recorded in
  a hash-chained ledger at `~/.phantom/account-ops.jsonl`, with a head anchor
  that detects truncation. Issued values go only to the vault writer. If
  storing a value fails, the engine revokes it. No CLI or MCP command calls
  the engine, and live provider issuance stays hard-denied.
  `.github/CODEOWNERS` now assigns an owner to the module.

### Fixed (Personal Cloud push)

- The Supabase migration `20261009225441_enforce_personal_vault_quota` adds
  `push_personal_vault`, the function that the `/api/v1/vault/push` route
  calls. It serializes pushes per user and checks the expected version, and
  it admits one new encrypted backup per account. Existing backups, including
  legacy over-quota rows, can still be read and updated. Only the service
  role can call it.

### Security (Personal Cloud table grants)

- The Supabase migration `20261009231437_clamp_browser_table_authority`
  limits browser sessions to `SELECT` on `users`, `vault_blobs`, `teams`, and
  `team_members`, under the existing ownership RLS policies. It also revokes
  every `PUBLIC` and `anon` table privilege, removes column-level grants, and
  drops service-role access to tables the server does not use. Rollback
  scripts are in `apps/web/supabase/rollback/`, and CI now runs the
  `supabase test db` grant and row-isolation suite.

### Fixed (npm wrappers)

- The `phantom-secrets` npm wrapper treats a zero-byte cached binary or
  manifest as missing and downloads it again, even if its digest matches.
- The `phantom-secrets-mcp` wrapper requires the version line to be the
  whole `phantom-mcp --version` output. Tests reject extra blank lines,
  Unicode line separators, and NUL suffixes.
- `npm/README.md` adds `freebsd`/`arm64`, `linux`/`riscv64`, and
  `sunos`/`arm` to the platforms that fail closed before any download.

### Changed (SEO observer)

- `scripts/seo/observe.mjs` now fetches `/llms.txt` and `/llms-full.txt`
  directly instead of requiring them in the sitemap, which lists only HTML
  pages. An `--experiments`, `--gsc-file`, or `--ahrefs-file` input that is
  not valid JSON now exits 1 with the error on stderr instead of writing a failure report.

### CI (release and tool downloads)

- The release workflow pins npm `11.19.0` for trusted publishing (was
  `11.6.2`).
- CI caches the `cargo-deny` and `gitleaks` archives under a key built from
  each tool's version and SHA-256. It retries downloads and still verifies
  the checksum before use. `scripts/ci/verified-download.test.mjs` covers
  that path.

### CI (test coverage)

- New regression tests cover `atomic_write`: empty contents, Unicode bytes,
  replacing an existing file, a parent that cannot be created, and no
  leftover temporary files. They also cover proxy rate limiting and port
  binding, Unix installer staging and PATH-update failure cleanup, npm
  wrapper version and cache validation, and web manifest, quickstart,
  redirect, and request-body handling. `apps/web/README.md` documents how to
  run the web tests.

### CI (docs and installer suite wiring)

- On every push to `main`, CI now runs `scripts/freshness/check.mjs`,
  `scripts/release/lint-changelog.mjs`, and `scripts/changelog-fold.mjs
  --check`. The `[Unreleased]` compare-link fresh block in `CHANGELOG.md` had
  picked up the `[0.8.9]` link at the release cut, and nothing caught it. The
  link now sits outside the block.
- The Linux offline installer step now runs
  `installer-mktemp-failure`, `installer-success-cleanup`,
  `public-installer-staging-creation-failure`, and
  `public-installer-tmpdir-spaces`. They had merged without being added to the
  step, which made the `installer-offline-suite` guard fail.

### Changed (developer guide)

- `CLAUDE.md` names `rmcp` 3.9 as the MCP SDK. The duplicate
  `[Unreleased]` agent-quickstart bullet in `CHANGELOG.md` was removed, because
  the `changelog.d/agent-quickstart.md` fragment already records that change.
