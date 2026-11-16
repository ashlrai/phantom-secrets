# keyring 4 migration scoping (issue #242)

Status: scoping note. Docs only. Nothing here changes code, dependencies or `deny.toml`.

Facts were checked on 2026-10-18 against `main` at `6895ecb`, the crates.io API, and a trial dependency resolution in a scratch worktree (no code was built or run against the new crates). Anything not checked is marked UNVERIFIED.

## 1. Question

Can moving from `keyring` 3.6.3 to 4.x remove the three RUSTSEC ignores in `deny.toml` (RUSTSEC-2026-0370 `zvariant`, RUSTSEC-2026-0371 `zbus_names`, RUSTSEC-2026-0372 `zvariant_derive`), and what would the move cost?

## 2. Current versions (crates.io, 2026-10-18)

| Crate | Latest stable |
|-------|---------------|
| keyring | 4.2.0 (2026-08-29) |
| zbus-secret-service-keyring-store | 1.0.1 (depends on secret-service ^5, zbus ^5) |
| dbus-secret-service-keyring-store | 1.0.1 (depends on dbus-secret-service ^4.1, no zbus) |
| secret-service | 5.2.0 (2026-08-29) |
| zbus | 6.0.0 (2026-10-16) |
| zvariant | 5.15.1 (2026-10-16) |
| oo7 | 0.6.0 (depends on zbus ^5.12) |
| linux-keyutils | 0.2.5 |
| apple-native-keyring-store | 1.0.2 |

Repository today: `keyring = "3"` in `crates/phantom-vault/Cargo.toml:26` and `crates/phantom-core/Cargo.toml:33`; lockfile has keyring 3.6.3, zbus 4.4.0.

## 3. Trial result (the deciding test)

In a scratch worktree the two `keyring` lines were replaced with `keyring-core` 1 plus the per-platform store crates, then `cargo metadata` resolved and `cargo tree -i` was run. Application code was not changed or compiled.

- Secret Service via `zbus-secret-service-keyring-store` 1.0.1: resolves to zbus 5.19.0 and zvariant 5.15.1. `cargo tree -i zvariant`, `zbus_names` and `zvariant_derive` all still show the crates (reached through `secret-service` 5.2.0). The three ignores would stay. keyring 4 does not help by itself, because no released Secret Service store is on zbus 6 yet (zbus 6.0.0 is two days old; the advisories say zvariant was folded into zbus from 6.0.0).
- Secret Service via `dbus-secret-service-keyring-store` 1.0.1 (libdbus based): `cargo tree -i zvariant` and `-i zbus_names` report that no such package is in the graph. With the three ignores deleted from `deny.toml`, `cargo deny check advisories` (cargo-deny 0.20.2) printed "advisories ok". `cargo deny check bans` reported the skips for `nix@0.29.0` and `security-framework@2.11.1` as unmatched (they would become removable). `core-foundation@0.9.4` stays, because `system-configuration` (via hyper-util) still uses it.
- Cost of the libdbus route: it links the system `libdbus-1` (the stores expose a `vendored` feature that builds it from source and needs a C toolchain). The scratch machine had no `pkg-config` or libdbus headers, so a real build was not attempted: build and release-binary impact is UNVERIFIED. It also changes which Linux systems work without extra packages, so the install docs and the Linux release job would need review.

Result: the ignores can go only with the libdbus store, or later with a zbus 6 store. Plain keyring 4 with the default (zbus) store keeps them.

## 4. API changes that matter to Phantom

Sources: docs.rs for keyring 4.2.0 and keyring-core 1.0.1, plus the crates' own source in the cargo registry.

- keyring 4 is split into `keyring-core` (the `Entry` API) and one crate per store. The old features (`apple-native`, `linux-native`, `async-secret-service`, `async-io`, `crypto-rust`, `windows-native`) no longer exist; the `keyring` crate has only `default`, `v1` and `cli`.
- Phantom builds an `Entry` from a chosen backend (`keyutils` or Secret Service) using `KeyutilsCredential::new_with_target`, `SsCredential::new_with_target` and `Entry::new_with_credential` (`crates/phantom-vault/src/keychain.rs:36` to `:55`). Those constructors are gone. keyring 4 installs one process-wide default store, so a per-entry backend choice must be rebuilt, for example as explicit store objects that each create entries. This is the largest code change. The keyutils default for unmigrated projects and cloud credentials (`crates/phantom-core/src/auth.rs:10` to `:22`) must stay byte-for-byte the same.
- Error type moves to `keyring_core::Error`; the code matches `NoEntry` in several places (`keychain.rs` and `crates/phantom-vault/src/lib.rs:192` to `:199`). Variant names were not compared: UNVERIFIED.
- MSRV: keyring 4.2.0 and the zbus store need 1.88, zbus 6.0.0 needs 1.89. CI pins 1.95.0, so this is fine.
- keyring 4.1.3 is yanked; avoid it.

## 5. Data compatibility with keyring 3 items

By source reading (not by running anything):

- keyring 3.6.3 Secret Service items carry attributes `service`, `username`, optionally `target`, plus `application = rust-keyring`, and a label (`keyring-3.6.3/src/secret_service.rs:244` to `:271`).
- Both keyring 4 Secret Service stores search by `service` and `username` (plus `target` when set) only (`zbus-secret-service-keyring-store-1.0.1/src/cred.rs:100` to `:109`). Searching by a subset of attributes should find items written by keyring 3, so reads should keep working. This is a reading of the code, not a test.
- keyutils entries are a separate backend (`linux-keyutils-keyring-store` 1.0.0). Whether its key descriptions equal keyring 3's was not compared: UNVERIFIED.
- macOS Keychain and Windows Credential Manager: attribute and target naming compat with keyring 3 is UNVERIFIED. A real upgrade-read test on each platform is required before merging.
- Not testable on this machine: it has no running Secret Service and no libdbus headers, so no old-build-writes, new-build-reads test was run. The mock store in `keyring-core` would not exercise the real attribute mapping.

## 6. Options

| Option | Effect on ignores | Risk | Notes |
|--------|-------------------|------|-------|
| A. Stay on keyring 3 | none | none | Ignores stay documented in `deny.toml`; advisories are "unmaintained", not vulnerabilities |
| B. keyring 4 with zbus store | none (zbus 5 still pulls the crates) | high code churn for no advisory gain | Not recommended on its own |
| C. keyring 4 with libdbus store | all three removable (trial) | new system library on Linux, unverified build and data compat | Removes ignores; changes Linux requirements |
| D. Wait for a zbus 6 store, then B | removable once released | none now | Check `zbus-secret-service-keyring-store` and `secret-service` releases; zbus 6 is only two days old |

## 7. Recommendation

Do D now (wait, keep the ignores, which are already commented as "revisit with the keyring 4 migration"), and re-check upstream when `secret-service` or `zbus-secret-service-keyring-store` publishes a zbus 6 release. Do not start the code migration before one of these is true: a zbus 6 store exists, or the reviewer accepts the libdbus requirement of option C. When it starts, do it in this order, one PR each: (1) introduce a thin Phantom store trait around today's calls with no behavior change, (2) swap the store crates, (3) delete the ignores and the skips that become unmatched.

Option C is a legitimate alternative only if removing the ignores is worth the new system dependency; that is a maintainer decision.

## 8. Test plan (when work starts)

1. `cargo tree -i zvariant -i zbus_names -i zvariant_derive` shows nothing; delete the three ignores; `cargo deny check` passes (`unused-ignored-advisory = "deny"` already forces deletion).
2. Existing vault and auth unit tests on Linux, macOS and Windows CI.
3. Compat: write entries with a keyring 3 build, read and migrate them with the new build, on Linux with an unlocked Secret Service (and keyutils), macOS Keychain and Windows Credential Manager.
4. Confirm the keyutils path is unchanged for unmigrated projects and cloud credentials.
5. Measure binary size and build time before and after; no numbers are claimed here.

## 9. Open questions

1. Is a new libdbus system dependency on Linux acceptable (option C), or should the project wait for a zbus 6 store (option D)?
2. Are the `keyring_core::Error` variants Phantom matches unchanged? (UNVERIFIED)
3. Do keyring 3 keyutils and platform entries remain readable under the new store crates? (UNVERIFIED)
