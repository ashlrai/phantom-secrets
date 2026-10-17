# Lease store key provisioning and a value-free list method

Status: proposal for security review. Docs only. No behavior described here is implemented, and nothing in this document activates lease issuance, revocation, or any broker path.

All line references are to `main` at commit `dab7f32`. Re-verify them before acting on this document.

## 1. Where things stand

`DurableReplayStore` (`crates/phantom-broker/src/replay_store.rs:195`) keeps replay, lease, and use accounting in one HMAC-authenticated JSON snapshot. Facts verified in code:

- The constructors take the key as a caller-supplied `[u8; 32]` (`bootstrap`, line 207; `open_existing`, line 230). Nothing in the repository supplies one: the only users of `DurableReplayStore` are the broker crate and `phantom-runtime` (`crates/phantom-runtime/src/runtime.rs:5`, `:125`, `:356`). Outside tests there is no caller that creates a store.
- The doc comment states the key "must come from a protected host facility; it is never written to disk and is zeroized on drop" (lines 193 to 194, field `Zeroizing<[u8; 32]>` at line 198).
- `validate_key` (line 1005) rejects only the all-zero key. It does not check entropy.
- The snapshot MAC is `HMAC-SHA256(key, "phantom.broker.replay-state.v2\0" || canonical_json(format_version, payload))` (lines 931 to 932 and 972 to 973). A second use of the same key derives a per-store binding with the domain string `phantom.broker.replay-store-binding.v2\0` (line 765), used to bind permits and witnesses to this store (lines 426, 590, 647, 756).
- The module header says the snapshot "cannot, by itself, detect replacement with an older valid snapshot" and is "not an activation authority until a host-protected monotonic rollback anchor is added" (lines 9 to 13). Key provisioning alone does not fix this.
- Files are created `0700` for the directory and `0600` for files (`replay_storage.rs:25` and `:26`). Unsupported platforms fail closed.
- The snapshot never stores grants, signatures, credential locators, proxy credentials, request bodies, or secret values (header, lines 3 to 5). Persisted lease fields are listed at `replay_store.rs:859` (`PersistedLease`).

The key is therefore both an integrity key for the state file and the root of the store binding. It is not an encryption key; the snapshot is plaintext JSON of opaque identifiers and digests.

## 2. Threat model for the key

In scope:

1. A process running as a different user, or a later reader of a backup or disk image, who can read the store directory. They must not be able to forge a valid snapshot (for example to mark a revoked lease unrevoked, or to reset `remaining_uses`).
2. Accidental exposure: the key must not land in the repository, logs, shell history, environment, or crash dumps.
3. An agent running as the same OS user. Phantom's stated boundary treats agent context as the thing to protect. A same-user process can usually read `0600` files and often the user keychain, so for this adversary no local key source is sufficient on its own. The mitigation is the approval ceremony and process separation, not key placement. This document does not claim otherwise.

Out of scope here: rollback of the snapshot to an older valid one (needs a monotonic anchor, see section 8), a compromised `phantom` binary (already out of scope in `THREAT_MODEL.md`), and bind-mount aliasing (called out in `replay_storage.rs:8` to `:10`).

## 3. Key source options

### Option A: OS credential store

Store a random 32-byte key in the platform credential store, one entry per store, using the existing `keyring` dependency (`crates/phantom-vault/src/keychain.rs`).

- Pros: not on disk, survives restarts on macOS Keychain and Windows Credential Manager, reuses reviewed code paths and the entry-name hashing approach (`hash_secret_name`, `keychain.rs:182` to `:195`).
- Cons: on Linux the current feature selects kernel keyutils, which "is not durable across a reboot" (doc comment on the vault backend, `keychain.rs:196` to `:201`). A lost key makes the store unreadable. Because `open_existing` treats failures as hard errors and never resets (doc at `replay_store.rs:228` to `:229`), a lost key means every lease is gone and a new store must be bootstrapped, which is the same outcome as "new broker run revokes every lease" (section 7) but with a manual step.
- Same-user agents can often read the same keychain entry.

### Option B: derive from a vault key

There is no single vault master key to derive from. Verified: secrets live as separate credential-store entries (`keychain.rs`), and the encrypted-file fallback derives a key per blob from a passphrase using Argon2id inside `crypto::encrypt` and `crypto::decrypt` (`crates/phantom-vault/src/crypto.rs:62` and `:89`), with `FileVault` holding only the passphrase string (`file.rs:17`). So derivation would be possible only for the file-vault fallback, and only from the passphrase, not from a key.

If pursued: `key = HMAC-SHA256(passphrase_derived_ikm, "phantom.broker.replay-store-key.v1\0" || store_id_or_project_digest)`, with a domain string distinct from the two existing ones (`replay-state.v2`, `replay-store-binding.v2`). The workspace has `hmac` and `sha2` (`phantom-core/Cargo.toml:44` to `:45`) but no `hkdf` crate (a repository-wide search for `hkdf` in `crates/` finds nothing), so a derivation would either add `hkdf` or use a single-block HMAC construction and say so in the review.

- Pros: no new secret to store.
- Cons: couples lease integrity to passphrase compromise and passphrase rotation; works for one backend only; weaker than Option A for the default keychain vaults. Not recommended as the primary design.

### Option C: per-project file, mode 0600

Generate a random key and write it with `phantom_core::fs::atomic_write` (`crates/phantom-core/src/fs.rs:32`). There is precedent: the MCP approval key is generated, hex-encoded, and stored this way in `~/.phantom/mcp-approval-key` (`crates/phantom-core/src/mcp_approval.rs:363` to `:394`).

- Pros: works on every platform that supports the store, no keychain prompts, trivial to implement and test.
- Cons: key sits next to the data class it protects if the same directory is used. It must live outside the replay-store root and outside the workspace (the store already refuses to overlap the workspace, `replay_store.rs:236` to `:238`). Backups of the home directory would carry both. The file protects against other users, not the same user.

### Recommendation

Primary: Option A where the credential store is durable (macOS, Windows, Linux Secret Service), with Option C as the explicit fallback on Linux keyutils, chosen at bootstrap and recorded in a non-secret store descriptor (backend name only, never key bytes). Do not use Option B. The reviewer should decide whether a fallback to a file is acceptable or whether Linux without Secret Service should refuse to bootstrap (fail closed). Fail closed is the conservative default and the proposal.

In every option: generate with `OsRng` (already used for `store_id`, `replay_store.rs:218` to `:221`), wrap in `Zeroizing`, never accept the key from an environment variable or argv, and never log it.

## 4. Rotation

Rotation replaces the MAC key, not the lease contents.

1. Open the store with the old key and `start_epoch` as usual (which revokes all prior leases, section 7).
2. Generate the new key, re-serialize the snapshot with the new MAC, and write it with the existing atomic replace (`replay_storage.rs:259`) under the transaction lock.
3. Only after the write succeeds, update the key source and delete the old key.

Because step 1 revokes every lease, the simplest correct rotation is "rotate on broker restart", which loses nothing the restart does not already lose. A failed step 3 after a successful step 2 leaves a store the old key cannot open, so the new key must be persisted before the snapshot is rewritten, and the old key kept until the rewrite is verified by reopening. This ordering needs a test with injected faults. `replay_storage.rs` already has a replace-fault test hook (`ReplaceFault`, imported at `replay_store.rs:18` to `:19`) that can be reused.

The format version (`STORE_FORMAT_VERSION = 2`, line 39) does not change for key rotation. A key id field would require a format bump and is not proposed here.

## 5. A value-free list method

Goal: let a CLI show lease state without any path to secrets or to mutating state. The store currently has no read-only enumeration. Every public operation except `current_generation` is a mutation or requires an active epoch (`ensure_active`, line 800), and `current_generation` itself requires an active store.

Proposed shape, on the store, read-only, and requiring only `open_existing` (not `start_epoch`, so that listing never revokes anything):

```rust
pub struct LeaseSummary {
    pub lease_id: LeaseId,            // opaque id, already non-secret
    pub grant_id: GrantId,            // opaque id
    pub operation: Operation,         // enum, e.g. need_secret
    pub workspace_id: WorkspaceId,    // opaque id
    pub broker_generation: u64,
    pub remaining_uses: u32,
    pub revoked: bool,
    pub active_uses: u32,             // count of PersistedUseState::Active
    pub environment: String,          // from AuthorityConstraints, 1..=64 validated chars
    pub expires_at: Option<u64>,      // only if derivable from TimeConstraints; else omit
}

impl DurableReplayStore {
    pub fn list_leases(&self) -> Result<Vec<LeaseSummary>, ReplayStoreError>;
}
```

Fields deliberately excluded: `canonical_args_sha256`, `policy_sha256`, `workspace_manifest_sha256`, `seen_nonce_digests`, idempotency fingerprints, terminal record digests, and the full constraints (network and spend details). They are digests, not secrets, but they are unneeded for a status view and shrink the review surface. `LeaseSummary` must not derive anything that serializes the private `PersistedLease`; build it field by field.

It must verify the HMAC before returning anything (reuse `read_authenticated_state`, `replay_store.rs:915`), so a forged snapshot returns `AuthenticationFailed` rather than attacker-chosen rows. Tests required: listing leaves the snapshot bytes and mtime unchanged; a tampered file is rejected; no field in the output type can carry a value (assert on the type's field list in a unit test); a listed store can still be activated afterwards.

## 6. Why phantom-cli needs a dependency or an IPC boundary

`phantom-cli` today depends on core, vault, proxy, mcp, and workspace only (`crates/phantom-cli/Cargo.toml:20` to `:24`). It does not depend on `phantom-broker`. The broker is reachable from the CLI binary only transitively: `phantom-mcp` depends on `phantom-runtime` (`phantom-mcp/Cargo.toml:27`), which depends on `phantom-broker` (`phantom-runtime/Cargo.toml:20`). That transitive link gives the CLI no API access.

Two ways to let a CLI command show lease state:

1. Direct dependency on `phantom-broker` plus the key source. The CLI process would open the store itself. Simple, but it puts the MAC key in the CLI process, which is the same process users run in agent-reachable shells, and it makes the CLI a second writer-capable opener of the store. `open_existing` plus `list_leases` would be read-only in effect, but the key would still be loaded. The store's instance lock (`start_epoch`, `replay_store.rs:265`) protects only an active broker, and a read-only opener does not take it.
2. An IPC boundary: the broker process owns the key and exposes a narrow, read-only status call over the existing protocol crate surface (`protocol.rs`, `transport.rs`). The CLI never holds the key. This better matches the project's boundary claims, but the production authority transport is explicitly unavailable today (`replay_store.rs:14` to `:15`), so this is blocked on work that does not exist.

Recommendation: do not add the dependency now. Ship phase 0 and 1 below first. Choose between the two options in phase 3 with the reviewer, and prefer IPC if the transport exists by then.

## 7. "A new broker run revokes every lease"

Verified behavior: `start_epoch` increments `broker_generation`, sets `revoked = true` on every existing lease, and converts every `Active` use to `Abandoned` with a restart terminal digest (`replay_store.rs:265` to `:327`; the revoke loop starts at line 299, and `lease.revoked = true` is line 301). `begin_use` checks both `revoked` and the generation (lines 433 and 514). It cannot be retried on the same object after a failure (`POISONED`, set before the write at line 291), and a second live broker on the same directory is refused through the instance lock.

Consequences for this design:

- Leases are strictly per-process-lifetime. Anything that survives a restart must be re-issued, which is the intended fail-closed behavior and means key loss costs little: a lost key and a restart look the same to a holder.
- The list method sees stale leases from earlier generations as `revoked = true`. A status view should show the generation and call these "revoked by restart", not "active".
- Rotation (section 4) can piggyback on restart.
- It is a correctness property, not a security boundary against rollback: replacing the snapshot with an older valid one would un-revoke leases until a monotonic anchor exists.

## 8. Phased plan

Each phase is its own PR. None enables lease issuance or revocation.

- Phase 0 (this document): review and decisions on section 3 (key source, Linux fallback policy) and section 6 (dependency vs IPC).
- Phase 1: `list_leases` and `LeaseSummary` in `phantom-broker` with the tests in section 5. Library only, no CLI wiring, no new callers.
- Phase 2: a key-provisioning module (in the broker crate or a small new crate, to be decided) that generates, stores, and loads the key per section 3, with fail-closed behavior and fault-injection tests. Still no CLI use.
- Phase 3: a read-only status surface in the CLI using the option chosen in section 6. Only after review of phases 1 and 2.
- Phase 4 (separate design, not covered here): a host-protected monotonic rollback anchor. Without it the store stays an inactive boundary regardless of how the key is provisioned.
- Later, and only with explicit approval: any command that issues or revokes leases.

## 9. Open questions for the reviewer

1. Is a 0600 file acceptable as a Linux fallback, or must bootstrap fail when no durable credential store exists?
2. Is `LeaseSummary` missing a field operators need, or does it include one that should be dropped?
3. Should the store descriptor record the key backend in the snapshot (format bump) or beside it?
4. Is `HMAC-SHA256` with a distinct domain string acceptable as the derivation primitive if Option B is ever revisited, or must it use HKDF?
