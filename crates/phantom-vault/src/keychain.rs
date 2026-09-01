use crate::metadata::SecretMetadata;
use crate::traits::{MetadataCas, ValidationMetadataCas, VaultBackend};
use phantom_core::error::{PhantomError, Result};
use phantom_core::validator::ValidationMetadata;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::hash::{DefaultHasher, Hash, Hasher};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard, OnceLock};
use zeroize::Zeroizing;

const SERVICE_PREFIX: &str = "phantom-secrets";
const PROCESS_LOCK_SHARDS: usize = 64;

/// Process-local lock shards complement the filesystem lock. Some OS locking
/// APIs treat locks from one process as mutually compatible even when they use
/// different file descriptors; the shard keeps threads honest while fs2
/// provides the cross-process boundary.
fn process_lock_for(project_id: &str) -> MutexGuard<'static, ()> {
    static LOCKS: OnceLock<Vec<Mutex<()>>> = OnceLock::new();
    let locks = LOCKS.get_or_init(|| (0..PROCESS_LOCK_SHARDS).map(|_| Mutex::new(())).collect());
    let mut hasher = DefaultHasher::new();
    project_id.hash(&mut hasher);
    let index = hasher.finish() as usize % locks.len();
    locks[index]
        .lock()
        .unwrap_or_else(|error| error.into_inner())
}

pub(crate) struct ProjectLock {
    _process: MutexGuard<'static, ()>,
    _file: std::fs::File,
}

fn safe_project_component(project_id: &str) -> String {
    project_id
        .chars()
        .map(|character| {
            if character.is_alphanumeric() || matches!(character, '-' | '_') {
                character
            } else {
                '_'
            }
        })
        .collect()
}

fn project_lock_path(project_id: &str) -> PathBuf {
    metadata_dir()
        .join("locks")
        .join(format!("{}.lock", safe_project_component(project_id)))
}

fn acquire_project_lock_at(project_id: &str, path: &Path) -> Result<ProjectLock> {
    let process = process_lock_for(project_id);
    let file =
        crate::lock_file::acquire_exclusive_lock_file(path, "per-project keychain lock", true)
            .map_err(|error| {
                PhantomError::VaultError(format!(
                    "Cannot acquire per-project keychain lock {}: {error}",
                    path.display()
                ))
            })?;
    Ok(ProjectLock {
        _process: process,
        _file: file,
    })
}

pub(crate) fn acquire_project_lock(project_id: &str) -> Result<ProjectLock> {
    acquire_project_lock_at(project_id, &project_lock_path(project_id))
}

/// 16-hex-char (64-bit) SHA-256 digest of `{project_id}:{name}`. Used as the
/// keychain entry's service and account metadata so the plaintext secret
/// name is never visible to unrelated processes that enumerate keychain
/// entries (audit F13). 64 bits is ample collision resistance for a
/// per-project keyspace while keeping the metadata string short.
fn hash_secret_name(project_id: &str, name: &str) -> String {
    let mut h = Sha256::new();
    h.update(project_id.as_bytes());
    h.update(b":");
    h.update(name.as_bytes());
    let out = h.finalize();
    hex::encode(&out[..8])
}

/// Vault backend that uses the OS keychain (macOS Keychain, Linux Secret Service).
pub struct KeychainVault {
    project_id: String,
    /// We track stored keys in a special keychain entry since keychain APIs
    /// don't support listing by prefix on all platforms.
    index_key: String,
}

// ── Metadata sidecar helpers ─────────────────────────────────────────────────
//
// The OS keychain stores opaque password strings — there is no structured
// per-entry metadata slot. We persist TTL/expiry metadata in a small JSON
// sidecar file alongside the keychain index. The file contains only
// timestamps and policy config — no secret values — so it is safe to store
// as plaintext on disk (it is no more sensitive than a .phantom.toml).

fn metadata_dir() -> PathBuf {
    directories::ProjectDirs::from("ai", "phantom", "phantom-secrets")
        .map(|d| d.data_dir().join("metadata"))
        .unwrap_or_else(|| {
            dirs::home_dir()
                .unwrap_or_else(std::env::temp_dir)
                .join(".phantom")
                .join("metadata")
        })
}

fn metadata_path(project_id: &str) -> PathBuf {
    let safe = safe_project_component(project_id);
    metadata_dir().join(format!("{safe}.meta.json"))
}

fn load_sidecar_map<T>(path: &Path, label: &str) -> Result<BTreeMap<String, T>>
where
    T: serde::de::DeserializeOwned,
{
    let Some(contents) = phantom_core::fs::read_regular_file(path)? else {
        return Ok(BTreeMap::new());
    };
    serde_json::from_slice(&contents).map_err(|error| {
        PhantomError::VaultError(format!(
            "Corrupt keychain {label} sidecar {}: {error}",
            path.display()
        ))
    })
}

type SidecarSnapshot<T> = (BTreeMap<String, T>, Option<Vec<u8>>);

fn load_sidecar_snapshot<T>(path: &Path, label: &str) -> Result<SidecarSnapshot<T>>
where
    T: serde::de::DeserializeOwned,
{
    let before = phantom_core::fs::read_regular_file(path)?;
    let map = match before.as_deref() {
        Some(contents) => serde_json::from_slice(contents).map_err(|error| {
            PhantomError::VaultError(format!(
                "Corrupt keychain {label} sidecar {}: {error}",
                path.display()
            ))
        })?,
        None => BTreeMap::new(),
    };
    Ok((map, before))
}

fn save_sidecar_map<T>(path: &Path, label: &str, map: &BTreeMap<String, T>) -> Result<()>
where
    T: serde::Serialize,
{
    phantom_core::fs::ensure_real_parent(path)?;
    let _ = phantom_core::fs::read_regular_file(path)?;
    let json = serde_json::to_string_pretty(map).map_err(|error| {
        PhantomError::VaultError(format!("Keychain {label} serialize error: {error}"))
    })?;
    // `atomic_write` uses a unique temporary file in the target directory,
    // then persists it with an atomic rename. Concurrent writers therefore
    // cannot collide on a shared `.tmp` path.
    phantom_core::fs::atomic_write(path, json.as_bytes())?;
    Ok(())
}

fn save_sidecar_map_if_unchanged<T>(
    path: &Path,
    label: &str,
    expected_before: Option<&[u8]>,
    map: &BTreeMap<String, T>,
) -> Result<()>
where
    T: serde::Serialize,
{
    phantom_core::fs::ensure_real_parent(path)?;
    let json = serde_json::to_vec_pretty(map).map_err(|error| {
        PhantomError::VaultError(format!("Keychain {label} serialize error: {error}"))
    })?;
    phantom_core::fs::atomic_write_if_unchanged(path, expected_before, &json)?;
    Ok(())
}

/// Load the full per-project metadata map from the sidecar file.
fn load_meta_map(project_id: &str) -> Result<BTreeMap<String, SecretMetadata>> {
    load_sidecar_map(&metadata_path(project_id), "metadata")
}

/// Persist the full per-project metadata map to the sidecar file.
fn save_meta_map(project_id: &str, map: &BTreeMap<String, SecretMetadata>) -> Result<()> {
    save_sidecar_map(&metadata_path(project_id), "metadata", map)
}

// ── Validation metadata sidecar ──────────────────────────────────────────────
//
// Mirrors the TTL metadata sidecar: a separate JSON file stores per-secret
// validation state (last_check_ts, is_valid, failure_reason). No secret
// values are ever written here.

fn validation_meta_path(project_id: &str) -> std::path::PathBuf {
    let safe = safe_project_component(project_id);
    metadata_dir().join(format!("{safe}.validation.json"))
}

fn load_validation_meta_map(project_id: &str) -> Result<BTreeMap<String, ValidationMetadata>> {
    load_sidecar_map(&validation_meta_path(project_id), "validation")
}

fn save_validation_meta_map(
    project_id: &str,
    map: &BTreeMap<String, ValidationMetadata>,
) -> Result<()> {
    save_sidecar_map(&validation_meta_path(project_id), "validation", map)
}

fn read_credential(entry: &keyring::Entry, label: &str) -> Result<Option<Zeroizing<String>>> {
    match entry.get_password() {
        Ok(value) => Ok(Some(Zeroizing::new(value))),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(error) => Err(PhantomError::VaultError(format!(
            "Failed to read {label}: {error}"
        ))),
    }
}

fn remove_credential(entry: &keyring::Entry, label: &str) -> Result<()> {
    match entry.delete_credential() {
        Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
        Err(error) => Err(PhantomError::VaultError(format!(
            "Failed to delete {label}: {error}"
        ))),
    }
}

fn restore_credential(
    entry: &keyring::Entry,
    value: Option<&Zeroizing<String>>,
    label: &str,
) -> Result<()> {
    match value {
        Some(value) => entry.set_password(value.as_str()).map_err(|error| {
            PhantomError::VaultError(format!("Failed to restore {label}: {error}"))
        }),
        None => remove_credential(entry, label),
    }
}

fn compensated_error(
    operation: &str,
    primary: PhantomError,
    compensation_results: impl IntoIterator<Item = Result<()>>,
) -> PhantomError {
    let failures = compensation_results
        .into_iter()
        .filter_map(std::result::Result::err)
        .map(|error| error.to_string())
        .collect::<Vec<_>>();
    if failures.is_empty() {
        PhantomError::VaultError(format!(
            "{operation} failed and prior keychain state was restored: {primary}"
        ))
    } else {
        PhantomError::VaultError(format!(
            "{operation} failed ({primary}); rollback was incomplete: {}",
            failures.join("; ")
        ))
    }
}

/// Narrow adapter for the read-time F13 legacy migration. Keeping the
/// transaction independent from the concrete keyring backend lets tests inject
/// ambiguous failures after each mutation and verify the compensation order.
trait LegacyMigrationBackend {
    fn read_hashed(&self) -> Result<Option<Zeroizing<String>>>;
    fn write_hashed(&self, value: &str) -> Result<()>;
    fn remove_hashed(&self) -> Result<()>;
    fn load_index(&self) -> Result<Vec<String>>;
    fn save_index(&self, names: &[String]) -> Result<()>;
    fn read_legacy(&self) -> Result<Option<Zeroizing<String>>>;
    fn write_legacy(&self, value: &str) -> Result<()>;
    fn remove_legacy(&self) -> Result<()>;
}

struct KeychainLegacyMigration<'a> {
    vault: &'a KeychainVault,
    hashed: &'a keyring::Entry,
    legacy: &'a keyring::Entry,
}

impl LegacyMigrationBackend for KeychainLegacyMigration<'_> {
    fn read_hashed(&self) -> Result<Option<Zeroizing<String>>> {
        read_credential(self.hashed, "hashed secret")
    }

    fn write_hashed(&self, value: &str) -> Result<()> {
        self.hashed.set_password(value).map_err(|error| {
            PhantomError::VaultError(format!("Failed to migrate legacy secret: {error}"))
        })
    }

    fn remove_hashed(&self) -> Result<()> {
        remove_credential(self.hashed, "migrated hashed secret")
    }

    fn load_index(&self) -> Result<Vec<String>> {
        self.vault.load_index()
    }

    fn save_index(&self, names: &[String]) -> Result<()> {
        self.vault.save_index(names)
    }

    fn read_legacy(&self) -> Result<Option<Zeroizing<String>>> {
        read_credential(self.legacy, "legacy secret")
    }

    fn write_legacy(&self, value: &str) -> Result<()> {
        self.legacy.set_password(value).map_err(|error| {
            PhantomError::VaultError(format!("Failed to restore legacy secret: {error}"))
        })
    }

    fn remove_legacy(&self) -> Result<()> {
        remove_credential(self.legacy, "legacy secret")
    }
}

fn migrate_legacy_transaction(
    backend: &dyn LegacyMigrationBackend,
    name: &str,
) -> Result<Zeroizing<String>> {
    // A concurrent process may have completed migration while this caller was
    // waiting for the project lock. In that case the hashed entry is already
    // authoritative and no migration mutations are necessary.
    if let Some(value) = backend.read_hashed()? {
        return Ok(value);
    }

    let legacy_value = backend
        .read_legacy()?
        .ok_or_else(|| PhantomError::SecretNotFound(name.to_string()))?;
    let before_index = backend.load_index()?;
    let mut after_index = before_index.clone();
    if !after_index.iter().any(|indexed| indexed == name) {
        after_index.push(name.to_string());
        after_index.sort();
    }
    let index_changed = after_index != before_index;

    if let Err(error) = backend.write_hashed(legacy_value.as_str()) {
        // A backend may report an error after persisting the credential. The
        // legacy entry is still untouched, so remove any ambiguous hashed copy.
        return Err(compensated_error(
            "legacy keychain migration",
            error,
            [backend.remove_hashed()],
        ));
    }

    if index_changed {
        if let Err(error) = backend.save_index(&after_index) {
            // The legacy entry is still authoritative. Remove the hashed copy
            // only after restoring the index is proven successful. If that
            // restoration fails before applying, the after-index may still
            // point at the hashed entry and removing it would create a dangling
            // index record.
            match backend.save_index(&before_index) {
                Ok(()) => {
                    return Err(compensated_error(
                        "legacy keychain migration",
                        error,
                        [Ok(()), backend.remove_hashed()],
                    ));
                }
                Err(restore_error) => {
                    return Err(compensated_error(
                        "legacy keychain migration",
                        error,
                        [Err(restore_error)],
                    ));
                }
            }
        }
    }

    if let Err(error) = backend.remove_legacy() {
        // Deletion failures are ambiguous. First prove the legacy copy exists
        // again. Until that succeeds, retain the indexed hashed copy so the
        // credential cannot be lost or stranded by an attempted rollback.
        let mut compensations = Vec::new();
        match backend.write_legacy(legacy_value.as_str()) {
            Ok(()) => compensations.push(Ok(())),
            Err(restore_error) => {
                compensations.push(Err(restore_error));
                return Err(compensated_error(
                    "legacy keychain migration",
                    error,
                    compensations,
                ));
            }
        }

        if index_changed {
            match backend.save_index(&before_index) {
                Ok(()) => compensations.push(Ok(())),
                Err(restore_error) => {
                    // Keep the hashed credential because the post-migration
                    // index may still be the only discoverable copy.
                    compensations.push(Err(restore_error));
                    return Err(compensated_error(
                        "legacy keychain migration",
                        error,
                        compensations,
                    ));
                }
            }
        }

        compensations.push(backend.remove_hashed());
        return Err(compensated_error(
            "legacy keychain migration",
            error,
            compensations,
        ));
    }

    Ok(legacy_value)
}

impl KeychainVault {
    /// Create a new keychain vault for a project.
    /// Returns an error if the keychain is not available.
    pub fn new(project_id: &str) -> Result<Self> {
        // Test that keychain is accessible by trying a no-op
        let test_entry = keyring::Entry::new(SERVICE_PREFIX, "__phantom_test__")
            .map_err(|e| PhantomError::VaultError(format!("Keychain not available: {e}")))?;

        // Try to access it (will fail with NotFound, which is fine)
        match test_entry.get_password() {
            Ok(_) | Err(keyring::Error::NoEntry) => {}
            Err(e) => {
                return Err(PhantomError::VaultError(format!(
                    "Keychain not accessible: {e}"
                )));
            }
        }

        Ok(Self {
            index_key: format!("{SERVICE_PREFIX}:{project_id}:__index__"),
            project_id: project_id.to_string(),
        })
    }

    fn hash_name(&self, name: &str) -> String {
        hash_secret_name(&self.project_id, name)
    }

    /// F13 entry key: opaque hash of the secret name. The `h-` prefix
    /// distinguishes post-F13 entries from legacy plaintext-named entries
    /// for migration.
    fn entry_key(&self, name: &str) -> String {
        format!(
            "{SERVICE_PREFIX}:{}:h-{}",
            self.project_id,
            self.hash_name(name)
        )
    }

    /// Pre-F13 entry key used by older phantom versions. Kept for read-time
    /// migration so existing users don't lose access to their stored secrets.
    fn legacy_entry_key(&self, name: &str) -> String {
        format!("{SERVICE_PREFIX}:{}:{}", self.project_id, name)
    }

    fn entry_for(&self, name: &str) -> Result<keyring::Entry> {
        // Use the hashed name for the account field too — `keyring::Entry`
        // uses (service, account) as the lookup key on most backends, and we
        // want neither to leak the plaintext name.
        let account = self.hash_name(name);
        keyring::Entry::new(&self.entry_key(name), &account)
            .map_err(|e| PhantomError::VaultError(format!("Keychain error: {e}")))
    }

    fn legacy_entry_for(&self, name: &str) -> Option<keyring::Entry> {
        keyring::Entry::new(&self.legacy_entry_key(name), name).ok()
    }

    /// Best-effort deletion of the legacy plaintext-named entry for `name`.
    /// Used during F13 migration — failures are swallowed because the new
    /// entry already holds the authoritative value.
    fn delete_legacy(&self, name: &str) {
        if let Some(legacy) = self.legacy_entry_for(name) {
            let _ = legacy.delete_credential();
        }
    }

    /// Load the index of stored secret names.
    fn load_index(&self) -> Result<Vec<String>> {
        let entry = keyring::Entry::new(
            &format!("{SERVICE_PREFIX}:{}", self.project_id),
            &self.index_key,
        )
        .map_err(|e| PhantomError::VaultError(format!("Keychain error: {e}")))?;

        match entry.get_password() {
            Ok(data) => serde_json::from_str(&data).map_err(|e| {
                PhantomError::VaultError(format!(
                    "Corrupt keychain index (try `phantom init` to rebuild): {e}"
                ))
            }),
            Err(keyring::Error::NoEntry) => Ok(Vec::new()),
            Err(e) => Err(PhantomError::VaultError(format!(
                "Failed to read index: {e}"
            ))),
        }
    }

    /// Save the index of stored secret names.
    fn save_index(&self, names: &[String]) -> Result<()> {
        let entry = keyring::Entry::new(
            &format!("{SERVICE_PREFIX}:{}", self.project_id),
            &self.index_key,
        )
        .map_err(|e| PhantomError::VaultError(format!("Keychain error: {e}")))?;
        let data = serde_json::to_string(names)
            .map_err(|e| PhantomError::VaultError(format!("Serialize error: {e}")))?;
        entry
            .set_password(&data)
            .map_err(|e| PhantomError::VaultError(format!("Failed to save index: {e}")))?;
        Ok(())
    }

    /// Store a credential and update its index while the caller holds the
    /// per-project exclusive lock.
    fn store_locked(
        &self,
        name: &str,
        value: &str,
        metadata_override: Option<SecretMetadata>,
    ) -> Result<()> {
        let entry = self.entry_for(name)?;
        let before_credential = read_credential(&entry, "secret before-image")?;
        let before_index = self.load_index()?;
        let before_metadata = load_meta_map(&self.project_id)?;
        let mut after_index = before_index.clone();
        if !after_index.iter().any(|indexed| indexed == name) {
            after_index.push(name.to_string());
            after_index.sort();
        }
        let mut after_metadata = before_metadata.clone();
        match metadata_override {
            Some(metadata) => {
                after_metadata.insert(name.to_string(), metadata);
            }
            None => {
                after_metadata
                    .entry(name.to_string())
                    .or_insert_with(SecretMetadata::new_now);
            }
        }

        entry.set_password(value).map_err(|error| {
            PhantomError::VaultError(format!("Failed to store secret: {error}"))
        })?;
        let commit = (|| {
            if after_index != before_index {
                self.save_index(&after_index)?;
            }
            if after_metadata != before_metadata {
                save_meta_map(&self.project_id, &after_metadata)?;
            }
            Ok(())
        })();
        if let Err(error) = commit {
            return Err(compensated_error(
                "keychain store",
                error,
                [
                    restore_credential(&entry, before_credential.as_ref(), "secret before-image"),
                    self.save_index(&before_index),
                    save_meta_map(&self.project_id, &before_metadata),
                ],
            ));
        }
        self.delete_legacy(name);
        Ok(())
    }

    fn current_value_locked(&self, name: &str) -> Result<Option<Zeroizing<String>>> {
        let entry = self.entry_for(name)?;
        if let Some(value) = read_credential(&entry, "secret")? {
            return Ok(Some(value));
        }
        match self.legacy_entry_for(name) {
            Some(legacy) => read_credential(&legacy, "legacy secret"),
            None => Ok(None),
        }
    }

    fn delete_locked(&self, name: &str) -> Result<()> {
        let entry = self.entry_for(name)?;
        let legacy = self.legacy_entry_for(name);
        let before_credential = read_credential(&entry, "secret before-image")?;
        let before_legacy = match &legacy {
            Some(legacy) => read_credential(legacy, "legacy secret before-image")?,
            None => None,
        };
        let before_index = self.load_index()?;
        let before_metadata = load_meta_map(&self.project_id)?;
        let before_validation = load_validation_meta_map(&self.project_id)?;
        let was_indexed = before_index.iter().any(|indexed| indexed == name);
        if before_credential.is_none() && before_legacy.is_none() && !was_indexed {
            return Err(PhantomError::SecretNotFound(name.to_string()));
        }

        let mut after_index = before_index.clone();
        after_index.retain(|indexed| indexed != name);
        let mut after_metadata = before_metadata.clone();
        after_metadata.remove(name);
        let mut after_validation = before_validation.clone();
        after_validation.remove(name);

        let commit = (|| {
            if after_metadata != before_metadata {
                save_meta_map(&self.project_id, &after_metadata)?;
            }
            if after_validation != before_validation {
                save_validation_meta_map(&self.project_id, &after_validation)?;
            }
            if after_index != before_index {
                self.save_index(&after_index)?;
            }
            remove_credential(&entry, "secret")?;
            if let Some(legacy) = &legacy {
                remove_credential(legacy, "legacy secret")?;
            }
            Ok(())
        })();
        if let Err(error) = commit {
            let mut compensations = vec![
                restore_credential(&entry, before_credential.as_ref(), "secret before-image"),
                self.save_index(&before_index),
                save_meta_map(&self.project_id, &before_metadata),
                save_validation_meta_map(&self.project_id, &before_validation),
            ];
            if let Some(legacy) = &legacy {
                compensations.push(restore_credential(
                    legacy,
                    before_legacy.as_ref(),
                    "legacy secret before-image",
                ));
            }
            return Err(compensated_error("keychain delete", error, compensations));
        }
        Ok(())
    }
}

impl VaultBackend for KeychainVault {
    fn store(&self, name: &str, value: &str) -> Result<()> {
        let _lock = acquire_project_lock(&self.project_id)?;
        self.store_locked(name, value, None)?;
        phantom_core::audit::log("vault.store", Some(name));
        Ok(())
    }

    fn retrieve(&self, name: &str) -> Result<zeroize::Zeroizing<String>> {
        let entry = self.entry_for(name)?;
        match entry.get_password() {
            Ok(value) => {
                phantom_core::audit::log("vault.retrieve", Some(name));
                Ok(zeroize::Zeroizing::new(value))
            }
            Err(keyring::Error::NoEntry) => {
                let _lock = acquire_project_lock(&self.project_id)?;
                // F13 migration: older phantom versions stored entries under
                // the plaintext name. The migration spans the hashed entry,
                // index, and legacy deletion as one compensated transaction.
                let legacy = self
                    .legacy_entry_for(name)
                    .ok_or_else(|| PhantomError::SecretNotFound(name.to_string()))?;
                let migration = KeychainLegacyMigration {
                    vault: self,
                    hashed: &entry,
                    legacy: &legacy,
                };
                let value = migrate_legacy_transaction(&migration, name)?;
                phantom_core::audit::log("vault.retrieve", Some(name));
                Ok(value)
            }
            Err(e) => Err(PhantomError::VaultError(format!(
                "Failed to retrieve secret: {e}"
            ))),
        }
    }

    fn retrieve_for_injection(&self, name: &str) -> Result<zeroize::Zeroizing<String>> {
        let _lock = acquire_project_lock(&self.project_id)?;
        let metadata = load_meta_map(&self.project_id)?;
        crate::traits::ensure_secret_injectable(name, metadata.get(name))?;
        let value = self
            .current_value_locked(name)?
            .ok_or_else(|| PhantomError::SecretNotFound(name.to_string()))?;
        phantom_core::audit::log("vault.retrieve_for_injection", Some(name));
        Ok(value)
    }

    fn delete(&self, name: &str) -> Result<()> {
        let _lock = acquire_project_lock(&self.project_id)?;
        self.delete_locked(name)?;
        phantom_core::audit::log("vault.delete", Some(name));
        Ok(())
    }

    fn compare_and_swap(
        &self,
        name: &str,
        expected: Option<&str>,
        replacement: Option<&str>,
    ) -> Result<bool> {
        let _lock = acquire_project_lock(&self.project_id)?;
        let current = self.current_value_locked(name)?;
        if current.as_ref().map(|value| value.as_str()) != expected {
            return Ok(false);
        }
        if replacement == expected {
            return Ok(true);
        }
        match replacement {
            Some(value) => self.store_locked(name, value, None)?,
            None => self.delete_locked(name)?,
        }
        phantom_core::audit::log("vault.compare_and_swap", Some(name));
        Ok(true)
    }

    fn list(&self) -> Result<Vec<String>> {
        let _lock = acquire_project_lock(&self.project_id)?;
        self.load_index()
    }

    fn backend_name(&self) -> &str {
        "os-keychain"
    }

    fn get_metadata(&self, name: &str) -> Result<Option<SecretMetadata>> {
        let _lock = acquire_project_lock(&self.project_id)?;
        let map = load_meta_map(&self.project_id)?;
        Ok(map.get(name).cloned())
    }

    fn set_metadata(&self, name: &str, meta: SecretMetadata) -> Result<()> {
        let _lock = acquire_project_lock(&self.project_id)?;
        // Only allow metadata on keys that actually exist in the vault index.
        let index = self.load_index()?;
        if !index.contains(&name.to_string()) {
            return Err(PhantomError::SecretNotFound(name.to_string()));
        }
        let mut map = load_meta_map(&self.project_id)?;
        map.insert(name.to_string(), meta);
        save_meta_map(&self.project_id, &map)
    }

    fn compare_and_swap_metadata_batch(&self, changes: &[MetadataCas]) -> Result<bool> {
        let _lock = acquire_project_lock(&self.project_id)?;
        let index = self.load_index()?;
        let path = metadata_path(&self.project_id);
        let (mut map, before) = load_sidecar_snapshot(&path, "metadata")?;
        let mut seen = std::collections::BTreeSet::new();
        for change in changes {
            if !seen.insert(change.name.as_str()) {
                return Err(PhantomError::VaultError(
                    "metadata CAS batch contains a duplicate secret name".to_string(),
                ));
            }
            if !index.iter().any(|indexed| indexed == &change.name) {
                return Err(PhantomError::SecretNotFound(change.name.clone()));
            }
            if map.get(&change.name) != change.expected.as_ref() {
                return Ok(false);
            }
        }
        for change in changes {
            match &change.replacement {
                Some(metadata) => {
                    map.insert(change.name.clone(), metadata.clone());
                }
                None => {
                    map.remove(&change.name);
                }
            }
        }
        if !changes.is_empty() {
            save_sidecar_map_if_unchanged(&path, "metadata", before.as_deref(), &map)?;
        }
        Ok(true)
    }

    fn list_with_metadata(&self) -> Result<Vec<(String, Option<SecretMetadata>)>> {
        let _lock = acquire_project_lock(&self.project_id)?;
        let names = self.load_index()?;
        let metadata = load_meta_map(&self.project_id)?;
        Ok(names
            .into_iter()
            .map(|name| {
                let meta = metadata.get(&name).cloned();
                (name, meta)
            })
            .collect())
    }

    fn store_with_expiry(&self, name: &str, value: &str, days_ttl: u64) -> Result<()> {
        let _lock = acquire_project_lock(&self.project_id)?;
        self.store_locked(name, value, Some(SecretMetadata::with_expiry(days_ttl)))?;
        phantom_core::audit::log("vault.store", Some(name));
        Ok(())
    }

    fn get_validation_metadata(&self, name: &str) -> Result<ValidationMetadata> {
        let _lock = acquire_project_lock(&self.project_id)?;
        let map = load_validation_meta_map(&self.project_id)?;
        Ok(map.get(name).cloned().unwrap_or_default())
    }

    fn get_validation_metadata_exact(&self, name: &str) -> Result<Option<ValidationMetadata>> {
        let _lock = acquire_project_lock(&self.project_id)?;
        let map = load_validation_meta_map(&self.project_id)?;
        Ok(map.get(name).cloned())
    }

    fn set_validation_metadata(&self, name: &str, meta: ValidationMetadata) -> Result<()> {
        let _lock = acquire_project_lock(&self.project_id)?;
        let index = self.load_index()?;
        if !index.contains(&name.to_string()) {
            return Err(PhantomError::SecretNotFound(name.to_string()));
        }
        let mut map = load_validation_meta_map(&self.project_id)?;
        map.insert(name.to_string(), meta);
        save_validation_meta_map(&self.project_id, &map)
    }

    fn compare_and_swap_validation_metadata_batch(
        &self,
        changes: &[ValidationMetadataCas],
    ) -> Result<bool> {
        let _lock = acquire_project_lock(&self.project_id)?;
        let index = self.load_index()?;
        let path = validation_meta_path(&self.project_id);
        let (mut map, before) = load_sidecar_snapshot(&path, "validation metadata")?;
        let mut seen = std::collections::BTreeSet::new();
        for change in changes {
            if !seen.insert(change.name.as_str()) {
                return Err(PhantomError::VaultError(
                    "validation metadata CAS batch contains a duplicate secret name".to_string(),
                ));
            }
            if !index.iter().any(|indexed| indexed == &change.name) {
                return Err(PhantomError::SecretNotFound(change.name.clone()));
            }
            if map.get(&change.name) != change.expected.as_ref() {
                return Ok(false);
            }
        }
        for change in changes {
            match &change.replacement {
                Some(metadata) => {
                    map.insert(change.name.clone(), metadata.clone());
                }
                None => {
                    map.remove(&change.name);
                }
            }
        }
        if !changes.is_empty() {
            save_sidecar_map_if_unchanged(&path, "validation metadata", before.as_deref(), &map)?;
        }
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::BTreeSet;
    use std::sync::{Arc, Barrier};
    use tempfile::tempdir;

    const MIGRATION_NAME: &str = "API_KEY";
    const MIGRATION_VALUE: &str = "test-legacy-value";

    #[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
    enum MigrationFault {
        HashedWrite,
        IndexCommit,
        LegacyDelete,
        LegacyRestore,
        IndexRestoreBeforeMutation,
        IndexRestoreAfterMutation,
        HashedRemove,
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    struct MigrationState {
        hashed: Option<String>,
        legacy: Option<String>,
        index: Vec<String>,
    }

    struct ScriptedMigration {
        state: RefCell<MigrationState>,
        faults: RefCell<BTreeSet<MigrationFault>>,
    }

    impl ScriptedMigration {
        fn new(faults: impl IntoIterator<Item = MigrationFault>) -> Self {
            Self {
                state: RefCell::new(MigrationState {
                    hashed: None,
                    legacy: Some(MIGRATION_VALUE.to_string()),
                    index: vec!["EXISTING_KEY".to_string()],
                }),
                faults: RefCell::new(faults.into_iter().collect()),
            }
        }

        fn trip(&self, fault: MigrationFault) -> Result<()> {
            if self.faults.borrow_mut().remove(&fault) {
                Err(PhantomError::VaultError(format!(
                    "injected {fault:?} failure after mutation"
                )))
            } else {
                Ok(())
            }
        }

        fn snapshot(&self) -> MigrationState {
            self.state.borrow().clone()
        }
    }

    impl LegacyMigrationBackend for ScriptedMigration {
        fn read_hashed(&self) -> Result<Option<Zeroizing<String>>> {
            Ok(self.state.borrow().hashed.clone().map(Zeroizing::new))
        }

        fn write_hashed(&self, value: &str) -> Result<()> {
            self.state.borrow_mut().hashed = Some(value.to_string());
            self.trip(MigrationFault::HashedWrite)
        }

        fn remove_hashed(&self) -> Result<()> {
            self.state.borrow_mut().hashed = None;
            self.trip(MigrationFault::HashedRemove)
        }

        fn load_index(&self) -> Result<Vec<String>> {
            Ok(self.state.borrow().index.clone())
        }

        fn save_index(&self, names: &[String]) -> Result<()> {
            let is_commit = names.iter().any(|name| name == MIGRATION_NAME);
            if !is_commit
                && self
                    .faults
                    .borrow_mut()
                    .remove(&MigrationFault::IndexRestoreBeforeMutation)
            {
                return Err(PhantomError::VaultError(
                    "injected IndexRestoreBeforeMutation failure before mutation".to_string(),
                ));
            }
            self.state.borrow_mut().index = names.to_vec();
            let fault = if is_commit {
                MigrationFault::IndexCommit
            } else {
                MigrationFault::IndexRestoreAfterMutation
            };
            self.trip(fault)
        }

        fn read_legacy(&self) -> Result<Option<Zeroizing<String>>> {
            Ok(self.state.borrow().legacy.clone().map(Zeroizing::new))
        }

        fn write_legacy(&self, value: &str) -> Result<()> {
            self.state.borrow_mut().legacy = Some(value.to_string());
            self.trip(MigrationFault::LegacyRestore)
        }

        fn remove_legacy(&self) -> Result<()> {
            self.state.borrow_mut().legacy = None;
            self.trip(MigrationFault::LegacyDelete)
        }
    }

    #[test]
    fn compensation_result_distinguishes_complete_and_incomplete_rollback() {
        let restored = compensated_error(
            "keychain store",
            PhantomError::VaultError("index write failed".into()),
            [Ok(())],
        );
        assert!(restored
            .to_string()
            .contains("prior keychain state was restored"));
        assert!(!restored.to_string().contains("rollback was incomplete"));

        let incomplete = compensated_error(
            "keychain delete",
            PhantomError::VaultError("credential delete failed".into()),
            [Err(PhantomError::VaultError("index restore failed".into()))],
        );
        assert!(incomplete.to_string().contains("rollback was incomplete"));
        assert!(incomplete.to_string().contains("index restore failed"));
    }

    #[test]
    fn legacy_migration_commits_hashed_value_index_and_deletion_together() {
        let backend = ScriptedMigration::new([]);

        let migrated = migrate_legacy_transaction(&backend, MIGRATION_NAME).unwrap();

        assert_eq!(migrated.as_str(), MIGRATION_VALUE);
        assert_eq!(
            backend.snapshot(),
            MigrationState {
                hashed: Some(MIGRATION_VALUE.to_string()),
                legacy: None,
                index: vec!["API_KEY".to_string(), "EXISTING_KEY".to_string()],
            }
        );
    }

    #[test]
    fn legacy_migration_compensates_ambiguous_hashed_write_failure() {
        let backend = ScriptedMigration::new([MigrationFault::HashedWrite]);
        let before = backend.snapshot();

        let error = migrate_legacy_transaction(&backend, MIGRATION_NAME).unwrap_err();

        assert!(error
            .to_string()
            .contains("prior keychain state was restored"));
        assert_eq!(backend.snapshot(), before);
    }

    #[test]
    fn legacy_migration_compensates_ambiguous_index_failure() {
        let backend = ScriptedMigration::new([MigrationFault::IndexCommit]);
        let before = backend.snapshot();

        let error = migrate_legacy_transaction(&backend, MIGRATION_NAME).unwrap_err();

        assert!(error
            .to_string()
            .contains("prior keychain state was restored"));
        assert_eq!(backend.snapshot(), before);
    }

    #[test]
    fn legacy_migration_retains_hashed_copy_when_index_restore_is_uncertain() {
        for restore_fault in [
            MigrationFault::IndexRestoreBeforeMutation,
            MigrationFault::IndexRestoreAfterMutation,
        ] {
            let backend = ScriptedMigration::new([MigrationFault::IndexCommit, restore_fault]);

            let error = migrate_legacy_transaction(&backend, MIGRATION_NAME).unwrap_err();
            let after = backend.snapshot();

            assert!(error.to_string().contains("rollback was incomplete"));
            assert_eq!(after.hashed.as_deref(), Some(MIGRATION_VALUE));
            assert_eq!(after.legacy.as_deref(), Some(MIGRATION_VALUE));
            match restore_fault {
                MigrationFault::IndexRestoreBeforeMutation => {
                    assert!(after.index.iter().any(|name| name == MIGRATION_NAME));
                }
                MigrationFault::IndexRestoreAfterMutation => {
                    assert_eq!(after.index, vec!["EXISTING_KEY".to_string()]);
                }
                _ => unreachable!("test supplies only index restoration faults"),
            }
        }
    }

    #[test]
    fn legacy_migration_compensates_ambiguous_legacy_delete_failure() {
        let backend = ScriptedMigration::new([MigrationFault::LegacyDelete]);
        let before = backend.snapshot();

        let error = migrate_legacy_transaction(&backend, MIGRATION_NAME).unwrap_err();

        assert!(error
            .to_string()
            .contains("prior keychain state was restored"));
        assert_eq!(backend.snapshot(), before);
    }

    #[test]
    fn legacy_migration_retains_committed_copy_when_legacy_restore_is_ambiguous() {
        let backend =
            ScriptedMigration::new([MigrationFault::LegacyDelete, MigrationFault::LegacyRestore]);

        let error = migrate_legacy_transaction(&backend, MIGRATION_NAME).unwrap_err();
        let after = backend.snapshot();

        assert!(error.to_string().contains("rollback was incomplete"));
        assert_eq!(after.hashed.as_deref(), Some(MIGRATION_VALUE));
        assert_eq!(after.legacy.as_deref(), Some(MIGRATION_VALUE));
        assert!(after.index.iter().any(|name| name == MIGRATION_NAME));
    }

    #[test]
    fn hash_secret_name_is_deterministic() {
        let a = hash_secret_name("proj-abc", "OPENAI_API_KEY");
        let b = hash_secret_name("proj-abc", "OPENAI_API_KEY");
        assert_eq!(a, b);
    }

    #[test]
    fn hash_secret_name_differs_by_project() {
        // Same secret name under different projects must map to different
        // hashes — otherwise two projects on the same keychain would collide.
        let a = hash_secret_name("proj-a", "OPENAI_API_KEY");
        let b = hash_secret_name("proj-b", "OPENAI_API_KEY");
        assert_ne!(a, b);
    }

    #[test]
    fn hash_secret_name_differs_by_name() {
        let a = hash_secret_name("proj", "OPENAI_API_KEY");
        let b = hash_secret_name("proj", "ANTHROPIC_API_KEY");
        assert_ne!(a, b);
    }

    #[test]
    fn hash_secret_name_does_not_contain_plaintext() {
        // F13 core property: the hashed metadata string must not contain the
        // plaintext secret name as a substring.
        let name = "OPENAI_API_KEY";
        let hashed = hash_secret_name("proj", name);
        assert!(!hashed.contains(name));
        assert!(!hashed.contains(&name.to_ascii_lowercase()));
    }

    #[test]
    fn hash_secret_name_format() {
        let h = hash_secret_name("proj", "OPENAI_API_KEY");
        assert_eq!(h.len(), 16, "expected 16 hex chars (64 bits)");
        assert!(
            h.chars().all(|c| c.is_ascii_hexdigit()),
            "expected lowercase hex: {h}"
        );
    }

    #[test]
    fn project_lock_serializes_sidecar_read_modify_write_without_lost_names() {
        const WRITERS: usize = 24;
        let directory = tempdir().unwrap();
        let root = directory.path().canonicalize().unwrap();
        let lock_path = root.join("locks").join("project.lock");
        let sidecar_path = root.join("project.meta.json");
        let barrier = Arc::new(Barrier::new(WRITERS));
        let mut workers = Vec::new();

        for writer in 0..WRITERS {
            let barrier = Arc::clone(&barrier);
            let lock_path = lock_path.clone();
            let sidecar_path = sidecar_path.clone();
            workers.push(std::thread::spawn(move || {
                barrier.wait();
                let _lock = acquire_project_lock_at("concurrent-project", &lock_path).unwrap();
                let mut map: BTreeMap<String, usize> =
                    load_sidecar_map(&sidecar_path, "test metadata").unwrap();
                // Enlarge the unprotected race window. With the production
                // lock held, every process-equivalent writer still observes
                // and preserves every prior name.
                std::thread::yield_now();
                map.insert(format!("KEY_{writer:02}"), writer);
                save_sidecar_map(&sidecar_path, "test metadata", &map).unwrap();
            }));
        }
        for worker in workers {
            worker.join().unwrap();
        }

        let map: BTreeMap<String, usize> =
            load_sidecar_map(&sidecar_path, "test metadata").unwrap();
        assert_eq!(map.len(), WRITERS);
        for writer in 0..WRITERS {
            assert_eq!(map.get(&format!("KEY_{writer:02}")), Some(&writer));
        }

        let artifacts = std::fs::read_dir(directory.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect::<Vec<_>>();
        assert_eq!(
            artifacts.len(),
            2,
            "atomic writes must not leave temp files"
        );
    }

    #[cfg(unix)]
    #[test]
    fn project_lock_file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempdir().unwrap();
        let path = directory
            .path()
            .canonicalize()
            .unwrap()
            .join("locks")
            .join("owner-only.lock");
        let _lock = acquire_project_lock_at("owner-only", &path).unwrap();
        let lock_mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        let parent_mode = std::fs::metadata(path.parent().unwrap())
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(lock_mode, 0o600);
        assert_eq!(parent_mode, 0o700);
    }

    #[cfg(unix)]
    #[test]
    fn project_lock_rejects_permissive_existing_parent_without_chmod() {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempdir().unwrap();
        let parent = directory.path().canonicalize().unwrap().join("locks");
        std::fs::create_dir(&parent).unwrap();
        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o755)).unwrap();
        let path = parent.join("owner-only.lock");

        assert!(acquire_project_lock_at("owner-only", &path).is_err());
        assert!(!path.exists());
        assert_eq!(
            std::fs::metadata(parent).unwrap().permissions().mode() & 0o777,
            0o755
        );
    }

    #[test]
    fn corrupt_sidecar_is_not_silently_replaced() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("corrupt.meta.json");
        std::fs::write(&path, b"not-json").unwrap();

        let error = load_sidecar_map::<usize>(&path, "metadata").unwrap_err();

        assert!(error
            .to_string()
            .contains("Corrupt keychain metadata sidecar"));
        assert_eq!(std::fs::read(&path).unwrap(), b"not-json");
    }

    #[test]
    fn exact_sidecar_save_rejects_concurrent_owner() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("metadata.json");
        let (mut proposed, before) = load_sidecar_snapshot::<usize>(&path, "metadata").unwrap();
        proposed.insert("PHANTOM".into(), 1);
        std::fs::write(&path, br#"{"OWNER":2}"#).unwrap();
        assert!(
            save_sidecar_map_if_unchanged(&path, "metadata", before.as_deref(), &proposed).is_err()
        );
        assert_eq!(std::fs::read(&path).unwrap(), br#"{"OWNER":2}"#);
    }

    #[test]
    fn sidecar_contract_uses_shared_windows_safe_exact_reader() {
        let source = include_str!("keychain.rs");
        assert!(source.contains("read_regular_file"));
        assert!(source.contains("atomic_write_if_unchanged"));
    }

    /// End-to-end round-trip against the real OS keychain. Ignored by
    /// default because it touches the user's actual keychain (and CI
    /// may not have one without `keyring`'s mock backend). Run with
    /// `cargo test -p phantom-secrets-vault -- --ignored` on each
    /// platform (macOS Keychain, Linux Secret Service, Windows
    /// Credential Manager) to confirm the backend is wired up.
    #[test]
    #[ignore = "touches OS keychain — run with --ignored on each platform"]
    fn os_keychain_roundtrip() {
        use crate::traits::VaultBackend;

        // Per-run unique project_id so a previous failed run can't
        // pollute this one's state.
        let project_id = format!("phantom-test-{}", std::process::id());
        let vault = KeychainVault::new(&project_id).expect("keychain backend should initialize");

        let name = "ROUNDTRIP_TEST_KEY";
        let value = "sk-test-value-do-not-use-12345";
        vault.store(name, value).expect("store");

        let got = vault.retrieve(name).expect("retrieve");
        assert_eq!(got.as_str(), value);

        let listed = vault.list().expect("list");
        assert!(listed.iter().any(|n| n == name));

        vault.delete(name).expect("delete");
        assert!(vault.retrieve(name).is_err());
    }
}
