use crate::metadata::SecretMetadata;
use crate::traits::{MetadataCas, ValidationMetadataCas, VaultBackend};
use phantom_core::error::{PhantomError, Result};
use phantom_core::fs::{AnchoredEffect, AnchoredLock, AnchoredRead, AnchoredTarget, TrustedAnchor};
use phantom_core::validator::ValidationMetadata;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::hash::{DefaultHasher, Hash, Hasher};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};
use zeroize::Zeroizing;

const SERVICE_PREFIX: &str = "phantom-secrets";
const PROCESS_LOCK_SHARDS: usize = 64;

/// Process-local lock shards complement the filesystem lock. Some OS locking
/// APIs treat locks from one process as mutually compatible even when they use
/// different file descriptors; the shard keeps threads honest while fs2
/// provides the cross-process boundary.
fn process_locks() -> &'static [Mutex<()>] {
    static LOCKS: OnceLock<Vec<Mutex<()>>> = OnceLock::new();
    LOCKS.get_or_init(|| (0..PROCESS_LOCK_SHARDS).map(|_| Mutex::new(())).collect())
}

fn process_lock_index(identity: &str) -> usize {
    let locks = process_locks();
    let mut hasher = DefaultHasher::new();
    identity.hash(&mut hasher);
    hasher.finish() as usize % locks.len()
}

fn process_locks_for(project_id: &str) -> Vec<MutexGuard<'static, ()>> {
    let locks = process_locks();
    let stable = format!("stable:{}", project_digest(project_id));
    let legacy = format!("legacy:{}", safe_project_component(project_id));
    let mut indices = [process_lock_index(&stable), process_lock_index(&legacy)];
    indices.sort_unstable();
    let count = if indices[0] == indices[1] { 1 } else { 2 };
    indices[..count]
        .iter()
        .map(|index| {
            locks[*index]
                .lock()
                .unwrap_or_else(|error| error.into_inner())
        })
        .collect()
}

pub(crate) struct ProjectLock {
    // Fields drop in declaration order. Release the compatibility lock, then
    // the stable filesystem lock, and only then the in-process guards so no
    // same-process caller can enter while an fs2 handle is still live.
    _legacy_file: AnchoredLock,
    _stable_file: AnchoredLock,
    _process: Vec<MutexGuard<'static, ()>>,
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

fn legacy_project_name_is_unambiguous(project_id: &str) -> bool {
    !project_id.is_empty()
        && project_id.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_')
        })
}

fn project_digest(project_id: &str) -> String {
    hex::encode(Sha256::digest(project_id.as_bytes()))
}

fn stable_lock_name(project_id: &str) -> String {
    format!("project-{}.lock", project_digest(project_id))
}

fn legacy_lock_path(project_id: &str) -> PathBuf {
    Path::new("metadata")
        .join("locks")
        .join(format!("{}.lock", safe_project_component(project_id)))
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
    sidecars: KeychainSidecars,
}

// ── Metadata sidecar helpers ─────────────────────────────────────────────────
//
// The OS keychain stores opaque password strings — there is no structured
// per-entry metadata slot. We persist TTL/expiry metadata in a small JSON
// sidecar file alongside the keychain index. The file contains only
// timestamps and policy config — no secret values — so it is safe to store
// as plaintext on disk (it is no more sensitive than a .phantom.toml).

struct KeychainSidecars {
    _app_data: Arc<TrustedAnchor>,
    _metadata: Arc<TrustedAnchor>,
    stable_lock: AnchoredTarget,
    legacy_lock: AnchoredTarget,
    metadata: AnchoredTarget,
    validation: AnchoredTarget,
    legacy_metadata: AnchoredTarget,
    legacy_validation: AnchoredTarget,
    legacy_name_is_ambiguous: bool,
}

fn open_app_data_anchor() -> Result<TrustedAnchor> {
    // ProjectDirs, BaseDirs, home_dir, and temp_dir all consult process-global
    // environment. Resolve the authority once under Phantom's shared lock,
    // then retain descriptors for every later filesystem operation.
    let _environment = phantom_core::PROCESS_ENV_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let project = directories::ProjectDirs::from("ai", "phantom", "phantom-secrets");
    let target = project
        .as_ref()
        .map(|dirs| dirs.data_dir().to_path_buf())
        .unwrap_or_else(|| {
            dirs::home_dir()
                .unwrap_or_else(std::env::temp_dir)
                .join(".phantom")
        });

    open_configured_app_data_anchor(&target)
}

fn open_configured_app_data_anchor(target: &Path) -> Result<TrustedAnchor> {
    // The OS/configured app-data path is the explicit ambient authority. It may
    // legitimately traverse aliases (macOS `/var`, redirected HOME/XDG roots),
    // so create it as configured, canonicalize once, then retain the resulting
    // directory capability. Only the final Phantom directory is chmod-repaired.
    std::fs::create_dir_all(target).map_err(|error| {
        PhantomError::VaultError(format!(
            "Cannot create Phantom app-data directory {}: {error}",
            target.display()
        ))
    })?;
    TrustedAnchor::open_canonical_private(target).map_err(Into::into)
}

impl KeychainSidecars {
    fn open(project_id: &str) -> Result<Self> {
        Self::from_anchor(open_app_data_anchor()?, project_id)
    }

    fn from_anchor(app_data: TrustedAnchor, project_id: &str) -> Result<Self> {
        let app_data = Arc::new(app_data);
        let metadata = Arc::new(app_data.private_subdirectory("metadata")?);
        let digest = project_digest(project_id);
        let legacy = safe_project_component(project_id);
        Ok(Self {
            stable_lock: app_data.target(stable_lock_name(project_id))?,
            legacy_lock: app_data.target_with_private_parents(legacy_lock_path(project_id))?,
            metadata: metadata.target(format!("{digest}.meta.json"))?,
            validation: metadata.target(format!("{digest}.validation.json"))?,
            legacy_metadata: metadata.target(format!("{legacy}.meta.json"))?,
            legacy_validation: metadata.target(format!("{legacy}.validation.json"))?,
            // Older sidecars used the project identifier directly after a
            // lossy sanitizer. Even unchanged uppercase or Unicode spellings
            // are ambiguous on case-folding/normalizing filesystems.
            legacy_name_is_ambiguous: !legacy_project_name_is_unambiguous(project_id),
            _app_data: app_data,
            _metadata: metadata,
        })
    }

    fn acquire_project_lock(&self, project_id: &str) -> Result<ProjectLock> {
        let process = process_locks_for(project_id);
        // Stable digest authority is always acquired first. The sanitized lock
        // is a one-release rolling-version bridge for older Phantom processes;
        // remove it only after the minimum supported version no longer writes
        // sanitized sidecars.
        let stable_file = self.stable_lock.acquire_exclusive_lock().map_err(|error| {
            PhantomError::VaultError(format!(
                "Cannot acquire stable per-project keychain lock: {error}"
            ))
        })?;
        let legacy_file = self.legacy_lock.acquire_exclusive_lock().map_err(|error| {
            PhantomError::VaultError(format!(
                "Cannot acquire legacy compatibility keychain lock: {error}"
            ))
        })?;
        Ok(ProjectLock {
            _legacy_file: legacy_file,
            _stable_file: stable_file,
            _process: process,
        })
    }

    fn reconcile_legacy(&self) -> Result<()> {
        let metadata = read_sidecar_pair(&self.metadata, &self.legacy_metadata)?;
        let validation = read_sidecar_pair(&self.validation, &self.legacy_validation)?;
        if self.legacy_name_is_ambiguous
            && (metadata.legacy.is_some() || validation.legacy.is_some())
        {
            return Err(PhantomError::VaultError(
                "Legacy keychain sidecar uses an ambiguous sanitized project identifier; close older Phantom processes, upgrade them to the current release, and manually attribute the value-free sidecar before retrying"
                    .to_string(),
            ));
        }
        ensure_sidecar_pair_compatible("metadata", &metadata)?;
        ensure_sidecar_pair_compatible("validation metadata", &validation)?;
        repair_sidecar_pair(&self.metadata, &self.legacy_metadata, &metadata)?;
        repair_sidecar_pair(&self.validation, &self.legacy_validation, &validation)?;
        reconcile_sidecar_pair("metadata", &self.metadata, &self.legacy_metadata, metadata)?;
        reconcile_sidecar_pair(
            "validation metadata",
            &self.validation,
            &self.legacy_validation,
            validation,
        )
    }
}

pub(crate) fn acquire_project_lock(project_id: &str) -> Result<ProjectLock> {
    KeychainSidecars::open(project_id)?.acquire_project_lock(project_id)
}

struct SidecarPair {
    stable: Option<AnchoredRead>,
    legacy: Option<AnchoredRead>,
}

fn read_sidecar_pair(stable: &AnchoredTarget, legacy: &AnchoredTarget) -> Result<SidecarPair> {
    Ok(SidecarPair {
        stable: stable.read_regular()?,
        legacy: legacy.read_regular()?,
    })
}

fn repair_sidecar_pair(
    stable_target: &AnchoredTarget,
    legacy_target: &AnchoredTarget,
    pair: &SidecarPair,
) -> Result<()> {
    if pair.stable.is_some() {
        stable_target.repair_private_regular()?;
    }
    if pair.legacy.is_some() {
        legacy_target.repair_private_regular()?;
    }
    Ok(())
}

fn ensure_sidecar_pair_compatible(label: &str, pair: &SidecarPair) -> Result<()> {
    if let (Some(stable), Some(legacy)) = (&pair.stable, &pair.legacy) {
        if stable.bytes() != legacy.bytes() {
            return Err(PhantomError::VaultError(format!(
                "Stable and legacy keychain {label} sidecars diverged; close older Phantom processes, upgrade them to the current release, and retry after reconciling the two value-free sidecar files"
            )));
        }
    }
    Ok(())
}

fn reconcile_sidecar_pair(
    label: &str,
    stable_target: &AnchoredTarget,
    legacy_target: &AnchoredTarget,
    pair: SidecarPair,
) -> Result<()> {
    match (pair.stable, pair.legacy) {
        (None, Some(legacy)) => {
            let published = require_durable_sidecar_effect(
                stable_target.replace_if_exact(None, legacy.bytes())?,
                &format!(
                    "keychain {label} stable sidecar publication; the legacy sidecar was preserved"
                ),
            )?;
            match legacy_target.unlink_if_exact(&legacy) {
                Err(error) => {
                    return Err(compensated_error(
                        &format!("keychain {label} sidecar migration"),
                        error.into(),
                        [stable_target
                            .unlink_if_exact(&published)
                            .map_err(PhantomError::from)
                            .and_then(|outcome| {
                                require_durable_sidecar_effect(
                                    outcome,
                                    &format!("keychain {label} stable sidecar rollback; the legacy sidecar remains authoritative"),
                                )
                            })],
                    ));
                }
                Ok(outcome) => {
                    // The legacy unlink committed. Never compensate by
                    // deleting the new authoritative sidecar merely because
                    // its parent sync was uncertain.
                    require_durable_sidecar_effect(
                        outcome,
                        &format!("keychain {label} legacy sidecar removal"),
                    )?;
                }
            }
            Ok(())
        }
        (Some(_), Some(legacy)) => {
            let outcome = legacy_target.unlink_if_exact(&legacy)?;
            require_durable_sidecar_effect(
                outcome,
                &format!("duplicate keychain {label} legacy sidecar removal"),
            )
        }
        (Some(_), None) | (None, None) => Ok(()),
    }
}

fn load_sidecar_map<T>(target: &AnchoredTarget, label: &str) -> Result<BTreeMap<String, T>>
where
    T: serde::de::DeserializeOwned,
{
    let Some(contents) = target.read_regular()? else {
        return Ok(BTreeMap::new());
    };
    serde_json::from_slice(contents.bytes()).map_err(|error| {
        PhantomError::VaultError(format!(
            "Corrupt keychain {label} sidecar {}: {error}",
            target.relative_path().display()
        ))
    })
}

type SidecarSnapshot<T> = (BTreeMap<String, T>, Option<AnchoredRead>);

fn load_sidecar_snapshot<T>(target: &AnchoredTarget, label: &str) -> Result<SidecarSnapshot<T>>
where
    T: serde::de::DeserializeOwned,
{
    let before = target.read_regular()?;
    let map = match before.as_ref() {
        Some(contents) => serde_json::from_slice(contents.bytes()).map_err(|error| {
            PhantomError::VaultError(format!(
                "Corrupt keychain {label} sidecar {}: {error}",
                target.relative_path().display()
            ))
        })?,
        None => BTreeMap::new(),
    };
    Ok((map, before))
}

fn save_sidecar_map<T>(
    target: &AnchoredTarget,
    label: &str,
    map: &BTreeMap<String, T>,
) -> Result<()>
where
    T: serde::Serialize,
{
    let before = target.read_regular()?;
    let json = serde_json::to_vec_pretty(map).map_err(|error| {
        PhantomError::VaultError(format!("Keychain {label} serialize error: {error}"))
    })?;
    let outcome = target.replace_if_exact(before.as_ref(), &json)?;
    require_durable_sidecar_effect(outcome, &format!("keychain {label} sidecar update")).map(|_| ())
}

fn save_sidecar_map_if_unchanged<T>(
    target: &AnchoredTarget,
    label: &str,
    expected_before: Option<&AnchoredRead>,
    map: &BTreeMap<String, T>,
) -> Result<()>
where
    T: serde::Serialize,
{
    let json = serde_json::to_vec_pretty(map).map_err(|error| {
        PhantomError::VaultError(format!("Keychain {label} serialize error: {error}"))
    })?;
    let outcome = target.replace_if_exact(expected_before, &json)?;
    require_durable_sidecar_effect(outcome, &format!("keychain {label} sidecar update")).map(|_| ())
}

fn require_durable_sidecar_effect<T>(outcome: AnchoredEffect<T>, operation: &str) -> Result<T> {
    match outcome {
        AnchoredEffect::Durable(value) => Ok(value),
        AnchoredEffect::CommittedButUncertain { value: _, error } => Err(PhantomError::VaultError(format!(
            "{operation} committed, but durability or post-effect verification is uncertain: {error}. Do not assume the operation had no effect; reopen and verify the sidecar state before retrying"
        ))),
    }
}

// ── Validation metadata sidecar ──────────────────────────────────────────────
//
// Mirrors the TTL metadata sidecar: a separate JSON file stores per-secret
// validation state (last_check_ts, is_valid, failure_reason). No secret
// values are ever written here.

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

        let vault = Self {
            index_key: format!("{SERVICE_PREFIX}:{project_id}:__index__"),
            project_id: project_id.to_string(),
            sidecars: KeychainSidecars::open(project_id)?,
        };
        // Reconcile value-free sidecars while both the stable lock and the
        // rolling legacy bridge are held. No ambient pathname is consulted.
        let _lock = vault.lock_sidecars()?;
        Ok(vault)
    }

    fn lock_sidecars(&self) -> Result<ProjectLock> {
        let lock = self.sidecars.acquire_project_lock(&self.project_id)?;
        self.sidecars.reconcile_legacy()?;
        Ok(lock)
    }

    fn load_meta_map(&self) -> Result<BTreeMap<String, SecretMetadata>> {
        load_sidecar_map(&self.sidecars.metadata, "metadata")
    }

    fn save_meta_map(&self, map: &BTreeMap<String, SecretMetadata>) -> Result<()> {
        save_sidecar_map(&self.sidecars.metadata, "metadata", map)
    }

    fn load_validation_meta_map(&self) -> Result<BTreeMap<String, ValidationMetadata>> {
        load_sidecar_map(&self.sidecars.validation, "validation")
    }

    fn save_validation_meta_map(&self, map: &BTreeMap<String, ValidationMetadata>) -> Result<()> {
        save_sidecar_map(&self.sidecars.validation, "validation", map)
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
        let before_metadata = self.load_meta_map()?;
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
                self.save_meta_map(&after_metadata)?;
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
                    self.save_meta_map(&before_metadata),
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
        let before_metadata = self.load_meta_map()?;
        let before_validation = self.load_validation_meta_map()?;
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
                self.save_meta_map(&after_metadata)?;
            }
            if after_validation != before_validation {
                self.save_validation_meta_map(&after_validation)?;
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
                self.save_meta_map(&before_metadata),
                self.save_validation_meta_map(&before_validation),
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
        let _lock = self.lock_sidecars()?;
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
                let _lock = self.lock_sidecars()?;
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
        let _lock = self.lock_sidecars()?;
        let metadata = self.load_meta_map()?;
        crate::traits::ensure_secret_injectable(name, metadata.get(name))?;
        let value = self
            .current_value_locked(name)?
            .ok_or_else(|| PhantomError::SecretNotFound(name.to_string()))?;
        phantom_core::audit::log("vault.retrieve_for_injection", Some(name));
        Ok(value)
    }

    fn delete(&self, name: &str) -> Result<()> {
        let _lock = self.lock_sidecars()?;
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
        let _lock = self.lock_sidecars()?;
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
        let _lock = self.lock_sidecars()?;
        self.load_index()
    }

    fn backend_name(&self) -> &str {
        "os-keychain"
    }

    fn get_metadata(&self, name: &str) -> Result<Option<SecretMetadata>> {
        let _lock = self.lock_sidecars()?;
        let map = self.load_meta_map()?;
        Ok(map.get(name).cloned())
    }

    fn set_metadata(&self, name: &str, meta: SecretMetadata) -> Result<()> {
        let _lock = self.lock_sidecars()?;
        // Only allow metadata on keys that actually exist in the vault index.
        let index = self.load_index()?;
        if !index.contains(&name.to_string()) {
            return Err(PhantomError::SecretNotFound(name.to_string()));
        }
        let mut map = self.load_meta_map()?;
        map.insert(name.to_string(), meta);
        self.save_meta_map(&map)
    }

    fn compare_and_swap_metadata_batch(&self, changes: &[MetadataCas]) -> Result<bool> {
        let _lock = self.lock_sidecars()?;
        let index = self.load_index()?;
        let target = &self.sidecars.metadata;
        let (mut map, before) = load_sidecar_snapshot(target, "metadata")?;
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
            save_sidecar_map_if_unchanged(target, "metadata", before.as_ref(), &map)?;
        }
        Ok(true)
    }

    fn list_with_metadata(&self) -> Result<Vec<(String, Option<SecretMetadata>)>> {
        let _lock = self.lock_sidecars()?;
        let names = self.load_index()?;
        let metadata = self.load_meta_map()?;
        Ok(names
            .into_iter()
            .map(|name| {
                let meta = metadata.get(&name).cloned();
                (name, meta)
            })
            .collect())
    }

    fn store_with_expiry(&self, name: &str, value: &str, days_ttl: u64) -> Result<()> {
        let _lock = self.lock_sidecars()?;
        self.store_locked(name, value, Some(SecretMetadata::with_expiry(days_ttl)))?;
        phantom_core::audit::log("vault.store", Some(name));
        Ok(())
    }

    fn get_validation_metadata(&self, name: &str) -> Result<ValidationMetadata> {
        let _lock = self.lock_sidecars()?;
        let map = self.load_validation_meta_map()?;
        Ok(map.get(name).cloned().unwrap_or_default())
    }

    fn get_validation_metadata_exact(&self, name: &str) -> Result<Option<ValidationMetadata>> {
        let _lock = self.lock_sidecars()?;
        let map = self.load_validation_meta_map()?;
        Ok(map.get(name).cloned())
    }

    fn set_validation_metadata(&self, name: &str, meta: ValidationMetadata) -> Result<()> {
        let _lock = self.lock_sidecars()?;
        let index = self.load_index()?;
        if !index.contains(&name.to_string()) {
            return Err(PhantomError::SecretNotFound(name.to_string()));
        }
        let mut map = self.load_validation_meta_map()?;
        map.insert(name.to_string(), meta);
        self.save_validation_meta_map(&map)
    }

    fn compare_and_swap_validation_metadata_batch(
        &self,
        changes: &[ValidationMetadataCas],
    ) -> Result<bool> {
        let _lock = self.lock_sidecars()?;
        let index = self.load_index()?;
        let target = &self.sidecars.validation;
        let (mut map, before) = load_sidecar_snapshot(target, "validation metadata")?;
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
            save_sidecar_map_if_unchanged(target, "validation metadata", before.as_ref(), &map)?;
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
        let sidecars = Arc::new(
            KeychainSidecars::from_anchor(
                TrustedAnchor::open_canonical_private(&root).unwrap(),
                "concurrent-project",
            )
            .unwrap(),
        );
        let barrier = Arc::new(Barrier::new(WRITERS));
        let mut workers = Vec::new();

        for writer in 0..WRITERS {
            let barrier = Arc::clone(&barrier);
            let sidecars = Arc::clone(&sidecars);
            workers.push(std::thread::spawn(move || {
                barrier.wait();
                let _lock = sidecars.acquire_project_lock("concurrent-project").unwrap();
                sidecars.reconcile_legacy().unwrap();
                let mut map: BTreeMap<String, usize> =
                    load_sidecar_map(&sidecars.metadata, "test metadata").unwrap();
                // Enlarge the unprotected race window. With the production
                // lock held, every process-equivalent writer still observes
                // and preserves every prior name.
                std::thread::yield_now();
                map.insert(format!("KEY_{writer:02}"), writer);
                save_sidecar_map(&sidecars.metadata, "test metadata", &map).unwrap();
            }));
        }
        for worker in workers {
            worker.join().unwrap();
        }

        let map: BTreeMap<String, usize> =
            load_sidecar_map(&sidecars.metadata, "test metadata").unwrap();
        assert_eq!(map.len(), WRITERS);
        for writer in 0..WRITERS {
            assert_eq!(map.get(&format!("KEY_{writer:02}")), Some(&writer));
        }

        let metadata_artifacts = std::fs::read_dir(root.join("metadata"))
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        assert!(metadata_artifacts
            .iter()
            .all(|name| !name.starts_with(".phantom-tmp-")));
    }

    #[cfg(unix)]
    #[test]
    fn project_lock_file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempdir().unwrap();
        let root = directory.path().canonicalize().unwrap();
        let sidecars = KeychainSidecars::from_anchor(
            TrustedAnchor::open_canonical_private(&root).unwrap(),
            "owner-only",
        )
        .unwrap();
        let _lock = sidecars.acquire_project_lock("owner-only").unwrap();
        let stable_path = root.join(stable_lock_name("owner-only"));
        let legacy_path = root.join(legacy_lock_path("owner-only"));
        let stable_mode = std::fs::metadata(&stable_path)
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        let legacy_mode = std::fs::metadata(&legacy_path)
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(stable_mode, 0o600);
        assert_eq!(legacy_mode, 0o600);
    }

    #[cfg(unix)]
    #[test]
    fn project_lock_repairs_permissive_legacy_parent_through_handle() {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempdir().unwrap();
        let root = directory.path().canonicalize().unwrap();
        let parent = root.join("metadata").join("locks");
        std::fs::create_dir_all(&parent).unwrap();
        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o755)).unwrap();
        let sidecars = KeychainSidecars::from_anchor(
            TrustedAnchor::open_canonical_private(&root).unwrap(),
            "owner-only",
        )
        .unwrap();
        let _lock = sidecars.acquire_project_lock("owner-only").unwrap();
        assert_eq!(
            std::fs::metadata(parent).unwrap().permissions().mode() & 0o777,
            0o700
        );
    }

    #[test]
    fn corrupt_sidecar_is_not_silently_replaced() {
        let directory = tempdir().unwrap();
        let root = directory.path().canonicalize().unwrap();
        let anchor = TrustedAnchor::open_canonical_private(&root).unwrap();
        let target = anchor.target("corrupt.meta.json").unwrap();
        let path = root.join("corrupt.meta.json");
        std::fs::write(&path, b"not-json").unwrap();

        let error = load_sidecar_map::<usize>(&target, "metadata").unwrap_err();

        assert!(error
            .to_string()
            .contains("Corrupt keychain metadata sidecar"));
        assert_eq!(std::fs::read(&path).unwrap(), b"not-json");
    }

    #[test]
    fn exact_sidecar_save_rejects_concurrent_owner() {
        let directory = tempdir().unwrap();
        let root = directory.path().canonicalize().unwrap();
        let anchor = TrustedAnchor::open_canonical_private(&root).unwrap();
        let target = anchor.target("metadata.json").unwrap();
        let path = root.join("metadata.json");
        let (mut proposed, before) = load_sidecar_snapshot::<usize>(&target, "metadata").unwrap();
        proposed.insert("PHANTOM".into(), 1);
        std::fs::write(&path, br#"{"OWNER":2}"#).unwrap();
        assert!(
            save_sidecar_map_if_unchanged(&target, "metadata", before.as_ref(), &proposed).is_err()
        );
        assert_eq!(std::fs::read(&path).unwrap(), br#"{"OWNER":2}"#);
    }

    #[test]
    fn sanitized_project_collision_has_distinct_stable_authority() {
        let directory = tempdir().unwrap();
        let root = directory.path().canonicalize().unwrap();
        let first = KeychainSidecars::from_anchor(
            TrustedAnchor::open_canonical_private(&root).unwrap(),
            "project/a",
        )
        .unwrap();
        let second = KeychainSidecars::from_anchor(
            TrustedAnchor::open_canonical_private(&root).unwrap(),
            "project?a",
        )
        .unwrap();

        assert_eq!(
            first.legacy_metadata.relative_path(),
            second.legacy_metadata.relative_path()
        );
        assert_ne!(
            first.metadata.relative_path(),
            second.metadata.relative_path()
        );
        assert_ne!(
            first.stable_lock.relative_path(),
            second.stable_lock.relative_path()
        );

        let _outcome = first
            .legacy_metadata
            .replace_if_exact(None, br#"{"AMBIGUOUS":1}"#)
            .unwrap();
        let _lock = first.acquire_project_lock("project/a").unwrap();
        let error = first.reconcile_legacy().unwrap_err();
        assert!(error.to_string().contains("ambiguous sanitized"));
        assert!(first.metadata.read_regular().unwrap().is_none());
        assert_eq!(
            first
                .legacy_metadata
                .read_regular()
                .unwrap()
                .unwrap()
                .bytes(),
            br#"{"AMBIGUOUS":1}"#
        );
    }

    #[test]
    fn case_folded_legacy_sidecar_is_never_auto_claimed() {
        let directory = tempdir().unwrap();
        let root = directory.path().canonicalize().unwrap();
        let upper = KeychainSidecars::from_anchor(
            TrustedAnchor::open_canonical_private(&root).unwrap(),
            "Project",
        )
        .unwrap();
        let lower = KeychainSidecars::from_anchor(
            TrustedAnchor::open_canonical_private(&root).unwrap(),
            "project",
        )
        .unwrap();

        assert!(upper.legacy_name_is_ambiguous);
        assert!(!lower.legacy_name_is_ambiguous);
        assert_ne!(
            upper.metadata.relative_path(),
            lower.metadata.relative_path()
        );
        let _outcome = upper
            .legacy_metadata
            .replace_if_exact(None, br#"{"OWNER":1}"#)
            .unwrap();

        let _lock = upper.acquire_project_lock("Project").unwrap();
        let error = upper.reconcile_legacy().unwrap_err();
        assert!(error.to_string().contains("ambiguous sanitized"));
        assert!(upper.metadata.read_regular().unwrap().is_none());
        assert_eq!(
            upper
                .legacy_metadata
                .read_regular()
                .unwrap()
                .unwrap()
                .bytes(),
            br#"{"OWNER":1}"#
        );
    }

    #[test]
    fn unicode_legacy_sidecars_are_always_ambiguous() {
        for project_id in ["caf\u{e9}", "cafe\u{301}"] {
            let directory = tempdir().unwrap();
            let root = directory.path().canonicalize().unwrap();
            let sidecars = KeychainSidecars::from_anchor(
                TrustedAnchor::open_canonical_private(&root).unwrap(),
                project_id,
            )
            .unwrap();
            assert!(sidecars.legacy_name_is_ambiguous);
            let _outcome = sidecars
                .legacy_metadata
                .replace_if_exact(None, br#"{"OWNER":1}"#)
                .unwrap();

            let _lock = sidecars.acquire_project_lock(project_id).unwrap();
            assert!(sidecars
                .reconcile_legacy()
                .unwrap_err()
                .to_string()
                .contains("ambiguous sanitized"));
            assert!(sidecars.metadata.read_regular().unwrap().is_none());
            assert!(sidecars.legacy_metadata.read_regular().unwrap().is_some());
        }
    }

    #[test]
    fn committed_sidecar_effect_receipt_is_not_treated_as_no_effect() {
        let error = require_durable_sidecar_effect(
            AnchoredEffect::CommittedButUncertain {
                value: (),
                error: std::io::Error::other("injected parent sync failure"),
            },
            "keychain metadata sidecar update",
        )
        .unwrap_err();

        let message = error.to_string();
        assert!(message.contains("committed"));
        assert!(message.contains("Do not assume the operation had no effect"));
    }

    #[test]
    fn legacy_sidecar_migrates_exactly_under_bridge_locks() {
        let directory = tempdir().unwrap();
        let root = directory.path().canonicalize().unwrap();
        let sidecars = KeychainSidecars::from_anchor(
            TrustedAnchor::open_canonical_private(&root).unwrap(),
            "legacy-project",
        )
        .unwrap();
        let _outcome = sidecars
            .legacy_metadata
            .replace_if_exact(None, br#"{"API_KEY":1}"#)
            .unwrap();

        let _lock = sidecars.acquire_project_lock("legacy-project").unwrap();
        sidecars.reconcile_legacy().unwrap();

        assert_eq!(
            sidecars.metadata.read_regular().unwrap().unwrap().bytes(),
            br#"{"API_KEY":1}"#
        );
        assert!(sidecars.legacy_metadata.read_regular().unwrap().is_none());
    }

    #[test]
    fn divergent_sequential_legacy_write_fails_closed_without_effect() {
        let directory = tempdir().unwrap();
        let root = directory.path().canonicalize().unwrap();
        let sidecars = KeychainSidecars::from_anchor(
            TrustedAnchor::open_canonical_private(&root).unwrap(),
            "legacy-project",
        )
        .unwrap();
        let _outcome = sidecars
            .metadata
            .replace_if_exact(None, br#"{"NEW":1}"#)
            .unwrap();
        let _outcome = sidecars
            .legacy_metadata
            .replace_if_exact(None, br#"{"OLD":2}"#)
            .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            let metadata_dir = root.join("metadata");
            std::fs::set_permissions(
                metadata_dir.join(format!("{}.meta.json", project_digest("legacy-project"))),
                std::fs::Permissions::from_mode(0o644),
            )
            .unwrap();
            std::fs::set_permissions(
                metadata_dir.join("legacy-project.meta.json"),
                std::fs::Permissions::from_mode(0o644),
            )
            .unwrap();
        }

        let _lock = sidecars.acquire_project_lock("legacy-project").unwrap();
        let error = sidecars.reconcile_legacy().unwrap_err();

        assert!(error.to_string().contains("sidecars diverged"));
        assert_eq!(
            sidecars.metadata.read_regular().unwrap().unwrap().bytes(),
            br#"{"NEW":1}"#
        );
        assert_eq!(
            sidecars
                .legacy_metadata
                .read_regular()
                .unwrap()
                .unwrap()
                .bytes(),
            br#"{"OLD":2}"#
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            let metadata_dir = root.join("metadata");
            let stable_mode = std::fs::metadata(
                metadata_dir.join(format!("{}.meta.json", project_digest("legacy-project"))),
            )
            .unwrap()
            .permissions()
            .mode()
                & 0o777;
            let legacy_mode = std::fs::metadata(metadata_dir.join("legacy-project.meta.json"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!((stable_mode, legacy_mode), (0o644, 0o644));
        }
    }

    #[cfg(unix)]
    #[test]
    fn configured_app_data_symlink_is_canonicalized_once() {
        use std::os::unix::fs::symlink;

        let directory = tempdir().unwrap();
        let real = directory.path().join("real-app-data");
        let alias = directory.path().join("configured-app-data");
        std::fs::create_dir(&real).unwrap();
        symlink(&real, &alias).unwrap();

        let anchor = open_configured_app_data_anchor(&alias).unwrap();
        let sidecars = KeychainSidecars::from_anchor(anchor, "alias-project").unwrap();
        save_sidecar_map(
            &sidecars.metadata,
            "metadata",
            &BTreeMap::from([("OWNER".to_string(), 1_usize)]),
        )
        .unwrap();

        assert!(real
            .join("metadata")
            .join(format!("{}.meta.json", project_digest("alias-project")))
            .is_file());
    }

    #[cfg(unix)]
    #[test]
    fn retained_metadata_capability_ignores_ancestor_swap_decoy() {
        let directory = tempdir().unwrap();
        let app = directory.path().join("app");
        std::fs::create_dir(&app).unwrap();
        let sidecars = KeychainSidecars::from_anchor(
            TrustedAnchor::open_canonical_private(&app).unwrap(),
            "swap-project",
        )
        .unwrap();
        save_sidecar_map(
            &sidecars.metadata,
            "metadata",
            &BTreeMap::from([("OWNER".to_string(), 1_usize)]),
        )
        .unwrap();

        let owned = directory.path().join("owned");
        std::fs::rename(&app, &owned).unwrap();
        std::fs::create_dir_all(app.join("metadata")).unwrap();
        let decoy = app
            .join("metadata")
            .join(format!("{}.meta.json", project_digest("swap-project")));
        std::fs::write(&decoy, br#"{"DECOY":9}"#).unwrap();

        let _lock = sidecars.acquire_project_lock("swap-project").unwrap();
        sidecars.reconcile_legacy().unwrap();
        save_sidecar_map(
            &sidecars.metadata,
            "metadata",
            &BTreeMap::from([("OWNER".to_string(), 2_usize)]),
        )
        .unwrap();

        assert_eq!(std::fs::read(&decoy).unwrap(), br#"{"DECOY":9}"#);
        let anchored: BTreeMap<String, usize> =
            load_sidecar_map(&sidecars.metadata, "metadata").unwrap();
        assert_eq!(anchored.get("OWNER"), Some(&2));
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
