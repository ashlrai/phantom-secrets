use crate::crypto;
use crate::metadata::SecretMetadata;
use crate::traits::{MetadataCas, ValidationMetadataCas, VaultBackend};
use phantom_core::error::{PhantomError, Result};
use phantom_core::fs::{AnchoredEffect, AnchoredLock, AnchoredRead, AnchoredTarget, TrustedAnchor};
use phantom_core::validator::ValidationMetadata;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// ChaCha20-Poly1305 encrypted file vault backend.
/// Uses shared crypto module for encryption/decryption.
pub struct FileVault {
    base_anchor: TrustedAnchor,
    names: VaultNames,
    vault_path: PathBuf,
    passphrase: String,
}

struct VaultNames {
    stable_lock: String,
    legacy_lock: String,
    encrypted: String,
    legacy_json: String,
}

struct LockedVault {
    _stable_lock: AnchoredLock,
    _legacy_lock: AnchoredLock,
    encrypted: AnchoredTarget,
    legacy_json: AnchoredTarget,
}

struct LoadedVault {
    data: VaultData,
    before: Option<AnchoredRead>,
}

#[derive(Debug, Serialize, Deserialize, Default, PartialEq)]
struct VaultData {
    secrets: BTreeMap<String, String>,
    /// Per-secret TTL/expiry metadata. Keys match the keys in `secrets`.
    /// Absent entries mean "no metadata" — graceful on older vault files.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    metadata: BTreeMap<String, SecretMetadata>,
    /// Per-secret validation metadata (last check timestamp, is_valid, failure_reason).
    /// Stored alongside TTL metadata. Absent entries mean "never validated".
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    validation_metadata: BTreeMap<String, ValidationMetadata>,
}

impl FileVault {
    /// Create a new encrypted file vault beneath an explicitly authorized base.
    ///
    /// `base_dir` is a trust boundary, not untrusted project input. Phantom may
    /// create it and resolves configured symlinks/junctions in it so OS-managed
    /// aliases and XDG/home redirections work. The resolved base is retained by
    /// handle. Every operation takes a stable lock directly beneath that base,
    /// then pins `vaults` and takes the legacy subtree lock for compatibility
    /// with older Phantom processes before performing capability-relative I/O.
    pub fn new(base_dir: &Path, project_id: &str, passphrase: String) -> Result<Self> {
        validate_project_id(project_id)?;
        let (base_anchor, canonical_base) = open_trusted_base(base_dir)?;
        let names = VaultNames::new(project_id);

        let vault = Self {
            base_anchor,
            vault_path: canonical_base.join("vaults").join(&names.encrypted),
            names,
            passphrase,
        };

        // Auto-migrate from the old unencrypted .json format while both the
        // stable base lock and the compatibility subtree lock are held.
        let locked = vault.lock_view()?;
        vault.migrate_from_json(&locked)?;

        Ok(vault)
    }

    /// Migrate from old unencrypted JSON vault to encrypted format.
    fn migrate_from_json(&self, locked: &LockedVault) -> Result<()> {
        let encrypted_before = locked.encrypted.read_regular()?;
        let legacy_before = locked.legacy_json.read_regular()?;

        let Some(legacy) = legacy_before else {
            return Ok(());
        };
        let legacy_data: VaultData = serde_json::from_slice(legacy.bytes()).map_err(|error| {
            PhantomError::VaultError(format!(
                "Legacy plaintext vault coexists with migration state but is corrupt; refusing to remove or replace either file: {error}"
            ))
        })?;

        if let Some(encrypted) = encrypted_before {
            let plaintext = zeroize::Zeroizing::new(
                crypto::decrypt(encrypted.bytes(), &self.passphrase).map_err(|error| {
                    PhantomError::VaultError(format!(
                        "Encrypted vault coexists with a legacy plaintext vault but cannot be verified; refusing to remove or replace either file: {error}"
                    ))
                })?,
            );
            let encrypted_data: VaultData = serde_json::from_slice(&plaintext).map_err(|error| {
                PhantomError::VaultError(format!(
                    "Encrypted vault coexists with a legacy plaintext vault but is corrupt; refusing to remove or replace either file: {error}"
                ))
            })?;
            if encrypted_data != legacy_data {
                return Err(PhantomError::VaultError(
                    "Encrypted and legacy plaintext vaults contain divergent state; refusing to remove or replace either file. Reconcile them manually before retrying"
                        .into(),
                ));
            }
            let removal = locked.legacy_json.unlink_if_exact(&legacy)?;
            require_durable_effect(removal, "verified duplicate legacy plaintext vault removal")?;
            eprintln!(
                "phantom: removed verified duplicate legacy plaintext vault ({})",
                self.vault_path.with_extension("json").display()
            );
            return Ok(());
        }

        let encrypted = self.encrypt(&legacy_data)?;
        let published = require_durable_effect(
            locked.encrypted.replace_if_exact(None, &encrypted)?,
            "encrypted legacy-vault replacement publication; the legacy plaintext copy was preserved",
        )?;
        match locked.legacy_json.unlink_if_exact(&legacy) {
            Err(unlink_error) => {
                let rollback = locked
                    .encrypted
                    .unlink_if_exact(&published)
                    .map_err(PhantomError::from)
                    .and_then(|outcome| {
                        require_durable_effect(
                            outcome,
                            "encrypted legacy-vault migration rollback; the legacy plaintext copy remains authoritative",
                        )
                    });
                return Err(PhantomError::VaultError(match rollback {
                    Ok(()) => format!(
                        "Legacy vault changed before exact removal; encrypted migration was rolled back: {unlink_error}"
                    ),
                    Err(rollback_error) => format!(
                        "Legacy vault changed before exact removal and encrypted migration rollback failed: {unlink_error}; rollback: {rollback_error}"
                    ),
                }));
            }
            Ok(outcome) => {
                // A committed-but-uncertain unlink may already have removed
                // the legacy copy. Preserve the published encrypted copy.
                require_durable_effect(outcome, "legacy plaintext vault removal")?;
            }
        }

        eprintln!(
            "phantom: migrated vault to encrypted format ({})",
            self.vault_path.display()
        );

        Ok(())
    }

    fn load(&self, locked: &LockedVault) -> Result<LoadedVault> {
        let Some(before) = locked.encrypted.read_regular()? else {
            return Ok(LoadedVault {
                data: VaultData::default(),
                before: None,
            });
        };

        if locked.encrypted.repair_private_regular()? {
            eprintln!(
                "phantom: WARNING — repaired vault file permissions to owner-only: {}",
                self.vault_path.display()
            );
        }

        // Wrap the decrypted JSON in Zeroizing so the heap buffer is overwritten
        // with zeros when it drops — whether that's on success or on an early
        // return from the serde_json error path below.
        let plaintext = zeroize::Zeroizing::new(crypto::decrypt(before.bytes(), &self.passphrase)?);

        let data = serde_json::from_slice::<VaultData>(&plaintext)
            .map_err(|e| PhantomError::VaultError(format!("Corrupt vault data: {e}")))?;
        Ok(LoadedVault {
            data,
            before: Some(before),
        })
    }

    /// Lock a stable base child first, then pin the current `vaults` directory
    /// and take the legacy lock. This ordering serializes new processes across
    /// subtree replacement while remaining compatible with older processes.
    fn lock_view(&self) -> Result<LockedVault> {
        let stable_lock = self
            .base_anchor
            .acquire_lock(&self.names.stable_lock)
            .map_err(|e| {
                PhantomError::VaultError(format!("Cannot acquire stable vault lock: {e}"))
            })?;
        let vaults = self.base_anchor.private_subdirectory("vaults")?;
        // One-release compatibility bridge: remove this second lock only after
        // every supported Phantom client emits the stable base lock and a full
        // release cycle shows no legacy-only lock contention in migration QA.
        let legacy_lock = vaults.acquire_lock(&self.names.legacy_lock).map_err(|e| {
            PhantomError::VaultError(format!("Cannot acquire legacy vault lock: {e}"))
        })?;
        let encrypted = vaults.target(&self.names.encrypted)?;
        let legacy_json = vaults.target(&self.names.legacy_json)?;
        Ok(LockedVault {
            _stable_lock: stable_lock,
            _legacy_lock: legacy_lock,
            encrypted,
            legacy_json,
        })
    }

    fn encrypt(&self, data: &VaultData) -> Result<Vec<u8>> {
        // The plaintext JSON holds every secret in the vault. Wrap it in
        // Zeroizing so the heap allocation is scrubbed on drop — including on
        // the error paths below. String's own Drop does not zero memory.
        let plaintext = zeroize::Zeroizing::new(
            serde_json::to_string_pretty(data)
                .map_err(|e| PhantomError::VaultError(format!("Serialize error: {e}")))?,
        );

        crypto::encrypt(plaintext.as_bytes(), &self.passphrase)
    }

    fn save(
        &self,
        locked: &LockedVault,
        data: &VaultData,
        expected: Option<&AnchoredRead>,
    ) -> Result<()> {
        let encrypted = self.encrypt(data)?;
        let outcome = locked.encrypted.replace_if_exact(expected, &encrypted)?;
        require_durable_effect(outcome, "encrypted vault update").map(|_| ())
    }
}

pub(crate) fn encrypted_vault_exists(base_dir: &Path, project_id: &str) -> Result<bool> {
    validate_project_id(project_id)?;
    let (base_anchor, _) = open_trusted_base(base_dir)?;
    let names = VaultNames::new(project_id);
    let stable_lock = base_anchor.acquire_lock(&names.stable_lock)?;
    let vaults = base_anchor.private_subdirectory("vaults")?;
    let legacy_lock = vaults.acquire_lock(&names.legacy_lock)?;
    let exists = vaults.target(&names.encrypted)?.read_regular()?.is_some();
    drop(legacy_lock);
    drop(stable_lock);
    Ok(exists)
}

impl VaultNames {
    fn new(project_id: &str) -> Self {
        Self {
            stable_lock: format!("vault-{project_id}.lock"),
            legacy_lock: format!("{project_id}.lock"),
            encrypted: format!("{project_id}.vault"),
            legacy_json: format!("{project_id}.json"),
        }
    }
}

fn open_trusted_base(base_dir: &Path) -> Result<(TrustedAnchor, PathBuf)> {
    std::fs::create_dir_all(base_dir)?;
    let canonical = base_dir.canonicalize()?;
    let anchor = TrustedAnchor::open(&canonical)?;
    Ok((anchor, canonical))
}

/// Validate the identifier before it is ever interpolated into a filesystem
/// path. Generated Phantom IDs are hexadecimal, while legacy/test IDs may also
/// contain `-` or `_`; path separators, dot segments, whitespace, and Unicode
/// are deliberately rejected so the file backend cannot escape `vaults/` on
/// any supported platform.
fn validate_project_id(project_id: &str) -> Result<()> {
    let valid = !project_id.is_empty()
        && project_id.len() <= 128
        && project_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'));

    if valid && !is_windows_reserved_basename(project_id) {
        Ok(())
    } else {
        Err(PhantomError::VaultError(
            "Invalid project ID for encrypted file vault".to_string(),
        ))
    }
}

fn is_windows_reserved_basename(project_id: &str) -> bool {
    let upper = project_id.to_ascii_uppercase();
    matches!(upper.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || upper.strip_prefix("COM").is_some_and(|suffix| {
            matches!(suffix, "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9")
        })
        || upper.strip_prefix("LPT").is_some_and(|suffix| {
            matches!(suffix, "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9")
        })
}

fn require_durable_effect<T>(outcome: AnchoredEffect<T>, operation: &str) -> Result<T> {
    match outcome {
        AnchoredEffect::Durable(value) => Ok(value),
        AnchoredEffect::CommittedButUncertain { value: _, error } => Err(PhantomError::VaultError(format!(
            "{operation} committed, but durability or post-effect verification is uncertain: {error}. Do not assume the operation had no effect; reopen and verify the vault before retrying"
        ))),
    }
}

impl VaultBackend for FileVault {
    fn store(&self, name: &str, value: &str) -> Result<()> {
        let locked = self.lock_view()?;
        let LoadedVault { mut data, before } = self.load(&locked)?;
        // Preserve existing metadata on overwrite; seed created_at for new entries.
        if !data.secrets.contains_key(name) {
            data.metadata
                .entry(name.to_string())
                .or_insert_with(crate::metadata::SecretMetadata::new_now);
        }
        data.secrets.insert(name.to_string(), value.to_string());
        self.save(&locked, &data, before.as_ref())?;
        phantom_core::audit::log("vault.store", Some(name));
        Ok(())
    }

    fn retrieve(&self, name: &str) -> Result<zeroize::Zeroizing<String>> {
        let locked = self.lock_view()?;
        let data = self.load(&locked)?.data;
        let value = data
            .secrets
            .get(name)
            .cloned()
            .ok_or_else(|| PhantomError::SecretNotFound(name.to_string()))?;
        phantom_core::audit::log("vault.retrieve", Some(name));
        Ok(zeroize::Zeroizing::new(value))
    }

    fn retrieve_for_injection(&self, name: &str) -> Result<zeroize::Zeroizing<String>> {
        let locked = self.lock_view()?;
        let data = self.load(&locked)?.data;
        crate::traits::ensure_secret_injectable(name, data.metadata.get(name))?;
        let value = data
            .secrets
            .get(name)
            .cloned()
            .ok_or_else(|| PhantomError::SecretNotFound(name.to_string()))?;
        phantom_core::audit::log("vault.retrieve_for_injection", Some(name));
        Ok(zeroize::Zeroizing::new(value))
    }

    fn delete(&self, name: &str) -> Result<()> {
        let locked = self.lock_view()?;
        let LoadedVault { mut data, before } = self.load(&locked)?;
        if data.secrets.remove(name).is_none() {
            return Err(PhantomError::SecretNotFound(name.to_string()));
        }
        // Remove associated metadata so the vault stays consistent.
        data.metadata.remove(name);
        data.validation_metadata.remove(name);
        self.save(&locked, &data, before.as_ref())?;
        phantom_core::audit::log("vault.delete", Some(name));
        Ok(())
    }

    fn compare_and_swap(
        &self,
        name: &str,
        expected: Option<&str>,
        replacement: Option<&str>,
    ) -> Result<bool> {
        let locked = self.lock_view()?;
        let LoadedVault { mut data, before } = self.load(&locked)?;
        let current = data.secrets.get(name).map(String::as_str);
        if current != expected {
            return Ok(false);
        }

        match replacement {
            Some(value) => {
                if current.is_none() {
                    data.metadata
                        .entry(name.to_string())
                        .or_insert_with(crate::metadata::SecretMetadata::new_now);
                }
                data.secrets.insert(name.to_string(), value.to_string());
            }
            None => {
                data.secrets.remove(name);
                data.metadata.remove(name);
                data.validation_metadata.remove(name);
            }
        }
        self.save(&locked, &data, before.as_ref())?;
        phantom_core::audit::log("vault.compare_and_swap", Some(name));
        Ok(true)
    }

    fn list(&self) -> Result<Vec<String>> {
        let locked = self.lock_view()?;
        let data = self.load(&locked)?.data;
        Ok(data.secrets.keys().cloned().collect())
    }

    fn backend_name(&self) -> &str {
        "encrypted-file"
    }

    fn get_metadata(&self, name: &str) -> phantom_core::error::Result<Option<SecretMetadata>> {
        let locked = self.lock_view()?;
        let data = self.load(&locked)?.data;
        Ok(data.metadata.get(name).cloned())
    }

    fn set_metadata(&self, name: &str, meta: SecretMetadata) -> phantom_core::error::Result<()> {
        let locked = self.lock_view()?;
        let LoadedVault { mut data, before } = self.load(&locked)?;
        // Only set metadata for secrets that actually exist in the vault.
        if !data.secrets.contains_key(name) {
            return Err(PhantomError::SecretNotFound(name.to_string()));
        }
        data.metadata.insert(name.to_string(), meta);
        self.save(&locked, &data, before.as_ref())
    }

    fn compare_and_swap_metadata_batch(&self, changes: &[MetadataCas]) -> Result<bool> {
        let locked = self.lock_view()?;
        let LoadedVault { mut data, before } = self.load(&locked)?;
        let mut seen = std::collections::BTreeSet::new();
        for change in changes {
            if !seen.insert(change.name.as_str()) {
                return Err(PhantomError::VaultError(
                    "metadata CAS batch contains a duplicate secret name".to_string(),
                ));
            }
            if !data.secrets.contains_key(&change.name) {
                return Err(PhantomError::SecretNotFound(change.name.clone()));
            }
            if data.metadata.get(&change.name) != change.expected.as_ref() {
                return Ok(false);
            }
        }
        for change in changes {
            match &change.replacement {
                Some(metadata) => {
                    data.metadata.insert(change.name.clone(), metadata.clone());
                }
                None => {
                    data.metadata.remove(&change.name);
                }
            }
        }
        if !changes.is_empty() {
            self.save(&locked, &data, before.as_ref())?;
        }
        Ok(true)
    }

    fn get_validation_metadata(
        &self,
        name: &str,
    ) -> phantom_core::error::Result<ValidationMetadata> {
        let locked = self.lock_view()?;
        let data = self.load(&locked)?.data;
        Ok(data
            .validation_metadata
            .get(name)
            .cloned()
            .unwrap_or_default())
    }

    fn get_validation_metadata_exact(&self, name: &str) -> Result<Option<ValidationMetadata>> {
        let locked = self.lock_view()?;
        let data = self.load(&locked)?.data;
        Ok(data.validation_metadata.get(name).cloned())
    }

    fn set_validation_metadata(
        &self,
        name: &str,
        meta: ValidationMetadata,
    ) -> phantom_core::error::Result<()> {
        let locked = self.lock_view()?;
        let LoadedVault { mut data, before } = self.load(&locked)?;
        // Only persist if the secret exists.
        if !data.secrets.contains_key(name) {
            return Err(PhantomError::SecretNotFound(name.to_string()));
        }
        data.validation_metadata.insert(name.to_string(), meta);
        self.save(&locked, &data, before.as_ref())
    }

    fn compare_and_swap_validation_metadata_batch(
        &self,
        changes: &[ValidationMetadataCas],
    ) -> Result<bool> {
        let locked = self.lock_view()?;
        let LoadedVault { mut data, before } = self.load(&locked)?;
        let mut seen = std::collections::BTreeSet::new();
        for change in changes {
            if !seen.insert(change.name.as_str()) {
                return Err(PhantomError::VaultError(
                    "validation metadata CAS batch contains a duplicate secret name".to_string(),
                ));
            }
            if !data.secrets.contains_key(&change.name) {
                return Err(PhantomError::SecretNotFound(change.name.clone()));
            }
            if data.validation_metadata.get(&change.name) != change.expected.as_ref() {
                return Ok(false);
            }
        }
        for change in changes {
            match &change.replacement {
                Some(metadata) => {
                    data.validation_metadata
                        .insert(change.name.clone(), metadata.clone());
                }
                None => {
                    data.validation_metadata.remove(&change.name);
                }
            }
        }
        if !changes.is_empty() {
            self.save(&locked, &data, before.as_ref())?;
        }
        Ok(true)
    }

    fn store_with_expiry(&self, name: &str, value: &str, days_ttl: u64) -> Result<()> {
        let locked = self.lock_view()?;
        let LoadedVault { mut data, before } = self.load(&locked)?;
        data.secrets.insert(name.to_string(), value.to_string());
        data.metadata
            .insert(name.to_string(), SecretMetadata::with_expiry(days_ttl));
        self.save(&locked, &data, before.as_ref())?;
        phantom_core::audit::log("vault.store", Some(name));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn canonical_temp_root(dir: &TempDir) -> PathBuf {
        dir.path().canonicalize().unwrap()
    }

    fn test_vault() -> (FileVault, TempDir) {
        let dir = TempDir::new().unwrap();
        let vault = FileVault::new(
            &canonical_temp_root(&dir),
            "test-project",
            "test-passphrase".to_string(),
        )
        .unwrap();
        (vault, dir)
    }

    #[test]
    fn test_project_id_rejects_path_traversal_and_unsafe_components() {
        for project_id in [
            "../escape",
            "..\\escape",
            ".",
            "..",
            "nested/project",
            "nested\\project",
            "contains space",
            "café",
            "",
        ] {
            let dir = TempDir::new().unwrap();
            let result = FileVault::new(dir.path(), project_id, "passphrase".to_string());
            assert!(
                result.is_err(),
                "unsafe project ID accepted: {project_id:?}"
            );
            assert!(
                !dir.path().join("vaults").exists(),
                "validation must run before creating the vault directory"
            );
        }
    }

    #[test]
    fn test_project_id_accepts_portable_legacy_identifiers() {
        for project_id in ["0123456789abcdef", "test-project", "project_name-42"] {
            let dir = TempDir::new().unwrap();
            FileVault::new(
                &canonical_temp_root(&dir),
                project_id,
                "passphrase".to_string(),
            )
            .expect("portable project ID should be accepted");
        }
    }

    #[test]
    fn project_id_rejects_windows_device_basenames_on_every_platform() {
        for project_id in [
            "CON", "con", "PrN", "AUX", "nul", "COM1", "com9", "LPT1", "lPt9",
        ] {
            let dir = TempDir::new().unwrap();
            let result = FileVault::new(dir.path(), project_id, "passphrase".to_string());
            assert!(
                result.is_err(),
                "Windows device basename accepted: {project_id:?}"
            );
            assert!(!dir.path().join("vaults").exists());
        }
    }

    #[test]
    fn committed_effect_receipt_is_not_treated_as_no_effect() {
        let error = require_durable_effect(
            AnchoredEffect::CommittedButUncertain {
                value: (),
                error: std::io::Error::other("injected parent sync failure"),
            },
            "encrypted vault update",
        )
        .unwrap_err();

        let message = error.to_string();
        assert!(message.contains("committed"));
        assert!(message.contains("Do not assume the operation had no effect"));
    }

    #[cfg(unix)]
    #[test]
    fn constructor_accepts_explicit_symlinked_base_anchor() {
        use std::os::unix::fs::symlink;

        let directory = TempDir::new().unwrap();
        let root = canonical_temp_root(&directory);
        let target = root.join("owner-state");
        std::fs::create_dir(&target).unwrap();
        let redirected = root.join("redirected");
        symlink(&target, &redirected).unwrap();

        FileVault::new(&redirected, "test-project", "passphrase".into())
            .expect("configured base aliases are trusted anchors");
        assert!(target.join("vaults").is_dir());
    }

    #[cfg(unix)]
    #[test]
    fn constructor_rejects_symlinked_owned_vault_directory() {
        use std::os::unix::fs::symlink;

        let directory = TempDir::new().unwrap();
        let root = canonical_temp_root(&directory);
        let target = root.join("owner-state");
        std::fs::create_dir(&target).unwrap();
        symlink(&target, root.join("vaults")).unwrap();

        assert!(FileVault::new(&root, "test-project", "passphrase".into()).is_err());
        assert!(std::fs::read_dir(&target).unwrap().next().is_none());
    }

    #[cfg(unix)]
    #[test]
    fn legacy_vault_lock_symlink_is_rejected_without_mutating_target() {
        use std::os::unix::fs::{symlink, PermissionsExt};

        let (vault, _directory) = test_vault();
        let victim = vault.vault_path.with_extension("owner-state");
        std::fs::write(&victim, b"preserve").unwrap();
        std::fs::set_permissions(&victim, std::fs::Permissions::from_mode(0o640)).unwrap();
        std::fs::remove_file(vault.vault_path.with_extension("lock")).unwrap();
        symlink(&victim, vault.vault_path.with_extension("lock")).unwrap();

        assert!(vault.store("API_KEY", "secret").is_err());
        assert_eq!(std::fs::read(&victim).unwrap(), b"preserve");
        assert_eq!(
            std::fs::metadata(&victim).unwrap().permissions().mode() & 0o777,
            0o640
        );
    }

    #[cfg(unix)]
    #[test]
    fn stable_base_lock_symlink_is_rejected_without_mutating_target() {
        use std::os::unix::fs::{symlink, PermissionsExt};

        let (vault, directory) = test_vault();
        let root = canonical_temp_root(&directory);
        let stable_lock = root.join(&vault.names.stable_lock);
        let victim = root.join("owner-state");
        std::fs::write(&victim, b"preserve").unwrap();
        std::fs::set_permissions(&victim, std::fs::Permissions::from_mode(0o640)).unwrap();
        std::fs::remove_file(&stable_lock).unwrap();
        symlink(&victim, &stable_lock).unwrap();

        assert!(vault.store("API_KEY", "secret").is_err());
        assert_eq!(std::fs::read(&victim).unwrap(), b"preserve");
        assert_eq!(
            std::fs::metadata(&victim).unwrap().permissions().mode() & 0o777,
            0o640
        );
    }

    #[cfg(unix)]
    #[test]
    fn pinned_operation_ignores_vaults_swap_and_preserves_decoy() {
        let (vault, directory) = test_vault();
        let root = canonical_temp_root(&directory);
        let locked = vault.lock_view().unwrap();

        std::fs::rename(root.join("vaults"), root.join("vaults-original")).unwrap();
        std::fs::create_dir(root.join("vaults")).unwrap();
        let decoy = root.join("vaults/test-project.vault");
        std::fs::write(&decoy, b"decoy-owner-state").unwrap();

        let mut data = VaultData::default();
        data.secrets.insert("API_KEY".into(), "secret".into());
        vault.save(&locked, &data, None).unwrap();
        assert_eq!(
            vault
                .load(&locked)
                .unwrap()
                .data
                .secrets
                .get("API_KEY")
                .map(String::as_str),
            Some("secret")
        );
        assert_eq!(std::fs::read(&decoy).unwrap(), b"decoy-owner-state");
        assert!(root.join("vaults-original/test-project.vault").is_file());
    }

    #[cfg(unix)]
    #[test]
    fn stable_base_lock_serializes_old_and_new_vaults_views() {
        use std::sync::mpsc;
        use std::time::Duration;

        let (vault, directory) = test_vault();
        vault.store("ORIGINAL", "owner").unwrap();
        let root = canonical_temp_root(&directory);
        let original_before = std::fs::read(root.join("vaults/test-project.vault")).unwrap();
        let locked = vault.lock_view().unwrap();

        std::fs::rename(root.join("vaults"), root.join("vaults-original")).unwrap();
        std::fs::create_dir(root.join("vaults")).unwrap();

        let (started_tx, started_rx) = mpsc::channel();
        let (finished_tx, finished_rx) = mpsc::channel();
        let worker_root = root.clone();
        let worker = std::thread::spawn(move || {
            started_tx.send(()).unwrap();
            let current =
                FileVault::new(&worker_root, "test-project", "test-passphrase".into()).unwrap();
            current.store("CURRENT", "decoy-view").unwrap();
            finished_tx.send(()).unwrap();
        });

        started_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        assert!(
            finished_rx
                .recv_timeout(Duration::from_millis(150))
                .is_err(),
            "new subtree writer entered before the stable base lock was released"
        );
        assert!(!root.join("vaults/test-project.vault").exists());

        drop(locked);
        finished_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        worker.join().unwrap();

        assert_eq!(
            std::fs::read(root.join("vaults-original/test-project.vault")).unwrap(),
            original_before
        );
        let current = FileVault::new(&root, "test-project", "test-passphrase".into()).unwrap();
        assert_eq!(current.retrieve("CURRENT").unwrap().as_str(), "decoy-view");
        assert!(current.retrieve("ORIGINAL").is_err());
    }

    #[test]
    fn test_store_and_retrieve() {
        let (vault, _dir) = test_vault();
        vault.store("API_KEY", "sk-secret123").unwrap();
        assert_eq!(vault.retrieve("API_KEY").unwrap().as_str(), "sk-secret123");
    }

    #[test]
    fn test_retrieve_not_found() {
        let (vault, _dir) = test_vault();
        assert!(vault.retrieve("NONEXISTENT").is_err());
    }

    #[test]
    fn test_delete() {
        let (vault, _dir) = test_vault();
        vault.store("KEY", "value").unwrap();
        vault.delete("KEY").unwrap();
        assert!(vault.retrieve("KEY").is_err());
    }

    #[test]
    fn test_delete_not_found() {
        let (vault, _dir) = test_vault();
        assert!(vault.delete("NOPE").is_err());
    }

    #[test]
    fn test_list() {
        let (vault, _dir) = test_vault();
        vault.store("B", "2").unwrap();
        vault.store("A", "1").unwrap();
        let keys = vault.list().unwrap();
        assert_eq!(keys, vec!["A", "B"]);
    }

    #[test]
    fn test_exists() {
        let (vault, _dir) = test_vault();
        vault.store("KEY", "val").unwrap();
        assert!(vault.exists("KEY").unwrap());
        assert!(!vault.exists("OTHER").unwrap());
    }

    #[test]
    fn test_overwrite() {
        let (vault, _dir) = test_vault();
        vault.store("KEY", "v1").unwrap();
        vault.store("KEY", "v2").unwrap();
        assert_eq!(vault.retrieve("KEY").unwrap().as_str(), "v2");
    }

    #[test]
    fn compare_and_swap_is_atomic_and_preserves_metadata_on_replace() {
        let (vault, _dir) = test_vault();
        vault.store("KEY", "v1").unwrap();
        vault.set_rotation_policy("KEY", 14).unwrap();
        let metadata = vault.get_metadata("KEY").unwrap();

        assert!(!vault
            .compare_and_swap("KEY", Some("wrong"), Some("v2"))
            .unwrap());
        assert_eq!(vault.retrieve("KEY").unwrap().as_str(), "v1");
        assert!(vault
            .compare_and_swap("KEY", Some("v1"), Some("v2"))
            .unwrap());
        assert_eq!(vault.retrieve("KEY").unwrap().as_str(), "v2");
        assert_eq!(vault.get_metadata("KEY").unwrap(), metadata);
    }

    #[test]
    fn compare_and_swap_create_and_delete_keep_metadata_consistent() {
        let (vault, _dir) = test_vault();
        assert!(vault.compare_and_swap("KEY", None, Some("value")).unwrap());
        assert!(vault.get_metadata("KEY").unwrap().is_some());
        assert!(vault.compare_and_swap("KEY", Some("value"), None).unwrap());
        assert!(!vault.exists("KEY").unwrap());
        assert!(vault.get_metadata("KEY").unwrap().is_none());
    }

    #[test]
    fn metadata_batch_cas_is_all_or_nothing() {
        let (vault, _dir) = test_vault();
        vault.store("A", "one").unwrap();
        vault.store("B", "two").unwrap();
        let before_a = vault.get_metadata("A").unwrap();
        let before_b = vault.get_metadata("B").unwrap();
        let mut after_a = before_a.clone().unwrap();
        after_a.expires_at = Some(111);
        let mut after_b = before_b.clone().unwrap();
        after_b.expires_at = Some(222);
        let stale_b = SecretMetadata::default();

        assert!(!vault
            .compare_and_swap_metadata_batch(&[
                MetadataCas {
                    name: "A".into(),
                    expected: before_a.clone(),
                    replacement: Some(after_a.clone()),
                },
                MetadataCas {
                    name: "B".into(),
                    expected: Some(stale_b),
                    replacement: Some(after_b.clone()),
                },
            ])
            .unwrap());
        assert_eq!(vault.get_metadata("A").unwrap(), before_a);
        assert_eq!(vault.get_metadata("B").unwrap(), before_b);

        assert!(vault
            .compare_and_swap_metadata_batch(&[
                MetadataCas {
                    name: "A".into(),
                    expected: before_a,
                    replacement: Some(after_a.clone()),
                },
                MetadataCas {
                    name: "B".into(),
                    expected: before_b,
                    replacement: Some(after_b.clone()),
                },
            ])
            .unwrap());
        assert_eq!(vault.get_metadata("A").unwrap(), Some(after_a));
        assert_eq!(vault.get_metadata("B").unwrap(), Some(after_b));
    }

    #[test]
    fn validation_metadata_batch_rejects_stale_before_image() {
        let (vault, _dir) = test_vault();
        vault.store("A", "one").unwrap();
        vault.store("B", "two").unwrap();
        let valid = ValidationMetadata::mark_valid("test");
        vault.set_validation_metadata("B", valid.clone()).unwrap();
        let proposed = ValidationMetadata::mark_invalid("test", "rejected");
        assert!(!vault
            .compare_and_swap_validation_metadata_batch(&[
                ValidationMetadataCas {
                    name: "A".into(),
                    expected: None,
                    replacement: Some(proposed.clone()),
                },
                ValidationMetadataCas {
                    name: "B".into(),
                    expected: None,
                    replacement: Some(proposed),
                },
            ])
            .unwrap());
        assert_eq!(vault.get_validation_metadata_exact("A").unwrap(), None);
        assert_eq!(
            vault.get_validation_metadata_exact("B").unwrap(),
            Some(valid)
        );
    }

    #[test]
    fn test_encrypted_file_does_not_contain_plaintext() {
        let (vault, _dir) = test_vault();
        let secret = "sk-super-secret-api-key-12345";
        vault.store("MY_KEY", secret).unwrap();

        // Read raw vault file bytes
        let raw = std::fs::read(&vault.vault_path).unwrap();
        let raw_str = String::from_utf8_lossy(&raw);

        // The plaintext secret should NOT appear in the encrypted file
        assert!(
            !raw_str.contains(secret),
            "Encrypted vault file contains plaintext secret!"
        );
        // The key name should also not appear
        assert!(
            !raw_str.contains("MY_KEY"),
            "Encrypted vault file contains plaintext key name!"
        );
    }

    #[test]
    fn test_wrong_passphrase_fails() {
        let dir = TempDir::new().unwrap();
        let root = canonical_temp_root(&dir);

        // Create vault with one passphrase
        let vault1 =
            FileVault::new(&root, "test-project", "correct-passphrase".to_string()).unwrap();
        vault1.store("KEY", "secret").unwrap();

        // Try to read with wrong passphrase
        let vault2 = FileVault::new(&root, "test-project", "wrong-passphrase".to_string()).unwrap();
        let result = vault2.retrieve("KEY");
        assert!(result.is_err());
    }

    #[test]
    fn test_migrate_from_json() {
        let dir = TempDir::new().unwrap();
        let root = canonical_temp_root(&dir);
        let vault_dir = root.join("vaults");
        std::fs::create_dir_all(&vault_dir).unwrap();

        // Create a legacy unencrypted JSON vault
        let legacy_data = r#"{"secrets":{"OLD_KEY":"old-secret-value"}}"#;
        std::fs::write(vault_dir.join("test-project.json"), legacy_data).unwrap();

        // Create new encrypted vault — should auto-migrate
        let vault = FileVault::new(&root, "test-project", "my-passphrase".to_string()).unwrap();

        // Old secret should be accessible through encrypted vault
        assert_eq!(
            vault.retrieve("OLD_KEY").unwrap().as_str(),
            "old-secret-value"
        );

        // Legacy JSON file should be deleted
        assert!(!vault_dir.join("test-project.json").exists());

        // New encrypted file should exist
        assert!(vault_dir.join("test-project.vault").exists());
    }

    #[test]
    fn equal_encrypted_and_legacy_vaults_remove_plaintext_duplicate() {
        let dir = TempDir::new().unwrap();
        let root = canonical_temp_root(&dir);
        let vault = FileVault::new(&root, "test-project", "my-passphrase".into()).unwrap();
        vault.store("OLD_KEY", "old-secret-value").unwrap();
        let locked = vault.lock_view().unwrap();
        let data = vault.load(&locked).unwrap().data;
        drop(locked);

        let legacy_path = root.join("vaults/test-project.json");
        std::fs::write(&legacy_path, serde_json::to_vec(&data).unwrap()).unwrap();
        let reopened = FileVault::new(&root, "test-project", "my-passphrase".into()).unwrap();

        assert_eq!(
            reopened.retrieve("OLD_KEY").unwrap().as_str(),
            "old-secret-value"
        );
        assert!(!legacy_path.exists());
    }

    #[test]
    fn divergent_encrypted_and_legacy_vaults_preserve_both_without_effect() {
        let dir = TempDir::new().unwrap();
        let root = canonical_temp_root(&dir);
        let vault = FileVault::new(&root, "test-project", "my-passphrase".into()).unwrap();
        vault.store("KEY", "encrypted-owner").unwrap();
        let encrypted_path = root.join("vaults/test-project.vault");
        let encrypted_before = std::fs::read(&encrypted_path).unwrap();
        let legacy_path = root.join("vaults/test-project.json");
        let legacy_before = br#"{"secrets":{"KEY":"legacy-owner"}}"#;
        std::fs::write(&legacy_path, legacy_before).unwrap();

        let error = FileVault::new(&root, "test-project", "my-passphrase".into())
            .err()
            .expect("divergent coexistence must fail closed");

        assert!(error.to_string().contains("divergent state"));
        assert_eq!(std::fs::read(&encrypted_path).unwrap(), encrypted_before);
        assert_eq!(std::fs::read(&legacy_path).unwrap(), legacy_before);
    }

    // ── Metadata / TTL tests ─────────────────────────────────────────

    #[test]
    fn test_store_seeds_created_at() {
        let (vault, _dir) = test_vault();
        vault.store("MY_KEY", "value").unwrap();
        let meta = vault.get_metadata("MY_KEY").unwrap();
        assert!(meta.is_some(), "metadata should be seeded on first store");
        let meta = meta.unwrap();
        assert!(meta.created_at.is_some(), "created_at must be set");
    }

    #[test]
    fn test_store_preserves_existing_metadata() {
        let (vault, _dir) = test_vault();
        vault.store("MY_KEY", "v1").unwrap();
        // Set TTL metadata
        vault.set_rotation_policy("MY_KEY", 30).unwrap();
        let meta_before = vault.get_metadata("MY_KEY").unwrap().unwrap();
        // Overwrite value — metadata must be preserved
        vault.store("MY_KEY", "v2").unwrap();
        let meta_after = vault.get_metadata("MY_KEY").unwrap().unwrap();
        assert_eq!(
            meta_before.created_at, meta_after.created_at,
            "created_at must survive overwrite"
        );
        assert!(
            meta_after.rotation_policy.is_some(),
            "rotation_policy must survive overwrite"
        );
    }

    #[test]
    fn test_delete_removes_metadata() {
        let (vault, _dir) = test_vault();
        vault.store("MY_KEY", "value").unwrap();
        vault.set_rotation_policy("MY_KEY", 7).unwrap();
        assert!(vault.get_metadata("MY_KEY").unwrap().is_some());
        vault.delete("MY_KEY").unwrap();
        // After delete the key is gone; get_metadata on a missing key returns Ok(None)
        let locked = vault.lock_view().unwrap();
        let data_after = vault.load(&locked).unwrap().data;
        assert!(!data_after.metadata.contains_key("MY_KEY"));
    }

    #[test]
    fn test_store_with_expiry() {
        let (vault, _dir) = test_vault();
        vault.store_with_expiry("EXP_KEY", "secret", 7).unwrap();
        let meta = vault.get_metadata("EXP_KEY").unwrap().unwrap();
        assert!(meta.expires_at.is_some());
        assert!(!meta.is_expired(), "7-day TTL should not be expired yet");
        let days = meta.days_remaining().unwrap();
        assert!((6..=7).contains(&days), "days_remaining={days}");
    }

    #[test]
    fn test_set_rotation_policy() {
        let (vault, _dir) = test_vault();
        vault.store("KEY", "val").unwrap();
        vault.set_rotation_policy("KEY", 14).unwrap();
        let meta = vault.get_metadata("KEY").unwrap().unwrap();
        assert!(meta.expires_at.is_some());
        assert_eq!(
            meta.rotated_at, None,
            "configuring local expiry policy is not a provider rotation"
        );
        let policy = meta.rotation_policy.unwrap();
        assert_eq!(policy.days_ttl, 14);
    }

    #[test]
    fn test_set_metadata_rejects_nonexistent_key() {
        let (vault, _dir) = test_vault();
        let result = vault.set_metadata("GHOST", crate::metadata::SecretMetadata::new_now());
        assert!(result.is_err(), "set_metadata on missing secret must fail");
    }

    #[test]
    fn test_list_with_metadata() {
        let (vault, _dir) = test_vault();
        vault.store_with_expiry("A", "v1", 7).unwrap();
        vault.store("B", "v2").unwrap();
        let entries = vault.list_with_metadata().unwrap();
        assert_eq!(entries.len(), 2);
        let a_entry = entries.iter().find(|(n, _)| n == "A").unwrap();
        assert!(a_entry.1.is_some(), "A should have metadata");
        let a_meta = a_entry.1.as_ref().unwrap();
        assert!(a_meta.expires_at.is_some());
    }

    #[test]
    fn runtime_injection_rejects_read_only_and_rotation_restores_access() {
        let (vault, _dir) = test_vault();
        vault.store("API_KEY", "provider-secret").unwrap();
        let mut metadata = vault.get_metadata("API_KEY").unwrap().unwrap();
        metadata.vault_mode = crate::metadata::VaultMode::ReadOnly;
        vault.set_metadata("API_KEY", metadata.clone()).unwrap();

        assert_eq!(
            vault.retrieve("API_KEY").unwrap().as_str(),
            "provider-secret",
            "read-only lifecycle mode must preserve explicit inspection access"
        );
        let error = vault.retrieve_for_injection("API_KEY").unwrap_err();
        assert!(error.to_string().contains("read-only"));

        metadata.record_rotation();
        vault.set_metadata("API_KEY", metadata).unwrap();
        assert_eq!(
            vault.retrieve_for_injection("API_KEY").unwrap().as_str(),
            "provider-secret"
        );
    }

    #[test]
    fn test_ttl_serialization_survives_vault_round_trip() {
        let (vault, _dir) = test_vault();
        vault.store_with_expiry("TOKEN", "sk-test", 7).unwrap();
        // Force a full serialize/deserialize by reading back from disk
        let meta = vault.get_metadata("TOKEN").unwrap().unwrap();
        let json = serde_json::to_string(&meta).unwrap();
        let back: crate::metadata::SecretMetadata = serde_json::from_str(&json).unwrap();
        assert_eq!(meta.expires_at, back.expires_at);
        assert_eq!(
            meta.rotation_policy.unwrap().days_ttl,
            back.rotation_policy.unwrap().days_ttl
        );
    }

    /// Stress test: 10 threads each writing a unique key concurrently.
    /// Without the exclusive file lock this reliably loses writes.
    #[test]
    fn test_concurrent_stores_no_clobber() {
        use std::sync::Arc;

        let dir = TempDir::new().unwrap();
        let root = canonical_temp_root(&dir);
        let vault =
            Arc::new(FileVault::new(&root, "stress-project", "stress-pass".to_string()).unwrap());

        const N: usize = 10;
        let handles: Vec<_> = (0..N)
            .map(|i| {
                let v = Arc::clone(&vault);
                std::thread::spawn(move || {
                    v.store(&format!("KEY_{i}"), &format!("value_{i}")).unwrap();
                })
            })
            .collect();

        for h in handles {
            h.join().expect("thread panicked");
        }

        // Every key must be present and hold the correct value.
        let mut keys = vault.list().unwrap();
        keys.sort();
        assert_eq!(
            keys.len(),
            N,
            "expected {N} keys, got {}: {keys:?}",
            keys.len()
        );

        for i in 0..N {
            let expected = format!("value_{i}");
            let got = vault.retrieve(&format!("KEY_{i}")).unwrap();
            assert_eq!(got.as_str(), expected, "KEY_{i} has wrong value");
        }
    }
}
