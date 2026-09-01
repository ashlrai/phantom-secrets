use crate::crypto;
use crate::metadata::SecretMetadata;
use crate::traits::{MetadataCas, ValidationMetadataCas, VaultBackend};
use fs2::FileExt;
use phantom_core::error::{PhantomError, Result};
use phantom_core::validator::ValidationMetadata;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// ChaCha20-Poly1305 encrypted file vault backend.
/// Uses shared crypto module for encryption/decryption.
pub struct FileVault {
    vault_path: PathBuf,
    passphrase: String,
}

#[derive(Debug, Serialize, Deserialize, Default)]
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
    /// Create a new encrypted file vault.
    pub fn new(base_dir: &Path, project_id: &str, passphrase: String) -> Result<Self> {
        validate_project_id(project_id)?;
        let vault_dir = base_dir.join("vaults");
        std::fs::create_dir_all(&vault_dir)?;

        let vault = Self {
            vault_path: vault_dir.join(format!("{project_id}.vault")),
            passphrase,
        };

        // Auto-migrate from old unencrypted .json format
        let legacy_path = vault_dir.join(format!("{project_id}.json"));
        if legacy_path.exists() && !vault.vault_path.exists() {
            vault.migrate_from_json(&legacy_path)?;
        }

        Ok(vault)
    }

    /// Migrate from old unencrypted JSON vault to encrypted format.
    fn migrate_from_json(&self, json_path: &Path) -> Result<()> {
        let _lock = self.lock_file()?;

        let content = std::fs::read_to_string(json_path)?;
        let data: VaultData = serde_json::from_str(&content)
            .map_err(|e| PhantomError::VaultError(format!("Corrupt legacy vault: {e}")))?;

        // Save encrypted
        self.save(&data)?;

        // Remove old unencrypted file
        let _ = std::fs::remove_file(json_path);

        eprintln!(
            "phantom: migrated vault to encrypted format ({})",
            self.vault_path.display()
        );

        Ok(())
    }

    fn load(&self) -> Result<VaultData> {
        let Some(encrypted) = phantom_core::fs::read_regular_file(&self.vault_path)? else {
            return Ok(VaultData::default());
        };

        // Warn if file permissions are too open
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Ok(metadata) = std::fs::metadata(&self.vault_path) {
                let mode = metadata.permissions().mode() & 0o777;
                if mode != 0o600 {
                    eprintln!(
                        "phantom: WARNING — vault file has permissions {:o} (expected 600): {}",
                        mode,
                        self.vault_path.display()
                    );
                }
            }
        }

        // Wrap the decrypted JSON in Zeroizing so the heap buffer is overwritten
        // with zeros when it drops — whether that's on success or on an early
        // return from the serde_json error path below.
        let plaintext = zeroize::Zeroizing::new(crypto::decrypt(&encrypted, &self.passphrase)?);

        serde_json::from_slice::<VaultData>(&plaintext)
            .map_err(|e| PhantomError::VaultError(format!("Corrupt vault data: {e}")))
    }

    /// Open (creating if needed) the sidecar lock file and take an exclusive
    /// advisory lock on it.  The returned `File` MUST be kept alive for the
    /// duration of the critical section — dropping it releases the lock.
    fn lock_file(&self) -> Result<std::fs::File> {
        let lock_path = self.vault_path.with_extension("lock");
        let file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(&lock_path)
            .map_err(|e| PhantomError::VaultError(format!("Cannot open lock file: {e}")))?;
        file.lock_exclusive()
            .map_err(|e| PhantomError::VaultError(format!("Cannot acquire vault lock: {e}")))?;
        Ok(file)
    }

    fn save(&self, data: &VaultData) -> Result<()> {
        // The plaintext JSON holds every secret in the vault. Wrap it in
        // Zeroizing so the heap allocation is scrubbed on drop — including on
        // the error paths below. String's own Drop does not zero memory.
        let plaintext = zeroize::Zeroizing::new(
            serde_json::to_string_pretty(data)
                .map_err(|e| PhantomError::VaultError(format!("Serialize error: {e}")))?,
        );

        let encrypted = crypto::encrypt(plaintext.as_bytes(), &self.passphrase)?;

        phantom_core::fs::ensure_real_parent(&self.vault_path)?;
        phantom_core::fs::atomic_write(&self.vault_path, &encrypted)?;

        // Set restrictive permissions (owner read/write only)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&self.vault_path, std::fs::Permissions::from_mode(0o600))?;
        }

        Ok(())
    }
}

pub(crate) fn encrypted_vault_exists(base_dir: &Path, project_id: &str) -> Result<bool> {
    validate_project_id(project_id)?;
    Ok(phantom_core::fs::read_regular_file(
        &base_dir.join("vaults").join(format!("{project_id}.vault")),
    )?
    .is_some())
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

    if valid {
        Ok(())
    } else {
        Err(PhantomError::VaultError(
            "Invalid project ID for encrypted file vault".to_string(),
        ))
    }
}

impl VaultBackend for FileVault {
    fn store(&self, name: &str, value: &str) -> Result<()> {
        let _lock = self.lock_file()?;
        let mut data = self.load()?;
        // Preserve existing metadata on overwrite; seed created_at for new entries.
        if !data.secrets.contains_key(name) {
            data.metadata
                .entry(name.to_string())
                .or_insert_with(crate::metadata::SecretMetadata::new_now);
        }
        data.secrets.insert(name.to_string(), value.to_string());
        self.save(&data)?;
        phantom_core::audit::log("vault.store", Some(name));
        Ok(())
    }

    fn retrieve(&self, name: &str) -> Result<zeroize::Zeroizing<String>> {
        let data = self.load()?;
        let value = data
            .secrets
            .get(name)
            .cloned()
            .ok_or_else(|| PhantomError::SecretNotFound(name.to_string()))?;
        phantom_core::audit::log("vault.retrieve", Some(name));
        Ok(zeroize::Zeroizing::new(value))
    }

    fn retrieve_for_injection(&self, name: &str) -> Result<zeroize::Zeroizing<String>> {
        let _lock = self.lock_file()?;
        let data = self.load()?;
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
        let _lock = self.lock_file()?;
        let mut data = self.load()?;
        if data.secrets.remove(name).is_none() {
            return Err(PhantomError::SecretNotFound(name.to_string()));
        }
        // Remove associated metadata so the vault stays consistent.
        data.metadata.remove(name);
        data.validation_metadata.remove(name);
        self.save(&data)?;
        phantom_core::audit::log("vault.delete", Some(name));
        Ok(())
    }

    fn compare_and_swap(
        &self,
        name: &str,
        expected: Option<&str>,
        replacement: Option<&str>,
    ) -> Result<bool> {
        let _lock = self.lock_file()?;
        let mut data = self.load()?;
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
        self.save(&data)?;
        phantom_core::audit::log("vault.compare_and_swap", Some(name));
        Ok(true)
    }

    fn list(&self) -> Result<Vec<String>> {
        let data = self.load()?;
        Ok(data.secrets.keys().cloned().collect())
    }

    fn backend_name(&self) -> &str {
        "encrypted-file"
    }

    fn get_metadata(&self, name: &str) -> phantom_core::error::Result<Option<SecretMetadata>> {
        let data = self.load()?;
        Ok(data.metadata.get(name).cloned())
    }

    fn set_metadata(&self, name: &str, meta: SecretMetadata) -> phantom_core::error::Result<()> {
        let _lock = self.lock_file()?;
        let mut data = self.load()?;
        // Only set metadata for secrets that actually exist in the vault.
        if !data.secrets.contains_key(name) {
            return Err(PhantomError::SecretNotFound(name.to_string()));
        }
        data.metadata.insert(name.to_string(), meta);
        self.save(&data)
    }

    fn compare_and_swap_metadata_batch(&self, changes: &[MetadataCas]) -> Result<bool> {
        let _lock = self.lock_file()?;
        let mut data = self.load()?;
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
            self.save(&data)?;
        }
        Ok(true)
    }

    fn get_validation_metadata(
        &self,
        name: &str,
    ) -> phantom_core::error::Result<ValidationMetadata> {
        let data = self.load()?;
        Ok(data
            .validation_metadata
            .get(name)
            .cloned()
            .unwrap_or_default())
    }

    fn get_validation_metadata_exact(&self, name: &str) -> Result<Option<ValidationMetadata>> {
        let data = self.load()?;
        Ok(data.validation_metadata.get(name).cloned())
    }

    fn set_validation_metadata(
        &self,
        name: &str,
        meta: ValidationMetadata,
    ) -> phantom_core::error::Result<()> {
        let _lock = self.lock_file()?;
        let mut data = self.load()?;
        // Only persist if the secret exists.
        if !data.secrets.contains_key(name) {
            return Err(PhantomError::SecretNotFound(name.to_string()));
        }
        data.validation_metadata.insert(name.to_string(), meta);
        self.save(&data)
    }

    fn compare_and_swap_validation_metadata_batch(
        &self,
        changes: &[ValidationMetadataCas],
    ) -> Result<bool> {
        let _lock = self.lock_file()?;
        let mut data = self.load()?;
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
            self.save(&data)?;
        }
        Ok(true)
    }

    fn store_with_expiry(&self, name: &str, value: &str, days_ttl: u64) -> Result<()> {
        let _lock = self.lock_file()?;
        let mut data = self.load()?;
        data.secrets.insert(name.to_string(), value.to_string());
        data.metadata
            .insert(name.to_string(), SecretMetadata::with_expiry(days_ttl));
        self.save(&data)?;
        phantom_core::audit::log("vault.store", Some(name));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn test_vault() -> (FileVault, TempDir) {
        let dir = TempDir::new().unwrap();
        let vault =
            FileVault::new(dir.path(), "test-project", "test-passphrase".to_string()).unwrap();
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
            FileVault::new(dir.path(), project_id, "passphrase".to_string())
                .expect("portable project ID should be accepted");
        }
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

        // Create vault with one passphrase
        let vault1 =
            FileVault::new(dir.path(), "test-project", "correct-passphrase".to_string()).unwrap();
        vault1.store("KEY", "secret").unwrap();

        // Try to read with wrong passphrase
        let vault2 =
            FileVault::new(dir.path(), "test-project", "wrong-passphrase".to_string()).unwrap();
        let result = vault2.retrieve("KEY");
        assert!(result.is_err());
    }

    #[test]
    fn test_migrate_from_json() {
        let dir = TempDir::new().unwrap();
        let vault_dir = dir.path().join("vaults");
        std::fs::create_dir_all(&vault_dir).unwrap();

        // Create a legacy unencrypted JSON vault
        let legacy_data = r#"{"secrets":{"OLD_KEY":"old-secret-value"}}"#;
        std::fs::write(vault_dir.join("test-project.json"), legacy_data).unwrap();

        // Create new encrypted vault — should auto-migrate
        let vault =
            FileVault::new(dir.path(), "test-project", "my-passphrase".to_string()).unwrap();

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
        let data_after = vault.load().unwrap();
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
        let vault = Arc::new(
            FileVault::new(dir.path(), "stress-project", "stress-pass".to_string()).unwrap(),
        );

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
