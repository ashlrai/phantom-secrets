use crate::crypto;
use crate::traits::VaultBackend;
use fs2::FileExt;
use phantom_core::error::{PhantomError, Result};
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
}

impl FileVault {
    /// Create a new encrypted file vault.
    pub fn new(base_dir: &Path, project_id: &str, passphrase: String) -> Result<Self> {
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
        if !self.vault_path.exists() {
            return Ok(VaultData::default());
        }

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

        let encrypted = std::fs::read(&self.vault_path)?;
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

        // Write atomically via temp file
        let tmp_path = self.vault_path.with_extension("tmp");
        std::fs::write(&tmp_path, &encrypted)?;
        std::fs::rename(&tmp_path, &self.vault_path)?;

        // Set restrictive permissions (owner read/write only)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&self.vault_path, std::fs::Permissions::from_mode(0o600))?;
        }

        Ok(())
    }
}

impl VaultBackend for FileVault {
    fn store(&self, name: &str, value: &str) -> Result<()> {
        let _lock = self.lock_file()?;
        let mut data = self.load()?;
        data.secrets.insert(name.to_string(), value.to_string());
        self.save(&data)?;
        Ok(())
    }

    fn retrieve(&self, name: &str) -> Result<zeroize::Zeroizing<String>> {
        let data = self.load()?;
        data.secrets
            .get(name)
            .cloned()
            .map(zeroize::Zeroizing::new)
            .ok_or_else(|| PhantomError::SecretNotFound(name.to_string()))
    }

    fn delete(&self, name: &str) -> Result<()> {
        let _lock = self.lock_file()?;
        let mut data = self.load()?;
        if data.secrets.remove(name).is_none() {
            return Err(PhantomError::SecretNotFound(name.to_string()));
        }
        self.save(&data)?;
        Ok(())
    }

    fn list(&self) -> Result<Vec<String>> {
        let data = self.load()?;
        Ok(data.secrets.keys().cloned().collect())
    }

    fn backend_name(&self) -> &str {
        "encrypted-file"
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
        assert_eq!(keys.len(), N, "expected {N} keys, got {}: {keys:?}", keys.len());

        for i in 0..N {
            let expected = format!("value_{i}");
            let got = vault.retrieve(&format!("KEY_{i}")).unwrap();
            assert_eq!(got.as_str(), expected, "KEY_{i} has wrong value");
        }
    }
}
