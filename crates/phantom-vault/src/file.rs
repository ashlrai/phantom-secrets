use crate::traits::VaultBackend;
use argon2::Argon2;
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use phantom_core::error::{PhantomError, Result};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use zeroize::Zeroize;

/// ChaCha20-Poly1305 encrypted file vault backend.
/// Used when OS keychain is not available (Docker, CI, etc.).
///
/// Encryption scheme:
/// - Key derivation: Argon2id(passphrase, salt) → 256-bit key
/// - Encryption: ChaCha20-Poly1305(key, nonce, plaintext)
/// - File format: salt (32 bytes) || nonce (12 bytes) || ciphertext
pub struct FileVault {
    vault_path: PathBuf,
    passphrase: String,
}

const SALT_LEN: usize = 32;
const NONCE_LEN: usize = 12;
const KEY_LEN: usize = 32;

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

    fn derive_key(&self, salt: &[u8]) -> Result<[u8; KEY_LEN]> {
        let mut key = [0u8; KEY_LEN];
        Argon2::default()
            .hash_password_into(self.passphrase.as_bytes(), salt, &mut key)
            .map_err(|e| PhantomError::VaultError(format!("Key derivation failed: {e}")))?;
        Ok(key)
    }

    fn load(&self) -> Result<VaultData> {
        if !self.vault_path.exists() {
            return Ok(VaultData::default());
        }

        let encrypted = std::fs::read(&self.vault_path)?;

        if encrypted.len() < SALT_LEN + NONCE_LEN + 1 {
            return Err(PhantomError::VaultError(
                "Vault file too small — may be corrupt".to_string(),
            ));
        }

        // Parse: salt || nonce || ciphertext
        let salt = &encrypted[..SALT_LEN];
        let nonce_bytes = &encrypted[SALT_LEN..SALT_LEN + NONCE_LEN];
        let ciphertext = &encrypted[SALT_LEN + NONCE_LEN..];

        // Derive key from passphrase + salt
        let mut key = self.derive_key(salt)?;
        let cipher = ChaCha20Poly1305::new_from_slice(&key)
            .map_err(|e| PhantomError::VaultError(format!("Cipher init failed: {e}")))?;
        key.zeroize();

        let nonce = Nonce::from_slice(nonce_bytes);

        // Decrypt
        let plaintext = cipher.decrypt(nonce, ciphertext).map_err(|_| {
            PhantomError::VaultError(
                "Decryption failed — wrong passphrase or corrupt vault file".to_string(),
            )
        })?;

        // Parse JSON
        serde_json::from_slice(&plaintext)
            .map_err(|e| PhantomError::VaultError(format!("Corrupt vault data: {e}")))
    }

    fn save(&self, data: &VaultData) -> Result<()> {
        let plaintext = serde_json::to_string_pretty(data)
            .map_err(|e| PhantomError::VaultError(format!("Serialize error: {e}")))?;

        // Generate random salt and nonce
        let mut salt = [0u8; SALT_LEN];
        let mut nonce_bytes = [0u8; NONCE_LEN];
        rand::thread_rng().fill_bytes(&mut salt);
        rand::thread_rng().fill_bytes(&mut nonce_bytes);

        // Derive key
        let mut key = self.derive_key(&salt)?;
        let cipher = ChaCha20Poly1305::new_from_slice(&key)
            .map_err(|e| PhantomError::VaultError(format!("Cipher init failed: {e}")))?;
        key.zeroize();

        let nonce = Nonce::from_slice(&nonce_bytes);

        // Encrypt
        let ciphertext = cipher
            .encrypt(nonce, plaintext.as_bytes())
            .map_err(|e| PhantomError::VaultError(format!("Encryption failed: {e}")))?;

        // Write: salt || nonce || ciphertext
        let mut output = Vec::with_capacity(SALT_LEN + NONCE_LEN + ciphertext.len());
        output.extend_from_slice(&salt);
        output.extend_from_slice(&nonce_bytes);
        output.extend_from_slice(&ciphertext);

        // Write atomically via temp file
        let tmp_path = self.vault_path.with_extension("tmp");
        std::fs::write(&tmp_path, &output)?;
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
        let mut data = self.load()?;
        data.secrets.insert(name.to_string(), value.to_string());
        self.save(&data)?;
        Ok(())
    }

    fn retrieve(&self, name: &str) -> Result<String> {
        let data = self.load()?;
        data.secrets
            .get(name)
            .cloned()
            .ok_or_else(|| PhantomError::SecretNotFound(name.to_string()))
    }

    fn delete(&self, name: &str) -> Result<()> {
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
        assert_eq!(vault.retrieve("API_KEY").unwrap(), "sk-secret123");
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
        assert_eq!(vault.retrieve("KEY").unwrap(), "v2");
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
        assert_eq!(vault.retrieve("OLD_KEY").unwrap(), "old-secret-value");

        // Legacy JSON file should be deleted
        assert!(!vault_dir.join("test-project.json").exists());

        // New encrypted file should exist
        assert!(vault_dir.join("test-project.vault").exists());
    }
}
