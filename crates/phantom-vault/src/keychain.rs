use crate::traits::VaultBackend;
use phantom_core::error::{PhantomError, Result};
use sha2::{Digest, Sha256};

const SERVICE_PREFIX: &str = "phantom-secrets";

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
}

impl VaultBackend for KeychainVault {
    fn store(&self, name: &str, value: &str) -> Result<()> {
        let entry = self.entry_for(name)?;
        entry
            .set_password(value)
            .map_err(|e| PhantomError::VaultError(format!("Failed to store secret: {e}")))?;

        // F13 migration: once the hashed entry is written, best-effort delete
        // any pre-F13 plaintext entry left over from an older phantom version.
        self.delete_legacy(name);

        // Update index
        let mut index = self.load_index()?;
        if !index.contains(&name.to_string()) {
            index.push(name.to_string());
            index.sort();
            self.save_index(&index)?;
        }
        Ok(())
    }

    fn retrieve(&self, name: &str) -> Result<zeroize::Zeroizing<String>> {
        let entry = self.entry_for(name)?;
        match entry.get_password() {
            Ok(value) => Ok(zeroize::Zeroizing::new(value)),
            Err(keyring::Error::NoEntry) => {
                // F13 migration: older phantom versions stored entries under
                // the plaintext name. If we find one, return its value and
                // silently re-store at the hashed location so future reads
                // hit the new path.
                if let Some(legacy) = self.legacy_entry_for(name) {
                    match legacy.get_password() {
                        Ok(value) => {
                            if let Ok(new_entry) = self.entry_for(name) {
                                let _ = new_entry.set_password(&value);
                            }
                            let _ = legacy.delete_credential();
                            Ok(zeroize::Zeroizing::new(value))
                        }
                        Err(keyring::Error::NoEntry) => {
                            Err(PhantomError::SecretNotFound(name.to_string()))
                        }
                        Err(e) => Err(PhantomError::VaultError(format!(
                            "Failed to retrieve secret: {e}"
                        ))),
                    }
                } else {
                    Err(PhantomError::SecretNotFound(name.to_string()))
                }
            }
            Err(e) => Err(PhantomError::VaultError(format!(
                "Failed to retrieve secret: {e}"
            ))),
        }
    }

    fn delete(&self, name: &str) -> Result<()> {
        let entry = self.entry_for(name)?;
        let new_result = entry.delete_credential();

        // Always best-effort delete the legacy entry regardless of whether
        // the new-style delete succeeded — the two are independent and
        // leaving a legacy copy behind defeats F13.
        self.delete_legacy(name);

        match new_result {
            Ok(()) => {}
            Err(keyring::Error::NoEntry) => {
                // If neither form existed, surface SecretNotFound. If the
                // legacy form existed and we deleted it, that's also a
                // successful delete.
                //
                // We can't easily distinguish the two here without another
                // lookup, so fall through and rebuild the index — if the
                // name isn't in the index either, callers get the not-found
                // signal from the next `list()`.
            }
            Err(e) => {
                return Err(PhantomError::VaultError(format!(
                    "Failed to delete secret: {e}"
                )));
            }
        }

        // Update index
        let mut index = self.load_index()?;
        let was_in_index = index.contains(&name.to_string());
        index.retain(|n| n != name);
        if was_in_index {
            self.save_index(&index)?;
            Ok(())
        } else if matches!(new_result, Err(keyring::Error::NoEntry)) {
            Err(PhantomError::SecretNotFound(name.to_string()))
        } else {
            self.save_index(&index)?;
            Ok(())
        }
    }

    fn list(&self) -> Result<Vec<String>> {
        self.load_index()
    }

    fn backend_name(&self) -> &str {
        "os-keychain"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
