use crate::traits::VaultBackend;
use phantom_core::error::{PhantomError, Result};

const SERVICE_PREFIX: &str = "phantom-secrets";

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

    fn entry_key(&self, name: &str) -> String {
        format!("{SERVICE_PREFIX}:{}:{}", self.project_id, name)
    }

    fn entry_for(&self, name: &str) -> Result<keyring::Entry> {
        keyring::Entry::new(&self.entry_key(name), name)
            .map_err(|e| PhantomError::VaultError(format!("Keychain error: {e}")))
    }

    /// Load the index of stored secret names.
    fn load_index(&self) -> Result<Vec<String>> {
        let entry = keyring::Entry::new(SERVICE_PREFIX, &self.index_key)
            .map_err(|e| PhantomError::VaultError(format!("Keychain error: {e}")))?;

        match entry.get_password() {
            Ok(data) => Ok(serde_json::from_str(&data).unwrap_or_default()),
            Err(keyring::Error::NoEntry) => Ok(Vec::new()),
            Err(e) => Err(PhantomError::VaultError(format!(
                "Failed to read index: {e}"
            ))),
        }
    }

    /// Save the index of stored secret names.
    fn save_index(&self, names: &[String]) -> Result<()> {
        let entry = keyring::Entry::new(SERVICE_PREFIX, &self.index_key)
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

        // Update index
        let mut index = self.load_index()?;
        if !index.contains(&name.to_string()) {
            index.push(name.to_string());
            index.sort();
            self.save_index(&index)?;
        }
        Ok(())
    }

    fn retrieve(&self, name: &str) -> Result<String> {
        let entry = self.entry_for(name)?;
        entry.get_password().map_err(|e| match e {
            keyring::Error::NoEntry => PhantomError::SecretNotFound(name.to_string()),
            _ => PhantomError::VaultError(format!("Failed to retrieve secret: {e}")),
        })
    }

    fn delete(&self, name: &str) -> Result<()> {
        let entry = self.entry_for(name)?;
        match entry.delete_credential() {
            Ok(()) => {}
            Err(keyring::Error::NoEntry) => {
                return Err(PhantomError::SecretNotFound(name.to_string()));
            }
            Err(e) => {
                return Err(PhantomError::VaultError(format!(
                    "Failed to delete secret: {e}"
                )));
            }
        }

        // Update index
        let mut index = self.load_index()?;
        index.retain(|n| n != name);
        self.save_index(&index)?;
        Ok(())
    }

    fn list(&self) -> Result<Vec<String>> {
        self.load_index()
    }

    fn backend_name(&self) -> &str {
        "os-keychain"
    }
}
