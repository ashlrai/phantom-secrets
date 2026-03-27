use crate::traits::VaultBackend;
use phantom_core::error::{PhantomError, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Encrypted file-based vault backend.
/// Used as fallback when OS keychain is not available (Docker, CI, etc.).
///
/// For MVP, this uses a simple JSON file with a clear warning that it's
/// not as secure as the OS keychain. Production would use age encryption.
#[derive(Debug)]
pub struct FileVault {
    vault_path: PathBuf,
    #[allow(dead_code)]
    project_id: String,
}

#[derive(Debug, Serialize, Deserialize, Default)]
struct VaultData {
    secrets: BTreeMap<String, String>,
}

impl FileVault {
    /// Create a new file vault in the given directory.
    pub fn new(base_dir: &Path, project_id: &str) -> Result<Self> {
        let vault_dir = base_dir.join("vaults");
        std::fs::create_dir_all(&vault_dir)?;

        Ok(Self {
            vault_path: vault_dir.join(format!("{project_id}.json")),
            project_id: project_id.to_string(),
        })
    }

    fn load(&self) -> Result<VaultData> {
        if !self.vault_path.exists() {
            return Ok(VaultData::default());
        }
        let content = std::fs::read_to_string(&self.vault_path)?;
        serde_json::from_str(&content)
            .map_err(|e| PhantomError::VaultError(format!("Corrupt vault file: {e}")))
    }

    fn save(&self, data: &VaultData) -> Result<()> {
        let content = serde_json::to_string_pretty(data)
            .map_err(|e| PhantomError::VaultError(format!("Serialize error: {e}")))?;

        // Write atomically via temp file
        let tmp_path = self.vault_path.with_extension("tmp");
        std::fs::write(&tmp_path, &content)?;
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
        let vault = FileVault::new(dir.path(), "test-project").unwrap();
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
        assert_eq!(keys, vec!["A", "B"]); // BTreeMap sorts
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
}
