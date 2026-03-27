use phantom_core::error::Result;

/// Trait for secret storage backends.
pub trait VaultBackend: Send + Sync {
    /// Store a secret value under a given name.
    fn store(&self, name: &str, value: &str) -> Result<()>;

    /// Retrieve a secret value by name.
    fn retrieve(&self, name: &str) -> Result<String>;

    /// Delete a secret by name.
    fn delete(&self, name: &str) -> Result<()>;

    /// List all secret names stored in this vault.
    fn list(&self) -> Result<Vec<String>>;

    /// Check if a secret exists.
    fn exists(&self, name: &str) -> Result<bool> {
        Ok(self.list()?.contains(&name.to_string()))
    }

    /// Get the backend name for display purposes.
    fn backend_name(&self) -> &str;
}
