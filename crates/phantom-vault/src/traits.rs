use phantom_core::error::Result;
use zeroize::Zeroizing;

/// Trait for secret storage backends.
pub trait VaultBackend: Send + Sync {
    /// Store a secret value under a given name.
    fn store(&self, name: &str, value: &str) -> Result<()>;

    /// Retrieve a secret value by name. Returns `Zeroizing<String>` so the
    /// secret is scrubbed from memory on drop — callers cannot forget to zeroize.
    fn retrieve(&self, name: &str) -> Result<Zeroizing<String>>;

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
