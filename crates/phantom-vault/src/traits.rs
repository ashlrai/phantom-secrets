use crate::metadata::SecretMetadata;
use phantom_core::error::Result;
use phantom_core::validator::ValidationMetadata;
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

    // ── Metadata / TTL ───────────────────────────────────────────────

    /// Retrieve metadata for a secret. Returns `None` if no metadata exists
    /// or if the backend does not support metadata.
    fn get_metadata(&self, name: &str) -> Result<Option<SecretMetadata>> {
        let _ = name;
        Ok(None)
    }

    /// Persist metadata for a secret. No-op on backends that do not support
    /// metadata storage (e.g. OS keychain — metadata lives in the file vault
    /// sidecar when the keychain is the primary backend).
    fn set_metadata(&self, name: &str, meta: SecretMetadata) -> Result<()> {
        let _ = (name, meta);
        Ok(())
    }

    /// List all secret names together with their metadata (if any).
    /// Backends that do not support metadata return `(name, None)` pairs.
    fn list_with_metadata(&self) -> Result<Vec<(String, Option<SecretMetadata>)>> {
        let names = self.list()?;
        let mut out = Vec::with_capacity(names.len());
        for name in names {
            let meta = self.get_metadata(&name)?;
            out.push((name, meta));
        }
        Ok(out)
    }

    /// Store a secret and attach TTL metadata in one atomic operation.
    fn store_with_expiry(&self, name: &str, value: &str, days_ttl: u64) -> Result<()> {
        self.store(name, value)?;
        let meta = SecretMetadata::with_expiry(days_ttl);
        self.set_metadata(name, meta)?;
        Ok(())
    }

    /// Set the rotation policy (TTL) on an existing secret without changing
    /// its value. Updates `rotated_at` and recomputes `expires_at`.
    fn set_rotation_policy(&self, name: &str, days_ttl: u64) -> Result<()> {
        let mut meta = self.get_metadata(name)?.unwrap_or_default();
        meta.record_rotation();
        meta.rotation_policy = Some(crate::metadata::RotationPolicy {
            days_ttl,
            auto_rotate: false,
        });
        // Recompute expires_at based on updated rotation time
        let now = crate::metadata::now_secs();
        meta.expires_at = Some(now + days_ttl * 86_400);
        self.set_metadata(name, meta)
    }

    // ── Validation metadata ──────────────────────────────────────────────

    /// Retrieve the last validation result metadata for a secret.
    /// Returns `Default` (never_checked) if no record exists or the backend
    /// does not support validation metadata.
    fn get_validation_metadata(&self, name: &str) -> Result<ValidationMetadata> {
        let _ = name;
        Ok(ValidationMetadata::default())
    }

    /// Persist validation result metadata for a secret.
    /// No-op on backends that do not support metadata (graceful degradation).
    fn set_validation_metadata(&self, name: &str, meta: ValidationMetadata) -> Result<()> {
        let _ = (name, meta);
        Ok(())
    }
}
