use crate::metadata::SecretMetadata;
use phantom_core::error::Result;
use phantom_core::validator::ValidationMetadata;
use zeroize::Zeroizing;

#[derive(Clone)]
pub struct MetadataCas {
    pub name: String,
    pub expected: Option<SecretMetadata>,
    pub replacement: Option<SecretMetadata>,
}

#[derive(Clone)]
pub struct ValidationMetadataCas {
    pub name: String,
    pub expected: Option<ValidationMetadata>,
    pub replacement: Option<ValidationMetadata>,
}

/// Trait for secret storage backends.
pub trait VaultBackend: Send + Sync {
    /// Store a secret value under a given name.
    fn store(&self, name: &str, value: &str) -> Result<()>;

    /// Retrieve a secret value by name. Returns `Zeroizing<String>` so the
    /// secret is scrubbed from memory on drop — callers cannot forget to zeroize.
    fn retrieve(&self, name: &str) -> Result<Zeroizing<String>>;

    /// Delete a secret by name.
    fn delete(&self, name: &str) -> Result<()>;

    /// Atomically replace one secret value when its current value matches the
    /// expected before-image. `None` represents an absent entry. Backends that
    /// cannot provide a real atomic compare-and-swap must fail closed rather
    /// than emulate it with a racy retrieve/store sequence.
    fn compare_and_swap(
        &self,
        name: &str,
        expected: Option<&str>,
        replacement: Option<&str>,
    ) -> Result<bool> {
        let _ = (name, expected, replacement);
        Err(phantom_core::error::PhantomError::VaultError(
            "vault backend does not support atomic compare-and-swap".to_string(),
        ))
    }

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

    /// Persist metadata for a secret. Unsupported backends fail closed so a
    /// caller can never report lifecycle policy success without persistence.
    fn set_metadata(&self, name: &str, meta: SecretMetadata) -> Result<()> {
        let _ = (name, meta);
        Err(phantom_core::error::PhantomError::VaultError(
            "vault backend does not support lifecycle metadata persistence".to_string(),
        ))
    }

    /// Atomically apply an exact-before batch of lifecycle metadata changes.
    /// Every named secret must exist, every before-image must match, and either
    /// the whole batch commits or no metadata changes. Unsupported backends
    /// fail closed.
    fn compare_and_swap_metadata_batch(&self, changes: &[MetadataCas]) -> Result<bool> {
        let _ = changes;
        Err(phantom_core::error::PhantomError::VaultError(
            "vault backend does not support atomic metadata compare-and-swap".to_string(),
        ))
    }

    fn compare_and_swap_metadata(
        &self,
        name: &str,
        expected: Option<&SecretMetadata>,
        replacement: Option<SecretMetadata>,
    ) -> Result<bool> {
        self.compare_and_swap_metadata_batch(&[MetadataCas {
            name: name.to_string(),
            expected: expected.cloned(),
            replacement,
        }])
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

    /// Set a local expiry-enforcement policy without changing the credential.
    /// This deliberately leaves `rotated_at` unchanged: policy configuration is
    /// not evidence that a provider issued a successor credential.
    fn set_rotation_policy(&self, name: &str, days_ttl: u64) -> Result<()> {
        let before = self.get_metadata(name)?;
        let mut meta = before.clone().unwrap_or_default();
        meta.rotation_policy = Some(crate::metadata::RotationPolicy {
            days_ttl,
            auto_rotate: false,
        });
        // Starts a local enforcement deadline; this is not a provider TTL.
        let now = crate::metadata::now_secs();
        meta.expires_at = Some(now + days_ttl * 86_400);
        if self.compare_and_swap_metadata(name, before.as_ref(), Some(meta))? {
            Ok(())
        } else {
            Err(phantom_core::error::PhantomError::VaultError(
                "secret metadata changed concurrently; rotation policy was not applied".to_string(),
            ))
        }
    }

    /// Record that a vendor-provider rotation replaced this secret's value,
    /// updating `rotated_at` and recomputing `expires_at` so the secret does
    /// not stay perpetually "due" after a successful rotation.
    ///
    /// Expiry resolution order:
    /// 1. `expires_override` (e.g. GitHub installation tokens expire in 1 h);
    /// 2. the secret's existing `rotation_policy.days_ttl`;
    /// 3. when the secret previously had an `expires_at` but no policy, a
    ///    default TTL of 30 days (so expiry-driven batch rotation converges);
    /// 4. otherwise no expiry is set.
    ///
    /// Returns the `expires_at` that was persisted (if any).
    fn record_provider_rotation(
        &self,
        name: &str,
        expires_override: Option<u64>,
    ) -> Result<Option<u64>> {
        const DEFAULT_ROTATION_TTL_DAYS: u64 = 30;
        let before = self.get_metadata(name)?;
        let mut meta = before.clone().unwrap_or_default();
        let had_expiry = meta.expires_at.is_some();
        // record_rotation() stamps rotated_at and recomputes expires_at when a
        // rotation policy exists.
        meta.record_rotation();
        if let Some(exp) = expires_override {
            meta.expires_at = Some(exp);
        } else if meta.rotation_policy.is_none() && had_expiry {
            meta.expires_at =
                Some(crate::metadata::now_secs() + DEFAULT_ROTATION_TTL_DAYS * 86_400);
        }
        let expires_at = meta.expires_at;
        if self.compare_and_swap_metadata(name, before.as_ref(), Some(meta))? {
            Ok(expires_at)
        } else {
            Err(phantom_core::error::PhantomError::VaultError(
                "secret metadata changed concurrently; provider rotation metadata was not applied"
                    .to_string(),
            ))
        }
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
        Err(phantom_core::error::PhantomError::VaultError(
            "vault backend does not support validation metadata persistence".to_string(),
        ))
    }

    /// Retrieve the exact optional validation metadata before-image.
    fn get_validation_metadata_exact(&self, name: &str) -> Result<Option<ValidationMetadata>> {
        let metadata = self.get_validation_metadata(name)?;
        Ok((!metadata.never_checked()).then_some(metadata))
    }

    /// Atomically apply a batch of exact-before validation metadata changes.
    fn compare_and_swap_validation_metadata_batch(
        &self,
        changes: &[ValidationMetadataCas],
    ) -> Result<bool> {
        let _ = changes;
        Err(phantom_core::error::PhantomError::VaultError(
            "vault backend does not support atomic validation metadata compare-and-swap"
                .to_string(),
        ))
    }

    fn compare_and_swap_validation_metadata(
        &self,
        name: &str,
        expected: Option<&ValidationMetadata>,
        replacement: Option<ValidationMetadata>,
    ) -> Result<bool> {
        self.compare_and_swap_validation_metadata_batch(&[ValidationMetadataCas {
            name: name.to_string(),
            expected: expected.cloned(),
            replacement,
        }])
    }
}
