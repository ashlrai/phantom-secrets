//! `enforce_rotation_on_access`: refuse to hand a protected secret to a proxy
//! session when its rotation schedule says it is overdue.
//!
//! The age of a secret is measured from machine-local vault metadata, never
//! from `.phantom.toml`: the later of the vault entry's `created_at` (stamped
//! when `phantom add` first stores the name, kept on overwrite, cleared by
//! `phantom remove`) and `rotated_at` (stamped by a confirmed provider
//! rotation). The current value can be no older than that anchor, so a secret
//! is let through only when it is provably inside its window. A missing or
//! future anchor, a missing schedule, or a metadata read error refuses.

use anyhow::{Context, Result};
use phantom_core::config::PhantomConfig;
use phantom_core::env_scope::{namespaced_key, DEFAULT_ENV};
use phantom_core::rotation_strategy::check_rotation_enforcement;
use phantom_vault::{SecretMetadata, VaultBackend};

/// The time the entry's current value is known to be no older than.
fn rotation_anchor(metadata: Option<&SecretMetadata>) -> Option<u64> {
    let metadata = metadata?;
    match (metadata.created_at, metadata.rotated_at) {
        (Some(created), Some(rotated)) => Some(created.max(rotated)),
        (created, rotated) => created.or(rotated),
    }
}

/// The vault entry a session would read for `key`, mirroring exec/start
/// retrieval: the env-namespaced entry first, the bare legacy entry only in
/// the default environment. `None` when neither is listed.
fn injected_entry<'a>(vault_names: &'a [String], key: &str, active_env: &str) -> Option<&'a str> {
    let namespaced = namespaced_key(active_env, key);
    vault_names
        .iter()
        .find(|name| **name == namespaced)
        .or_else(|| {
            (active_env == DEFAULT_ENV)
                .then(|| vault_names.iter().find(|name| name.as_str() == key))
                .flatten()
        })
        .map(String::as_str)
}

/// Refuse the launch when any `keys` entry with
/// `enforce_rotation_on_access = true` is overdue or has an unknown age.
/// Runs before any secret value is read; messages carry names only.
pub(crate) fn enforce_rotation_on_access<'k>(
    config: &PhantomConfig,
    vault: &dyn VaultBackend,
    vault_names: &[String],
    active_env: &str,
    keys: impl IntoIterator<Item = &'k str>,
    now_secs: u64,
) -> Result<()> {
    let mut keys: Vec<&str> = keys.into_iter().collect();
    keys.sort_unstable();
    keys.dedup();

    let mut refusals = Vec::new();
    for key in keys {
        let enforce = config
            .phantom
            .secrets
            .get(key)
            .is_some_and(|secret| secret.enforce_rotation_on_access);
        if !enforce {
            continue;
        }
        let schedule = config
            .get_rotation_schedule(key)
            .context("Rotation enforcement could not read the rotation schedule")?;
        let anchor = match injected_entry(vault_names, key, active_env) {
            Some(entry) => rotation_anchor(
                vault
                    .get_metadata(entry)
                    .with_context(|| {
                        format!("Rotation enforcement could not read vault metadata for '{key}'")
                    })?
                    .as_ref(),
            ),
            None => None,
        };
        let status = check_rotation_enforcement(true, schedule.as_ref(), anchor, now_secs);
        if let Some(message) = status.error_message(key) {
            refusals.push(message);
        }
    }

    if refusals.is_empty() {
        Ok(())
    } else {
        anyhow::bail!(
            "Refusing to start: rotation enforcement blocked {} secret(s).\n{}",
            refusals.len(),
            refusals.join("\n")
        )
    }
}

/// Current Unix time in seconds.
pub(crate) fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use phantom_core::config::SecretOverride;
    use phantom_core::error::{PhantomError, Result as PhantomResult};
    use std::collections::BTreeMap;
    use zeroize::Zeroizing;

    const DAY: u64 = 86_400;
    const NOW: u64 = 1_800_000_000;

    /// Names and metadata only; any value read is a test failure.
    struct MetadataVault {
        metadata: BTreeMap<String, SecretMetadata>,
        fail_metadata: bool,
    }

    impl MetadataVault {
        fn with(entries: &[(&str, Option<u64>, Option<u64>)]) -> Self {
            Self {
                metadata: entries
                    .iter()
                    .map(|(name, created_at, rotated_at)| {
                        (
                            name.to_string(),
                            SecretMetadata {
                                created_at: *created_at,
                                rotated_at: *rotated_at,
                                ..SecretMetadata::default()
                            },
                        )
                    })
                    .collect(),
                fail_metadata: false,
            }
        }
    }

    impl VaultBackend for MetadataVault {
        fn store(&self, _name: &str, _value: &str) -> PhantomResult<()> {
            unreachable!("the rotation gate never writes")
        }
        fn retrieve(&self, _name: &str) -> PhantomResult<Zeroizing<String>> {
            unreachable!("the rotation gate never reads a value")
        }
        fn delete(&self, _name: &str) -> PhantomResult<()> {
            unreachable!("the rotation gate never deletes")
        }
        fn list(&self) -> PhantomResult<Vec<String>> {
            Ok(self.metadata.keys().cloned().collect())
        }
        fn backend_name(&self) -> &str {
            "metadata-only"
        }
        fn get_metadata(&self, name: &str) -> PhantomResult<Option<SecretMetadata>> {
            if self.fail_metadata {
                return Err(PhantomError::VaultError("metadata unavailable".to_string()));
            }
            Ok(self.metadata.get(name).cloned())
        }
    }

    fn config_with(secrets: &[(&str, SecretOverride)]) -> PhantomConfig {
        let mut config = PhantomConfig::new_with_defaults("rotation-gate".to_string());
        for (name, secret) in secrets {
            config
                .phantom
                .secrets
                .insert(name.to_string(), secret.clone());
        }
        config
    }

    fn enforced(rotate_every: Option<&str>) -> SecretOverride {
        SecretOverride {
            rotate_every: rotate_every.map(str::to_string),
            enforce_rotation_on_access: true,
            ..SecretOverride::default()
        }
    }

    fn gate(config: &PhantomConfig, vault: &MetadataVault, env: &str, keys: &[&str]) -> Result<()> {
        let names = vault.list().unwrap();
        enforce_rotation_on_access(config, vault, &names, env, keys.iter().copied(), NOW)
    }

    fn refusal_text(result: Result<()>) -> String {
        match result {
            Ok(()) => String::new(),
            Err(error) => format!("{error:#}"),
        }
    }

    #[test]
    fn overdue_secret_is_refused_with_its_name_and_fix() {
        let config = config_with(&[("API_KEY", enforced(Some("30d")))]);
        let vault = MetadataVault::with(&[("API_KEY", Some(NOW - 45 * DAY), None)]);
        let text = refusal_text(gate(&config, &vault, DEFAULT_ENV, &["API_KEY"]));
        assert!(
            text.contains("'API_KEY'"),
            "refusal does not name the secret"
        );
        assert!(text.contains("45 days ago"));
        assert!(text.contains("phantom remove API_KEY"));
    }

    #[test]
    fn secret_inside_its_window_is_allowed() {
        let config = config_with(&[("API_KEY", enforced(Some("30d")))]);
        let vault = MetadataVault::with(&[("API_KEY", Some(NOW - 10 * DAY), None)]);
        assert!(gate(&config, &vault, DEFAULT_ENV, &["API_KEY"]).is_ok());
    }

    #[test]
    fn a_recorded_provider_rotation_resets_the_age() {
        let config = config_with(&[("API_KEY", enforced(Some("30d")))]);
        let vault = MetadataVault::with(&[("API_KEY", Some(NOW - 400 * DAY), Some(NOW - 2 * DAY))]);
        assert!(gate(&config, &vault, DEFAULT_ENV, &["API_KEY"]).is_ok());
    }

    #[test]
    fn unenforced_secrets_are_not_checked() {
        let config = config_with(&[(
            "API_KEY",
            SecretOverride {
                rotate_every: Some("30d".to_string()),
                ..SecretOverride::default()
            },
        )]);
        let mut vault = MetadataVault::with(&[("API_KEY", Some(NOW - 400 * DAY), None)]);
        vault.fail_metadata = true;
        assert!(gate(&config, &vault, DEFAULT_ENV, &["API_KEY", "OTHER_KEY"]).is_ok());
    }

    #[test]
    fn unknown_age_is_refused() {
        let config = config_with(&[("API_KEY", enforced(Some("30d")))]);
        for vault in [
            MetadataVault::with(&[("API_KEY", None, None)]),
            MetadataVault::with(&[("API_KEY", Some(NOW + DAY), None)]),
            MetadataVault::with(&[]),
        ] {
            let text = refusal_text(gate(&config, &vault, DEFAULT_ENV, &["API_KEY"]));
            assert!(text.contains("'API_KEY'"), "unknown age was not refused");
            assert!(text.contains("age is unknown"));
        }
    }

    #[test]
    fn enforcement_without_a_schedule_is_refused() {
        let config = config_with(&[("API_KEY", enforced(None))]);
        let vault = MetadataVault::with(&[("API_KEY", Some(NOW), None)]);
        let text = refusal_text(gate(&config, &vault, DEFAULT_ENV, &["API_KEY"]));
        assert!(text.contains("no rotation schedule"));
    }

    #[test]
    fn metadata_and_schedule_errors_are_refusals() {
        let config = config_with(&[("API_KEY", enforced(Some("30d")))]);
        let mut vault = MetadataVault::with(&[("API_KEY", Some(NOW), None)]);
        vault.fail_metadata = true;
        assert!(gate(&config, &vault, DEFAULT_ENV, &["API_KEY"]).is_err());

        let bad = config_with(&[("API_KEY", enforced(Some("3mo")))]);
        let vault = MetadataVault::with(&[("API_KEY", Some(NOW), None)]);
        assert!(gate(&bad, &vault, DEFAULT_ENV, &["API_KEY"]).is_err());
    }

    #[test]
    fn the_entry_a_session_would_read_decides_the_age() {
        let config = config_with(&[("API_KEY", enforced(Some("30d")))]);
        let namespaced = namespaced_key("staging", "API_KEY");
        // Fresh bare entry, stale namespaced entry: staging reads the stale one.
        let vault = MetadataVault::with(&[
            ("API_KEY", Some(NOW), None),
            (namespaced.as_str(), Some(NOW - 90 * DAY), None),
        ]);
        assert!(gate(&config, &vault, "staging", &["API_KEY"]).is_err());
        // Outside the default environment the bare entry is never read.
        let vault = MetadataVault::with(&[("API_KEY", Some(NOW), None)]);
        assert!(gate(&config, &vault, "staging", &["API_KEY"]).is_err());
        assert!(gate(&config, &vault, DEFAULT_ENV, &["API_KEY"]).is_ok());
    }

    #[test]
    fn every_blocked_secret_is_listed() {
        let config = config_with(&[
            ("A_KEY", enforced(Some("7d"))),
            ("B_KEY", enforced(Some("7d"))),
        ]);
        let vault = MetadataVault::with(&[
            ("A_KEY", Some(NOW - 8 * DAY), None),
            ("B_KEY", Some(NOW - 9 * DAY), None),
        ]);
        let text = refusal_text(gate(&config, &vault, DEFAULT_ENV, &["B_KEY", "A_KEY"]));
        assert!(text.contains("blocked 2 secret(s)"));
        assert!(text.contains("'A_KEY'") && text.contains("'B_KEY'"));
    }
}
