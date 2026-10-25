//! `enforce_rotation_on_access`: refuse to hand a protected secret to a proxy
//! session, a terminal, another vault, a deployment platform, or a team when
//! its rotation schedule says it is overdue.
//!
//! The decision lives in [`phantom_vault::rotation_gate`] so the MCP server
//! applies the same gate. The age of a secret is measured from machine-local
//! vault metadata, never from `.phantom.toml`: the later of the vault entry's
//! `created_at` (stamped when `phantom add` first stores the name, kept on
//! overwrite, cleared by `phantom remove`) and `rotated_at` (stamped by a
//! confirmed provider rotation). A secret is let through only when it is
//! provably inside its window. A missing or future anchor, a missing schedule,
//! or a metadata read error refuses.

use anyhow::Result;
use phantom_core::config::PhantomConfig;
use phantom_vault::rotation_gate::{
    entry_targets, refusal_summary, restore_targets, rotation_refusals, session_targets, GateTarget,
};
use phantom_vault::VaultBackend;

fn enforce(
    config: &PhantomConfig,
    vault: &dyn VaultBackend,
    targets: Vec<GateTarget>,
    action: &str,
    now_secs: u64,
) -> Result<()> {
    let refusals = rotation_refusals(config, vault, targets, now_secs)?;
    match refusal_summary(action, &refusals) {
        Some(summary) => Err(anyhow::anyhow!(summary)),
        None => Ok(()),
    }
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
    enforce(
        config,
        vault,
        session_targets(vault_names, active_env, keys),
        "start",
        now_secs,
    )
}

/// The same gate for paths that read exact vault entries and hand the value
/// out (reveal, copy, sync, env copy, team push). `env/NAME` is judged by the
/// `[phantom.secrets.NAME]` policy and that entry's own age. `action`
/// completes "Refusing to ...". Runs before any secret value is read.
pub(crate) fn enforce_rotation_on_entries<'e>(
    config: &PhantomConfig,
    vault: &dyn VaultBackend,
    entries: impl IntoIterator<Item = &'e str>,
    action: &str,
    now_secs: u64,
) -> Result<()> {
    enforce(config, vault, entry_targets(entries), action, now_secs)
}

/// The same gate for paths that write values of unknown age into the vault
/// (cloud, team or provider pull, encrypted backup restore, competitor
/// import): a restored value would get a fresh
/// anchor (new entry) or inherit the local one (overwrite), laundering an
/// overdue value. Each written `entries` name whose secret enforces rotation
/// is refused as having an unknown age. Runs before any vault write.
pub(crate) fn enforce_rotation_on_restore<'e>(
    config: &PhantomConfig,
    vault: &dyn VaultBackend,
    entries: impl IntoIterator<Item = &'e str>,
    action: &str,
    now_secs: u64,
) -> Result<()> {
    enforce(config, vault, restore_targets(entries), action, now_secs)
}

/// The lifecycle gate for paths that hand real values to new places (a
/// deployment platform, team members, the cloud copy): the rotation gate of
/// [`enforce_rotation_on_entries`], then a refusal when any entry was demoted
/// to read-only by the expiry policy or its lifecycle metadata cannot be read
/// ([`phantom_vault::rotation_gate::read_only_refusal`]). `remedy` follows
/// the read-only names and `unsent` ends that refusal, e.g. "No vault
/// plaintext was read and no provider request was sent.". Reads names and
/// metadata only, never a value; messages carry names only.
pub(crate) fn enforce_lifecycle_on_propagation<'e>(
    config: &PhantomConfig,
    vault: &dyn VaultBackend,
    entries: impl IntoIterator<Item = &'e str> + Clone,
    action: &str,
    remedy: &str,
    unsent: &str,
    now_secs: u64,
) -> Result<()> {
    enforce_rotation_on_entries(config, vault, entries.clone(), action, now_secs)?;
    match phantom_vault::rotation_gate::read_only_refusal(vault, entries, action, remedy) {
        Some(refusal) => Err(anyhow::anyhow!("{refusal} {unsent}")),
        None => Ok(()),
    }
}

/// Current Unix time in seconds.
pub(crate) fn now_secs() -> u64 {
    phantom_vault::rotation_gate::now_secs()
}

/// Fixtures for the per-command rotation-gate tests.
#[cfg(test)]
pub(crate) mod fixtures {
    use phantom_core::config::{PhantomConfig, SecretOverride};
    use phantom_vault::file::FileVault;
    use phantom_vault::{SecretMetadata, VaultBackend};

    pub(crate) const DAY: u64 = 86_400;
    pub(crate) const NOW: u64 = 1_800_000_000;

    /// A config that enforces a 30-day rotation for each of `names`.
    pub(crate) fn enforced_config(names: &[&str]) -> PhantomConfig {
        let mut config = PhantomConfig::new_with_defaults("rotation-gate-fixture".to_string());
        for name in names {
            config.phantom.secrets.insert(
                name.to_string(),
                SecretOverride {
                    rotate_every: Some("30d".to_string()),
                    enforce_rotation_on_access: true,
                    ..SecretOverride::default()
                },
            );
        }
        config
    }

    /// A file vault holding `entries`, each stored `age_days` before [`NOW`].
    pub(crate) fn aged_vault(dir: &tempfile::TempDir, entries: &[(&str, u64)]) -> FileVault {
        let vault = FileVault::new(
            &crate::test_support::canonical_tempdir_path(dir),
            "rotation-gate-fixture",
            format!("gate-{}", std::process::id()),
        )
        .unwrap();
        for (entry, age_days) in entries {
            vault.store(entry, "fixture-value").unwrap();
            vault
                .set_metadata(
                    entry,
                    SecretMetadata {
                        created_at: Some(NOW - age_days * DAY),
                        ..SecretMetadata::default()
                    },
                )
                .unwrap();
        }
        vault
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use phantom_core::config::SecretOverride;
    use phantom_core::env_scope::{namespaced_key, DEFAULT_ENV};
    use phantom_core::error::{PhantomError, Result as PhantomResult};
    use phantom_vault::SecretMetadata;
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

    #[test]
    fn restore_gate_refuses_enforced_writes_whatever_the_local_age() {
        let config = config_with(&[("API_KEY", enforced(Some("30d")))]);
        let vault = MetadataVault::with(&[("API_KEY", Some(NOW - DAY), None)]);
        let text = refusal_text(enforce_rotation_on_restore(
            &config,
            &vault,
            ["API_KEY", "OTHER_KEY"],
            "restore the backup",
            NOW,
        ));
        assert!(text.starts_with(
            "Refusing to restore the backup: rotation enforcement blocked 1 secret(s)."
        ));
        assert!(text.contains("age is unknown"));
        assert!(enforce_rotation_on_restore(
            &config,
            &vault,
            ["OTHER_KEY"],
            "restore the backup",
            NOW
        )
        .is_ok());
    }

    #[test]
    fn entry_gate_judges_each_exact_entry_and_names_the_action() {
        let config = config_with(&[("API_KEY", enforced(Some("30d")))]);
        let namespaced = namespaced_key("staging", "API_KEY");
        let vault = MetadataVault::with(&[
            ("API_KEY", Some(NOW - DAY), None),
            (namespaced.as_str(), Some(NOW - 60 * DAY), None),
        ]);
        let refused =
            enforce_rotation_on_entries(&config, &vault, [namespaced.as_str()], "reveal", NOW);
        let text = refusal_text(refused);
        assert!(text.starts_with("Refusing to reveal: rotation enforcement blocked 1 secret(s)."));
        assert!(text.contains("'API_KEY'"));
        assert!(enforce_rotation_on_entries(&config, &vault, ["API_KEY"], "reveal", NOW).is_ok());
        // Session wording for exec/start is unchanged.
        let text = refusal_text(gate(&config, &vault, "staging", &["API_KEY"]));
        assert!(text.starts_with("Refusing to start:"));
    }
}
