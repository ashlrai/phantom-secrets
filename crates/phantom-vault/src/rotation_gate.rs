//! Value-blind core of `enforce_rotation_on_access`, shared by the CLI and the
//! MCP server so every path that hands a real vault value out applies the same
//! gate.
//!
//! The age of a secret is measured from machine-local vault metadata, never
//! from `.phantom.toml`: the later of the vault entry's `created_at` and
//! `rotated_at`. A secret is let through only when it is provably inside its
//! window; a missing or future anchor, a missing schedule, or a metadata read
//! error refuses. Nothing here reads a secret value, and every message names
//! secrets only.

use crate::{SecretMetadata, VaultBackend};
use phantom_core::config::PhantomConfig;
use phantom_core::env_scope::{namespaced_key, split_key, DEFAULT_ENV};
use phantom_core::error::PhantomError;
use phantom_core::rotation_strategy::check_rotation_enforcement;

/// One secret the caller is about to hand out: its logical name (the
/// `[phantom.secrets.NAME]` key) and the exact vault entry whose value would
/// be read, `None` when no entry is listed.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct GateTarget {
    pub key: String,
    pub entry: Option<String>,
}

/// Why the gate could not decide. Either way the caller must refuse.
#[derive(Debug, thiserror::Error)]
pub enum RotationGateError {
    /// The effective rotation schedule could not be read from the config.
    #[error("Rotation enforcement could not read the rotation schedule")]
    Schedule(#[source] PhantomError),
    /// The vault metadata for `key` could not be read.
    #[error("Rotation enforcement could not read vault metadata for '{key}'")]
    Metadata {
        key: String,
        #[source]
        source: PhantomError,
    },
}

/// The time the entry's current value is known to be no older than.
pub fn rotation_anchor(metadata: Option<&SecretMetadata>) -> Option<u64> {
    let metadata = metadata?;
    match (metadata.created_at, metadata.rotated_at) {
        (Some(created), Some(rotated)) => Some(created.max(rotated)),
        (created, rotated) => created.or(rotated),
    }
}

/// The vault entry a proxy session would read for `key`, mirroring exec/start
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

/// Targets for a proxy session that injects dotenv `keys` in `active_env`.
pub fn session_targets<'k>(
    vault_names: &[String],
    active_env: &str,
    keys: impl IntoIterator<Item = &'k str>,
) -> Vec<GateTarget> {
    keys.into_iter()
        .map(|key| GateTarget {
            key: key.to_string(),
            entry: injected_entry(vault_names, key, active_env).map(str::to_string),
        })
        .collect()
}

/// Targets for paths that read exact vault entry names (reveal, copy, sync,
/// team push): `env/NAME` is gated as `NAME`, a bare entry as itself.
pub fn entry_targets<'e>(entries: impl IntoIterator<Item = &'e str>) -> Vec<GateTarget> {
    entries
        .into_iter()
        .map(|entry| GateTarget {
            key: split_key(entry).map_or(entry, |(_, name)| name).to_string(),
            entry: Some(entry.to_string()),
        })
        .collect()
}

/// Targets for paths that write values of unknown age into the vault (a
/// cloud pull, an encrypted backup restore). The incoming value carries no
/// rotation anchor: a new entry would be stamped as stored now and an
/// overwritten one would keep the local entry's anchor, so either way the
/// value's real age is lost. Each written entry is judged with no anchor,
/// which refuses it whenever its secret enforces rotation on access.
pub fn restore_targets<'e>(entries: impl IntoIterator<Item = &'e str>) -> Vec<GateTarget> {
    entries
        .into_iter()
        .map(|entry| GateTarget {
            key: split_key(entry).map_or(entry, |(_, name)| name).to_string(),
            entry: None,
        })
        .collect()
}

/// One refusal message per target with `enforce_rotation_on_access = true`
/// that is overdue or has an unknown age; empty when access may proceed.
/// Runs before any secret value is read.
pub fn rotation_refusals(
    config: &PhantomConfig,
    vault: &dyn VaultBackend,
    targets: impl IntoIterator<Item = GateTarget>,
    now_secs: u64,
) -> Result<Vec<String>, RotationGateError> {
    let mut targets: Vec<GateTarget> = targets.into_iter().collect();
    targets.sort_unstable();
    targets.dedup();

    let mut refusals = Vec::new();
    for target in targets {
        let key = target.key.as_str();
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
            .map_err(RotationGateError::Schedule)?;
        let anchor = match target.entry.as_deref() {
            Some(entry) => rotation_anchor(
                vault
                    .get_metadata(entry)
                    .map_err(|source| RotationGateError::Metadata {
                        key: key.to_string(),
                        source,
                    })?
                    .as_ref(),
            ),
            None => None,
        };
        let status = check_rotation_enforcement(true, schedule.as_ref(), anchor, now_secs);
        if let Some(message) = status.error_message(key) {
            if !refusals.contains(&message) {
                refusals.push(message);
            }
        }
    }
    Ok(refusals)
}

/// The refusal text every caller shows: `Refusing to {action}: ...` followed
/// by one line per blocked secret. `None` when nothing is blocked.
pub fn refusal_summary(action: &str, refusals: &[String]) -> Option<String> {
    if refusals.is_empty() {
        return None;
    }
    Some(format!(
        "Refusing to {action}: rotation enforcement blocked {} secret(s).\n{}",
        refusals.len(),
        refusals.join("\n")
    ))
}

/// Current Unix time in seconds.
pub fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::file::FileVault;
    use phantom_core::config::SecretOverride;

    const DAY: u64 = 86_400;

    fn enforced_config() -> PhantomConfig {
        let mut config = PhantomConfig::new_with_defaults("rotation-gate-core".to_string());
        config.phantom.secrets.insert(
            "API_KEY".to_string(),
            SecretOverride {
                rotate_every: Some("30d".to_string()),
                enforce_rotation_on_access: true,
                ..SecretOverride::default()
            },
        );
        config
    }

    fn vault_with(dir: &tempfile::TempDir, entries: &[(&str, u64)]) -> FileVault {
        let vault = FileVault::new(
            dir.path(),
            "rotation-gate-core",
            format!("gate-{}", std::process::id()),
        )
        .expect("file vault");
        for (entry, created_at) in entries {
            vault.store(entry, "placeholder").expect("store");
            vault
                .set_metadata(
                    entry,
                    SecretMetadata {
                        created_at: Some(*created_at),
                        ..SecretMetadata::default()
                    },
                )
                .expect("metadata");
        }
        vault
    }

    #[test]
    fn entry_targets_strip_the_environment_prefix() {
        let targets = entry_targets(["staging/API_KEY", "API_KEY"]);
        assert_eq!(targets[0].key, "API_KEY");
        assert_eq!(targets[0].entry.as_deref(), Some("staging/API_KEY"));
        assert_eq!(targets[1].key, "API_KEY");
        assert_eq!(targets[1].entry.as_deref(), Some("API_KEY"));
    }

    #[test]
    fn an_overdue_entry_is_refused_and_a_fresh_one_passes() {
        let now = 1_800_000_000;
        let dir = tempfile::tempdir().unwrap();
        let vault = vault_with(
            &dir,
            &[("staging/API_KEY", now - 45 * DAY), ("API_KEY", now - DAY)],
        );
        let config = enforced_config();

        let stale =
            rotation_refusals(&config, &vault, entry_targets(["staging/API_KEY"]), now).unwrap();
        assert_eq!(stale.len(), 1);
        assert!(stale[0].contains("'API_KEY'"));
        assert!(stale[0].contains("45 days ago"));

        let fresh = rotation_refusals(&config, &vault, entry_targets(["API_KEY"]), now).unwrap();
        assert!(fresh.is_empty());
    }

    #[test]
    fn unenforced_entries_are_never_checked() {
        let now = 1_800_000_000;
        let dir = tempfile::tempdir().unwrap();
        let vault = vault_with(&dir, &[("OTHER_KEY", now - 400 * DAY)]);
        let config = enforced_config();
        assert!(
            rotation_refusals(&config, &vault, entry_targets(["OTHER_KEY"]), now)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn a_restored_entry_is_refused_even_when_the_local_entry_is_fresh() {
        let now = 1_800_000_000;
        let dir = tempfile::tempdir().unwrap();
        let vault = vault_with(&dir, &[("API_KEY", now - DAY)]);
        let config = enforced_config();

        let targets = restore_targets(["API_KEY", "staging/API_KEY", "OTHER_KEY"]);
        assert!(targets.iter().all(|target| target.entry.is_none()));
        let refused = rotation_refusals(&config, &vault, targets, now).unwrap();
        assert_eq!(refused.len(), 1);
        assert!(refused[0].contains("'API_KEY'"));
        assert!(refused[0].contains("age is unknown"));

        assert!(
            rotation_refusals(&config, &vault, restore_targets(["OTHER_KEY"]), now)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn refusal_summary_names_the_action() {
        assert!(refusal_summary("reveal", &[]).is_none());
        let text = refusal_summary("reveal", &["line".to_string()]).unwrap();
        assert!(text.starts_with("Refusing to reveal: rotation enforcement blocked 1 secret(s)."));
    }
}
