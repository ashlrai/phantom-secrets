/// Environment scoping for phantom secrets.
///
/// Secrets are stored under a composite vault key `<env>:<name>` so that the
/// same logical secret name can hold different values in different environments
/// (e.g. dev vs staging vs prod).
///
/// The **default** environment uses the legacy bare `<name>` key for full
/// backward compatibility: when reading under `default` we first try
/// `default:<name>`, then fall back to the legacy `default/<name>`, then to
/// the bare `<name>` so existing vaults work without migration.
///
/// The active environment is persisted in `.phantom/env` (a single line
/// containing the env name). It is overridable per-invocation via the
/// `--env` CLI flag.
use std::path::Path;

pub const DEFAULT_ENV: &str = "default";

/// Separator used between env name and secret name in vault keys.
///
/// `:` is chosen over `/` because `/` is a path separator on Windows and can
/// cause issues with file-vault backends or Windows Credential Manager entries.
/// `:` is safe on all platforms and cannot appear in env names (validated by
/// `validate_env_name`).
pub const KEY_SEP: char = ':';

/// Return the composite vault key for a given env + secret name.
///
/// `default:<name>` is the canonical form even for the default env; the
/// backward-compat fallback to bare `<name>` (and the legacy `<env>/<name>`
/// format from pre-v2 vaults) is handled at the vault call sites.
pub fn namespaced_key(env: &str, name: &str) -> String {
    format!("{env}{KEY_SEP}{name}")
}

/// Strip the env prefix from a namespaced key, returning `(env, name)`.
///
/// Recognises both the current separator (`:`) and the legacy separator (`/`)
/// for backward compatibility with vaults written before this change.
/// Returns `None` if the key has neither separator.
pub fn split_key(key: &str) -> Option<(&str, &str)> {
    key.split_once(KEY_SEP).or_else(|| key.split_once('/'))
}

/// Read the active environment name from `.phantom/env` in `project_dir`.
/// Returns `"default"` if the file is absent or empty.
pub fn read_active_env(project_dir: &Path) -> String {
    let env_file = project_dir.join(".phantom").join("env");
    if let Ok(content) = std::fs::read_to_string(&env_file) {
        let trimmed = content.trim().to_string();
        if !trimmed.is_empty() {
            return trimmed;
        }
    }
    DEFAULT_ENV.to_string()
}

/// Write `env_name` as the active environment to `.phantom/env`.
pub fn write_active_env(project_dir: &Path, env_name: &str) -> crate::error::Result<()> {
    let dir = project_dir.join(".phantom");
    std::fs::create_dir_all(&dir)?;
    std::fs::write(dir.join("env"), format!("{env_name}\n"))?;
    Ok(())
}

/// Resolve the effective environment: `--env` flag takes priority over the
/// persisted value, which takes priority over the compiled-in default.
pub fn resolve_env(project_dir: &Path, flag: Option<&str>) -> String {
    if let Some(e) = flag {
        return e.to_string();
    }
    read_active_env(project_dir)
}

/// Validate an environment name: lowercase alphanumeric plus `-` and `_`,
/// 1–64 characters, no `/` or whitespace.
pub fn validate_env_name(name: &str) -> crate::error::Result<()> {
    if name.is_empty() || name.len() > 64 {
        return Err(crate::error::PhantomError::Other(
            "Environment name must be 1–64 characters.".to_string(),
        ));
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(crate::error::PhantomError::Other(format!(
            "Invalid environment name '{name}': use only letters, digits, '-', '_'."
        )));
    }
    Ok(())
}

/// Extract the list of known environments from vault keys (anything with the
/// `<env>/` prefix), plus the persisted current env and `"default"`.
pub fn known_envs_from_keys(keys: &[String], current_env: &str) -> Vec<String> {
    let mut envs: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    envs.insert(DEFAULT_ENV.to_string());
    envs.insert(current_env.to_string());
    for key in keys {
        if let Some((env, _)) = split_key(key) {
            envs.insert(env.to_string());
        }
    }
    envs.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn namespaced_key_format() {
        assert_eq!(namespaced_key("dev", "STRIPE_KEY"), "dev:STRIPE_KEY");
        assert_eq!(
            namespaced_key("default", "OPENAI_KEY"),
            "default:OPENAI_KEY"
        );
    }

    #[test]
    fn namespaced_key_contains_no_path_separators() {
        // Regression test: the separator must not be `/` (path separator on
        // Windows) or `\`. This ensures the file-vault backend and Windows
        // Credential Manager never interpret the key as a file path.
        let key = namespaced_key("default", "MY_KEY");
        assert!(
            !key.contains('/'),
            "namespaced key must not contain '/' (Windows path separator): {key}"
        );
        assert!(
            !key.contains('\\'),
            "namespaced key must not contain '\\' (Windows path separator): {key}"
        );
    }

    #[test]
    fn split_key_round_trips_colon() {
        let (env, name) = split_key("dev:STRIPE_KEY").unwrap();
        assert_eq!(env, "dev");
        assert_eq!(name, "STRIPE_KEY");
    }

    #[test]
    fn split_key_round_trips_legacy_slash() {
        // Backward compat: old vaults used `/` — must still parse correctly.
        let (env, name) = split_key("dev/STRIPE_KEY").unwrap();
        assert_eq!(env, "dev");
        assert_eq!(name, "STRIPE_KEY");
    }

    #[test]
    fn split_key_no_separator_returns_none() {
        assert!(split_key("BARE_NAME").is_none());
    }

    #[test]
    fn validate_env_name_ok() {
        assert!(validate_env_name("dev").is_ok());
        assert!(validate_env_name("staging-01").is_ok());
        assert!(validate_env_name("prod_v2").is_ok());
    }

    #[test]
    fn validate_env_name_rejects_slash() {
        assert!(validate_env_name("a/b").is_err());
    }

    #[test]
    fn validate_env_name_rejects_colon() {
        // Colon is the vault key separator — must not be allowed in env names.
        assert!(validate_env_name("a:b").is_err());
    }

    #[test]
    fn validate_env_name_rejects_empty() {
        assert!(validate_env_name("").is_err());
    }

    #[test]
    fn known_envs_includes_default_and_current() {
        let keys = vec!["dev:KEY".to_string(), "staging:KEY".to_string()];
        let envs = known_envs_from_keys(&keys, "prod");
        assert!(envs.contains(&"default".to_string()));
        assert!(envs.contains(&"dev".to_string()));
        assert!(envs.contains(&"staging".to_string()));
        assert!(envs.contains(&"prod".to_string()));
    }

    #[test]
    fn read_active_env_returns_default_when_missing() {
        let dir = tempfile::TempDir::new().unwrap();
        assert_eq!(read_active_env(dir.path()), DEFAULT_ENV);
    }

    #[test]
    fn write_and_read_active_env() {
        let dir = tempfile::TempDir::new().unwrap();
        write_active_env(dir.path(), "staging").unwrap();
        assert_eq!(read_active_env(dir.path()), "staging");
    }

    #[test]
    fn resolve_env_flag_overrides_file() {
        let dir = tempfile::TempDir::new().unwrap();
        write_active_env(dir.path(), "staging").unwrap();
        assert_eq!(resolve_env(dir.path(), Some("prod")), "prod");
        assert_eq!(resolve_env(dir.path(), None), "staging");
    }
}
