//! Value-free secret lookup shared by CLI and MCP. Never opens a vault.
use crate::{config::PhantomConfig, managed_dotenv};
use serde_json::{json, Value};
use std::path::Path;

/// `exists` means the exact name occurs in the managed dotenv, not that a
/// readable vault value exists. Expiry is configured metadata, not a grant.
pub fn get(project: &Path, config: Option<&PhantomConfig>, name: &str) -> anyhow::Result<Value> {
    anyhow::ensure!(
        !name.is_empty()
            && name.bytes().enumerate().all(|(i, c)| c == b'_'
                || c.is_ascii_alphabetic()
                || (i > 0 && c.is_ascii_digit())),
        "Expected an environment variable name"
    );
    let dotenv = match config {
        Some(config) => managed_dotenv::resolve_dotenv(project, config, &[])?.file,
        None => managed_dotenv::parse_regular_dotenv(project, ".env")?,
    };
    if let Some(file) = &dotenv {
        file.validate_for_mutation()?;
    }
    let exists = dotenv
        .as_ref()
        .is_some_and(|file| file.entries().iter().any(|entry| entry.key == name));
    let delivery = config.map(|config| config.exec_delivery_for_key(name));
    let expires_at = config
        .and_then(|config| config.phantom.secrets.get(name))
        .and_then(|secret| secret.expires_at);
    Ok(json!({
        "schema_version": 1,
        "name": name,
        "initialized": config.is_some(),
        "exists": exists,
        "existence_source": "managed_dotenv",
        "vault_inspected": false,
        "route": delivery.and_then(|delivery| delivery.upstream().map(str::to_owned)),
        "delivery_mode": delivery.map(|delivery| delivery.label()),
        "expires_at": expires_at,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lookup_is_value_free_and_delivery_matches_exec() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = PhantomConfig::new_with_defaults("metadata-test".into());
        let names = ["OPENAI_API_KEY", "DATABASE_URL", "UNROUTED_KEY"];
        let mapping = crate::token::PhantomToken::generate();
        std::fs::write(
            dir.path().join(".env"),
            names
                .iter()
                .map(|name| format!("{name}={}\n", mapping.as_str()))
                .collect::<String>(),
        )
        .unwrap();
        let policy = crate::config::SecretOverride {
            expires_at: Some(1),
            ..Default::default()
        };
        config.phantom.secrets.insert(names[0].into(), policy);
        for name in names {
            let report = get(dir.path(), Some(&config), name).unwrap();
            assert_eq!(report["exists"], true);
            assert_eq!(report["vault_inspected"], false);
            assert_eq!(
                report["delivery_mode"],
                config.exec_delivery_for_key(name).label()
            );
            assert_eq!(
                report["route"],
                json!(config.exec_delivery_for_key(name).upstream())
            );
            assert!(!report
                .to_string()
                .contains("fixture-value-must-stay-private"));
            assert!(!report.to_string().contains(mapping.as_str()));
            assert_eq!(report.as_object().unwrap().len(), 9);
        }
        assert_eq!(
            get(dir.path(), Some(&config), names[0]).unwrap()["expires_at"],
            1
        );
        assert_eq!(
            get(dir.path(), Some(&config), "MISSING").unwrap()["exists"],
            false
        );
        assert_eq!(
            get(dir.path(), None, names[0]).unwrap()["delivery_mode"],
            Value::Null
        );
        std::fs::write(
            dir.path().join(".env"),
            "OPENAI_API_KEY=fixture-value-must-stay-private\n",
        )
        .unwrap();
        let uninitialized = get(dir.path(), None, names[0]).unwrap();
        assert_eq!(uninitialized["exists"], true);
        assert!(!uninitialized
            .to_string()
            .contains("fixture-value-must-stay-private"));
    }

    #[test]
    fn configured_dotenv_and_refused_route_are_reported_without_mapping_contents() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = PhantomConfig::new_with_defaults("metadata-test".into());
        config.phantom.dotenv_path = Some("managed.env".into());
        let mapping = crate::token::PhantomToken::generate();
        std::fs::write(
            dir.path().join("managed.env"),
            format!("OPENAI_API_KEY={}\n", mapping.as_str()),
        )
        .unwrap();
        std::fs::write(dir.path().join(".env"), "OTHER_KEY=unused-fixture\n").unwrap();
        config.services.get_mut("openai").unwrap().header = Some("x-api-key".into());
        let report = get(dir.path(), Some(&config), "OPENAI_API_KEY").unwrap();
        assert_eq!(report["exists"], true);
        assert_eq!(report["delivery_mode"], "custom_route_refused");
        assert!(report["route"].is_null());
        assert!(!report.to_string().contains(mapping.as_str()));
        assert_eq!(
            get(dir.path(), Some(&config), "OTHER_KEY").unwrap()["exists"],
            false
        );
    }

    #[test]
    fn missing_files_and_invalid_names() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(get(dir.path(), None, "MISSING").unwrap()["exists"], false);
        for name in ["", " ", "A\nB", "1KEY", "KEY=value"] {
            assert!(get(dir.path(), None, name).is_err());
        }
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
    }

    #[cfg(unix)]
    #[test]
    fn refuses_symlinked_dotenv() {
        let dir = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink("missing", dir.path().join(".env")).unwrap();
        assert!(get(dir.path(), None, "KEY").is_err());
    }
}
