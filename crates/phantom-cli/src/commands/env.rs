use anyhow::{Context, Result};
use colored::Colorize;
use phantom_core::config::PhantomConfig;
use phantom_core::dotenv::DotenvFile;
use phantom_core::token::PhantomToken;

/// Generate a .env.example file from the current .env.
/// Secret values are replaced with descriptive placeholders.
/// Non-secret values and public keys are preserved as-is.
pub fn run(output: &str) -> Result<()> {
    let project_dir = std::env::current_dir()?;
    run_in(&project_dir, output, || {})
}

fn run_in(project_dir: &std::path::Path, output: &str, after_lock: impl FnOnce()) -> Result<()> {
    let output_path = validated_output_path(project_dir, output)?;
    let transaction_lock = phantom_vault::acquire_project_transaction_lock(project_dir)
        .context("Failed to acquire the project transaction lock")?;
    after_lock();
    let output_target = transaction_lock.target(&output_path)?;
    if output_target
        .read_regular()
        .with_context(|| format!("Refusing unsafe output target: {}", output_path.display()))?
        .is_some()
    {
        anyhow::bail!(
            "Refusing to overwrite existing output {}. This command has no overwrite policy; choose a new filename.",
            output_path.display()
        );
    }
    let config_path = project_dir.join(".phantom.toml");
    let config = transaction_lock
        .target(&config_path)?
        .read_regular()?
        .and_then(|bytes| PhantomConfig::load_from_bytes(&config_path, bytes.bytes()).ok());
    let (_env_path, dotenv) = match config.as_ref() {
        Some(config) => resolve_dotenv_anchored(&transaction_lock, project_dir, config)?,
        None => {
            let path = project_dir.join(".env");
            let bytes = transaction_lock
                .target(&path)?
                .read_regular()?
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "No .env file found in current directory.\n  {}",
                        crate::util::docs_url("getting-started")
                    )
                })?;
            let content = std::str::from_utf8(bytes.bytes()).context("Failed to read .env")?;
            (path, Some(DotenvFile::parse_str(content)))
        }
    };
    let dotenv = dotenv.ok_or_else(|| {
        anyhow::anyhow!(
            "No .env file found in current directory.\n  {}",
            crate::util::docs_url("getting-started")
        )
    })?;
    let entries = dotenv.entries();

    if entries.is_empty() {
        println!("{} .env is empty.", "!".yellow().bold());
        return Ok(());
    }

    // Load config for service info if available
    // Use shared generation logic from phantom-core
    let content = dotenv.generate_example_content(config.as_ref());
    match output_target.replace_if_exact(None, content.as_bytes())? {
        phantom_core::fs::AnchoredEffect::Durable(_) => {}
        phantom_core::fs::AnchoredEffect::CommittedButUncertain { error, .. } => anyhow::bail!(
            "{} was created, but durability could not be verified: {error}",
            output_path.display()
        ),
    }

    let secret_count =
        dotenv.real_secret_entries().len() + entries.iter().filter(|e| e.is_phantom).count();
    let config_count = entries.len() - secret_count;

    println!(
        "{} Generated {} ({} secrets masked, {} config values preserved)",
        "ok".green().bold(),
        output.cyan(),
        secret_count,
        config_count
    );
    println!(
        "{} Share this file with your team for onboarding.",
        "->".blue().bold()
    );

    Ok(())
}

pub(super) fn resolve_dotenv_anchored(
    lock: &phantom_vault::ProjectTransactionLock,
    project_dir: &std::path::Path,
    config: &PhantomConfig,
) -> Result<(std::path::PathBuf, Option<DotenvFile>)> {
    let protected_state = !config.phantom.secrets.is_empty();
    if let Some(name) = config.phantom.dotenv_path.as_deref() {
        let name = phantom_core::managed_dotenv::validate_dotenv_basename(name)?;
        let (path, dotenv) = read_dotenv_anchored(lock, project_dir.join(name))?;
        if protected_state && !has_tokens(&dotenv) {
            anyhow::bail!(
                "Protected vault/config state exists, but {} contains no phantom tokens; refusing an unprotected direct launch",
                path.display()
            );
        }
        return Ok((path, Some(dotenv)));
    }

    let mut existing = Vec::new();
    let mut token_bearing = Vec::new();
    for name in [
        ".env",
        ".env.local",
        ".env.development",
        ".env.development.local",
    ] {
        let path = project_dir.join(name);
        let Some(bytes) = lock.target(&path)?.read_regular()? else {
            continue;
        };
        let content = std::str::from_utf8(bytes.bytes())
            .with_context(|| format!("Failed to read {}", path.display()))?;
        let dotenv = DotenvFile::parse_str(content);
        if dotenv
            .entries()
            .iter()
            .any(|entry| PhantomToken::is_phantom_token(&entry.value))
        {
            token_bearing.push((path.clone(), DotenvFile::parse_str(content)));
        }
        existing.push((path, dotenv));
    }
    if token_bearing.len() == 1 {
        let (path, dotenv) = token_bearing.pop().expect("length checked");
        return Ok((path, Some(dotenv)));
    }
    if token_bearing.len() > 1 {
        anyhow::bail!(
            "Legacy config has {} token-bearing dotenv files; rerun `phantom init --from <file>` to persist one explicit filename",
            token_bearing.len()
        );
    }
    if protected_state {
        anyhow::bail!(
            "Protected vault/config state exists, but no token-bearing dotenv file could be resolved; refusing an unprotected direct launch. Rerun `phantom init --from <file>` to persist the protected filename"
        );
    }
    Ok(existing
        .into_iter()
        .next()
        .map(|(path, dotenv)| (path, Some(dotenv)))
        .unwrap_or_else(|| (project_dir.join(".env"), None)))
}

fn has_tokens(dotenv: &DotenvFile) -> bool {
    dotenv
        .entries()
        .iter()
        .any(|entry| PhantomToken::is_phantom_token(&entry.value))
}

fn read_dotenv_anchored(
    lock: &phantom_vault::ProjectTransactionLock,
    path: std::path::PathBuf,
) -> Result<(std::path::PathBuf, DotenvFile)> {
    let bytes = lock.target(&path)?.read_regular()?.ok_or_else(|| {
        anyhow::anyhow!(
            "Configured protected dotenv does not exist: {}",
            path.display()
        )
    })?;
    let content = std::str::from_utf8(bytes.bytes())
        .with_context(|| format!("Failed to read {}", path.display()))?;
    Ok((path, DotenvFile::parse_str(content)))
}

fn validated_output_path(
    project_dir: &std::path::Path,
    output: &str,
) -> Result<std::path::PathBuf> {
    phantom_core::fs::validate_project_filename(output)
        .context("Invalid env-example output path")?;
    Ok(project_dir.join(output))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn output_is_one_project_relative_filename() {
        let root = std::path::Path::new("/project");
        assert_eq!(
            validated_output_path(root, ".env.example").unwrap(),
            root.join(".env.example")
        );
        for invalid in ["../owner", "nested/file", "nested\\file", "/tmp/owner"] {
            assert!(validated_output_path(root, invalid).is_err());
        }
    }

    #[test]
    fn configured_protected_dotenv_without_tokens_fails_closed() {
        let project = tempfile::tempdir().unwrap();
        std::fs::write(project.path().join("custom.env"), "API_KEY=plaintext\n").unwrap();
        let mut config = PhantomConfig::new_with_defaults("a".repeat(64));
        config.phantom.dotenv_path = Some("custom.env".to_string());
        config.phantom.secrets.insert(
            "API_KEY".to_string(),
            phantom_core::config::SecretOverride::default(),
        );
        let lock = phantom_vault::acquire_project_transaction_lock(project.path()).unwrap();

        let error = resolve_dotenv_anchored(&lock, project.path(), &config)
            .unwrap_err()
            .to_string();
        assert!(error.contains("refusing an unprotected direct launch"));
    }

    #[test]
    fn legacy_unprotected_config_preserves_missing_dotenv_result() {
        let project = tempfile::tempdir().unwrap();
        let config = PhantomConfig::new_with_defaults("a".repeat(64));
        let lock = phantom_vault::acquire_project_transaction_lock(project.path()).unwrap();

        let (path, dotenv) = resolve_dotenv_anchored(&lock, project.path(), &config).unwrap();
        assert_eq!(path, project.path().join(".env"));
        assert!(dotenv.is_none());
    }

    #[cfg(unix)]
    #[test]
    fn generation_uses_retained_root_after_rename() {
        let container = tempfile::tempdir().unwrap();
        let project = container.path().join("project");
        let moved = container.path().join("moved");
        std::fs::create_dir(&project).unwrap();
        std::fs::write(project.join(".env"), "API_KEY=sk_test_value\n").unwrap();

        run_in(&project, ".env.example", || {
            std::fs::rename(&project, &moved).unwrap();
            std::fs::create_dir(&project).unwrap();
            std::fs::write(project.join(".env"), "API_KEY=decoy\n").unwrap();
        })
        .unwrap();

        assert!(moved.join(".env.example").exists());
        assert!(!project.join(".env.example").exists());
        assert_eq!(
            std::fs::read_to_string(project.join(".env")).unwrap(),
            "API_KEY=decoy\n"
        );
    }
}
