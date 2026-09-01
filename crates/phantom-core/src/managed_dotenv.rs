use crate::config::PhantomConfig;
use crate::dotenv::DotenvFile;
use crate::token::PhantomToken;
use anyhow::{Context, Result};
use std::path::{Component, Path, PathBuf};

const KNOWN_DOTENV_NAMES: &[&str] = &[
    ".env",
    ".env.local",
    ".env.development",
    ".env.development.local",
];

#[derive(Debug)]
pub struct ResolvedDotenv {
    pub path: PathBuf,
    pub file: Option<DotenvFile>,
}

impl ResolvedDotenv {
    pub fn protected_keys(&self) -> Vec<String> {
        self.file
            .iter()
            .flat_map(DotenvFile::entries)
            .filter(|entry| PhantomToken::is_phantom_token(&entry.value))
            .map(|entry| entry.key.clone())
            .collect()
    }
}

/// Convert an init target into one repository-safe filename beside config.
pub fn dotenv_basename(project_dir: &Path, env_path: &Path) -> Result<String> {
    let parent = env_path
        .parent()
        .context("dotenv target has no parent directory")?
        .canonicalize()
        .context("Failed to resolve dotenv parent directory")?;
    let project = project_dir
        .canonicalize()
        .context("Failed to resolve Phantom project directory")?;
    if parent != project {
        anyhow::bail!("dotenv must be stored beside .phantom.toml");
    }
    validate_dotenv_basename(
        env_path
            .file_name()
            .and_then(|name| name.to_str())
            .context("dotenv filename must be valid UTF-8")?,
    )
}

pub fn validate_dotenv_basename(name: &str) -> Result<String> {
    let mut components = Path::new(name).components();
    let single =
        matches!(components.next(), Some(Component::Normal(_))) && components.next().is_none();
    if !single
        || name.is_empty()
        || name.len() > 255
        || matches!(name, "." | ".." | ".phantom.toml")
        || !(name == ".env" || name.starts_with(".env.") || name.ends_with(".env"))
    {
        anyhow::bail!(
            "invalid phantom.dotenv_path: expected one safe filename beside .phantom.toml"
        );
    }
    Ok(name.to_string())
}

fn parse_regular_dotenv(path: &Path) -> Result<Option<DotenvFile>> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error).with_context(|| format!("Failed to inspect {}", path.display()))
        }
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        anyhow::bail!(
            "Refusing dotenv path that is not a regular, non-symlink file: {}",
            path.display()
        );
    }
    DotenvFile::parse_file(path)
        .with_context(|| format!("Failed to read {}", path.display()))
        .map(Some)
}

fn has_tokens(dotenv: &DotenvFile) -> bool {
    dotenv
        .entries()
        .iter()
        .any(|entry| PhantomToken::is_phantom_token(&entry.value))
}

/// Resolve a managed dotenv. Repository config cannot escape the config
/// directory. Legacy configs may select exactly one token-bearing conventional
/// dotenv; protected state with no such file fails closed.
pub fn resolve_dotenv(
    project_dir: &Path,
    config: &PhantomConfig,
    vault_names: &[String],
) -> Result<ResolvedDotenv> {
    let protected_state = !vault_names.is_empty() || !config.phantom.secrets.is_empty();

    if let Some(configured) = config.phantom.dotenv_path.as_deref() {
        let path = project_dir.join(validate_dotenv_basename(configured)?);
        let file = parse_regular_dotenv(&path)?.ok_or_else(|| {
            anyhow::anyhow!(
                "Configured protected dotenv does not exist: {}",
                path.display()
            )
        })?;
        if protected_state && !has_tokens(&file) {
            anyhow::bail!(
                "Protected vault/config state exists, but {} contains no phantom tokens; refusing an unprotected direct launch",
                path.display()
            );
        }
        return Ok(ResolvedDotenv {
            path,
            file: Some(file),
        });
    }

    let mut existing = Vec::new();
    let mut token_bearing = Vec::new();
    for name in KNOWN_DOTENV_NAMES {
        let path = project_dir.join(name);
        if let Some(file) = parse_regular_dotenv(&path)? {
            if has_tokens(&file) {
                token_bearing.push(path.clone());
            }
            existing.push((path, file));
        }
    }
    match token_bearing.len() {
        1 => {
            let path = token_bearing.pop().expect("length checked");
            return Ok(ResolvedDotenv {
                file: parse_regular_dotenv(&path)?,
                path,
            });
        }
        count if count > 1 => anyhow::bail!(
            "Legacy config has {count} token-bearing dotenv files; rerun `phantom init --from <file>` to persist one explicit filename"
        ),
        _ => {}
    }
    if protected_state {
        anyhow::bail!(
            "Protected vault/config state exists, but no token-bearing dotenv file could be resolved; refusing an unprotected direct launch. Rerun `phantom init --from <file>` to persist the protected filename"
        );
    }
    let (path, file) = existing
        .into_iter()
        .next()
        .map(|(path, file)| (path, Some(file)))
        .unwrap_or_else(|| (project_dir.join(".env"), None));
    Ok(ResolvedDotenv { path, file })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_repository_controlled_path_traversal() {
        for bad in [
            "../.env",
            "nested/.env",
            "/tmp/.env",
            ".phantom.toml",
            "README.md",
        ] {
            assert!(validate_dotenv_basename(bad).is_err(), "accepted {bad}");
        }
        assert_eq!(
            validate_dotenv_basename("custom.env").unwrap(),
            "custom.env"
        );
    }

    #[test]
    fn protected_state_without_tokens_never_selects_direct_launch() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(".env"), "OPENAI_API_KEY=plaintext\n").unwrap();
        let config = PhantomConfig::new_with_defaults("a".repeat(64));
        let error = resolve_dotenv(dir.path(), &config, &["default/OPENAI_API_KEY".into()])
            .unwrap_err()
            .to_string();
        assert!(error.contains("refusing an unprotected direct launch"));
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlinked_dotenv() {
        use std::os::unix::fs::symlink;
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("target"), "A=1\n").unwrap();
        symlink("target", dir.path().join(".env")).unwrap();
        assert!(parse_regular_dotenv(&dir.path().join(".env"))
            .unwrap_err()
            .to_string()
            .contains("non-symlink"));
    }
}
