use anyhow::{Context, Result};
use colored::Colorize;
use phantom_core::config::PhantomConfig;
use phantom_core::dotenv::DotenvFile;
use phantom_core::error::PhantomError;
use phantom_core::token::TokenMap;
use phantom_vault::{InitFile, InitSecret, VaultBackend};
use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use zeroize::{Zeroize, Zeroizing};

fn stdin_is_tty() -> bool {
    std::io::stdin().is_terminal()
}

struct AddPlan {
    mutation: InitSecret,
    files: Vec<InitFile>,
    env_path: PathBuf,
}

/// Add one secret through a single exact-before project transaction.
pub fn run(name: &str, value_arg: Option<String>, from_stdin: bool) -> Result<()> {
    if let Some(mut value) = value_arg {
        value.zeroize();
        anyhow::bail!(
            "Positional secret values are disabled because command-line arguments can be exposed by process inspection. Omit the value for a hidden terminal prompt, or use --stdin."
        );
    }
    validate_secret_name(name)?;

    let project_dir = std::env::current_dir()?
        .canonicalize()
        .context("Failed to resolve the current project directory")?;
    let config_path = project_dir.join(".phantom.toml");
    if !config_path.exists() {
        anyhow::bail!(
            "Project is not initialized. Run `phantom init --empty` first; `phantom add` will not create config, gitignore, or vault state outside its secret transaction."
        );
    }

    let (config, config_before) = load_config_exact(&config_path)?;
    let vault = phantom_vault::try_create_vault(config.local_project_id())?;
    ensure_secret_absent(vault.as_ref(), name)?;

    // Existing-name authority is resolved from value-blind vault metadata
    // before stdin or the hidden prompt is touched. A second check in
    // `prepare_add_plan` closes the race between this preflight and commit.
    let value = read_secret_value(name, from_stdin)?;
    let plan = prepare_add_plan(
        &project_dir,
        &config_path,
        config,
        config_before,
        vault.as_ref(),
        name,
        value.as_str(),
    )?;

    phantom_vault::commit_init(
        &project_dir,
        vault.as_ref(),
        vec![plan.mutation],
        plan.files,
    )
    .context(
        "Add transaction failed; exact transaction-owned state was rolled back where verifiable. Inspect the vault and managed dotenv before retrying.",
    )?;

    println!(
        "{} Stored {} in vault ({}) and updated {} (value never printed)",
        "ok".green().bold(),
        name.bold(),
        vault.backend_name().dimmed(),
        plan.env_path
            .file_name()
            .and_then(|part| part.to_str())
            .unwrap_or("managed dotenv")
            .cyan()
    );
    Ok(())
}

fn ensure_secret_absent(vault: &dyn VaultBackend, name: &str) -> Result<()> {
    let vault_names = vault.list().context("Failed to list protected secrets")?;
    if vault_names.iter().any(|existing| existing == name) {
        anyhow::bail!(
            "Secret '{name}' is already protected. `phantom add` creates new names only and refuses replacement before reading a value. Use the trusted-terminal `phantom remove {name}` ceremony first if you explicitly intend a separate, non-atomic remove-and-add sequence."
        );
    }
    Ok(())
}

fn read_secret_value(name: &str, from_stdin: bool) -> Result<Zeroizing<String>> {
    if from_stdin {
        let mut secret = Zeroizing::new(String::new());
        std::io::stdin()
            .read_line(&mut secret)
            .context("Failed to read value from stdin")?;
        while secret.ends_with(['\n', '\r']) {
            secret.pop();
        }
        if secret.is_empty() {
            anyhow::bail!("Received empty value on stdin — aborting.");
        }
        return Ok(secret);
    }
    if !stdin_is_tty() {
        anyhow::bail!(
            "stdin is not a terminal. Omit the value for a hidden prompt, or use {} to read it from a pipe.",
            "--stdin".cyan().bold()
        );
    }
    let secret = rpassword::prompt_password(format!("Value for {name}: "))
        .context("Failed to read secret interactively")?;
    if secret.is_empty() {
        anyhow::bail!("Empty value — aborting.");
    }
    Ok(Zeroizing::new(secret))
}

#[allow(clippy::too_many_arguments)]
fn prepare_add_plan(
    project_dir: &Path,
    config_path: &Path,
    mut config: PhantomConfig,
    config_before: Vec<u8>,
    vault: &dyn VaultBackend,
    name: &str,
    value: &str,
) -> Result<AddPlan> {
    let vault_names = vault.list().context("Failed to list protected secrets")?;
    if vault_names.iter().any(|existing| existing == name) {
        anyhow::bail!(
            "Secret '{name}' became protected during add preflight; refusing replacement"
        );
    }
    let resolved =
        phantom_core::managed_dotenv::resolve_dotenv(project_dir, &config, &vault_names)?;
    let env_path = resolved.path;
    let env_before = snapshot_regular_file(&env_path)?;
    let env_after = rewrite_dotenv(env_before.as_deref(), name)?;
    let before = snapshot_secret(vault, name)?;
    if before.is_some() {
        anyhow::bail!(
            "Secret '{name}' became protected during add preflight; refusing replacement"
        );
    }

    let mutation = InitSecret::replace_if_unchanged(name, None::<String>, value);
    let config_after = if config.phantom.dotenv_path.is_none() && vault_names.is_empty() {
        config.phantom.dotenv_path = Some(
            phantom_core::managed_dotenv::dotenv_basename(project_dir, &env_path)
                .context("Failed to persist the managed dotenv mapping")?,
        );
        toml::to_string_pretty(&config)
            .context("Failed to serialize managed dotenv configuration")?
            .into_bytes()
    } else {
        config_before.clone()
    };
    // Even when no config field changes, the exact no-op replacement keeps
    // config identity/lifecycle policy inside the same transaction boundary.
    let mut files = vec![InitFile::replace_if_unchanged(
        config_path,
        Some(config_before),
        config_after,
    )];
    files.push(InitFile::replace_if_unchanged(&env_path, env_before, env_after).commit_last());
    Ok(AddPlan {
        mutation,
        files,
        env_path,
    })
}

pub(super) fn validate_secret_name(name: &str) -> Result<()> {
    let mut bytes = name.bytes();
    if !matches!(bytes.next(), Some(b'A'..=b'Z' | b'a'..=b'z' | b'_'))
        || !bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    {
        anyhow::bail!(
            "Invalid secret name: expected an environment key matching [A-Za-z_][A-Za-z0-9_]*"
        );
    }
    Ok(())
}

pub(super) fn load_config_exact(path: &Path) -> Result<(PhantomConfig, Vec<u8>)> {
    let before = snapshot_regular_file(path)?.ok_or_else(|| {
        anyhow::anyhow!("Project is not initialized. Run `phantom init --empty` first.")
    })?;
    let config = PhantomConfig::load(path).context("Failed to load .phantom.toml")?;
    if snapshot_regular_file(path)?.as_deref() != Some(before.as_slice()) {
        anyhow::bail!(".phantom.toml changed during preflight; no secret was read or stored");
    }
    Ok((config, before))
}

pub(super) fn snapshot_secret(
    vault: &dyn VaultBackend,
    name: &str,
) -> Result<Option<Zeroizing<String>>> {
    match vault.retrieve(name) {
        Ok(value) => Ok(Some(value)),
        Err(PhantomError::SecretNotFound(_)) => Ok(None),
        Err(error) => Err(anyhow::anyhow!(
            "Failed to snapshot destination secret '{name}': {error}"
        )),
    }
}

pub(super) fn snapshot_regular_file(path: &Path) -> Result<Option<Vec<u8>>> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            anyhow::bail!(
                "Refusing {}: target must be a regular, non-symlink file or absent",
                path.display()
            )
        }
        Ok(_) => Ok(Some(std::fs::read(path).with_context(|| {
            format!("Failed to snapshot {}", path.display())
        })?)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).with_context(|| format!("Failed to inspect {}", path.display())),
    }
}

pub(super) fn rewrite_dotenv(before: Option<&[u8]>, name: &str) -> Result<Vec<u8>> {
    let mut content = Zeroizing::new(match before {
        Some(bytes) => String::from_utf8(bytes.to_vec())
            .context("Managed dotenv is not valid UTF-8; refusing to rewrite it")?,
        None => String::new(),
    });
    let dotenv = DotenvFile::parse_str(content.as_str());
    let mut tokens = TokenMap::new();
    let token = tokens.insert(name.to_string()).to_string();
    let mut after = if dotenv.entries().iter().any(|entry| entry.key == name) {
        let (rewritten, mut originals) = dotenv.rewrite_with_phantoms(&tokens);
        for original in originals.values_mut() {
            original.zeroize();
        }
        originals.clear();
        Zeroizing::new(rewritten)
    } else {
        if !content.is_empty() && !content.ends_with('\n') {
            content.push('\n');
        }
        content.push_str(&format!("{name}={token}\n"));
        Zeroizing::new(std::mem::take(&mut *content))
    };
    Ok(std::mem::take(&mut *after).into_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use phantom_core::error::Result as PhantomResult;
    use phantom_vault::file::FileVault;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tempfile::TempDir;

    struct AmbiguousCasVault {
        inner: FileVault,
        calls: AtomicUsize,
    }

    impl VaultBackend for AmbiguousCasVault {
        fn store(&self, name: &str, value: &str) -> PhantomResult<()> {
            self.inner.store(name, value)
        }
        fn retrieve(&self, name: &str) -> PhantomResult<Zeroizing<String>> {
            self.inner.retrieve(name)
        }
        fn delete(&self, name: &str) -> PhantomResult<()> {
            self.inner.delete(name)
        }
        fn compare_and_swap(
            &self,
            name: &str,
            expected: Option<&str>,
            replacement: Option<&str>,
        ) -> PhantomResult<bool> {
            let call = self.calls.fetch_add(1, Ordering::SeqCst);
            if call == 0 {
                let _ = self.inner.compare_and_swap(name, expected, replacement)?;
                return Err(PhantomError::VaultError(
                    "injected ambiguous CAS failure".to_string(),
                ));
            }
            self.inner.compare_and_swap(name, expected, replacement)
        }
        fn list(&self) -> PhantomResult<Vec<String>> {
            self.inner.list()
        }
        fn backend_name(&self) -> &str {
            "ambiguous-cas"
        }
    }

    fn initialized(dir: &TempDir) -> (PathBuf, PhantomConfig, Vec<u8>, FileVault) {
        let project = dir.path().canonicalize().unwrap();
        let config_path = project.join(".phantom.toml");
        PhantomConfig::new_with_defaults(PhantomConfig::project_id_from_path(&project))
            .save(&config_path)
            .unwrap();
        let (config, before) = load_config_exact(&config_path).unwrap();
        let vault = FileVault::new(
            &crate::test_support::canonical_tempdir_path(dir),
            "add-test",
            "passphrase".to_string(),
        )
        .unwrap();
        (config_path, config, before, vault)
    }

    #[test]
    fn stdin_tty_check_does_not_panic() {
        let _ = stdin_is_tty();
    }

    #[test]
    fn rejects_names_that_can_inject_dotenv_lines() {
        for name in ["", "A=B", "A\nB", "../A", "1KEY"] {
            assert!(validate_secret_name(name).is_err());
        }
        assert!(validate_secret_name("API_KEY_2").is_ok());
    }

    #[test]
    fn ambiguous_first_cas_rolls_back_config_and_new_dotenv() {
        let dir = TempDir::new().unwrap();
        let (config_path, config, before, inner) = initialized(&dir);
        let project = dir.path().canonicalize().unwrap();
        let original_config = std::fs::read(&config_path).unwrap();
        let vault = AmbiguousCasVault {
            inner,
            calls: AtomicUsize::new(0),
        };
        let plan = prepare_add_plan(
            &project,
            &config_path,
            config,
            before,
            &vault,
            "API_KEY",
            "secret-value",
        )
        .unwrap();

        assert!(
            phantom_vault::commit_init(&project, &vault, vec![plan.mutation], plan.files).is_err()
        );
        assert!(matches!(
            vault.retrieve("API_KEY"),
            Err(PhantomError::SecretNotFound(_))
        ));
        assert_eq!(std::fs::read(&config_path).unwrap(), original_config);
        assert!(!project.join(".env").exists());
    }

    #[test]
    fn dotenv_create_race_is_detected_before_vault_cas() {
        let dir = TempDir::new().unwrap();
        let (config_path, config, before, vault) = initialized(&dir);
        let project = dir.path().canonicalize().unwrap();
        let plan = prepare_add_plan(
            &project,
            &config_path,
            config,
            before,
            &vault,
            "API_KEY",
            "secret-value",
        )
        .unwrap();
        std::fs::write(project.join(".env"), "FOREIGN=owner\n").unwrap();

        assert!(
            phantom_vault::commit_init(&project, &vault, vec![plan.mutation], plan.files).is_err()
        );
        assert_eq!(
            std::fs::read_to_string(project.join(".env")).unwrap(),
            "FOREIGN=owner\n"
        );
        assert!(matches!(
            vault.retrieve("API_KEY"),
            Err(PhantomError::SecretNotFound(_))
        ));
    }

    #[test]
    fn config_drift_aborts_before_vault_or_dotenv_mutation() {
        let dir = TempDir::new().unwrap();
        let (config_path, config, before, vault) = initialized(&dir);
        let project = dir.path().canonicalize().unwrap();
        let plan = prepare_add_plan(
            &project,
            &config_path,
            config,
            before,
            &vault,
            "API_KEY",
            "secret-value",
        )
        .unwrap();
        let mut concurrent_config = std::fs::read(&config_path).unwrap();
        concurrent_config.extend_from_slice(b"\n# concurrent owner\n");
        std::fs::write(&config_path, &concurrent_config).unwrap();

        assert!(
            phantom_vault::commit_init(&project, &vault, vec![plan.mutation], plan.files).is_err()
        );
        assert_eq!(std::fs::read(&config_path).unwrap(), concurrent_config);
        assert!(!project.join(".env").exists());
        assert!(matches!(
            vault.retrieve("API_KEY"),
            Err(PhantomError::SecretNotFound(_))
        ));
    }

    #[test]
    fn plan_refuses_existing_name_without_rewriting_project_state() {
        let dir = TempDir::new().unwrap();
        let (config_path, config, before, vault) = initialized(&dir);
        let project = dir.path().canonicalize().unwrap();
        vault.store("API_KEY", "original-value").unwrap();
        let original_config = std::fs::read(&config_path).unwrap();

        let error = prepare_add_plan(
            &project,
            &config_path,
            config,
            before,
            &vault,
            "API_KEY",
            "unapproved-replacement",
        )
        .err()
        .expect("existing names must be denied");

        assert!(error.to_string().contains("refusing replacement"));
        assert_eq!(
            vault.retrieve("API_KEY").unwrap().as_str(),
            "original-value"
        );
        assert_eq!(std::fs::read(&config_path).unwrap(), original_config);
        assert!(!project.join(".env").exists());
    }
}
