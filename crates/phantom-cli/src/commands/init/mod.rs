mod config;
mod docs;
pub(crate) mod env;
mod hooks;
pub mod multi;
mod prompts;

use anyhow::{Context, Result};
use colored::Colorize;
use phantom_core::dotenv::{DotenvFile, SecretClassification};
use phantom_core::error::PhantomError;
use phantom_core::fs::{AnchoredRead, FileIdentity, TrustedAnchor};
use phantom_core::token::TokenMap;
use phantom_vault::{InitFile, InitReceipt, InitSecret, VaultBackend};
use std::path::{Component, Path};
#[cfg(test)]
use zeroize::Zeroizing;

fn read_reviewed_project_file(
    project: &TrustedAnchor,
    relative: &Path,
    display_path: &Path,
) -> Result<Option<AnchoredRead>> {
    let mut components = relative.components();
    if !matches!(components.next(), Some(Component::Normal(_))) || components.next().is_some() {
        anyhow::bail!(
            "Initialization target {} is not one direct reviewed project child",
            display_path.display()
        );
    }
    project
        .target(relative)
        .with_context(|| format!("Failed to retain {}", display_path.display()))?
        .read_regular()
        .with_context(|| format!("Failed to safely inspect {}", display_path.display()))
}

fn commit_after_vault_provisioning(
    project_dir: &Path,
    reviewed_project_identity: FileIdentity,
    vault: phantom_core::error::Result<Box<dyn VaultBackend>>,
    secrets: Vec<InitSecret>,
    files: Vec<InitFile>,
    commit_error: &'static str,
) -> Result<(InitReceipt, String)> {
    commit_after_vault_provisioning_with(
        project_dir,
        reviewed_project_identity,
        vault,
        secrets,
        files,
        commit_error,
        || {},
    )
}

fn commit_after_vault_provisioning_with(
    project_dir: &Path,
    reviewed_project_identity: FileIdentity,
    vault: phantom_core::error::Result<Box<dyn VaultBackend>>,
    secrets: Vec<InitSecret>,
    files: Vec<InitFile>,
    commit_error: &'static str,
    before_commit: impl FnOnce(),
) -> Result<(InitReceipt, String)> {
    let vault = vault.context(
        "Vault provisioning failed before any project files were changed. Set \
         PHANTOM_VAULT_PASSPHRASE to a durable secret value and retry",
    )?;
    let backend_name = vault.backend_name().to_string();
    before_commit();
    let receipt = phantom_vault::commit_init_if_project_identity(
        project_dir,
        reviewed_project_identity,
        vault.as_ref(),
        secrets,
        files,
    )
    .with_context(|| commit_error)?;
    Ok((receipt, backend_name))
}

/// `phantom init --empty`
///
/// Creates a valid `.phantom.toml` and an empty vault in the current directory
/// without requiring a `.env` file. Use this to bootstrap a brand-new project
/// before any secrets exist — then add secrets one at a time with `phantom add`.
pub fn run_empty() -> Result<()> {
    let cwd = std::env::current_dir()?.canonicalize()?;
    let reviewed_project = TrustedAnchor::open(&cwd)
        .context("Failed to retain the reviewed project root for empty initialization")?;
    let reviewed_project_identity = reviewed_project.identity();
    let config_path = cwd.join(".phantom.toml");
    let config_before =
        read_reviewed_project_file(&reviewed_project, Path::new(".phantom.toml"), &config_path)?;
    if config_before.is_some() {
        println!(
            "{} .phantom.toml already exists — nothing to do.",
            "!".yellow().bold()
        );
        return Ok(());
    }

    let project_id = phantom_core::config::PhantomConfig::project_id_from_path(&cwd);
    let phantom_config = phantom_core::config::PhantomConfig::new_with_defaults(project_id.clone());

    let mut files = vec![InitFile::replace_if_exact_snapshot(
        &config_path,
        None,
        toml::to_string_pretty(&phantom_config)?.into_bytes(),
    )];
    if let Some(file) = env::prepare_gitignore(&cwd)? {
        files.push(file);
    }
    commit_after_vault_provisioning(
        &cwd,
        reviewed_project_identity,
        phantom_vault::try_create_vault(&project_id),
        Vec::new(),
        files,
        "Empty initialization failed; prior project state was preserved",
    )?;
    println!("{} Created .phantom.toml", "ok".green().bold());

    println!(
        "\n{} Empty vault initialised. Add secrets with:\n     {}",
        "done".green().bold(),
        "phantom add <NAME>".cyan().bold()
    );

    Ok(())
}

pub fn run(env_path_arg: &str) -> Result<()> {
    let cwd = std::env::current_dir()?;

    // Auto-detect .env file if the default wasn't found
    let env_path = if Path::new(env_path_arg).exists() {
        std::path::PathBuf::from(env_path_arg)
    } else {
        env::find_env_file(&cwd, env_path_arg).ok_or_else(|| {
            anyhow::anyhow!(
                "No .env file found.\n\
                 Checked: .env, .env.local, .env.development, .env.development.local\n\
                 (also searched immediate subdirectories)\n\n\
                 Create a .env file with your secrets, or specify one:\n\
                 {}",
                "phantom init --from .env.local".cyan().bold()
            )
        })?
    };
    // Transactions require stable, process-independent targets. Keep the
    // original dotenv path absolute instead of staging a relative `.env`
    // whose empty parent cannot be safely preflighted.
    let env_path = if env_path.is_absolute() {
        env_path
    } else {
        cwd.join(env_path)
    };

    // Config and project dir are based on where the .env file lives (not cwd)
    // Canonicalize for stable project IDs regardless of which directory user runs from
    let project_dir = env_path.parent().unwrap_or(&cwd).to_path_buf();
    let project_dir = project_dir
        .canonicalize()
        .context("Failed to resolve the initialization project root")?;
    let reviewed_project = TrustedAnchor::open(&project_dir)
        .context("Failed to retain the reviewed initialization project root")?;
    let reviewed_project_identity = reviewed_project.identity();
    let config_path = project_dir.join(".phantom.toml");

    let env_name = env_path
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("Dotenv path has no reviewed direct-child name"))?;
    let env_before = read_reviewed_project_file(&reviewed_project, Path::new(env_name), &env_path)?
        .ok_or_else(|| anyhow::anyhow!("Dotenv disappeared during preflight"))?;
    // Bind the transaction target to the canonical retained project spelling.
    // Windows can represent the same file as both `C:\...` and `\\?\C:\...`;
    // carrying the ambient spelling into the lexical containment check would
    // reject a file that was already reviewed as this exact direct child.
    let env_transaction_path = project_dir.join(env_name);
    let dotenv_basename =
        phantom_core::managed_dotenv::dotenv_basename(&project_dir, &env_transaction_path)?;

    println!("{} Reading {}...", "->".blue().bold(), env_path.display());
    let env_text =
        std::str::from_utf8(env_before.bytes()).context("Managed dotenv is not valid UTF-8")?;
    let dotenv = DotenvFile::parse_str(env_text);

    // Classify all entries
    let classified = dotenv.classified_entries();
    let real_entries: Vec<_> = classified
        .iter()
        .filter(|(_, c)| *c == SecretClassification::Secret)
        .map(|(e, _)| *e)
        .collect();
    let public_entries: Vec<_> = classified
        .iter()
        .filter(|(_, c)| *c == SecretClassification::PublicKey)
        .map(|(e, _)| *e)
        .collect();

    let config_before =
        read_reviewed_project_file(&reviewed_project, Path::new(".phantom.toml"), &config_path)?;
    let existing_protected_setup =
        config_before.is_some() || dotenv.entries().iter().any(|e| e.is_phantom);
    // Preflight migration of any project-local Claude settings before touching
    // either a new secret or an already-protected project. This keeps reruns
    // useful for removing legacy network-capable MCP entries.
    let claude_setup = if !real_entries.is_empty() || existing_protected_setup {
        prompts::prepare_auto_setup_claude_code(&project_dir)?
    } else {
        None
    };

    if real_entries.is_empty() {
        println!(
            "{} No real secrets found in {} (all values are already phantom tokens, public keys, or config)",
            "!".yellow().bold(),
            env_path.display()
        );
        if !public_entries.is_empty() {
            println!(
                "\n{} {} public key(s) detected (safe for browser bundles, not protected):",
                "->".blue().bold(),
                public_entries.len()
            );
            for entry in &public_entries {
                println!("   {} {}", "·".dimmed(), entry.key);
            }
        }

        if existing_protected_setup {
            let mut files = Vec::new();
            let mut existing_config = config::load_or_create(
                &project_dir,
                &config_path,
                config_before.as_ref().map(AnchoredRead::bytes),
            )?;
            existing_config.phantom.dotenv_path = Some(dotenv_basename.clone());
            let vault_project_id = existing_config.local_project_id().to_string();
            files.push(InitFile::replace_if_exact_snapshot(
                &config_path,
                config_before.as_ref(),
                toml::to_string_pretty(&existing_config)?.into_bytes(),
            ));
            if let Some(file) = env::prepare_gitignore(&project_dir)? {
                files.push(file);
            }
            let mut prepared_hook = hooks::prepare_precommit_hook(&project_dir)?;
            if let Some(prepared) = &claude_setup {
                if let Some(file) = prepared.transaction_file() {
                    files.push(file);
                }
            }
            let mut guidance = docs::prepare_guidance(&project_dir)?;
            files.extend(guidance.take_files());
            let vault = phantom_vault::try_create_vault(&vault_project_id);
            commit_after_vault_provisioning(
                &project_dir,
                reviewed_project_identity,
                vault,
                Vec::new(),
                files,
                "Existing Phantom state was preserved, but local integration refresh is incomplete",
            )?;
            prepared_hook.commit().with_context(|| {
                "Project files were committed, but the separate Git pre-commit hook transaction is incomplete; project changes were not rolled back"
            })?;
            prepared_hook.finish();
            if let Some(prepared) = &claude_setup {
                prompts::finish_auto_setup_claude_code(prepared);
            }
            guidance.finish();
            prompts::detect_platforms(&project_dir, &cwd);
            print_next_steps(&config_path);
            println!(
                "{} Existing Phantom setup checked and local integrations refreshed without rotating tokens.",
                "ok".green().bold()
            );
        }
        return Ok(());
    }

    println!(
        "{} Found {} secret(s) to protect:",
        "->".blue().bold(),
        real_entries.len()
    );
    for entry in &real_entries {
        println!("   {} {}", "+".cyan().bold(), entry.key.bold());
    }

    if !public_entries.is_empty() {
        println!(
            "\n{} Skipping {} public key(s) (safe for browser bundles):",
            "->".blue().bold(),
            public_entries.len()
        );
        for entry in &public_entries {
            println!("   {} {}", "·".dimmed(), entry.key);
        }
        println!("   Override with: {}", "phantom add <KEY>".dimmed());
    }

    // Load or create config, then auto-detect services
    let mut phantom_config = config::load_or_create(
        &project_dir,
        &config_path,
        config_before.as_ref().map(AnchoredRead::bytes),
    )?;
    phantom_config.phantom.dotenv_path = Some(dotenv_basename);
    config::apply_detected_services(&mut phantom_config, &real_entries);

    // Persist public key classifications
    if !public_entries.is_empty() {
        phantom_config.public_keys = public_entries.iter().map(|e| e.key.clone()).collect();
    }

    // Fully prepare every vault and file change before mutating any target.
    let mut token_map = TokenMap::new();
    for entry in &real_entries {
        token_map.insert(entry.key.clone());
    }
    let (phantomized_env, mut originals) = dotenv.rewrite_with_phantoms(&token_map);
    for value in originals.values_mut() {
        use zeroize::Zeroize;
        value.zeroize();
    }
    originals.clear();

    let mut files = vec![
        InitFile::replace_if_exact_snapshot(
            &env_transaction_path,
            Some(&env_before),
            phantomized_env.into_bytes(),
        )
        .commit_last(),
        InitFile::replace_if_exact_snapshot(
            &config_path,
            config_before.as_ref(),
            toml::to_string_pretty(&phantom_config)?.into_bytes(),
        ),
    ];
    if let Some(file) = env::prepare_gitignore(&project_dir)? {
        files.push(file);
    }
    let example_path = project_dir.join(".env.example");
    let example_content = dotenv.generate_example_content(Some(&phantom_config));
    let example_before = phantom_core::fs::read_regular_file(&example_path)
        .with_context(|| format!("Failed to safely inspect {}", example_path.display()))?;
    files.push(InitFile::replace_if_unchanged(
        &example_path,
        example_before,
        example_content.into_bytes(),
    ));

    let mut prepared_hook = hooks::prepare_precommit_hook(&project_dir)?;
    if let Some(prepared) = &claude_setup {
        if let Some(file) = prepared.transaction_file() {
            files.push(file);
        }
    }
    let mut guidance = docs::prepare_guidance(&project_dir)?;
    files.extend(guidance.take_files());

    let vault = phantom_vault::try_create_vault(phantom_config.local_project_id()).context(
        "Vault provisioning failed before any project files were changed. Set PHANTOM_VAULT_PASSPHRASE to a durable secret value and retry",
    )?;
    let secrets = real_entries
        .iter()
        .map(|entry| {
            let before = match vault.retrieve(&entry.key) {
                Ok(value) => Some(value),
                Err(PhantomError::SecretNotFound(_)) => None,
                Err(error) => {
                    return Err(anyhow::anyhow!(
                        "Failed to snapshot vault entry '{}': {error}",
                        entry.key
                    ));
                }
            };
            Ok(InitSecret::replace_if_unchanged(
                entry.key.clone(),
                before.as_ref().map(|value| value.as_str().to_string()),
                entry.value.clone(),
            ))
        })
        .collect::<Result<Vec<_>>>()?;
    let (receipt, backend_name) = commit_after_vault_provisioning(
        &project_dir,
        reviewed_project_identity,
        Ok(vault),
        secrets,
        files,
        "Initialization failed; inspect the reported rollback status before retrying",
    )?;
    println!(
        "{} Using {} vault backend",
        "->".blue().bold(),
        backend_name.cyan()
    );
    for name in &receipt.secret_names {
        let token = token_map
            .get_token(name)
            .expect("every committed secret has a staged token");
        println!(
            "   {} {} -> {}",
            "+".green().bold(),
            name.bold(),
            token.as_str()[..12].dimmed()
        );
    }
    println!(
        "\n{} Rewrote {} with phantom tokens",
        "ok".green().bold(),
        env_path.display()
    );
    println!("{} Saved .phantom.toml", "ok".green().bold());
    println!(
        "{} Generated {} (commit this for team onboarding)",
        "ok".green().bold(),
        ".env.example".cyan()
    );

    prepared_hook.commit().with_context(|| {
        "Project files and vault entries were committed, but the separate Git pre-commit hook transaction is incomplete; project changes were not rolled back"
    })?;
    prepared_hook.finish();

    println!(
        "\n{} {} secret(s) are now protected!",
        "done".green().bold(),
        real_entries.len()
    );

    if let Some(prepared) = &claude_setup {
        prompts::finish_auto_setup_claude_code(prepared);
    }
    guidance.finish();

    // Detect deployment platforms and suggest sync setup
    prompts::detect_platforms(&project_dir, &cwd);

    print_next_steps(&config_path);

    Ok(())
}

/// Print a contextual "what's next?" block. Items are conditional on
/// state — e.g., we don't suggest `phantom login` if the user is already
/// authenticated, and we promote `phantom cloud push` instead if they
/// have credentials but no cloud version yet.
fn print_next_steps(config_path: &Path) {
    use phantom_core::auth;
    use phantom_core::config::PhantomConfig;

    let logged_in = auth::load_token().is_some();
    let has_cloud_version = PhantomConfig::load(config_path)
        .ok()
        .and_then(|c| c.cloud)
        .is_some();

    println!("\n{}", "What's next?".bold());

    let mut step = 1;
    let mut item = |label: &str, command: &str| {
        println!(
            "  {}. {}\n     {}",
            step.to_string().bold(),
            label,
            command.cyan().bold()
        );
        step += 1;
    };

    item(
        "Run code with secret injection:",
        "phantom exec -- <your-command>",
    );
    item("Verify everything looks healthy:", "phantom doctor");

    if !logged_in {
        item(
            "Sign in to Phantom Cloud (optional, for E2E-encrypted backups):",
            "phantom login",
        );
    } else if !has_cloud_version {
        item("Back up this vault to Phantom Cloud:", "phantom cloud push");
    }

    item("Open your dashboard:", "phantom open");
    item(
        "Block raw-secret commits (recommended for teams):",
        "pre-commit install   # uses .pre-commit-hooks.yaml shipped with phantom",
    );
    item(
        "Other AI tools (Cursor, Windsurf, Codex):",
        "phantom setup --client cursor|windsurf|codex|claude   # --print to stdout",
    );

    println!();
}

#[cfg(test)]
mod tests {
    use super::*;
    use phantom_core::error::{PhantomError, Result as PhantomResult};
    use phantom_vault::file::FileVault;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tempfile::tempdir;

    struct FailNthCasVault {
        inner: FileVault,
        calls: AtomicUsize,
        fail_at: usize,
    }

    impl VaultBackend for FailNthCasVault {
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
            let result = self.inner.compare_and_swap(name, expected, replacement)?;
            if call == self.fail_at {
                return Err(PhantomError::VaultError(
                    "injected ambiguous init CAS failure".to_string(),
                ));
            }
            Ok(result)
        }
        fn list(&self) -> PhantomResult<Vec<String>> {
            self.inner.list()
        }
        fn backend_name(&self) -> &str {
            "fail-nth-init"
        }
    }

    #[test]
    fn init_entrypoints_bind_commit_to_the_preopened_project_identity() {
        let source = include_str!("mod.rs");
        let empty = source
            .split("pub fn run_empty()")
            .nth(1)
            .unwrap()
            .split("pub fn run(env_path_arg")
            .next()
            .unwrap();
        assert!(empty.contains("TrustedAnchor::open(&cwd)"));
        assert!(empty.contains("reviewed_project_identity"));

        let regular = source
            .split("pub fn run(env_path_arg")
            .nth(1)
            .unwrap()
            .split("/// Print a contextual")
            .next()
            .unwrap();
        assert!(regular.contains("TrustedAnchor::open(&project_dir)"));
        assert!(regular.contains("prepare_auto_setup_claude_code(&project_dir)"));
        assert_eq!(
            regular.matches("prepare_guidance(&project_dir)").count(),
            2,
            "both init branches must keep mutating guidance inside the reviewed project"
        );
        assert!(!regular.contains("prepare_guidance(&project_dir, &cwd)"));
        assert_eq!(
            regular.matches("reviewed_project_identity,").count(),
            2,
            "both protected-state refresh and secret-bearing init must bind the reviewed root"
        );
    }

    #[test]
    fn vault_provisioning_failure_cannot_commit_tokenized_dotenv() {
        let directory = tempdir().unwrap();
        let env_path = directory.path().join(".env");
        let original = b"API_KEY=real-provider-value\n";
        std::fs::write(&env_path, original).unwrap();
        let staged_files =
            vec![InitFile::replace(&env_path, b"API_KEY=phm_staged\n".to_vec()).commit_last()];
        let provisioning_failure = Err(PhantomError::VaultError(
            "secure passphrase persistence failed".to_string(),
        ));

        let error = commit_after_vault_provisioning(
            directory.path(),
            TrustedAnchor::open(directory.path()).unwrap().identity(),
            provisioning_failure,
            vec![InitSecret::new("API_KEY", "real-provider-value")],
            staged_files,
            "transaction must not start",
        )
        .unwrap_err();

        assert!(error
            .to_string()
            .contains("before any project files were changed"));
        assert_eq!(std::fs::read(&env_path).unwrap(), original);
    }

    #[cfg(unix)]
    #[test]
    fn empty_init_rejects_a_same_path_root_replacement_before_create() {
        let container = tempdir().unwrap();
        let project = container.path().join("project");
        let moved = container.path().join("moved");
        let vault_dir = container.path().join("vault");
        std::fs::create_dir(&project).unwrap();
        let reviewed = TrustedAnchor::open(&project).unwrap();
        let vault = FileVault::new(
            &vault_dir,
            "empty-root-replacement",
            "passphrase".to_string(),
        )
        .unwrap();

        let error = commit_after_vault_provisioning_with(
            &project,
            reviewed.identity(),
            Ok(Box::new(vault)),
            Vec::new(),
            vec![InitFile::replace_if_unchanged(
                project.join(".phantom.toml"),
                None::<Vec<u8>>,
                b"[phantom]\nproject_id = \"reviewed\"\n".to_vec(),
            )],
            "empty init rejected root replacement",
            || {
                std::fs::rename(&project, &moved).unwrap();
                std::fs::create_dir(&project).unwrap();
            },
        )
        .unwrap_err();

        assert!(
            format!("{error:#}").contains("project root identity changed"),
            "{error:#}"
        );
        assert!(!project.join(".phantom.toml").exists());
        assert!(!moved.join(".phantom.toml").exists());
    }

    #[cfg(unix)]
    #[test]
    fn dotenv_init_rejects_a_byte_identical_same_path_root_decoy() {
        let container = tempdir().unwrap();
        let project = container.path().join("project");
        let moved = container.path().join("moved");
        let vault_dir = container.path().join("vault");
        std::fs::create_dir(&project).unwrap();
        let env_path = project.join(".env");
        let before = b"API_KEY=real-provider-value\n".to_vec();
        std::fs::write(&env_path, &before).unwrap();
        let reviewed = TrustedAnchor::open(&project).unwrap();
        let vault = FileVault::new(
            &vault_dir,
            "dotenv-root-replacement",
            "passphrase".to_string(),
        )
        .unwrap();

        let error = commit_after_vault_provisioning_with(
            &project,
            reviewed.identity(),
            Ok(Box::new(vault)),
            vec![InitSecret::replace_if_unchanged(
                "API_KEY",
                None::<String>,
                "real-provider-value",
            )],
            vec![InitFile::replace_if_unchanged(
                &env_path,
                Some(before.clone()),
                b"API_KEY=phm_staged\n".to_vec(),
            )
            .commit_last()],
            "dotenv init rejected root replacement",
            || {
                std::fs::rename(&project, &moved).unwrap();
                std::fs::create_dir(&project).unwrap();
                std::fs::write(project.join(".env"), &before).unwrap();
            },
        )
        .unwrap_err();

        assert!(
            format!("{error:#}").contains("project root identity changed"),
            "{error:#}"
        );
        assert_eq!(std::fs::read(project.join(".env")).unwrap(), before);
        assert_eq!(std::fs::read(moved.join(".env")).unwrap(), before);
        let verify = FileVault::new(
            &vault_dir,
            "dotenv-root-replacement",
            "passphrase".to_string(),
        )
        .unwrap();
        assert!(matches!(
            verify.retrieve("API_KEY"),
            Err(PhantomError::SecretNotFound(_))
        ));
    }

    #[cfg(unix)]
    #[test]
    fn dotenv_init_rejects_a_byte_identical_same_root_file_decoy() {
        let container = tempdir().unwrap();
        let project = container.path().join("project");
        let vault_dir = container.path().join("vault");
        std::fs::create_dir(&project).unwrap();
        let env_path = project.join(".env");
        let moved = project.join(".env.reviewed");
        let before = b"API_KEY=real-provider-value\n";
        std::fs::write(&env_path, before).unwrap();
        let reviewed_project = TrustedAnchor::open(&project).unwrap();
        let reviewed_env = reviewed_project
            .target(".env")
            .unwrap()
            .read_regular()
            .unwrap()
            .unwrap();
        let vault = FileVault::new(
            &vault_dir,
            "dotenv-file-replacement",
            "passphrase".to_string(),
        )
        .unwrap();

        let error = commit_after_vault_provisioning_with(
            &project,
            reviewed_project.identity(),
            Ok(Box::new(vault)),
            vec![InitSecret::replace_if_unchanged(
                "API_KEY",
                None::<String>,
                "real-provider-value",
            )],
            vec![InitFile::replace_if_exact_snapshot(
                &env_path,
                Some(&reviewed_env),
                b"API_KEY=phm_staged\n".to_vec(),
            )
            .commit_last()],
            "dotenv init rejected file replacement",
            || {
                std::fs::rename(&env_path, &moved).unwrap();
                std::fs::write(&env_path, before).unwrap();
            },
        )
        .unwrap_err();

        assert!(format!("{error:#}").contains("changed concurrently"));
        assert_eq!(std::fs::read(&env_path).unwrap(), before);
        assert_eq!(std::fs::read(&moved).unwrap(), before);
        let verify = FileVault::new(
            &vault_dir,
            "dotenv-file-replacement",
            "passphrase".to_string(),
        )
        .unwrap();
        assert!(matches!(
            verify.retrieve("API_KEY"),
            Err(PhantomError::SecretNotFound(_))
        ));
    }

    #[test]
    fn config_drift_aborts_before_vault_or_dotenv_mutation() {
        let directory = tempdir().unwrap();
        let config_path = directory.path().join(".phantom.toml");
        let env_path = directory.path().join(".env");
        let config_before = b"[phantom]\nproject_id = \"owner\"\n".to_vec();
        let env_before = b"API_KEY=real-provider-value\n".to_vec();
        std::fs::write(&config_path, &config_before).unwrap();
        std::fs::write(&env_path, &env_before).unwrap();
        let vault = FileVault::new(
            &crate::test_support::canonical_tempdir_path(&directory),
            "init-config-drift",
            "passphrase".to_string(),
        )
        .unwrap();
        let files = vec![
            InitFile::replace_if_unchanged(
                &config_path,
                Some(config_before),
                b"[phantom]\nproject_id = \"phantom\"\n".to_vec(),
            ),
            InitFile::replace_if_unchanged(
                &env_path,
                Some(env_before.clone()),
                b"API_KEY=phm_staged\n".to_vec(),
            )
            .commit_last(),
        ];
        let concurrent = b"[phantom]\nproject_id = \"concurrent\"\n";
        std::fs::write(&config_path, concurrent).unwrap();

        assert!(phantom_vault::commit_init(
            directory.path(),
            &vault,
            vec![InitSecret::replace_if_unchanged(
                "API_KEY",
                None::<String>,
                "real-provider-value",
            )],
            files,
        )
        .is_err());
        assert_eq!(std::fs::read(&config_path).unwrap(), concurrent);
        assert_eq!(std::fs::read(&env_path).unwrap(), env_before);
        assert!(matches!(
            vault.retrieve("API_KEY"),
            Err(PhantomError::SecretNotFound(_))
        ));
    }

    #[test]
    fn nth_ambiguous_vault_failure_rolls_back_all_secrets_and_plaintext_env() {
        let directory = tempdir().unwrap();
        let env_path = directory.path().join(".env");
        let env_before = b"A=source-a\nB=source-b\n".to_vec();
        std::fs::write(&env_path, &env_before).unwrap();
        let inner = FileVault::new(
            &crate::test_support::canonical_tempdir_path(&directory),
            "init-nth-failure",
            "passphrase".to_string(),
        )
        .unwrap();
        let vault = FailNthCasVault {
            inner,
            calls: AtomicUsize::new(0),
            fail_at: 1,
        };

        let result = phantom_vault::commit_init(
            directory.path(),
            &vault,
            vec![
                InitSecret::replace_if_unchanged("A", None::<String>, "source-a"),
                InitSecret::replace_if_unchanged("B", None::<String>, "source-b"),
            ],
            vec![InitFile::replace_if_unchanged(
                &env_path,
                Some(env_before.clone()),
                b"A=phm_a\nB=phm_b\n".to_vec(),
            )
            .commit_last()],
        );

        assert!(result.is_err());
        assert_eq!(std::fs::read(&env_path).unwrap(), env_before);
        for name in ["A", "B"] {
            assert!(matches!(
                vault.retrieve(name),
                Err(PhantomError::SecretNotFound(_))
            ));
        }
    }
}
