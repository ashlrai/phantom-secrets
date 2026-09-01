mod config;
mod docs;
pub(crate) mod env;
mod hooks;
pub mod multi;
mod prompts;

use anyhow::{Context, Result};
use colored::Colorize;
use phantom_core::dotenv::{DotenvFile, SecretClassification};
use phantom_core::token::TokenMap;
use phantom_vault::{InitFile, InitReceipt, InitSecret, VaultBackend};
use std::path::Path;

fn commit_after_vault_provisioning(
    project_dir: &Path,
    vault: phantom_core::error::Result<Box<dyn VaultBackend>>,
    secrets: Vec<InitSecret>,
    files: Vec<InitFile>,
    commit_error: &'static str,
) -> Result<(InitReceipt, String)> {
    let vault = vault.context(
        "Vault provisioning failed before any project files were changed. Set \
         PHANTOM_VAULT_PASSPHRASE to a durable secret value and retry",
    )?;
    let backend_name = vault.backend_name().to_string();
    let receipt = phantom_vault::commit_init(project_dir, vault.as_ref(), secrets, files)
        .with_context(|| commit_error)?;
    Ok((receipt, backend_name))
}

/// `phantom init --empty`
///
/// Creates a valid `.phantom.toml` and an empty vault in the current directory
/// without requiring a `.env` file. Use this to bootstrap a brand-new project
/// before any secrets exist — then add secrets one at a time with `phantom add`.
pub fn run_empty() -> Result<()> {
    let cwd = std::env::current_dir()?;
    let config_path = cwd.join(".phantom.toml");

    if config_path.exists() {
        println!(
            "{} .phantom.toml already exists — nothing to do.",
            "!".yellow().bold()
        );
        return Ok(());
    }

    let project_id = phantom_core::config::PhantomConfig::project_id_from_path(&cwd);
    let phantom_config = phantom_core::config::PhantomConfig::new_with_defaults(project_id.clone());

    let mut files = vec![InitFile::replace(
        &config_path,
        toml::to_string_pretty(&phantom_config)?.into_bytes(),
    )];
    if let Some(file) = env::prepare_gitignore(&cwd)? {
        files.push(file);
    }
    commit_after_vault_provisioning(
        &cwd,
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
        .unwrap_or_else(|_| cwd.join(&project_dir));
    let config_path = project_dir.join(".phantom.toml");

    // Parse .env file
    println!("{} Reading {}...", "->".blue().bold(), env_path.display());
    let dotenv = DotenvFile::parse_file(&env_path).context("Failed to read .env file")?;

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

    let existing_protected_setup =
        config_path.exists() || dotenv.entries().iter().any(|e| e.is_phantom);
    // Preflight migration of any project-local Claude settings before touching
    // either a new secret or an already-protected project. This keeps reruns
    // useful for removing legacy network-capable MCP entries.
    let claude_setup = if !real_entries.is_empty() || existing_protected_setup {
        prompts::prepare_auto_setup_claude_code(&project_dir, &cwd)?
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
            if config_path.exists() {
                if let Some(file) = env::prepare_gitignore(&project_dir)? {
                    files.push(file);
                }
            }
            let mut prepared_hook = hooks::prepare_precommit_hook(&project_dir)?;
            if let Some(file) = prepared_hook.take_file() {
                files.push(file);
            }
            if let Some(prepared) = &claude_setup {
                if let Some(file) = prepared.transaction_file() {
                    files.push(file);
                }
            }
            let mut guidance = docs::prepare_guidance(&project_dir, &cwd)?;
            files.extend(guidance.take_files());
            let vault = if config_path.exists() {
                let config = phantom_core::config::PhantomConfig::load(&config_path)?;
                phantom_vault::try_create_vault(config.local_project_id())
            } else {
                let project_id =
                    phantom_core::config::PhantomConfig::project_id_from_path(&project_dir);
                phantom_vault::try_create_vault(&project_id)
            };
            commit_after_vault_provisioning(
                &project_dir,
                vault,
                Vec::new(),
                files,
                "Existing Phantom state was preserved, but local integration refresh is incomplete",
            )?;
            prepared_hook.finish();
            if let Some(prepared) = &claude_setup {
                prompts::finish_auto_setup_claude_code(prepared);
            }
            guidance.finish();
            prompts::detect_platforms(&project_dir, &cwd);
            if config_path.exists() {
                print_next_steps(&config_path);
            }
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
    let mut phantom_config = config::load_or_create(&project_dir, &config_path)?;
    config::apply_detected_services(&mut phantom_config, &real_entries);

    // Persist public key classifications
    if !public_entries.is_empty() {
        phantom_config.public_keys = public_entries.iter().map(|e| e.key.clone()).collect();
    }

    // Fully prepare every vault and file change before mutating any target.
    let mut token_map = TokenMap::new();
    let secrets = real_entries
        .iter()
        .map(|entry| {
            token_map.insert(entry.key.clone());
            InitSecret::new(entry.key.clone(), entry.value.clone())
        })
        .collect::<Vec<_>>();
    let (phantomized_env, mut originals) = dotenv.rewrite_with_phantoms(&token_map);
    for value in originals.values_mut() {
        use zeroize::Zeroize;
        value.zeroize();
    }
    originals.clear();

    let mut files = vec![
        InitFile::replace(&env_path, phantomized_env.into_bytes()).commit_last(),
        InitFile::replace(
            &config_path,
            toml::to_string_pretty(&phantom_config)?.into_bytes(),
        ),
    ];
    if let Some(file) = env::prepare_gitignore(&project_dir)? {
        files.push(file);
    }
    let example_path = project_dir.join(".env.example");
    let example_content = dotenv.generate_example_content(Some(&phantom_config));
    files.push(InitFile::replace(
        &example_path,
        example_content.into_bytes(),
    ));

    let mut prepared_hook = hooks::prepare_precommit_hook(&project_dir)?;
    if let Some(file) = prepared_hook.take_file() {
        files.push(file);
    }
    if let Some(prepared) = &claude_setup {
        if let Some(file) = prepared.transaction_file() {
            files.push(file);
        }
    }
    let mut guidance = docs::prepare_guidance(&project_dir, &cwd)?;
    files.extend(guidance.take_files());

    let (receipt, backend_name) = commit_after_vault_provisioning(
        &project_dir,
        phantom_vault::try_create_vault(phantom_config.local_project_id()),
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
    use phantom_core::error::PhantomError;
    use tempfile::tempdir;

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
}
