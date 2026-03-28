use anyhow::Result;
use colored::Colorize;
use phantom_core::config::PhantomConfig;
use phantom_core::dotenv::DotenvFile;

pub fn run() -> Result<()> {
    let project_dir = std::env::current_dir()?;
    let config_path = project_dir.join(".phantom.toml");
    let env_path = project_dir.join(".env");
    let mut issues = 0;

    println!("{}", "Phantom Doctor".bold().underline());
    println!();

    // Check 1: .phantom.toml exists
    if config_path.exists() {
        check_pass(".phantom.toml found");
        match PhantomConfig::load(&config_path) {
            Ok(config) => {
                check_pass(&format!(
                    "Config valid (project: {})",
                    config
                        .phantom
                        .project_id
                        .get(..8)
                        .unwrap_or(&config.phantom.project_id)
                ));

                // Check 2: Vault accessible
                let vault = phantom_vault::create_vault(&config.phantom.project_id);
                check_pass(&format!("Vault backend: {}", vault.backend_name()));

                match vault.list() {
                    Ok(names) => {
                        check_pass(&format!("{} secret(s) in vault", names.len()));
                    }
                    Err(e) => {
                        check_fail(&format!("Vault access failed: {e}"));
                        issues += 1;
                    }
                }

                // Check sync targets (inside config block to avoid re-parsing)
                if !config.sync.is_empty() {
                    check_pass(&format!("{} sync target(s) configured", config.sync.len()));
                } else {
                    check_info("No sync targets — add [[sync]] to .phantom.toml for deployment");
                }
            }
            Err(e) => {
                check_fail(&format!("Config parse error: {e}"));
                issues += 1;
            }
        }
    } else {
        check_warn("No .phantom.toml — run `phantom init`");
    }

    // Check 3: .env file
    if env_path.exists() {
        let dotenv = DotenvFile::parse_file(&env_path);
        match dotenv {
            Ok(dotenv) => {
                let entries = dotenv.entries();
                let real_secrets = dotenv.real_secret_entries();

                if real_secrets.is_empty() {
                    check_pass(&format!(
                        ".env has {} entries, all protected",
                        entries.len()
                    ));
                } else {
                    check_warn(&format!(
                        ".env has {} unprotected secret(s): {}",
                        real_secrets.len(),
                        real_secrets
                            .iter()
                            .map(|e| e.key.as_str())
                            .collect::<Vec<_>>()
                            .join(", ")
                    ));
                    issues += 1;
                }
            }
            Err(e) => {
                check_fail(&format!(".env parse error: {e}"));
                issues += 1;
            }
        }
    } else {
        check_info("No .env file in current directory");
    }

    // Check 4: .gitignore
    let gitignore_path = project_dir.join(".gitignore");
    if gitignore_path.exists() {
        let content = std::fs::read_to_string(&gitignore_path).unwrap_or_default();
        if content.lines().any(|l| l.trim() == ".env") {
            check_pass(".env is in .gitignore");
        } else {
            check_warn(".env is NOT in .gitignore — secrets could be committed!");
            issues += 1;
        }
    } else {
        check_warn("No .gitignore — consider adding one");
        issues += 1;
    }

    // Check 5: Claude Code MCP configuration
    let claude_settings = project_dir.join(".claude/settings.local.json");
    if claude_settings.exists() {
        let content = std::fs::read_to_string(&claude_settings).unwrap_or_default();
        if content.contains("phantom") {
            check_pass("Claude Code MCP server configured");
        } else {
            check_info("Claude Code settings exist but no Phantom MCP — run `phantom setup`");
        }
    } else {
        check_info("No Claude Code config — run `phantom setup` for auto-mode");
    }

    // Check 6: Pre-commit hook
    let pre_commit_config = project_dir.join(".pre-commit-config.yaml");
    let git_hook = project_dir.join(".git/hooks/pre-commit");
    if pre_commit_config.exists() {
        let content = std::fs::read_to_string(&pre_commit_config).unwrap_or_default();
        if content.contains("phantom") {
            check_pass("Pre-commit hook configured");
        } else {
            check_info("pre-commit config exists but no phantom hook");
        }
    } else if git_hook.exists() {
        let content = std::fs::read_to_string(&git_hook).unwrap_or_default();
        if content.contains("phantom") {
            check_pass("Git pre-commit hook includes phantom check");
        } else {
            check_info("Git pre-commit hook exists but no phantom check");
        }
    } else {
        check_info("No pre-commit hook — run `phantom check` before commits");
    }

    println!();
    if issues == 0 {
        println!("{} All checks passed!", "ok".green().bold());
    } else {
        println!("{} {} issue(s) found", "!".yellow().bold(), issues);
    }

    Ok(())
}

fn check_pass(msg: &str) {
    println!("  {} {}", "pass".green(), msg);
}

fn check_fail(msg: &str) {
    println!("  {} {}", "FAIL".red().bold(), msg);
}

fn check_warn(msg: &str) {
    println!("  {} {}", "warn".yellow(), msg);
}

fn check_info(msg: &str) {
    println!("  {} {}", "info".blue(), msg);
}
