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
                    &config.phantom.project_id[..8]
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
