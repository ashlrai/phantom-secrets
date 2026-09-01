use anyhow::Result;
use colored::Colorize;
use phantom_core::config::PhantomConfig;
use phantom_core::dotenv::DotenvFile;
use phantom_core::token::PhantomToken;
use std::path::{Path, PathBuf};

/// Check for unprotected secrets in .env files and staged git files.
/// Returns exit code 1 if found. Designed to be used as a pre-commit hook.
///
/// When `staged_only` is true, checks staged content from the git index,
/// including staged .env files, so pre-commit hooks block newly staged secrets.
///
/// When `runtime` is true, scans the current environment for phantom tokens
/// that haven't been replaced (proxy not running).
pub fn run(staged_only: bool, runtime: bool) -> Result<()> {
    if runtime {
        return run_runtime_check();
    }

    let project_dir = std::env::current_dir()?;
    let mut issues = 0;

    // Check all .env files (skip when --staged flag is used for fast pre-commit)
    if !staged_only {
        for path in dotenv_scan_paths(&project_dir)? {
            let dotenv = DotenvFile::parse_file(&path)?;
            let real_secrets = dotenv.real_secret_entries();

            if !real_secrets.is_empty() {
                if issues == 0 {
                    eprintln!(
                        "\n{} Unprotected secrets detected!\n",
                        "BLOCKED".red().bold()
                    );
                }

                eprintln!(
                    "  {} {} has unprotected secret name(s):",
                    "!".red().bold(),
                    path.display()
                );

                for entry in &real_secrets {
                    eprintln!("    {} {}", "-".dimmed(), entry.key.bold());
                }

                issues += real_secrets.len();
            }
        }
    }

    // Scan staged files for .env secrets and common hardcoded secret patterns.
    let staged = get_staged_files();
    for file in &staged {
        let content = if staged_only {
            read_staged_file(file)
        } else {
            std::fs::read_to_string(project_dir.join(file)).ok()
        };

        if let Some(content) = content {
            if file.ends_with(".phantom.toml") {
                warn_on_config_risks(file, &content);
                continue;
            }

            if is_env_file(file) {
                let dotenv = DotenvFile::parse_str(&content);
                let real_secrets = dotenv.real_secret_entries();

                if !real_secrets.is_empty() {
                    if issues == 0 {
                        eprintln!(
                            "\n{} Unprotected secrets detected!\n",
                            "BLOCKED".red().bold()
                        );
                    }

                    eprintln!(
                        "  {} staged {} has unprotected secret name(s):",
                        "!".red().bold(),
                        file
                    );

                    for entry in &real_secrets {
                        eprintln!("    {} {}", "-".dimmed(), entry.key.bold());
                    }

                    issues += real_secrets.len();
                }
                continue;
            }

            let secret_patterns = [
                ("sk-", "OpenAI API key"),
                ("sk_live_", "Stripe live key"),
                ("sk_test_", "Stripe test key"),
                ("ghp_", "GitHub personal token"),
                ("github_pat_", "GitHub PAT"),
                ("glpat-", "GitLab PAT"),
                ("xoxb-", "Slack bot token"),
                ("xoxp-", "Slack user token"),
                ("AKIA", "AWS access key"),
            ];

            let scan_content = if staged_only {
                staged_added_lines(file).unwrap_or_default()
            } else {
                content
            };

            for (pattern, label) in &secret_patterns {
                if scan_content.contains(pattern) {
                    if issues == 0 {
                        eprintln!("\n{} Potential secrets in code!\n", "BLOCKED".red().bold());
                    }
                    eprintln!(
                        "  {} {} may contain {} ({})",
                        "!".red().bold(),
                        file,
                        label,
                        pattern
                    );
                    issues += 1;
                }
            }
        }
    }

    if issues > 0 {
        eprintln!(
            "\n{} Run {} to protect your secrets.",
            "fix".yellow().bold(),
            "phantom init".cyan().bold()
        );
        eprintln!(
            "{} Or use {} to bypass (not recommended).\n",
            "   ".yellow(),
            "git commit --no-verify".dimmed()
        );
        std::process::exit(1);
    }

    println!("{} No unprotected secrets found.", "ok".green().bold());
    Ok(())
}

fn dotenv_scan_paths(project_dir: &Path) -> Result<Vec<PathBuf>> {
    let mut candidates = vec![
        project_dir.join(".env"),
        project_dir.join(".env.local"),
        project_dir.join(".env.development"),
        project_dir.join(".env.production"),
    ];
    let config_path = project_dir.join(".phantom.toml");
    if config_path.exists() {
        let config = PhantomConfig::load(&config_path)?;
        if let Some(configured) = config.phantom.dotenv_path.as_deref() {
            let configured = phantom_core::managed_dotenv::validate_dotenv_basename(configured)?;
            candidates.push(project_dir.join(configured));
        }
    }

    let mut paths = Vec::new();
    for path in candidates {
        if paths.contains(&path) {
            continue;
        }
        match std::fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
                anyhow::bail!(
                    "Refusing dotenv scan target that is not a regular, non-symlink file: {}",
                    path.display()
                )
            }
            Ok(_) => paths.push(path),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(paths)
}

fn warn_on_config_risks(file: &str, content: &str) {
    let Ok(config) = toml::from_str::<PhantomConfig>(content) else {
        return;
    };

    let risks = config.service_risks();
    if risks.is_empty() {
        return;
    }

    eprintln!(
        "\n{} Risky Phantom service route(s) in {}:\n",
        "warn".yellow().bold(),
        file
    );
    for risk in risks {
        eprintln!(
            "  {} {}: {}",
            "!".yellow().bold(),
            risk.service.bold(),
            risk.message
        );
    }
    eprintln!(
        "\n{} Review .phantom.toml service mappings before running untrusted code.\n",
        "note".yellow().bold()
    );
}

fn is_env_file(file: &str) -> bool {
    file.rsplit('/')
        .next()
        .is_some_and(|name| name == ".env" || name.starts_with(".env.") || name.ends_with(".env"))
}

/// Check if the current environment has phantom tokens in API key variables
/// (meaning the proxy is not running and API calls will fail with auth errors).
fn run_runtime_check() -> Result<()> {
    let mut issues = 0;

    // Common env vars that hold API keys
    let api_key_vars = [
        "OPENAI_API_KEY",
        "ANTHROPIC_API_KEY",
        "STRIPE_SECRET_KEY",
        "SUPABASE_SERVICE_ROLE_KEY",
        "SUPABASE_ANON_KEY",
        "DATABASE_URL",
        "RESEND_API_KEY",
        "SENDGRID_API_KEY",
        "TWILIO_AUTH_TOKEN",
        "GITHUB_TOKEN",
        "CLOUDFLARE_API_TOKEN",
    ];

    for var_name in &api_key_vars {
        if let Ok(value) = std::env::var(var_name) {
            if PhantomToken::is_phantom_token(&value) {
                if issues == 0 {
                    eprintln!(
                        "\n{} Phantom tokens in environment (proxy not running)!\n",
                        "warn".yellow().bold()
                    );
                }
                eprintln!(
                    "  {} {} contains phantom token ({})",
                    "!".yellow().bold(),
                    var_name.bold(),
                    value.get(..12).unwrap_or(&value).dimmed()
                );
                issues += 1;
            }
        }
    }

    if issues > 0 {
        eprintln!(
            "\n{} Start the proxy with: {}",
            "fix".yellow().bold(),
            "phantom exec -- <your-command>".cyan().bold()
        );
        std::process::exit(1);
    }

    println!(
        "{} No phantom tokens in environment (proxy running or secrets injected).",
        "ok".green().bold()
    );
    Ok(())
}

fn get_staged_files() -> Vec<String> {
    std::process::Command::new("git")
        .args(["diff", "--cached", "--name-only", "--diff-filter=ACMR"])
        .output()
        .ok()
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|s| s.lines().map(String::from).collect())
        .unwrap_or_default()
}

fn read_staged_file(file: &str) -> Option<String> {
    std::process::Command::new("git")
        .args(["show", &format!(":{file}")])
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| String::from_utf8(output.stdout).ok())
}

fn staged_added_lines(file: &str) -> Option<String> {
    std::process::Command::new("git")
        .args(["diff", "--cached", "--unified=0", "--", file])
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|diff| {
            diff.lines()
                .filter_map(|line| {
                    line.strip_prefix('+')
                        .filter(|_| !line.starts_with("+++ "))
                        .map(str::to_string)
                })
                .collect::<Vec<_>>()
                .join("\n")
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn configured_custom_dotenv_is_scanned_for_real_secrets() {
        let dir = tempfile::tempdir().unwrap();
        let custom = dir.path().join("custom.env");
        std::fs::write(&custom, "OPENAI_API_KEY=example-secret-value\n").unwrap();
        let mut config = PhantomConfig::new_with_defaults("check-custom".to_string());
        config.phantom.dotenv_path = Some("custom.env".to_string());
        config.save(&dir.path().join(".phantom.toml")).unwrap();

        let paths = dotenv_scan_paths(dir.path()).unwrap();
        assert_eq!(paths, vec![custom.clone()]);
        let dotenv = DotenvFile::parse_file(&custom).unwrap();
        let names: Vec<_> = dotenv
            .real_secret_entries()
            .into_iter()
            .map(|entry| entry.key.as_str())
            .collect();
        assert_eq!(names, vec!["OPENAI_API_KEY"]);
    }

    #[test]
    fn configured_dotenv_traversal_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = PhantomConfig::new_with_defaults("check-traversal".to_string());
        config.phantom.dotenv_path = Some("../outside.env".to_string());
        config.save(&dir.path().join(".phantom.toml")).unwrap();
        assert!(dotenv_scan_paths(dir.path()).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn configured_dotenv_symlink_is_rejected() {
        use std::os::unix::fs::symlink;
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target.env");
        std::fs::write(&target, "OPENAI_API_KEY=example-secret-value\n").unwrap();
        symlink(&target, dir.path().join("custom.env")).unwrap();
        let mut config = PhantomConfig::new_with_defaults("check-symlink".to_string());
        config.phantom.dotenv_path = Some("custom.env".to_string());
        config.save(&dir.path().join(".phantom.toml")).unwrap();
        assert!(dotenv_scan_paths(dir.path()).is_err());
    }
}
