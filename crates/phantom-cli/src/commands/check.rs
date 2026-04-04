use anyhow::Result;
use colored::Colorize;
use phantom_core::dotenv::DotenvFile;
use phantom_core::token::PhantomToken;

/// Check for unprotected secrets in .env files and staged git files.
/// Returns exit code 1 if found. Designed to be used as a pre-commit hook.
///
/// When `staged_only` is true, skips .env file scanning and only checks
/// git-staged files for hardcoded secrets. This is faster for pre-commit hooks.
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
        let env_files = [".env", ".env.local", ".env.development", ".env.production"];

        for env_file in &env_files {
            let path = project_dir.join(env_file);
            if path.exists() {
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
                        "  {} {} has {} unprotected secret(s):",
                        "!".red().bold(),
                        env_file,
                        real_secrets.len()
                    );

                    for entry in &real_secrets {
                        eprintln!("    {} {}", "-".dimmed(), entry.key.bold());
                    }

                    issues += real_secrets.len();
                }
            }
        }
    }

    // Scan staged files for common secret patterns
    let staged = get_staged_files();
    for file in &staged {
        if file.ends_with(".env") || file.contains(".env.") || file.ends_with(".phantom.toml") {
            continue; // Already handled above or safe
        }

        // Check for hardcoded secrets in code files
        if let Ok(content) = std::fs::read_to_string(project_dir.join(file)) {
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

            for (pattern, label) in &secret_patterns {
                if content.contains(pattern) {
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
