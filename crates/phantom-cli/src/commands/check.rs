use anyhow::Result;
use colored::Colorize;
use phantom_core::dotenv::DotenvFile;

/// Check for unprotected secrets in .env files. Returns exit code 1 if found.
/// Designed to be used as a pre-commit hook.
pub fn run() -> Result<()> {
    let project_dir = std::env::current_dir()?;
    let mut issues = 0;

    // Check all .env files
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

    // Also scan staged files for common secret patterns
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

fn get_staged_files() -> Vec<String> {
    std::process::Command::new("git")
        .args(["diff", "--cached", "--name-only", "--diff-filter=ACMR"])
        .output()
        .ok()
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|s| s.lines().map(String::from).collect())
        .unwrap_or_default()
}
