use anyhow::{Context, Result};
use colored::Colorize;
use phantom_core::config::PhantomConfig;
use phantom_core::dotenv::DotenvFile;
use phantom_core::token::PhantomToken;

/// Generate a .env.example file from the current .env.
/// Secret values are replaced with descriptive placeholders.
/// Non-secret values are preserved as-is.
pub fn run(output: &str) -> Result<()> {
    let project_dir = std::env::current_dir()?;
    let env_path = project_dir.join(".env");
    let output_path = project_dir.join(output);

    if !env_path.exists() {
        anyhow::bail!("No .env file found in current directory.");
    }

    let dotenv = DotenvFile::parse_file(&env_path).context("Failed to read .env")?;
    let entries = dotenv.entries();

    if entries.is_empty() {
        println!("{} .env is empty.", "!".yellow().bold());
        return Ok(());
    }

    // Load config for service info if available
    let config_path = project_dir.join(".phantom.toml");
    let config = PhantomConfig::load(&config_path).ok();

    let mut output_lines: Vec<String> = Vec::new();

    // Read the raw .env to preserve comments and structure
    let raw_content = std::fs::read_to_string(&env_path)?;
    for line in raw_content.lines() {
        let trimmed = line.trim();

        // Preserve comments and blank lines
        if trimmed.is_empty() || trimmed.starts_with('#') {
            output_lines.push(line.to_string());
            continue;
        }

        // Parse key=value
        if let Some(eq_pos) = trimmed.find('=') {
            let key = trimmed[..eq_pos].trim();
            let key_clean = key.strip_prefix("export ").unwrap_or(key);
            let value = trimmed[eq_pos + 1..].trim();

            if PhantomToken::is_phantom_token(value) {
                // This is a phantom-protected secret — use a placeholder
                let placeholder = generate_placeholder(key_clean, config.as_ref());
                output_lines.push(format!("{}={}", key, placeholder));
            } else if is_likely_secret_value(value) {
                // Real secret that hasn't been phantomized — still mask it
                let placeholder = generate_placeholder(key_clean, config.as_ref());
                output_lines.push(format!("{}={}", key, placeholder));
            } else {
                // Non-secret config value — preserve as-is
                output_lines.push(line.to_string());
            }
        } else {
            output_lines.push(line.to_string());
        }
    }

    let content = output_lines.join("\n");
    std::fs::write(&output_path, &content)?;

    let secret_count = entries
        .iter()
        .filter(|e| e.is_phantom || is_likely_secret_value(&e.value))
        .count();
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

fn generate_placeholder(key: &str, config: Option<&PhantomConfig>) -> String {
    // Check for service mapping to give helpful hints
    if let Some(cfg) = config {
        for (svc_name, svc) in &cfg.services {
            if svc.secret_key == key {
                return format!("your_{}_here", svc_name);
            }
        }
    }

    // Generate placeholder based on key name
    let key_lower = key.to_lowercase();
    if key_lower.contains("url") {
        "your_connection_string_here".to_string()
    } else if key_lower.contains("password") || key_lower.contains("passwd") {
        "your_password_here".to_string()
    } else {
        format!("your_{key_lower}_here")
    }
}

fn is_likely_secret_value(value: &str) -> bool {
    let secret_prefixes = [
        "sk-",
        "sk_",
        "pk_",
        "ghp_",
        "gho_",
        "github_pat_",
        "glpat-",
        "xoxb-",
        "xoxp-",
        "AKIA",
        "shpat_",
        "eyJ",
        "Bearer ",
    ];
    if secret_prefixes.iter().any(|p| value.starts_with(p)) {
        return true;
    }
    if value.contains("://") && value.contains('@') {
        return true;
    }
    false
}
