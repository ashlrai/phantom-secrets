use anyhow::{Context, Result};
use colored::Colorize;
use phantom_core::config::PhantomConfig;
use phantom_core::dotenv::DotenvFile;

/// Generate a .env.example file from the current .env.
/// Secret values are replaced with descriptive placeholders.
/// Non-secret values and public keys are preserved as-is.
pub fn run(output: &str) -> Result<()> {
    let project_dir = std::env::current_dir()?;
    let output_path = validated_output_path(&project_dir, output)?;
    let _transaction_lock = phantom_vault::acquire_project_transaction_lock(&project_dir)
        .context("Failed to acquire the project transaction lock")?;
    if phantom_core::fs::read_regular_file(&output_path)
        .with_context(|| format!("Refusing unsafe output target: {}", output_path.display()))?
        .is_some()
    {
        anyhow::bail!(
            "Refusing to overwrite existing output {}. This command has no overwrite policy; choose a new filename.",
            output_path.display()
        );
    }
    let config_path = project_dir.join(".phantom.toml");
    let config = PhantomConfig::load(&config_path).ok();
    let env_path = match config.as_ref() {
        Some(config) => {
            phantom_core::managed_dotenv::resolve_dotenv(&project_dir, config, &[])?.path
        }
        None => project_dir.join(".env"),
    };
    if !env_path.exists() {
        anyhow::bail!(
            "No .env file found in current directory.\n  {}",
            crate::util::docs_url("getting-started")
        );
    }

    let dotenv = DotenvFile::parse_file(&env_path).context("Failed to read .env")?;
    let entries = dotenv.entries();

    if entries.is_empty() {
        println!("{} .env is empty.", "!".yellow().bold());
        return Ok(());
    }

    // Load config for service info if available
    // Use shared generation logic from phantom-core
    let content = dotenv.generate_example_content(config.as_ref());
    phantom_core::fs::atomic_write_if_unchanged(&output_path, None, content.as_bytes())
        .with_context(|| {
            format!(
                "Output target changed while generating {}; no file was overwritten",
                output_path.display()
            )
        })?;

    let secret_count =
        dotenv.real_secret_entries().len() + entries.iter().filter(|e| e.is_phantom).count();
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

fn validated_output_path(
    project_dir: &std::path::Path,
    output: &str,
) -> Result<std::path::PathBuf> {
    phantom_core::fs::validate_project_filename(output)
        .context("Invalid env-example output path")?;
    Ok(project_dir.join(output))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn output_is_one_project_relative_filename() {
        let root = std::path::Path::new("/project");
        assert_eq!(
            validated_output_path(root, ".env.example").unwrap(),
            root.join(".env.example")
        );
        for invalid in ["../owner", "nested/file", "nested\\file", "/tmp/owner"] {
            assert!(validated_output_path(root, invalid).is_err());
        }
    }
}
