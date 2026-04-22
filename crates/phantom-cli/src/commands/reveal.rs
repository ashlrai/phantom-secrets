use anyhow::{Context, Result};
use colored::Colorize;
use phantom_core::config::PhantomConfig;
use zeroize::Zeroize;

/// Reveal a single secret value from the vault.
/// Requires --yes flag or interactive TTY to prevent AI agents from extracting secrets.
pub fn run(name: &str, clipboard: bool, yes: bool) -> Result<()> {
    let project_dir = std::env::current_dir()?;
    let config_path = project_dir.join(".phantom.toml");

    if !config_path.exists() {
        anyhow::bail!(
            "No .phantom.toml found. Run {} first.",
            "phantom init".cyan().bold()
        );
    }

    // Safety gate: refuse to reveal in non-interactive contexts unless --yes is passed.
    // This prevents AI agents from calling `phantom reveal` to extract real secrets.
    if !yes {
        use std::io::IsTerminal;
        if !std::io::stdout().is_terminal() {
            anyhow::bail!(
                "Refusing to reveal secret in non-interactive context.\n\
                 Pass --yes to override. This prevents AI agents from extracting secrets."
            );
        }

        eprintln!(
            "{} About to reveal the real value of {}",
            "!".yellow().bold(),
            name.bold()
        );
    }

    let config = PhantomConfig::load(&config_path).context("Failed to load .phantom.toml")?;
    let vault = phantom_vault::create_vault(&config.phantom.project_id);

    let mut value = vault
        .retrieve(name)
        .context(format!("Secret '{}' not found in vault", name))?;

    if clipboard {
        if copy_to_clipboard(&value) {
            println!(
                "{} Copied {} to clipboard (clears in 30 seconds)",
                "ok".green().bold(),
                name.bold()
            );
            #[cfg(target_os = "macos")]
            {
                let _ = std::process::Command::new("bash")
                    .args(["-c", "sleep 30 && echo -n '' | pbcopy"])
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null())
                    .spawn();
            }
        } else {
            eprintln!(
                "{} Clipboard not available. Printing to stdout instead.",
                "warn".yellow()
            );
            println!("{}", value);
        }
    } else {
        println!("{}", value);
    }

    // Zeroize the secret from memory
    value.zeroize();

    Ok(())
}

fn copy_to_clipboard(text: &str) -> bool {
    match arboard::Clipboard::new() {
        Ok(mut clipboard) => clipboard.set_text(text.to_string()).is_ok(),
        Err(_) => false,
    }
}
