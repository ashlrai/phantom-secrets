use anyhow::{Context, Result};
use colored::Colorize;
use phantom_core::config::PhantomConfig;
use phantom_core::env_scope::{namespaced_key, DEFAULT_ENV};
use zeroize::Zeroizing;

/// Reveal a single secret value from the vault.
/// Requires --yes flag or interactive TTY to prevent AI agents from extracting secrets.
pub fn run(name: &str, clipboard: bool, yes: bool, env: Option<&str>) -> Result<()> {
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

    let active_env = crate::commands::env_scope::effective_env(&project_dir, env);
    let vault_key = namespaced_key(&active_env, name);

    // Try namespaced key; for default env fall back to bare name (backward compat).
    let value: Zeroizing<String> = match vault.retrieve(&vault_key) {
        Ok(v) => v,
        Err(_) if active_env == DEFAULT_ENV && vault.exists(name).unwrap_or(false) => vault
            .retrieve(name)
            .context(format!("Secret '{}' not found in vault", name))?,
        Err(e) => {
            return Err(e).context(format!(
                "Secret '{}' not found in vault [env: {}]",
                name, active_env
            ))
        }
    };

    if clipboard {
        if copy_to_clipboard(&value) {
            println!(
                "{} Copied {} to clipboard (clears in 30 seconds)",
                "ok".green().bold(),
                name.bold()
            );
            schedule_clipboard_clear(std::time::Duration::from_secs(30));
        } else {
            eprintln!(
                "{} Clipboard not available. Printing to stdout instead.",
                "warn".yellow()
            );
            println!("{}", value.as_str());
        }
    } else {
        println!("{}", value.as_str());
    }

    Ok(())
}

fn copy_to_clipboard(text: &str) -> bool {
    match arboard::Clipboard::new() {
        Ok(mut clipboard) => clipboard.set_text(text.to_string()).is_ok(),
        Err(_) => false,
    }
}

fn schedule_clipboard_clear(delay: std::time::Duration) {
    let exe = match std::env::current_exe() {
        Ok(p) => p,
        Err(_) => return,
    };
    let _ = std::process::Command::new(exe)
        .arg("__clear-clipboard-after")
        .arg("--secs")
        .arg(delay.as_secs().to_string())
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn();
}

/// Body of the hidden `__clear-clipboard-after` subcommand. Sleeps the
/// given number of seconds and writes an empty string to the clipboard.
pub fn run_clear_after(secs: u64) -> Result<()> {
    std::thread::sleep(std::time::Duration::from_secs(secs));
    if let Ok(mut cb) = arboard::Clipboard::new() {
        let _ = cb.set_text(String::new());
    }
    Ok(())
}
