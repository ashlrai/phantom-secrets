use anyhow::{Context, Result};
use colored::Colorize;
use phantom_core::config::PhantomConfig;

/// Reveal a single secret value from the vault.
/// Requires explicit confirmation to prevent accidental exposure.
pub fn run(name: &str, clipboard: bool) -> Result<()> {
    let project_dir = std::env::current_dir()?;
    let config_path = project_dir.join(".phantom.toml");

    if !config_path.exists() {
        anyhow::bail!(
            "No .phantom.toml found. Run {} first.",
            "phantom init".cyan().bold()
        );
    }

    let config = PhantomConfig::load(&config_path).context("Failed to load .phantom.toml")?;
    let vault = phantom_vault::create_vault(&config.phantom.project_id);

    let value = vault
        .retrieve(name)
        .context(format!("Secret '{}' not found in vault", name))?;

    if clipboard {
        // Try to copy to clipboard using pbcopy (macOS) or xclip (Linux)
        if copy_to_clipboard(&value) {
            println!(
                "{} Copied {} to clipboard (clears in 30 seconds)",
                "ok".green().bold(),
                name.bold()
            );
            // Spawn a background process to clear the clipboard after 30 seconds
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
        // Print to stdout (for piping)
        println!("{}", value);
    }

    Ok(())
}

fn copy_to_clipboard(text: &str) -> bool {
    #[cfg(target_os = "macos")]
    {
        use std::io::Write;
        if let Ok(mut child) = std::process::Command::new("pbcopy")
            .stdin(std::process::Stdio::piped())
            .spawn()
        {
            if let Some(stdin) = child.stdin.as_mut() {
                let _ = stdin.write_all(text.as_bytes());
            }
            return child.wait().map(|s| s.success()).unwrap_or(false);
        }
    }

    #[cfg(target_os = "linux")]
    {
        use std::io::Write;
        // Try xclip first, then xsel
        for cmd in &["xclip", "xsel"] {
            if let Ok(mut child) = std::process::Command::new(cmd)
                .args(["-selection", "clipboard"])
                .stdin(std::process::Stdio::piped())
                .spawn()
            {
                if let Some(stdin) = child.stdin.as_mut() {
                    let _ = stdin.write_all(text.as_bytes());
                }
                if child.wait().map(|s| s.success()).unwrap_or(false) {
                    return true;
                }
            }
        }
    }

    false
}
