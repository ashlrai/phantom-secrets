use anyhow::{Context, Result};
use colored::Colorize;
use phantom_core::config::PhantomConfig;
use std::io::{IsTerminal, Write};
use zeroize::Zeroizing;

/// Reveal a single secret value from the vault after a trusted-terminal ceremony.
pub fn run(name: &str, clipboard: bool, yes: bool) -> Result<()> {
    if yes {
        anyhow::bail!(
            "--yes is no longer supported for secret reveal; plaintext access requires a trusted interactive terminal"
        );
    }

    let project_dir = std::env::current_dir()?;
    let config_path = project_dir.join(".phantom.toml");

    if !config_path.exists() {
        anyhow::bail!(
            "No .phantom.toml found. Run {} first.",
            "phantom init".cyan().bold()
        );
    }

    if !std::io::stdin().is_terminal() || !std::io::stderr().is_terminal() {
        anyhow::bail!("Refusing to reveal a secret without attached stdin and stderr terminals");
    }

    eprintln!(
        "{} Plaintext access can expose {} to the current terminal session.",
        "!".yellow().bold(),
        name.bold()
    );
    eprint!("Type `reveal {name}` to continue: ");
    std::io::stderr().flush()?;
    let mut confirmation = String::new();
    std::io::stdin().read_line(&mut confirmation)?;
    if confirmation.trim() != format!("reveal {name}") {
        anyhow::bail!("Secret reveal cancelled: typed confirmation did not match");
    }

    let config = PhantomConfig::load(&config_path).context("Failed to load .phantom.toml")?;
    let vault = phantom_vault::create_vault(config.local_project_id());

    phantom_core::audit::log_result("vault.reveal", Some(name))
        .context("Failed to write audit event for secret reveal")?;

    let value: Zeroizing<String> = vault
        .retrieve(name)
        .context(format!("Secret '{}' not found in vault", name))?;

    if clipboard {
        require_clipboard_copy(copy_to_clipboard(&value))?;
        println!(
            "{} Copied {} to clipboard (clears in 30 seconds)",
            "ok".green().bold(),
            name.bold()
        );
        schedule_clipboard_clear(std::time::Duration::from_secs(30));
    } else {
        println!("{}", value.as_str());
    }

    // Zeroizing<String> scrubs memory on drop automatically.

    Ok(())
}

fn require_clipboard_copy(copied: bool) -> Result<()> {
    if copied {
        Ok(())
    } else {
        anyhow::bail!("Clipboard access failed; refusing to fall back to plaintext stdout")
    }
}

fn copy_to_clipboard(text: &str) -> bool {
    match arboard::Clipboard::new() {
        Ok(mut clipboard) => clipboard.set_text(text.to_string()).is_ok(),
        Err(_) => false,
    }
}

/// Spawn a detached child of this same binary that sleeps `delay`, then
/// clears the clipboard. Cross-platform replacement for the macOS-only
/// `bash -c 'sleep && pbcopy'` shell-out — works on Windows where there's
/// no bash, and avoids quoting/PATH fragility on Unix.
///
/// We spawn a child rather than a thread so the parent `phantom reveal`
/// process can exit immediately and return the user to their prompt; a
/// thread would die when the parent exits, and on macOS/Windows the
/// clipboard contents persist past process exit so we need a live process
/// to issue the clear.
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

#[cfg(test)]
mod tests {
    #[test]
    fn legacy_noninteractive_bypass_is_always_rejected() {
        let error = super::run("TEST_SECRET", false, true).unwrap_err();
        assert!(error.to_string().contains("--yes is no longer supported"));
    }

    #[test]
    fn clipboard_failure_never_falls_back_to_stdout() {
        let error = super::require_clipboard_copy(false).unwrap_err();
        assert!(error.to_string().contains("refusing to fall back"));
    }
}
