use anyhow::{Context, Result};
use colored::Colorize;
use phantom_core::config::PhantomConfig;

/// Returns true when fd 0 is connected to a terminal (not a pipe or redirect).
fn stdin_is_tty() -> bool {
    #[cfg(unix)]
    {
        // SAFETY: isatty is always safe to call with a valid fd number.
        unsafe { libc::isatty(0) != 0 }
    }
    #[cfg(not(unix))]
    {
        // On non-POSIX targets assume tty; users must pass --stdin explicitly
        // when piping on those platforms.
        true
    }
}

/// `phantom add KEY [VALUE]`
///
/// When VALUE is omitted:
///   - If stdin is a tty, prompt silently on stderr via rpassword.
///   - If `--stdin` is passed, read one line from stdin (piped use).
///   - If stdin is not a tty and `--stdin` was not passed, bail with a
///     clear error so CI jobs don't hang silently.
pub fn run(name: &str, value_arg: Option<&str>, from_stdin: bool) -> Result<()> {
    let project_dir = std::env::current_dir()?;
    let config_path = project_dir.join(".phantom.toml");

    if !config_path.exists() {
        anyhow::bail!(
            "No .phantom.toml found. Run {} first.",
            "phantom init".cyan().bold()
        );
    }

    // ── Resolve the secret value ─────────────────────────────────────
    let value: String = if let Some(v) = value_arg {
        // Positional value provided — backward-compatible path.
        v.to_string()
    } else if from_stdin {
        // --stdin: read one line from a pipe (e.g. `echo "$VAL" | phantom add KEY --stdin`).
        // Trim the trailing newline only — preserve any internal whitespace.
        let mut buf = String::new();
        std::io::stdin()
            .read_line(&mut buf)
            .context("Failed to read value from stdin")?;
        let trimmed = buf
            .trim_end_matches('\n')
            .trim_end_matches('\r')
            .to_string();
        if trimmed.is_empty() {
            anyhow::bail!("Received empty value on stdin — aborting.");
        }
        trimmed
    } else {
        // Interactive: prompt on stderr so that stdout can still be captured,
        // and read silently from the controlling tty via rpassword.
        if !stdin_is_tty() {
            anyhow::bail!(
                "stdin is not a terminal. \
                 Pass the value as a positional argument or use {} \
                 to read it from a pipe.",
                "--stdin".cyan().bold()
            );
        }
        let prompt = format!("Value for {name}: ");
        // rpassword::prompt_password_stderr opens /dev/tty directly so it
        // works even if stdout is redirected.
        let secret =
            rpassword::prompt_password(&prompt).context("Failed to read secret interactively")?;
        if secret.is_empty() {
            anyhow::bail!("Empty value — aborting.");
        }
        secret
    };

    // ── Store in vault ───────────────────────────────────────────────
    let config = PhantomConfig::load(&config_path).context("Failed to load .phantom.toml")?;
    let vault = phantom_vault::create_vault(&config.phantom.project_id);

    // Warn if secret already exists
    if vault.exists(name).unwrap_or(false) {
        eprintln!(
            "{} Secret {} already exists — overwriting with new value",
            "warn".yellow(),
            name.bold()
        );
    }

    vault
        .store(name, &value)
        .context(format!("Failed to store secret: {name}"))?;

    println!(
        "{} Stored {} in vault ({})",
        "ok".green().bold(),
        name.bold(),
        vault.backend_name().dimmed()
    );

    // Also update .env if it exists
    let env_path = project_dir.join(".env");
    if env_path.exists() {
        let content = std::fs::read_to_string(&env_path)?;
        let token = phantom_core::token::PhantomToken::generate();

        if content
            .lines()
            .any(|l| l.trim().starts_with(&format!("{name}=")))
        {
            // Key exists — replace its value with the phantom token.
            let new_content: String = content
                .lines()
                .map(|line| {
                    if line.trim().starts_with(&format!("{name}=")) {
                        format!("{name}={token}")
                    } else {
                        line.to_string()
                    }
                })
                .collect::<Vec<_>>()
                .join("\n")
                + "\n";
            std::fs::write(&env_path, new_content)?;
        } else {
            // Append new entry.
            let mut content = content;
            if !content.is_empty() && !content.ends_with('\n') {
                content.push('\n');
            }
            content.push_str(&format!("{name}={token}\n"));
            std::fs::write(&env_path, content)?;
        }

        println!(
            "{} Updated .env with phantom token for {}",
            "ok".green().bold(),
            name.bold()
        );
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    /// Verify the tty-check helper compiles and is callable without panicking.
    #[test]
    fn stdin_tty_check_does_not_panic() {
        let _ = super::stdin_is_tty();
    }
}
