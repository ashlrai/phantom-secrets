use anyhow::{Context, Result};
use colored::Colorize;
use phantom_core::config::PhantomConfig;
use phantom_core::env_scope::namespaced_key;
use std::io::IsTerminal;

/// Returns true when stdin is connected to a terminal (not a pipe or redirect).
fn stdin_is_tty() -> bool {
    std::io::stdin().is_terminal()
}

/// `phantom add KEY [VALUE]`
///
/// When VALUE is omitted:
///   - If stdin is a tty, prompt silently on stderr via rpassword.
///   - If `--stdin` is passed, read one line from stdin (piped use).
///   - If stdin is not a tty and `--stdin` was not passed, bail with a
///     clear error so CI jobs don't hang silently.
pub fn run(name: &str, value_arg: Option<&str>, from_stdin: bool, env: Option<&str>) -> Result<()> {
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
        v.to_string()
    } else if from_stdin {
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
        if !stdin_is_tty() {
            anyhow::bail!(
                "stdin is not a terminal. \
                 Pass the value as a positional argument or use {} \
                 to read it from a pipe.",
                "--stdin".cyan().bold()
            );
        }
        let prompt = format!("Value for {name}: ");
        let secret =
            rpassword::prompt_password(&prompt).context("Failed to read secret interactively")?;
        if secret.is_empty() {
            anyhow::bail!("Empty value — aborting.");
        }
        secret
    };

    // ── Resolve environment and vault key ────────────────────────────
    let config = PhantomConfig::load(&config_path).context("Failed to load .phantom.toml")?;
    let vault = phantom_vault::create_vault(&config.phantom.project_id);

    let active_env = crate::commands::env_scope::effective_env(&project_dir, env);
    let vault_key = namespaced_key(&active_env, name);

    if vault.exists(&vault_key).unwrap_or(false) {
        eprintln!(
            "{} Secret {} already exists in env '{}' — overwriting with new value",
            "warn".yellow(),
            name.bold(),
            active_env
        );
    }

    vault
        .store(&vault_key, &value)
        .context(format!("Failed to store secret: {name}"))?;

    println!(
        "{} Stored {} in vault ({}) [env: {}]",
        "ok".green().bold(),
        name.bold(),
        vault.backend_name().dimmed(),
        active_env.cyan()
    );

    // Update .env with a phantom token when the key is present there
    let env_path = project_dir.join(".env");
    if env_path.exists() {
        let content = std::fs::read_to_string(&env_path)?;
        let token = phantom_core::token::PhantomToken::generate();

        if content
            .lines()
            .any(|l| l.trim().starts_with(&format!("{name}=")))
        {
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
    #[test]
    fn stdin_tty_check_does_not_panic() {
        let _ = super::stdin_is_tty();
    }
}
