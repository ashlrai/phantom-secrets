use anyhow::{Context, Result};
use colored::Colorize;
use phantom_core::config::PhantomConfig;
use phantom_core::dotenv::{classify, is_public_key, DotenvFile, EnvEntry, SecretClassification};
use phantom_core::why::Surface;

/// Human output for how `phantom exec` treats a protected key. It prints only
/// fixed labels and sentences: the service and host are already shown on the
/// `Service:` line, and `phantom why --json` carries the names.
fn print_exec_verdict(verdict: &phantom_core::why::ExecVerdict<'_>) {
    use phantom_core::config::{ExecBlocker, ExecDelivery};
    let delivery: &'static str = match verdict.delivery {
        ExecDelivery::Proxied { .. } => "proxied (the real value is injected for its provider)",
        ExecDelivery::NoRoute => "no route (the child gets a session token no provider accepts)",
        ExecDelivery::Withheld => "withheld (exec never hands this key to the child)",
        ExecDelivery::ConnectionStringRefused { .. } => {
            "refused (a connection string needs a protocol-aware broker)"
        }
        ExecDelivery::CustomRouteRefused { .. } => {
            "refused (its service is not Phantom's built-in route)"
        }
    };
    let blocked: Option<&'static str> = verdict.blocked_by.map(|blocker| match blocker {
        ExecBlocker::ConnectionString { .. } => {
            "exec will not start for any key while a connection string is protected in the dotenv; run database commands from a trusted terminal outside `phantom exec`"
        }
        ExecBlocker::CustomRoute { .. } => {
            "exec will not start for any key while .phantom.toml has a custom proxy route; removing it is the user's decision in a trusted terminal"
        }
        ExecBlocker::AlteredBuiltinRoute { .. } => {
            "exec will not start for any key until every built-in service in .phantom.toml matches Phantom's route again"
        }
    });
    let ok = blocked.is_none() && matches!(verdict.delivery, ExecDelivery::Proxied { .. });
    if ok {
        println!("   Exec:   {}", delivery.green());
        return;
    }
    println!("   Exec:   {}", delivery.yellow());
    if let Some(blocked) = blocked {
        println!("   {} {}", "!".yellow().bold(), blocked);
    }
    println!(
        "   {} Run {} for the service and next step.",
        "->".blue().bold(),
        "phantom why <KEY> --json".cyan()
    );
}

/// The dotenv `why` classifies: the managed dotenv when the project has a
/// config, else `./.env`, matching MCP `phantom_why`. Either way a symlinked
/// or non-regular file is refused before it is read; `None` when it is absent.
fn read_dotenv(
    project_dir: &std::path::Path,
    config: Option<&PhantomConfig>,
) -> Result<Option<DotenvFile>> {
    match config {
        Some(config) => {
            Ok(phantom_core::managed_dotenv::resolve_dotenv(project_dir, config, &[])?.file)
        }
        None => phantom_core::managed_dotenv::parse_regular_dotenv(project_dir, ".env")
            .context("Refusing to classify ./.env; protection status is indeterminate"),
    }
}

/// Explain why a specific key is or isn't protected by Phantom.
///
/// With `json`, prints the value-free report shared with the MCP `phantom_why`
/// tool instead of the human explanation.
pub fn run(key: &str, json: bool) -> Result<()> {
    let project_dir = std::env::current_dir()?;
    let config_path = project_dir.join(".phantom.toml");
    let config = PhantomConfig::load(&config_path).ok();
    let dotenv = read_dotenv(&project_dir, config.as_ref())?;

    if json && dotenv.is_none() {
        let report = phantom_core::why::why_report_for(Surface::Cli, key, None, config.as_ref());
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }

    let Some(dotenv) = dotenv else {
        anyhow::bail!(
            "No .env file found in current directory.\n  {}",
            crate::util::docs_url("getting-started")
        );
    };

    dotenv
        .validate_for_mutation()
        .context("Managed dotenv is malformed; protection status is indeterminate")?;
    if json {
        let report =
            phantom_core::why::why_report_for(Surface::Cli, key, Some(&dotenv), config.as_ref());
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }
    // Find the entry
    let entry = dotenv.entries().into_iter().find(|e| e.key == key);

    match entry {
        Some(entry) => {
            if entry.is_phantom {
                // Already protected
                println!(
                    "{} {} is {}",
                    "->".blue().bold(),
                    key.bold(),
                    "PROTECTED".green().bold()
                );
                println!(
                    "   Token:  {}",
                    entry.value.get(..12).unwrap_or(&entry.value).dimmed()
                );

                // Show service mapping if available
                if let Some(ref cfg) = config {
                    for (svc_name, svc) in &cfg.services {
                        if svc.secret_key == key {
                            println!(
                                "   Service: {} ({})",
                                svc_name.cyan(),
                                svc.pattern.as_deref().unwrap_or("env var")
                            );
                            break;
                        }
                    }
                    print_exec_verdict(&phantom_core::why::ExecVerdict::new(key, &dotenv, cfg));
                    println!(
                        "   Vault:  {}",
                        phantom_vault::try_create_vault(cfg.local_project_id())?
                            .backend_name()
                            .cyan()
                    );
                }
            } else {
                let classification = classify(entry);
                match classification {
                    SecretClassification::PublicKey => {
                        println!(
                            "{} {} is {} (public key)",
                            "->".blue().bold(),
                            key.bold(),
                            "NOT PROTECTED".yellow().bold()
                        );
                        let public_prefixes = [
                            "NEXT_PUBLIC_",
                            "EXPO_PUBLIC_",
                            "VITE_",
                            "REACT_APP_",
                            "NUXT_PUBLIC_",
                            "GATSBY_",
                        ];
                        let prefix = public_prefixes
                            .iter()
                            .find(|p| key.starts_with(*p))
                            .unwrap_or(&"PUBLIC_");
                        println!(
                            "   Reason: Keys with {} prefix are browser-safe (shipped in client bundles)",
                            prefix.cyan()
                        );
                        println!("   Override: {}", format!("phantom add {key}").dimmed());
                    }
                    SecretClassification::Secret => {
                        println!(
                            "{} {} is {} (detected as secret but not yet phantomized)",
                            "!".yellow().bold(),
                            key.bold(),
                            "UNPROTECTED".red().bold()
                        );
                        explain_why_secret(entry);
                        println!("   Fix: {}", "phantom init".cyan().bold());
                    }
                    SecretClassification::NotSecret => {
                        println!(
                            "{} {} is {} (non-secret config)",
                            "->".blue().bold(),
                            key.bold(),
                            "NOT PROTECTED".dimmed()
                        );
                        println!("   Reason: Does not match secret key patterns or value patterns");
                        println!("   Override: {}", format!("phantom add {key}").dimmed());
                    }
                }
            }
        }
        None => {
            // A name that is not in the dotenv has nothing to explain; fail so
            // a typo is not mistaken for an answer.
            let public = if is_public_key(key) {
                " (its prefix would classify it as a browser-safe public key)"
            } else {
                ""
            };
            anyhow::bail!(
                "{key} not found in the dotenv{public}.\n  Key names are case-sensitive; run {} to list the protected keys.",
                "phantom status".cyan().bold()
            );
        }
    }

    Ok(())
}

fn explain_why_secret(entry: &EnvEntry) {
    let key = entry.key.to_uppercase();
    let value = &entry.value;

    let secret_key_patterns = [
        "KEY",
        "SECRET",
        "TOKEN",
        "PASSWORD",
        "PASSWD",
        "CREDENTIAL",
        "AUTH",
        "PRIVATE",
    ];
    let connection_patterns = ["DATABASE_URL", "REDIS_URL", "MONGO_URL"];

    for pattern in &secret_key_patterns {
        if key.contains(pattern) {
            println!(
                "   Reason: Key name contains \"{}\" (secret key pattern)",
                pattern
            );
            return;
        }
    }
    for pattern in &connection_patterns {
        if key.contains(pattern) {
            println!(
                "   Reason: Key name matches connection string pattern (\"{}\")",
                pattern
            );
            return;
        }
    }

    let secret_prefixes = [
        ("sk-", "OpenAI-style key"),
        ("sk_", "Stripe-style key"),
        ("ghp_", "GitHub token"),
        ("eyJ", "JWT/base64 token"),
    ];
    for (prefix, label) in &secret_prefixes {
        if value.starts_with(prefix) {
            println!("   Reason: Value starts with \"{}\" ({})", prefix, label);
            return;
        }
    }

    if value.contains("://") && value.contains('@') {
        println!("   Reason: Value looks like a connection string with credentials");
        return;
    }

    if value.len() >= 32 {
        println!(
            "   Reason: Value is a high-entropy string ({} chars)",
            value.len()
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn read_dotenv_refuses_a_symlinked_env_before_init() {
        let project = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let target = outside.path().join("elsewhere.env");
        std::fs::write(&target, "NODE_ENV=production\n").unwrap();
        std::os::unix::fs::symlink(&target, project.path().join(".env")).unwrap();

        let error = read_dotenv(project.path(), None).unwrap_err();
        assert!(
            format!("{error:#}").contains("not a regular, non-symlink file"),
            "{error:#}"
        );

        // A regular ./.env is still read, and a missing one is None.
        std::fs::remove_file(project.path().join(".env")).unwrap();
        assert!(read_dotenv(project.path(), None).unwrap().is_none());
        std::fs::write(project.path().join(".env"), "NODE_ENV=production\n").unwrap();
        let dotenv = read_dotenv(project.path(), None).unwrap().unwrap();
        assert_eq!(dotenv.entries().len(), 1);
    }
}
