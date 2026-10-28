use anyhow::{Context, Result};
use colored::Colorize;
use phantom_core::config::PhantomConfig;
use phantom_core::dotenv::{classify_with_reason, is_public_key, DotenvFile, SecretClassification};
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

/// The `Vault:` line for a protected key. Beside an encrypted-file vault this
/// process cannot open, the selected backend is the OS keychain, and naming
/// it alone read as "the value is in the keychain" next to a proxied exec
/// verdict; a warning line names the locked vault and the unlock step.
fn vault_lines(vault: &dyn phantom_vault::VaultBackend, project_id: &str) -> Vec<String> {
    let mut lines = vec![format!("   Vault:  {}", vault.backend_name().cyan())];
    if let Some(notice) = crate::util::locked_vault_notice(vault, project_id) {
        lines.push(format!(
            "   {} {}; this key may be stored there, and `phantom exec` refuses a protected key it cannot read. {notice}",
            "!".yellow().bold(),
            crate::util::VAULT_LOCKED
        ));
    }
    lines
}

/// Refuse an empty or whitespace-only key. It can never match a dotenv
/// entry, so answering "not found" (exit 0) sent agents chasing spelling.
fn validate_key_argument(key: &str) -> Result<()> {
    if key.trim().is_empty() {
        anyhow::bail!(
            "No key name given. Pass the exact dotenv key name, for example `phantom why OPENAI_API_KEY`; `phantom status` lists the managed dotenv."
        );
    }
    Ok(())
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

/// The project's `.phantom.toml`, or `None` only when it does not exist.
///
/// A config that exists but cannot be read or parsed is an error, matching
/// MCP `phantom_why`: treating it as "not initialized" would classify
/// `./.env` instead of the managed dotenv and drop the exec verdict, so a
/// protected key read as fine while `phantom exec` refuses to start.
fn load_config(project_dir: &std::path::Path) -> Result<Option<PhantomConfig>> {
    crate::util::load_config_if_present(&project_dir.join(".phantom.toml")).map_err(|error| {
        anyhow::Error::new(error).context(
            "Failed to load .phantom.toml; protection status is indeterminate. Fix or restore it, then retry",
        )
    })
}

fn print_why_json(report: &serde_json::Value) -> Result<()> {
    let pretty = serde_json::to_string_pretty(report)?;
    println!(
        "{}",
        crate::commands::report_json::with_schema_pretty(
            pretty,
            crate::commands::report_json::WHY_SCHEMA
        )?
    );
    Ok(())
}

/// Explain why a specific key is or isn't protected by Phantom.
///
/// With `json`, prints the value-free report shared with the MCP `phantom_why`
/// tool instead of the human explanation.
pub fn run(key: &str, json: bool, strict: bool) -> Result<()> {
    run_in(&std::env::current_dir()?, key, json, strict)
}

fn exit_unless_protected(strict: bool, protected: bool) {
    if strict && !protected {
        std::process::exit(crate::commands::report_json::STRICT_ISSUES_FOUND);
    }
}

fn run_in(project_dir: &std::path::Path, key: &str, json: bool, strict: bool) -> Result<()> {
    validate_key_argument(key)?;
    let config = load_config(project_dir)?;
    let dotenv = read_dotenv(project_dir, config.as_ref())?;

    if json && dotenv.is_none() {
        let report = phantom_core::why::why_report_for(Surface::Cli, key, None, config.as_ref());
        print_why_json(&report)?;
        exit_unless_protected(strict, report["protected"].as_bool() == Some(true));
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
        print_why_json(&report)?;
        exit_unless_protected(strict, report["protected"].as_bool() == Some(true));
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
                    let vault = crate::util::open_vault(cfg.local_project_id())?;
                    for line in vault_lines(vault.as_ref(), cfg.local_project_id()) {
                        println!("{line}");
                    }
                }
            } else {
                // The reason shown is the rule the classifier decided by.
                let (classification, reason) = classify_with_reason(entry);
                match classification {
                    SecretClassification::PublicKey => {
                        println!(
                            "{} {} is {} (public key)",
                            "->".blue().bold(),
                            key.bold(),
                            "NOT PROTECTED".yellow().bold()
                        );
                        println!("   Reason: {}", reason.explanation());
                        println!("   Override: {}", format!("phantom add {key}").dimmed());
                    }
                    SecretClassification::Secret => {
                        println!(
                            "{} {} is {} (detected as secret but not yet phantomized)",
                            "!".yellow().bold(),
                            key.bold(),
                            "UNPROTECTED".red().bold()
                        );
                        println!("   Reason: {}", reason.explanation());
                        println!("   Fix: {}", "phantom init".cyan().bold());
                    }
                    SecretClassification::NotSecret => {
                        println!(
                            "{} {} is {} (non-secret config)",
                            "->".blue().bold(),
                            key.bold(),
                            "NOT PROTECTED".dimmed()
                        );
                        println!("   Reason: {}", reason.explanation());
                        println!("   Override: {}", format!("phantom add {key}").dimmed());
                    }
                }
                exit_unless_protected(strict, false);
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Beside an encrypted-file vault this process cannot open, `why` named
    /// the OS keychain as the vault with no word that the project's secrets
    /// are in a locked file `phantom exec` cannot read.
    #[cfg(unix)]
    #[test]
    fn why_names_a_locked_file_vault_beside_the_keychain() {
        let project =
            crate::util::test_seam::LockedProject::new(crate::util::test_seam::empty_keychain);
        let vault = crate::util::open_vault(&project.project_id).unwrap();

        let lines = vault_lines(vault.as_ref(), &project.project_id);

        assert_eq!(lines.len(), 2);
        assert!(lines[1].contains("Vault locked:"));
        assert!(lines[1].contains("PHANTOM_VAULT_PASSPHRASE"));
        // Another project id has no file vault: only the backend line.
        assert_eq!(vault_lines(vault.as_ref(), "another-project").len(), 1);
    }

    #[test]
    fn empty_or_blank_key_is_refused_with_an_example() {
        for key in ["", "   ", "\t"] {
            let error = format!("{:#}", run(key, true, false).unwrap_err());
            assert!(error.contains("No key name given"), "{error}");
            assert!(error.contains("phantom why OPENAI_API_KEY"), "{error}");
        }
        assert!(validate_key_argument("OPENAI_API_KEY").is_ok());
    }

    #[test]
    fn not_found_next_step_names_the_cli_command() {
        let dotenv = DotenvFile::parse_str("NODE_ENV=production\n");
        let report = phantom_core::why::why_report("MISSING_KEY", Some(&dotenv), None);
        let step = report["next_step"].as_str().unwrap();
        assert!(step.contains("`phantom status`"), "{step}");
    }

    #[test]
    fn malformed_config_is_an_error_not_an_uninitialized_project() {
        let project = tempfile::tempdir().unwrap();
        let token = phantom_core::token::PhantomToken::generate();
        std::fs::write(
            project.path().join(".env"),
            format!("OPENAI_API_KEY={}\n", token.as_str()),
        )
        .unwrap();
        std::fs::write(project.path().join(".phantom.toml"), "[phantom\nversion = ").unwrap();

        for json in [true, false] {
            let error = run_in(project.path(), "OPENAI_API_KEY", json, false).unwrap_err();
            assert!(
                format!("{error:#}").contains("Failed to load .phantom.toml"),
                "malformed config must not read as not initialized (json={json})"
            );
        }
        assert!(load_config(project.path()).is_err());

        // Only a missing config means "not initialized".
        std::fs::remove_file(project.path().join(".phantom.toml")).unwrap();
        assert!(load_config(project.path()).unwrap().is_none());
        assert!(run_in(project.path(), "OPENAI_API_KEY", true, false).is_ok());
    }

    /// A dangling `.phantom.toml` symlink is not "not initialized", and a
    /// symlink to another project's config is not followed: either would
    /// classify a dotenv this project does not manage.
    #[cfg(unix)]
    #[test]
    fn symlinked_config_is_indeterminate_not_absent() {
        let outside = tempfile::tempdir().unwrap();
        PhantomConfig::new_with_defaults("why-outside".to_string())
            .save(&outside.path().join(".phantom.toml"))
            .unwrap();
        let project = tempfile::tempdir().unwrap();
        let link = project.path().join(".phantom.toml");
        std::os::unix::fs::symlink("missing.toml", &link).unwrap();
        assert!(load_config(project.path()).is_err());
        std::fs::remove_file(&link).unwrap();
        std::os::unix::fs::symlink(outside.path().join(".phantom.toml"), &link).unwrap();
        let message = format!("{:#}", load_config(project.path()).unwrap_err());
        assert!(
            message.contains("protection status is indeterminate"),
            "unexpected refusal text"
        );
        assert!(
            !message.contains(&outside.path().display().to_string()),
            "refusal names the outside path"
        );
    }

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
