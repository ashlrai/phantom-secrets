//! `phantom secrets-expiring-soon` and `phantom expiry` — TTL-based expiry enforcement.
//!
//! `phantom secrets-expiring-soon` returns a table/JSON of secrets near expiry (default 7d).
//! `phantom expiry set <KEY> <DAYS>` — store `expires_at` in `.phantom.toml`.
//! `phantom expiry enforce [--fail-closed]` — exit 1 if any secret is expired.
//! `phantom expiry rotate <KEY>` — deprecated compatibility token remap.

use anyhow::{Context, Result};
use colored::Colorize;
use phantom_core::config::PhantomConfig;
use serde::Serialize;

/// One entry in the expiry report.
#[derive(Debug, Serialize)]
pub struct ExpiryEntry {
    /// Secret name (never includes the value).
    pub name: String,
    /// Days remaining until expiry; negative means already expired.
    pub days_remaining: i64,
    /// Unix timestamp of the expiry instant.
    pub expires_at: u64,
    /// Human-readable status string (e.g. "3 days remaining", "EXPIRED").
    pub status: String,
}

/// Run `phantom secrets-expiring-soon [--days N] [--auto-rotate] [--sync]`.
///
/// * `warn_days`    — warn about secrets expiring within this many days
///   (default 7; 0 means only report already-expired secrets)
/// * `auto_rotate`  — legacy name; if `true`, remap the local phantom tokens
///   for each expiring/expired secret without changing credentials or TTLs
/// * `sync_after`   — legacy option; rejected because no credential changes
/// * `json`         — emit machine-readable JSON instead of coloured table
pub fn run(warn_days: u64, auto_rotate: bool, sync_after: bool, json: bool) -> Result<()> {
    if auto_rotate && sync_after {
        anyhow::bail!(
            "--sync is not valid with the deprecated --auto-rotate token remap: provider credentials are unchanged. Use `phantom rotate --name <NAME> [--provider <PROVIDER>] --sync` for a real provider rotation."
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

    let config = PhantomConfig::load(&config_path).context("Failed to load .phantom.toml")?;
    let vault = phantom_vault::try_create_vault(config.local_project_id())?;

    let entries = vault
        .list_with_metadata()
        .context("Failed to read vault metadata")?;

    // Collect secrets that are expired or expiring within warn_days.
    let mut expiring: Vec<ExpiryEntry> = entries
        .iter()
        .filter_map(|(name, meta)| {
            let m = meta.as_ref()?;
            let expires_at = m.expires_at?;
            let days_remaining = m.days_remaining()?;
            // Include expired (days_remaining < 0) and expiring soon.
            if days_remaining <= warn_days as i64 {
                Some(ExpiryEntry {
                    name: name.clone(),
                    days_remaining,
                    expires_at,
                    status: m.ttl_status(),
                })
            } else {
                None
            }
        })
        .collect();

    // Sort: most-urgent first (lowest / most-negative days_remaining).
    expiring.sort_by_key(|e| e.days_remaining);

    if json {
        println!("{}", serde_json::to_string_pretty(&expiring)?);
    } else {
        print_human_table(&expiring, warn_days);
    }

    if auto_rotate && !expiring.is_empty() {
        run_token_remap(&expiring, &config, json)?;
    }

    Ok(())
}

/// Print the human-readable expiry table to stdout.
fn print_human_table(expiring: &[ExpiryEntry], warn_days: u64) {
    if expiring.is_empty() {
        println!(
            "{} No secrets expiring within {} day(s).",
            "ok".green().bold(),
            warn_days
        );
        return;
    }

    println!(
        "{} {} secret(s) expiring within {} day(s):\n",
        "!".yellow().bold(),
        expiring.len(),
        warn_days
    );
    println!("  {:<30} {:>15}  STATUS", "NAME", "DAYS LEFT");
    println!("  {}", "-".repeat(60));

    for entry in expiring {
        let days_str = if entry.days_remaining < 0 {
            format!("{}", entry.days_remaining).red().bold().to_string()
        } else if entry.days_remaining <= 3 {
            format!("{}", entry.days_remaining).red().to_string()
        } else {
            format!("{}", entry.days_remaining).yellow().to_string()
        };

        let status_str = if entry.status == "EXPIRED" {
            entry.status.red().bold().to_string()
        } else {
            entry.status.yellow().to_string()
        };

        println!(
            "  {:<30} {:>15}  {}",
            entry.name.bold(),
            days_str,
            status_str
        );
    }

    println!();
    println!(
        "  {} Run a configured provider rotation to replace an expiring credential. The legacy {} flag only remaps local phm_ placeholders.",
        "Tip:".dimmed(),
        "phantom secrets-expiring-soon --auto-rotate".cyan()
    );
}

/// Remap local placeholders for expiring secrets without changing the
/// underlying provider credentials or their lifecycle metadata.
fn run_token_remap(expiring: &[ExpiryEntry], config: &PhantomConfig, json: bool) -> Result<()> {
    let vault = phantom_vault::try_create_vault(config.local_project_id())?;
    let project_dir = std::env::current_dir()?;
    let env_path = project_dir.join(".env");
    let names = expiring
        .iter()
        .map(|entry| entry.name.clone())
        .collect::<Vec<_>>();

    // Read metadata before and after the file transaction to make the invariant
    // explicit and regression-testable: a token remap cannot renew TTL state.
    let metadata_before = names
        .iter()
        .map(|name| {
            vault
                .get_metadata(name)
                .with_context(|| format!("Failed to read metadata for {name}"))
        })
        .collect::<Result<Vec<_>>>()?;

    crate::commands::rotate::remap_phantom_tokens(&env_path, &names)?;

    let metadata_after = names
        .iter()
        .map(|name| {
            vault
                .get_metadata(name)
                .with_context(|| format!("Failed to re-read metadata for {name}"))
        })
        .collect::<Result<Vec<_>>>()?;
    if metadata_before != metadata_after {
        anyhow::bail!("Token remap invariant failed: credential lifecycle metadata changed.");
    }
    for name in &names {
        phantom_core::audit::log("secret.token_remapped", Some(name));
    }

    if json {
        let result = serde_json::json!({
            "tokens_remapped": names,
            "provider_credentials_rotated": 0,
            "expiry_metadata_changed": false,
        });
        println!("{}", serde_json::to_string_pretty(&result)?);
    } else {
        println!(
            "\n{} Remapped {} local Phantom token(s). Provider credentials and expiry metadata are unchanged:",
            "ok".green().bold(),
            names.len()
        );
        for name in &names {
            println!("   {} {}", "+".green(), name.bold());
        }
    }

    Ok(())
}

// ── phantom expiry set <KEY> <DAYS> ──────────────────────────────────────────

/// `phantom expiry set <KEY> <DAYS>` — mark a secret as expiring in N days from now.
///
/// Stores `expires_at` (Unix timestamp) and `rotation_window` in the
/// per-secret `[phantom.secrets.{name}]` section of `.phantom.toml`.
pub fn run_set(key: &str, days: u64) -> Result<()> {
    use phantom_core::rotation_strategy::compute_new_expires_at;
    use phantom_vault::metadata::now_secs;

    let project_dir = std::env::current_dir()?;
    let config_path = project_dir.join(".phantom.toml");

    if !config_path.exists() {
        anyhow::bail!(
            "No .phantom.toml found. Run {} first.",
            "phantom init".cyan().bold()
        );
    }

    let mut config = PhantomConfig::load(&config_path).context("Failed to load .phantom.toml")?;

    let now = now_secs();
    let expires_at = compute_new_expires_at(days, now);

    // Ensure the secret exists in the vault (advisory; don't block if vault unavailable).
    let vault = phantom_vault::try_create_vault(config.local_project_id())?;
    match vault.list() {
        Ok(names) if !names.contains(&key.to_string()) => {
            eprintln!(
                "{} Secret '{}' is not in the vault — storing expiry config anyway.",
                "warn:".yellow().bold(),
                key
            );
        }
        _ => {}
    }

    // Upsert the per-secret override.
    let entry = config.phantom.secrets.entry(key.to_string()).or_default();
    entry.expires_at = Some(expires_at);
    entry.rotation_window = Some(days);

    config
        .save(&config_path)
        .context("Failed to save .phantom.toml")?;

    println!(
        "{} Set expiry for '{}': expires in {} day(s) (at Unix timestamp {}).",
        "ok".green().bold(),
        key.bold(),
        days,
        expires_at
    );
    println!("  Run {} to check status.", "phantom expiry enforce".cyan());

    Ok(())
}

// ── phantom expiry enforce [--fail-closed] ───────────────────────────────────

/// One entry in the enforce report.
#[derive(Debug, Serialize)]
pub struct EnforceEntry {
    pub name: String,
    pub expires_at: u64,
    pub secs_overdue: u64,
    pub status: String,
}

/// `phantom expiry enforce [--fail-closed]`
///
/// Scans `.phantom.toml` per-secret `expires_at` fields and exits with status 1
/// if ANY secret has passed its expiry timestamp. Intended for pre-commit hooks
/// and CI pipelines to block deployments.
///
/// * `fail_closed` — if `true`, also exit 1 when there are NO secrets with an
///   expiry set (i.e. treat "no TTL policy" as a hard failure).
/// * `json`        — emit machine-readable JSON instead of human-readable output.
pub fn run_enforce(fail_closed: bool, json: bool) -> Result<()> {
    use phantom_core::rotation_strategy::check_expiry;
    use phantom_vault::metadata::now_secs;

    let project_dir = std::env::current_dir()?;
    let config_path = project_dir.join(".phantom.toml");

    if !config_path.exists() {
        anyhow::bail!(
            "No .phantom.toml found. Run {} first.",
            "phantom init".cyan().bold()
        );
    }

    let config = PhantomConfig::load(&config_path).context("Failed to load .phantom.toml")?;
    let now = now_secs();

    let mut expired: Vec<EnforceEntry> = Vec::new();
    let mut ok_count: usize = 0;
    let mut no_expiry_count: usize = 0;

    for (name, override_cfg) in &config.phantom.secrets {
        match override_cfg.expires_at {
            None => {
                no_expiry_count += 1;
            }
            Some(expires_at) => {
                let status = check_expiry(expires_at, 0, now);
                if status.is_expired() {
                    let secs_overdue = match status {
                        phantom_core::rotation_strategy::ExpiryStatus::Expired { secs_overdue } => {
                            secs_overdue
                        }
                        _ => 0,
                    };
                    expired.push(EnforceEntry {
                        name: name.clone(),
                        expires_at,
                        secs_overdue,
                        status: status.label(),
                    });
                } else {
                    ok_count += 1;
                }
            }
        }
    }

    if json {
        let out = serde_json::json!({
            "expired": expired,
            "ok_count": ok_count,
            "no_expiry_count": no_expiry_count,
            "fail_closed": fail_closed,
            "pass": expired.is_empty() && (!fail_closed || no_expiry_count == 0),
        });
        println!("{}", serde_json::to_string_pretty(&out)?);
    } else {
        if expired.is_empty() {
            if fail_closed && no_expiry_count > 0 {
                eprintln!(
                    "{} --fail-closed: {} secret(s) have no expiry policy set.",
                    "FAIL".red().bold(),
                    no_expiry_count
                );
            } else {
                println!(
                    "{} All {} secret(s) with expiry are within TTL ({} with no expiry).",
                    "ok".green().bold(),
                    ok_count,
                    no_expiry_count
                );
            }
        } else {
            eprintln!(
                "{} {} expired secret(s) detected:",
                "EXPIRED".red().bold(),
                expired.len()
            );
            for e in &expired {
                let days_overdue = e.secs_overdue / 86_400;
                eprintln!(
                    "   {} {}: {} ({} day(s) overdue)",
                    "x".red(),
                    e.name.bold(),
                    e.status,
                    days_overdue
                );
            }
            eprintln!(
                "\nRun a configured provider rotation to replace expired credentials. {} only remaps the local phm_ placeholder and does not reset expiry.",
                "phantom expiry rotate <KEY>".cyan()
            );
        }
    }

    // Exit 1 if expired, or if fail_closed with no-TTL secrets.
    let should_fail = !expired.is_empty() || (fail_closed && no_expiry_count > 0);

    if should_fail {
        std::process::exit(1);
    }

    Ok(())
}

// ── phantom expiry rotate <KEY> (deprecated token remap) ─────────────────────

/// `phantom expiry rotate <KEY>`
///
/// Deprecated compatibility command. Remaps the local Phantom token only; the
/// provider credential and all expiry/rotation metadata remain unchanged.
pub fn run_rotate(key: &str) -> Result<()> {
    let project_dir = std::env::current_dir()?;
    let config_path = project_dir.join(".phantom.toml");

    if !config_path.exists() {
        anyhow::bail!(
            "No .phantom.toml found. Run {} first.",
            "phantom init".cyan().bold()
        );
    }

    let config = PhantomConfig::load(&config_path).context("Failed to load .phantom.toml")?;
    let vault = phantom_vault::try_create_vault(config.local_project_id())?;

    // Ensure the secret exists.
    if !vault
        .exists(key)
        .with_context(|| format!("Failed to check whether '{key}' exists in the vault"))?
    {
        anyhow::bail!("Secret '{}' not found in vault.", key);
    }

    let metadata_before = vault
        .get_metadata(key)
        .context("Failed to read vault metadata")?;
    let env_path = project_dir.join(".env");
    crate::commands::rotate::remap_phantom_tokens(&env_path, &[key.to_string()])?;
    let metadata_after = vault
        .get_metadata(key)
        .context("Failed to re-read vault metadata")?;
    if metadata_before != metadata_after {
        anyhow::bail!("Token remap invariant failed: credential lifecycle metadata changed.");
    }
    phantom_core::audit::log("secret.token_remapped", Some(key));

    println!(
        "{} Remapped the local Phantom token for '{}'. Provider credential and expiry metadata are unchanged; this command is deprecated for credential rotation.",
        "ok".green().bold(),
        key.bold()
    );

    Ok(())
}
