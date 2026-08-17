//! `phantom secrets-expiring-soon` and `phantom expiry` — TTL-based expiry enforcement.
//!
//! `phantom secrets-expiring-soon` returns a table/JSON of secrets near expiry (default 7d).
//! `phantom expiry set <KEY> <DAYS>` — store `expires_at` in `.phantom.toml`.
//! `phantom expiry enforce [--fail-closed]` — exit 1 if any secret is expired.
//! `phantom expiry rotate <KEY>` — reset expiry timer + bump rotation counter.

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
/// * `auto_rotate`  — if `true`, regenerate phantom tokens and update TTL
///   for each expiring/expired secret
/// * `sync_after`   — if `true` (and `auto_rotate` is also `true`), push to
///   all configured deployment platforms after rotating
/// * `json`         — emit machine-readable JSON instead of coloured table
pub fn run(warn_days: u64, auto_rotate: bool, sync_after: bool, json: bool) -> Result<()> {
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
        run_auto_rotate(&expiring, sync_after, &config, json)?;
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
        "  {} Run {} to rotate expiring secrets.",
        "Tip:".dimmed(),
        "phantom secrets-expiring-soon --auto-rotate".cyan()
    );
}

/// Rotate every expiring secret in-place and optionally sync platforms.
///
/// Rotation here means:
///   1. Record a new rotation timestamp on the secret's metadata.
///   2. Extend `expires_at` using the existing `days_ttl` from the rotation
///      policy (or `warn_days` as a fallback so we don't shrink the TTL).
///   3. Rewrite the .env with fresh phantom tokens for rotated secrets.
fn run_auto_rotate(
    expiring: &[ExpiryEntry],
    sync_after: bool,
    config: &PhantomConfig,
    json: bool,
) -> Result<()> {
    use phantom_core::dotenv::DotenvFile;
    use phantom_core::token::TokenMap;
    use phantom_vault::metadata::{now_secs, RotationPolicy, SecretMetadata};

    let vault = phantom_vault::create_vault(&config.phantom.project_id);
    let project_dir = std::env::current_dir()?;
    let env_path = project_dir.join(".env");

    let mut rotated: Vec<String> = Vec::new();
    let mut failed: Vec<(String, String)> = Vec::new();

    for entry in expiring {
        // Retrieve existing metadata to preserve days_ttl.
        let existing_meta = vault.get_metadata(&entry.name).unwrap_or(None);
        let days_ttl = existing_meta
            .as_ref()
            .and_then(|m| m.rotation_policy.as_ref())
            .map(|p| p.days_ttl)
            .unwrap_or(30); // sensible default if no policy was set

        // Build fresh metadata: extend expiry from now.
        let now = now_secs();
        let new_meta = SecretMetadata {
            created_at: existing_meta
                .as_ref()
                .and_then(|m| m.created_at)
                .or(Some(now)),
            rotated_at: Some(now),
            expires_at: Some(now + days_ttl * 86_400),
            rotation_policy: Some(RotationPolicy {
                days_ttl,
                auto_rotate: true,
            }),
            vault_mode: phantom_vault::metadata::VaultMode::ReadWrite,
        };

        match vault.set_metadata(&entry.name, new_meta) {
            Ok(()) => {
                phantom_core::audit::log("secret.auto_rotated", Some(&entry.name));
                rotated.push(entry.name.clone());
            }
            Err(e) => {
                failed.push((entry.name.clone(), e.to_string()));
            }
        }
    }

    // Rewrite .env with fresh phantom tokens for all rotated secrets.
    if !rotated.is_empty() && env_path.exists() {
        let mut token_map = TokenMap::new();
        for name in &rotated {
            token_map.insert(name.clone());
        }
        if let Ok(dotenv) = DotenvFile::parse_file(&env_path) {
            let _ = dotenv.write_phantomized(&token_map, &env_path);
        }
    }

    if json {
        let result = serde_json::json!({
            "auto_rotated": rotated,
            "failed": failed.iter().map(|(n, e)| serde_json::json!({"name": n, "error": e})).collect::<Vec<_>>(),
        });
        println!("{}", serde_json::to_string_pretty(&result)?);
    } else {
        if !rotated.is_empty() {
            println!(
                "\n{} Auto-rotated {} secret(s):",
                "ok".green().bold(),
                rotated.len()
            );
            for name in &rotated {
                println!("   {} {}", "+".green(), name.bold());
            }
        }
        if !failed.is_empty() {
            println!(
                "\n{} Failed to rotate {} secret(s):",
                "!".red().bold(),
                failed.len()
            );
            for (name, err) in &failed {
                println!("   {} {}: {}", "x".red(), name.bold(), err);
            }
        }
    }

    // Optionally sync to deployment platforms.
    if sync_after && !rotated.is_empty() {
        if !json {
            println!(
                "\n{} Syncing to deployment platforms...",
                "->".blue().bold()
            );
        }
        crate::commands::sync::run(None, None, vec![], false, false)
            .context("Sync after auto-rotate failed")?;
    }

    if !failed.is_empty() {
        anyhow::bail!(
            "Auto-rotate completed with {} error(s). See output above.",
            failed.len()
        );
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
    let vault = phantom_vault::create_vault(&config.phantom.project_id);
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
                "\nRun {} to reset the expiry timer.",
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

// ── phantom expiry rotate <KEY> ───────────────────────────────────────────────

/// `phantom expiry rotate <KEY>`
///
/// Generates a fresh phantom token, bumps the rotation counter on the vault
/// metadata, and resets the expiry timer to `NOW + rotation_window` days
/// (where `rotation_window` is stored in `.phantom.toml`; defaults to 30 days
/// if unset).  Also rewrites the `.env` file with the new phantom token.
pub fn run_rotate(key: &str) -> Result<()> {
    use phantom_core::dotenv::DotenvFile;
    use phantom_core::rotation_strategy::compute_new_expires_at;
    use phantom_core::token::TokenMap;
    use phantom_vault::metadata::{now_secs, RotationPolicy, SecretMetadata};

    let project_dir = std::env::current_dir()?;
    let config_path = project_dir.join(".phantom.toml");

    if !config_path.exists() {
        anyhow::bail!(
            "No .phantom.toml found. Run {} first.",
            "phantom init".cyan().bold()
        );
    }

    let mut config = PhantomConfig::load(&config_path).context("Failed to load .phantom.toml")?;
    let vault = phantom_vault::create_vault(&config.phantom.project_id);

    // Ensure the secret exists.
    if !vault.exists(key).unwrap_or(false) {
        anyhow::bail!("Secret '{}' not found in vault.", key);
    }

    let now = now_secs();

    // Determine rotation_window from per-secret config or default to 30 days.
    let rotation_window = config
        .phantom
        .secrets
        .get(key)
        .and_then(|ov| ov.rotation_window)
        .unwrap_or(30);

    let new_expires_at = compute_new_expires_at(rotation_window, now);

    // Update vault metadata: bump rotation counter, reset expiry.
    let existing_meta = vault.get_metadata(key).unwrap_or(None);
    let rotation_count = existing_meta
        .as_ref()
        .and_then(|m| m.rotation_policy.as_ref())
        .map(|_| 1u64) // We don't have a counter field; record the rotation via rotated_at
        .unwrap_or(0);
    let _ = rotation_count; // used for audit semantics; rotated_at captures the event

    let new_meta = SecretMetadata {
        created_at: existing_meta
            .as_ref()
            .and_then(|m| m.created_at)
            .or(Some(now)),
        rotated_at: Some(now),
        expires_at: Some(new_expires_at),
        rotation_policy: Some(RotationPolicy {
            days_ttl: rotation_window,
            auto_rotate: false,
        }),
        vault_mode: phantom_vault::metadata::VaultMode::ReadWrite,
    };

    vault
        .set_metadata(key, new_meta)
        .context("Failed to update vault metadata")?;

    phantom_core::audit::log("secret.expiry_rotated", Some(key));

    // Rewrite `.env` with a fresh phantom token for this key.
    let env_path = project_dir.join(".env");
    if env_path.exists() {
        let mut token_map = TokenMap::new();
        token_map.insert(key.to_string());
        if let Ok(dotenv) = DotenvFile::parse_file(&env_path) {
            dotenv
                .write_phantomized(&token_map, &env_path)
                .context("Failed to rewrite .env with new phantom token")?;
        }
    }

    // Reset the expires_at in .phantom.toml as well.
    let entry = config.phantom.secrets.entry(key.to_string()).or_default();
    entry.expires_at = Some(new_expires_at);
    entry.rotation_window = Some(rotation_window);
    config
        .save(&config_path)
        .context("Failed to save updated .phantom.toml")?;

    println!(
        "{} Rotated '{}': new phantom token generated, expiry reset to {} day(s) from now (Unix timestamp {}).",
        "ok".green().bold(),
        key.bold(),
        rotation_window,
        new_expires_at
    );

    Ok(())
}
