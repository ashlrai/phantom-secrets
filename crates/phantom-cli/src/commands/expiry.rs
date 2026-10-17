//! `phantom secrets-expiring-soon` and `phantom expiry` — TTL-based expiry enforcement.
//!
//! `phantom secrets-expiring-soon` returns a table/JSON of secrets near expiry (default 7d).
//! `phantom expiry set <KEY> <DAYS>` — store lifecycle policy in vault metadata.
//! `phantom expiry enforce [--fail-closed]` — exit 1 if any secret is expired.
//! `phantom expiry rotate <KEY>` — deprecated compatibility token remap.

use anyhow::{Context, Result};
use colored::Colorize;
use phantom_core::config::PhantomConfig;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::io::{IsTerminal, Write};

/// One entry in the expiry report.
#[derive(Debug, Serialize)]
pub struct ExpiryEntry {
    /// Secret name (never includes the value).
    pub name: String,
    /// Whole days remaining until expiry, floored: negative means already
    /// expired (a secret that expired under 24 h ago reports `-1`).
    pub days_remaining: i64,
    /// Unix timestamp of the expiry instant.
    pub expires_at: u64,
    /// Human-readable status string (e.g. "3 days remaining", "EXPIRED").
    pub status: String,
    /// `true` when the expiry instant has passed (`days_remaining < 0`).
    pub expired: bool,
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
            "--sync is not valid with the deprecated --auto-rotate token remap: provider credentials are unchanged. Rotate at the provider, store the replacement from a trusted terminal, then run an explicitly reviewed sync; automated live provider issuance is disabled."
        );
    }

    let project_dir = crate::util::project_dir()?;
    let config_path = project_dir.join(".phantom.toml");

    if !config_path.exists() {
        return Err(crate::util::missing_config_error(&project_dir));
    }

    let config = PhantomConfig::load(&config_path).context("Failed to load .phantom.toml")?;
    if auto_rotate {
        crate::commands::add::validate_managed_dotenv_preflight(&project_dir, &config).context(
            "Managed dotenv is malformed; auto-rotate stopped before vault, metadata, or output effects",
        )?;
    }
    let vault = crate::util::open_vault(config.local_project_id())?;

    let entries = vault
        .list_with_metadata()
        .context("Failed to read vault metadata")?;
    // A locked file vault would otherwise read as "nothing expiring".
    let note =
        crate::util::inventory_guard(vault.as_ref(), config.local_project_id(), entries.len())?;
    crate::util::warn_inventory_note(note.as_deref());

    let expiring = collect_expiring(&entries, warn_days);

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

/// Secrets that are expired or expire within `warn_days`, most urgent first.
/// Never reads secret values; only names and lifecycle metadata.
fn collect_expiring(
    entries: &[(String, Option<phantom_vault::SecretMetadata>)],
    warn_days: u64,
) -> Vec<ExpiryEntry> {
    let mut expiring: Vec<ExpiryEntry> = entries
        .iter()
        .filter_map(|(entry_name, meta)| {
            let m = meta.as_ref()?;
            let expires_at = m.expires_at?;
            let days_remaining = m.days_remaining()?;
            // Include expired (days_remaining < 0) and expiring soon.
            if days_remaining <= warn_days as i64 {
                Some(ExpiryEntry {
                    name: entry_name.clone(),
                    days_remaining,
                    expires_at,
                    status: m.ttl_status(),
                    expired: days_remaining < 0,
                })
            } else {
                None
            }
        })
        .collect();

    // Sort: most-urgent first (lowest / most-negative days_remaining).
    expiring.sort_by_key(|e| e.days_remaining);
    expiring
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
    let names = expiring
        .iter()
        .map(|entry| entry.name.clone())
        .collect::<Vec<_>>();
    let vault_names = vault.list().context("Failed to list protected secrets")?;
    let env_path =
        phantom_core::managed_dotenv::resolve_dotenv(&project_dir, config, &vault_names)?.path;

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
/// Stores `expires_at` and the rotation policy atomically with the secret's
/// existing lifecycle metadata.
pub fn run_set(key: &str, days: u64) -> Result<()> {
    let project_dir = std::env::current_dir()?.canonicalize()?;
    let config_path = project_dir.join(".phantom.toml");

    if !config_path.exists() {
        return Err(crate::util::missing_config_error(&project_dir));
    }

    let config_before =
        phantom_core::fs::read_regular_file(&config_path)?.context("Project is not initialized")?;
    let config = PhantomConfig::load_from_bytes(&config_path, &config_before)
        .context("Failed to load exact .phantom.toml snapshot")?;
    let vault = phantom_vault::try_create_vault(config.local_project_id())?;
    if !vault
        .exists(key)
        .with_context(|| format!("Failed to check whether '{key}' exists in the vault"))?
    {
        anyhow::bail!(
            "Secret '{}' not found in vault; no policy was written.",
            key
        );
    }
    let before = vault
        .get_metadata(key)
        .context("Failed to snapshot expiry metadata")?;
    require_trusted_terminal_expiry_set(
        &project_dir,
        config.local_project_id(),
        &config_before,
        key,
        days,
        before.as_ref(),
    )?;
    let mut after = before.clone().unwrap_or_default();
    after.rotation_policy = Some(phantom_vault::RotationPolicy {
        days_ttl: days,
        auto_rotate: false,
    });
    let expires_at =
        phantom_vault::metadata::now_secs().saturating_add(days.saturating_mul(86_400));
    after.expires_at = Some(expires_at);
    if !vault
        .compare_and_swap_metadata(key, before.as_ref(), Some(after))
        .context("Failed to atomically persist expiry policy")?
    {
        anyhow::bail!("Expiry metadata changed concurrently; no policy was written.");
    }

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

fn require_trusted_terminal_expiry_set(
    project_dir: &std::path::Path,
    project_id: &str,
    config_before: &[u8],
    key: &str,
    days: u64,
    metadata_before: Option<&phantom_vault::SecretMetadata>,
) -> Result<()> {
    if !std::io::stdin().is_terminal()
        || !std::io::stdout().is_terminal()
        || !std::io::stderr().is_terminal()
    {
        anyhow::bail!("`phantom expiry set` requires attached stdin, stdout, and stderr terminals; no expiry policy was written");
    }
    let mut digest = Sha256::new();
    digest.update(b"phantom-expiry-set-v1\0");
    digest.update(config_before);
    digest.update(serde_json::to_vec(&metadata_before)?);
    let challenge = format!(
        "SET EXPIRY {} DAYS {} IN {} ID {} DIGEST {}",
        key,
        days,
        project_dir.display(),
        project_id,
        hex::encode(digest.finalize())
    );
    eprintln!("This changes persistent local credential lifecycle policy.\nType this exact challenge to continue:\n{challenge}");
    eprint!("> ");
    std::io::stderr().flush()?;
    let mut response = String::new();
    std::io::stdin().read_line(&mut response)?;
    if response.trim_end_matches(['\r', '\n']) != challenge {
        anyhow::bail!("Expiry confirmation did not match exactly; no policy was written");
    }
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
/// Scans vault lifecycle metadata and exits with status 1
/// if ANY secret has passed its expiry timestamp. Intended for pre-commit hooks
/// and CI pipelines to block deployments.
///
/// * `fail_closed` — if `true`, also exit 1 when there are NO secrets with an
///   expiry set (i.e. treat "no TTL policy" as a hard failure).
/// * `json`        — emit machine-readable JSON instead of human-readable output.
pub fn run_enforce(fail_closed: bool, json: bool) -> Result<()> {
    use phantom_core::rotation_strategy::check_expiry;
    use phantom_vault::metadata::now_secs;

    let project_dir = crate::util::project_dir()?;
    let config_path = project_dir.join(".phantom.toml");

    if !config_path.exists() {
        return Err(crate::util::missing_config_error(&project_dir));
    }

    let config = PhantomConfig::load(&config_path).context("Failed to load .phantom.toml")?;
    let vault = crate::util::open_vault(config.local_project_id())?;
    let now = now_secs();

    let mut expired: Vec<EnforceEntry> = Vec::new();
    let mut ok_count: usize = 0;
    let mut no_expiry_count: usize = 0;

    let entries = vault
        .list_with_metadata()
        .context("Failed to read vault lifecycle metadata")?;
    // A gate: it must not pass over secrets in a vault it cannot open.
    crate::util::require_complete_inventory(
        vault.as_ref(),
        config.local_project_id(),
        entries.len(),
        "enforce expiry",
    )?;
    for (name, metadata) in entries {
        match metadata.and_then(|metadata| metadata.expires_at) {
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
                        name,
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
        return Err(crate::util::missing_config_error(&project_dir));
    }

    let config = PhantomConfig::load(&config_path).context("Failed to load .phantom.toml")?;
    crate::commands::add::validate_managed_dotenv_preflight(&project_dir, &config).context(
        "Managed dotenv is malformed; expiry token remap stopped before vault, metadata, or output effects",
    )?;
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
    let vault_names = vault.list().context("Failed to list protected secrets")?;
    let env_path =
        phantom_core::managed_dotenv::resolve_dotenv(&project_dir, &config, &vault_names)?.path;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn headless_expiry_consent_denies_without_write_authority() {
        if !std::io::stdin().is_terminal()
            || !std::io::stdout().is_terminal()
            || !std::io::stderr().is_terminal()
        {
            let error = require_trusted_terminal_expiry_set(
                std::path::Path::new("/tmp/project"),
                "local-id",
                b"config",
                "API_KEY",
                30,
                None,
            )
            .unwrap_err()
            .to_string();
            assert!(error.contains("no expiry policy was written"));
        }
    }

    #[test]
    fn recently_expired_secret_reports_negative_days_and_expired() {
        let now = phantom_vault::metadata::now_secs();
        let meta = |expires_at| {
            Some(phantom_vault::SecretMetadata {
                expires_at: Some(expires_at),
                ..Default::default()
            })
        };
        let entries = vec![
            ("SOON".to_string(), meta(now + 3 * 86_400 + 600)),
            ("JUST_EXPIRED".to_string(), meta(now - 3_600)),
            ("FAR".to_string(), meta(now + 90 * 86_400)),
            ("NO_EXPIRY".to_string(), None),
        ];
        let report = collect_expiring(&entries, 7);
        let names: Vec<&str> = report.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, ["JUST_EXPIRED", "SOON"]);
        assert_eq!(report[0].days_remaining, -1);
        assert!(report[0].expired);
        assert_eq!(report[0].status, "EXPIRED");
        assert_eq!(report[1].days_remaining, 3);
        assert!(!report[1].expired);
        let json = serde_json::to_value(&report).unwrap();
        assert_eq!(json[0]["expired"], true);
        assert_eq!(json[1]["expired"], false);
    }
}

#[cfg(all(test, unix))]
mod locked_vault_tests {
    use crate::util::test_seam::{empty_keychain, keychain_with_one, LockedProject};

    /// `phantom expiry enforce` is a CI gate. It passed (exit 0, "All 0
    /// secret(s) ... within TTL"), even with --fail-closed, when the secrets
    /// were in a vault it could not open.
    #[test]
    fn enforce_fails_on_a_locked_file_vault() {
        let _project = LockedProject::new(empty_keychain);
        for (fail_closed, json) in [(false, false), (true, false), (false, true)] {
            let error = super::run_enforce(fail_closed, json).unwrap_err();
            assert!(error.to_string().starts_with("Vault locked:"), "{error:#}");
        }
    }

    #[test]
    fn enforce_fails_on_a_keychain_only_view() {
        let _project = LockedProject::new(keychain_with_one);
        let error = super::run_enforce(false, true).unwrap_err().to_string();
        assert!(
            error.starts_with("Refusing to enforce expiry from a partial inventory"),
            "{error}"
        );
    }

    /// `phantom secrets-expiring-soon` answered "No secrets expiring".
    #[test]
    fn expiring_soon_refuses_a_locked_file_vault() {
        let _project = LockedProject::new(empty_keychain);
        let error = super::run(7, false, false, true).unwrap_err();
        assert!(error.to_string().starts_with("Vault locked:"), "{error:#}");
    }
}
