use anyhow::{Context, Result};
use colored::Colorize;
use phantom_core::config::PhantomConfig;
use phantom_core::dotenv::DotenvFile;
use phantom_core::token::TokenMap;
use phantom_vault::VaultBackend;
use zeroize::Zeroize;

/// Remap all local phantom tokens without changing provider credentials.
///
/// The legacy `--with-expiry` and `--sync` combinations are rejected because a
/// placeholder remap is not evidence of credential rotation and must not renew
/// provider lifecycle metadata or deploy an unchanged credential.
pub fn run_with_expiry(sync_after: bool, expiry_days: Option<u64>) -> Result<()> {
    if expiry_days.is_some() {
        anyhow::bail!(
            "--with-expiry is not valid for a Phantom token remap: the provider credential is unchanged, so its TTL cannot be renewed. Use `phantom rotate --name <NAME> [--provider <PROVIDER>]` for a real provider rotation."
        );
    }
    if sync_after {
        anyhow::bail!(
            "--sync is not valid for a Phantom token remap: there is no new provider credential to deploy. Use `phantom rotate --name <NAME> [--provider <PROVIDER>] --sync` for a real provider rotation."
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
    let vault = phantom_vault::try_create_vault(config.local_project_id())
        .context("Failed to initialize vault")?;
    let names = vault.list().context("Failed to list secrets")?;
    let env_path =
        phantom_core::managed_dotenv::resolve_dotenv(&project_dir, &config, &names)?.path;

    if names.is_empty() {
        println!("{} No Phantom tokens to remap.", "!".yellow().bold());
        return Ok(());
    }

    remap_phantom_tokens(&env_path, &names)?;
    for name in &names {
        phantom_core::audit::log("secret.token_remapped", Some(name));
    }
    println!(
        "{} Remapped {} Phantom token(s) in .env. Provider credentials and expiry metadata are unchanged.",
        "ok".green().bold(),
        names.len()
    );

    Ok(())
}

/// Reject the legacy local auto-rotation schedule.
///
/// Called by `phantom rotate --schedule-strategy <STRATEGY>`.
pub fn run_with_schedule_strategy(
    _strategy_str: &str,
    _sync_after: bool,
    _expiry_days: Option<u64>,
) -> Result<()> {
    anyhow::bail!(
        "--schedule-strategy is deprecated and disabled: the legacy watcher only remapped local phm_ placeholders and did not rotate provider credentials. Configure a rotation_provider and use an explicitly reviewed provider rotation workflow."
    )
}

/// Replace local `phm_` placeholders under Phantom's cooperative project lock.
///
/// This deliberately has no access to vault metadata or deployment sync. Every
/// requested name must already be represented by a Phantom token, otherwise no
/// file is written. Before/after checks detect observable interference, but a
/// same-user process that ignores the lock can still swap the pathname between
/// verification and atomic rename; portable filesystems do not provide a true
/// pathname compare-and-swap.
pub(crate) fn remap_phantom_tokens(env_path: &std::path::Path, names: &[String]) -> Result<()> {
    remap_phantom_tokens_with(env_path, names, || {})
}

fn remap_phantom_tokens_with(
    env_path: &std::path::Path,
    names: &[String],
    before_commit: impl FnOnce(),
) -> Result<()> {
    let project_dir = env_path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| std::path::Path::new("."));
    let _transaction_lock = phantom_vault::acquire_project_transaction_lock(project_dir)
        .with_context(|| {
            format!(
                "Failed to acquire transaction lock for {}",
                project_dir.display()
            )
        })?;
    if !env_path.exists() {
        anyhow::bail!(
            "Cannot remap Phantom tokens: {} does not exist.",
            env_path.display()
        );
    }

    let before = std::fs::read(env_path)
        .with_context(|| format!("Failed to snapshot {}", env_path.display()))?;
    let dotenv = DotenvFile::parse_file(env_path)
        .with_context(|| format!("Failed to parse {}", env_path.display()))?;
    for name in names {
        let entry = dotenv
            .entries()
            .into_iter()
            .find(|entry| entry.key == *name)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "Cannot remap '{name}': it is not present in {}.",
                    env_path.display()
                )
            })?;
        if !entry.is_phantom {
            anyhow::bail!(
                "Cannot remap '{name}': its value in {} is not a protected phm_ token.",
                env_path.display()
            );
        }
    }

    let mut token_map = TokenMap::new();
    for name in names {
        token_map.insert(name.clone());
    }
    let (rewritten, mut originals) = dotenv.rewrite_with_phantoms(&token_map);
    for value in originals.values_mut() {
        value.zeroize();
    }
    originals.clear();

    before_commit();
    let current = std::fs::read(env_path)
        .with_context(|| format!("Failed to verify {} before commit", env_path.display()))?;
    if current != before {
        anyhow::bail!(
            "Cannot remap Phantom tokens: {} changed after it was read; no Phantom write was committed.",
            env_path.display()
        );
    }
    phantom_core::fs::atomic_write(env_path, rewritten.as_bytes())
        .with_context(|| format!("Failed to atomically rewrite {}", env_path.display()))?;
    Ok(())
}

fn read_expiry_metadata(vault: &dyn VaultBackend, name: &str) -> Result<Option<u64>> {
    Ok(vault
        .get_metadata(name)
        .with_context(|| format!("Failed to read rotation metadata for '{name}'"))?
        .and_then(|metadata| metadata.expires_at))
}

fn persist_provider_rotation_metadata(
    vault: &dyn VaultBackend,
    name: &str,
    expires_override: Option<u64>,
) -> Result<Option<u64>> {
    vault
        .record_provider_rotation(name, expires_override)
        .with_context(|| {
            format!(
                "Provider issued and Phantom stored a new credential for '{name}', but rotation metadata could not be persisted; provider cleanup and deployment sync were not attempted"
            )
        })
}

/// Current Unix timestamp in seconds.
fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Format a Unix timestamp as an ISO-8601-like UTC string for display.
fn chrono_iso(secs: u64) -> String {
    // Manual calculation to avoid pulling in chrono — only for display.
    let s = secs;
    let sec = s % 60;
    let min = (s / 60) % 60;
    let hour = (s / 3600) % 24;
    let days = s / 86_400;
    // Approximate date from days since epoch (good enough for display).
    let year = 1970 + days / 365;
    let rem_days = days % 365;
    let month = rem_days / 30 + 1;
    let day = rem_days % 30 + 1;
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{min:02}:{sec:02}Z")
}

/// Reject the legacy shadow-candidate path.
///
/// It generated only a local `phm_cand_` placeholder, not a provider-issued
/// credential, so neither staging nor later promotion was a real rotation.
pub fn run_shadow(_name: &str) -> Result<String> {
    anyhow::bail!(
        "--shadow is deprecated and disabled: Phantom's legacy implementation generated a local phm_cand_ placeholder, not a provider credential. No candidate was created or stored. Use `phantom rotate --name <NAME> [--provider <PROVIDER>]` for a real provider rotation."
    )
}

/// Reject legacy candidate validation and promotion without reading or writing
/// the vault. `promote` is retained only for call-site compatibility.
pub fn run_validate_promote(_name: &str, _promote: bool) -> Result<()> {
    anyhow::bail!(
        "--promote is deprecated and disabled: legacy shadow candidates were local phm_cand_ placeholders, not provider-issued credentials. No credential or metadata was changed. Use `phantom rotate --name <NAME> [--provider <PROVIDER>]` for a real provider rotation."
    )
}

/// Rotate a single named secret using a vendor-specific rotation provider.
///
/// Called by `phantom rotate --name <KEY> [--provider stripe|github|aws|google|vercel]`.
/// (`sentry` / `supabase` are recognized but report manual-rotation-required.)
///
/// When `provider` is `None` the provider is resolved from the secret's
/// `[phantom.secrets.<KEY>.rotation_provider]` block in `.phantom.toml`.
/// The bootstrap credential named by `api_key_env` is sourced from the
/// process environment first, then from the vault under the same name —
/// it is never echoed.
///
/// This delegates to the appropriate [`phantom_core::rotation_provider`]
/// implementation, which calls the vendor API to re-issue the credential.
/// The new value is stored in the vault (same write path as `phantom add`)
/// and the secret's `phm_` token in `.env` is refreshed; the value itself
/// is never printed to stdout. With `--json`, a metadata-only JSON object
/// is emitted for scripting.
pub fn run_with_provider(
    provider: Option<&str>,
    name: &str,
    sync_after: bool,
    json_output: bool,
) -> Result<()> {
    use phantom_core::rotation_provider::{
        auto_sync_rotation_with_bootstrap, default_rotation_providers,
    };

    let project_dir = std::env::current_dir()?;
    let config_path = project_dir.join(".phantom.toml");

    if !config_path.exists() {
        anyhow::bail!(
            "No .phantom.toml found. Run {} first.",
            "phantom init".cyan().bold()
        );
    }

    let config = PhantomConfig::load(&config_path).context("Failed to load .phantom.toml")?;
    let vault = phantom_vault::try_create_vault(config.local_project_id())
        .context("Failed to initialize vault")?;
    let vault_names = vault.list().context("Failed to list secrets")?;
    let env_path =
        phantom_core::managed_dotenv::resolve_dotenv(&project_dir, &config, &vault_names)?.path;

    // Resolve provider config from .phantom.toml.
    let provider_config = config
        .phantom
        .secrets
        .get(name)
        .and_then(|ov| ov.rotation_provider.as_ref());

    // GitHub App installation tokens are minted fresh from the App PEM, so a
    // github-provider target that does not exist yet is legal — the mint
    // creates it. Every other provider still requires an existing value to
    // rotate.
    let is_github_grant = provider_config
        .map(|cfg| cfg.provider.eq_ignore_ascii_case("github"))
        .unwrap_or(false);
    if !vault
        .exists(name)
        .with_context(|| format!("Failed to check if '{name}' exists in vault"))?
        && !is_github_grant
    {
        anyhow::bail!("Secret '{}' not found in vault.", name);
    }

    // Determine the effective provider: explicit --provider flag, else the
    // provider named in the secret's rotation_provider config block.
    let effective_provider: String = match (provider, provider_config) {
        (Some(requested), Some(cfg)) => {
            if cfg.provider != requested {
                anyhow::bail!(
                    "Secret '{}' is configured for provider '{}' but '{}' was requested.\n\
                     Update [phantom.secrets.{}.rotation_provider] in .phantom.toml.",
                    name,
                    cfg.provider,
                    requested,
                    name
                );
            }
            requested.to_string()
        }
        (requested, None) => {
            // No config in .phantom.toml — inform the user how to add it.
            anyhow::bail!(
                "No rotation_provider configured for secret '{}'.\n\
                 Add the following to .phantom.toml:\n\n\
                 [phantom.secrets.{}.rotation_provider]\n\
                 provider = \"{}\"\n\
                 api_key_env = \"<ENV_VAR_OR_VAULT_NAME_HOLDING_ROTATION_CREDENTIAL>\"",
                name,
                name,
                requested.unwrap_or("stripe")
            );
        }
        (None, Some(cfg)) => {
            if !json_output {
                println!(
                    "{} Using provider {} from .phantom.toml",
                    "->".blue().bold(),
                    cfg.provider.cyan().bold()
                );
            }
            cfg.provider.clone()
        }
    };

    // Source the bootstrap credential: environment variable first, then the
    // vault under the same name. The value is zeroized after the call and is
    // never printed.
    let mut bootstrap = if let Some(env_name) = provider_config
        .and_then(|cfg| cfg.api_key_env.as_deref())
        .filter(|env_name| std::env::var(env_name).is_err())
    {
        Some(vault.retrieve(env_name).with_context(|| {
            format!("Failed to retrieve rotation bootstrap credential '{env_name}'")
        })?)
    } else {
        None
    };

    // GitHub App grants vault the PEM (never a ready JWT) under api_key_env.
    // Mint the short-lived RS256 App JWT in-process from that PEM immediately
    // before rotation: it is never an env var, never on disk, and is zeroized
    // on drop; the PEM's only destination is GitHub. A non-PEM value (a mock
    // prefix, or a pre-minted JWT) passes through untouched.
    if effective_provider.eq_ignore_ascii_case("github") {
        if let Some(pem) = bootstrap.as_ref() {
            if pem.as_str().trim_start().starts_with("-----BEGIN") {
                let client_id = vault
                    .retrieve(phantom_core::issuance::github_app::GITHUB_APP_CLIENT_ID_NAME)
                    .context("Failed to retrieve GitHub App client ID")?;
                bootstrap = Some(
                    phantom_core::issuance::mint_app_jwt(pem, &client_id)
                        .context("Failed to mint GitHub App bootstrap JWT")?,
                );
            }
        }
    }

    if !json_output {
        println!(
            "{} Calling {} rotation API for {}…",
            "->".blue().bold(),
            effective_provider.cyan().bold(),
            name.bold()
        );
    }

    let providers = default_rotation_providers();

    // Capture the outgoing value BEFORE overwriting it: providers that revoke
    // the old credential at the vendor (Vercel) do so only after the new value
    // is durably stored, authenticating with the old value itself.
    let old_value = match vault.retrieve(name) {
        Ok(value) => Some(value),
        Err(phantom_core::error::PhantomError::SecretNotFound(_)) if is_github_grant => None,
        Err(error) => {
            return Err(error).with_context(|| {
                format!("Failed to snapshot the outgoing credential for '{name}'")
            });
        }
    };

    let new_value = auto_sync_rotation_with_bootstrap(name, provider_config, &providers, bootstrap)
        .map_err(|e| anyhow::anyhow!("Provider rotation failed for '{}': {}", name, e))?;

    match new_value {
        Some(secret) => {
            // Same vault write path as `phantom add`.
            vault
                .store(name, secret.as_str())
                .with_context(|| format!("Failed to store rotated value for '{name}'"))?;

            phantom_core::audit::log("vault.rotation.provider.stored", Some(name));

            // Refresh the phm_ token for this secret in .env so the old
            // token cannot resolve to the new credential.
            let mut env_token_refreshed = false;
            if env_path.exists() {
                remap_phantom_tokens(&env_path, &[name.to_string()])?;
                env_token_refreshed = true;
            }

            // Persist rotation metadata (rotated_at + recomputed expires_at).
            // GitHub App installation tokens expire after 1 hour, so stamp the
            // real short TTL instead of leaving a dead token looking fresh.
            let expires_override = if effective_provider.eq_ignore_ascii_case("github") {
                Some(
                    now_unix()
                        + phantom_core::rotation_provider::GITHUB_INSTALLATION_TOKEN_TTL_SECS,
                )
            } else {
                None
            };
            let expires_at =
                persist_provider_rotation_metadata(vault.as_ref(), name, expires_override)?;

            // The new value is stored — now (and only now) let the provider
            // best-effort revoke the OLD credential at the vendor.
            if let (Some(provider), Some(cfg)) = (
                providers
                    .iter()
                    .find(|p| p.name().eq_ignore_ascii_case(&effective_provider)),
                provider_config,
            ) {
                let _ = provider.post_store_cleanup(name, cfg, old_value.as_ref());
            }

            if json_output {
                let obj = serde_json::json!({
                    "secret": name,
                    "provider": effective_provider,
                    "status": "rotated",
                    "vendor_rotated": true,
                    "stored_in_vault": true,
                    "env_token_refreshed": env_token_refreshed,
                    "expires_at": expires_at,
                    "value_printed": false,
                });
                println!("{}", serde_json::to_string_pretty(&obj)?);
            } else {
                println!(
                    "{} Provider rotation succeeded for {} via {}.",
                    "ok".green().bold(),
                    name.bold(),
                    effective_provider.cyan()
                );
                println!("   The new credential has been stored in the vault.");
                if env_token_refreshed {
                    println!("   The phm_ token for {name} in .env was refreshed.");
                }
                if let Some(ts) = expires_at {
                    println!("   Expires at: {}", chrono_iso(ts));
                }
                println!("   The secret value was not printed for security.");
            }
        }
        None => {
            // auto_sync returns Ok(None) only for provider = "manual" now;
            // disabled configs and unknown provider names are hard errors
            // surfaced above with their own messages.
            anyhow::bail!(
                "Secret '{}' is configured with provider = \"manual\" — there is no vendor \
                 API to call.\nRotate the credential manually, then store it with `phantom add {}`.",
                name,
                name
            );
        }
    }

    if sync_after {
        if !json_output {
            println!("\n{} Syncing to deployment platforms…", "->".blue().bold());
        }
        crate::commands::sync::run(None, None, vec![], false, false)?;
    }

    Ok(())
}

/// Execute expiry-driven batch rotation across all vault secrets whose TTL
/// falls within `rotation_window_days`.
///
/// For secrets with a `rotation_provider` configured (Stripe, GitHub, AWS),
/// vendor API calls are made respecting per-provider rate limits.
/// For manual secrets the item is listed in the summary table but no value
/// change is made (operator must supply values manually).
///
/// Emits a composite audit event with a shared `batch_id` covering all rotations.
/// Prints a summary table: secret name | old expiry | new expiry | provider.
pub fn run_batch(
    rotation_window_days: u64,
    sync_after: bool,
    json_output: bool,
) -> anyhow::Result<()> {
    use phantom_core::rotation_provider::{
        batch_discover_due, default_rotation_providers, execute_batch_rotation,
    };

    let project_dir = std::env::current_dir()?;
    let config_path = project_dir.join(".phantom.toml");

    if !config_path.exists() {
        anyhow::bail!(
            "No .phantom.toml found. Run {} first.",
            "phantom init".cyan().bold()
        );
    }

    let config = PhantomConfig::load(&config_path).context("Failed to load .phantom.toml")?;
    let vault = phantom_vault::try_create_vault(config.local_project_id())
        .context("Failed to initialize vault")?;

    // Gather all secrets with their expiry metadata and provider config.
    let names = vault.list().context("Failed to list secrets")?;
    if names.is_empty() {
        println!("{} No secrets in vault.", "!".yellow().bold());
        return Ok(());
    }

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    // Build the scan input: (name, expires_at, provider_config)
    let mut scan_input: Vec<(
        String,
        Option<u64>,
        Option<phantom_core::rotation_provider::RotationProviderConfig>,
    )> = Vec::new();
    for name in &names {
        let expires_at = read_expiry_metadata(vault.as_ref(), name)?;
        let provider_config = config
            .phantom
            .secrets
            .get(name)
            .and_then(|ov| ov.rotation_provider.clone());
        scan_input.push((name.clone(), expires_at, provider_config));
    }

    let rotation_window_secs = rotation_window_days * 86_400;
    let providers = default_rotation_providers();

    let due_items = batch_discover_due(&scan_input, rotation_window_secs, now, &providers);

    if due_items.is_empty() {
        println!(
            "{} No secrets are due for rotation within the next {} day(s).",
            "ok".green().bold(),
            rotation_window_days
        );
        return Ok(());
    }

    println!(
        "{} Found {} secret(s) due for rotation within {} day(s).",
        "->".blue().bold(),
        due_items.len(),
        rotation_window_days
    );
    println!();

    // Execute the batch.
    let (batch_id, mut outcomes) = execute_batch_rotation(&due_items, &providers, now);

    // Store any new values returned by vendor providers, persist the new
    // expiry metadata (otherwise the same secrets stay perpetually "due" and
    // get re-rotated at the vendor on every run), and only then let the
    // provider best-effort revoke the old credential.
    for outcome in &mut outcomes {
        if let Some(ref new_value) = outcome.new_value {
            // Capture the outgoing value BEFORE overwriting it (needed by
            // providers whose post-store cleanup revokes the old credential).
            let old_value = Some(vault.retrieve(&outcome.secret_name).with_context(|| {
                format!(
                    "Failed to snapshot the outgoing credential for '{}'",
                    outcome.secret_name
                )
            })?);

            vault
                .store(&outcome.secret_name, new_value.as_str())
                .with_context(|| {
                    format!(
                        "Failed to store rotated value for '{}'",
                        outcome.secret_name
                    )
                })?;
            phantom_core::audit::log("vault.rotation.provider.stored", Some(&outcome.secret_name));

            // Persist rotated_at + recomputed expires_at so the reported new
            // expiry is REAL. GitHub App installation tokens expire in 1 hour.
            let expires_override = if outcome.provider_label.eq_ignore_ascii_case("github") {
                Some(now + phantom_core::rotation_provider::GITHUB_INSTALLATION_TOKEN_TTL_SECS)
            } else {
                None
            };
            outcome.new_expires_at = persist_provider_rotation_metadata(
                vault.as_ref(),
                &outcome.secret_name,
                expires_override,
            )?;

            // New value is durably stored — run post-store cleanup.
            if let Some(item) = due_items
                .iter()
                .find(|i| i.secret_name == outcome.secret_name)
            {
                if let (Some(provider), Some(cfg)) = (
                    providers
                        .iter()
                        .find(|p| p.name().eq_ignore_ascii_case(&outcome.provider_label)),
                    item.provider_config.as_ref(),
                ) {
                    let _ =
                        provider.post_store_cleanup(&outcome.secret_name, cfg, old_value.as_ref());
                }
            }
        }
    }

    // Also rotate phantom tokens for all successfully vendor-rotated secrets.
    let rotated_vendor_names: Vec<&str> = outcomes
        .iter()
        .filter(|o| o.vendor_rotated)
        .map(|o| o.secret_name.as_str())
        .collect();

    if !rotated_vendor_names.is_empty() {
        let vault_names = vault.list().context("Failed to list secrets")?;
        let env_path =
            phantom_core::managed_dotenv::resolve_dotenv(&project_dir, &config, &vault_names)?.path;
        if env_path.exists() {
            let names = rotated_vendor_names
                .iter()
                .map(|name| (*name).to_string())
                .collect::<Vec<_>>();
            remap_phantom_tokens(&env_path, &names)?;
        }
    }

    // Print summary table.
    if json_output {
        // Emit JSON array for scripting.
        let rows: Vec<serde_json::Value> = outcomes
            .iter()
            .map(|o| {
                serde_json::json!({
                    "secret": o.secret_name,
                    "old_expires_at": o.old_expires_at,
                    "new_expires_at": o.new_expires_at,
                    "provider": o.provider_label,
                    "vendor_rotated": o.vendor_rotated,
                    "ok": o.is_ok(),
                    "error": o.error,
                    "batch_id": batch_id,
                })
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&rows)?);
    } else {
        println!("{}", "Batch Rotation Summary".bold());
        println!("{}", "-".repeat(80));
        println!(
            "{:<32} {:<20} {:<20} {:<12} {}",
            "Secret".bold(),
            "Old Expiry".bold(),
            "New Expiry".bold(),
            "Provider".bold(),
            "Status".bold()
        );
        println!("{}", "-".repeat(80));

        for outcome in &outcomes {
            let old_exp = outcome
                .old_expires_at
                .map(chrono_iso)
                .unwrap_or_else(|| "none".to_string());
            let new_exp = outcome
                .new_expires_at
                .map(chrono_iso)
                .unwrap_or_else(|| "none".to_string());
            let status = if let Some(ref err) = outcome.error {
                format!(
                    "{} {}",
                    "FAIL".red().bold(),
                    err.chars().take(30).collect::<String>()
                )
            } else if outcome.vendor_rotated {
                format!("{} via {}", "ok".green().bold(), outcome.provider_label)
            } else if outcome.new_value.is_none() && outcome.error.is_none() {
                format!("{} (manual rotation needed)", "!".yellow().bold())
            } else {
                "ok".green().bold().to_string()
            };

            println!(
                "{:<32} {:<20} {:<20} {:<12} {}",
                outcome.secret_name.chars().take(31).collect::<String>(),
                old_exp,
                new_exp,
                outcome.provider_label.chars().take(11).collect::<String>(),
                status
            );
        }

        println!("{}", "-".repeat(80));
        let succeeded = outcomes
            .iter()
            .filter(|o| o.is_ok() && o.vendor_rotated)
            .count();
        let manual = outcomes
            .iter()
            .filter(|o| o.is_ok() && !o.vendor_rotated)
            .count();
        let failed = outcomes.iter().filter(|o| !o.is_ok()).count();
        println!(
            "\n{} Batch {}: {} vendor-rotated, {} manual, {} failed",
            "ok".green().bold(),
            batch_id.cyan(),
            succeeded,
            manual,
            failed
        );
        println!(
            "   Audit events tagged with {}",
            format!("batch_id={batch_id}").cyan()
        );
    }

    if sync_after && outcomes.iter().any(|o| o.vendor_rotated) {
        println!("\n{} Syncing to deployment platforms…", "->".blue().bold());
        crate::commands::sync::run(None, None, vec![], false, false)?;
    }

    Ok(())
}

#[cfg(test)]
mod token_remap_tests {
    use super::*;
    use phantom_core::error::{PhantomError, Result as PhantomResult};
    use phantom_core::validator::ValidationMetadata;
    use phantom_vault::SecretMetadata;
    use tempfile::tempdir;
    use zeroize::Zeroizing;

    #[test]
    fn remap_changes_only_requested_protected_placeholder() {
        let dir = tempdir().unwrap();
        let env_path = dir.path().join(".env");
        let old = format!("phm_{}", "a".repeat(64));
        let untouched = format!("phm_{}", "b".repeat(64));
        std::fs::write(
            &env_path,
            format!("TARGET={old}\nOTHER={untouched}\nPUBLIC=yes\n"),
        )
        .unwrap();

        remap_phantom_tokens(&env_path, &["TARGET".to_string()]).unwrap();

        let rewritten = std::fs::read_to_string(&env_path).unwrap();
        assert!(!rewritten.contains(&format!("TARGET={old}")));
        assert!(rewritten.contains("TARGET=phm_"));
        assert!(rewritten.contains(&format!("OTHER={untouched}")));
        assert!(rewritten.contains("PUBLIC=yes"));
    }

    #[test]
    fn remap_fails_closed_for_plaintext_and_preserves_file() {
        let dir = tempdir().unwrap();
        let env_path = dir.path().join(".env");
        let before = "TARGET=real-provider-value\n";
        std::fs::write(&env_path, before).unwrap();

        let error = remap_phantom_tokens(&env_path, &["TARGET".to_string()]).unwrap_err();

        assert!(error.to_string().contains("not a protected phm_ token"));
        assert_eq!(std::fs::read_to_string(&env_path).unwrap(), before);
    }

    #[test]
    fn remap_detects_concurrent_file_change_and_preserves_the_other_writer() {
        let dir = tempdir().unwrap();
        let env_path = dir.path().join(".env");
        let old = format!("phm_{}", "a".repeat(64));
        std::fs::write(&env_path, format!("TARGET={old}\n")).unwrap();

        let error = remap_phantom_tokens_with(&env_path, &["TARGET".to_string()], || {
            std::fs::write(&env_path, b"TARGET=concurrent-owner\n").unwrap();
        })
        .unwrap_err();

        assert!(error.to_string().contains("changed after it was read"));
        assert_eq!(
            std::fs::read(&env_path).unwrap(),
            b"TARGET=concurrent-owner\n"
        );
    }

    struct MetadataFailingVault {
        fail_read: bool,
    }

    impl VaultBackend for MetadataFailingVault {
        fn store(&self, _name: &str, _value: &str) -> PhantomResult<()> {
            Ok(())
        }
        fn retrieve(&self, name: &str) -> PhantomResult<Zeroizing<String>> {
            Err(PhantomError::SecretNotFound(name.to_string()))
        }
        fn delete(&self, _name: &str) -> PhantomResult<()> {
            Ok(())
        }
        fn list(&self) -> PhantomResult<Vec<String>> {
            Ok(Vec::new())
        }
        fn backend_name(&self) -> &str {
            "metadata-failure"
        }
        fn get_metadata(&self, _name: &str) -> PhantomResult<Option<SecretMetadata>> {
            if self.fail_read {
                Err(PhantomError::VaultError(
                    "injected metadata read failure".into(),
                ))
            } else {
                Ok(Some(SecretMetadata::default()))
            }
        }
        fn set_metadata(&self, _name: &str, _meta: SecretMetadata) -> PhantomResult<()> {
            Err(PhantomError::VaultError(
                "injected metadata write failure".into(),
            ))
        }
        fn get_validation_metadata(&self, _name: &str) -> PhantomResult<ValidationMetadata> {
            Ok(ValidationMetadata::default())
        }
    }

    #[test]
    fn provider_metadata_read_and_write_errors_fail_closed() {
        let read_error =
            read_expiry_metadata(&MetadataFailingVault { fail_read: true }, "TARGET").unwrap_err();
        assert!(read_error
            .to_string()
            .contains("Failed to read rotation metadata"));

        let write_error = persist_provider_rotation_metadata(
            &MetadataFailingVault { fail_read: false },
            "TARGET",
            None,
        )
        .unwrap_err();
        assert!(write_error
            .to_string()
            .contains("rotation metadata could not be persisted"));
        assert!(write_error
            .to_string()
            .contains("cleanup and deployment sync were not attempted"));
    }

    #[test]
    fn local_remap_rejects_ttl_sync_and_schedule_claims_before_mutation() {
        assert!(run_with_expiry(true, None)
            .unwrap_err()
            .to_string()
            .contains("no new provider credential"));
        assert!(run_with_expiry(false, Some(30))
            .unwrap_err()
            .to_string()
            .contains("TTL cannot be renewed"));
        assert!(run_with_schedule_strategy("daily", false, None)
            .unwrap_err()
            .to_string()
            .contains("deprecated and disabled"));
    }

    #[test]
    fn legacy_shadow_create_and_promote_are_hard_denials() {
        let create_error = run_shadow("OPENAI_API_KEY").unwrap_err().to_string();
        assert!(create_error.contains("deprecated and disabled"));
        assert!(create_error.contains("No candidate was created or stored"));

        let promote_error = run_validate_promote("OPENAI_API_KEY", true)
            .unwrap_err()
            .to_string();
        assert!(promote_error.contains("deprecated and disabled"));
        assert!(promote_error.contains("No credential or metadata was changed"));
    }
}
