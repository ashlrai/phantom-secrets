use anyhow::{Context, Result};
use colored::Colorize;
use phantom_core::config::PhantomConfig;
use phantom_core::dotenv::DotenvFile;
use phantom_core::token::TokenMap;

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
    let env_path = project_dir.join(".env");

    if !config_path.exists() {
        anyhow::bail!(
            "No .phantom.toml found. Run {} first.",
            "phantom init".cyan().bold()
        );
    }

    let config = PhantomConfig::load(&config_path).context("Failed to load .phantom.toml")?;
    let vault = phantom_vault::create_vault(config.local_project_id());
    let names = vault.list().context("Failed to list secrets")?;

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

/// Atomically replace the local `phm_` placeholders for `names`.
///
/// This deliberately has no access to vault metadata or deployment sync. Every
/// requested name must already be represented by a Phantom token, otherwise no
/// file is written.
pub(crate) fn remap_phantom_tokens(env_path: &std::path::Path, names: &[String]) -> Result<()> {
    if !env_path.exists() {
        anyhow::bail!(
            "Cannot remap Phantom tokens: {} does not exist.",
            env_path.display()
        );
    }

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
    dotenv
        .write_phantomized(&token_map, env_path)
        .with_context(|| format!("Failed to atomically rewrite {}", env_path.display()))?;
    Ok(())
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

/// Rotate a single secret using shadow mode: generate a new candidate value,
/// store it under `<name>__SHADOW_CANDIDATE` in the vault, and save shadow
/// metadata so the candidate can be validated and promoted later.
///
/// Returns the shadow ID on success.
pub fn run_shadow(name: &str) -> Result<String> {
    use phantom_vault::shadowing::{shadow_dir, ShadowStore, ShadowedSecret};

    let project_dir = std::env::current_dir()?;
    let config_path = project_dir.join(".phantom.toml");

    if !config_path.exists() {
        anyhow::bail!(
            "No .phantom.toml found. Run {} first.",
            "phantom init".cyan().bold()
        );
    }

    let config = PhantomConfig::load(&config_path).context("Failed to load .phantom.toml")?;
    let vault = phantom_vault::create_vault(config.local_project_id());

    if !vault
        .exists(name)
        .context("Failed to check secret existence")?
    {
        anyhow::bail!("Secret '{}' not found in vault.", name);
    }

    // Retrieve the current (primary) value
    let primary = vault
        .retrieve(name)
        .with_context(|| format!("Failed to retrieve secret '{name}'"))?;

    // Generate a new candidate value (random hex token as placeholder;
    // in production this would call the appropriate importer/generator)
    let candidate = generate_candidate_value();

    // Store candidate in the vault under a shadow key
    let shadow_key = format!("{name}__SHADOW_CANDIDATE");
    vault
        .store(&shadow_key, &candidate)
        .with_context(|| format!("Failed to store shadow candidate for '{name}'"))?;

    phantom_core::audit::log("shadow.candidate_created", Some(name));

    // Persist shadow metadata (no secret values — just status + audit trail)
    let shadow = ShadowedSecret::new(
        name,
        primary.as_str(),
        &candidate,
        None, // no auto-promote TTL by default
    );
    let shadow_id = shadow.shadow_id.clone();

    let store = ShadowStore::new(shadow_dir(config.local_project_id()))
        .context("Failed to open shadow store")?;
    store
        .save(&shadow)
        .context("Failed to save shadow metadata")?;

    println!(
        "{} Shadow candidate created for {}",
        "ok".green().bold(),
        name.bold()
    );
    println!("   Shadow ID : {shadow_id}");
    println!(
        "   To validate: {}",
        format!("phantom validate {name} --promote").cyan()
    );
    println!(
        "   Candidate mode: set {} to inject candidate in proxy sessions",
        "PHANTOM_CANDIDATE_MODE=1".cyan()
    );

    Ok(shadow_id)
}

/// Validate the shadow candidate for `name` and optionally promote it.
///
/// When `promote` is `true` and validation succeeds the candidate becomes
/// the new primary and the old primary is discarded.
pub fn run_validate_promote(name: &str, promote: bool) -> Result<()> {
    use phantom_vault::shadowing::{shadow_dir, ShadowStore};

    let project_dir = std::env::current_dir()?;
    let config_path = project_dir.join(".phantom.toml");

    if !config_path.exists() {
        anyhow::bail!(
            "No .phantom.toml found. Run {} first.",
            "phantom init".cyan().bold()
        );
    }

    let config = PhantomConfig::load(&config_path).context("Failed to load .phantom.toml")?;
    let vault = phantom_vault::create_vault(config.local_project_id());

    let store = ShadowStore::new(shadow_dir(config.local_project_id()))
        .context("Failed to open shadow store")?;

    let meta = store
        .load_meta(name)
        .context("Failed to load shadow metadata")?
        .ok_or_else(|| {
            anyhow::anyhow!(
                "No shadow exists for secret '{name}'. Run `phantom rotate {name} --shadow` first."
            )
        })?;

    println!(
        "{} Shadow status for {}: {}",
        "->".blue().bold(),
        name.bold(),
        meta.promotion_status
    );

    // Retrieve the candidate from the vault
    let shadow_key = format!("{name}__SHADOW_CANDIDATE");
    let candidate = vault
        .retrieve(&shadow_key)
        .with_context(|| format!("Failed to retrieve shadow candidate for '{name}'"))?;

    // Run lightweight validation: check the candidate is non-empty and
    // structurally plausible (length > 8, no whitespace).
    let validation_ok =
        !candidate.is_empty() && candidate.len() > 8 && !candidate.chars().any(char::is_whitespace);

    // Reload as mutable ShadowedSecret to record the validation result
    let primary = vault
        .retrieve(name)
        .with_context(|| format!("Failed to retrieve primary secret '{name}'"))?;

    let mut shadow = phantom_vault::shadowing::ShadowedSecret::from_meta(
        meta,
        primary.as_str(),
        candidate.as_str(),
    );

    if validation_ok {
        shadow
            .record_validation_success(Some("cli-validate".to_string()))
            .context("Failed to record validation success")?;
        println!("{} Candidate validation passed.", "ok".green().bold());

        phantom_core::audit::log("shadow.validation_passed", Some(name));

        if promote {
            shadow
                .promote(Some("phantom-validate --promote".to_string()))
                .context("Failed to promote candidate")?;

            // Atomically update the vault: store new primary, delete shadow key
            vault
                .store(name, shadow.primary.as_str())
                .with_context(|| format!("Failed to store promoted value for '{name}'"))?;
            vault
                .delete(&shadow_key)
                .context("Failed to clean up shadow candidate")?;

            store
                .save(&shadow)
                .context("Failed to update shadow metadata")?;

            phantom_core::audit::log("shadow.promoted", Some(name));

            println!(
                "{} Candidate promoted to primary for {}. Old primary discarded.",
                "ok".green().bold(),
                name.bold()
            );
        } else {
            store
                .save(&shadow)
                .context("Failed to save shadow metadata")?;
            println!(
                "   Run {} to promote the validated candidate.",
                format!("phantom validate {name} --promote").cyan()
            );
        }
    } else {
        shadow
            .record_validation_failure(Some("structural-check-failed".to_string()))
            .context("Failed to record validation failure")?;
        store
            .save(&shadow)
            .context("Failed to save shadow metadata")?;

        phantom_core::audit::log("shadow.validation_failed", Some(name));

        println!(
            "{} Candidate validation failed for {}.",
            "FAIL".red().bold(),
            name.bold()
        );
        println!("   The candidate will remain in shadow state until abandoned or re-validated.");
        anyhow::bail!("Shadow candidate validation failed for '{name}'");
    }

    Ok(())
}

/// Generate a random candidate credential value (32 hex bytes).
fn generate_candidate_value() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    format!("phm_cand_{}", hex::encode(&bytes[..16]))
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
    let env_path = project_dir.join(".env");

    if !config_path.exists() {
        anyhow::bail!(
            "No .phantom.toml found. Run {} first.",
            "phantom init".cyan().bold()
        );
    }

    let config = PhantomConfig::load(&config_path).context("Failed to load .phantom.toml")?;
    let vault = phantom_vault::create_vault(config.local_project_id());

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
    let mut bootstrap = provider_config
        .and_then(|cfg| cfg.api_key_env.as_deref())
        .filter(|env_name| std::env::var(env_name).is_err())
        .and_then(|env_name| vault.retrieve(env_name).ok());

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
                    .map(|z| z.as_str().to_string())
                    .unwrap_or_default();
                if let Ok(jwt) = phantom_core::issuance::mint_app_jwt(pem, &client_id) {
                    bootstrap = Some(jwt);
                }
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
    let old_value = vault.retrieve(name).ok();

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
                let mut token_map = TokenMap::new();
                token_map.insert(name.to_string());
                let dotenv = DotenvFile::parse_file(&env_path)?;
                dotenv.write_phantomized(&token_map, &env_path)?;
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
            let expires_at = vault
                .record_provider_rotation(name, expires_override)
                .unwrap_or(None);

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
    let vault = phantom_vault::create_vault(config.local_project_id());

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
        let expires_at = vault
            .get_metadata(name)
            .ok()
            .flatten()
            .and_then(|m| m.expires_at);
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
            let old_value = vault.retrieve(&outcome.secret_name).ok();

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
            outcome.new_expires_at = vault
                .record_provider_rotation(&outcome.secret_name, expires_override)
                .unwrap_or(None);

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
        let env_path = project_dir.join(".env");
        if env_path.exists() {
            let mut token_map = phantom_core::token::TokenMap::new();
            for n in &rotated_vendor_names {
                token_map.insert(n.to_string());
            }
            let dotenv = phantom_core::dotenv::DotenvFile::parse_file(&env_path)?;
            dotenv.write_phantomized(&token_map, &env_path)?;
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
    use tempfile::tempdir;

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
}
