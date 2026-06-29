use anyhow::{Context, Result};
use colored::Colorize;
use phantom_core::config::PhantomConfig;
use phantom_core::dotenv::DotenvFile;
use phantom_core::token::TokenMap;

/// Rotate all phantom tokens and optionally set a TTL (expiry) on every secret.
///
/// When `expiry_days` is `Some(n)` each secret gets a rotation policy of
/// `n` days and its `expires_at` is set to `now + n * 86400`.
pub fn run_with_expiry(sync_after: bool, expiry_days: Option<u64>) -> Result<()> {
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
    let vault = phantom_vault::create_vault(&config.phantom.project_id);
    let names = vault.list().context("Failed to list secrets")?;

    if names.is_empty() {
        println!("{} No secrets to rotate.", "!".yellow().bold());
        return Ok(());
    }

    // Generate new phantom tokens for all secrets
    let mut token_map = TokenMap::new();
    for name in &names {
        token_map.insert(name.clone());
    }

    // Rewrite .env if it exists
    if env_path.exists() {
        let dotenv = DotenvFile::parse_file(&env_path)?;
        dotenv.write_phantomized(&token_map, &env_path)?;
        println!(
            "{} Rotated {} phantom token(s) in .env",
            "ok".green().bold(),
            names.len()
        );
    } else {
        println!(
            "{} No .env file found — tokens rotated in memory only",
            "!".yellow().bold()
        );
    }

    for name in &names {
        if let Some(days) = expiry_days {
            vault
                .set_rotation_policy(name, days)
                .with_context(|| format!("Failed to set rotation policy for {name}"))?;
            println!(
                "   {} {} -> new token, expires in {} day(s)",
                "+".green(),
                name.bold(),
                days
            );
        } else {
            println!("   {} {} -> new token", "+".green(), name.bold());
        }
    }

    if expiry_days.is_some() {
        println!(
            "\n{} TTL metadata updated. Use {} to see expiry status.",
            "ok".green().bold(),
            "phantom list --show-expiry".cyan()
        );
    }

    // Sync to all deployment platforms if --sync flag is set
    if sync_after {
        println!(
            "\n{} Syncing to deployment platforms...",
            "->".blue().bold()
        );
        crate::commands::sync::run(None, None, vec![], false, false)?;
    }

    Ok(())
}

/// Persist a rotation schedule in `.phantom.toml` and perform an immediate
/// rotation so `last_rotated` is stamped.
///
/// Called by `phantom rotate --schedule-strategy <STRATEGY>`.
pub fn run_with_schedule_strategy(
    strategy_str: &str,
    sync_after: bool,
    expiry_days: Option<u64>,
) -> Result<()> {
    use phantom_core::rotation_strategy::{RotationSchedule, RotationStrategy};

    let strategy = RotationStrategy::from_str(strategy_str).ok_or_else(|| {
        anyhow::anyhow!(
            "Unknown schedule strategy '{}'. Valid values: never, daily, weekly, monthly.",
            strategy_str
        )
    })?;

    let project_dir = std::env::current_dir()?;
    let config_path = project_dir.join(".phantom.toml");

    if !config_path.exists() {
        anyhow::bail!(
            "No .phantom.toml found. Run {} first.",
            "phantom init".cyan().bold()
        );
    }

    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let schedule = RotationSchedule {
        last_rotated: Some(now_secs),
        ..RotationSchedule::from_strategy(strategy.clone())
    };

    // Persist the schedule into .phantom.toml.
    {
        let mut config =
            PhantomConfig::load(&config_path).context("Failed to load .phantom.toml")?;
        config.phantom.rotation_policy = Some(schedule.clone());
        config.save(&config_path).context("Failed to save .phantom.toml")?;
    }

    println!(
        "{} Rotation policy set: {}",
        "ok".green().bold(),
        schedule.describe().cyan()
    );
    println!(
        "   {} last_rotated stamped to now ({})",
        "->".blue().bold(),
        chrono_iso(now_secs)
    );

    if strategy != RotationStrategy::Never {
        println!(
            "\n{} Running initial rotation…",
            "->".blue().bold()
        );
        run_with_expiry(sync_after, expiry_days)?;
    } else {
        println!(
            "{} Strategy is 'never' — no immediate rotation performed.",
            "!".yellow().bold()
        );
    }

    println!(
        "\n{} Use {} to enforce this schedule.",
        "->".blue().bold(),
        "phantom watch --auto-rotate".cyan()
    );

    Ok(())
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
    let vault = phantom_vault::create_vault(&config.phantom.project_id);

    if !vault.exists(name).context("Failed to check secret existence")? {
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

    let store = ShadowStore::new(shadow_dir(&config.phantom.project_id))
        .context("Failed to open shadow store")?;
    store.save(&shadow).context("Failed to save shadow metadata")?;

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
    let vault = phantom_vault::create_vault(&config.phantom.project_id);

    let store = ShadowStore::new(shadow_dir(&config.phantom.project_id))
        .context("Failed to open shadow store")?;

    let meta = store
        .load_meta(name)
        .context("Failed to load shadow metadata")?
        .ok_or_else(|| anyhow::anyhow!("No shadow exists for secret '{name}'. Run `phantom rotate {name} --shadow` first."))?;

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
    let validation_ok = !candidate.is_empty()
        && candidate.len() > 8
        && !candidate.chars().any(char::is_whitespace);

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

            store.save(&shadow).context("Failed to update shadow metadata")?;

            phantom_core::audit::log("shadow.promoted", Some(name));

            println!(
                "{} Candidate promoted to primary for {}. Old primary discarded.",
                "ok".green().bold(),
                name.bold()
            );
        } else {
            store.save(&shadow).context("Failed to save shadow metadata")?;
            println!(
                "   Run {} to promote the validated candidate.",
                format!("phantom validate {name} --promote").cyan()
            );
        }
    } else {
        shadow
            .record_validation_failure(Some("structural-check-failed".to_string()))
            .context("Failed to record validation failure")?;
        store.save(&shadow).context("Failed to save shadow metadata")?;

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
/// Called by `phantom rotate --provider stripe|github|aws --name <KEY>`.
///
/// This delegates to the appropriate [`phantom_core::rotation_provider`]
/// implementation, which calls the vendor API to re-issue the credential.
/// The new value is stored in the vault; it is never printed to stdout.
pub fn run_with_provider(provider: &str, name: &str, sync_after: bool) -> Result<()> {
    use phantom_core::rotation_provider::{auto_sync_rotation, default_rotation_providers};

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

    if !vault
        .exists(name)
        .with_context(|| format!("Failed to check if '{name}' exists in vault"))?
    {
        anyhow::bail!("Secret '{}' not found in vault.", name);
    }

    // Resolve provider config from .phantom.toml.
    let provider_config = config
        .phantom
        .secrets
        .get(name)
        .and_then(|ov| ov.rotation_provider.as_ref());

    // If a provider config is present, verify it matches the requested provider.
    if let Some(cfg) = provider_config {
        if cfg.provider != provider {
            anyhow::bail!(
                "Secret '{}' is configured for provider '{}' but '{}' was requested.\n\
                 Update [phantom.secrets.{}.rotation_provider] in .phantom.toml.",
                name, cfg.provider, provider, name
            );
        }
    } else {
        // No config in .phantom.toml — inform the user how to add it.
        anyhow::bail!(
            "No rotation_provider configured for secret '{}'.\n\
             Add the following to .phantom.toml:\n\n\
             [phantom.secrets.{}.rotation_provider]\n\
             provider = \"{}\"\n\
             api_key_env = \"<ENV_VAR_HOLDING_ROTATION_CREDENTIAL>\"",
            name, name, provider
        );
    }

    println!(
        "{} Calling {} rotation API for {}…",
        "->".blue().bold(),
        provider.cyan().bold(),
        name.bold()
    );

    let providers = default_rotation_providers();
    let new_value = auto_sync_rotation(name, provider_config, &providers)
        .map_err(|e| anyhow::anyhow!("Provider rotation failed for '{}': {}", name, e))?;

    match new_value {
        Some(secret) => {
            vault
                .store(name, secret.as_str())
                .with_context(|| format!("Failed to store rotated value for '{name}'"))?;

            phantom_core::audit::log("vault.rotation.provider.stored", Some(name));

            println!(
                "{} Provider rotation succeeded for {} via {}.",
                "ok".green().bold(),
                name.bold(),
                provider.cyan()
            );
            println!("   The new credential has been stored in the vault.");
            println!("   The secret value was not printed for security.");
        }
        None => {
            anyhow::bail!(
                "No rotation provider matched secret '{}' with provider '{}'.\n\
                 Check that api_key_env resolves to a valid credential in the environment.",
                name, provider
            );
        }
    }

    if sync_after {
        println!(
            "\n{} Syncing to deployment platforms…",
            "->".blue().bold()
        );
        crate::commands::sync::run(None, None, vec![], false, false)?;
    }

    Ok(())
}
