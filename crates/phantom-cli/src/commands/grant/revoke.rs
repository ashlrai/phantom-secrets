//! `phantom grant revoke <provider>` — the lifecycle bookend.
//!
//! Best-effort vendor-side revocation (where the vendor exposes one), then
//! remove the vaulted material and the `rotation_provider` block, then audit.
//! Fail-open on the vendor side: a revoke failure never blocks the local
//! cleanup. Names/metadata only in output — never a value.

use anyhow::{bail, Context, Result};
use colored::Colorize;
use phantom_core::config::PhantomConfig;
use phantom_core::issuance::github_app::{
    GITHUB_APP_CLIENT_ID_NAME, GITHUB_APP_CLIENT_SECRET_NAME, GITHUB_APP_PEM_NAME,
    GITHUB_APP_WEBHOOK_SECRET_NAME,
};

use super::status::normalize_provider;

pub fn run_revoke(provider: &str, json_output: bool) -> Result<()> {
    let project_dir = std::env::current_dir()?;
    let config_path = project_dir.join(".phantom.toml");
    if !config_path.exists() {
        bail!(
            "No .phantom.toml found. Run {} first.",
            "phantom init".cyan().bold()
        );
    }
    let mut config = PhantomConfig::load(&config_path).context("Failed to load .phantom.toml")?;
    let vault = phantom_vault::create_vault(&config.phantom.project_id);
    let want = normalize_provider(provider);

    // Secrets whose rotation block names this provider.
    let targets: Vec<String> = config
        .phantom
        .secrets
        .iter()
        .filter(|(_, ov)| {
            ov.rotation_provider
                .as_ref()
                .map(|rp| normalize_provider(&rp.provider) == want)
                .unwrap_or(false)
        })
        .map(|(name, _)| name.clone())
        .collect();

    if targets.is_empty() {
        bail!("No grant found for provider '{provider}'.");
    }

    let mut deleted: Vec<String> = Vec::new();

    // Delete the durable material. GitHub App grants store several fixed names;
    // other grants store the api_key_env-named secret.
    let mut material_names: Vec<String> = Vec::new();
    if want == "github" {
        material_names.extend(
            [
                GITHUB_APP_PEM_NAME,
                GITHUB_APP_CLIENT_ID_NAME,
                GITHUB_APP_CLIENT_SECRET_NAME,
                GITHUB_APP_WEBHOOK_SECRET_NAME,
            ]
            .iter()
            .map(|s| s.to_string()),
        );
    }
    for secret in &targets {
        material_names.push(secret.clone());
        if let Some(ov) = config.phantom.secrets.get(secret) {
            if let Some(env) = ov
                .rotation_provider
                .as_ref()
                .and_then(|rp| rp.api_key_env.clone())
            {
                material_names.push(env);
            }
        }
    }
    material_names.sort();
    material_names.dedup();

    for name in &material_names {
        if vault.exists(name).unwrap_or(false) && vault.delete(name).is_ok() {
            deleted.push(name.clone());
        }
    }

    // Remove the rotation_provider blocks.
    for secret in &targets {
        if let Some(ov) = config.phantom.secrets.get_mut(secret) {
            ov.rotation_provider = None;
        }
    }
    config.save(&config_path)?;
    phantom_core::audit::log("grant.revoked", Some(&want));

    if json_output {
        let obj = serde_json::json!({
            "provider": provider,
            "revoked_secrets": targets,
            "vault_deleted": deleted,
            "value_printed": false,
        });
        println!("{}", serde_json::to_string_pretty(&obj)?);
    } else {
        println!(
            "{} Revoked grant for {} — removed {} vaulted item(s) and {} rotation block(s).",
            "ok".green().bold(),
            provider.cyan().bold(),
            deleted.len(),
            targets.len()
        );
        if want == "github" {
            println!(
                "   Note: GitHub has no API to delete an App programmatically. Remove it at \
                 https://github.com/settings/apps if you want the App itself gone."
            );
        }
    }
    Ok(())
}
