//! `phantom grant status [<provider>]` — chain health, metadata only.
//!
//! `state ∈ active | expiring | broken | manual`. Safe to surface to agents via
//! MCP (`phantom_grant_status`): no values, ever.

use anyhow::{bail, Context, Result};
use colored::Colorize;
use phantom_core::config::PhantomConfig;
use phantom_core::rotation_provider::RotationProviderConfig;
use serde::Serialize;

/// One row of grant status — names and state only.
#[derive(Debug, Serialize)]
pub struct GrantRow {
    /// The secret the rotation chain feeds.
    pub secret: String,
    /// Provider identity (`github`, `supabase`, …).
    pub provider: String,
    /// `active | expiring | broken | manual`.
    pub state: String,
    /// Next-renewal unix timestamp, when known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
}

/// Providers with no token-minting API — their grants are scheduling-only.
const MANUAL_PROVIDERS: &[&str] = &["manual", "stripe", "sentry", "supabase-pat"];

/// Derive a grant's lifecycle state from its config + stored expiry.
pub fn grant_state(rp: &RotationProviderConfig, expires_at: Option<u64>) -> String {
    if !rp.enabled {
        return "broken".to_string();
    }
    if MANUAL_PROVIDERS.contains(&rp.provider.as_str()) {
        return "manual".to_string();
    }
    match expires_at {
        Some(ts) => {
            let now = now_unix();
            if ts <= now {
                "broken".to_string()
            } else if ts.saturating_sub(now) <= 7 * 86_400 {
                "expiring".to_string()
            } else {
                "active".to_string()
            }
        }
        None => "active".to_string(),
    }
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub fn run_status(provider: Option<&str>, json_output: bool) -> Result<()> {
    let project_dir = std::env::current_dir()?;
    let config_path = project_dir.join(".phantom.toml");
    if !config_path.exists() {
        bail!(
            "No .phantom.toml found. Run {} first.",
            "phantom init".cyan().bold()
        );
    }
    let config = PhantomConfig::load(&config_path).context("Failed to load .phantom.toml")?;

    let want = provider.map(normalize_provider);
    let rows: Vec<GrantRow> = config
        .phantom
        .secrets
        .iter()
        .filter_map(|(name, ov)| {
            let rp = ov.rotation_provider.as_ref()?;
            if let Some(want) = &want {
                if &normalize_provider(&rp.provider) != want {
                    return None;
                }
            }
            Some(GrantRow {
                secret: name.clone(),
                provider: rp.provider.clone(),
                state: grant_state(rp, ov.expires_at),
                expires_at: ov.expires_at,
            })
        })
        .collect();

    if json_output {
        println!("{}", serde_json::to_string_pretty(&rows)?);
        return Ok(());
    }

    if rows.is_empty() {
        match provider {
            Some(p) => println!("{} No grant for provider '{}'.", "!".yellow().bold(), p),
            None => println!("{} No grants configured.", "!".yellow().bold()),
        }
        return Ok(());
    }

    for row in rows {
        println!(
            "{} {} provider={} state={}",
            "grant".blue().bold(),
            row.secret.bold(),
            row.provider.cyan(),
            row.state
        );
        if let Some(ts) = row.expires_at {
            println!("   next renewal by unix ts {ts}");
        }
    }
    Ok(())
}

/// Fold `github-app` → `github` so status/revoke match the identity the
/// rotation block stores.
pub fn normalize_provider(p: &str) -> String {
    match p {
        "github-app" => "github".to_string(),
        other => other.to_string(),
    }
}
