//! `phantom grant list` — provider, grant type, state, next renewal. Never values.

use anyhow::{bail, Context, Result};
use colored::Colorize;
use phantom_core::config::PhantomConfig;

use super::status::{grant_state, GrantRow};

pub fn run_list(json_output: bool) -> Result<()> {
    let project_dir = std::env::current_dir()?;
    let config_path = project_dir.join(".phantom.toml");
    if !config_path.exists() {
        bail!(
            "No .phantom.toml found. Run {} first.",
            "phantom init".cyan().bold()
        );
    }
    let config = PhantomConfig::load(&config_path).context("Failed to load .phantom.toml")?;

    let rows: Vec<GrantRow> = config
        .phantom
        .secrets
        .iter()
        .filter_map(|(name, ov)| {
            ov.rotation_provider.as_ref().map(|rp| GrantRow {
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
        println!("{} No grants configured.", "!".yellow().bold());
        println!(
            "   Live enrollment is unavailable in this release. Obtain credentials from the provider with fresh operator consent, then store them from a trusted terminal with {}.",
            "phantom add <NAME>".cyan()
        );
        return Ok(());
    }

    println!("{}", "Grants".bold());
    for row in rows {
        println!(
            "  {:<24} provider={:<10} state={}",
            row.secret.bold(),
            row.provider.cyan(),
            colorize_state(&row.state)
        );
    }
    Ok(())
}

fn colorize_state(state: &str) -> String {
    match state {
        "active" => state.green().to_string(),
        "expiring" => state.yellow().to_string(),
        "broken" => state.red().to_string(),
        _ => state.normal().to_string(),
    }
}
