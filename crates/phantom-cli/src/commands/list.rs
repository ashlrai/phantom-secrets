use anyhow::{Context, Result};
use colored::Colorize;
use phantom_core::config::PhantomConfig;
use serde::Serialize;

#[derive(Serialize)]
struct SecretEntry<'a> {
    name: &'a str,
    detected_service: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ttl_status: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    expires_at: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    days_remaining: Option<i64>,
}

pub fn run_with_expiry(json: bool, show_expiry: bool) -> Result<()> {
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

    let entries_with_meta = vault
        .list_with_metadata()
        .context("Failed to list secrets")?;

    if json {
        let entries: Vec<SecretEntry> = entries_with_meta
            .iter()
            .map(|(name, meta)| SecretEntry {
                name,
                detected_service: config
                    .services
                    .iter()
                    .find(|(_, c)| c.secret_key == *name)
                    .map(|(svc, _)| svc.as_str()),
                ttl_status: if show_expiry {
                    Some(
                        meta.as_ref()
                            .map(|m| m.ttl_status())
                            .unwrap_or_else(|| "no expiry".to_string()),
                    )
                } else {
                    None
                },
                expires_at: meta.as_ref().and_then(|m| m.expires_at),
                days_remaining: meta.as_ref().and_then(|m| m.days_remaining()),
            })
            .collect();
        let out = serde_json::to_string_pretty(&entries)
            .context("Failed to serialize secret list to JSON")?;
        println!("{}", out);
        return Ok(());
    }

    if entries_with_meta.is_empty() {
        println!("{} No secrets stored.", "!".yellow().bold());
        return Ok(());
    }

    println!(
        "{} {} secret(s) in vault ({}):\n",
        "->".blue().bold(),
        entries_with_meta.len(),
        vault.backend_name().dimmed()
    );

    for (name, meta) in &entries_with_meta {
        // Check if this name has a service mapping
        let service = config
            .services
            .iter()
            .find(|(_, c)| c.secret_key == *name)
            .map(|(svc_name, _)| svc_name.as_str());

        let expiry_label = if show_expiry {
            let status = meta
                .as_ref()
                .map(|m| m.ttl_status())
                .unwrap_or_else(|| "no expiry".to_string());

            let colored_status = match meta.as_ref() {
                Some(m) if m.is_expired() => format!(" [{}]", status.red().bold()),
                Some(m) if m.is_expiring_soon(7) => format!(" [{}]", status.yellow()),
                Some(m) if m.expires_at.is_some() => format!(" [{}]", status.green()),
                _ => format!(" [{}]", status.dimmed()),
            };
            colored_status
        } else {
            String::new()
        };

        match service {
            Some(svc) => println!(
                "   {} {}{}  ({})",
                "-".dimmed(),
                name.bold(),
                expiry_label,
                svc.cyan()
            ),
            None => println!("   {} {}{}", "-".dimmed(), name.bold(), expiry_label),
        }
    }

    println!(
        "\n{} Values are never displayed. Use {} to manage.",
        "note".dimmed(),
        "phantom add/remove".cyan()
    );

    Ok(())
}
