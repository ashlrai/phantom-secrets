use anyhow::{Context, Result};
use colored::Colorize;
use phantom_core::audit::AnomalyClass;
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
    #[serde(skip_serializing_if = "Option::is_none")]
    anomaly_score: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    anomaly_class: Option<String>,
}

/// Build a name → (anomaly_score, anomaly_class) map from the audit log.
/// Falls back to empty map on any error — anomaly info is best-effort.
fn anomaly_map() -> std::collections::HashMap<String, (u8, AnomalyClass)> {
    let mut map = std::collections::HashMap::new();
    let stats = match phantom_core::audit::audit_stats() {
        Ok(s) => s,
        Err(_) => return map,
    };
    for s in &stats.secrets {
        // Use retrieval frequency as a proxy for anomaly score:
        // secrets retrieved >20 times (in log history) get caution/alert flags.
        // The real per-request anomaly scoring lives in the proxy rate limiter;
        // here we surface a rough heuristic from historical audit log data.
        let (score, class) = if s.retrieves >= 50 {
            (80u8, AnomalyClass::Alert)
        } else if s.retrieves >= 20 {
            (40u8, AnomalyClass::Caution)
        } else {
            (
                ((s.retrieves as f64 / 20.0) * 40.0) as u8,
                AnomalyClass::Normal,
            )
        };
        map.insert(s.name.clone(), (score, class));
    }
    map
}

pub fn run_with_expiry(json: bool, show_expiry: bool, min_anomaly_score: Option<u8>) -> Result<()> {
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

    let anomalies = if min_anomaly_score.is_some() {
        anomaly_map()
    } else {
        std::collections::HashMap::new()
    };

    // Apply min_anomaly_score filter
    let filtered: Vec<_> = entries_with_meta
        .iter()
        .filter(|(name, _)| {
            if let Some(min_score) = min_anomaly_score {
                let score = anomalies.get(name.as_str()).map(|(s, _)| *s).unwrap_or(0);
                score >= min_score
            } else {
                true
            }
        })
        .collect();

    if json {
        let entries: Vec<SecretEntry> = filtered
            .iter()
            .map(|(name, meta)| {
                let (a_score, a_class) = anomalies
                    .get(name.as_str())
                    .cloned()
                    .unwrap_or((0, AnomalyClass::Normal));
                SecretEntry {
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
                    anomaly_score: if min_anomaly_score.is_some() {
                        Some(a_score)
                    } else {
                        None
                    },
                    anomaly_class: if min_anomaly_score.is_some() {
                        Some(a_class.as_str().to_string())
                    } else {
                        None
                    },
                }
            })
            .collect();
        let out = serde_json::to_string_pretty(&entries)
            .context("Failed to serialize secret list to JSON")?;
        println!("{}", out);
        return Ok(());
    }

    if filtered.is_empty() {
        if min_anomaly_score.is_some() {
            println!(
                "{} No secrets match the anomaly score filter.",
                "!".yellow().bold()
            );
        } else {
            println!("{} No secrets stored.", "!".yellow().bold());
        }
        return Ok(());
    }

    println!(
        "{} {} secret(s) in vault ({}):\n",
        "->".blue().bold(),
        filtered.len(),
        vault.backend_name().dimmed()
    );

    for (name, meta) in &filtered {
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

        // Anomaly label (shown when --min-anomaly-score is passed)
        let anomaly_label = if min_anomaly_score.is_some() {
            let (score, class) = anomalies
                .get(name.as_str())
                .cloned()
                .unwrap_or((0, AnomalyClass::Normal));
            let label = format!(" [anomaly:{} score:{}]", class.as_str(), score);
            match class {
                AnomalyClass::Alert => format!("{}", label.red().bold()),
                AnomalyClass::Caution => format!("{}", label.yellow()),
                AnomalyClass::Normal => format!("{}", label.dimmed()),
            }
        } else {
            String::new()
        };

        match service {
            Some(svc) => println!(
                "   {} {}{}{}  ({})",
                "-".dimmed(),
                name.bold(),
                expiry_label,
                anomaly_label,
                svc.cyan()
            ),
            None => println!(
                "   {} {}{}{}",
                "-".dimmed(),
                name.bold(),
                expiry_label,
                anomaly_label
            ),
        }
    }

    println!(
        "\n{} Values are never displayed. Use {} to manage.",
        "note".dimmed(),
        "phantom add/remove".cyan()
    );

    Ok(())
}
