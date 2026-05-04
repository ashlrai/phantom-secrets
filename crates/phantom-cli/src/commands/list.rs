use anyhow::{Context, Result};
use colored::Colorize;
use phantom_core::config::PhantomConfig;
use phantom_core::env_scope::{known_envs_from_keys, split_key, DEFAULT_ENV};
use serde::Serialize;

#[derive(Serialize)]
struct SecretEntry<'a> {
    name: &'a str,
    env: &'a str,
    detected_service: Option<&'a str>,
}

pub fn run(json: bool, env: Option<&str>) -> Result<()> {
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
    let all_keys = vault.list().context("Failed to list secrets")?;

    let active_env = crate::commands::env_scope::effective_env(&project_dir, env);

    // Filter to the requested environment.
    // Namespaced keys: `<env>/<name>` where env matches.
    // Bare keys (legacy): shown when active_env == "default".
    let filtered: Vec<(String, String)> = all_keys
        .iter()
        .filter_map(|k| {
            if let Some((e, name)) = split_key(k) {
                if e == active_env {
                    return Some((name.to_string(), e.to_string()));
                }
            } else if active_env == DEFAULT_ENV {
                return Some((k.clone(), DEFAULT_ENV.to_string()));
            }
            None
        })
        .collect();

    if json {
        let entries: Vec<SecretEntry> = filtered
            .iter()
            .map(|(name, env_name)| SecretEntry {
                name,
                env: env_name,
                detected_service: config
                    .services
                    .iter()
                    .find(|(_, c)| c.secret_key == *name)
                    .map(|(svc, _)| svc.as_str()),
            })
            .collect();
        let out = serde_json::to_string_pretty(&entries)
            .context("Failed to serialize secret list to JSON")?;
        println!("{}", out);
        return Ok(());
    }

    if filtered.is_empty() {
        let known = known_envs_from_keys(&all_keys, &active_env);
        if known.len() > 1 {
            println!(
                "{} No secrets in env '{}'. Known envs: {}",
                "!".yellow().bold(),
                active_env,
                known.join(", ")
            );
        } else {
            println!("{} No secrets stored.", "!".yellow().bold());
        }
        return Ok(());
    }

    println!(
        "{} {} secret(s) in vault ({}) [env: {}]:\n",
        "->".blue().bold(),
        filtered.len(),
        vault.backend_name().dimmed(),
        active_env.cyan()
    );

    for (name, _) in &filtered {
        let service = config
            .services
            .iter()
            .find(|(_, c)| c.secret_key == *name)
            .map(|(svc_name, _)| svc_name.as_str());

        if let Some(svc) = service {
            println!("   {} {} ({})", "-".dimmed(), name.bold(), svc.cyan());
        } else {
            println!("   {} {}", "-".dimmed(), name.bold());
        }
    }

    println!(
        "\n{} Values are never displayed. Use {} to manage.",
        "note".dimmed(),
        "phantom add/remove".cyan()
    );

    Ok(())
}
