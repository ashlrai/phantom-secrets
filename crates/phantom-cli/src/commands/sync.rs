use anyhow::{Context, Result};
use colored::Colorize;
use phantom_core::config::PhantomConfig;
use phantom_core::sync::{self, Platform, SyncStatus};
use serde::Serialize;
use std::collections::BTreeMap;
use zeroize::Zeroize;

pub fn run(
    platform: Option<String>,
    project: Option<String>,
    only: Vec<String>,
    dry_run: bool,
    json: bool,
) -> Result<()> {
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(run_async(platform, project, only, dry_run, json))
}

async fn run_async(
    platform_filter: Option<String>,
    project_override: Option<String>,
    cli_only: Vec<String>,
    dry_run: bool,
    json: bool,
) -> Result<()> {
    if json && !dry_run {
        anyhow::bail!("`phantom sync --json` is currently supported with `--dry-run` only.");
    }

    let project_dir = std::env::current_dir()?;
    let config_path = project_dir.join(".phantom.toml");

    if !config_path.exists() {
        anyhow::bail!(
            "No .phantom.toml found. Run {} first.\n  {}",
            "phantom init".cyan().bold(),
            crate::util::docs_url("sync")
        );
    }

    let config = PhantomConfig::load(&config_path).context("Failed to load .phantom.toml")?;
    let vault = phantom_vault::create_vault(&config.phantom.project_id);

    // Cheap precondition check before decrypting anything.
    let secret_names = vault.list().context("Failed to list secrets")?;
    if secret_names.is_empty() && dry_run && json {
        println!(
            "{}",
            serde_json::to_string_pretty(&SyncDryRunReport {
                mode: "dry-run",
                secret_count: 0,
                target_count: 0,
                would_call_platform_api: false,
                targets: Vec::new(),
                exit_code: 1,
            })?
        );
        std::process::exit(1);
    }
    if secret_names.is_empty() {
        println!("{} No secrets in vault to sync.", "!".yellow().bold());
        return Ok(());
    }

    // Determine sync targets
    let targets: Vec<_> = if config.sync.is_empty() {
        // No sync targets configured — try to infer from platform arg
        if let Some(platform_str) = &platform_filter {
            let platform: Platform = platform_str.parse().context("Invalid platform")?;

            let token_env = match platform {
                Platform::Vercel => "VERCEL_TOKEN",
                Platform::Railway => "RAILWAY_TOKEN",
            };

            let token = std::env::var(token_env).unwrap_or_default();

            if token.is_empty() && !dry_run {
                anyhow::bail!("{token_env} not set. Export your {} API token.", platform);
            }

            let project_id = project_override.clone().context(
                "No project ID specified. Use --project <id> or add [[sync]] to .phantom.toml",
            )?;

            vec![(
                platform,
                token,
                project_id,
                vec!["production".to_string(), "preview".to_string()],
                None,
                None,
                Vec::<String>::new(), // no per-target only; cli_only applied later
            )]
        } else {
            eprintln!("{} No sync targets configured.", "!".yellow().bold());
            eprintln!();
            eprintln!("Add sync targets to .phantom.toml:");
            eprintln!();
            eprintln!("  {}", r#"[[sync]]"#.dimmed());
            eprintln!("  {}", r#"platform = "vercel""#.dimmed());
            eprintln!("  {}", r#"token_env = "VERCEL_TOKEN""#.dimmed());
            eprintln!("  {}", r#"project_id = "prj_your_project_id""#.dimmed());
            eprintln!();
            eprintln!(
                "Or run: {} {} {}",
                "phantom sync".cyan().bold(),
                "--platform vercel".cyan(),
                "--project <project-id>".cyan()
            );
            return Ok(());
        }
    } else {
        // Use configured sync targets
        config
            .sync
            .iter()
            .filter(|t| {
                if let Some(filter) = &platform_filter {
                    t.platform.to_string() == *filter
                } else {
                    true
                }
            })
            .map(|t| {
                let token = std::env::var(&t.token_env).unwrap_or_default();
                let pid = project_override
                    .clone()
                    .unwrap_or_else(|| t.project_id.clone());
                (
                    t.platform.clone(),
                    token,
                    pid,
                    t.targets.clone(),
                    t.service_id.clone(),
                    t.environment_id.clone(),
                    t.only.clone(), // per-target only patterns from .phantom.toml
                )
            })
            .collect()
    };

    if targets.is_empty() {
        println!("{} No matching sync targets.", "!".yellow().bold());
        return Ok(());
    }

    if dry_run {
        return run_dry_run(&secret_names, &targets, &cli_only, json);
    }

    // Decrypt vault values only after we know we have targets to push to.
    // Anything that exits via `return Ok(())` above never touches plaintext.
    let mut secrets: BTreeMap<String, String> = BTreeMap::new();
    for name in &secret_names {
        match vault.retrieve(name) {
            Ok(value) => {
                secrets.insert(name.clone(), String::from(value.as_str()));
            }
            Err(_) => {
                eprintln!(
                    "{} Could not retrieve {} from vault, skipping",
                    "warn".yellow(),
                    name
                );
            }
        }
    }

    for (platform, token, project_id, env_targets, service_id, environment_id, target_only) in
        &targets
    {
        // Merge CLI --only flags with per-target `only` from .phantom.toml.
        // The union is OR-ed: a key passes if it matches any pattern from
        // either source. When both are empty no filter is applied.
        let effective_only: Vec<String> = {
            let mut merged = cli_only.clone();
            merged.extend(target_only.iter().cloned());
            merged
        };
        // Apply the filter; build a temporary owned map for the push calls.
        let filtered_secrets: BTreeMap<String, String> =
            phantom_core::sync::filter_by_only(&secrets, &effective_only)
                .into_iter()
                .map(|(k, v)| (k, v.clone()))
                .collect();

        if filtered_secrets.is_empty() && !effective_only.is_empty() {
            println!(
                "{} No secrets matched the --only filter for {} — skipping",
                "!".yellow().bold(),
                platform.to_string().cyan().bold()
            );
            continue;
        }
        if token.is_empty() {
            let token_env = match platform {
                Platform::Vercel => "VERCEL_TOKEN",
                Platform::Railway => "RAILWAY_TOKEN",
            };
            eprintln!(
                "{} {} not set — skipping {}",
                "warn".yellow(),
                token_env,
                platform
            );
            continue;
        }

        println!(
            "\n{} Syncing {} secret(s) to {} (project: {})...",
            "->".blue().bold(),
            filtered_secrets.len(),
            platform.to_string().cyan().bold(),
            project_id.dimmed()
        );

        let results = match platform {
            Platform::Vercel => {
                sync::sync_to_vercel(token, project_id, &filtered_secrets, env_targets).await
            }
            Platform::Railway => {
                let env_id = environment_id.as_deref().unwrap_or("production");
                sync::sync_to_railway(
                    token,
                    project_id,
                    env_id,
                    service_id.as_deref(),
                    &filtered_secrets,
                )
                .await
            }
        };

        let mut created = 0;
        let mut updated = 0;
        let mut errors = 0;

        for result in &results {
            match &result.status {
                SyncStatus::Created => {
                    println!("   {} {} (created)", "+".green(), result.key.bold());
                    created += 1;
                }
                SyncStatus::Updated => {
                    println!("   {} {} (updated)", "~".blue(), result.key.bold());
                    updated += 1;
                }
                SyncStatus::Unchanged => {
                    println!("   {} {} (unchanged)", "-".dimmed(), result.key);
                }
                SyncStatus::Error(e) => {
                    eprintln!("   {} {} ({})", "!".red().bold(), result.key.bold(), e);
                    errors += 1;
                }
            }
        }

        println!();
        if errors > 0 {
            println!(
                "{} {}: {} created, {} updated, {} errors",
                "!".yellow().bold(),
                platform,
                created,
                updated,
                errors
            );
        } else {
            println!(
                "{} {}: {} created, {} updated",
                "ok".green().bold(),
                platform,
                created,
                updated
            );
        }
    }

    for value in secrets.values_mut() {
        value.zeroize();
    }
    drop(secrets);

    Ok(())
}

#[derive(Debug, Serialize)]
struct SyncDryRunReport {
    mode: &'static str,
    secret_count: usize,
    target_count: usize,
    would_call_platform_api: bool,
    targets: Vec<SyncDryRunTarget>,
    exit_code: i32,
}

#[derive(Debug, Serialize)]
struct SyncDryRunTarget {
    platform: String,
    project_id: String,
    token_env: String,
    token_present: bool,
    environments: Vec<String>,
    service_id: Option<String>,
    environment_id: Option<String>,
    filters: Vec<String>,
    invalid_filters: Vec<InvalidFilter>,
    selected_keys: Vec<String>,
    selected_count: usize,
    skipped_keys: Vec<String>,
    warnings: Vec<String>,
}

#[derive(Debug, Serialize)]
struct InvalidFilter {
    pattern: String,
    error: String,
}

type TargetTuple = (
    Platform,
    String,
    String,
    Vec<String>,
    Option<String>,
    Option<String>,
    Vec<String>,
);

fn run_dry_run(
    secret_names: &[String],
    targets: &[TargetTuple],
    cli_only: &[String],
    json: bool,
) -> Result<()> {
    let mut report_targets = Vec::new();

    for (platform, token, project_id, env_targets, service_id, environment_id, target_only) in
        targets
    {
        let mut filters = cli_only.to_vec();
        filters.extend(target_only.iter().cloned());

        let (selected_keys, skipped_keys) = filter_key_names(secret_names, &filters);
        let invalid_filters: Vec<InvalidFilter> = sync::validate_only_patterns(&filters)
            .into_iter()
            .map(|(pattern, error)| InvalidFilter { pattern, error })
            .collect();
        let token_env = token_env_for(platform).to_string();
        let mut warnings = Vec::new();

        if token.is_empty() {
            warnings.push(format!("{token_env} is not set"));
        }
        if selected_keys.is_empty() {
            warnings.push("no secrets selected for this target".to_string());
        }
        if !invalid_filters.is_empty() {
            warnings.push("one or more filters are invalid".to_string());
        }
        let selected_count = selected_keys.len();

        report_targets.push(SyncDryRunTarget {
            platform: platform.to_string(),
            project_id: project_id.clone(),
            token_env,
            token_present: !token.is_empty(),
            environments: env_targets.clone(),
            service_id: service_id.clone(),
            environment_id: environment_id.clone(),
            filters,
            invalid_filters,
            selected_keys,
            selected_count,
            skipped_keys,
            warnings,
        });
    }

    let exit_code = if report_targets.iter().any(|target| {
        !target.token_present
            || target.selected_keys.is_empty()
            || !target.invalid_filters.is_empty()
    }) {
        1
    } else {
        0
    };

    let report = SyncDryRunReport {
        mode: "dry-run",
        secret_count: secret_names.len(),
        target_count: report_targets.len(),
        would_call_platform_api: false,
        targets: report_targets,
        exit_code,
    };

    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!(
            "{} Sync dry run: {} secret(s), {} target(s)",
            "->".blue().bold(),
            report.secret_count,
            report.targets.len()
        );
        for target in &report.targets {
            println!(
                "\n{} {} (project: {})",
                "target".blue().bold(),
                target.platform.cyan().bold(),
                target.project_id.dimmed()
            );
            println!(
                "   token: {} ({})",
                if target.token_present {
                    "present".green()
                } else {
                    "missing".yellow()
                },
                target.token_env
            );
            if !target.filters.is_empty() {
                println!("   filters: {}", target.filters.join(", "));
            }
            if !target.invalid_filters.is_empty() {
                for invalid in &target.invalid_filters {
                    println!(
                        "   {} invalid filter {} ({})",
                        "warn".yellow().bold(),
                        invalid.pattern,
                        invalid.error
                    );
                }
            }
            println!("   selected: {}", target.selected_count);
            for key in &target.selected_keys {
                println!("      {}", key);
            }
            if !target.skipped_keys.is_empty() {
                println!("   skipped by filters: {}", target.skipped_keys.len());
            }
            for warning in &target.warnings {
                println!("   {} {}", "warn".yellow().bold(), warning);
            }
        }
    }

    if exit_code == 0 {
        Ok(())
    } else {
        std::process::exit(exit_code);
    }
}

fn filter_key_names(secret_names: &[String], patterns: &[String]) -> (Vec<String>, Vec<String>) {
    let dummy: BTreeMap<String, String> = secret_names
        .iter()
        .map(|name| (name.clone(), String::new()))
        .collect();
    let selected_map = phantom_core::sync::filter_by_only(&dummy, patterns);
    let mut selected: Vec<String> = selected_map.keys().cloned().collect();
    let mut skipped: Vec<String> = dummy
        .keys()
        .filter(|name| !selected_map.contains_key(*name))
        .cloned()
        .collect();
    selected.sort();
    skipped.sort();
    (selected, skipped)
}

fn token_env_for(platform: &Platform) -> &'static str {
    match platform {
        Platform::Vercel => "VERCEL_TOKEN",
        Platform::Railway => "RAILWAY_TOKEN",
    }
}

#[cfg(test)]
mod tests {
    use super::filter_key_names;

    #[test]
    fn filter_key_names_without_patterns_selects_all() {
        let names = vec!["B".to_string(), "A".to_string()];
        let (selected, skipped) = filter_key_names(&names, &[]);
        assert_eq!(selected, vec!["A", "B"]);
        assert!(skipped.is_empty());
    }

    #[test]
    fn filter_key_names_splits_selected_and_skipped() {
        let names = vec![
            "OPENAI_API_KEY".to_string(),
            "STRIPE_SECRET_KEY".to_string(),
            "NODE_ENV".to_string(),
        ];
        let (selected, skipped) = filter_key_names(&names, &["*_KEY".to_string()]);
        assert_eq!(selected, vec!["OPENAI_API_KEY", "STRIPE_SECRET_KEY"]);
        assert_eq!(skipped, vec!["NODE_ENV"]);
    }
}
