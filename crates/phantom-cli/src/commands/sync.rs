use anyhow::{Context, Result};
use colored::Colorize;
use phantom_core::config::PhantomConfig;
use phantom_core::sync::{self, Platform, SyncStatus};
use rand::RngCore;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::io::{BufRead, IsTerminal, Write};
use zeroize::{Zeroize, Zeroizing};

struct SyncTargetSpec {
    platform: Platform,
    token: Zeroizing<String>,
    token_env: String,
    project_id: String,
    environments: Vec<String>,
    service_id: Option<String>,
    environment_id: Option<String>,
    only: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
struct LiveTargetPlan {
    platform: String,
    project_id: String,
    token_env: String,
    token_present: bool,
    environments: Vec<String>,
    service_id: Option<String>,
    environment_id: Option<String>,
    filters: Vec<String>,
    selected_keys: Vec<String>,
}

#[derive(Debug, Serialize)]
struct LiveSyncReceipt {
    mode: &'static str,
    plan_digest: String,
    fully_succeeded: bool,
    targets: Vec<LiveTargetReceipt>,
}

#[derive(Debug, Serialize)]
struct LiveTargetReceipt {
    plan: LiveTargetPlan,
    outcome: &'static str,
    stages: Vec<LiveKeyStage>,
}

#[derive(Debug, Serialize)]
struct LiveKeyStage {
    key: String,
    status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

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

    // Connector-pack sync targets are addressed by target name:
    // `phantom sync --platform <pack-target>`.
    if let Some(filter) = &platform_filter {
        if let Some((pack_name, spec)) = phantom_core::connector::find_sync_target(filter)? {
            if project_override.is_some() {
                anyhow::bail!("--project cannot override a signed connector destination");
            }
            // reqwest::blocking must live outside Tokio's runtime thread.
            return run_connector_worker(move || {
                run_pack_sync(&config, cli_only, dry_run, json, &pack_name, &spec)
            })
            .await;
        }
    }

    let vault = phantom_vault::try_create_vault(config.local_project_id())?;

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
        anyhow::bail!("Sync dry run found no vault secrets.");
    }
    if secret_names.is_empty() {
        anyhow::bail!("No secrets in vault to sync.");
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

            let token = Zeroizing::new(std::env::var(token_env).unwrap_or_default());

            let project_id = project_override.clone().context(
                "No project ID specified. Use --project <id> or add [[sync]] to .phantom.toml",
            )?;

            vec![SyncTargetSpec {
                platform,
                token,
                token_env: token_env.to_string(),
                project_id,
                environments: vec!["production".to_string(), "preview".to_string()],
                service_id: None,
                environment_id: None,
                only: Vec::new(),
            }]
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
            anyhow::bail!("No sync targets configured.");
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
                let token = Zeroizing::new(std::env::var(&t.token_env).unwrap_or_default());
                let pid = project_override
                    .clone()
                    .unwrap_or_else(|| t.project_id.clone());
                SyncTargetSpec {
                    platform: t.platform.clone(),
                    token,
                    token_env: t.token_env.clone(),
                    project_id: pid,
                    environments: t.targets.clone(),
                    service_id: t.service_id.clone(),
                    environment_id: t.environment_id.clone(),
                    only: t.only.clone(),
                }
            })
            .collect()
    };

    if targets.is_empty() {
        anyhow::bail!("No matching sync targets.");
    }

    if dry_run {
        return run_dry_run(&secret_names, &targets, &cli_only, json);
    }

    let plans = build_live_plans(&secret_names, &targets, &cli_only);
    let plan_digest = sync_plan_digest(&plans)?;
    let mut preflight_receipts = Vec::new();
    let mut preflight_failed = false;
    for (target, plan) in targets.iter().zip(&plans) {
        let mut stages = Vec::new();
        if target.token.is_empty() {
            preflight_failed = true;
            stages.push(LiveKeyStage {
                key: target.token_env.clone(),
                status: "missing_credential",
                error: Some("deployment credential environment variable is not set".to_string()),
            });
        }
        for (pattern, error) in sync::validate_only_patterns(&plan.filters) {
            preflight_failed = true;
            stages.push(LiveKeyStage {
                key: pattern,
                status: "invalid_filter",
                error: Some(error),
            });
        }
        if plan.selected_keys.is_empty() {
            preflight_failed = true;
            stages.push(LiveKeyStage {
                key: "selection".to_string(),
                status: "empty_selection",
                error: Some("no vault secret names matched this target".to_string()),
            });
        }
        preflight_receipts.push(LiveTargetReceipt {
            plan: plan.clone(),
            outcome: if stages.is_empty() {
                "ready"
            } else {
                "preflight_failed"
            },
            stages,
        });
    }
    if preflight_failed {
        let receipt = LiveSyncReceipt {
            mode: "live",
            plan_digest,
            fully_succeeded: false,
            targets: preflight_receipts,
        };
        eprintln!("stage_receipt: {}", serde_json::to_string(&receipt)?);
        anyhow::bail!(
            "Live sync preflight failed before vault plaintext access or provider network calls."
        );
    }

    require_trusted_terminal_sync(&plans)?;

    // Decrypt only the exact union reviewed in the attached terminal.
    let selected_names: BTreeSet<String> = plans
        .iter()
        .flat_map(|plan| plan.selected_keys.iter().cloned())
        .collect();
    let mut secrets: BTreeMap<String, String> = BTreeMap::new();
    let mut retrieval_failures = BTreeSet::new();
    for name in &selected_names {
        match vault.retrieve(name) {
            Ok(value) => {
                secrets.insert(name.clone(), String::from(value.as_str()));
            }
            Err(_) => {
                retrieval_failures.insert(name.clone());
                eprintln!(
                    "{} Could not retrieve {} from vault; the stage receipt records the skip",
                    "warn".yellow(),
                    name
                );
            }
        }
    }

    let mut target_receipts = Vec::new();
    let mut any_failure = !retrieval_failures.is_empty();
    for (target, plan) in targets.iter().zip(&plans) {
        let mut stages: Vec<LiveKeyStage> = plan
            .selected_keys
            .iter()
            .filter(|name| retrieval_failures.contains(*name))
            .map(|name| LiveKeyStage {
                key: name.clone(),
                status: "vault_retrieval_failed",
                error: Some("vault retrieval failed; provider was not called for this key".into()),
            })
            .collect();
        let mut filtered_secrets: BTreeMap<String, String> = plan
            .selected_keys
            .iter()
            .filter_map(|name| secrets.get(name).map(|value| (name.clone(), value.clone())))
            .collect();

        println!(
            "\n{} Syncing reviewed secret selection to {} (project: {})...",
            "->".blue().bold(),
            target.platform.to_string().cyan().bold(),
            target.project_id.dimmed()
        );

        let results = if filtered_secrets.is_empty() {
            Vec::new()
        } else {
            match target.platform {
                Platform::Vercel => {
                    sync::sync_to_vercel(
                        target.token.as_str(),
                        &target.project_id,
                        &filtered_secrets,
                        &target.environments,
                    )
                    .await
                }
                Platform::Railway => {
                    let env_id = target.environment_id.as_deref().unwrap_or("production");
                    sync::sync_to_railway(
                        target.token.as_str(),
                        &target.project_id,
                        env_id,
                        target.service_id.as_deref(),
                        &filtered_secrets,
                    )
                    .await
                }
            }
        };

        for result in &results {
            match &result.status {
                SyncStatus::Created => {
                    println!("   {} {} (created)", "+".green(), result.key.bold());
                    stages.push(LiveKeyStage {
                        key: result.key.clone(),
                        status: "created",
                        error: None,
                    });
                }
                SyncStatus::Updated => {
                    println!("   {} {} (updated)", "~".blue(), result.key.bold());
                    stages.push(LiveKeyStage {
                        key: result.key.clone(),
                        status: "updated",
                        error: None,
                    });
                }
                SyncStatus::Unchanged => {
                    println!("   {} {} (unchanged)", "-".dimmed(), result.key);
                    stages.push(LiveKeyStage {
                        key: result.key.clone(),
                        status: "unchanged",
                        error: None,
                    });
                }
                SyncStatus::Error(e) => {
                    eprintln!("   {} {} ({})", "!".red().bold(), result.key.bold(), e);
                    any_failure = true;
                    stages.push(LiveKeyStage {
                        key: result.key.clone(),
                        status: "provider_error",
                        error: Some(e.clone()),
                    });
                }
            }
        }
        for value in filtered_secrets.values_mut() {
            value.zeroize();
        }
        let target_failed = stages.iter().any(|stage| stage.error.is_some());
        target_receipts.push(LiveTargetReceipt {
            plan: plan.clone(),
            outcome: if target_failed {
                "partially_failed"
            } else {
                "succeeded"
            },
            stages,
        });
    }

    for value in secrets.values_mut() {
        value.zeroize();
    }
    drop(secrets);

    let receipt = LiveSyncReceipt {
        mode: "live",
        plan_digest,
        fully_succeeded: !any_failure,
        targets: target_receipts,
    };
    eprintln!("stage_receipt: {}", serde_json::to_string(&receipt)?);
    if any_failure {
        anyhow::bail!(
            "Live sync did not fully succeed. Successful remote effects are preserved in the stage receipt; reconcile them before retrying."
        );
    }
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

fn build_live_plans(
    secret_names: &[String],
    targets: &[SyncTargetSpec],
    cli_only: &[String],
) -> Vec<LiveTargetPlan> {
    targets
        .iter()
        .map(|target| {
            let mut filters = cli_only.to_vec();
            filters.extend(target.only.iter().cloned());
            let (selected_keys, _) = filter_key_names(secret_names, &filters);
            LiveTargetPlan {
                platform: target.platform.to_string(),
                project_id: target.project_id.clone(),
                token_env: target.token_env.clone(),
                token_present: !target.token.is_empty(),
                environments: target.environments.clone(),
                service_id: target.service_id.clone(),
                environment_id: target.environment_id.clone(),
                filters,
                selected_keys,
            }
        })
        .collect()
}

fn sync_plan_digest(plans: &[LiveTargetPlan]) -> Result<String> {
    let canonical = serde_json::to_vec(plans).context("Could not serialize live sync plan")?;
    let mut digest = Sha256::new();
    digest.update(b"phantom.live-sync.v1\0");
    digest.update(canonical);
    Ok(hex::encode(digest.finalize()))
}

fn require_trusted_terminal_sync(plans: &[LiveTargetPlan]) -> Result<()> {
    if !std::io::stdin().is_terminal()
        || !std::io::stdout().is_terminal()
        || !std::io::stderr().is_terminal()
    {
        anyhow::bail!(
            "Live `phantom sync` requires attached stdin, stdout, and stderr terminals and cannot run headlessly. No vault plaintext was read and no provider request was sent. Use --dry-run for a value-blind headless preview."
        );
    }
    let nonce = fresh_confirmation_nonce();
    let mut reader = std::io::BufReader::new(std::io::stdin().lock());
    let mut diagnostic = std::io::stderr();
    run_sync_confirmation(plans, &nonce, &mut reader, &mut diagnostic)
}

fn fresh_confirmation_nonce() -> String {
    let mut nonce_bytes = [0_u8; 16];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    hex::encode(nonce_bytes)
}

fn run_sync_confirmation(
    plans: &[LiveTargetPlan],
    nonce: &str,
    input: &mut impl BufRead,
    diagnostic: &mut impl Write,
) -> Result<()> {
    let plan_digest = sync_plan_digest(plans)?;
    let plan_json = serde_json::to_string_pretty(plans)?;
    let expected = format!("SYNC {plan_digest} {nonce}");
    writeln!(diagnostic, "Phantom live deployment sync")?;
    writeln!(diagnostic, "Exact value-blind plan:\n{plan_json}")?;
    writeln!(
        diagnostic,
        "This sends the selected vault values to the named provider targets and may partially succeed."
    )?;
    writeln!(
        diagnostic,
        "Approve only if this terminal is outside the requesting agent's authority. A same-user shell or agent-controlled PTY can automate this ceremony."
    )?;
    writeln!(
        diagnostic,
        "Type this exact challenge to continue:\n{expected}"
    )?;
    write!(diagnostic, "> ")?;
    diagnostic.flush()?;

    let mut response = String::new();
    input
        .read_line(&mut response)
        .context("Failed to read trusted-terminal sync confirmation")?;
    if response.trim_end_matches(['\r', '\n']) != expected {
        anyhow::bail!(
            "Live sync confirmation did not match exactly. No vault plaintext was read and no provider request was sent."
        );
    }
    Ok(())
}

fn run_dry_run(
    secret_names: &[String],
    targets: &[SyncTargetSpec],
    cli_only: &[String],
    json: bool,
) -> Result<()> {
    let mut report_targets = Vec::new();

    for target in targets {
        let mut filters = cli_only.to_vec();
        filters.extend(target.only.iter().cloned());

        let (selected_keys, skipped_keys) = filter_key_names(secret_names, &filters);
        let invalid_filters: Vec<InvalidFilter> = sync::validate_only_patterns(&filters)
            .into_iter()
            .map(|(pattern, error)| InvalidFilter { pattern, error })
            .collect();
        let token_env = target.token_env.clone();
        let mut warnings = Vec::new();

        if target.token.is_empty() {
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
            platform: target.platform.to_string(),
            project_id: target.project_id.clone(),
            token_env,
            token_present: !target.token.is_empty(),
            environments: target.environments.clone(),
            service_id: target.service_id.clone(),
            environment_id: target.environment_id.clone(),
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
        anyhow::bail!("Sync dry run found one or more blocking target conditions.");
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

/// Sync vault secrets to a connector pack's declarative sync target.
///
/// The target's API credential comes from the vault (`credential_name` in the
/// pack manifest — the operator stores it with `phantom add`; packs never
/// ship credentials). The exact plan (target, endpoint host, secret names)
/// is printed before anything is sent, and the push requires an attached
/// trusted terminal plus explicit confirmation.
fn run_pack_sync(
    config: &PhantomConfig,
    only: Vec<String>,
    dry_run: bool,
    json: bool,
    pack_name: &str,
    spec: &phantom_core::connector::SyncTargetSpec,
) -> Result<()> {
    let snapshot = phantom_core::connector::load_verified_pack(pack_name)?;
    if !snapshot.manifest().capabilities.iter().any(|cap| {
        matches!(cap,
        phantom_core::connector::Capability::SyncTarget { targets } if targets.contains(spec))
    }) {
        anyhow::bail!("connector sync destination changed; reauthorize");
    }
    if !sync::validate_only_patterns(&only).is_empty() {
        anyhow::bail!("invalid connector sync selection filter");
    }
    if dry_run {
        // Opening a vault can migrate legacy files or reconcile sidecars. A
        // headless preview only reports signed metadata, never opens a vault.
        let plan = serde_json::json!({"mode":"dry-run", "pack":pack_name,
            "target":spec, "signer":snapshot.signer(), "sha256":snapshot.sha256_pin(),
            "filters":only, "secret_inventory":"unknown_without_authorized_vault_access",
            "would_call_provider_api":false});
        if !json {
            println!("Connector sync preview (vault inventory not read):");
        }
        println!("{}", serde_json::to_string_pretty(&plan)?);
        return Ok(());
    }

    if !std::io::stdin().is_terminal()
        || !std::io::stdout().is_terminal()
        || !std::io::stderr().is_terminal()
    {
        anyhow::bail!(
            "Live pack sync requires attached stdin, stdout, and stderr terminals and cannot run headlessly. No vault plaintext was read and no provider request was sent. Use --dry-run for a value-blind headless preview."
        );
    }

    let vault = phantom_vault::try_create_vault(config.local_project_id())?;
    let mut secret_names = vault.list().context("Failed to list secrets")?;
    secret_names.sort();
    let (selected, _) = filter_key_names(&secret_names, &only);
    if selected.is_empty() {
        anyhow::bail!("no vault secrets selected for connector sync");
    }
    super::export_cmd::validate_consent_names(&selected)?;
    let plan = pack_sync_plan(
        config,
        pack_name,
        snapshot.signer(),
        &snapshot.sha256_pin(),
        spec,
        &selected,
    )?;
    let digest = pack_sync_plan_digest(&plan)?;
    super::export_cmd::require_trusted_terminal_effect(
        &serde_json::to_string(&plan)?,
        &format!(
            "SYNC CONNECTOR DIGEST {digest} NONCE {}",
            fresh_confirmation_nonce()
        ),
    )?;
    let current = phantom_core::connector::load_verified_pack(pack_name)?;
    if current.sha256_pin() != snapshot.sha256_pin() || current.signer() != snapshot.signer() {
        anyhow::bail!(
            "connector trust or destination changed; reauthorize before credential access"
        );
    }
    let current_config = PhantomConfig::load(&std::env::current_dir()?.join(".phantom.toml"))?;
    let current_selected = filter_key_names(&vault.list()?, &only).0;
    if pack_sync_plan(
        &current_config,
        pack_name,
        current.signer(),
        &current.sha256_pin(),
        spec,
        &current_selected,
    )? != plan
    {
        anyhow::bail!(
            "connector sync configuration or selected names changed; reauthorize before credential access"
        );
    }

    let credential = vault
        .retrieve(&spec.credential_name)
        .with_context(|| {
            format!(
                "Pack target {:?} needs vault secret {:?}; store it first with `phantom add {}` (value prompted on the trusted terminal).",
                spec.name, spec.credential_name, spec.credential_name
            )
        })?;
    let mut secrets: Vec<(String, Zeroizing<String>)> = Vec::new();
    for name in &selected {
        secrets.push((
            name.clone(),
            vault
                .retrieve(name)
                .context("connector sync selected secret unavailable; nothing sent")?,
        ));
    }

    let report = phantom_core::connector::push_sync_target(&snapshot, spec, &credential, &secrets)
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    // `credential` is a Zeroizing<String>: scrubbed from memory on drop.
    println!(
        "\n{} Pushed {} secret(s) to pack target {} ({} skipped empty)",
        "✓".green().bold(),
        report.pushed,
        spec.name.cyan(),
        report.skipped_empty
    );
    Ok(())
}

async fn run_connector_worker<T: Send + 'static>(
    work: impl FnOnce() -> Result<T> + Send + 'static,
) -> Result<T> {
    tokio::task::spawn_blocking(work)
        .await
        .context("connector sync worker failed")?
}

fn pack_sync_plan(
    config: &PhantomConfig,
    pack: &str,
    signer: &str,
    pin: &str,
    spec: &phantom_core::connector::SyncTargetSpec,
    selected: &[String],
) -> Result<serde_json::Value> {
    Ok(serde_json::json!({"project_id":config.local_project_id(),
        "config_sha256":hex::encode(Sha256::digest(serde_json::to_vec(config)?)),
        "pack":pack,"signer":signer,"sha256":pin,"request":spec,"selected_names":selected}))
}

fn pack_sync_plan_digest(plan: &serde_json::Value) -> Result<String> {
    let mut digest = Sha256::new();
    digest.update(b"phantom.connector-sync.v1\0");
    digest.update(serde_json::to_vec(plan)?);
    Ok(hex::encode(digest.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn signed_pack_consent_binds_full_destination_request_and_provenance() {
        let config = PhantomConfig::new_with_defaults("fixture".into());
        let spec = phantom_core::connector::SyncTargetSpec {
            name: "fixture-target".into(),
            method: phantom_core::connector::HttpMethod::Post,
            url: "https://example.invalid/api?a=1".into(),
            auth_header: "Authorization".into(),
            auth_scheme: "Bearer".into(),
            credential_name: "TEST_CREDENTIAL".into(),
        };
        let selected = vec!["TEST_SECRET".into()];
        let original = pack_sync_plan_digest(
            &pack_sync_plan(&config, "fixture", "signer", "pin", &spec, &selected).unwrap(),
        )
        .unwrap();
        for changed in [
            phantom_core::connector::SyncTargetSpec {
                url: "https://example.invalid/other?a=1".into(),
                ..spec.clone()
            },
            phantom_core::connector::SyncTargetSpec {
                url: "https://example.invalid/api?a=2".into(),
                ..spec.clone()
            },
            phantom_core::connector::SyncTargetSpec {
                method: phantom_core::connector::HttpMethod::Put,
                ..spec.clone()
            },
            phantom_core::connector::SyncTargetSpec {
                auth_header: "X-Auth".into(),
                ..spec.clone()
            },
            phantom_core::connector::SyncTargetSpec {
                credential_name: "OTHER".into(),
                ..spec.clone()
            },
        ] {
            assert_ne!(
                original,
                pack_sync_plan_digest(
                    &pack_sync_plan(&config, "fixture", "signer", "pin", &changed, &selected)
                        .unwrap()
                )
                .unwrap()
            );
        }
        assert_ne!(
            original,
            pack_sync_plan_digest(
                &pack_sync_plan(&config, "fixture", "changed", "pin", &spec, &selected).unwrap()
            )
            .unwrap()
        );
        assert_ne!(
            original,
            pack_sync_plan_digest(
                &pack_sync_plan(&config, "fixture", "signer", "changed", &spec, &selected).unwrap()
            )
            .unwrap()
        );
    }

    #[test]
    fn connector_transport_runs_off_runtime_without_network_or_credentials() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let result = run_connector_worker(|| {
                // Entering a nested blocking runtime panics on an async
                // worker; the production connector worker must isolate it.
                let nested = tokio::runtime::Runtime::new()?;
                nested.block_on(async {});
                drop(nested);
                Ok(())
            })
            .await;
            result.unwrap();
        });
    }

    #[test]
    fn live_sync_source_omits_decrypted_map_size_from_progress() {
        let source = include_str!("sync.rs");
        let prior_progress = ["Syncing {} secret(s)", " to"].concat();
        assert!(source.contains("Syncing reviewed secret selection to"));
        assert!(!source.contains(&prior_progress));
    }

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

    fn plan() -> LiveTargetPlan {
        LiveTargetPlan {
            platform: "vercel".into(),
            project_id: "project-a".into(),
            token_env: "VERCEL_TOKEN".into(),
            token_present: true,
            environments: vec!["production".into()],
            service_id: None,
            environment_id: None,
            filters: vec!["API_*".into()],
            selected_keys: vec!["API_KEY".into()],
        }
    }

    #[test]
    fn plan_digest_binds_every_effect_field() {
        let original = plan();
        let original_digest = sync_plan_digest(std::slice::from_ref(&original)).unwrap();
        let mut variants = Vec::new();
        let mut changed = original.clone();
        changed.platform = "railway".into();
        variants.push(changed);
        let mut changed = original.clone();
        changed.project_id = "project-b".into();
        variants.push(changed);
        let mut changed = original.clone();
        changed.environments = vec!["preview".into()];
        variants.push(changed);
        let mut changed = original.clone();
        changed.environment_id = Some("environment-b".into());
        variants.push(changed);
        let mut changed = original.clone();
        changed.service_id = Some("service-b".into());
        variants.push(changed);
        let mut changed = original.clone();
        changed.filters = vec!["OTHER_*".into()];
        variants.push(changed);
        let mut changed = original;
        changed.selected_keys = vec!["OTHER_KEY".into()];
        variants.push(changed);

        for variant in variants {
            assert_ne!(
                original_digest,
                sync_plan_digest(&[variant]).unwrap(),
                "every provider effect field must be challenge-bound"
            );
        }
    }

    #[test]
    fn exact_digest_and_fresh_nonce_are_required() {
        let plans = vec![plan()];
        let digest = sync_plan_digest(&plans).unwrap();
        let nonce = fresh_confirmation_nonce();
        let expected = format!("SYNC {digest} {nonce}\n");
        let mut output = Vec::new();
        run_sync_confirmation(&plans, &nonce, &mut Cursor::new(expected), &mut output).unwrap();

        let wrong_nonce = format!("{nonce}00");
        let error = run_sync_confirmation(
            &plans,
            &nonce,
            &mut Cursor::new(format!("SYNC {digest} {wrong_nonce}\n")),
            &mut Vec::new(),
        )
        .unwrap_err();
        assert!(error.to_string().contains("did not match exactly"));
    }

    #[test]
    fn noninteractive_entrypoint_denies_before_confirmation() {
        if !std::io::stdin().is_terminal()
            || !std::io::stdout().is_terminal()
            || !std::io::stderr().is_terminal()
        {
            let error = require_trusted_terminal_sync(&[plan()]).unwrap_err();
            assert!(error.to_string().contains("cannot run headlessly"));
        }
    }

    #[test]
    fn confirmation_precedes_vault_retrieval_and_provider_calls() {
        let source = include_str!("sync.rs");
        let confirmation = source
            .find("require_trusted_terminal_sync(&plans)?")
            .expect("live path must require terminal confirmation");
        let retrieval = source
            .find("for name in &selected_names")
            .expect("live path must retrieve the reviewed selection");
        let provider = source
            .find("sync::sync_to_vercel(")
            .expect("live path must contain provider call");
        assert!(confirmation < retrieval);
        assert!(retrieval < provider);
    }
}
