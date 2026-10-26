use anyhow::{Context, Result};
use colored::Colorize;
use phantom_core::sync::{self, Platform, SyncStatus};
use rand::RngCore;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::io::{BufRead, IsTerminal, Write};
use zeroize::{Zeroize, Zeroizing};

/// `enforce_rotation_on_access` for a live sync: deployment platforms receive
/// real values, so an overdue enforced secret in any target's selection is
/// refused before the terminal review, any vault value read, or any provider
/// call, as `phantom exec` would refuse it.
///
/// A secret demoted to read-only by the expiry policy is refused the same
/// way: deployment platforms inject the value at runtime, which the demotion
/// exists to stop. Metadata that cannot be read refuses too.
fn gate_sync_selection(
    config: &phantom_core::config::PhantomConfig,
    vault: &dyn phantom_vault::VaultBackend,
    plans: &[LiveTargetPlan],
    now_secs: u64,
) -> Result<()> {
    super::rotation_gate::enforce_lifecycle_on_propagation(
        config,
        vault,
        plans
            .iter()
            .flat_map(|plan| plan.selected_keys.iter().map(String::as_str)),
        "sync",
        "Rotate or promote them before pushing to a deployment platform.",
        "No vault plaintext was read and no provider request was sent.",
        now_secs,
    )
}

fn no_sync_targets_message() -> String {
    format!(
        "No sync targets configured.\n\n\
         Add sync targets to .phantom.toml:\n\n  \
         {}\n  {}\n  {}\n  {}\n\n\
         Or run: {} {} {}",
        r#"[[sync]]"#.dimmed(),
        r#"platform = "vercel""#.dimmed(),
        r#"token_env = "VERCEL_TOKEN""#.dimmed(),
        r#"project_id = "prj_your_project_id""#.dimmed(),
        "phantom sync".cyan().bold(),
        "--platform vercel".cyan(),
        "--project <project-id>".cyan()
    )
}

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

    let project_dir = crate::util::project_dir()?;
    let config_path = project_dir.join(".phantom.toml");

    let Some(config) = crate::util::load_config_if_present(&config_path)
        .context("Failed to load .phantom.toml")?
    else {
        anyhow::bail!(
            "No .phantom.toml found. Run {} first.\n  {}",
            "phantom init".cyan().bold(),
            crate::util::docs_url("sync")
        );
    };
    let vault = crate::util::open_vault(config.local_project_id())?;

    // Cheap precondition check before decrypting anything.
    let secret_names = vault.list().context("Failed to list secrets")?;
    // A locked file vault would otherwise read as "no secrets to sync".
    let note = crate::util::inventory_guard(
        vault.as_ref(),
        config.local_project_id(),
        secret_names.len(),
    )?;
    crate::util::warn_inventory_note(note.as_deref());
    if secret_names.is_empty() && dry_run && json {
        println!(
            "{}",
            serde_json::to_string_pretty(&SyncDryRunReport {
                mode: "dry-run",
                entry_count: 0,
                target_count: 0,
                would_call_platform_api: false,
                targets: Vec::new(),
                live_gate_refusal: None,
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
            let platform: Platform = platform_str.parse().map_err(|_| {
                anyhow::anyhow!("Unknown --platform '{platform_str}'. Supported: vercel, railway")
            })?;

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
            if dry_run && json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&SyncDryRunReport {
                        mode: "dry-run",
                        entry_count: secret_names.len(),
                        target_count: 0,
                        would_call_platform_api: false,
                        targets: Vec::new(),
                        live_gate_refusal: None,
                        exit_code: 1,
                    })?
                );
            }
            // One message, printed once by main's error reporter. Printing the
            // guidance here and then bailing repeated the headline as
            // `Error: No sync targets configured.` after the guidance.
            anyhow::bail!("{}", no_sync_targets_message());
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
        return run_dry_run(
            &config,
            vault.as_ref(),
            super::rotation_gate::now_secs(),
            &secret_names,
            &targets,
            &cli_only,
            json,
        );
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

    gate_sync_selection(
        &config,
        vault.as_ref(),
        &plans,
        super::rotation_gate::now_secs(),
    )?;
    require_trusted_terminal_sync(&plans)?;

    // Decrypt only the exact union reviewed in the attached terminal.
    let selected_names: BTreeSet<String> = plans
        .iter()
        .flat_map(|plan| plan.selected_keys.iter().cloned())
        .collect();
    let (mut secrets, retrieval_failures) =
        retrieve_reviewed_selection(vault.as_ref(), &selected_names);

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
            if let Some(warning) = &result.warning {
                eprintln!("   {} {}", "warn".yellow(), warning);
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
    /// Vault entry names in scope (a count of names; never a value). The
    /// JSON key stays `secret_count` for existing consumers.
    #[serde(rename = "secret_count")]
    entry_count: usize,
    target_count: usize,
    would_call_platform_api: bool,
    targets: Vec<SyncDryRunTarget>,
    /// The refusal the live path's rotation-enforcement and read-only
    /// lifecycle gate would return for this selection (names only), or
    /// `null` when that gate passes.
    live_gate_refusal: Option<String>,
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
    config: &phantom_core::config::PhantomConfig,
    vault: &dyn phantom_vault::VaultBackend,
    now_secs: u64,
    secret_names: &[String],
    targets: &[SyncTargetSpec],
    cli_only: &[String],
    json: bool,
) -> Result<()> {
    let report = build_dry_run_report(config, vault, now_secs, secret_names, targets, cli_only);
    print_dry_run_report(&report, json)?;
    if report.exit_code == 0 {
        Ok(())
    } else {
        anyhow::bail!("Sync dry run found one or more blocking target conditions.");
    }
}

/// The value-blind preview of a live sync. It applies every preflight check
/// the live path applies before the terminal review, including the
/// rotation-enforcement and read-only lifecycle gate, so a preview never
/// reports success for a run the live path would refuse. It reads names and
/// metadata only: no vault value, no prompt, no provider call.
fn build_dry_run_report(
    config: &phantom_core::config::PhantomConfig,
    vault: &dyn phantom_vault::VaultBackend,
    now_secs: u64,
    secret_names: &[String],
    targets: &[SyncTargetSpec],
    cli_only: &[String],
) -> SyncDryRunReport {
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

    // The live path's rotation-enforcement and read-only lifecycle gate,
    // judged over the same per-target selection the live run would review.
    // Metadata only: the gate never reads a value.
    let plans = build_live_plans(secret_names, targets, cli_only);
    let live_gate_refusal = gate_sync_selection(config, vault, &plans, now_secs)
        .err()
        .map(|refusal| refusal.to_string());

    let exit_code = if live_gate_refusal.is_some()
        || report_targets.iter().any(|target| {
            !target.token_present
                || target.selected_keys.is_empty()
                || !target.invalid_filters.is_empty()
        }) {
        1
    } else {
        0
    };

    SyncDryRunReport {
        mode: "dry-run",
        entry_count: secret_names.len(),
        target_count: report_targets.len(),
        would_call_platform_api: false,
        targets: report_targets,
        live_gate_refusal,
        exit_code,
    }
}

fn print_dry_run_report(report: &SyncDryRunReport, json: bool) -> Result<()> {
    if json {
        println!("{}", serde_json::to_string_pretty(report)?);
        return Ok(());
    }
    println!(
        "{} Sync dry run: {} secret(s), {} target(s)",
        "->".blue().bold(),
        report.entry_count,
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
        for invalid in &target.invalid_filters {
            println!(
                "   {} invalid filter {} ({})",
                "warn".yellow().bold(),
                invalid.pattern,
                invalid.error
            );
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
    if let Some(refusal) = &report.live_gate_refusal {
        println!(
            "\n{} The live sync would refuse this selection:\n   {}",
            "!".red().bold(),
            refusal.replace('\n', "\n   ")
        );
    }
    Ok(())
}

/// Read the reviewed selection's values for a deployment platform. Each read
/// applies the runtime-injection check, so an entry demoted to read-only after
/// the preflight gate is never pushed. A name that cannot be read is recorded
/// as a retrieval failure, and its provider call is skipped.
fn retrieve_reviewed_selection(
    vault: &dyn phantom_vault::VaultBackend,
    selected_names: &BTreeSet<String>,
) -> (BTreeMap<String, String>, BTreeSet<String>) {
    let mut secrets: BTreeMap<String, String> = BTreeMap::new();
    let mut retrieval_failures = BTreeSet::new();
    for name in selected_names {
        match vault.retrieve_for_injection(name) {
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
    (secrets, retrieval_failures)
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn plan_selecting(keys: &[&str]) -> LiveTargetPlan {
        LiveTargetPlan {
            platform: "vercel".to_string(),
            project_id: "prj_fixture".to_string(),
            token_env: "VERCEL_TOKEN".to_string(),
            token_present: true,
            environments: vec!["production".to_string()],
            service_id: None,
            environment_id: None,
            filters: Vec::new(),
            selected_keys: keys.iter().map(|key| key.to_string()).collect(),
        }
    }

    /// `phantom sync` pushed an overdue enforced secret to a deployment
    /// platform that `phantom exec` refuses to inject. The reviewed selection
    /// is now gated before the terminal review and any value read; a
    /// selection inside its window passes.
    #[test]
    fn live_sync_selection_applies_rotation_enforcement() {
        use crate::commands::rotation_gate::fixtures::{aged_vault, enforced_config, NOW};
        let dir = tempfile::tempdir().unwrap();
        let vault = aged_vault(
            &dir,
            &[("prod/STALE_KEY", 45), ("FRESH_KEY", 1), ("PLAIN_KEY", 400)],
        );
        let config = enforced_config(&["STALE_KEY", "FRESH_KEY"]);

        let plans = [
            plan_selecting(&["FRESH_KEY"]),
            plan_selecting(&["prod/STALE_KEY", "PLAIN_KEY"]),
        ];
        let refused = gate_sync_selection(&config, &vault, &plans, NOW);
        let message = refused
            .err()
            .map(|error| error.to_string())
            .unwrap_or_default();
        assert!(message.starts_with("Refusing to sync: rotation enforcement blocked 1 secret(s)."));
        assert!(message.contains("'STALE_KEY'"));

        let plans = [plan_selecting(&["FRESH_KEY", "PLAIN_KEY"])];
        assert!(gate_sync_selection(&config, &vault, &plans, NOW).is_ok());
    }

    /// A file vault holding `entries`, each with its `vault_mode`.
    fn vault_with_modes(
        dir: &tempfile::TempDir,
        entries: &[(&str, phantom_vault::metadata::VaultMode)],
    ) -> phantom_vault::file::FileVault {
        use phantom_vault::VaultBackend;
        let vault = phantom_vault::file::FileVault::new(
            &crate::test_support::canonical_tempdir_path(dir),
            "sync-read-only-fixture",
            format!("sync-{}", std::process::id()),
        )
        .unwrap();
        for (entry, mode) in entries {
            vault.store(entry, "fixture-value").unwrap();
            vault
                .set_metadata(
                    entry,
                    phantom_vault::SecretMetadata {
                        created_at: Some(1_800_000_000),
                        vault_mode: mode.clone(),
                        ..phantom_vault::SecretMetadata::default()
                    },
                )
                .unwrap();
        }
        vault
    }

    /// A secret demoted to read-only by the expiry policy is refused by
    /// `phantom exec` and `phantom start`, yet `phantom sync` pushed it to
    /// a deployment platform. The live selection is now refused before the
    /// terminal review, any value read, or any provider call.
    #[test]
    fn live_sync_selection_refuses_read_only_entries() {
        use phantom_vault::metadata::VaultMode;
        let dir = tempfile::tempdir().unwrap();
        let vault = vault_with_modes(
            &dir,
            &[
                ("prod/DEMOTED_KEY", VaultMode::ReadOnly),
                ("ACTIVE_KEY", VaultMode::ReadWrite),
            ],
        );
        let config = phantom_core::config::PhantomConfig::new_with_defaults(
            "sync-read-only-fixture".to_string(),
        );

        let plans = [
            plan_selecting(&["ACTIVE_KEY"]),
            plan_selecting(&["prod/DEMOTED_KEY"]),
        ];
        let refused = gate_sync_selection(&config, &vault, &plans, 1_800_000_000);
        assert!(refused.is_err());
        let message = refused
            .err()
            .map(|error| error.to_string())
            .unwrap_or_default();
        assert!(message.starts_with("Refusing to sync: 1 secret(s) are read-only"));
        assert!(message.contains("'prod/DEMOTED_KEY'"));
        assert!(!message.contains("'ACTIVE_KEY'"));

        let plans = [plan_selecting(&["ACTIVE_KEY"])];
        assert!(gate_sync_selection(&config, &vault, &plans, 1_800_000_000).is_ok());
    }

    /// An entry demoted after the preflight gate (between the review and
    /// the value read) is still never handed to a provider: the value read
    /// applies the same injection check atomically.
    #[test]
    fn reviewed_selection_read_skips_read_only_entries() {
        use phantom_vault::metadata::VaultMode;
        let dir = tempfile::tempdir().unwrap();
        let vault = vault_with_modes(
            &dir,
            &[
                ("DEMOTED_KEY", VaultMode::ReadOnly),
                ("ACTIVE_KEY", VaultMode::ReadWrite),
            ],
        );
        let selected: BTreeSet<String> = ["DEMOTED_KEY", "ACTIVE_KEY"]
            .iter()
            .map(|name| name.to_string())
            .collect();
        let (values, failures) = retrieve_reviewed_selection(&vault, &selected);
        assert_eq!(values.keys().collect::<Vec<_>>(), vec!["ACTIVE_KEY"]);
        assert_eq!(
            failures.into_iter().collect::<Vec<_>>(),
            vec!["DEMOTED_KEY"]
        );
    }

    /// Names and metadata pass through; any value read, write or delete
    /// fails the test, so a dry run that touched a value cannot pass.
    struct ValueBlindVault<'v>(&'v dyn phantom_vault::VaultBackend);

    impl phantom_vault::VaultBackend for ValueBlindVault<'_> {
        fn store(&self, _name: &str, _value: &str) -> phantom_core::error::Result<()> {
            unreachable!("a sync dry run never writes")
        }
        fn retrieve(&self, _name: &str) -> phantom_core::error::Result<Zeroizing<String>> {
            unreachable!("a sync dry run never reads a value")
        }
        fn retrieve_for_injection(
            &self,
            _name: &str,
        ) -> phantom_core::error::Result<Zeroizing<String>> {
            unreachable!("a sync dry run never reads a value")
        }
        fn delete(&self, _name: &str) -> phantom_core::error::Result<()> {
            unreachable!("a sync dry run never deletes")
        }
        fn list(&self) -> phantom_core::error::Result<Vec<String>> {
            self.0.list()
        }
        fn backend_name(&self) -> &str {
            "value-blind"
        }
        fn get_metadata(
            &self,
            name: &str,
        ) -> phantom_core::error::Result<Option<phantom_vault::SecretMetadata>> {
            self.0.get_metadata(name)
        }
    }

    /// A ready target (credential env set) selecting `only`.
    fn ready_target(only: &[&str]) -> SyncTargetSpec {
        SyncTargetSpec {
            platform: Platform::Vercel,
            token: Zeroizing::new("set".to_string()),
            token_env: "VERCEL_TOKEN".to_string(),
            project_id: "prj_fixture".to_string(),
            environments: vec!["production".to_string()],
            service_id: None,
            environment_id: None,
            only: only.iter().map(|pattern| pattern.to_string()).collect(),
        }
    }

    /// `phantom sync --dry-run` reported exit 0 for a selection holding a
    /// secret demoted to read-only, which the live path refuses. The preview
    /// now applies the same gate, names the entry, and exits non-zero,
    /// without reading a single value.
    #[test]
    fn dry_run_reports_the_live_read_only_refusal_value_blind() {
        use phantom_vault::metadata::VaultMode;
        use phantom_vault::VaultBackend;
        let dir = tempfile::tempdir().unwrap();
        let inner = vault_with_modes(
            &dir,
            &[
                ("DEMOTED_KEY", VaultMode::ReadOnly),
                ("ACTIVE_KEY", VaultMode::ReadWrite),
            ],
        );
        let vault = ValueBlindVault(&inner);
        let config = phantom_core::config::PhantomConfig::new_with_defaults(
            "sync-read-only-fixture".to_string(),
        );
        let names = vault.list().unwrap();
        let targets = [ready_target(&[])];

        let report = build_dry_run_report(&config, &vault, 1_800_000_000, &names, &targets, &[]);
        assert_eq!(report.exit_code, 1);
        let refusal = report.live_gate_refusal.clone().unwrap_or_default();
        assert!(refusal.starts_with("Refusing to sync: 1 secret(s) are read-only"));
        assert!(refusal.contains("'DEMOTED_KEY'"));
        assert!(!refusal.contains("'ACTIVE_KEY'"));
        let json = serde_json::to_value(&report).unwrap();
        assert!(json["live_gate_refusal"].is_string());

        // The live gate refuses the same selection.
        let plans = build_live_plans(&names, &targets, &[]);
        assert!(gate_sync_selection(&config, &vault, &plans, 1_800_000_000).is_err());

        // A selection the live gate accepts previews as ready.
        let report = build_dry_run_report(
            &config,
            &vault,
            1_800_000_000,
            &names,
            &targets,
            &["ACTIVE_*".to_string()],
        );
        assert_eq!(report.exit_code, 0);
        assert!(report.live_gate_refusal.is_none());
        assert!(serde_json::to_value(&report).unwrap()["live_gate_refusal"].is_null());
    }

    /// The dry run applied no rotation enforcement, so it previewed a sync of
    /// an overdue enforced secret as ready while the live path refused it.
    #[test]
    fn dry_run_reports_the_live_rotation_refusal_value_blind() {
        use crate::commands::rotation_gate::fixtures::{aged_vault, enforced_config, NOW};
        use phantom_vault::VaultBackend;
        let dir = tempfile::tempdir().unwrap();
        let inner = aged_vault(&dir, &[("prod/STALE_KEY", 45), ("FRESH_KEY", 1)]);
        let vault = ValueBlindVault(&inner);
        let config = enforced_config(&["STALE_KEY", "FRESH_KEY"]);
        let names = vault.list().unwrap();

        // The overdue entry is selected by the second target only; the
        // union is judged, as the live path judges it.
        let targets = [ready_target(&["FRESH_*"]), ready_target(&[])];
        let report = build_dry_run_report(&config, &vault, NOW, &names, &targets, &[]);
        assert_eq!(report.exit_code, 1);
        let refusal = report.live_gate_refusal.clone().unwrap_or_default();
        assert!(refusal.starts_with("Refusing to sync: rotation enforcement blocked 1 secret(s)."));
        assert!(refusal.contains("'STALE_KEY'"));
        let plans = build_live_plans(&names, &targets, &[]);
        assert!(gate_sync_selection(&config, &vault, &plans, NOW).is_err());

        let targets = [ready_target(&["FRESH_*"])];
        let report = build_dry_run_report(&config, &vault, NOW, &names, &targets, &[]);
        assert_eq!(report.exit_code, 0);
        assert!(report.live_gate_refusal.is_none());
    }

    /// Lifecycle metadata the live gate cannot read refuses the live run, so
    /// the preview reports that refusal too instead of a ready plan.
    #[test]
    fn dry_run_reports_unreadable_lifecycle_metadata_as_a_refusal() {
        struct UnreadableMetadata;
        impl phantom_vault::VaultBackend for UnreadableMetadata {
            fn store(&self, _name: &str, _value: &str) -> phantom_core::error::Result<()> {
                unreachable!("a sync dry run never writes")
            }
            fn retrieve(&self, _name: &str) -> phantom_core::error::Result<Zeroizing<String>> {
                unreachable!("a sync dry run never reads a value")
            }
            fn delete(&self, _name: &str) -> phantom_core::error::Result<()> {
                unreachable!("a sync dry run never deletes")
            }
            fn list(&self) -> phantom_core::error::Result<Vec<String>> {
                Ok(vec!["SOME_KEY".to_string()])
            }
            fn backend_name(&self) -> &str {
                "unreadable-metadata"
            }
            fn get_metadata(
                &self,
                _name: &str,
            ) -> phantom_core::error::Result<Option<phantom_vault::SecretMetadata>> {
                Err(phantom_core::error::PhantomError::VaultError(
                    "metadata unavailable".to_string(),
                ))
            }
        }
        let config = phantom_core::config::PhantomConfig::new_with_defaults(
            "sync-unreadable-fixture".to_string(),
        );
        let names = vec!["SOME_KEY".to_string()];
        let report = build_dry_run_report(
            &config,
            &UnreadableMetadata,
            1_800_000_000,
            &names,
            &[ready_target(&[])],
            &[],
        );
        assert_eq!(report.exit_code, 1);
        assert!(report
            .live_gate_refusal
            .unwrap_or_default()
            .contains("could not read lifecycle metadata for 'SOME_KEY'"));
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
            .find("retrieve_reviewed_selection(vault.as_ref(), &selected_names)")
            .expect("live path must retrieve the reviewed selection");
        let provider = source
            .find("sync::sync_to_vercel(")
            .expect("live path must contain provider call");
        assert!(confirmation < retrieval);
        assert!(retrieval < provider);
    }
}

#[cfg(all(test, unix))]
mod locked_vault_tests {
    use crate::util::test_seam::{empty_keychain, LockedProject};

    /// `phantom sync --dry-run --json` reported `secret_count: 0` for a vault
    /// it could not open.
    #[test]
    fn sync_refuses_a_locked_file_vault() {
        let _project = LockedProject::new(empty_keychain);
        let error = super::run(None, None, Vec::new(), true, true).unwrap_err();
        assert!(error.to_string().starts_with("Vault locked:"), "{error:#}");
    }
}
