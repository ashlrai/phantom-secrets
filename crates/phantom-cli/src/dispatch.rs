//! Runtime command dispatch. Parsing lives in main and cli_actions.
use crate::cli_actions::{
    AgentAction, CloudAction, CryptoAction, ExpiryAction, GrantAction, LeaksAction, McpAction,
    TeamAction, ValidateAction, VaultAction, WorkspaceCliAction,
};
use crate::commands::audit::AuditAction;
use crate::{cli_json::apply_global_json, commands, Cli, Commands, UsageError};
use clap::Parser;
use tracing_subscriber::EnvFilter;

pub(crate) fn run() -> anyhow::Result<()> {
    let mut cli = Cli::parse();
    let global_json = cli.json;
    if global_json {
        if let Err(command) = apply_global_json(&mut cli.command) {
            return Err(UsageError(format!(
                "'{command}' has no --json output; run it without --json"
            ))
            .into());
        }
    }

    // Initialize logging — only show tracing output in verbose mode
    let filter = if cli.verbose {
        EnvFilter::new("debug")
    } else {
        // Suppress all tracing output by default — our CLI uses println for user-facing output
        EnvFilter::new("warn")
    };
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .without_time()
        // Stdout carries command output, including `--json` reports.
        .with_writer(std::io::stderr)
        .init();

    match cli.command {
        Commands::GitCredential { operation, secret } => {
            commands::git_credential::run(operation, &secret)
        }
        Commands::Init {
            from,
            all,
            dry_run,
            jobs,
            empty,
        } => {
            if empty && dry_run {
                commands::init::dry_run::run_empty()
            } else if empty {
                commands::init::run_empty()
            } else {
                match all {
                    Some(root) => {
                        let j = jobs
                            .or_else(commands::init::multi::jobs_from_env)
                            .unwrap_or(commands::init::multi::DEFAULT_JOBS);
                        commands::init::multi::run(root, dry_run, j)
                    }
                    None if dry_run => commands::init::dry_run::run(&from),
                    None => commands::init::run(&from),
                }
            }
        }
        Commands::List {
            json,
            show_expiry,
            min_anomaly_score,
            scope,
        } => match scope.as_deref() {
            Some(scope) => {
                commands::list::run_with_scope(json, show_expiry, min_anomaly_score, Some(scope))
            }
            None => commands::list::run_with_expiry(json, show_expiry, min_anomaly_score),
        },
        Commands::Add {
            name,
            value,
            stdin,
            multiline,
            first_line,
            generate,
            dry_run,
        } => {
            let lines = if multiline {
                commands::add::StdinLines::Multiline
            } else if first_line {
                commands::add::StdinLines::FirstLine
            } else {
                commands::add::StdinLines::SingleOnly
            };
            commands::add::run(&name, value, stdin, lines, dry_run, generate)
        }
        Commands::Remove { name, dry_run } => commands::remove::run(&name, dry_run),
        Commands::Reveal {
            name,
            clipboard,
            yes,
        } => commands::reveal::run(&name, clipboard, yes),
        Commands::Status { oneline } => commands::status::run(oneline, global_json),
        Commands::Rotate {
            sync,
            with_expiry,
            shadow,
            name,
            schedule_strategy,
            provider,
            batch,
            rotation_window_days,
        } => {
            if batch {
                commands::rotate::run_batch(rotation_window_days, sync, cli.json)
            } else if shadow {
                let secret_name =
                    name.ok_or_else(|| anyhow::anyhow!("--shadow requires --name <NAME>"))?;
                commands::rotate::run_shadow(&secret_name).map(|_| ())
            } else if provider.is_some() || name.is_some() {
                let secret_name =
                    name.ok_or_else(|| anyhow::anyhow!("--provider requires --name <NAME>"))?;
                commands::rotate::run_with_provider(
                    provider.as_deref(),
                    &secret_name,
                    sync,
                    cli.json,
                )
            } else if let Some(ref strategy_str) = schedule_strategy {
                commands::rotate::run_with_schedule_strategy(strategy_str, sync, with_expiry)
            } else {
                commands::rotate::run_with_expiry(sync, with_expiry)
            }
        }
        Commands::Validate {
            action,
            check_all,
            jobs,
            promote,
            watch,
        } => match action {
            Some(ValidateAction::Schedule {
                interval,
                status,
                disable,
            }) => commands::validation_scheduler::run_schedule(
                interval.as_deref(),
                status,
                disable,
                cli.json,
            ),
            Some(ValidateAction::History { last }) => {
                commands::validation_scheduler::run_history(last, cli.json)
            }
            None => {
                if watch {
                    commands::validate::run_watch(jobs, cli.json)
                } else if let Some(secret_name) = promote {
                    commands::rotate::run_validate_promote(&secret_name, true)
                } else {
                    commands::validate::run(check_all, jobs, cli.json)
                }
            }
        },
        Commands::Doctor {
            fix,
            expiry,
            json,
            strict,
            pq,
            all,
            output,
        } => {
            if let Some(path) = output {
                commands::doctor::run_doctor_to_file(
                    fix,
                    expiry,
                    json || global_json,
                    strict,
                    &path,
                )
            } else if all {
                commands::doctor_all::run(json || global_json)
            } else if pq {
                commands::pq_report::run(json || global_json)
            } else {
                commands::doctor::run_doctor(fix, expiry, json || global_json, strict)
            }
        }
        Commands::Agent { action } => match action {
            AgentAction::Report { json } => commands::agent::report(json || global_json),
            AgentAction::Doctor {
                json,
                vault,
                strict,
            } => commands::agent::doctor(json || global_json, vault, strict),
            AgentAction::Status { json } => commands::agent::status(json || global_json),
            AgentAction::Setup { dry_run, apply } => commands::agent::setup(dry_run, apply),
        },
        Commands::Exec {
            cmd,
            bind_source,
            scrub_output,
        } => commands::exec::run(&cmd, None, bind_source.as_deref(), cli.quiet, scrub_output),
        Commands::Start { daemon } => commands::start::run(daemon),
        Commands::Stop => commands::stop::run(),
        Commands::Check {
            staged,
            runtime,
            json,
        } => commands::check::run(staged, runtime, json || global_json),
        Commands::Pull {
            from,
            project,
            environment,
            service,
            force,
        } => commands::pull::run(&from, &project, environment, service, force),
        Commands::Setup {
            client,
            print,
            audit_mode,
            status,
            dry_run,
            replace,
            undo,
            apply,
            force_undo,
        } => {
            if undo {
                commands::setup_undo::run(apply, force_undo)
            } else if status {
                commands::setup_status::run(cli.json)
            } else if dry_run {
                commands::setup_plan::run_dry_run(client)
            } else {
                commands::setup::run(client, print, audit_mode, replace)
            }
        }
        Commands::Sync {
            platform,
            project,
            dry_run,
            only,
        } => commands::sync::run(platform, project, only, dry_run, cli.json),
        Commands::Env { output } => commands::env::run(&output),
        Commands::Export {
            output,
            passphrase,
            passphrase_file,
            json,
            allow_plaintext,
        } => commands::export_cmd::run(
            output.as_deref(),
            passphrase,
            passphrase_file.as_deref(),
            json,
            allow_plaintext,
        ),
        Commands::Import {
            file,
            passphrase,
            passphrase_file,
            from,
            file_path,
            force,
        } => {
            if let Some(source) = from {
                commands::export_cmd::reject_legacy_passphrase(passphrase)?;
                if passphrase_file.is_some() {
                    anyhow::bail!("--passphrase-file is only valid for encrypted Phantom backups");
                }
                let fp = file_path.as_deref().unwrap_or("");
                commands::import_cmd::run_from(&source, fp, force)
            } else {
                commands::import_cmd::run(
                    file.as_deref().unwrap_or(""),
                    passphrase,
                    passphrase_file.as_deref(),
                    force,
                )
            }
        }
        Commands::Login => commands::login::run(),
        Commands::Logout => commands::logout::run(),
        Commands::Cloud { action } => match action {
            CloudAction::Push => commands::cloud::run_push(),
            CloudAction::Pull { force } => commands::cloud::run_pull(force),
            CloudAction::Status => commands::cloud::run_status(cli.json),
        },
        Commands::Watch { auto, auto_rotate } => {
            commands::watch::run_with_rotate(auto, auto_rotate)
        }
        Commands::Leaks { action } => match action {
            LeaksAction::Plan {
                min_confidence,
                json,
            } => commands::leaks::run_plan(min_confidence, json || global_json),
        },
        Commands::Why { key, strict } => commands::why::run(&key, global_json, strict),
        Commands::Wrap { only, skip } => commands::wrap::run(&only, &skip, cli.quiet),
        Commands::Unwrap => commands::unwrap::run(cli.quiet),
        Commands::Redact { .. } => commands::redact::run(),
        Commands::Copy {
            name,
            to,
            rename,
            allow_cross_owner,
        } => commands::copy::run(&name, &to, &rename, allow_cross_owner),
        Commands::Audit { action } => match action {
            AuditAction::Feed { follow, cursor } => crate::audit_feed::run(follow, cursor),
            AuditAction::Show {
                last,
                op,
                name,
                json,
                leaked_secrets,
                output,
            } => commands::audit::run_show(
                last,
                op.as_deref(),
                name.as_deref(),
                json,
                leaked_secrets,
                output.as_deref(),
            ),
            AuditAction::Tail { op, name } => {
                commands::audit::run_tail(op.as_deref(), name.as_deref())
            }
            AuditAction::Path => commands::audit::run_path(),
            AuditAction::Verify { with_context } => {
                commands::audit::run_verify(with_context, global_json)
            }
            AuditAction::Stats {
                json,
                top,
                analytics,
                min_anomaly_score,
            } => commands::audit::run_stats(json, top, analytics, min_anomaly_score),
            AuditAction::Export {
                format,
                period,
                min_anomaly_score,
            } => commands::audit::run_export(&format, &period, min_anomaly_score),
            AuditAction::Analytics {
                window,
                min_anomaly_score,
                format,
                export,
                auto_alert_on_anomaly,
            } => commands::audit::run_analytics(
                window,
                min_anomaly_score,
                &format,
                export.as_deref(),
                auto_alert_on_anomaly,
            ),
            AuditAction::Anomalies {
                realtime,
                threshold,
                name,
                max_accesses_per_hour,
                max_quiet_days,
                json,
            } => commands::audit::run_anomalies(
                realtime,
                threshold,
                name.as_deref(),
                max_accesses_per_hour,
                max_quiet_days,
                json,
            ),
            AuditAction::Incidents {
                min_confidence,
                json,
                auto_rotate_on_high,
            } => commands::audit::run_incidents(min_confidence, json, auto_rotate_on_high),
            AuditAction::Alerts {
                last,
                backfill,
                json,
            } => commands::audit::run_alerts(last, backfill, json),
            AuditAction::ExportRange {
                format,
                from,
                to,
                name,
                op,
                pid,
            } => commands::audit::run_export_range(
                &format,
                &from,
                &to,
                name.as_deref(),
                op.as_deref(),
                pid,
            ),
            AuditAction::Report {
                r#type,
                from,
                to,
                save,
                compact,
            } => commands::audit::run_report(&r#type, &from, &to, save, compact),
        },
        Commands::Open { target } => commands::open::run(&target),
        Commands::Upgrade { force, check_only } => commands::upgrade::run(force, check_only),
        Commands::Completion { shell } => commands::completion::run(shell),
        Commands::Crypto { action } => match action {
            CryptoAction::Inventory { format } => commands::crypto::run_inventory(if global_json {
                commands::crypto::InventoryFormat::Json
            } else {
                format
            }),
        },
        Commands::Mcp { action } => match action {
            McpAction::Serve => commands::mcp::run_serve(),
        },
        Commands::McpApprove { nonce } => commands::mcp_approve::run(&nonce),
        Commands::Workspace { action } => match action {
            WorkspaceCliAction::Plan { json } => commands::workspace::run_plan(json),
            WorkspaceCliAction::Apply { request } => commands::workspace::run_apply(&request),
            WorkspaceCliAction::Status { request, json } => {
                commands::workspace::run_status(&request, json)
            }
        },
        Commands::Vault { action } => match action {
            VaultAction::MigrateLinux => commands::vault::run_migrate_linux(cli.json),
        },
        Commands::SecretsExpiringSoon {
            days,
            auto_rotate,
            sync,
            json,
        } => commands::expiry::run(days, auto_rotate, sync, json),
        Commands::FleetStatus {
            expiring_within,
            strict,
            json,
        } => crate::fleet_status::run(expiring_within, strict, json || global_json),
        Commands::Expiry { action } => match action {
            ExpiryAction::Set { key, days } => commands::expiry::run_set(&key, days),
            ExpiryAction::Enforce { fail_closed, json } => {
                commands::expiry::run_enforce(fail_closed, json)
            }
            ExpiryAction::Rotate { key } => commands::expiry::run_rotate(&key),
        },
        Commands::ClearClipboardAfter { secs } => commands::reveal::run_clear_after(secs),
        Commands::Team { action } => match action {
            TeamAction::List => commands::team::run_list(cli.json),
            TeamAction::Create { name } => commands::team::run_create(&name),
            TeamAction::Members { team_id } => commands::team::run_members(&team_id),
            TeamAction::Invite {
                team_id,
                github_login,
                role,
            } => commands::team::run_invite(&team_id, &github_login, &role),
            TeamAction::KeyPublish { team_id } => commands::team::run_key_publish(&team_id),
            TeamAction::VaultPush { team_id } => commands::team::run_vault_push(&team_id),
            TeamAction::VaultPull { team_id } => commands::team::run_vault_pull(&team_id),
            TeamAction::Revoke {
                team_id,
                github_login,
                yes,
            } => commands::team::run_revoke(&team_id, &github_login, yes),
            TeamAction::RotateVault { team_id } => commands::team::run_rotate_vault(&team_id),
        },
        Commands::Grant { action } => match action {
            GrantAction::Add {
                provider,
                org,
                name,
                rotate_secret,
                flow,
                client_id,
                client_secret_env,
                scope,
                team,
                account,
                no_browser,
                json,
            } => commands::grant::add::run_add(
                &provider,
                org,
                name,
                rotate_secret,
                no_browser,
                flow.as_deref(),
                client_id,
                client_secret_env,
                scope,
                team,
                account,
                json || global_json,
            ),
            GrantAction::List { json } => commands::grant::list::run_list(json || global_json),
            GrantAction::Status { provider, json } => {
                commands::grant::status::run_status(provider.as_deref(), json || global_json)
            }
            GrantAction::Revoke { provider, json } => {
                commands::grant::revoke::run_revoke(&provider, json || global_json)
            }
        },
    }
}
