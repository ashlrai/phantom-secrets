//! `phantom onboard` — one guided flow for first-run setup.
//!
//! First-run setup used to be split across four entry points (`init`,
//! `setup`, `agent setup`, `workspace`) with overlapping responsibilities and
//! different trust assumptions. `onboard` sequences them into four explicit
//! phases with gates:
//!
//! 1. **Detect** (read-only, anywhere): find dotenv files, `.phantom.toml`,
//!    and existing MCP client configs. Never mutates.
//! 2. **Protect** (trusted terminal only): the `init` transaction — vault
//!    selection, value intake, dotenv rewrite. Refuses to run without an
//!    attached terminal, because real secret values are in play.
//! 3. **Connect** (trusted terminal only): MCP client configs + safe
//!    defaults for AI-agent use. Each step is previewed/confirmed.
//! 4. **Verify** (anywhere): `doctor`, `check`, and the agent readiness
//!    report. "Done" means all three are clean.
//!
//! The whole run emits a machine-readable receipt with `--json` so the
//! Phantom workbench can render progress without parsing prose. Verify steps
//! run as `phantom` subprocesses of the current executable so their prose can
//! be captured into the receipt instead of interleaved with JSON.
//!
//! Product decisions (defaults; see INTEGRATION.md for the open questions):
//! - The wizard is a thin sequencer over the existing commands — `agent
//!   setup` and `workspace` are *not* refactored onto a phase engine.
//! - "Done" = `phantom doctor`, `phantom check`, and `phantom agent report`
//!   all exit clean.

use std::io::IsTerminal;
use std::path::PathBuf;
use std::process::Command;

use anyhow::Result;
use colored::Colorize;
use serde::{Deserialize, Serialize};

use super::connector::prompt_yes_no;
use super::{agent, init, setup};

/// One wizard phase outcome in the receipt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PhaseResult {
    pub phase: String,
    pub status: PhaseStatus,
    pub detail: String,
}

/// Outcome of a single phase.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum PhaseStatus {
    Ok,
    Skipped,
    Failed,
}

/// Machine-readable receipt for the whole onboard run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OnboardReceipt {
    pub version: u8,
    pub done: bool,
    pub phases: Vec<PhaseResult>,
}

/// Read-only detection of the project's current setup state.
#[derive(Debug, Clone)]
struct Detection {
    initialized: bool,
    dotenv_files: Vec<String>,
    clients: Vec<(String, bool)>,
    vault_secret_count: Option<usize>,
}

fn detect() -> Detection {
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let initialized = cwd.join(".phantom.toml").exists();

    let mut dotenv_files = Vec::new();
    for name in [".env", ".env.local", ".env.development"] {
        if cwd.join(name).exists() {
            dotenv_files.push(name.to_string());
        }
    }

    let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
    let client_checks: Vec<(String, PathBuf)> = vec![
        ("claude".to_string(), cwd.join(".mcp.json")),
        ("cursor".to_string(), home.join(".cursor/mcp.json")),
        (
            "windsurf".to_string(),
            home.join(".codeium/windsurf/mcp_config.json"),
        ),
        ("codex".to_string(), home.join(".codex/config.toml")),
    ];
    let clients = client_checks
        .into_iter()
        .map(|(name, path)| {
            let configured = path.exists()
                && std::fs::read_to_string(&path)
                    .map(|c| c.contains("phantom"))
                    .unwrap_or(false);
            (name, configured)
        })
        .collect();

    // Best-effort vault census; failures just mean "unknown".
    let vault_secret_count = if initialized {
        read_vault_count().ok()
    } else {
        None
    };

    Detection {
        initialized,
        dotenv_files,
        clients,
        vault_secret_count,
    }
}

fn read_vault_count() -> Result<usize> {
    let project_dir = std::env::current_dir()?.canonicalize()?;
    let config_path = project_dir.join(".phantom.toml");
    let raw = phantom_core::fs::read_regular_file(&config_path)?
        .ok_or_else(|| anyhow::anyhow!("not initialized"))?;
    let config = phantom_core::config::PhantomConfig::load_from_bytes(&config_path, &raw)?;
    let vault = phantom_vault::try_create_vault(config.local_project_id())?;
    Ok(vault.list()?.len())
}

fn require_trusted_terminal(phase: &str) -> Result<()> {
    if std::io::stdin().is_terminal() && std::io::stdout().is_terminal() {
        return Ok(());
    }
    anyhow::bail!(
        "The {phase} phase handles real secret values, so it only runs on an attached trusted terminal.\n\
         Rerun `phantom onboard` from a terminal you trust (not from an agent's shell or a pipe).\n\
         `phantom onboard --plan` works anywhere and shows what would happen."
    )
}

/// Run a `phantom` subcommand as a child process, capturing its output for
/// the receipt. Returns (exit_ok, combined_output).
fn run_subcommand(args: &[&str]) -> (bool, String) {
    let exe = match std::env::current_exe() {
        Ok(e) => e,
        Err(_) => return (false, "cannot locate phantom executable".to_string()),
    };
    let output = Command::new(exe).args(args).output();
    match output {
        Ok(o) => {
            let mut combined = String::from_utf8_lossy(&o.stdout).to_string();
            let stderr = String::from_utf8_lossy(&o.stderr);
            if !stderr.trim().is_empty() {
                combined.push_str("\n[stderr]\n");
                combined.push_str(&stderr);
            }
            // Bound the receipt: keep the tail, where the verdict lives.
            const MAX: usize = 4000;
            let detail = if combined.len() > MAX {
                format!("…(truncated)…\n{}", &combined[combined.len() - MAX..])
            } else {
                combined
            };
            (o.status.success(), detail)
        }
        Err(e) => (
            false,
            format!("failed to run phantom {}: {e}", args.join(" ")),
        ),
    }
}

fn client_from_name(name: &str) -> Option<setup::Client> {
    match name {
        "claude" => Some(setup::Client::ClaudeCode),
        "cursor" => Some(setup::Client::Cursor),
        "windsurf" => Some(setup::Client::Windsurf),
        "codex" => Some(setup::Client::Codex),
        _ => None,
    }
}

/// `phantom onboard [--plan] [--yes] [--skip-connect]`.
pub fn run(plan_only: bool, yes: bool, skip_connect: bool, json: bool) -> Result<()> {
    let mut receipt = OnboardReceipt {
        version: 1,
        done: false,
        phases: Vec::new(),
    };
    let quiet_json = json;

    if !quiet_json {
        println!("{}", "Phantom onboarding".bold());
        println!("{}", "──────────────────".dimmed());
    }

    // ── Phase 1: Detect (read-only, anywhere) ────────────────────────────
    let d = detect();
    let detail = format!(
        "initialized={} dotenv=[{}] clients=[{}]{}",
        d.initialized,
        d.dotenv_files.join(","),
        d.clients
            .iter()
            .map(|(n, c)| format!("{n}:{}", if *c { "yes" } else { "no" }))
            .collect::<Vec<_>>()
            .join(","),
        d.vault_secret_count
            .map(|n| format!(" vault_secrets={n}"))
            .unwrap_or_default()
    );
    receipt.phases.push(PhaseResult {
        phase: "detect".to_string(),
        status: PhaseStatus::Ok,
        detail: detail.clone(),
    });
    if !quiet_json {
        println!("\n{} {}", "●".cyan().bold(), "Detect".bold());
        println!(
            "  Project: {}",
            if d.initialized {
                "protected (.phantom.toml present)".green().to_string()
            } else {
                "not protected yet".yellow().to_string()
            }
        );
        println!(
            "  Dotenv files: {}",
            if d.dotenv_files.is_empty() {
                "none found".dimmed().to_string()
            } else {
                d.dotenv_files.join(", ")
            }
        );
        if let Some(n) = d.vault_secret_count {
            println!("  Vault secrets: {n}");
        }
        println!("  MCP clients:");
        for (name, configured) in &d.clients {
            println!(
                "    {name}: {}",
                if *configured {
                    "configured".green().to_string()
                } else {
                    "not configured".dimmed().to_string()
                }
            );
        }
    }

    let needs_protect = !d.initialized;
    let unconfigured: Vec<String> = d
        .clients
        .iter()
        .filter(|(_, c)| !c)
        .map(|(n, _)| n.clone())
        .collect();
    let needs_connect = !skip_connect && !unconfigured.is_empty();

    if !quiet_json {
        println!("\n{} {}", "●".cyan().bold(), "Plan".bold());
        println!(
            "  Protect: {}",
            if needs_protect {
                "run `phantom init` (trusted terminal required)".to_string()
            } else {
                "skip — already protected".dimmed().to_string()
            }
        );
        println!(
            "  Connect: {}",
            if needs_connect {
                format!("configure {}", unconfigured.join(", "))
            } else if skip_connect {
                "skip — --skip-connect".dimmed().to_string()
            } else {
                "skip — all clients configured".dimmed().to_string()
            }
        );
        println!("  Verify: run doctor, check, and the agent readiness report");
    }

    if plan_only {
        receipt.phases.push(PhaseResult {
            phase: "protect".to_string(),
            status: PhaseStatus::Skipped,
            detail: "--plan: no mutations performed".to_string(),
        });
        receipt.phases.push(PhaseResult {
            phase: "connect".to_string(),
            status: PhaseStatus::Skipped,
            detail: "--plan: no mutations performed".to_string(),
        });
        receipt.phases.push(PhaseResult {
            phase: "verify".to_string(),
            status: PhaseStatus::Skipped,
            detail: "--plan: no mutations performed".to_string(),
        });
        emit_receipt(&receipt, json);
        return Ok(());
    }

    // ── Phase 2: Protect (trusted terminal only) ─────────────────────────
    if needs_protect {
        require_trusted_terminal("Protect")?;
        if !quiet_json {
            println!("\n{} {}", "●".cyan().bold(), "Protect".bold());
            println!(
                "  This runs {}: values move into the encrypted vault and",
                "`phantom init`".bold()
            );
            println!("  the dotenv file is rewritten with phm_ placeholders.");
        }
        let proceed = yes || prompt_yes_no("Run `phantom init` now?", true)?;
        if !proceed {
            receipt.phases.push(PhaseResult {
                phase: "protect".to_string(),
                status: PhaseStatus::Skipped,
                detail: "operator declined".to_string(),
            });
        } else {
            match init::run(".env") {
                Ok(()) => receipt.phases.push(PhaseResult {
                    phase: "protect".to_string(),
                    status: PhaseStatus::Ok,
                    detail: "phantom init completed".to_string(),
                }),
                Err(e) => {
                    receipt.phases.push(PhaseResult {
                        phase: "protect".to_string(),
                        status: PhaseStatus::Failed,
                        detail: format!("phantom init failed: {e:#}"),
                    });
                    emit_receipt(&receipt, json);
                    anyhow::bail!(
                        "Protect phase failed: {e:#}\nFix the error above, then rerun `phantom onboard` — it resumes from detection."
                    );
                }
            }
        }
    } else {
        receipt.phases.push(PhaseResult {
            phase: "protect".to_string(),
            status: PhaseStatus::Skipped,
            detail: "project already protected".to_string(),
        });
    }

    // ── Phase 3: Connect (trusted terminal only) ─────────────────────────
    if needs_connect {
        require_trusted_terminal("Connect")?;
        if !quiet_json {
            println!("\n{} {}", "●".cyan().bold(), "Connect".bold());
        }
        let mut all_ok = true;
        for name in &unconfigured {
            let Some(client) = client_from_name(name) else {
                continue;
            };
            let proceed = yes || prompt_yes_no(&format!("Configure the {name} MCP client?"), true)?;
            if !proceed {
                continue;
            }
            match setup::run(Some(client), false, None) {
                Ok(()) => {
                    if !quiet_json {
                        println!("  {} {name} configured", "✓".green());
                    }
                }
                Err(e) => {
                    all_ok = false;
                    if !quiet_json {
                        println!("  {} {name}: {e:#}", "✗".red());
                    }
                }
            }
        }
        // Safe defaults for AI-agent use.
        let do_agent_setup = yes
            || prompt_yes_no(
                "Initialize safe defaults for AI-agent use (`phantom agent setup --apply`)?",
                true,
            )?;
        if do_agent_setup {
            if let Err(e) = agent::setup(false, true) {
                all_ok = false;
                if !quiet_json {
                    println!("  {} agent setup: {e:#}", "✗".red());
                }
            } else if !quiet_json {
                println!("  {} agent defaults applied", "✓".green());
            }
        }
        receipt.phases.push(PhaseResult {
            phase: "connect".to_string(),
            status: if all_ok {
                PhaseStatus::Ok
            } else {
                PhaseStatus::Failed
            },
            detail: if all_ok {
                "client configs written".to_string()
            } else {
                "one or more connect steps failed; see output above".to_string()
            },
        });
    } else {
        receipt.phases.push(PhaseResult {
            phase: "connect".to_string(),
            status: PhaseStatus::Skipped,
            detail: if skip_connect {
                "--skip-connect".to_string()
            } else {
                "all clients already configured".to_string()
            },
        });
    }

    // ── Phase 4: Verify (anywhere) ───────────────────────────────────────
    if !quiet_json {
        println!("\n{} {}", "●".cyan().bold(), "Verify".bold());
    }
    let mut verify_ok = true;
    let mut verify_notes = Vec::new();
    for (label, args) in [
        ("doctor", &["doctor"] as &[&str]),
        ("check", &["check"] as &[&str]),
        ("agent report", &["agent", "report"] as &[&str]),
    ] {
        let (ok, output) = run_subcommand(args);
        if !quiet_json {
            println!("  {} {label}", if ok { "✓".green() } else { "✗".red() });
        }
        if !ok {
            verify_ok = false;
            verify_notes.push(format!("{label} failed"));
        }
        verify_notes.push(format!("--- {label} ---\n{output}"));
    }
    receipt.phases.push(PhaseResult {
        phase: "verify".to_string(),
        status: if verify_ok {
            PhaseStatus::Ok
        } else {
            PhaseStatus::Failed
        },
        detail: verify_notes.join("\n"),
    });
    receipt.done = verify_ok
        && receipt
            .phases
            .iter()
            .all(|p| p.status != PhaseStatus::Failed);

    if !quiet_json {
        println!();
        if receipt.done {
            println!(
                "{} Onboarding complete — this project is protected and agent-ready.",
                "✓".green().bold()
            );
            println!(
                "  Next: {} to run your agent through the proxy.",
                "`phantom exec -- <command>`".cyan()
            );
        } else {
            println!(
                "{} Onboarding finished with issues — see the phases above.",
                "!".yellow().bold()
            );
            println!("  Rerunning `phantom onboard` resumes from detection.");
        }
    }

    emit_receipt(&receipt, json);
    if !receipt.done {
        anyhow::bail!("onboarding verify phase reported failures");
    }
    Ok(())
}

fn emit_receipt(receipt: &OnboardReceipt, json: bool) {
    if json {
        match serde_json::to_string_pretty(receipt) {
            Ok(s) => println!("{s}"),
            Err(e) => eprintln!("failed to serialize onboard receipt: {e}"),
        }
    }
}

/// Human-readable one-line summary of a detection, for tests.
#[cfg(test)]
fn detection_summary(d: &Detection) -> String {
    format!(
        "initialized={} dotenv={} clients={}",
        d.initialized,
        d.dotenv_files.len(),
        d.clients.iter().filter(|(_, c)| *c).count()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn receipt_serializes_with_all_statuses() {
        let receipt = OnboardReceipt {
            version: 1,
            done: false,
            phases: vec![
                PhaseResult {
                    phase: "detect".to_string(),
                    status: PhaseStatus::Ok,
                    detail: "d".to_string(),
                },
                PhaseResult {
                    phase: "protect".to_string(),
                    status: PhaseStatus::Skipped,
                    detail: "s".to_string(),
                },
                PhaseResult {
                    phase: "verify".to_string(),
                    status: PhaseStatus::Failed,
                    detail: "f".to_string(),
                },
            ],
        };
        let s = serde_json::to_string(&receipt).unwrap();
        assert!(s.contains("\"done\":false"));
        assert!(s.contains("\"ok\"") && s.contains("\"skipped\"") && s.contains("\"failed\""));
    }

    #[test]
    fn detection_summary_counts() {
        let d = Detection {
            initialized: true,
            dotenv_files: vec![".env".to_string()],
            clients: vec![("claude".to_string(), true), ("cursor".to_string(), false)],
            vault_secret_count: Some(3),
        };
        assert_eq!(detection_summary(&d), "initialized=true dotenv=1 clients=1");
    }

    #[test]
    fn client_from_name_maps_all() {
        assert!(client_from_name("claude").is_some());
        assert!(client_from_name("cursor").is_some());
        assert!(client_from_name("windsurf").is_some());
        assert!(client_from_name("codex").is_some());
        assert!(client_from_name("bogus").is_none());
    }
}
