//! Metadata-only planning followed by explicitly confirmed local command phases.
//! Receipts describe completed work; they never imply rollback or provider setup.
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::io::{BufRead, Read, Write};
use std::path::Path;
use std::process::{Command, Stdio};

const PHASES: [&str; 4] = ["detect", "protect", "connect", "verify"];
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PhaseResult {
    pub phase: String,
    pub status: PhaseStatus,
    pub detail: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub steps: Vec<PhaseResult>,
}
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum PhaseStatus {
    Ok,
    Skipped,
    Declined,
    Failed,
}
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum OnboardOutcome {
    Planned,
    Complete,
    Declined,
    Failed,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OnboardReceipt {
    pub version: u8,
    pub done: bool,
    pub outcome: OnboardOutcome,
    pub rerun: String,
    pub phases: Vec<PhaseResult>,
}
#[derive(Debug, Clone)]
struct Detection {
    config_present: bool,
    dotenv_files: Vec<String>,
    clients: Vec<(String, bool)>,
}
fn phase(name: &str, status: PhaseStatus, detail: impl Into<String>) -> PhaseResult {
    PhaseResult {
        phase: name.into(),
        status,
        detail: detail.into(),
        steps: Vec::new(),
    }
}
fn local_mcp_entry(command: Option<&str>, args: Option<&serde_json::Value>) -> bool {
    let binary = command
        .and_then(|c| Path::new(c).file_name())
        .and_then(|s| s.to_str());
    match binary {
        Some("phantom-mcp" | "phantom-mcp.exe") => true,
        Some("phantom" | "phantom.exe") => {
            args.and_then(|a| a.get(0)).and_then(|v| v.as_str()) == Some("mcp")
        }
        _ => false,
    }
}
fn client_configured(path: &Path, codex: bool) -> bool {
    let Ok(meta) = std::fs::symlink_metadata(path) else {
        return false;
    };
    if !meta.is_file() || meta.len() > 64 * 1024 {
        return false;
    }
    let Ok(Some(raw)) = phantom_core::fs::read_regular_file(path) else {
        return false;
    };
    if raw.len() > 64 * 1024 {
        return false;
    }
    let value = if codex {
        let Ok(text) = std::str::from_utf8(&raw) else {
            return false;
        };
        let Ok(document) = toml::from_str::<toml::Value>(text) else {
            return false;
        };
        let Ok(value) = serde_json::to_value(document) else {
            return false;
        };
        value
            .get("mcp_servers")
            .and_then(|v| v.get("phantom"))
            .cloned()
    } else {
        serde_json::from_slice::<serde_json::Value>(&raw)
            .ok()
            .and_then(|v| v.get("mcpServers").and_then(|s| s.get("phantom")).cloned())
    };
    value.is_some_and(|entry| {
        local_mcp_entry(
            entry.get("command").and_then(|v| v.as_str()),
            entry.get("args"),
        )
    })
}
fn detect() -> Result<Detection> {
    let cwd = std::env::current_dir()?;
    let home = phantom_core::home::home_dir()?;
    let dotenv_files = [".env", ".env.local", ".env.development"]
        .into_iter()
        .filter(|name| std::fs::symlink_metadata(cwd.join(name)).is_ok())
        .map(String::from)
        .collect();
    let profiles = [
        ("claude", cwd.join(".mcp.json"), false),
        ("cursor", home.join(".cursor/mcp.json"), false),
        (
            "windsurf",
            home.join(".codeium/windsurf/mcp_config.json"),
            false,
        ),
        ("codex", home.join(".codex/config.toml"), true),
    ];
    // Vault construction can migrate plaintext or reconcile sidecars. Do not
    // open any vault or count secrets during detection, including live runs.
    Ok(Detection {
        config_present: std::fs::symlink_metadata(cwd.join(".phantom.toml")).is_ok(),
        dotenv_files,
        clients: profiles
            .into_iter()
            .map(|(name, path, codex)| (name.into(), client_configured(&path, codex)))
            .collect(),
    })
}
trait Runtime {
    fn terminal(&mut self, phase: &str) -> Result<()>;
    fn confirm(&mut self, question: &str, yes: bool) -> Result<bool>;
    fn effect(&mut self, args: &[&str], json: bool) -> Result<bool>;
    fn verify(&mut self, args: &[&str]) -> (bool, String);
}
struct LocalRuntime;
impl Runtime for LocalRuntime {
    fn terminal(&mut self, phase: &str) -> Result<()> {
        super::export_cmd::require_attached_terminals(&format!("Onboarding {phase}"))
    }
    fn confirm(&mut self, question: &str, yes: bool) -> Result<bool> {
        if yes {
            return Ok(true);
        }
        eprint!("{question} [y/N] ");
        std::io::stderr().flush()?;
        let mut answer = String::new();
        std::io::stdin().lock().take(4096).read_line(&mut answer)?;
        Ok(matches!(
            answer.trim().to_ascii_lowercase().as_str(),
            "y" | "yes"
        ))
    }
    fn effect(&mut self, args: &[&str], json: bool) -> Result<bool> {
        let mut child = Command::new(std::env::current_exe()?);
        child
            .args(args)
            .stdin(Stdio::inherit())
            .stderr(Stdio::inherit());
        child.stdout(if json {
            terminal_stderr()?
        } else {
            Stdio::inherit()
        });
        // Early exits in agent setup stay in this child; the parent always
        // records the phase outcome and stops after a failed phase.
        Ok(child
            .status()
            .context("could not run onboarding phase")?
            .success())
    }
    fn verify(&mut self, args: &[&str]) -> (bool, String) {
        let result = std::env::current_exe()
            .and_then(|exe| Command::new(exe).args(args).stdin(Stdio::null()).output());
        match result {
            Ok(output) => {
                let mut text = String::from_utf8_lossy(&output.stdout).into_owned();
                if !output.stderr.is_empty() {
                    text.push_str("\n[stderr]\n");
                    text.push_str(&String::from_utf8_lossy(&output.stderr));
                }
                (output.status.success(), bounded_tail(&text, 4000))
            }
            Err(_) => (false, "could not run local verification command".into()),
        }
    }
}
// Duplicate the already attached stderr, preserving child terminal gates.
// Never open a new terminal or manufacture a PTY to authorize a phase.
#[cfg(unix)]
fn terminal_stderr() -> Result<Stdio> {
    use std::os::fd::AsFd;
    Ok(Stdio::from(std::io::stderr().as_fd().try_clone_to_owned()?))
}
#[cfg(windows)]
fn terminal_stderr() -> Result<Stdio> {
    use std::os::windows::io::AsHandle;
    Ok(Stdio::from(
        std::io::stderr().as_handle().try_clone_to_owned()?,
    ))
}
#[cfg(not(any(unix, windows)))]
fn terminal_stderr() -> Result<Stdio> {
    anyhow::bail!("live JSON onboarding unsupported on this platform")
}
fn bounded_tail(text: &str, limit: usize) -> String {
    if text.len() <= limit {
        return text.into();
    }
    let mut start = text.len() - limit;
    while !text.is_char_boundary(start) {
        start += 1;
    }
    format!("...(truncated)...\n{}", &text[start..])
}
fn preserve_connection_error<T>(
    result: Result<T>,
    connected: &PhaseResult,
    step: &str,
    receipt: &mut OnboardReceipt,
) -> Result<T> {
    result.inspect_err(|error| {
        let mut failed = connected.clone();
        failed.status = PhaseStatus::Failed;
        failed.steps.push(phase(
            step,
            PhaseStatus::Failed,
            "confirmation or child execution failed; inspect terminal output",
        ));
        failed.detail = format!(
            "connection stopped; earlier completed steps remain applied: {}",
            bounded_tail(&error.to_string(), 1000)
        );
        receipt.phases.push(failed);
    })
}
fn flow(
    d: &Detection,
    plan_only: bool,
    yes: bool,
    skip_connect: bool,
    json: bool,
    runtime: &mut impl Runtime,
    receipt: &mut OnboardReceipt,
) -> Result<()> {
    receipt.phases.push(phase(
        "detect",
        PhaseStatus::Ok,
        format!(
            "config_present={} dotenv=[{}] clients=[{}]; vault not inspected",
            d.config_present,
            d.dotenv_files.join(","),
            d.clients
                .iter()
                .map(|(name, ready)| format!("{name}:{ready}"))
                .collect::<Vec<_>>()
                .join(",")
        ),
    ));
    if !json {
        println!("Detect: {}", receipt.phases[0].detail);
        println!(
            "Protect: {}",
            if d.config_present {
                ".phantom.toml present; verification pending"
            } else {
                "run phantom init for .env after terminal consent"
            }
        );
        println!(
            "Connect: {}",
            if skip_connect {
                "skip requested"
            } else {
                "confirm each missing MCP client and agent defaults"
            }
        );
        println!("Verify: doctor, check and agent report");
    }
    if plan_only {
        for name in &PHASES[1..] {
            receipt.phases.push(phase(
                name,
                PhaseStatus::Skipped,
                "--plan: no phase commands or vault access",
            ));
        }
        receipt.outcome = OnboardOutcome::Planned;
        return Ok(());
    }
    if d.config_present {
        receipt.phases.push(phase(
            "protect",
            PhaseStatus::Skipped,
            "configuration present; verification pending",
        ));
    } else {
        runtime.terminal("Protect")?;
        if !runtime.confirm(
            "Run phantom init for this project's .env? Existing exact init consent still applies.",
            yes,
        )? {
            receipt.phases.push(phase(
                "protect",
                PhaseStatus::Declined,
                "operator declined; no protection command ran",
            ));
            receipt.outcome = OnboardOutcome::Declined;
            return Ok(());
        }
        let ok = runtime.effect(&["init"], json)?;
        receipt.phases.push(phase(
            "protect",
            if ok {
                PhaseStatus::Ok
            } else {
                PhaseStatus::Failed
            },
            if ok {
                "init completed; its own transaction and consent gates applied"
            } else {
                "init failed; inspect terminal output before rerunning"
            },
        ));
        if !ok {
            anyhow::bail!("protection phase failed");
        }
    }
    if skip_connect {
        receipt.phases.push(phase(
            "connect",
            PhaseStatus::Skipped,
            "--skip-connect; no client or agent configuration commands ran",
        ));
    } else {
        runtime.terminal("Connect")?;
        let mut connected = phase(
            "connect",
            PhaseStatus::Ok,
            "confirmed connection steps completed",
        );
        for (name, configured) in &d.clients {
            if *configured {
                connected.steps.push(phase(
                    name,
                    PhaseStatus::Skipped,
                    "local Phantom MCP entry already present",
                ));
                continue;
            }
            if !preserve_connection_error(
                runtime.confirm(
                    &format!("Configure the {name} MCP profile for local Phantom?"),
                    yes,
                ),
                &connected,
                name,
                receipt,
            )? {
                connected.steps.push(phase(
                    name,
                    PhaseStatus::Declined,
                    "operator declined; profile unchanged",
                ));
                connected.status = PhaseStatus::Declined;
                connected.detail =
                    "connection declined; earlier completed steps remain applied".into();
                receipt.phases.push(connected);
                receipt.outcome = OnboardOutcome::Declined;
                return Ok(());
            }
            let ok = preserve_connection_error(
                runtime.effect(&["setup", "--client", name], json),
                &connected,
                name,
                receipt,
            )?;
            connected.steps.push(phase(
                name,
                if ok {
                    PhaseStatus::Ok
                } else {
                    PhaseStatus::Failed
                },
                if ok {
                    "client setup completed"
                } else {
                    "client setup failed"
                },
            ));
            if !ok {
                connected.status = PhaseStatus::Failed;
                connected.detail =
                    "connection failed; earlier completed steps remain applied".into();
                receipt.phases.push(connected);
                anyhow::bail!("connection phase failed");
            }
        }
        if !preserve_connection_error(
            runtime.confirm(
                "Apply local agent defaults with phantom agent setup --apply?",
                yes,
            ),
            &connected,
            "agent-defaults",
            receipt,
        )? {
            connected.steps.push(phase(
                "agent-defaults",
                PhaseStatus::Declined,
                "operator declined; agent defaults unchanged",
            ));
            connected.status = PhaseStatus::Declined;
            connected.detail =
                "agent defaults declined; earlier completed steps remain applied".into();
            receipt.phases.push(connected);
            receipt.outcome = OnboardOutcome::Declined;
            return Ok(());
        }
        let ok = preserve_connection_error(
            runtime.effect(&["agent", "setup", "--apply"], json),
            &connected,
            "agent-defaults",
            receipt,
        )?;
        connected.steps.push(phase(
            "agent-defaults",
            if ok {
                PhaseStatus::Ok
            } else {
                PhaseStatus::Failed
            },
            if ok {
                "agent setup completed"
            } else {
                "agent setup child failed; verification was not run"
            },
        ));
        if !ok {
            connected.status = PhaseStatus::Failed;
        }
        receipt.phases.push(connected);
        if !ok {
            anyhow::bail!("agent setup phase failed");
        }
    }
    // Existing diagnostic commands instantiate vault backends, which can
    // reconcile legacy storage. Do not present that as a headless observer.
    runtime.terminal("Verify")?;
    if !runtime.confirm("Run doctor, check and agent report for this project? Vault probes may reconcile existing local backend storage; no provider request is sent.", yes)? {
        receipt.phases.push(phase("verify", PhaseStatus::Declined, "operator declined; no diagnostic commands ran"));
        receipt.outcome = OnboardOutcome::Declined;
        return Ok(());
    }
    let mut verification = phase("verify", PhaseStatus::Ok, "local checks completed");
    for (name, args) in [
        ("doctor", &["doctor"] as &[&str]),
        ("check", &["check"] as &[&str]),
        ("agent-report", &["agent", "report"] as &[&str]),
    ] {
        let (ok, detail) = runtime.verify(args);
        verification.steps.push(phase(
            name,
            if ok {
                PhaseStatus::Ok
            } else {
                PhaseStatus::Failed
            },
            detail,
        ));
        if !ok {
            verification.status = PhaseStatus::Failed;
        }
    }
    let ok = verification.status == PhaseStatus::Ok;
    receipt.phases.push(verification);
    if !ok {
        anyhow::bail!("local verification failed; completed changes remain applied");
    }
    receipt.done = true;
    receipt.outcome = OnboardOutcome::Complete;
    Ok(())
}
fn finish(receipt: &mut OnboardReceipt, error: Option<&anyhow::Error>) {
    if let Some(error) = error {
        receipt.outcome = OnboardOutcome::Failed;
        if !receipt
            .phases
            .iter()
            .any(|p| p.status == PhaseStatus::Failed)
        {
            let name = PHASES[receipt.phases.len().min(PHASES.len() - 1)];
            receipt.phases.push(phase(
                name,
                PhaseStatus::Failed,
                bounded_tail(&error.to_string(), 1000),
            ));
        }
    }
    for name in PHASES {
        if !receipt.phases.iter().any(|p| p.phase == name) {
            receipt.phases.push(phase(
                name,
                PhaseStatus::Skipped,
                "not run after an earlier failure or decline",
            ));
        }
    }
}
pub fn run(plan_only: bool, yes: bool, skip_connect: bool, json: bool) -> Result<()> {
    let mut receipt = OnboardReceipt { version: 1, done: false, outcome: OnboardOutcome::Failed,
        rerun: "Rerun phantom onboard to detect current state; completed phases are not rolled back. --plan never opens the vault.".into(), phases: Vec::new() };
    let result = detect().and_then(|d| {
        flow(
            &d,
            plan_only,
            yes,
            skip_connect,
            json,
            &mut LocalRuntime,
            &mut receipt,
        )
    });
    finish(&mut receipt, result.as_ref().err());
    if json {
        println!("{}", serde_json::to_string_pretty(&receipt)?);
    } else {
        println!("Onboarding {:?}: {}", receipt.outcome, receipt.rerun);
        for p in &receipt.phases {
            println!("{}: {:?}: {}", p.phase, p.status, p.detail);
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    #[derive(Default)]
    struct FakeRuntime {
        effects: Vec<Vec<String>>,
        verifies: usize,
        answers: VecDeque<bool>,
        failures: VecDeque<bool>,
        error_after: Option<usize>,
        verify_failed: bool,
    }
    impl Runtime for FakeRuntime {
        fn terminal(&mut self, _: &str) -> Result<()> {
            Ok(())
        }
        fn confirm(&mut self, _: &str, yes: bool) -> Result<bool> {
            Ok(yes || self.answers.pop_front().unwrap_or(false))
        }
        fn effect(&mut self, args: &[&str], _: bool) -> Result<bool> {
            self.effects
                .push(args.iter().map(|s| s.to_string()).collect());
            if self.error_after == Some(self.effects.len()) {
                anyhow::bail!("synthetic child spawn failure");
            }
            Ok(!self.failures.pop_front().unwrap_or(false))
        }
        fn verify(&mut self, _: &[&str]) -> (bool, String) {
            self.verifies += 1;
            (!self.verify_failed, "local fixture result".into())
        }
    }
    fn exercise(
        d: Detection,
        plan: bool,
        yes: bool,
        skip: bool,
        runtime: &mut FakeRuntime,
    ) -> OnboardReceipt {
        let mut receipt = OnboardReceipt {
            version: 1,
            done: false,
            outcome: OnboardOutcome::Failed,
            rerun: "detect again".into(),
            phases: vec![],
        };
        let result = flow(&d, plan, yes, skip, true, runtime, &mut receipt);
        finish(&mut receipt, result.as_ref().err());
        receipt
    }
    fn detected(present: bool, configured: bool) -> Detection {
        Detection {
            config_present: present,
            dotenv_files: vec![".env".into()],
            clients: vec![("claude".into(), configured)],
        }
    }
    #[test]
    fn spawn_error_preserves_completed_connection_steps() {
        let mut runtime = FakeRuntime {
            error_after: Some(2),
            ..Default::default()
        };
        let mut d = detected(true, false);
        d.clients.push(("cursor".into(), false));
        let receipt = exercise(d, false, true, false, &mut runtime);
        assert_eq!(receipt.outcome, OnboardOutcome::Failed);
        assert_eq!(receipt.phases[2].status, PhaseStatus::Failed);
        assert_eq!(receipt.phases[2].steps.len(), 2);
        assert_eq!(receipt.phases[2].steps[0].phase, "claude");
        assert_eq!(receipt.phases[2].steps[0].status, PhaseStatus::Ok);
        assert_eq!(receipt.phases[2].steps[1].phase, "cursor");
        assert_eq!(receipt.phases[2].steps[1].status, PhaseStatus::Failed);
        assert_eq!(runtime.verifies, 0);
    }
    #[test]
    fn verification_decline_never_opens_diagnostic_commands() {
        let mut runtime = FakeRuntime::default();
        let receipt = exercise(detected(true, true), false, false, true, &mut runtime);
        assert_eq!(receipt.outcome, OnboardOutcome::Declined);
        assert_eq!(receipt.phases[3].status, PhaseStatus::Declined);
        assert!(runtime.effects.is_empty());
        assert_eq!(runtime.verifies, 0);
    }
    #[test]
    fn failed_verification_keeps_all_results_and_never_claims_done() {
        let mut runtime = FakeRuntime {
            verify_failed: true,
            ..Default::default()
        };
        let receipt = exercise(detected(true, true), false, true, true, &mut runtime);
        assert_eq!(receipt.outcome, OnboardOutcome::Failed);
        assert!(!receipt.done);
        assert_eq!(receipt.phases[3].steps.len(), 3);
        assert_eq!(runtime.verifies, 3);
        assert_eq!(receipt.phases[3].status, PhaseStatus::Failed);
    }
    #[test]
    fn plan_never_calls_effect_or_verification() {
        let mut runtime = FakeRuntime::default();
        let receipt = exercise(detected(false, false), true, true, false, &mut runtime);
        assert_eq!(receipt.outcome, OnboardOutcome::Planned);
        assert!(!receipt.done);
        assert!(runtime.effects.is_empty());
        assert_eq!(runtime.verifies, 0);
        assert_eq!(receipt.phases.len(), 4);
    }
    #[test]
    fn protection_decline_stops_before_connect_or_verify() {
        let mut runtime = FakeRuntime::default();
        let receipt = exercise(detected(false, false), false, false, false, &mut runtime);
        assert_eq!(receipt.outcome, OnboardOutcome::Declined);
        assert!(!receipt.done);
        assert!(runtime.effects.is_empty());
        assert_eq!(runtime.verifies, 0);
        assert_eq!(receipt.phases[1].status, PhaseStatus::Declined);
    }
    #[test]
    fn connection_decline_records_completed_protection() {
        let mut runtime = FakeRuntime {
            answers: VecDeque::from([true, false]),
            ..Default::default()
        };
        let receipt = exercise(detected(false, false), false, false, false, &mut runtime);
        assert_eq!(receipt.outcome, OnboardOutcome::Declined);
        assert_eq!(receipt.phases[1].status, PhaseStatus::Ok);
        assert_eq!(runtime.effects, vec![vec!["init"]]);
        assert_eq!(runtime.verifies, 0);
    }
    #[test]
    fn child_failure_cannot_skip_receipt_or_run_verifiers() {
        let mut runtime = FakeRuntime {
            failures: VecDeque::from([true]),
            ..Default::default()
        };
        let receipt = exercise(detected(true, true), false, true, false, &mut runtime);
        assert_eq!(runtime.effects, vec![vec!["agent", "setup", "--apply"]]);
        assert_eq!(receipt.outcome, OnboardOutcome::Failed);
        assert!(!receipt.done);
        assert_eq!(receipt.phases[2].steps[1].status, PhaseStatus::Failed);
        assert_eq!(runtime.verifies, 0);
        assert!(serde_json::to_string(&receipt)
            .unwrap()
            .contains("agent-defaults"));
    }
    #[test]
    fn rerun_skips_existing_profile_and_still_verifies() {
        let mut runtime = FakeRuntime::default();
        let receipt = exercise(detected(true, true), false, true, true, &mut runtime);
        assert_eq!(receipt.outcome, OnboardOutcome::Complete);
        assert!(receipt.done);
        assert!(runtime.effects.is_empty());
        assert_eq!(runtime.verifies, 3);
    }
    #[test]
    fn receipt_tail_never_splits_utf8() {
        let text = "é🙂".repeat(1001);
        let tail = bounded_tail(&text, 4000);
        assert!(tail.ends_with("é🙂"));
        assert!(tail.len() <= 4018);
    }
    #[test]
    fn local_entry_rejects_bootstrap_and_string_mentions() {
        assert!(!local_mcp_entry(
            Some("npx"),
            Some(&serde_json::json!(["phantom"]))
        ));
        assert!(!local_mcp_entry(
            Some("phantom"),
            Some(&serde_json::json!(["exec"]))
        ));
        assert!(local_mcp_entry(
            Some("/path with spaces/phantom"),
            Some(&serde_json::json!(["mcp"]))
        ));
        assert!(local_mcp_entry(Some("phantom-mcp"), None));
    }
}
