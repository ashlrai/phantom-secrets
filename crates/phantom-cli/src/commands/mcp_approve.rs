//! `phantom mcp-approve <NONCE>` — informed, out-of-band approval for MCP effects.
//!
//! This command deliberately requires an attached terminal. It shows the exact
//! value-blind parameters and bounded effect recorded by the MCP server, then
//! requires a fresh challenge before mutating the pending approval. The terminal
//! and this command must be outside the requesting agent's authority.

use std::io::{BufRead, IsTerminal, Read, Write};

use anyhow::{Context, Result};
use phantom_core::mcp_approval;
use rand::RngCore;

/// Run `phantom mcp-approve <nonce>`.
pub fn run(nonce: &str) -> Result<()> {
    let stdin = std::io::stdin();
    let mut stderr = std::io::stderr();
    let stdin_is_terminal = stdin.is_terminal();
    let stderr_is_terminal = stderr.is_terminal();
    let mut reader = std::io::BufReader::new(stdin.lock());
    let mut stdout = std::io::stdout();
    run_with_terminal_state(
        nonce,
        stdin_is_terminal,
        stderr_is_terminal,
        &mut reader,
        &mut stderr,
        &mut stdout,
    )
}

fn run_with_terminal_state(
    nonce: &str,
    stdin_is_terminal: bool,
    stderr_is_terminal: bool,
    input: &mut impl BufRead,
    diagnostic: &mut impl Write,
    output: &mut impl Write,
) -> Result<()> {
    let nonce = nonce.trim();
    if nonce.is_empty() {
        anyhow::bail!(
            "Usage: phantom mcp-approve <NONCE>\n\
            The NONCE is printed to stderr by the MCP server when an effectful \
            tool is called without a valid approval token."
        );
    }

    // Keep terminal admission ahead of approval inspection, challenge
    // generation, and every read. Besides preventing non-terminal approval,
    // this makes the denial path independent of whether the test runner itself
    // happens to own a PTY.
    if !stdin_is_terminal || !stderr_is_terminal {
        anyhow::bail!(
            "Approval refused: stdin and stderr must both be attached to an interactive terminal. \
             Run `phantom mcp-approve {nonce}` yourself in a terminal outside the requesting \
             agent's command authority. A same-user shell or controllable PTY can defeat this \
             ceremony; leave MCP effects disabled when that separation cannot be guaranteed."
        );
    }

    let mut challenge_bytes = [0_u8; 4];
    rand::thread_rng().fill_bytes(&mut challenge_bytes);
    let challenge = hex::encode(challenge_bytes);
    run_interactive(nonce, &challenge, input, diagnostic, output)
}

fn run_interactive(
    nonce: &str,
    challenge: &str,
    input: &mut impl BufRead,
    diagnostic: &mut impl Write,
    output: &mut impl Write,
) -> Result<()> {
    run_interactive_with(
        nonce,
        challenge,
        input,
        diagnostic,
        output,
        |nonce| {
            mcp_approval::inspect_pending_approval(nonce)
                .with_context(|| "Approval inspection failed")
        },
        |nonce| mcp_approval::approve_nonce(nonce).with_context(|| "Approval failed"),
    )
}

fn run_interactive_with<Inspect, Approve>(
    nonce: &str,
    challenge: &str,
    input: &mut impl BufRead,
    diagnostic: &mut impl Write,
    output: &mut impl Write,
    inspect: Inspect,
    approve: Approve,
) -> Result<()>
where
    Inspect: FnOnce(&str) -> Result<mcp_approval::ApprovalRecord>,
    Approve: FnOnce(&str) -> Result<mcp_approval::ApprovalOutcome>,
{
    // Inspection is read-only. Nothing is approved until after the challenge.
    let record = inspect(nonce)?;
    review_and_confirm(&record, challenge, input, diagnostic)?;

    let outcome = approve(nonce)?;
    write_approval_output(nonce, &outcome, output)
}

/// Render the exact persisted review record and require the fresh terminal
/// challenge. This function is deliberately free of approval-state mutation:
/// callers may proceed to `approve_nonce` only after it returns successfully.
fn review_and_confirm(
    record: &mcp_approval::ApprovalRecord,
    challenge: &str,
    input: &mut impl BufRead,
    diagnostic: &mut impl Write,
) -> Result<()> {
    let project = serde_json::to_string(&record.project_id)
        .context("Could not format the value-blind project identifier")?;
    let expires_at = record
        .expires_at
        .map(|timestamp| timestamp.to_string())
        .unwrap_or_else(|| "invalid legacy record".to_string());
    let remaining = record.remaining_secs().unwrap_or(0);
    let expected = format!("approve {challenge}");

    writeln!(diagnostic, "Phantom MCP approval request")?;
    writeln!(diagnostic, "  Tool:       {}", record.tool_name)?;
    writeln!(diagnostic, "  Project:    {project}")?;
    writeln!(
        diagnostic,
        "  Expires:    unix {expires_at} ({remaining}s remaining)"
    )?;
    writeln!(diagnostic, "  Effect:     {}", record.effect_summary)?;
    writeln!(diagnostic, "  Parameters: {}", record.parameter_summary)?;
    writeln!(diagnostic)?;
    writeln!(
        diagnostic,
        "Approve only if this terminal and command are outside the requesting agent's authority."
    )?;
    writeln!(
        diagnostic,
        "A same-user shell or agent-controlled PTY can automate this ceremony."
    )?;
    write!(diagnostic, "Type '{expected}' to approve: ")?;
    diagnostic.flush()?;

    let mut response = String::new();
    (&mut *input)
        .take((expected.len() + 2) as u64)
        .read_line(&mut response)
        .context("Could not read the bounded approval response")?;
    if response.trim_end_matches(['\r', '\n']) != expected {
        anyhow::bail!("Approval cancelled: the fresh confirmation challenge did not match.");
    }

    Ok(())
}

fn write_approval_output(
    nonce: &str,
    outcome: &mcp_approval::ApprovalOutcome,
    output: &mut impl Write,
) -> Result<()> {
    writeln!(output, "Approved: {}", outcome.tool_name)?;
    writeln!(
        output,
        "approval_token: \"{nonce}:{}\"",
        outcome.approval_token
    )?;
    writeln!(
        output,
        "This token is single-use, short-lived, and bound to the reviewed parameters."
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::io::{BufRead, Cursor, Read};
    use std::process::Command;
    use std::sync::mpsc;
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

    use phantom_core::mcp_approval;
    use rand::RngCore;
    use tempfile::TempDir;

    fn random_hex<const N: usize>() -> String {
        let mut bytes = [0_u8; N];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        hex::encode(bytes)
    }

    fn reviewed_record() -> mcp_approval::ApprovalRecord {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        mcp_approval::ApprovalRecord {
            nonce: random_hex::<32>(),
            tool_name: "phantom_rotate".to_string(),
            arg_hash: random_hex::<32>(),
            project_id: "test-project".to_string(),
            effect_summary: "Remap all managed local placeholders.".to_string(),
            parameter_summary: r#"{"confirm":true}"#.to_string(),
            created_at: now,
            expires_at: Some(now + mcp_approval::APPROVAL_TTL_SECS),
            approved: false,
            approved_at: None,
        }
    }

    struct FakeApprovalState {
        expected_nonce: String,
        approval_token: String,
        pending: Option<mcp_approval::ApprovalRecord>,
        inspected: bool,
        approved: bool,
    }

    impl FakeApprovalState {
        fn new(record: mcp_approval::ApprovalRecord) -> Self {
            Self {
                expected_nonce: record.nonce.clone(),
                approval_token: random_hex::<32>(),
                pending: Some(record),
                inspected: false,
                approved: false,
            }
        }

        fn inspect(&mut self, nonce: &str) -> anyhow::Result<mcp_approval::ApprovalRecord> {
            assert_eq!(nonce, self.expected_nonce, "inspected the wrong nonce");
            assert!(!self.inspected, "nonce was inspected more than once");
            assert!(!self.approved, "nonce was approved before inspection");
            self.inspected = true;
            Ok(self
                .pending
                .as_ref()
                .expect("inspected nonce must still be pending")
                .clone())
        }

        fn approve(&mut self, nonce: &str) -> anyhow::Result<mcp_approval::ApprovalOutcome> {
            assert_eq!(nonce, self.expected_nonce, "approved the wrong nonce");
            assert!(self.inspected, "nonce was approved before inspection");
            assert!(!self.approved, "nonce was approved more than once");
            let record = self
                .pending
                .take()
                .expect("approved nonce must still be pending");
            self.approved = true;
            Ok(mcp_approval::ApprovalOutcome {
                approval_token: self.approval_token.clone(),
                tool_name: record.tool_name,
                arg_hash: record.arg_hash,
            })
        }
    }

    fn with_temp_home<F: FnOnce() -> T, T>(f: F) -> T {
        let dir = TempDir::new().unwrap();
        let _guard = crate::test_support::ENV_LOCK
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let prev = std::env::var("HOME").ok();
        std::env::set_var("HOME", dir.path());
        let result = f();
        match prev {
            Some(p) => std::env::set_var("HOME", p),
            None => std::env::remove_var("HOME"),
        }
        result
    }

    struct PanicOnRead;

    impl Read for PanicOnRead {
        fn read(&mut self, _buffer: &mut [u8]) -> std::io::Result<usize> {
            panic!("noninteractive approval attempted to read stdin")
        }
    }

    impl BufRead for PanicOnRead {
        fn fill_buf(&mut self) -> std::io::Result<&[u8]> {
            panic!("noninteractive approval attempted to buffer stdin")
        }

        fn consume(&mut self, _amount: usize) {}
    }

    #[test]
    fn noninteractive_admission_never_reads_or_strands_transaction_waiters() {
        const ISOLATED_CHILD_ENV: &str = "PHANTOM_TEST_MCP_APPROVE_ISOLATED_CHILD_V1";
        const TEST_NAME: &str = "commands::mcp_approve::tests::noninteractive_admission_never_reads_or_strands_transaction_waiters";

        // This is a process-global lock-order test. Running its watchdog beside
        // unrelated ENV_LOCK users can starve the deliberately blocked thread
        // and misclassify scheduler contention as a deadlock. Re-enter only
        // this exact test in a bounded child process so the same production
        // locks are exercised without unrelated test-harness interference.
        if std::env::var(ISOLATED_CHILD_ENV).as_deref() != Ok("1") {
            let mut child = Command::new(std::env::current_exe().unwrap())
                .args(["--exact", TEST_NAME, "--nocapture"])
                .env(ISOLATED_CHILD_ENV, "1")
                .spawn()
                .unwrap();
            let deadline = Instant::now() + Duration::from_secs(30);
            loop {
                if let Some(status) = child.try_wait().unwrap() {
                    assert!(status.success(), "isolated lock-order test failed");
                    return;
                }
                if Instant::now() >= deadline {
                    child.kill().ok();
                    child.wait().ok();
                    panic!("isolated lock-order test exceeded its deadlock watchdog");
                }
                std::thread::sleep(Duration::from_millis(10));
            }
        }

        let project = TempDir::new().unwrap();
        let project_path = project.path().to_path_buf();
        let (acquired_rx, contender) = with_temp_home(|| {
            let nonce = random_hex::<32>();

            // A transaction contender must wait while this test owns the
            // environment guard. The noninteractive approval path must return
            // without reading the runner's terminal so the guard can be
            // released and the contender can make progress.
            let (started_tx, started_rx) = mpsc::channel();
            let (acquired_tx, acquired_rx) = mpsc::channel();
            let contender = std::thread::spawn(move || {
                started_tx.send(()).unwrap();
                let _lock = phantom_vault::acquire_project_transaction_lock(&project_path).unwrap();
                acquired_tx.send(()).unwrap();
            });
            started_rx.recv_timeout(Duration::from_secs(1)).unwrap();
            assert!(acquired_rx.recv_timeout(Duration::from_millis(50)).is_err());

            let mut input = PanicOnRead;
            let mut diagnostic = Vec::new();
            let mut output = Vec::new();
            let error = super::run_with_terminal_state(
                &nonce,
                false,
                true,
                &mut input,
                &mut diagnostic,
                &mut output,
            )
            .unwrap_err()
            .to_string();
            assert!(error.contains("interactive terminal"), "{error}");
            assert!(diagnostic.is_empty());
            assert!(output.is_empty());
            assert!(!mcp_approval::approvals_path().unwrap().exists());
            (acquired_rx, contender)
        });

        acquired_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        contender.join().unwrap();
    }

    #[test]
    fn informed_challenge_renders_exact_record_and_output() {
        let record = reviewed_record();
        let nonce = record.nonce.clone();
        let state = RefCell::new(FakeApprovalState::new(record));
        let token = state.borrow().approval_token.clone();
        let mut input = Cursor::new(b"approve a1b2c3d4\n".to_vec());
        let mut diagnostic = Vec::new();
        let mut output = Vec::new();

        super::run_interactive_with(
            &nonce,
            "a1b2c3d4",
            &mut input,
            &mut diagnostic,
            &mut output,
            |nonce| state.borrow_mut().inspect(nonce),
            |nonce| state.borrow_mut().approve(nonce),
        )
        .unwrap();

        let diagnostic = String::from_utf8(diagnostic).unwrap();
        assert!(diagnostic.contains("Tool:       phantom_rotate"));
        assert!(diagnostic.contains("Project:    \"test-project\""));
        assert!(diagnostic.contains("Effect:     Remap all managed local placeholders."));
        assert!(diagnostic.contains("Parameters: {\"confirm\":true}"));
        assert!(diagnostic.contains("same-user shell"));
        assert_eq!(
            String::from_utf8(output).unwrap(),
            format!(
                "Approved: phantom_rotate\napproval_token: \"{nonce}:{token}\"\n\
                This token is single-use, short-lived, and bound to the reviewed parameters.\n"
            )
        );
        let state = state.into_inner();
        assert!(state.inspected);
        assert!(state.approved);
        assert!(state.pending.is_none());
    }

    #[test]
    fn wrong_challenge_never_confirms_review() {
        let record = reviewed_record();
        let nonce = record.nonce.clone();
        let state = RefCell::new(FakeApprovalState::new(record));
        let mut input = Cursor::new(b"approve wrong\n".to_vec());
        let mut diagnostic = Vec::new();
        let mut output = Vec::new();

        let error = super::run_interactive_with(
            &nonce,
            "a1b2c3d4",
            &mut input,
            &mut diagnostic,
            &mut output,
            |nonce| state.borrow_mut().inspect(nonce),
            |nonce| state.borrow_mut().approve(nonce),
        )
        .unwrap_err()
        .to_string();

        assert!(error.contains("cancelled"));
        assert!(!diagnostic.is_empty());
        assert!(output.is_empty());
        let state = state.into_inner();
        assert!(state.inspected);
        assert!(!state.approved);
        assert!(state.pending.is_some());
    }

    #[test]
    fn oversized_challenge_response_is_bounded_and_never_confirms_review() {
        let record = reviewed_record();
        let nonce = record.nonce.clone();
        let state = RefCell::new(FakeApprovalState::new(record));
        let expected = "approve a1b2c3d4";
        let mut payload = format!("{expected}{}\n", "X".repeat(64 * 1024)).into_bytes();
        payload.extend_from_slice(b"unread sentinel");
        let mut input = Cursor::new(payload);
        let mut diagnostic = Vec::new();
        let mut output = Vec::new();
        let error = super::run_interactive_with(
            &nonce,
            "a1b2c3d4",
            &mut input,
            &mut diagnostic,
            &mut output,
            |nonce| state.borrow_mut().inspect(nonce),
            |nonce| state.borrow_mut().approve(nonce),
        )
        .unwrap_err()
        .to_string();

        assert!(error.contains("cancelled"));
        assert!(input.position() <= (expected.len() + 2) as u64);
        assert!(output.is_empty());
        let state = state.into_inner();
        assert!(state.inspected);
        assert!(!state.approved);
        assert!(state.pending.is_some());
    }

    #[test]
    fn test_run_rejects_empty_nonce() {
        let result = super::run("   ");
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("Usage"), "expected usage hint, got: {msg}");
    }
}
