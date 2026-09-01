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
    // Inspection is read-only. Nothing is approved until after the challenge.
    let record = mcp_approval::inspect_pending_approval(nonce)
        .with_context(|| "Approval inspection failed")?;
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

    let outcome = mcp_approval::approve_nonce(nonce).with_context(|| "Approval failed")?;
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
    use std::io::{BufRead, Cursor, Read};
    use std::sync::mpsc;
    use std::time::Duration;

    use phantom_core::mcp_approval;
    use tempfile::TempDir;

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
        let project = TempDir::new().unwrap();
        let project_path = project.path().to_path_buf();
        let (acquired_rx, contender) = with_temp_home(|| {
            let nonce = mcp_approval::generate_pending_approval(
                "phantom_rotate",
                r#"{"confirm":true}"#,
                "test-project",
            )
            .unwrap();

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
            assert_eq!(mcp_approval::list_pending_approvals().unwrap().len(), 1);
            (acquired_rx, contender)
        });

        acquired_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        contender.join().unwrap();
    }

    #[test]
    fn informed_challenge_approves_exact_record() {
        with_temp_home(|| {
            let nonce = mcp_approval::generate_pending_approval(
                "phantom_rotate",
                r#"{"confirm":true}"#,
                "test-project",
            )
            .unwrap();
            let mut input = Cursor::new(b"approve a1b2c3d4\n".to_vec());
            let mut diagnostic = Vec::new();
            let mut output = Vec::new();

            super::run_interactive(&nonce, "a1b2c3d4", &mut input, &mut diagnostic, &mut output)
                .unwrap();

            let diagnostic = String::from_utf8(diagnostic).unwrap();
            assert!(diagnostic.contains("Tool:       phantom_rotate"));
            assert!(diagnostic.contains("Project:    \"test-project\""));
            assert!(diagnostic.contains("Parameters: {\"confirm\":true}"));
            assert!(diagnostic.contains("same-user shell"));
            let output = String::from_utf8(output).unwrap();
            assert!(output.contains(&format!("approval_token: \"{nonce}:")));
            assert!(mcp_approval::list_pending_approvals().unwrap().is_empty());
        });
    }

    #[test]
    fn wrong_challenge_leaves_request_pending() {
        with_temp_home(|| {
            let nonce = mcp_approval::generate_pending_approval(
                "phantom_remove_secret",
                r#"{"name":"SAFE_NAME","confirm":true}"#,
                "test-project",
            )
            .unwrap();
            let mut input = Cursor::new(b"approve wrong\n".to_vec());
            let mut diagnostic = Vec::new();
            let mut output = Vec::new();

            let error = super::run_interactive(
                &nonce,
                "a1b2c3d4",
                &mut input,
                &mut diagnostic,
                &mut output,
            )
            .unwrap_err()
            .to_string();

            assert!(error.contains("cancelled"));
            assert!(output.is_empty());
            assert_eq!(mcp_approval::list_pending_approvals().unwrap().len(), 1);
        });
    }

    #[test]
    fn oversized_challenge_response_is_bounded_and_leaves_request_pending() {
        with_temp_home(|| {
            let nonce = mcp_approval::generate_pending_approval(
                "phantom_remove_secret",
                r#"{"name":"SAFE_NAME","confirm":true}"#,
                "test-project",
            )
            .unwrap();
            let expected = "approve a1b2c3d4";
            let mut payload = format!("{expected}{}\n", "X".repeat(64 * 1024)).into_bytes();
            payload.extend_from_slice(b"unread sentinel");
            let mut input = Cursor::new(payload);
            let error = super::run_interactive(
                &nonce,
                "a1b2c3d4",
                &mut input,
                &mut Vec::new(),
                &mut Vec::new(),
            )
            .unwrap_err()
            .to_string();

            assert!(error.contains("cancelled"));
            assert!(input.position() <= (expected.len() + 2) as u64);
            assert_eq!(mcp_approval::list_pending_approvals().unwrap().len(), 1);
        });
    }

    #[test]
    fn test_run_rejects_empty_nonce() {
        let result = super::run("   ");
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("Usage"), "expected usage hint, got: {msg}");
    }
}
