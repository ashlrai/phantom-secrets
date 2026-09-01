//! `phantom mcp-approve <NONCE>` — informed, out-of-band approval for MCP effects.
//!
//! This command deliberately requires an attached terminal. It shows the exact
//! value-blind parameters and bounded effect recorded by the MCP server, then
//! requires a fresh challenge before mutating the pending approval. The terminal
//! and this command must be outside the requesting agent's authority.

use std::io::{BufRead, IsTerminal, Write};

use anyhow::{Context, Result};
use phantom_core::mcp_approval;
use rand::RngCore;

/// Run `phantom mcp-approve <nonce>`.
pub fn run(nonce: &str) -> Result<()> {
    let nonce = nonce.trim();
    if nonce.is_empty() {
        anyhow::bail!(
            "Usage: phantom mcp-approve <NONCE>\n\
            The NONCE is printed to stderr by the MCP server when an effectful \
            tool is called without a valid approval token."
        );
    }

    let stdin = std::io::stdin();
    let mut stderr = std::io::stderr();
    if !stdin.is_terminal() || !stderr.is_terminal() {
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
    let mut reader = std::io::BufReader::new(stdin.lock());
    let mut stdout = std::io::stdout();
    run_interactive(nonce, &challenge, &mut reader, &mut stderr, &mut stdout)
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
    input.read_line(&mut response)?;
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
    use std::io::Cursor;

    use phantom_core::mcp_approval;
    use tempfile::TempDir;

    fn with_temp_home<F: FnOnce()>(f: F) {
        let dir = TempDir::new().unwrap();
        let _guard = crate::test_support::ENV_LOCK
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let prev = std::env::var("HOME").ok();
        std::env::set_var("HOME", dir.path());
        f();
        match prev {
            Some(p) => std::env::set_var("HOME", p),
            None => std::env::remove_var("HOME"),
        }
    }

    #[test]
    fn noninteractive_run_fails_without_approving() {
        with_temp_home(|| {
            let nonce = mcp_approval::generate_pending_approval(
                "phantom_rotate",
                r#"{"confirm":true}"#,
                "test-project",
            )
            .unwrap();

            let error = super::run(&nonce).unwrap_err().to_string();
            assert!(error.contains("interactive terminal"), "{error}");
            assert_eq!(mcp_approval::list_pending_approvals().unwrap().len(), 1);
        });
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
    fn test_run_rejects_empty_nonce() {
        let result = super::run("   ");
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("Usage"), "expected usage hint, got: {msg}");
    }
}
