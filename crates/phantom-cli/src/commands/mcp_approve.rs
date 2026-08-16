//! `phantom mcp-approve <NONCE>` — out-of-band approval for MCP mutating tools.
//!
//! The user runs this command in a trusted terminal after the MCP server prints
//! a nonce to stderr. It verifies the nonce is pending and unexpired, marks it
//! approved in `~/.phantom/mcp-approvals.jsonl`, and prints the approval token.
//!
//! The approval token must be passed as `approval_token: "<nonce>:<token>"` in
//! the next call to the same MCP tool.

use anyhow::Result;
use phantom_core::mcp_approval;

/// Run `phantom mcp-approve <nonce>`.
pub fn run(nonce: &str) -> Result<()> {
    let nonce = nonce.trim();
    if nonce.is_empty() {
        anyhow::bail!(
            "Usage: phantom mcp-approve <NONCE>\n\
            The NONCE is printed to stderr by the MCP server when a mutating \
            tool is called without a valid approval token."
        );
    }

    println!("Verifying nonce: {nonce}");

    match mcp_approval::approve_nonce(nonce) {
        Ok(outcome) => {
            println!();
            println!("Approved: {}", outcome.tool_name);
            println!();
            println!("Pass this approval_token in the MCP tool call:");
            println!("  approval_token: \"{}:{}\"", nonce, outcome.approval_token);
            println!();
            println!("The token is single-use and bound to the exact parameters");
            println!("that were hashed when the nonce was generated.");
            Ok(())
        }
        Err(e) => {
            anyhow::bail!("Approval failed: {e}");
        }
    }
}

#[cfg(test)]
mod tests {
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
    fn test_run_approves_valid_nonce() {
        with_temp_home(|| {
            let nonce = mcp_approval::generate_pending_approval(
                "phantom_rotate",
                r#"{"confirm":true}"#,
                "test-project",
            )
            .unwrap();

            // The CLI run() function should succeed.
            super::run(&nonce).unwrap();
        });
    }

    #[test]
    fn test_run_rejects_empty_nonce() {
        let result = super::run("   ");
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("Usage"), "expected usage hint, got: {msg}");
    }

    #[test]
    fn test_run_rejects_unknown_nonce() {
        with_temp_home(|| {
            // No approvals file exists yet.
            let result =
                super::run("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
            assert!(result.is_err());
        });
    }
}
