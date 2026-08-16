// ── Error helpers ───────────────────────────────────────────────────

use rmcp::{model::CallToolResult, model::Content, ErrorData as McpError};

pub fn internal_err(msg: impl Into<String>) -> McpError {
    McpError::new(rmcp::model::ErrorCode::INTERNAL_ERROR, msg.into(), None)
}

pub fn invalid_params_err(msg: impl Into<String>) -> McpError {
    McpError::new(rmcp::model::ErrorCode::INVALID_PARAMS, msg.into(), None)
}

pub fn require_confirm(tool: &str, confirm: bool) -> Result<(), McpError> {
    if confirm {
        return Ok(());
    }
    Err(invalid_params_err(format!(
        "{tool} is a destructive vault operation. Ask the user for explicit \
         confirmation, then retry the call with `confirm: true`. This gate \
         exists to prevent prompt-injected content (READMEs, issue comments, \
         dependency docs) from silently mutating or exfiltrating secrets."
    )))
}

/// Validate a nonce-based approval token for a mutating MCP tool.
///
/// If no approval token is present, generate a fresh pending nonce, print it
/// to stderr so the human can run `phantom mcp-approve <NONCE>`, and return
/// an INVALID_PARAMS error instructing the agent to retry with `approval_token`.
///
/// If an approval token is present, validate and consume it (replay-proof).
///
/// `params_json` must be the canonical JSON representation of the tool
/// parameters so the arg-hash can be verified.
pub fn require_approval_token(
    tool_name: &str,
    approval_token: Option<&str>,
    params_json: &str,
    project_id: &str,
) -> Result<(), McpError> {
    use phantom_core::mcp_approval;

    // Allow tests and CI to skip approval by setting PHANTOM_MCP_SKIP_APPROVAL=1.
    // Never set this in production.
    if std::env::var("PHANTOM_MCP_SKIP_APPROVAL").as_deref() == Ok("1") {
        return Ok(());
    }

    match approval_token {
        None | Some("") => {
            // Generate a nonce and surface it to the operator via stderr.
            match mcp_approval::generate_pending_approval(tool_name, params_json, project_id) {
                Ok(nonce) => {
                    eprintln!(
                        "[phantom-mcp] APPROVAL REQUIRED for {tool_name}\n\
                         Run in a trusted terminal:\n\
                         \n\
                         \x1b[1m  phantom mcp-approve {nonce}\x1b[0m\n\
                         \n\
                         Then retry the MCP call with the returned approval_token."
                    );
                    Err(invalid_params_err(format!(
                        "{tool_name} requires out-of-band approval. A nonce has been \
                         printed to the MCP server's stderr. Run `phantom mcp-approve \
                         <NONCE>` in a trusted terminal, then retry with \
                         `approval_token: \"<nonce>:<token>\"`."
                    )))
                }
                Err(e) => Err(internal_err(format!(
                    "Failed to generate approval nonce: {e}"
                ))),
            }
        }
        Some(token) => {
            mcp_approval::validate_and_consume_approval(
                // The nonce is embedded as the first 64 hex chars of the token field
                // if callers pass "nonce:token". We support two call conventions:
                //   1. approval_token = "<nonce_hex>:<approval_token_hex>"  (preferred)
                //   2. approval_token = "<approval_token_hex>" + nonce via approval_nonce field
                // For simplicity we use convention 1: "nonce:token".
                &extract_nonce(token),
                &extract_token(token),
                tool_name,
                params_json,
                project_id,
            )
            .map_err(invalid_params_err)
        }
    }
}

/// Extract the nonce from a combined `"<nonce>:<token>"` approval_token field.
/// If the token has no colon separator, treat the whole string as the token
/// (backwards-compat; will fail validation gracefully).
fn extract_nonce(combined: &str) -> String {
    combined.split(':').next().unwrap_or(combined).to_string()
}

/// Extract the HMAC token from a combined `"<nonce>:<token>"` field.
fn extract_token(combined: &str) -> String {
    combined
        .split_once(':')
        .map(|(_, token)| token)
        .unwrap_or(combined)
        .to_string()
}

pub fn text_result(msg: impl Into<String>) -> Result<CallToolResult, McpError> {
    Ok(CallToolResult::success(vec![Content::text(msg.into())]))
}

#[cfg(test)]
mod tests {
    use super::{extract_nonce, extract_token};

    #[test]
    fn parses_combined_approval_token() {
        let combined = "noncehex:tokenhex";

        assert_eq!(extract_nonce(combined), "noncehex");
        assert_eq!(extract_token(combined), "tokenhex");
    }

    #[test]
    fn bare_approval_token_falls_back_to_same_value() {
        let token = "tokenhex";

        assert_eq!(extract_nonce(token), "tokenhex");
        assert_eq!(extract_token(token), "tokenhex");
    }
}
