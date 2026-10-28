// ── Error helpers ───────────────────────────────────────────────────

use rmcp::{model::CallToolResult, model::ContentBlock, ErrorData as McpError};

const MCP_EFFECTS_ENV: &str = "PHANTOM_MCP_EFFECTS";
const TRUSTED_TERMINAL_MODE: &str = "trusted-terminal";

fn effect_execution_enabled(value: Option<&str>) -> bool {
    value == Some(TRUSTED_TERMINAL_MODE)
}

/// Whether `require_approval_token` would get past its effects gate. Value-
/// blind preflights call this first so a disabled server still answers with
/// "disabled by default" and never opens the vault.
pub fn mcp_effects_enabled() -> bool {
    #[cfg(test)]
    if std::env::var("PHANTOM_MCP_SKIP_APPROVAL").as_deref() == Ok("1") {
        return true;
    }
    effect_execution_enabled(std::env::var(MCP_EFFECTS_ENV).ok().as_deref())
}

/// Refuse recognizable credentials even when accidentally pasted into a
/// metadata field. Reuse the public-env value rules so hashes, plan IDs, and
/// approval tokens are not mistaken for secrets by the entropy heuristic.
/// This is admission hygiene, not a substitute for value-free result DTOs.
pub fn credential_shaped_input(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::String(text) => {
            let mut entry = phantom_core::dotenv::EnvEntry {
                key: "NEXT_PUBLIC_MCP_ARGUMENT".to_string(),
                value: text.clone(),
                is_phantom: false,
            };
            let classified = phantom_core::dotenv::classify_with_reason(&entry).0
                == phantom_core::dotenv::SecretClassification::Secret;
            zeroize::Zeroize::zeroize(&mut entry.value);
            classified
                || phantom_core::token::PhantomToken::is_phantom_token(text)
                || text.starts_with("eyJ")
        }
        serde_json::Value::Array(items) => items.iter().any(credential_shaped_input),
        serde_json::Value::Object(fields) => fields.iter().any(|(key, value)| {
            credential_shaped_input(&serde_json::Value::String(key.clone()))
                || credential_shaped_input(value)
        }),
        _ => false,
    }
}

/// Serde diagnostics may quote arbitrary strings from decrypted vault data,
/// persisted metadata, or rejected input. Preserve error codes and the data
/// shape around a failure, but never pass these diagnostics to the agent.
/// This is not a secret-pattern filter: opaque values are equally protected.
fn value_blind_diagnostic(message: String) -> String {
    const INPUT_BEARING_DIAGNOSTICS: &[&str] = &[
        "invalid type:",
        "invalid value:",
        "unknown variant ",
        "unknown field ",
        "missing field ",
        "Corrupt vault data:",
    ];
    if INPUT_BEARING_DIAGNOSTICS
        .iter()
        .any(|prefix| message.contains(prefix))
    {
        "Stored or submitted data could not be decoded. Diagnostic contents withheld; inspect the source in a trusted terminal.".to_string()
    } else {
        message
    }
}

fn value_blind_report(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::String(text) => {
            *text = value_blind_diagnostic(std::mem::take(text));
        }
        serde_json::Value::Array(items) => items.iter_mut().for_each(value_blind_report),
        serde_json::Value::Object(fields) => fields.values_mut().for_each(value_blind_report),
        _ => {}
    }
}

pub fn internal_err(msg: impl Into<String>) -> McpError {
    McpError::new(
        rmcp::model::ErrorCode::INTERNAL_ERROR,
        value_blind_diagnostic(msg.into()),
        None,
    )
}

pub fn invalid_params_err(msg: impl Into<String>) -> McpError {
    McpError::new(
        rmcp::model::ErrorCode::INVALID_PARAMS,
        value_blind_diagnostic(msg.into()),
        None,
    )
}

/// The call is well formed, but the project is not in a state to serve it:
/// not initialized, config unreadable, vault locked or undecryptable, not
/// logged in. The user can fix each of these, and the message names how.
/// INTERNAL_ERROR (-32603) would tell the client the server itself failed.
pub fn state_err(msg: impl Into<String>) -> McpError {
    McpError::new(
        rmcp::model::ErrorCode::INVALID_REQUEST,
        value_blind_diagnostic(msg.into()),
        None,
    )
}

/// `enforce_rotation_on_access` for MCP paths that hand a real vault value out
/// (a copy into another project, a team-vault push): the same decision and
/// wording as `phantom exec`/`start`, judged per exact vault entry before any
/// value is read. A blocked secret is a project state the user fixes (rotate,
/// then replace from a trusted terminal); an unreadable schedule or metadata
/// refuses too. Messages carry names only.
pub fn enforce_rotation_on_entries<'e>(
    config: &phantom_core::config::PhantomConfig,
    vault: &dyn phantom_vault::VaultBackend,
    entries: impl IntoIterator<Item = &'e str>,
    action: &str,
    now_secs: u64,
) -> Result<(), McpError> {
    enforce_rotation_targets(
        config,
        vault,
        phantom_vault::rotation_gate::entry_targets(entries),
        action,
        now_secs,
    )
}

/// Refuse an MCP path that hands real values to new places (a team-vault or
/// cloud push) when any entry was demoted to read-only by the expiry policy:
/// the recipients would inject it at runtime, which the demotion exists to
/// stop. Metadata that cannot be read refuses too. Messages carry names only.
/// The decision is [`phantom_vault::rotation_gate::read_only_refusal`], shared
/// with the CLI.
pub fn refuse_read_only_entries<'e>(
    vault: &dyn phantom_vault::VaultBackend,
    entries: impl IntoIterator<Item = &'e str>,
    action: &str,
) -> Result<(), McpError> {
    match phantom_vault::rotation_gate::read_only_refusal(
        vault,
        entries,
        action,
        "Rotate or promote them first.",
    ) {
        Some(refusal) => Err(state_err(format!(
            "{refusal} No vault plaintext was read and no network request was sent."
        ))),
        None => Ok(()),
    }
}

/// The same gate for MCP paths that write values of unknown age into the
/// vault (a cloud or team vault pull): the incoming value carries no rotation anchor, so a
/// new entry would look fresh and an overwrite would inherit the local
/// anchor. Every written entry whose secret enforces rotation is refused.
pub fn enforce_rotation_on_restore<'e>(
    config: &phantom_core::config::PhantomConfig,
    vault: &dyn phantom_vault::VaultBackend,
    entries: impl IntoIterator<Item = &'e str>,
    action: &str,
    now_secs: u64,
) -> Result<(), McpError> {
    enforce_rotation_targets(
        config,
        vault,
        phantom_vault::rotation_gate::restore_targets(entries),
        action,
        now_secs,
    )
}

fn enforce_rotation_targets(
    config: &phantom_core::config::PhantomConfig,
    vault: &dyn phantom_vault::VaultBackend,
    targets: Vec<phantom_vault::rotation_gate::GateTarget>,
    action: &str,
    now_secs: u64,
) -> Result<(), McpError> {
    use phantom_vault::rotation_gate::{refusal_summary, rotation_refusals, RotationGateError};
    let refusals = rotation_refusals(config, vault, targets, now_secs).map_err(|error| {
        let cause = match &error {
            RotationGateError::Schedule(source) => source.to_string(),
            RotationGateError::Metadata { source, .. } => source.to_string(),
        };
        state_err(format!("Refusing to {action}: {error}: {cause}"))
    })?;
    match refusal_summary(action, &refusals) {
        Some(summary) => Err(state_err(summary)),
        None => Ok(()),
    }
}

/// The next step before `phantom init`, shared with the listing tools.
pub const NOT_INITIALIZED_NEXT_STEP: &str = "Phantom is not initialized in this project. Ask the \
     user to run `phantom init` in a trusted terminal (or call phantom_init with confirm plus \
     approval); phantom_why shows what init would protect.";

pub fn not_initialized_err() -> McpError {
    state_err(NOT_INITIALIZED_NEXT_STEP)
}

/// `.phantom.toml` exists but cannot be loaded.
pub fn config_invalid_err(error: impl std::fmt::Display) -> McpError {
    state_err(format!(
        "Failed to load config: {error}. Next step: run phantom_doctor (it does not open the \
         vault) to see the failing check, then fix .phantom.toml and retry."
    ))
}

/// A vault read failed. A decryption failure is a wrong
/// PHANTOM_VAULT_PASSPHRASE in this server's environment or a corrupt vault
/// file; the user can act on either, so both next steps are named. Anything
/// else stays an internal error.
pub fn vault_read_err(context: &str, error: impl std::fmt::Display) -> McpError {
    let detail = error.to_string();
    if detail.contains("Decryption failed") {
        return state_err(format!(
            "{context}: the encrypted-file vault could not be decrypted: either a wrong \
             passphrase or a corrupt vault file. Wrong passphrase: set \
             PHANTOM_VAULT_PASSPHRASE in the MCP server's env config to the passphrase the \
             secrets were stored with (the one `phantom` uses in the user's terminal), then \
             restart the MCP server. Corrupt vault file: ask the user to run `phantom doctor` \
             in a trusted terminal, then restore the secrets from an encrypted backup \
             (`phantom import <FILE>`) or a cloud copy (`phantom cloud pull`)."
        ));
    }
    internal_err(format!("{context}: {detail}"))
}

/// Output format accepted by the audit export tools.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditFormat {
    Json,
    Csv,
}

/// Parse an audit export `format` parameter: "json" or "csv", ignoring ASCII
/// case. Anything else is an invalid-params error naming the accepted values.
pub fn parse_audit_format(format: &str) -> Result<AuditFormat, McpError> {
    if format.eq_ignore_ascii_case("json") {
        Ok(AuditFormat::Json)
    } else if format.eq_ignore_ascii_case("csv") {
        Ok(AuditFormat::Csv)
    } else {
        Err(invalid_params_err("Invalid format. Use: json or csv"))
    }
}

/// Normalize an anomaly-score threshold parameter with the rule every audit
/// tool and `phantom audit` command shares
/// ([`phantom_core::analytics::score_threshold`]): clamp to 0.0..=1.0 and
/// refuse NaN with an invalid-params error naming the parameter.
pub fn score_threshold_param(param: &str, value: f64) -> Result<f64, McpError> {
    phantom_core::analytics::score_threshold(value)
        .map_err(|error| invalid_params_err(format!("Invalid {param}: {error}")))
}

pub fn require_confirm(tool: &str, confirm: bool) -> Result<(), McpError> {
    if confirm {
        return Ok(());
    }
    Err(invalid_params_err(format!(
        "{tool} is effectful: it changes the vault or project files, or sends a \
         stored credential to a provider (even to read). Ask the user for explicit \
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

    // Unit tests can bypass the external terminal ceremony. This branch is
    // compiled out of production builds, so an agent cannot weaken approval
    // by setting an environment variable at runtime.
    #[cfg(test)]
    if std::env::var("PHANTOM_MCP_SKIP_APPROVAL").as_deref() == Ok("1") {
        return Ok(());
    }

    if !effect_execution_enabled(std::env::var(MCP_EFFECTS_ENV).ok().as_deref()) {
        return Err(invalid_params_err(format!(
            "{tool_name} is disabled by default. Effectful MCP tools may run only when the \
             operator sets {MCP_EFFECTS_ENV}={TRUSTED_TERMINAL_MODE} in a server environment \
             the requesting agent cannot modify, and `phantom mcp-approve` plus \
             ~/.phantom/mcp-approvals.jsonl are outside that agent's command and file \
             authority. A same-user shell or agent-controlled PTY can defeat the terminal \
             ceremony; leave effects disabled when that separation cannot be guaranteed. \
             Once enabled, each call also needs out-of-band approval: the operator must \
             approve it in their own trusted terminal and supply the resulting \
             `approval_token`. See docs/claude-code.md (Effectful tools)."
        )));
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
                Err(_) => Err(invalid_params_err(
                    "Approval request was rejected before persistence. Parameters must be bounded, value-blind JSON; check approval storage in a trusted terminal.",
                )),
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
            .map_err(|error| invalid_params_err(approval_failure_summary(&error)))
        }
    }
}

/// Approval storage is untrusted input, including serde failures and persisted
/// tool/project names. Keep useful refusal classes without reflecting it.
fn approval_failure_summary(error: &str) -> &'static str {
    if error.contains("expired") || error.contains("consumed") || error.contains("not found") {
        "Approval expired, consumed, or not found. Request fresh out-of-band approval."
    } else if error.contains("parameter mismatch") {
        "Approval parameter mismatch. Request fresh out-of-band approval for the exact parameters."
    } else if error.contains("has not been approved") {
        "Approval has not been approved yet. Use a trusted terminal outside agent authority."
    } else {
        "Approval verification failed. Check the exact tool, project, and parameters; request fresh out-of-band approval."
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
    Ok(CallToolResult::success(vec![ContentBlock::text(
        value_blind_diagnostic(msg.into()),
    )]))
}

/// A diagnostic result for agents: the existing human summary stays the first
/// text block, the value-blind report follows as serialized JSON text, and the
/// same report is attached as MCP `structuredContent`.
pub fn report_result(
    summary: impl Into<String>,
    report: &impl serde::Serialize,
) -> Result<CallToolResult, McpError> {
    let mut value = serde_json::to_value(report)
        .map_err(|error| internal_err(format!("Serialization error: {error}")))?;
    value_blind_report(&mut value);
    let json = serde_json::to_string_pretty(&value)
        .map_err(|error| internal_err(format!("Serialization error: {error}")))?;
    let mut result = CallToolResult::success(vec![
        ContentBlock::text(value_blind_diagnostic(summary.into())),
        ContentBlock::text(json),
    ]);
    result.structured_content = Some(value);
    Ok(result)
}

/// A tool whose whole answer is already a JSON object: keep the pretty JSON
/// as the only text block (existing clients parse it) and attach the same
/// object as MCP `structuredContent`.
pub fn json_object_result(report: &impl serde::Serialize) -> Result<CallToolResult, McpError> {
    let mut value = serde_json::to_value(report)
        .map_err(|error| internal_err(format!("Serialization error: {error}")))?;
    value_blind_report(&mut value);
    let json = serde_json::to_string_pretty(&value)
        .map_err(|error| internal_err(format!("Serialization error: {error}")))?;
    let mut result = CallToolResult::success(vec![ContentBlock::text(json)]);
    if value.is_object() {
        result.structured_content = Some(value);
    }
    Ok(result)
}

/// Vault construction failed. Tell the agent what to do next instead of
/// surfacing a bare backend error.
pub fn vault_init_err(error: impl std::fmt::Display) -> McpError {
    internal_err(format!(
        "Failed to initialize vault: {error}. Next step: ask the user to run \
         `phantom doctor` in a trusted terminal. If no OS keychain is available \
         (headless Linux, CI), the operator can set PHANTOM_VAULT_PASSPHRASE in the \
         MCP server environment to use the encrypted-file vault. Repository-only \
         tools (phantom_status, phantom_doctor, phantom_check) still work."
    ))
}

#[cfg(test)]
mod tests {
    use super::{
        effect_execution_enabled, extract_nonce, extract_token, json_object_result, require_confirm,
    };

    #[test]
    fn approval_refusals_never_echo_storage_or_submitted_values() {
        let marker = hex::encode(rand::random::<[u8; 24]>());
        for detail in [
            format!("invalid type: string {marker}, expected a boolean"),
            format!("Approval nonce was issued for project '{marker}'"),
            format!("Nonce '{marker}' not found; it may have been consumed"),
            format!("Nonce '{marker}' has not been approved yet"),
        ] {
            assert!(!super::approval_failure_summary(&detail).contains(&marker));
        }
    }

    #[test]
    fn json_object_result_attaches_objects_only() {
        let object = json_object_result(&serde_json::json!({ "count": 1 })).unwrap();
        assert_eq!(object.content.len(), 1);
        assert_eq!(
            object.structured_content,
            Some(serde_json::json!({ "count": 1 }))
        );
        let array = json_object_result(&serde_json::json!([1, 2])).unwrap();
        assert!(array.structured_content.is_none());
    }

    #[test]
    fn effect_execution_requires_exact_operator_mode() {
        assert!(!effect_execution_enabled(None));
        assert!(!effect_execution_enabled(Some("1")));
        assert!(!effect_execution_enabled(Some("TRUSTED-TERMINAL")));
        assert!(!effect_execution_enabled(Some("trusted-terminal ")));
        assert!(effect_execution_enabled(Some("trusted-terminal")));
    }

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

    #[test]
    fn confirm_refusal_does_not_call_a_provider_read_destructive() {
        // The gate also guards reads that send a stored credential to a
        // provider (phantom_cloud_status, phantom_team_list, ...). Calling
        // those "a destructive vault operation" sent agents the wrong signal.
        assert!(require_confirm("phantom_team_list", true).is_ok());
        let message = require_confirm("phantom_team_list", false)
            .unwrap_err()
            .message
            .to_string();
        assert!(message.contains("phantom_team_list"), "{message}");
        assert!(!message.contains("destructive"), "{message}");
        assert!(
            message.contains("sends a stored credential to a provider"),
            "{message}"
        );
        assert!(message.contains("`confirm: true`"), "{message}");
    }

    mod rotation_gate {
        use super::super::enforce_rotation_on_entries;
        use phantom_core::config::{PhantomConfig, SecretOverride};
        use phantom_vault::file::FileVault;
        use phantom_vault::{SecretMetadata, VaultBackend};

        const DAY: u64 = 86_400;
        const NOW: u64 = 1_800_000_000;

        fn enforced_config() -> PhantomConfig {
            let mut config = PhantomConfig::new_with_defaults("mcp-rotation-gate".to_string());
            config.phantom.secrets.insert(
                "API_KEY".to_string(),
                SecretOverride {
                    rotate_every: Some("30d".to_string()),
                    enforce_rotation_on_access: true,
                    ..SecretOverride::default()
                },
            );
            config
        }

        fn vault_with(dir: &tempfile::TempDir, entries: &[(&str, u64)]) -> FileVault {
            let vault = FileVault::new(
                dir.path(),
                "mcp-rotation-gate",
                format!("gate-{}", std::process::id()),
            )
            .expect("file vault");
            for (entry, created_at) in entries {
                vault.store(entry, "placeholder").expect("store");
                vault
                    .set_metadata(
                        entry,
                        SecretMetadata {
                            created_at: Some(*created_at),
                            ..SecretMetadata::default()
                        },
                    )
                    .expect("metadata");
            }
            vault
        }

        #[test]
        fn an_overdue_enforced_entry_is_refused_as_project_state() {
            let dir = tempfile::tempdir().unwrap();
            let vault = vault_with(&dir, &[("API_KEY", NOW - 45 * DAY)]);
            let refused =
                enforce_rotation_on_entries(&enforced_config(), &vault, ["API_KEY"], "copy", NOW);
            let Err(error) = refused else {
                panic!("an overdue enforced secret was let through");
            };
            assert_eq!(error.code, rmcp::model::ErrorCode::INVALID_REQUEST);
            assert!(error
                .message
                .starts_with("Refusing to copy: rotation enforcement blocked 1 secret(s)."));
            assert!(error.message.contains("'API_KEY'"));
            assert!(error.message.contains("phantom remove API_KEY"));
        }

        #[test]
        fn a_fresh_or_unenforced_entry_passes() {
            let dir = tempfile::tempdir().unwrap();
            let vault = vault_with(&dir, &[("API_KEY", NOW - DAY), ("OTHER", NOW - 400 * DAY)]);
            let config = enforced_config();
            assert!(enforce_rotation_on_entries(
                &config,
                &vault,
                ["API_KEY", "OTHER"],
                "copy",
                NOW
            )
            .is_ok());
        }

        #[test]
        fn a_namespaced_entry_is_judged_by_its_own_age() {
            let dir = tempfile::tempdir().unwrap();
            let vault = vault_with(&dir, &[("API_KEY", NOW), ("prod/API_KEY", NOW - 90 * DAY)]);
            let config = enforced_config();
            assert!(enforce_rotation_on_entries(
                &config,
                &vault,
                ["API_KEY", "prod/API_KEY"],
                "push the team vault",
                NOW
            )
            .is_err());
        }
    }
}
