// ── Parameter schemas ────────────────────────────────────────────────
//
// All mutating tools include a `confirm: bool` field that defaults to
// false. The MCP server returns INVALID_PARAMS unless the calling agent
// explicitly sets `confirm: true` — defends against prompt-injected
// instructions in project content silently mutating state.
//
// In addition, mutating tools include an optional `approval_token` field.
// When absent, the MCP server generates a nonce and returns INVALID_PARAMS
// instructing the user to run `phantom mcp-approve <NONCE>`.  When present,
// the server validates and consumes the nonce before executing the operation.
// Format: "<nonce_hex>:<approval_token_hex>"  (both produced by mcp-approve).

#[derive(Debug, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
pub struct InitParams {
    /// Path to the .env file (defaults to .env in current directory)
    #[serde(default = "default_env_path")]
    pub env_path: String,
    /// Required. Must be true because init stores secrets and rewrites .env.
    #[serde(default)]
    pub confirm: bool,
    /// Out-of-band approval token from `phantom mcp-approve <NONCE>`.
    /// Format: "<nonce_hex>:<approval_token_hex>".
    #[serde(default)]
    pub approval_token: Option<String>,
}

fn default_env_path() -> String {
    ".env".to_string()
}

#[derive(Debug, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
pub struct AddSecretParams {
    /// Name of the secret (e.g., OPENAI_API_KEY)
    pub name: String,
    /// Required. Must be true — the calling agent must confirm with the user
    /// before invoking this tool. Defends against prompt-injected instructions
    /// in project content (READMEs, issue comments, dependency docs) silently
    /// mutating the vault.
    #[serde(default)]
    pub confirm: bool,
    /// Out-of-band approval token from `phantom mcp-approve <NONCE>`.
    /// Format: "<nonce_hex>:<approval_token_hex>".
    #[serde(default)]
    pub approval_token: Option<String>,
}

#[derive(Debug, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
pub struct AddSecretInteractiveParams {
    /// Name of the secret to add (e.g., OPENAI_API_KEY)
    pub name: String,
    /// Required. Must be true — the calling agent must confirm with the user
    /// before starting an out-of-band terminal flow.
    #[serde(default)]
    pub confirm: bool,
    /// Out-of-band approval token from `phantom mcp-approve <NONCE>`.
    #[serde(default)]
    pub approval_token: Option<String>,
}

#[derive(Debug, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
pub struct RemoveSecretParams {
    /// Name of the secret to remove
    pub name: String,
    /// Required. Must be true — the calling agent must confirm with the user
    /// before invoking this tool. Defends against prompt-injected instructions
    /// deleting secrets.
    #[serde(default)]
    pub confirm: bool,
    /// Out-of-band approval token from `phantom mcp-approve <NONCE>`.
    #[serde(default)]
    pub approval_token: Option<String>,
}

#[derive(Debug, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
pub struct RotateParams {
    /// Required. Must be true — the calling agent must confirm with the user
    /// before invoking this tool. Rotating invalidates every live phantom token
    /// and will break any process that cached the old tokens (e.g. a running
    /// `phantom exec` or dev server) until it picks up the new .env.
    #[serde(default)]
    pub confirm: bool,
    /// Out-of-band approval token from `phantom mcp-approve <NONCE>`.
    #[serde(default)]
    pub approval_token: Option<String>,
}

#[derive(Debug, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
pub struct RotateWithExpiryParams {
    /// Number of days until secrets expire. Each secret gets `expires_at` set to
    /// `now + days_ttl * 86400` and a `rotation_policy` recording the TTL. After
    /// this call, `phantom list --show-expiry` and `phantom doctor --expiry` will
    /// report countdown status and warn when secrets approach expiry.
    pub days_ttl: u64,
    /// Required. Must be true — the calling agent must confirm with the user
    /// before invoking this tool. This rotates all phantom tokens (invalidating
    /// any cached ones) and sets persistent expiry metadata in the vault.
    #[serde(default)]
    pub confirm: bool,
    /// Out-of-band approval token from `phantom mcp-approve <NONCE>`.
    #[serde(default)]
    pub approval_token: Option<String>,
}

#[derive(Debug, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
pub struct ListWithExpiryParams {
    /// Include TTL/expiry status for each secret (countdown, expired flag, etc.)
    #[serde(default = "default_true")]
    pub show_expiry: bool,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
pub struct CloudPushParams {
    /// Required. Must be true — the calling agent must confirm with the user
    /// before invoking this tool. A push overwrites the cloud copy of the
    /// project's vault; damage from a prompt-injected push propagates to every
    /// machine that later pulls.
    #[serde(default)]
    pub confirm: bool,
    /// Out-of-band approval token from `phantom mcp-approve <NONCE>`.
    #[serde(default)]
    pub approval_token: Option<String>,
}

#[derive(Debug, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
pub struct CloudPullParams {
    /// Overwrite existing local secrets (default: false)
    #[serde(default)]
    pub force: bool,
    /// Required. Must be true — the calling agent must confirm with the user
    /// before invoking this tool. A pull writes entries into the local vault
    /// and (with force=true) overwrites existing values.
    #[serde(default)]
    pub confirm: bool,
    /// Out-of-band approval token from `phantom mcp-approve <NONCE>`.
    #[serde(default)]
    pub approval_token: Option<String>,
}

#[derive(Debug, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
pub struct CopySecretParams {
    /// Name of the secret to copy from the current project
    pub name: String,
    /// Path to the target project directory (must be phantom-initialized).
    /// `..` segments are rejected to prevent prompt-injected target-dir
    /// obfuscation; pass the full destination path explicitly.
    pub target_dir: String,
    /// Optional new name for the secret in the target project
    pub rename: Option<String>,
    /// Required. Must be true — the calling agent must confirm with the user
    /// before invoking this tool. Copying writes secrets into another vault,
    /// which an attacker can use as an exfiltration primitive.
    #[serde(default)]
    pub confirm: bool,
    /// Out-of-band approval token from `phantom mcp-approve <NONCE>`.
    #[serde(default)]
    pub approval_token: Option<String>,
}

#[derive(Debug, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
pub struct DoctorParams {
    /// Auto-fix safe issues (install hooks, generate .env.example, etc.)
    #[serde(default)]
    pub fix: bool,
    /// Required when fix=true because files may be created or modified.
    #[serde(default)]
    pub confirm: bool,
    /// Out-of-band approval token from `phantom mcp-approve <NONCE>`. Only
    /// required when fix=true (read-only doctor runs do not need approval).
    #[serde(default)]
    pub approval_token: Option<String>,
}

#[derive(Debug, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
pub struct WhyParams {
    /// Environment variable name to explain
    pub key: String,
}

#[derive(Debug, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
pub struct WrapParams {
    /// Only wrap specific scripts (by name). If empty, uses default heuristic.
    #[serde(default)]
    pub only: Vec<String>,
    /// Skip specific scripts (by name)
    #[serde(default)]
    pub skip: Vec<String>,
    /// Required. Must be true because this modifies package.json.
    #[serde(default)]
    pub confirm: bool,
    /// Out-of-band approval token from `phantom mcp-approve <NONCE>`.
    #[serde(default)]
    pub approval_token: Option<String>,
}

#[derive(Debug, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
pub struct UnwrapParams {
    /// Required. Must be true because this modifies package.json.
    #[serde(default)]
    pub confirm: bool,
    /// Out-of-band approval token from `phantom mcp-approve <NONCE>`.
    #[serde(default)]
    pub approval_token: Option<String>,
}

#[derive(Debug, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
pub struct CheckParams {
    /// Check if phantom tokens are in environment without proxy running
    #[serde(default)]
    pub runtime: bool,
}

#[derive(Debug, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
pub struct EnvParams {
    /// Output file name (defaults to .env.example)
    #[serde(default = "default_example_output")]
    pub output: String,
    /// Required. Must be true because this writes an env example file.
    #[serde(default)]
    pub confirm: bool,
    /// Out-of-band approval token from `phantom mcp-approve <NONCE>`.
    #[serde(default)]
    pub approval_token: Option<String>,
}

fn default_example_output() -> String {
    ".env.example".to_string()
}

#[derive(Debug, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
pub struct SyncParams {
    /// Platform to sync to (vercel, railway). If empty, syncs all configured targets.
    #[serde(default)]
    pub platform: Option<String>,
    /// Override project ID for this sync
    #[serde(default)]
    pub project_id: Option<String>,
}

// ── Team operations ──────────────────────────────────────────────────

#[derive(Debug, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
pub struct TeamCreateParams {
    /// Name for the new team (human-readable label)
    pub name: String,
    /// Required. Must be true — confirms the user wants to create a new
    /// team. Creating a team is a billable Pro action.
    #[serde(default)]
    pub confirm: bool,
    /// Out-of-band approval token from `phantom mcp-approve <NONCE>`.
    #[serde(default)]
    pub approval_token: Option<String>,
}

#[derive(Debug, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
pub struct TeamIdParams {
    /// Team identifier (UUID)
    pub team_id: String,
    /// Required for mutating operations that publish local key material.
    #[serde(default)]
    pub confirm: bool,
    /// Out-of-band approval token from `phantom mcp-approve <NONCE>`.
    #[serde(default)]
    pub approval_token: Option<String>,
}

#[derive(Debug, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
pub struct TeamInviteParams {
    /// Team identifier (UUID)
    pub team_id: String,
    /// GitHub username of the user to invite (no @ prefix)
    pub github_login: String,
    /// Role to assign — "member", "admin", or "owner". Defaults to "member".
    #[serde(default = "default_member_role")]
    pub role: String,
    /// Required. Must be true — confirms the user wants to add this person
    /// to the team. Defends against prompt-injected instructions silently
    /// expanding team membership.
    #[serde(default)]
    pub confirm: bool,
    /// Out-of-band approval token from `phantom mcp-approve <NONCE>`.
    #[serde(default)]
    pub approval_token: Option<String>,
}

fn default_member_role() -> String {
    "member".to_string()
}

#[derive(Debug, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
pub struct TeamVaultParams {
    /// Team identifier (UUID)
    pub team_id: String,
    /// Required. Must be true — push/pull mutates the team's shared vault
    /// (push) or overwrites local secrets with the team copy (pull). Both
    /// are write operations that need user consent.
    #[serde(default)]
    pub confirm: bool,
    /// Out-of-band approval token from `phantom mcp-approve <NONCE>`.
    #[serde(default)]
    pub approval_token: Option<String>,
}

// ── Validation ───────────────────────────────────────────────────────

#[derive(Debug, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
pub struct ValidateSecretParams {
    /// Name of the secret to query validation status for (e.g. OPENAI_API_KEY).
    /// Never the value — this tool only reads stored metadata.
    pub name: String,
}

#[derive(Debug, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
pub struct ValidateAllParams {
    /// Maximum number of concurrent validation jobs (default: 4, max: 16).
    #[serde(default = "default_validate_jobs")]
    pub jobs: usize,
}

fn default_validate_jobs() -> usize {
    4
}

// ── Audit analytics ──────────────────────────────────────────────────

#[derive(Debug, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
pub struct AuditStatsParams {
    /// Time period to analyse: "7d", "30d", or "all". Defaults to "all".
    #[serde(default = "default_audit_period")]
    pub period: String,
    /// Only include secrets whose anomaly score is at or above this threshold
    /// (range 0.0–1.0). Omit or set to 0.0 to return all secrets.
    #[serde(default)]
    pub min_anomaly_score: Option<f64>,
}

fn default_audit_period() -> String {
    "all".to_string()
}

// ── Audit & compliance tools ──────────────────────────────────────────

#[derive(Debug, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
pub struct AuditRecentParams {
    /// Maximum number of recent audit events to return (default: 20, max: 200).
    #[serde(default = "default_audit_recent_n")]
    pub n: usize,
    /// Filter by operation name prefix (e.g. "vault.retrieve", "cloud"). Omit for all ops.
    #[serde(default)]
    pub op_filter: Option<String>,
    /// Filter by secret name (exact match). Omit for all secrets.
    #[serde(default)]
    pub name_filter: Option<String>,
}

fn default_audit_recent_n() -> usize {
    20
}

#[derive(Debug, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
pub struct AuditAnomaliesParams {
    /// Time period to analyse: "7d", "30d", or "all". Defaults to "30d".
    #[serde(default = "default_anomalies_period")]
    pub period: String,
    /// Minimum anomaly score to include (0.0–1.0). Defaults to 0.4.
    #[serde(default = "default_min_anomaly")]
    pub min_score: f64,
}

fn default_anomalies_period() -> String {
    "30d".to_string()
}

fn default_min_anomaly() -> f64 {
    0.4
}

/// Parameters for `phantom_audit_anomalies_realtime` — windowed, per-second
/// rate-based anomaly check against the current audit log state.
#[derive(Debug, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
pub struct AuditAnomaliesRealtimeParams {
    /// Filter to a single secret name. Omit to check all secrets.
    #[serde(default)]
    pub name: Option<String>,
    /// Minimum anomaly score (0.0–1.0) to include in results. Defaults to 0.5.
    #[serde(default = "default_realtime_threshold")]
    pub threshold: f64,
    /// Override: max accesses allowed within any rolling 1-hour window before
    /// flagging a rate spike. Defaults to 100.
    #[serde(default)]
    pub max_accesses_per_hour: Option<u64>,
    /// Override: number of consecutive quiet days after which a re-access
    /// triggers a quiet-period alert. Defaults to 7.
    #[serde(default)]
    pub max_consecutive_quiet_days: Option<u64>,
}

fn default_realtime_threshold() -> f64 {
    0.5
}

// ── Audit analytics (full export) ────────────────────────────────────

/// Parameters for `phantom_audit_analytics` — full analytics + access-record export.
#[derive(Debug, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
pub struct AuditAnalyticsParams {
    /// Time window in days (default: 30). 0 means all available history.
    #[serde(default = "default_analytics_window")]
    pub window_days: u32,
    /// Only include secrets whose anomaly score is at or above this threshold
    /// (range 0.0–1.0). Defaults to 0.0 (return all secrets).
    #[serde(default)]
    pub min_anomaly_score: Option<f64>,
    /// Output format: "json" (default) or "csv".
    #[serde(default = "default_analytics_format")]
    pub format: String,
}

fn default_analytics_window() -> u32 {
    30
}

fn default_analytics_format() -> String {
    "json".to_string()
}

#[derive(Debug, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
pub struct ComplianceStatusParams {
    // No parameters needed — reads project state and global audit state.
}

// ── Leak incident correlation ─────────────────────────────────────────────────

/// Parameters for `phantom_audit_incidents`.
#[derive(Debug, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
pub struct AuditIncidentsParams {
    /// Only return incidents whose confidence score is at or above this value
    /// (range 0.0–1.0). Defaults to 0.7.
    #[serde(default = "default_min_confidence")]
    pub min_confidence: f64,
}

fn default_min_confidence() -> f64 {
    0.7
}

// ── Real-time leak incident dashboard ────────────────────────────────────────

/// Parameters for `phantom_leak_incidents_realtime`.
#[derive(Debug, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
pub struct LeakIncidentsRealtimeParams {
    /// Only return incidents whose confidence score is at or above this value
    /// (range 0.0–1.0). Defaults to 0.5 per spec (active incident threshold).
    #[serde(default = "default_realtime_min_confidence")]
    pub min_confidence: f64,
    /// When true, automatically call `phantom rotate <secret>` for any incident
    /// with confidence >= 0.9 and log the action.
    /// AI agents MUST set `confirm: true` to enable auto-rotate — the approval
    /// gate prevents unattended rotation without explicit user consent.
    #[serde(default)]
    pub auto_rotate_on_high: bool,
    /// Required when `auto_rotate_on_high` is true. The calling agent must
    /// obtain explicit user consent before auto-rotating secrets.
    /// Defends against prompt-injected instructions silently rotating keys.
    #[serde(default)]
    pub confirm: bool,
}

fn default_realtime_min_confidence() -> f64 {
    0.5
}

// ── Leak incident alert records ──────────────────────────────────────────────

/// Parameters for `phantom_audit_alerts`.
#[derive(Debug, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
pub struct AuditAlertsParams {
    /// Maximum number of recent alerts to return (default: 50).
    #[serde(default = "default_alerts_last")]
    pub last: usize,
    /// If true, re-run the leak correlation engine and emit pending alerts
    /// before returning the list. Default: false.
    #[serde(default)]
    pub backfill: bool,
}

fn default_alerts_last() -> usize {
    50
}

// ── Audit export & compliance report ─────────────────────────────────

/// Parameters for `phantom_audit_export_report`.
#[derive(Debug, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
pub struct AuditExportReportParams {
    /// Action: "export" to get raw rows as CSV/JSON, or "report" to get a
    /// full compliance report. Default: "report".
    #[serde(default = "default_export_action")]
    pub action: String,
    /// Output format: "csv" or "json". Default: "json".
    #[serde(default = "default_export_format_for_report")]
    pub format: String,
    /// Start date inclusive (YYYY-MM-DD). Omit for no lower bound.
    #[serde(default)]
    pub from: Option<String>,
    /// End date inclusive (YYYY-MM-DD). Omit for no upper bound.
    #[serde(default)]
    pub to: Option<String>,
    /// Filter rows to this secret name only (exact match). Omit for all secrets.
    #[serde(default)]
    pub secret_name: Option<String>,
    /// Filter rows to operations containing this string. Omit for all ops.
    #[serde(default)]
    pub operation: Option<String>,
    /// Save the compliance report to ~/.phantom/reports/ (report action only).
    #[serde(default)]
    pub save: bool,
}

fn default_export_action() -> String {
    "report".to_string()
}

fn default_export_format_for_report() -> String {
    "json".to_string()
}

// ── Validation scheduler ──────────────────────────────────────────────

/// Parameters for `phantom_validation_schedule` (get/set schedule).
#[derive(Debug, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
pub struct ValidationScheduleParams {
    /// New schedule interval to set: "hourly", "6h", "daily", "daily@2am",
    /// "weekly", "disabled". Omit to read the current schedule only.
    #[serde(default)]
    pub interval: Option<String>,
}

/// Parameters for `phantom_validation_history`.
#[derive(Debug, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
pub struct ValidationHistoryParams {
    /// Maximum number of recent runs to return (default: 20, max: 100).
    #[serde(default = "default_history_limit")]
    pub limit: usize,
}

fn default_history_limit() -> usize {
    20
}

// ── Shadow rotation ───────────────────────────────────────────────────

/// Parameters for `phantom_rotate_with_candidate`.
#[derive(Debug, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
pub struct RotateWithCandidateParams {
    /// Name of the secret to shadow-rotate (e.g. OPENAI_API_KEY).
    pub name: String,
    /// Optional TTL in seconds after which the candidate automatically expires.
    /// Omit for no automatic expiry (manual promotion only).
    #[serde(default)]
    pub auto_promote_ttl_secs: Option<u64>,
    /// Required. Must be true — creates a candidate credential and stores it
    /// in the vault. The agent must confirm with the user before calling.
    #[serde(default)]
    pub confirm: bool,
    /// Out-of-band approval token from `phantom mcp-approve <NONCE>`.
    #[serde(default)]
    pub approval_token: Option<String>,
}

/// Parameters for `phantom_rotate_promote`.
#[derive(Debug, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
pub struct RotatePromoteParams {
    /// Name of the secret whose shadow candidate should be promoted
    /// (e.g. OPENAI_API_KEY).
    pub name: String,
    /// Required. Must be true — promotes the candidate to primary, atomically
    /// replacing the current live credential. The agent must confirm with the
    /// user before calling.
    #[serde(default)]
    pub confirm: bool,
    /// Out-of-band approval token from `phantom mcp-approve <NONCE>`.
    #[serde(default)]
    pub approval_token: Option<String>,
}

#[derive(Debug, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
pub struct RotationDueParams {
    /// Warn when expiry is within this many days. Defaults to 7.
    #[serde(default = "default_warn_days")]
    pub warn_days: u64,
}

fn default_warn_days() -> u64 {
    7
}

// ── Expiry check & auto-rotate ────────────────────────────────────────

/// Parameters for `phantom_secrets_expiry_check`.
#[derive(Debug, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
pub struct ExpiryCheckParams {
    /// Warn about secrets expiring within this many days (default: 7).
    /// Set to 0 to return only already-expired secrets.
    #[serde(default = "default_warn_days")]
    pub days: u64,
}

// ── Per-secret rotation schedule & expiry policy ──────────────────────

/// Parameters for `phantom_rotation_schedule_next`.
///
/// Returns the next scheduled rotation time (ISO-8601 + Unix epoch) for a
/// named secret, based on its effective `RotationSchedule`.  Read-only; no
/// confirm required.
#[derive(Debug, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
pub struct RotationScheduleNextParams {
    /// Name of the secret to query (e.g. `OPENAI_API_KEY`).
    pub name: String,
}

/// Parameters for `phantom_apply_expiry_policy`.
///
/// Scans the vault, identifies secrets whose TTL has expired, sets
/// `vault_mode = ReadOnly` on each, and returns a list of affected secrets.
/// This is the "demotion" step that prevents stale credentials from being
/// injected by `phantom exec`.
///
/// Requires `confirm: true` because it writes metadata.
#[derive(Debug, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
pub struct ApplyExpiryPolicyParams {
    /// Must be `true`.  The caller must obtain user consent before demoting
    /// secrets to read-only mode, as it will break any running process that
    /// relies on those secrets being injected by `phantom exec`.
    #[serde(default)]
    pub confirm: bool,
    /// Out-of-band approval token from `phantom mcp-approve <NONCE>`.
    #[serde(default)]
    pub approval_token: Option<String>,
    /// When `true`, also promote secrets that were previously demoted but have
    /// since been rotated (vault_mode ReadOnly → ReadWrite if `rotated_at` is
    /// more recent than `expires_at`).  Default: `true`.
    #[serde(default = "default_true_flag")]
    pub also_promote_rotated: bool,
}

fn default_true_flag() -> bool {
    true
}

/// Parameters for `phantom_secrets_auto_rotate`.
#[derive(Debug, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
pub struct AutoRotateParams {
    /// Name of the secret to auto-rotate.
    pub name: String,
    /// If true, sync to all configured deployment platforms after rotation.
    #[serde(default)]
    pub sync: bool,
    /// Required. Must be true — the calling agent must confirm with the user
    /// before rotating credentials. Auto-rotation updates metadata and
    /// rewrites phantom tokens; an attacker-injected call could disrupt
    /// running services that cached the old token.
    #[serde(default)]
    pub confirm: bool,
    /// Out-of-band approval token from `phantom mcp-approve <NONCE>`.
    #[serde(default)]
    pub approval_token: Option<String>,
}

// ── Expiry enforcement ────────────────────────────────────────────────────────

/// Parameters for `phantom_expiry_enforce`.
#[derive(Debug, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
pub struct PhantomExpiryEnforceParams {
    /// If true, also treat secrets with no expiry policy as violations.
    /// Defaults to false (permissive: only hard-expired secrets are reported).
    #[serde(default)]
    pub fail_closed: bool,
}

// ── Provider-specific rotation ────────────────────────────────────────────────

/// Parameters for `phantom_rotate_provider`.
///
/// Calls a vendor-specific rotation provider (Stripe, GitHub, AWS) to
/// re-issue the credential server-side and stores the new value in the vault.
/// The secret value is NEVER exposed in the MCP response — only status,
/// provider name, and audit metadata are returned.
#[derive(Debug, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
pub struct RotateProviderParams {
    /// Name of the secret to rotate (e.g. `STRIPE_SECRET_KEY`).
    pub name: String,
    /// Which provider to use: `"stripe"`, `"github"`, or `"aws"`.
    /// Must match the `provider` field in the secret's
    /// `[phantom.secrets.{name}.rotation_provider]` config block.
    pub provider: String,
    /// Required. Must be `true` — the calling agent must confirm with the
    /// user before rotating a live credential. Vendor rotation calls
    /// external APIs and permanently invalidates the current key.
    #[serde(default)]
    pub confirm: bool,
    /// Out-of-band approval token from `phantom mcp-approve <NONCE>`.
    /// Format: `"<nonce_hex>:<approval_token_hex>"`.
    #[serde(default)]
    pub approval_token: Option<String>,
}
