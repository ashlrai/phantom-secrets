// ── Parameter schemas ────────────────────────────────────────────────
//
// All mutating tools include a `confirm: bool` field that defaults to
// false. The MCP server returns INVALID_PARAMS unless the calling agent
// explicitly sets `confirm: true` — defends against prompt-injected
// instructions in project content silently mutating state.

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct InitParams {
    /// Path to the .env file (defaults to .env in current directory)
    #[serde(default = "default_env_path")]
    pub env_path: String,
    /// Required. Must be true because init stores secrets and rewrites .env.
    #[serde(default)]
    pub confirm: bool,
}

fn default_env_path() -> String {
    ".env".to_string()
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AddSecretParams {
    /// Name of the secret (e.g., OPENAI_API_KEY)
    pub name: String,
    /// Required. Must be true — the calling agent must confirm with the user
    /// before invoking this tool. Defends against prompt-injected instructions
    /// in project content (READMEs, issue comments, dependency docs) silently
    /// mutating the vault.
    #[serde(default)]
    pub confirm: bool,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct AddSecretInteractiveParams {
    /// Name of the secret to add (e.g., OPENAI_API_KEY)
    pub name: String,
    /// Required. Must be true — the calling agent must confirm with the user
    /// before starting an out-of-band terminal flow.
    #[serde(default)]
    pub confirm: bool,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct RemoveSecretParams {
    /// Name of the secret to remove
    pub name: String,
    /// Required. Must be true — the calling agent must confirm with the user
    /// before invoking this tool. Defends against prompt-injected instructions
    /// deleting secrets.
    #[serde(default)]
    pub confirm: bool,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct RotateParams {
    /// Required. Must be true — the calling agent must confirm with the user
    /// before invoking this tool. Rotating invalidates every live phantom token
    /// and will break any process that cached the old tokens (e.g. a running
    /// `phantom exec` or dev server) until it picks up the new .env.
    #[serde(default)]
    pub confirm: bool,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
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
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct ListWithExpiryParams {
    /// Include TTL/expiry status for each secret (countdown, expired flag, etc.)
    #[serde(default = "default_true")]
    pub show_expiry: bool,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct CloudPushParams {
    /// Required. Must be true — the calling agent must confirm with the user
    /// before invoking this tool. A push overwrites the cloud copy of the
    /// project's vault; damage from a prompt-injected push propagates to every
    /// machine that later pulls.
    #[serde(default)]
    pub confirm: bool,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct CloudPullParams {
    /// Overwrite existing local secrets (default: false)
    #[serde(default)]
    pub force: bool,
    /// Required. Must be true — the calling agent must confirm with the user
    /// before invoking this tool. A pull writes entries into the local vault
    /// and (with force=true) overwrites existing values.
    #[serde(default)]
    pub confirm: bool,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
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
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct DoctorParams {
    /// Auto-fix safe issues (install hooks, generate .env.example, etc.)
    #[serde(default)]
    pub fix: bool,
    /// Required when fix=true because files may be created or modified.
    #[serde(default)]
    pub confirm: bool,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct WhyParams {
    /// Environment variable name to explain
    pub key: String,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
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
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct UnwrapParams {
    /// Required. Must be true because this modifies package.json.
    #[serde(default)]
    pub confirm: bool,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct CheckParams {
    /// Check if phantom tokens are in environment without proxy running
    #[serde(default)]
    pub runtime: bool,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct EnvParams {
    /// Output file name (defaults to .env.example)
    #[serde(default = "default_example_output")]
    pub output: String,
    /// Required. Must be true because this writes an env example file.
    #[serde(default)]
    pub confirm: bool,
}

fn default_example_output() -> String {
    ".env.example".to_string()
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct SyncParams {
    /// Platform to sync to (vercel, railway). If empty, syncs all configured targets.
    #[serde(default)]
    pub platform: Option<String>,
    /// Override project ID for this sync
    #[serde(default)]
    pub project_id: Option<String>,
}

// ── Team operations ──────────────────────────────────────────────────

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct TeamCreateParams {
    /// Name for the new team (human-readable label)
    pub name: String,
    /// Required. Must be true — confirms the user wants to create a new
    /// team. Creating a team is a billable Pro action.
    #[serde(default)]
    pub confirm: bool,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct TeamIdParams {
    /// Team identifier (UUID)
    pub team_id: String,
    /// Required for mutating operations that publish local key material.
    #[serde(default)]
    pub confirm: bool,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
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
}

fn default_member_role() -> String {
    "member".to_string()
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct TeamVaultParams {
    /// Team identifier (UUID)
    pub team_id: String,
    /// Required. Must be true — push/pull mutates the team's shared vault
    /// (push) or overwrites local secrets with the team copy (pull). Both
    /// are write operations that need user consent.
    #[serde(default)]
    pub confirm: bool,
}

// ── Validation ───────────────────────────────────────────────────────

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct ValidateSecretParams {
    /// Name of the secret to query validation status for (e.g. OPENAI_API_KEY).
    /// Never the value — this tool only reads stored metadata.
    pub name: String,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct ValidateAllParams {
    /// Maximum number of concurrent validation jobs (default: 4, max: 16).
    #[serde(default = "default_validate_jobs")]
    pub jobs: usize,
}

fn default_validate_jobs() -> usize {
    4
}

// ── Audit analytics ──────────────────────────────────────────────────

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
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

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
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

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
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

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct ComplianceStatusParams {
    // No parameters needed — reads project state and global audit state.
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct RotationDueParams {
    /// Warn when expiry is within this many days. Defaults to 7.
    #[serde(default = "default_warn_days")]
    pub warn_days: u64,
}

fn default_warn_days() -> u64 {
    7
}
