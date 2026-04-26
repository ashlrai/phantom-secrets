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
}

fn default_env_path() -> String {
    ".env".to_string()
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct AddSecretParams {
    /// Name of the secret (e.g., OPENAI_API_KEY)
    pub name: String,
    /// Value of the secret
    pub value: String,
    /// Required. Must be true — the calling agent must confirm with the user
    /// before invoking this tool. Defends against prompt-injected instructions
    /// in project content (READMEs, issue comments, dependency docs) silently
    /// mutating the vault.
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
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct UnwrapParams {}

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
