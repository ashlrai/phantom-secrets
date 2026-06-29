use phantom_core::config::PhantomConfig;
use phantom_core::dotenv::{classify, is_public_key, DotenvFile, SecretClassification};
use phantom_core::token::{PhantomToken, TokenMap};
use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::*;
use rmcp::{tool, tool_handler, tool_router, ErrorData as McpError, ServerHandler};
use std::path::PathBuf;

use crate::tools::helpers::{
    internal_err, invalid_params_err, require_approval_token, require_confirm, text_result,
};
use crate::tools::params::{
    AddSecretInteractiveParams, AddSecretParams, AuditAnalyticsParams, AuditAnomaliesParams,
    AuditAnomaliesRealtimeParams, AuditExportReportParams, AuditIncidentsParams, AuditRecentParams, AuditStatsParams,
    AutoRotateParams, CheckParams, CloudPullParams, CloudPushParams, ComplianceStatusParams,
    CopySecretParams, DoctorParams, EnvParams, ExpiryCheckParams, InitParams, ListWithExpiryParams,
    PhantomExpiryEnforceParams, RemoveSecretParams, RotateParams, RotateWithCandidateParams,
    RotatePromoteParams, RotateWithExpiryParams, RotationDueParams, SyncParams, TeamCreateParams,
    TeamIdParams, TeamInviteParams, TeamVaultParams, UnwrapParams, WhyParams, WrapParams,
    ValidateSecretParams, ValidateAllParams, ValidationScheduleParams, ValidationHistoryParams,
    RotationScheduleNextParams, ApplyExpiryPolicyParams, RotateProviderParams,
};
use crate::tools::pkg_json::{read_package_scripts, write_package_json};

// ── MCP Server ───────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct PhantomMcpServer {
    // rmcp's #[tool_router] / #[tool_handler] macros consume this field via
    // generated code that clippy's dead-code pass can't see through.
    #[allow(dead_code)]
    tool_router: ToolRouter<Self>,
    project_dir: PathBuf,
}

impl PhantomMcpServer {
    pub fn new() -> anyhow::Result<Self> {
        let project_dir = std::env::current_dir()?;
        Ok(Self {
            tool_router: Self::tool_router(),
            project_dir,
        })
    }

    /// Create a server for a specific directory (used in tests).
    #[allow(dead_code)]
    pub fn with_dir(project_dir: PathBuf) -> Self {
        Self {
            tool_router: Self::tool_router(),
            project_dir,
        }
    }

    fn config_path(&self) -> PathBuf {
        self.project_dir.join(".phantom.toml")
    }

    fn env_path(&self) -> PathBuf {
        self.project_dir.join(".env")
    }

    fn load_config(&self) -> Result<PhantomConfig, String> {
        let path = self.config_path();
        if !path.exists() {
            return Err("Not initialized. Run `phantom init` first.".to_string());
        }
        PhantomConfig::load(&path).map_err(|e| format!("Failed to load config: {e}"))
    }

    fn load_config_and_vault(
        &self,
    ) -> Result<(PhantomConfig, Box<dyn phantom_vault::VaultBackend>), McpError> {
        let config = self.load_config().map_err(internal_err)?;
        let vault = phantom_vault::create_vault(&config.phantom.project_id);
        Ok((config, vault))
    }

    fn save_cloud_version(&self, config: &mut PhantomConfig, version: u64) {
        let cloud_config = config.cloud.get_or_insert_default();
        cloud_config.version = version;
        let _ = config.save(&self.config_path());
    }

    /// Returns the project identifier used for approval nonce scoping.
    /// Uses the canonical string of the project directory.
    fn project_id(&self) -> String {
        self.project_dir.to_string_lossy().into_owned()
    }
}

#[tool_router]
impl PhantomMcpServer {
    /// List all secret names stored in the vault. Never returns secret values.
    #[tool(
        description = "List all secret names in the Phantom vault. Returns names only — never exposes actual secret values. Use this to see what secrets are configured."
    )]
    fn phantom_list_secrets(&self) -> Result<CallToolResult, McpError> {
        let (config, vault) = self.load_config_and_vault()?;
        let names = vault
            .list()
            .map_err(|e| internal_err(format!("Failed to list secrets: {e}")))?;

        if names.is_empty() {
            return text_result("No secrets stored in vault.");
        }

        let mut output = format!("{} secret(s) in vault:\n", names.len());
        for name in &names {
            // Check for service mapping
            let service = config
                .services
                .iter()
                .find(|(_, c)| c.secret_key == *name)
                .map(|(svc_name, _)| format!(" (service: {svc_name})"));

            output.push_str(&format!("  - {}{}\n", name, service.unwrap_or_default()));
        }

        text_result(output)
    }

    /// Show the current status of Phantom in this project.
    #[tool(
        description = "Show Phantom status: project ID, vault backend, number of secrets, configured services, and proxy state."
    )]
    fn phantom_status(&self) -> Result<CallToolResult, McpError> {
        if !self.config_path().exists() {
            return text_result(
                "Phantom is not initialized in this directory.\nRun `phantom init` to get started.",
            );
        }

        let (config, vault) = self.load_config_and_vault()?;
        let names = vault.list().unwrap_or_default();

        let mut output = String::new();
        output.push_str(&format!("Project ID: {}\n", config.phantom.project_id));
        output.push_str(&format!("Vault backend: {}\n", vault.backend_name()));
        output.push_str(&format!("Secrets stored: {}\n", names.len()));

        // Check .env status
        let env_path = self.env_path();
        if env_path.exists() {
            if let Ok(dotenv) = DotenvFile::parse_file(&env_path) {
                let real = dotenv.real_secret_entries();
                let total = dotenv.entries().len();
                let phantom_count = dotenv.entries().iter().filter(|e| e.is_phantom).count();
                output.push_str(&format!(
                    ".env: {} entries ({} phantom tokens, {} unprotected)\n",
                    total,
                    phantom_count,
                    real.len()
                ));
            }
        }

        // Service mappings
        let proxy_services = config.proxy_services();
        if !proxy_services.is_empty() {
            output.push_str("\nService mappings:\n");
            for (name, svc) in &proxy_services {
                output.push_str(&format!(
                    "  {} -> {} ({})\n",
                    svc.secret_key,
                    svc.pattern.as_deref().unwrap_or("n/a"),
                    name
                ));
            }
        }

        text_result(output)
    }

    /// Initialize Phantom in the current directory.
    #[tool(
        description = "Initialize Phantom: read .env file, store real secrets in the vault, and rewrite .env with phantom tokens. The AI agent will only see phantom tokens after this."
    )]
    fn phantom_init(
        &self,
        Parameters(params): Parameters<InitParams>,
    ) -> Result<CallToolResult, McpError> {
        require_confirm("phantom_init", params.confirm)?;
        let params_json = serde_json::to_string(&params).unwrap_or_default();
        require_approval_token("phantom_init", params.approval_token.as_deref(), &params_json, &self.project_id())?;
        let env_path = self.project_dir.join(&params.env_path);

        let dotenv = DotenvFile::parse_file(&env_path)
            .map_err(|e| invalid_params_err(format!("Failed to read {}: {e}", params.env_path)))?;

        let real_entries = dotenv.real_secret_entries();
        if real_entries.is_empty() {
            return text_result(
                "No real secrets found in .env (all values are already phantom tokens or non-secret config).",
            );
        }

        let project_id = PhantomConfig::project_id_from_path(&self.project_dir);
        let config = if self.config_path().exists() {
            PhantomConfig::load(&self.config_path())
                .map_err(|e| internal_err(format!("Config error: {e}")))?
        } else {
            PhantomConfig::new_with_defaults(project_id.clone())
        };

        let vault = phantom_vault::create_vault(&config.phantom.project_id);

        let mut token_map = TokenMap::new();
        let mut stored = Vec::new();
        for entry in &real_entries {
            token_map.insert(entry.key.clone());
            vault
                .store(&entry.key, &entry.value)
                .map_err(|e| internal_err(format!("Failed to store {}: {e}", entry.key)))?;
            stored.push(entry.key.clone());
        }

        dotenv
            .write_phantomized(&token_map, &env_path)
            .map_err(|e| internal_err(format!("Failed to rewrite .env: {e}")))?;

        config
            .save(&self.config_path())
            .map_err(|e| internal_err(format!("Failed to save config: {e}")))?;

        let mut output = format!(
            "Phantom initialized! {} secret(s) protected:\n",
            stored.len()
        );
        for name in &stored {
            output.push_str(&format!("  - {}\n", name));
        }
        output.push_str("\n.env has been rewritten with phantom tokens.\n");
        output.push_str("Real secrets are stored in the vault.\n");
        output.push_str("Use `phantom exec -- <command>` to run code with the proxy.");

        text_result(output)
    }

    /// Add a secret to the vault.
    #[tool(
        description = "Deprecated unsafe plaintext secret entry. This tool refuses values because MCP arguments enter agent context. Use phantom_add_secret_interactive instead."
    )]
    fn phantom_add_secret(
        &self,
        Parameters(params): Parameters<AddSecretParams>,
    ) -> Result<CallToolResult, McpError> {
        require_confirm("phantom_add_secret", params.confirm)?;
        let params_json = serde_json::to_string(&params).unwrap_or_default();
        require_approval_token("phantom_add_secret", params.approval_token.as_deref(), &params_json, &self.project_id())?;
        text_result(format!(
            "No secret value accepted through MCP for '{}'. Use phantom_add_secret_interactive to start an out-of-band terminal flow.",
            params.name
        ))
    }

    /// Start an out-of-band flow for adding a secret without exposing the value to MCP.
    #[tool(
        description = "Safely add a secret by name without passing its value through MCP. Requires confirm:true. The returned command prompts for the value directly in the user's terminal, outside agent context."
    )]
    fn phantom_add_secret_interactive(
        &self,
        Parameters(params): Parameters<AddSecretInteractiveParams>,
    ) -> Result<CallToolResult, McpError> {
        require_confirm("phantom_add_secret_interactive", params.confirm)?;
        let params_json = serde_json::to_string(&params).unwrap_or_default();
        require_approval_token("phantom_add_secret_interactive", params.approval_token.as_deref(), &params_json, &self.project_id())?;
        text_result(format!(
            "Run this in a trusted terminal from {}:\n\n  phantom add {}\n\nEnter the real value only at the terminal prompt. Do not paste it into chat or MCP tool arguments.",
            self.project_dir.display(),
            params.name
        ))
    }

    /// Remove a secret from the vault.
    #[tool(
        description = "Remove a secret from the Phantom vault by name. DESTRUCTIVE — the secret is permanently deleted (after a successful cloud pull it is recoverable, otherwise not). Requires `confirm: true`; the agent must ask the user for explicit consent before calling. See the `confirm` parameter docs for the threat model."
    )]
    fn phantom_remove_secret(
        &self,
        Parameters(params): Parameters<RemoveSecretParams>,
    ) -> Result<CallToolResult, McpError> {
        require_confirm("phantom_remove_secret", params.confirm)?;
        let (_config, vault) = self.load_config_and_vault()?;
        let params_json = serde_json::to_string(&params).unwrap_or_default();
        require_approval_token("phantom_remove_secret", params.approval_token.as_deref(), &params_json, &self.project_id())?;
        vault
            .delete(&params.name)
            .map_err(|e| internal_err(format!("Failed to remove secret: {e}")))?;

        text_result(format!("Secret '{}' removed from vault.", params.name))
    }

    /// Rotate all phantom tokens.
    #[tool(
        description = "Regenerate all phantom tokens in .env. Old tokens become invalid — any running `phantom exec` / dev server that cached them will break until it picks up the new .env. Real secrets in the vault are unchanged. DESTRUCTIVE; requires `confirm: true`; the agent must ask the user for explicit consent before calling."
    )]
    fn phantom_rotate(
        &self,
        Parameters(params): Parameters<RotateParams>,
    ) -> Result<CallToolResult, McpError> {
        require_confirm("phantom_rotate", params.confirm)?;
        let (_config, vault) = self.load_config_and_vault()?;
        let params_json = serde_json::to_string(&params).unwrap_or_default();
        require_approval_token("phantom_rotate", params.approval_token.as_deref(), &params_json, &self.project_id())?;
        let names = vault
            .list()
            .map_err(|e| internal_err(format!("Failed to list secrets: {e}")))?;

        if names.is_empty() {
            return text_result("No secrets to rotate.");
        }

        let mut token_map = TokenMap::new();
        for name in &names {
            token_map.insert(name.clone());
        }

        let env_path = self.env_path();
        if env_path.exists() {
            let dotenv = DotenvFile::parse_file(&env_path)
                .map_err(|e| internal_err(format!("Failed to read .env: {e}")))?;
            dotenv
                .write_phantomized(&token_map, &env_path)
                .map_err(|e| internal_err(format!("Failed to rewrite .env: {e}")))?;
        }

        text_result(format!(
            "Rotated {} phantom token(s). Old tokens are now invalid.",
            names.len()
        ))
    }

    /// Create a shadow (candidate) credential for staged rotation.
    #[tool(
        description = "Staged rotation: generate a new candidate credential alongside the current primary for a named secret. The primary remains active until phantom_rotate_promote succeeds. Set PHANTOM_CANDIDATE_MODE=1 in the proxy environment to inject the candidate instead of the primary for parallel validation. Returns { shadow_id, candidate_added_at, time_until_auto_promote_ttl } — never returns the credential values. Requires `confirm: true`."
    )]
    fn phantom_rotate_with_candidate(
        &self,
        Parameters(params): Parameters<RotateWithCandidateParams>,
    ) -> Result<CallToolResult, McpError> {
        require_confirm("phantom_rotate_with_candidate", params.confirm)?;

        let (config, vault) = self.load_config_and_vault()?;
        let params_json = serde_json::to_string(&params).unwrap_or_default();
        require_approval_token("phantom_rotate_with_candidate", params.approval_token.as_deref(), &params_json, &self.project_id())?;

        if !vault
            .exists(&params.name)
            .map_err(|e| internal_err(format!("Failed to check secret: {e}")))?
        {
            return Err(invalid_params_err(format!(
                "Secret '{}' not found in vault.",
                params.name
            )));
        }

        // Retrieve primary value to build the ShadowedSecret
        let primary = vault
            .retrieve(&params.name)
            .map_err(|e| internal_err(format!("Failed to retrieve secret: {e}")))?;

        // Generate a candidate value
        use rand::RngCore;
        let mut bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut bytes);
        let candidate = format!("phm_cand_{}", hex::encode(&bytes[..16]));

        // Store candidate under shadow key in vault
        let shadow_key = format!("{}__SHADOW_CANDIDATE", params.name);
        vault
            .store(&shadow_key, &candidate)
            .map_err(|e| internal_err(format!("Failed to store shadow candidate: {e}")))?;

        phantom_core::audit::log("shadow.candidate_created", Some(&params.name));

        // Build and persist shadow metadata
        use phantom_vault::shadowing::{shadow_dir, ShadowStore, ShadowedSecret};
        let shadow = ShadowedSecret::new(
            &params.name,
            primary.as_str(),
            &candidate,
            params.auto_promote_ttl_secs,
        );
        let shadow_id = shadow.shadow_id.clone();
        let candidate_added_at = shadow.candidate_added_at;
        let ttl_remaining = shadow.ttl_remaining_secs();

        let store = ShadowStore::new(shadow_dir(&config.phantom.project_id))
            .map_err(|e| internal_err(format!("Failed to open shadow store: {e}")))?;
        store
            .save(&shadow)
            .map_err(|e| internal_err(format!("Failed to save shadow metadata: {e}")))?;

        let ttl_str = match ttl_remaining {
            Some(secs) => format!("{secs}s"),
            None => "none (manual promotion only)".to_string(),
        };

        text_result(format!(
            "Shadow candidate created for '{}'.\nshadow_id: {}\ncandidate_added_at: {}\ntime_until_auto_promote_ttl: {}\n\nUse phantom_rotate_promote to validate and promote the candidate.\nSet PHANTOM_CANDIDATE_MODE=1 to inject the candidate in proxy sessions.",
            params.name, shadow_id, candidate_added_at, ttl_str
        ))
    }

    /// Promote a validated shadow candidate to primary.
    #[tool(
        description = "Validate the shadow candidate for a named secret and atomically promote it to primary. The old primary is discarded. Requires `confirm: true` — the agent must obtain explicit user consent before promoting. On success returns the new shadow_id and promotion timestamp."
    )]
    fn phantom_rotate_promote(
        &self,
        Parameters(params): Parameters<RotatePromoteParams>,
    ) -> Result<CallToolResult, McpError> {
        require_confirm("phantom_rotate_promote", params.confirm)?;

        let (config, vault) = self.load_config_and_vault()?;

        let params_json = serde_json::to_string(&params).unwrap_or_default();
        require_approval_token("phantom_rotate_promote", params.approval_token.as_deref(), &params_json, &self.project_id())?;
        use phantom_vault::shadowing::{shadow_dir, ShadowStore, ShadowedSecret};
        let store = ShadowStore::new(shadow_dir(&config.phantom.project_id))
            .map_err(|e| internal_err(format!("Failed to open shadow store: {e}")))?;

        let meta = store
            .load_meta(&params.name)
            .map_err(|e| internal_err(format!("Failed to load shadow metadata: {e}")))?
            .ok_or_else(|| {
                invalid_params_err(format!(
                    "No shadow exists for secret '{}'. Call phantom_rotate_with_candidate first.",
                    params.name
                ))
            })?;

        // Retrieve current primary and candidate from vault
        let primary = vault
            .retrieve(&params.name)
            .map_err(|e| internal_err(format!("Failed to retrieve primary: {e}")))?;
        let shadow_key = format!("{}__SHADOW_CANDIDATE", params.name);
        let candidate = vault
            .retrieve(&shadow_key)
            .map_err(|e| internal_err(format!("Failed to retrieve candidate: {e}")))?;

        // Reconstruct ShadowedSecret from metadata + vault values
        let mut shadow = ShadowedSecret::from_meta(meta, primary.as_str(), candidate.as_str());

        // Run validation: structural check (non-empty, length > 8, no whitespace)
        let validation_ok = !shadow.candidate.is_empty()
            && shadow.candidate.len() > 8
            && !shadow.candidate.chars().any(char::is_whitespace);

        if !validation_ok {
            shadow
                .record_validation_failure(Some("mcp-structural-check".to_string()))
                .map_err(|e| internal_err(e.to_string()))?;
            store
                .save(&shadow)
                .map_err(|e| internal_err(format!("Failed to save shadow: {e}")))?;
            phantom_core::audit::log("shadow.validation_failed", Some(&params.name));
            return Err(internal_err(format!(
                "Shadow candidate for '{}' failed validation. The candidate has been marked as failed. Call phantom_rotate_with_candidate again to generate a new one.",
                params.name
            )));
        }

        // Record success then promote
        shadow
            .record_validation_success(Some("mcp-promote".to_string()))
            .map_err(|e| internal_err(e.to_string()))?;
        shadow
            .promote(Some("phantom_rotate_promote".to_string()))
            .map_err(|e| internal_err(e.to_string()))?;

        // Atomically update vault: write promoted value, delete shadow key
        vault
            .store(&params.name, shadow.primary.as_str())
            .map_err(|e| internal_err(format!("Failed to store promoted value: {e}")))?;
        vault
            .delete(&shadow_key)
            .map_err(|e| internal_err(format!("Failed to delete shadow candidate: {e}")))?;

        store
            .save(&shadow)
            .map_err(|e| internal_err(format!("Failed to update shadow metadata: {e}")))?;

        phantom_core::audit::log("shadow.promoted", Some(&params.name));

        let promoted_at = shadow
            .audit_trail
            .last()
            .map(|e| e.ts)
            .unwrap_or(0);

        text_result(format!(
            "Shadow candidate for '{}' promoted to primary.\nshadow_id: {}\npromoted_at: {}\nOld primary has been discarded.",
            params.name, shadow.shadow_id, promoted_at
        ))
    }

    /// Rotate a secret using a vendor-specific provider (Stripe, GitHub, AWS).
    ///
    /// Calls the vendor's API to re-issue the credential, stores the new value
    /// in the vault, and records an audit event. The new secret value is NEVER
    /// returned in the MCP response — only status metadata is exposed.
    #[tool(
        description = "Rotate a secret via a vendor-specific provider (stripe | github | aws). \
            Calls the vendor API to re-issue the credential server-side, stores the new value \
            in the encrypted vault, and records a signed audit event. The new secret value is \
            NEVER exposed in the MCP response — only provider name, status, and audit metadata \
            are returned. Requires the secret's rotation_provider config to be set in \
            .phantom.toml under [phantom.secrets.{name}.rotation_provider]. \
            DESTRUCTIVE — permanently invalidates the current key at the vendor. \
            Requires `confirm: true`; the agent must obtain user consent before calling."
    )]
    fn phantom_rotate_provider(
        &self,
        Parameters(params): Parameters<RotateProviderParams>,
    ) -> Result<CallToolResult, McpError> {
        require_confirm("phantom_rotate_provider", params.confirm)?;
        let params_json = serde_json::to_string(&params).unwrap_or_default();
        require_approval_token(
            "phantom_rotate_provider",
            params.approval_token.as_deref(),
            &params_json,
            &self.project_id(),
        )?;

        let (config, vault) = self.load_config_and_vault()?;

        // Verify the secret exists in the vault.
        if !vault
            .exists(&params.name)
            .map_err(|e| internal_err(format!("Failed to check secret existence: {e}")))?
        {
            return Err(invalid_params_err(format!(
                "Secret '{}' not found in vault. Add it with phantom_add_secret first.",
                params.name
            )));
        }

        // Resolve the rotation provider config from .phantom.toml.
        let provider_config = config
            .phantom
            .secrets
            .get(&params.name)
            .and_then(|ov| ov.rotation_provider.as_ref());

        // Validate that the configured provider matches the requested provider.
        if let Some(cfg) = provider_config {
            if cfg.provider != params.provider {
                return Err(invalid_params_err(format!(
                    "Secret '{}' is configured for provider '{}' but '{}' was requested. \
                     Update [phantom.secrets.{}.rotation_provider] in .phantom.toml.",
                    params.name, cfg.provider, params.provider, params.name
                )));
            }
        }

        // Build the provider list and attempt vendor rotation.
        let providers = phantom_core::rotation_provider::default_rotation_providers();
        let new_value = phantom_core::rotation_provider::auto_sync_rotation(
            &params.name,
            provider_config,
            &providers,
        )
        .map_err(|e| internal_err(format!("Provider rotation failed: {e}")))?;

        match new_value {
            Some(secret) => {
                // Store the new value in vault — secret is zeroized after this.
                vault
                    .store(&params.name, secret.as_str())
                    .map_err(|e| internal_err(format!("Failed to store rotated secret: {e}")))?;

                phantom_core::audit::log("vault.rotation.provider.stored", Some(&params.name));

                text_result(format!(
                    "Provider rotation succeeded for '{}'.\n\
                     provider: {}\n\
                     status: rotated\n\
                     The new credential has been stored in the vault.\n\
                     The secret value was NOT exposed via MCP.",
                    params.name, params.provider
                ))
            }
            None => {
                // No provider matched — config may be missing or disabled.
                Err(invalid_params_err(format!(
                    "No rotation provider matched secret '{}' with provider '{}'. \
                     Ensure [phantom.secrets.{}.rotation_provider] is set in .phantom.toml \
                     with provider = \"{}\" and api_key_env pointing to a valid credential.",
                    params.name, params.provider, params.name, params.provider
                )))
            }
        }
    }

    /// Push encrypted vault to Phantom Cloud.
    #[tool(
        description = "Push local vault to Phantom Cloud. Encrypts secrets client-side before upload; server never sees plaintext. Requires phantom login first. DESTRUCTIVE — overwrites the existing cloud copy; damage from a prompt-injected push propagates to every machine that later pulls. Requires `confirm: true`; the agent must ask the user for explicit consent before calling."
    )]
    async fn phantom_cloud_push(
        &self,
        Parameters(params): Parameters<CloudPushParams>,
    ) -> Result<CallToolResult, McpError> {
        require_confirm("phantom_cloud_push", params.confirm)?;
        let params_json = serde_json::to_string(&params).unwrap_or_default();
        require_approval_token("phantom_cloud_push", params.approval_token.as_deref(), &params_json, &self.project_id())?;
        use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
        use std::collections::BTreeMap;

        let token = phantom_core::auth::load_token()
            .ok_or_else(|| internal_err("Not logged in. Run `phantom login` first."))?;

        let (config, vault) = self.load_config_and_vault()?;
        let names = vault
            .list()
            .map_err(|e| internal_err(format!("Failed to list secrets: {e}")))?;

        if names.is_empty() {
            return text_result("No secrets to push.");
        }

        let mut secrets = BTreeMap::new();
        for name in &names {
            let value = vault
                .retrieve(name)
                .map_err(|e| internal_err(format!("Failed to retrieve secret: {e}")))?;
            secrets.insert(name.clone(), String::from(value.as_str()));
        }

        // Serialize, then zeroize the map on every exit path — including the
        // serialization-error case (otherwise an `Err` early-returns with the
        // cloned plaintext strings still sitting in the map).
        let serialize_result = serde_json::to_string(&secrets);
        for value in secrets.values_mut() {
            zeroize::Zeroize::zeroize(value);
        }
        drop(secrets);
        let plaintext = zeroize::Zeroizing::new(
            serialize_result.map_err(|e| internal_err(format!("Failed to serialize: {e}")))?,
        );

        let passphrase = phantom_core::auth::get_or_create_cloud_passphrase()
            .map_err(|e| internal_err(format!("Failed to access cloud key: {e}")))?;

        let encrypted = phantom_vault::crypto::encrypt(plaintext.as_bytes(), &passphrase)
            .map_err(|e| internal_err(format!("Encryption failed: {e}")))?;

        let blob_b64 = BASE64.encode(&encrypted);
        let version = config.cloud.as_ref().map(|c| c.version).unwrap_or(0);
        let api_base = phantom_core::auth::api_base_url()
            .map_err(|e| internal_err(format!("Invalid cloud API URL: {e}")))?;

        let new_version = phantom_core::cloud::push(
            &api_base,
            &token,
            &config.phantom.project_id,
            &blob_b64,
            version,
        )
        .await
        .map_err(|e| internal_err(format!("Cloud push failed: {e}")))?;

        let mut config = config;
        self.save_cloud_version(&mut config, new_version);

        text_result(format!(
            "Pushed {} secret(s) to Phantom Cloud (v{new_version}). End-to-end encrypted.",
            names.len()
        ))
    }

    /// Pull vault from Phantom Cloud.
    #[tool(
        description = "Pull vault from Phantom Cloud to local machine. Decrypts client-side. Use force=true to overwrite existing secrets. DESTRUCTIVE — writes entries into the local vault and (with force=true) overwrites values. Requires `confirm: true`; the agent must ask the user for explicit consent before calling."
    )]
    async fn phantom_cloud_pull(
        &self,
        Parameters(params): Parameters<CloudPullParams>,
    ) -> Result<CallToolResult, McpError> {
        require_confirm("phantom_cloud_pull", params.confirm)?;
        let params_json = serde_json::to_string(&params).unwrap_or_default();
        require_approval_token("phantom_cloud_pull", params.approval_token.as_deref(), &params_json, &self.project_id())?;
        use base64::{engine::general_purpose::STANDARD as BASE64, Engine};

        let token = phantom_core::auth::load_token()
            .ok_or_else(|| internal_err("Not logged in. Run `phantom login` first."))?;

        let (config, vault) = self.load_config_and_vault()?;

        let api_base = phantom_core::auth::api_base_url()
            .map_err(|e| internal_err(format!("Invalid cloud API URL: {e}")))?;
        let pull_result = phantom_core::cloud::pull(&api_base, &token, &config.phantom.project_id)
            .await
            .map_err(|e| internal_err(format!("Cloud pull failed: {e}")))?;

        let pull_data = match pull_result {
            Some(data) => data,
            None => {
                return text_result(
                    "No cloud vault found for this project. Run phantom_cloud_push first.",
                );
            }
        };

        let passphrase = phantom_core::auth::get_or_create_cloud_passphrase()
            .map_err(|e| internal_err(format!("Failed to access cloud key: {e}")))?;

        let encrypted = BASE64
            .decode(&pull_data.encrypted_blob)
            .map_err(|e| internal_err(format!("Invalid cloud data: {e}")))?;

        let plaintext = zeroize::Zeroizing::new(
            phantom_vault::crypto::decrypt(&encrypted, &passphrase)
                .map_err(|e| internal_err(format!("Decryption failed: {e}")))?,
        );

        let mut secrets: std::collections::BTreeMap<String, String> =
            serde_json::from_slice(&plaintext)
                .map_err(|e| internal_err(format!("Invalid vault data: {e}")))?;

        // Run the store loop without `?` so a mid-loop error can't bypass the
        // zeroize sweep below — serde produced fresh String allocations the
        // Zeroizing<plaintext> wrapper does not reach.
        let mut added = 0;
        let mut skipped = 0;
        let mut store_err: Option<McpError> = None;
        for (name, value) in &secrets {
            if !params.force && vault.exists(name).unwrap_or(false) {
                skipped += 1;
                continue;
            }
            match vault.store(name, value) {
                Ok(()) => added += 1,
                Err(e) => {
                    store_err = Some(internal_err(format!("Failed to store secret: {e}")));
                    break;
                }
            }
        }

        for value in secrets.values_mut() {
            zeroize::Zeroize::zeroize(value);
        }
        drop(secrets);

        if let Some(err) = store_err {
            return Err(err);
        }

        let mut config = config;
        self.save_cloud_version(&mut config, pull_data.version);

        let msg = if skipped > 0 {
            format!("Pulled {added} secret(s), {skipped} skipped (already exist, use force=true to overwrite).")
        } else {
            format!(
                "Pulled {added} secret(s) from Phantom Cloud (v{}).",
                pull_data.version
            )
        };

        text_result(msg)
    }

    /// Copy a secret to another phantom-initialized project without exposing its value.
    #[tool(
        description = "Copy a secret from this project's vault to another project's vault. The secret value is never exposed — it transfers directly between encrypted vaults. The target project must be phantom-initialized. DESTRUCTIVE — writes a secret into another vault (exfiltration primitive if misdirected); requires `confirm: true`; the agent must ask the user for explicit consent before calling."
    )]
    fn phantom_copy_secret(
        &self,
        Parameters(params): Parameters<CopySecretParams>,
    ) -> Result<CallToolResult, McpError> {
        require_confirm("phantom_copy_secret", params.confirm)?;

        // Reject
        let params_json = serde_json::to_string(&params).unwrap_or_default();
        require_approval_token("phantom_copy_secret", params.approval_token.as_deref(), &params_json, &self.project_id())?;
        // Reject `..` in the raw input. Canonicalize below collapses traversal,
        // but only once target_dir exists on disk — and an attacker can stage a
        // missing-path case. Guarding at the textual layer is simplest.
        if params.target_dir.split(['/', '\\']).any(|seg| seg == "..") {
            return Err(invalid_params_err(
                "target_dir must not contain `..` segments; pass the full destination path explicitly.",
            ));
        }

        let (_config, source_vault) = self.load_config_and_vault()?;

        // Retrieve from source — Zeroizing<String> auto-zeroizes on all exit paths
        let secret_value = source_vault
            .retrieve(&params.name)
            .map_err(|e| invalid_params_err(format!("Secret '{}' not found: {e}", params.name)))?;

        // Resolve target directory, then canonicalize to normalize any symlinks
        // and give the user a fully-qualified path in the success message.
        let target_path = std::path::PathBuf::from(&params.target_dir);
        let target_dir_raw = if target_path.is_relative() {
            self.project_dir.join(&target_path)
        } else {
            target_path
        };
        let target_dir = target_dir_raw.canonicalize().map_err(|e| {
            invalid_params_err(format!(
                "target_dir '{}' cannot be resolved: {e}",
                target_dir_raw.display()
            ))
        })?;

        let target_config_path = target_dir.join(".phantom.toml");
        if !target_config_path.exists() {
            return Err(invalid_params_err(format!(
                "Target project at {} is not phantom-initialized",
                target_dir.display()
            )));
        }

        let target_config = PhantomConfig::load(&target_config_path)
            .map_err(|e| internal_err(format!("Failed to load target config: {e}")))?;

        let target_vault = phantom_vault::create_vault(&target_config.phantom.project_id);
        let target_name = params.rename.as_deref().unwrap_or(&params.name);

        target_vault
            .store(target_name, &secret_value)
            .map_err(|e| internal_err(format!("Failed to store in target vault: {e}")))?;

        text_result(format!(
            "Copied '{}' -> '{}' in {}. Secret value was never exposed.",
            params.name,
            target_name,
            target_dir.display()
        ))
    }

    /// Run health checks and optionally auto-fix issues.
    #[tool(
        description = "Run Phantom health checks: config validity, vault access, .env protection, .gitignore, .env.example, pre-commit hook. Set fix=true to auto-fix safe issues."
    )]
    fn phantom_doctor(
        &self,
        Parameters(params): Parameters<DoctorParams>,
    ) -> Result<CallToolResult, McpError> {
        if params.fix {
            require_confirm("phantom_doctor", params.confirm)?;
            let params_json = serde_json::to_string(&params).unwrap_or_default();
            require_approval_token("phantom_doctor", params.approval_token.as_deref(), &params_json, &self.project_id())?;
        }
        let mut lines: Vec<String> = Vec::new();
        let mut issues = 0u32;
        let mut fixed = 0u32;

        let config_path = self.config_path();
        let env_path = self.env_path();

        // ── Check 1: .phantom.toml ──────────────────────────────────────
        let config = if config_path.exists() {
            lines.push("pass: .phantom.toml found".to_string());
            match PhantomConfig::load(&config_path) {
                Ok(cfg) => {
                    let id_short = cfg
                        .phantom
                        .project_id
                        .get(..8)
                        .unwrap_or(&cfg.phantom.project_id);
                    lines.push(format!("pass: Config valid (project: {id_short})"));
                    Some(cfg)
                }
                Err(e) => {
                    lines.push(format!("FAIL: Config parse error: {e}"));
                    issues += 1;
                    None
                }
            }
        } else {
            lines.push("warn: No .phantom.toml found".to_string());
            lines.push("  Fix: Run `phantom init`".to_string());
            issues += 1;
            None
        };

        // ── Check 2: Vault accessible ───────────────────────────────────
        if let Some(cfg) = &config {
            let vault = phantom_vault::create_vault(&cfg.phantom.project_id);
            lines.push(format!("pass: Vault backend: {}", vault.backend_name()));
            match vault.list() {
                Ok(names) => {
                    lines.push(format!("pass: {} secret(s) in vault", names.len()));
                }
                Err(e) => {
                    lines.push(format!("FAIL: Vault access failed: {e}"));
                    issues += 1;
                }
            }
        }

        // ── Check 3: .env file ──────────────────────────────────────────
        if env_path.exists() {
            match DotenvFile::parse_file(&env_path) {
                Ok(dotenv) => {
                    let entries = dotenv.entries();
                    let real_secrets = dotenv.real_secret_entries();
                    if real_secrets.is_empty() {
                        lines.push(format!(
                            "pass: .env has {} entries, all protected",
                            entries.len()
                        ));
                    } else {
                        let names: Vec<&str> =
                            real_secrets.iter().map(|e| e.key.as_str()).collect();
                        lines.push(format!(
                            "warn: .env has {} unprotected secret(s): {}",
                            real_secrets.len(),
                            names.join(", ")
                        ));
                        lines.push("  Fix: Run `phantom init`".to_string());
                        issues += 1;
                    }
                }
                Err(e) => {
                    lines.push(format!("FAIL: .env parse error: {e}"));
                    issues += 1;
                }
            }
        } else {
            lines.push("info: No .env file in current directory".to_string());
        }

        // ── Check 4: .gitignore includes .env ───────────────────────────
        let gitignore_path = self.project_dir.join(".gitignore");
        if gitignore_path.exists() {
            let content = std::fs::read_to_string(&gitignore_path).unwrap_or_default();
            if content.lines().any(|l| l.trim() == ".env") {
                lines.push("pass: .env is in .gitignore".to_string());
            } else {
                lines.push(
                    "warn: .env is NOT in .gitignore — secrets could be committed!".to_string(),
                );
                if params.fix {
                    let mut c = content;
                    if !c.ends_with('\n') {
                        c.push('\n');
                    }
                    c.push_str(".env\n");
                    std::fs::write(&gitignore_path, c)
                        .map_err(|e| internal_err(format!("Failed to write .gitignore: {e}")))?;
                    lines.push("  Fixed: Added .env to .gitignore".to_string());
                    fixed += 1;
                } else {
                    issues += 1;
                }
            }
        } else {
            lines.push("warn: No .gitignore — consider adding one".to_string());
            if params.fix {
                std::fs::write(
                    &gitignore_path,
                    ".env\n.env.local\n.env.*.local\n.env.backup\n",
                )
                .map_err(|e| internal_err(format!("Failed to create .gitignore: {e}")))?;
                lines.push("  Fixed: Created .gitignore with .env patterns".to_string());
                fixed += 1;
            } else {
                issues += 1;
            }
        }

        // ── Check 5: .env.example exists ────────────────────────────────
        let example_path = self.project_dir.join(".env.example");
        if example_path.exists() {
            lines.push("pass: .env.example found (team onboarding ready)".to_string());
        } else {
            lines.push("warn: No .env.example — team onboarding may be difficult".to_string());
            if params.fix && env_path.exists() {
                if let Ok(dotenv) = DotenvFile::parse_file(&env_path) {
                    let cfg = config.as_ref();
                    let content = dotenv.generate_example_content(cfg);
                    std::fs::write(&example_path, content)
                        .map_err(|e| internal_err(format!("Failed to write .env.example: {e}")))?;
                    lines.push("  Fixed: Generated .env.example".to_string());
                    fixed += 1;
                }
            } else if !params.fix {
                issues += 1;
            }
        }

        // ── Check 6: Pre-commit hook ────────────────────────────────────
        let git_dir = self.project_dir.join(".git");
        let git_hook = git_dir.join("hooks/pre-commit");
        if git_dir.exists() {
            if git_hook.exists() {
                let content = std::fs::read_to_string(&git_hook).unwrap_or_default();
                if content.contains("phantom") {
                    lines.push("pass: Git pre-commit hook includes phantom check".to_string());
                } else {
                    lines.push("warn: Git pre-commit hook exists but no phantom check".to_string());
                    if params.fix {
                        let mut c = content;
                        c.push_str(
                            "\n\n# Phantom Secrets pre-commit hook\nnpx phantom-secrets check --staged\n",
                        );
                        std::fs::write(&git_hook, c).map_err(|e| {
                            internal_err(format!("Failed to update pre-commit hook: {e}"))
                        })?;
                        lines
                            .push("  Fixed: Appended phantom check to pre-commit hook".to_string());
                        fixed += 1;
                    } else {
                        issues += 1;
                    }
                }
            } else {
                lines.push("warn: No pre-commit hook installed".to_string());
                if params.fix {
                    let hooks_dir = git_dir.join("hooks");
                    let _ = std::fs::create_dir_all(&hooks_dir);
                    let hook = "#!/bin/sh\n# Phantom Secrets pre-commit hook\nnpx phantom-secrets check --staged\nexit $?\n";
                    std::fs::write(&git_hook, hook).map_err(|e| {
                        internal_err(format!("Failed to install pre-commit hook: {e}"))
                    })?;
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt;
                        let _ = std::fs::set_permissions(
                            &git_hook,
                            std::fs::Permissions::from_mode(0o755),
                        );
                    }
                    lines.push("  Fixed: Installed pre-commit hook".to_string());
                    fixed += 1;
                } else {
                    issues += 1;
                }
            }
        } else {
            lines.push("info: Not a git repo — pre-commit hook not applicable".to_string());
        }

        // ── Summary ─────────────────────────────────────────────────────
        lines.push(String::new());
        if params.fix && fixed > 0 {
            lines.push(format!("Auto-fixed {fixed} issue(s)."));
        }
        if issues == 0 {
            lines.push("All checks passed!".to_string());
        } else {
            let suffix = if !params.fix {
                " — use fix=true to auto-fix"
            } else {
                ""
            };
            lines.push(format!("{issues} issue(s) found{suffix}"));
        }

        text_result(lines.join("\n"))
    }

    /// Explain why a key is or isn't protected by Phantom.
    #[tool(
        description = "Explain why an environment variable is or isn't protected by Phantom. Shows classification (Secret, PublicKey, NotSecret), whether it has a phantom token, and what heuristic matched."
    )]
    fn phantom_why(
        &self,
        Parameters(params): Parameters<WhyParams>,
    ) -> Result<CallToolResult, McpError> {
        let env_path = self.env_path();
        if !env_path.exists() {
            return text_result(format!(
                "No .env file found. '{}' cannot be classified without an .env file.",
                params.key
            ));
        }
        let dotenv = DotenvFile::parse_file(&env_path)
            .map_err(|e| internal_err(format!("Failed to read .env: {e}")))?;

        let entry = dotenv.entries().into_iter().find(|e| e.key == params.key);

        let entry = match entry {
            Some(e) => e,
            None => {
                return text_result(format!("'{}' was not found in .env.", params.key));
            }
        };

        let config = self.load_config().ok();

        let mut output = String::new();

        if entry.is_phantom {
            // Already protected with a phantom token
            let truncated = if entry.value.len() > 12 {
                format!("{}...", &entry.value[..12])
            } else {
                entry.value.clone()
            };
            output.push_str(&format!(
                "PROTECTED: '{}' is a phantom token ({}).\n",
                params.key, truncated
            ));
            output.push_str(
                "The real secret is stored in the vault; only the phantom token appears in .env.\n",
            );

            // Check for service mapping
            if let Some(cfg) = &config {
                if let Some((svc_name, svc)) = cfg
                    .services
                    .iter()
                    .find(|(_, c)| c.secret_key == params.key)
                {
                    output.push_str(&format!(
                        "Service mapping: {} -> {} ({})\n",
                        params.key,
                        svc.pattern.as_deref().unwrap_or("n/a"),
                        svc_name
                    ));
                }
            }
        } else {
            let classification = classify(entry);
            match classification {
                SecretClassification::PublicKey => {
                    // Determine which prefix matched
                    let public_prefixes = [
                        "NEXT_PUBLIC_",
                        "EXPO_PUBLIC_",
                        "VITE_",
                        "REACT_APP_",
                        "NUXT_PUBLIC_",
                        "GATSBY_",
                    ];
                    let matched_prefix = public_prefixes
                        .iter()
                        .find(|p| params.key.starts_with(*p))
                        .unwrap_or(&"unknown");
                    output.push_str(&format!(
                        "PUBLIC KEY: '{}' matches the framework prefix '{}'.\n",
                        params.key, matched_prefix
                    ));
                    output.push_str(
                        "This is a browser-safe public key — it's designed to be \
                         embedded in client-side bundles and does not need protection.\n",
                    );
                }
                SecretClassification::Secret => {
                    output.push_str(&format!(
                        "UNPROTECTED: '{}' is classified as a secret but does NOT have a phantom token.\n",
                        params.key
                    ));
                    // Explain why it was detected
                    let key_upper = params.key.to_uppercase();
                    let secret_key_patterns = [
                        "KEY",
                        "SECRET",
                        "TOKEN",
                        "PASSWORD",
                        "PASSWD",
                        "CREDENTIAL",
                        "AUTH",
                        "PRIVATE",
                        "API_KEY",
                        "ACCESS_KEY",
                        "SIGNING",
                    ];
                    let connection_patterns = [
                        "DATABASE_URL",
                        "REDIS_URL",
                        "MONGO_URL",
                        "POSTGRES_URL",
                        "MYSQL_URL",
                        "AMQP_URL",
                        "RABBITMQ_URL",
                        "ELASTICSEARCH_URL",
                        "CONNECTION_STRING",
                        "DSN",
                    ];

                    if let Some(pat) = secret_key_patterns.iter().find(|p| key_upper.contains(*p)) {
                        output.push_str(&format!(
                            "Reason: key name contains '{}', which indicates a secret.\n",
                            pat
                        ));
                    } else if let Some(pat) =
                        connection_patterns.iter().find(|p| key_upper.contains(*p))
                    {
                        output.push_str(&format!(
                            "Reason: key name matches connection pattern '{}'.\n",
                            pat
                        ));
                    } else if is_public_key(&params.key) {
                        output.push_str(
                            "Reason: has a public-key prefix, but the value matches a known secret pattern.\n",
                        );
                    } else {
                        output.push_str(
                            "Reason: the value matches known secret patterns (prefix, connection string, or high-entropy string).\n",
                        );
                    }
                    output.push_str("Run `phantom init` to protect it with a phantom token.\n");
                }
                SecretClassification::NotSecret => {
                    output.push_str(&format!(
                        "NOT SECRET: '{}' is classified as non-secret configuration.\n",
                        params.key
                    ));
                    output.push_str(
                        "It doesn't match any secret key patterns (KEY, SECRET, TOKEN, PASSWORD, etc.), \
                         connection string patterns, or secret value prefixes.\n",
                    );
                    output.push_str("Phantom leaves non-secret config values untouched in .env.\n");
                }
            }
        }

        text_result(output.trim_end().to_string())
    }

    /// Wrap package.json scripts with `npx phantom-secrets exec --`.
    #[tool(
        description = "Wrap package.json scripts with `npx phantom-secrets exec --` so secrets are injected via the proxy at runtime. Saves originals as `script:raw` variants. Uses a heuristic to pick dev/start/build/serve/deploy scripts and skip lint/test/format scripts."
    )]
    fn phantom_wrap(
        &self,
        Parameters(params): Parameters<WrapParams>,
    ) -> Result<CallToolResult, McpError> {
        require_confirm("phantom_wrap", params.confirm)?;
        let params_json = serde_json::to_string(&params).unwrap_or_default();
        require_approval_token("phantom_wrap", params.approval_token.as_deref(), &params_json, &self.project_id())?;
        let pkg_path = self.project_dir.join("package.json");
        if !pkg_path.exists() {
            return Err(internal_err("No package.json found in project directory."));
        }

        let (mut pkg, scripts) = read_package_scripts(&pkg_path)?;
        if scripts.is_empty() {
            return text_result("No \"scripts\" field found in package.json.");
        }

        // We need a mutable reference for modifications below
        let scripts = pkg.get_mut("scripts").unwrap().as_object_mut().unwrap();

        // Heuristic keywords
        let wrap_keywords = ["dev", "start", "build", "serve", "deploy"];
        let skip_keywords = [
            "lint",
            "test",
            "format",
            "check",
            "typecheck",
            "prettier",
            "eslint",
            "clean",
            "prepare",
            "postinstall",
        ];

        // Collect script names to wrap (avoid mutating while iterating)
        let candidates: Vec<(String, String)> = scripts
            .iter()
            .filter_map(|(name, val)| {
                let value = val.as_str()?;
                // Skip :raw variants
                if name.ends_with(":raw") {
                    return None;
                }
                // Skip already wrapped
                if value.contains("phantom-secrets") {
                    return None;
                }
                // Apply skip list from params
                if params.skip.iter().any(|s| s == name) {
                    return None;
                }
                // If "only" is specified, use that; otherwise use heuristic
                let should_wrap = if !params.only.is_empty() {
                    params.only.iter().any(|o| o == name)
                } else {
                    let lower = name.to_lowercase();
                    let matches_wrap = wrap_keywords.iter().any(|kw| lower.contains(kw));
                    let matches_skip = skip_keywords.iter().any(|kw| lower.contains(kw));
                    matches_wrap && !matches_skip
                };
                if should_wrap {
                    Some((name.clone(), value.to_string()))
                } else {
                    None
                }
            })
            .collect();

        if candidates.is_empty() {
            return text_result("No scripts matched for wrapping.");
        }

        // Apply wrapping
        for (name, original) in &candidates {
            let raw_key = format!("{name}:raw");
            scripts.insert(raw_key, serde_json::Value::String(original.clone()));
            scripts.insert(
                name.clone(),
                serde_json::Value::String(format!("npx phantom-secrets exec -- {original}")),
            );
        }

        write_package_json(&pkg_path, &pkg)?;

        let mut output = format!("Wrapped {} script(s):\n", candidates.len());
        for (name, _) in &candidates {
            output.push_str(&format!("  - {name}\n"));
        }
        output.push_str("\nOriginals saved as `script:raw` variants.");

        text_result(output)
    }

    /// Unwrap package.json scripts, restoring originals from `:raw` variants.
    #[tool(
        description = "Reverse phantom_wrap: restore original package.json scripts from their `:raw` variants and remove the `:raw` entries."
    )]
    fn phantom_unwrap(
        &self,
        Parameters(params): Parameters<UnwrapParams>,
    ) -> Result<CallToolResult, McpError> {
        require_confirm("phantom_unwrap", params.confirm)?;
        let params_json = serde_json::to_string(&params).unwrap_or_default();
        require_approval_token("phantom_unwrap", params.approval_token.as_deref(), &params_json, &self.project_id())?;
        let pkg_path = self.project_dir.join("package.json");
        if !pkg_path.exists() {
            return Err(internal_err("No package.json found in project directory."));
        }

        let (mut pkg, scripts) = read_package_scripts(&pkg_path)?;
        if scripts.is_empty() {
            return text_result("No \"scripts\" field found in package.json.");
        }

        // Find all :raw variants from the read-only copy
        let raw_entries: Vec<(String, String)> = scripts
            .iter()
            .filter_map(|(name, val)| {
                if name.ends_with(":raw") {
                    Some((name.clone(), val.as_str()?.to_string()))
                } else {
                    None
                }
            })
            .collect();

        if raw_entries.is_empty() {
            return text_result("No wrapped scripts found (no `:raw` variants).");
        }

        // Get mutable reference to apply changes
        let scripts = pkg.get_mut("scripts").unwrap().as_object_mut().unwrap();
        let mut restored = Vec::new();
        for (raw_key, original_value) in &raw_entries {
            let base_name = raw_key.trim_end_matches(":raw");
            scripts.insert(
                base_name.to_string(),
                serde_json::Value::String(original_value.clone()),
            );
            scripts.remove(raw_key);
            restored.push(base_name.to_string());
        }

        write_package_json(&pkg_path, &pkg)?;

        let mut output = format!("Unwrapped {} script(s):\n", restored.len());
        for name in &restored {
            output.push_str(&format!("  - {name}\n"));
        }
        output.push_str("\n`:raw` variants removed. Scripts restored to originals.");

        text_result(output)
    }

    /// Check for leaked secrets or orphaned phantom tokens.
    #[tool(
        description = "Check for security issues. With runtime=true, scans current environment for phantom tokens without a proxy (leak detection). Otherwise, scans .env files for unprotected real secrets."
    )]
    fn phantom_check(
        &self,
        Parameters(params): Parameters<CheckParams>,
    ) -> Result<CallToolResult, McpError> {
        if params.runtime {
            // Scan common API key env vars for phantom tokens in the process environment
            let api_vars = [
                "OPENAI_API_KEY",
                "ANTHROPIC_API_KEY",
                "STRIPE_SECRET_KEY",
                "STRIPE_API_KEY",
                "GITHUB_TOKEN",
                "AWS_SECRET_ACCESS_KEY",
                "DATABASE_URL",
                "REDIS_URL",
                "SENDGRID_API_KEY",
                "TWILIO_AUTH_TOKEN",
                "SLACK_TOKEN",
                "SLACK_BOT_TOKEN",
                "DISCORD_TOKEN",
                "FIREBASE_API_KEY",
                "SUPABASE_SERVICE_ROLE_KEY",
                "CLOUDFLARE_API_TOKEN",
            ];

            let mut found = Vec::new();
            for var in &api_vars {
                if let Ok(val) = std::env::var(var) {
                    if PhantomToken::is_phantom_token(&val) {
                        found.push(*var);
                    }
                }
            }

            if found.is_empty() {
                return text_result(
                    "No issues found. No phantom tokens detected in environment variables.",
                );
            }

            let mut output = format!(
                "WARNING: {} phantom token(s) found in environment without proxy:\n",
                found.len()
            );
            for var in &found {
                output.push_str(&format!("  - {}\n", var));
            }
            output.push_str(
                "\nThese tokens will not resolve to real secrets without the proxy running.\n\
                 Run `phantom exec -- <command>` to start the proxy.",
            );
            text_result(output)
        } else {
            // Scan .env files for unprotected secrets
            let env_files = [".env", ".env.local", ".env.development", ".env.production"];
            let mut total_issues = 0;
            let mut output = String::new();

            for filename in &env_files {
                let path = self.project_dir.join(filename);
                if !path.exists() {
                    continue;
                }

                match DotenvFile::parse_file(&path) {
                    Ok(dotenv) => {
                        let real = dotenv.real_secret_entries();
                        if !real.is_empty() {
                            output.push_str(&format!(
                                "{}: {} unprotected secret(s)\n",
                                filename,
                                real.len()
                            ));
                            for entry in &real {
                                output.push_str(&format!("  - {}\n", entry.key));
                            }
                            total_issues += real.len();
                        }
                    }
                    Err(e) => {
                        output.push_str(&format!("{}: failed to parse ({})\n", filename, e));
                    }
                }
            }

            if total_issues == 0 {
                text_result("No issues found. All .env files are clean.")
            } else {
                output
                    .push_str("\nRun `phantom init` to protect these secrets with phantom tokens.");
                text_result(format!(
                    "Found {} unprotected secret(s) across .env files:\n\n{}",
                    total_issues, output
                ))
            }
        }
    }

    /// Generate a .env.example file from the current .env.
    #[tool(
        description = "Generate a .env.example file from .env. Secrets are replaced with descriptive placeholders; non-secret config values are preserved. Safe to commit to version control."
    )]
    fn phantom_env(
        &self,
        Parameters(params): Parameters<EnvParams>,
    ) -> Result<CallToolResult, McpError> {
        require_confirm("phantom_env", params.confirm)?;
        let env_path = self.env_path();
        let params_json = serde_json::to_string(&params).unwrap_or_default();
        require_approval_token("phantom_env", params.approval_token.as_deref(), &params_json, &self.project_id())?;

        let dotenv = DotenvFile::parse_file(&env_path)
            .map_err(|e| internal_err(format!("Failed to read .env: {e}")))?;

        let config = self.load_config().ok();

        let content = dotenv.generate_example_content(config.as_ref());

        let output_path = self.project_dir.join(&params.output);
        std::fs::write(&output_path, &content)
            .map_err(|e| internal_err(format!("Failed to write {}: {e}", params.output)))?;

        let entry_count = dotenv.entries().len();
        let secret_count = dotenv.real_secret_entries().len()
            + dotenv.entries().iter().filter(|e| e.is_phantom).count();

        text_result(format!(
            "Generated {} with {} entries ({} secrets replaced with placeholders).",
            params.output, entry_count, secret_count
        ))
    }

    /// Show what would be synced to deployment platforms and the current sync configuration.
    #[tool(
        description = "Show sync configuration and what secrets would be synced to deployment platforms (Vercel, Railway). This is an informational tool — actual sync requires platform API tokens. Use it to understand and explain the sync setup."
    )]
    fn phantom_sync(
        &self,
        Parameters(params): Parameters<SyncParams>,
    ) -> Result<CallToolResult, McpError> {
        let (config, vault) = self.load_config_and_vault()?;
        let secret_names = vault
            .list()
            .map_err(|e| internal_err(format!("Failed to list secrets: {e}")))?;

        // Filter sync targets by platform if specified
        let targets: Vec<_> = if let Some(ref platform_filter) = params.platform {
            let filter_lower = platform_filter.to_lowercase();
            config
                .sync
                .iter()
                .filter(|t| t.platform.to_string() == filter_lower)
                .collect()
        } else {
            config.sync.iter().collect()
        };

        if targets.is_empty() && config.sync.is_empty() {
            let mut output = String::from("No sync targets configured.\n\n");
            output.push_str("To add a sync target, add a [[sync]] section to .phantom.toml:\n\n");
            output.push_str("  [[sync]]\n");
            output.push_str("  platform = \"vercel\"\n");
            output.push_str("  token_env = \"VERCEL_TOKEN\"\n");
            output.push_str("  project_id = \"prj_xxxxx\"\n");
            output.push_str("  targets = [\"production\", \"preview\"]\n\n");
            output.push_str("  [[sync]]\n");
            output.push_str("  platform = \"railway\"\n");
            output.push_str("  token_env = \"RAILWAY_TOKEN\"\n");
            output.push_str("  project_id = \"your-railway-project-id\"\n");
            if !secret_names.is_empty() {
                output.push_str(&format!(
                    "\n{} secret(s) in vault that would be synced once configured.",
                    secret_names.len()
                ));
            }
            return text_result(output);
        }

        if targets.is_empty() {
            return text_result(format!(
                "No sync targets match platform '{}'. Configured platforms: {}",
                params.platform.as_deref().unwrap_or(""),
                config
                    .sync
                    .iter()
                    .map(|t| t.platform.to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }

        let mut output = format!(
            "Sync configuration ({} target(s), {} secret(s) in vault):\n\n",
            targets.len(),
            secret_names.len()
        );

        for target in &targets {
            let project_id = params.project_id.as_deref().unwrap_or(&target.project_id);

            output.push_str(&format!("Platform: {}\n", target.platform));
            output.push_str(&format!("  Project ID: {}\n", project_id));
            output.push_str(&format!("  Token env var: {}\n", target.token_env));
            output.push_str(&format!(
                "  Target environments: {}\n",
                target.targets.join(", ")
            ));

            if let Some(ref svc_id) = target.service_id {
                output.push_str(&format!("  Service ID: {}\n", svc_id));
            }
            if let Some(ref env_id) = target.environment_id {
                output.push_str(&format!("  Environment ID: {}\n", env_id));
            }

            output.push_str("  Secrets to sync:\n");
            if secret_names.is_empty() {
                output.push_str("    (none — vault is empty)\n");
            } else {
                for name in &secret_names {
                    output.push_str(&format!("    - {}\n", name));
                }
            }
            output.push('\n');
        }

        output.push_str(
            "Note: Actual sync requires platform API tokens. Run `phantom sync` in the CLI to execute.",
        );

        text_result(output)
    }

    /// Check cloud auth and sync status.
    #[tool(description = "Check Phantom Cloud authentication status, plan, and last sync version.")]
    async fn phantom_cloud_status(&self) -> Result<CallToolResult, McpError> {
        let api_base = phantom_core::auth::api_base_url()
            .map_err(|e| internal_err(format!("Invalid cloud API URL: {e}")))?;

        let status = match phantom_core::auth::load_token() {
            Some(token) => match phantom_core::auth::get_user_info(&api_base, &token).await {
                Ok(user) => {
                    let mut s =
                        format!("Cloud: logged in as @{} ({})", user.github_login, user.plan);
                    if let Some(count) = user.vaults_count {
                        s.push_str(&format!("\nVaults: {count}"));
                    }
                    s
                }
                Err(_) => {
                    "Cloud: token expired. Run `phantom login` to re-authenticate.".to_string()
                }
            },
            None => "Cloud: not logged in. Run `phantom login` to enable cloud sync.".to_string(),
        };

        let config_status = if let Ok(config) = self.load_config() {
            if let Some(cloud) = &config.cloud {
                format!("\nLast synced version: {}", cloud.version)
            } else {
                "\nNo cloud sync history for this project.".to_string()
            }
        } else {
            String::new()
        };

        text_result(format!("{status}{config_status}"))
    }

    // ── Team operations ────────────────────────────────────────────────
    //
    // These tools wrap the `phantom team …` CLI surface so an AI agent
    // can drive the entire team-vault flow (sign in, list, create,
    // invite, register key, push, pull) without dropping to the shell.

    /// List teams the user belongs to.
    #[tool(
        description = "List teams the authenticated user belongs to. Returns team id, name, and the user's role for each. Read-only."
    )]
    async fn phantom_team_list(&self) -> Result<CallToolResult, McpError> {
        let token = phantom_core::auth::require_token().map_err(|e| internal_err(e.to_string()))?;
        let api_base =
            phantom_core::auth::api_base_url().map_err(|e| internal_err(e.to_string()))?;
        let teams = phantom_core::teams::list_teams(&api_base, &token)
            .await
            .map_err(|e| internal_err(format!("Failed to list teams: {e}")))?;
        if teams.is_empty() {
            return text_result("No teams yet. Create one with phantom_team_create.".to_string());
        }
        let mut out = format!("{} team(s):\n", teams.len());
        for t in &teams {
            out.push_str(&format!("  {} — \"{}\" ({})\n", t.id, t.name, t.role));
        }
        text_result(out)
    }

    /// Create a new team. Pro-only.
    #[tool(
        description = "Create a new team. The authenticated user becomes the owner. Pro plan required. Mutating: requires confirm:true."
    )]
    async fn phantom_team_create(
        &self,
        Parameters(params): Parameters<TeamCreateParams>,
    ) -> Result<CallToolResult, McpError> {
        require_confirm("phantom_team_create", params.confirm)?;
        let params_json = serde_json::to_string(&params).unwrap_or_default();
        require_approval_token("phantom_team_create", params.approval_token.as_deref(), &params_json, &self.project_id())?;
        let token = phantom_core::auth::require_token().map_err(|e| internal_err(e.to_string()))?;
        let api_base =
            phantom_core::auth::api_base_url().map_err(|e| internal_err(e.to_string()))?;
        let team = phantom_core::teams::create_team(&api_base, &token, &params.name)
            .await
            .map_err(|e| internal_err(format!("Failed to create team: {e}")))?;
        text_result(format!(
            "Created team \"{}\" (id: {}). You are the owner.",
            team.name, team.id
        ))
    }

    /// List members of a team.
    #[tool(
        description = "List members of a team by team_id. Returns GitHub login, email, and role for each member. Read-only."
    )]
    async fn phantom_team_members(
        &self,
        Parameters(params): Parameters<TeamIdParams>,
    ) -> Result<CallToolResult, McpError> {
        let token = phantom_core::auth::require_token().map_err(|e| internal_err(e.to_string()))?;
        let api_base =
            phantom_core::auth::api_base_url().map_err(|e| internal_err(e.to_string()))?;
        let members = phantom_core::teams::list_members(&api_base, &token, &params.team_id)
            .await
            .map_err(|e| internal_err(format!("Failed to list members: {e}")))?;
        if members.is_empty() {
            return text_result(
                "No members yet. Invite someone with phantom_team_invite.".to_string(),
            );
        }
        let mut out = format!("{} member(s):\n", members.len());
        for m in &members {
            let email = m
                .email
                .as_deref()
                .map(|e| format!(" <{e}>"))
                .unwrap_or_default();
            out.push_str(&format!("  @{}{} ({})\n", m.github_login, email, m.role));
        }
        text_result(out)
    }

    /// Invite someone to a team by GitHub username.
    #[tool(
        description = "Invite someone to a team by GitHub username. Requires owner or admin role. Mutating: requires confirm:true."
    )]
    async fn phantom_team_invite(
        &self,
        Parameters(params): Parameters<TeamInviteParams>,
    ) -> Result<CallToolResult, McpError> {
        require_confirm("phantom_team_invite", params.confirm)?;
        let params_json = serde_json::to_string(&params).unwrap_or_default();
        require_approval_token("phantom_team_invite", params.approval_token.as_deref(), &params_json, &self.project_id())?;
        let role = params.role.as_str();
        if !matches!(role, "member" | "admin" | "owner") {
            return Err(invalid_params_err(format!(
                "role must be 'member', 'admin', or 'owner'; got '{role}'"
            )));
        }
        let token = phantom_core::auth::require_token().map_err(|e| internal_err(e.to_string()))?;
        let api_base =
            phantom_core::auth::api_base_url().map_err(|e| internal_err(e.to_string()))?;
        phantom_core::teams::invite_member(
            &api_base,
            &token,
            &params.team_id,
            &params.github_login,
            role,
        )
        .await
        .map_err(|e| internal_err(format!("Failed to invite: {e}")))?;
        text_result(format!(
            "Invited @{} to team {} as {}.",
            params.github_login, params.team_id, role
        ))
    }

    /// Register the user's X25519 public key on a team.
    #[tool(
        description = "One-time setup: register this device's public key with the team so you can send and receive encrypted vaults. Must be called before phantom_team_vault_push or phantom_team_vault_pull. Idempotent — safe to call again after a key rotation."
    )]
    async fn phantom_team_key_publish(
        &self,
        Parameters(params): Parameters<TeamIdParams>,
    ) -> Result<CallToolResult, McpError> {
        require_confirm("phantom_team_key_publish", params.confirm)?;
        let params_json = serde_json::to_string(&params).unwrap_or_default();
        require_approval_token("phantom_team_key_publish", params.approval_token.as_deref(), &params_json, &self.project_id())?;
        let token = phantom_core::auth::require_token().map_err(|e| internal_err(e.to_string()))?;
        let api_base =
            phantom_core::auth::api_base_url().map_err(|e| internal_err(e.to_string()))?;
        let kp = phantom_core::auth::get_or_create_team_keypair()
            .map_err(|e| internal_err(format!("Failed to load team keypair: {e}")))?;
        phantom_core::teams::register_team_key(
            &api_base,
            &token,
            &params.team_id,
            &kp.public_b64(),
        )
        .await
        .map_err(|e| internal_err(format!("Failed to register key: {e}")))?;
        text_result(format!(
            "Public key registered for team id {}.",
            params.team_id
        ))
    }

    /// Push the current project's vault to a team.
    #[tool(
        description = "Push this project's secrets to the shared team vault so all members can pull them. Encrypts client-side for each member who has registered a key (phantom_team_key_publish). Mutating: requires confirm:true."
    )]
    async fn phantom_team_vault_push(
        &self,
        Parameters(params): Parameters<TeamVaultParams>,
    ) -> Result<CallToolResult, McpError> {
        require_confirm("phantom_team_vault_push", params.confirm)?;
        let params_json = serde_json::to_string(&params).unwrap_or_default();
        require_approval_token("phantom_team_vault_push", params.approval_token.as_deref(), &params_json, &self.project_id())?;
        use std::collections::BTreeMap;
        use zeroize::Zeroizing;

        let token = phantom_core::auth::require_token().map_err(|e| internal_err(e.to_string()))?;
        let api_base =
            phantom_core::auth::api_base_url().map_err(|e| internal_err(e.to_string()))?;
        let kp = phantom_core::auth::get_or_create_team_keypair()
            .map_err(|e| internal_err(format!("Failed to load team keypair: {e}")))?;

        let (config, vault) = self.load_config_and_vault()?;
        let project_id = config.phantom.project_id.clone();

        let names = vault
            .list()
            .map_err(|e| internal_err(format!("Failed to list vault: {e}")))?;
        if names.is_empty() {
            return text_result("No secrets in this project's vault to push.".to_string());
        }
        let mut secrets: BTreeMap<String, Zeroizing<String>> = BTreeMap::new();
        for name in &names {
            let value = vault
                .retrieve(name)
                .map_err(|e| internal_err(format!("Failed to retrieve {name}: {e}")))?;
            secrets.insert(name.clone(), Zeroizing::new(String::from(value.as_str())));
        }

        let outcome = phantom_core::teams_vault::push_for_project(
            &api_base,
            &token,
            &params.team_id,
            &project_id,
            secrets,
            &kp,
        )
        .await
        .map_err(|e| internal_err(e.to_string()))?;

        let suffix = if outcome.skipped > 0 {
            format!(
                " ({} member(s) skipped — no public key registered yet)",
                outcome.skipped
            )
        } else {
            String::new()
        };
        text_result(format!(
            "Pushed {} secret(s) to team id {} as v{}, encrypted for {} member(s).{suffix}",
            outcome.secret_count, params.team_id, outcome.new_version, outcome.recipients
        ))
    }

    // ── TTL / Expiry tools ─────────────────────────────────────────────

    /// Rotate all phantom tokens and set a TTL (expiry) on every secret.
    #[tool(
        description = "Rotate all phantom tokens and set a TTL on every secret. \
            Sets `expires_at = now + days_ttl * 86400` and stores a `rotation_policy` \
            on each vault entry. After this call, use `phantom_list_with_expiry` to see \
            countdown status and `phantom_doctor` to get warned when secrets approach expiry. \
            DESTRUCTIVE — invalidates all current phantom tokens; requires `confirm: true`."
    )]
    fn phantom_rotate_with_expiry(
        &self,
        Parameters(params): Parameters<RotateWithExpiryParams>,
    ) -> Result<CallToolResult, McpError> {
        require_confirm("phantom_rotate_with_expiry", params.confirm)?;
        let params_json = serde_json::to_string(&params).unwrap_or_default();
        require_approval_token("phantom_rotate_with_expiry", params.approval_token.as_deref(), &params_json, &self.project_id())?;

        if params.days_ttl == 0 {
            return Err(invalid_params_err("days_ttl must be > 0"));
        }

        let (_config, vault) = self.load_config_and_vault()?;
        let names = vault
            .list()
            .map_err(|e| internal_err(format!("Failed to list secrets: {e}")))?;

        if names.is_empty() {
            return text_result("No secrets to rotate.");
        }

        // Regenerate phantom tokens
        use phantom_core::token::TokenMap;
        let mut token_map = TokenMap::new();
        for name in &names {
            token_map.insert(name.clone());
        }

        let env_path = self.env_path();
        if env_path.exists() {
            let dotenv = phantom_core::dotenv::DotenvFile::parse_file(&env_path)
                .map_err(|e| internal_err(format!("Failed to read .env: {e}")))?;
            dotenv
                .write_phantomized(&token_map, &env_path)
                .map_err(|e| internal_err(format!("Failed to rewrite .env: {e}")))?;
        }

        // Set rotation policy on every secret
        let mut failed = Vec::new();
        for name in &names {
            if let Err(e) = vault.set_rotation_policy(name, params.days_ttl) {
                failed.push(format!("{name}: {e}"));
            }
        }

        if !failed.is_empty() {
            return Err(internal_err(format!(
                "Failed to set expiry on: {}",
                failed.join(", ")
            )));
        }

        text_result(format!(
            "Rotated {} phantom token(s) and set {}-day TTL on all secrets.\n\
             Use phantom_list_with_expiry to see countdown status.",
            names.len(),
            params.days_ttl
        ))
    }

    /// List secrets with TTL/expiry countdown.
    #[tool(
        description = "List all secret names with their TTL/expiry status. \
            Shows days remaining, EXPIRED flag, or 'no expiry' for each secret. \
            Never returns secret values. Use after `phantom_rotate_with_expiry` to \
            confirm TTL was applied, or to audit which secrets are approaching expiry."
    )]
    fn phantom_list_with_expiry(
        &self,
        Parameters(params): Parameters<ListWithExpiryParams>,
    ) -> Result<CallToolResult, McpError> {
        let (config, vault) = self.load_config_and_vault()?;

        let entries = vault
            .list_with_metadata()
            .map_err(|e| internal_err(format!("Failed to list secrets: {e}")))?;

        if entries.is_empty() {
            return text_result("No secrets stored in vault.");
        }

        let mut output = format!("{} secret(s) in vault:\n", entries.len());
        let mut expired_count = 0usize;
        let mut expiring_soon_count = 0usize;

        for (name, meta) in &entries {
            let service = config
                .services
                .iter()
                .find(|(_, c)| c.secret_key == *name)
                .map(|(svc_name, _)| format!(" (service: {svc_name})"));

            let ttl_info = if params.show_expiry {
                match meta {
                    Some(m) => {
                        if m.is_expired() {
                            expired_count += 1;
                            format!(" [EXPIRED]")
                        } else if m.is_expiring_soon(7) {
                            expiring_soon_count += 1;
                            format!(" [{}]", m.ttl_status())
                        } else {
                            format!(" [{}]", m.ttl_status())
                        }
                    }
                    None => " [no expiry]".to_string(),
                }
            } else {
                String::new()
            };

            output.push_str(&format!(
                "  - {}{}{}\n",
                name,
                ttl_info,
                service.unwrap_or_default()
            ));
        }

        if params.show_expiry && (expired_count > 0 || expiring_soon_count > 0) {
            output.push('\n');
            if expired_count > 0 {
                output.push_str(&format!(
                    "WARNING: {expired_count} secret(s) are EXPIRED — rotate immediately.\n"
                ));
            }
            if expiring_soon_count > 0 {
                output.push_str(&format!(
                    "WARNING: {expiring_soon_count} secret(s) expire within 7 days.\n"
                ));
            }
            output.push_str("Run phantom_rotate_with_expiry to refresh TTLs.");
        }

        text_result(output)
    }

    /// Aggregate access statistics and anomaly scores from the HMAC-chained audit log.
    #[tool(
        description = "Aggregate access counts, last-access timestamps, daily averages, and anomaly \
            scores from the HMAC-chained audit log. Returns JSON only — never exposes secret values. \
            Anomaly detection flags: (1) any single day with >3× the daily average access count \
            (score 0.6); (2) first access after ≥7 days of inactivity (score 0.5). \
            Use period to limit the window (\"7d\", \"30d\", \"all\"). \
            Use min_anomaly_score to filter to flagged secrets only (e.g. 0.5). \
            Requires PHANTOM_AUDIT=1 to have been set when secrets were accessed."
    )]
    fn phantom_audit_stats(
        &self,
        Parameters(params): Parameters<AuditStatsParams>,
    ) -> Result<CallToolResult, McpError> {
        let period = phantom_core::analytics::Period::parse(&params.period).ok_or_else(|| {
            crate::tools::helpers::invalid_params_err(format!(
                "Invalid period '{}'. Use: 7d, 30d, or all",
                params.period
            ))
        })?;

        let report = phantom_core::analytics::compute_analytics(period)
            .map_err(|e| crate::tools::helpers::internal_err(format!("Failed to compute analytics: {e}")))?;

        let secrets: Vec<&phantom_core::analytics::SecretAnalytics> = report
            .secrets
            .iter()
            .filter(|s| {
                params
                    .min_anomaly_score
                    .map_or(true, |min| s.anomaly_score >= min)
            })
            .collect();

        let out = serde_json::json!({
            "generated_at": report.generated_at,
            "secrets": secrets,
        });

        let json_str = serde_json::to_string_pretty(&out)
            .map_err(|e| crate::tools::helpers::internal_err(format!("Serialization error: {e}")))?;

        crate::tools::helpers::text_result(json_str)
    }

    // ── Audit & Compliance tools ───────────────────────────────────────

    /// List the last N audit events, never exposing secret values.
    #[tool(
        description = "List the last N audit events from the HMAC-chained audit log. \
            Returns structured JSONL — each line is a JSON object with fields: \
            seq, ts (Unix epoch), op (operation name), name (secret name, if applicable), \
            pid, process. Secret VALUES are never recorded in the audit log and \
            will never appear here. Supports optional filtering by op prefix or \
            exact secret name. Read-only; no confirm required. \
            Requires PHANTOM_AUDIT=1 to have been set when operations were performed."
    )]
    fn phantom_audit_recent(
        &self,
        Parameters(params): Parameters<AuditRecentParams>,
    ) -> Result<CallToolResult, McpError> {
        let n = params.n.min(200).max(1);

        let log_path = phantom_core::audit::log_path()
            .map_err(|e| internal_err(format!("Cannot resolve audit log path: {e}")))?;

        if !log_path.exists() {
            let out = serde_json::json!({
                "events": [],
                "total_returned": 0,
                "note": "Audit log does not exist. Set PHANTOM_AUDIT=1 to enable logging."
            });
            return text_result(serde_json::to_string_pretty(&out)
                .map_err(|e| internal_err(format!("Serialization error: {e}")))?);
        }

        let content = std::fs::read_to_string(&log_path)
            .map_err(|e| internal_err(format!("Failed to read audit log: {e}")))?;

        // Parse all non-marker, non-malformed lines, collecting relevant fields only.
        // NEVER include "value" or any secret material.
        let mut events: Vec<serde_json::Value> = Vec::new();
        for raw in content.lines() {
            let trimmed = raw.trim();
            if trimmed.is_empty() {
                continue;
            }
            let v: serde_json::Value = match serde_json::from_str(trimmed) {
                Ok(v) => v,
                Err(_) => continue,
            };
            // Skip chain-started marker lines.
            if v.get("hmac_chain_started_at").is_some() {
                continue;
            }
            // Must have an "op" field to be a real event.
            let op = match v.get("op").and_then(|o| o.as_str()) {
                Some(op) => op.to_string(),
                None => continue,
            };

            // Apply op_filter
            if let Some(ref filter) = params.op_filter {
                if !op.starts_with(filter.as_str()) {
                    continue;
                }
            }

            // Apply name_filter
            let name = v.get("name").and_then(|n| n.as_str()).map(|s| s.to_string());
            if let Some(ref nf) = params.name_filter {
                match &name {
                    Some(n) if n == nf => {}
                    _ => continue,
                }
            }

            // Build a safe output object — explicitly whitelist fields, never include values.
            let mut obj = serde_json::Map::new();
            for field in &["seq", "ts", "pid", "process"] {
                if let Some(val) = v.get(*field) {
                    obj.insert(field.to_string(), val.clone());
                }
            }
            obj.insert("op".to_string(), serde_json::Value::String(op));
            if let Some(ref n) = name {
                obj.insert("name".to_string(), serde_json::Value::String(n.clone()));
            }

            events.push(serde_json::Value::Object(obj));
        }

        // Take the last N events.
        let total_in_log = events.len();
        if events.len() > n {
            let start = events.len() - n;
            events = events.into_iter().skip(start).collect();
        }

        let out = serde_json::json!({
            "events": events,
            "total_returned": events.len(),
            "total_in_log": total_in_log,
        });

        text_result(serde_json::to_string_pretty(&out)
            .map_err(|e| internal_err(format!("Serialization error: {e}")))?)
    }

    /// Query for suspicious access patterns in the audit log.
    #[tool(
        description = "Query the audit log for suspicious access patterns. \
            Returns a findings array where each entry has: name (secret name), \
            anomaly_type (spike | dormant | first_access), anomaly_score (0.0–1.0), \
            access_count, last_access (ISO-8601), daily_avg, and context (human-readable \
            explanation). Secret VALUES are never returned. Read-only; no confirm required. \
            Anomaly types: 'spike' = single day >3x daily average; \
            'dormant' = access after >=7 consecutive quiet days. \
            Use min_score to filter (default 0.4). Use period to limit the window."
    )]
    fn phantom_audit_anomalies(
        &self,
        Parameters(params): Parameters<AuditAnomaliesParams>,
    ) -> Result<CallToolResult, McpError> {
        let period =
            phantom_core::analytics::Period::parse(&params.period).ok_or_else(|| {
                invalid_params_err(format!(
                    "Invalid period '{}'. Use: 7d, 30d, or all",
                    params.period
                ))
            })?;

        let report = phantom_core::analytics::compute_analytics(period)
            .map_err(|e| internal_err(format!("Failed to compute analytics: {e}")))?;

        let findings: Vec<serde_json::Value> = report
            .secrets
            .iter()
            .filter(|s| s.anomaly_score >= params.min_score)
            .map(|s| {
                // Determine anomaly type(s) from score thresholds.
                let anomaly_type = if s.anomaly_score >= 0.6 {
                    "spike"
                } else if s.anomaly_score >= 0.5 {
                    "dormant"
                } else {
                    "elevated"
                };

                let context = if s.anomaly_score >= 0.6 {
                    format!(
                        "Access spike detected: max single-day count {} vs daily average {:.2}. \
                         Investigate whether this volume is expected.",
                        s.max_daily, s.daily_avg
                    )
                } else if s.anomaly_score >= 0.5 {
                    format!(
                        "Secret accessed after a dormant period (>=7 quiet days). \
                         Last access: {}. Total accesses: {}.",
                        phantom_core::analytics::unix_to_iso8601(s.last_access),
                        s.access_count
                    )
                } else {
                    format!(
                        "Elevated anomaly score {:.2}. access_count={}, daily_avg={:.2}",
                        s.anomaly_score, s.access_count, s.daily_avg
                    )
                };

                serde_json::json!({
                    "name": s.name,
                    "anomaly_type": anomaly_type,
                    "anomaly_score": s.anomaly_score,
                    "access_count": s.access_count,
                    "last_access": phantom_core::analytics::unix_to_iso8601(s.last_access),
                    "daily_avg": s.daily_avg,
                    "max_daily": s.max_daily,
                    "context": context,
                })
            })
            .collect();

        let out = serde_json::json!({
            "generated_at": report.generated_at,
            "period": params.period,
            "min_score": params.min_score,
            "findings": findings,
            "total_findings": findings.len(),
        });

        text_result(serde_json::to_string_pretty(&out)
            .map_err(|e| internal_err(format!("Serialization error: {e}")))?)
    }

    /// Real-time windowed anomaly check — safe for AI agent polling.
    #[tool(
        description = "Check whether a secret (or all secrets) has been accessed unusually \
            based on windowed rate and quiet-period analysis of the current audit log. \
            Unlike phantom_audit_anomalies (which uses multi-day daily-bucket statistics), \
            this tool evaluates: (1) accesses within the last rolling hour vs \
            max_accesses_per_hour threshold; (2) re-access after a quiet period longer than \
            max_consecutive_quiet_days. Returns a findings array with fields: name, \
            anomaly_score (0.0–1.0), alert (bool), reason (string), accesses_last_hour, \
            max_quiet_gap_days. Secret VALUES are never returned. Read-only; no confirm required. \
            Use threshold (default 0.5) to filter results. Pass name to check a single secret. \
            Per-secret overrides from .phantom.toml [phantom.secrets.{name}.audit] are respected \
            when max_accesses_per_hour / max_consecutive_quiet_days are omitted."
    )]
    fn phantom_audit_anomalies_realtime(
        &self,
        Parameters(params): Parameters<AuditAnomaliesRealtimeParams>,
    ) -> Result<CallToolResult, McpError> {
        use phantom_core::analytics::{AuditThresholdConfig, compute_windowed_anomalies};

        let threshold = params.threshold.clamp(0.0, 1.0);

        // Build threshold config from MCP params (if either override is set).
        let thresholds = if params.max_accesses_per_hour.is_some()
            || params.max_consecutive_quiet_days.is_some()
        {
            Some(AuditThresholdConfig {
                max_accesses_per_hour: params.max_accesses_per_hour,
                max_consecutive_quiet_days: params.max_consecutive_quiet_days,
                alert_on_anomaly_score: Some(threshold),
            })
        } else {
            None
        };

        let results = compute_windowed_anomalies(
            params.name.as_deref(),
            thresholds.as_ref(),
            threshold,
        )
        .map_err(|e| internal_err(format!("Failed to compute windowed anomalies: {e}")))?;

        let findings: Vec<serde_json::Value> = results
            .iter()
            .filter(|r| r.anomaly_score >= threshold)
            .map(|r| {
                serde_json::json!({
                    "name": r.name,
                    "anomaly_score": r.anomaly_score,
                    "alert": r.alert,
                    "reason": r.reason,
                    "accesses_last_hour": r.accesses_last_hour,
                    "max_quiet_gap_days": r.max_quiet_gap_days,
                })
            })
            .collect();

        let now_ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let out = serde_json::json!({
            "checked_at": phantom_core::analytics::unix_to_iso8601(now_ts),
            "threshold": threshold,
            "name_filter": params.name,
            "findings": findings,
            "total_findings": findings.len(),
        });

        text_result(
            serde_json::to_string_pretty(&out)
                .map_err(|e| internal_err(format!("Serialization error: {e}")))?,
        )
    }

    /// Full audit analytics export for external dashboards (Datadog, Grafana, CloudWatch).
    #[tool(
        description = "Export full audit analytics for compliance dashboards. \
            Returns per-secret SecretAnalytics (access_count, daily_avg, max_daily, \
            min_daily, anomaly_score) plus timestamped AccessRecords for the requested \
            window. Supports JSON or CSV format. Use min_anomaly_score to filter to \
            flagged secrets only. Never exposes secret values. \
            Feed the output to Datadog, Grafana, CloudWatch, or any BI tool. \
            window_days=0 returns all history; default is 30 days. \
            format=\"csv\" produces RFC 4180 CSV; format=\"json\" produces structured JSON \
            with 'analytics' (SecretAnalytics[]) and 'records' (AccessRecord[]) arrays."
    )]
    fn phantom_audit_analytics(
        &self,
        Parameters(params): Parameters<AuditAnalyticsParams>,
    ) -> Result<CallToolResult, McpError> {
        use phantom_core::analytics::{
            compute_analytics, export_records, records_to_csv, Period,
        };

        // Convert window_days to a Period.
        let period = match params.window_days {
            0 => Period::All,
            7 => Period::Days7,
            1..=30 => Period::Days30,
            _ => Period::All,
        };

        let report = compute_analytics(period)
            .map_err(|e| internal_err(format!("Failed to compute analytics: {e}")))?;

        let analytics: Vec<&phantom_core::analytics::SecretAnalytics> = report
            .secrets
            .iter()
            .filter(|s| {
                params
                    .min_anomaly_score
                    .map_or(true, |min| s.anomaly_score >= min)
            })
            .collect();

        let records = export_records(period, params.min_anomaly_score)
            .map_err(|e| internal_err(format!("Failed to export records: {e}")))?;

        if params.format == "csv" {
            let csv = records_to_csv(&records);
            return text_result(csv);
        }

        // Build daily bucket time-series per secret for BI tools.
        let mut daily_buckets: std::collections::BTreeMap<
            String,
            std::collections::BTreeMap<String, u64>,
        > = std::collections::BTreeMap::new();
        for rec in &records {
            let day = phantom_core::analytics::unix_to_iso8601(rec.ts / 86400 * 86400);
            let day_key = &day[..10]; // YYYY-MM-DD
            *daily_buckets
                .entry(rec.name.clone())
                .or_default()
                .entry(day_key.to_string())
                .or_insert(0) += 1;
        }

        let time_series: Vec<serde_json::Value> = daily_buckets
            .iter()
            .map(|(name, days)| {
                let buckets: Vec<serde_json::Value> = days
                    .iter()
                    .map(|(day, count)| serde_json::json!({"date": day, "count": count}))
                    .collect();
                serde_json::json!({"name": name, "daily_buckets": buckets})
            })
            .collect();

        let out = serde_json::json!({
            "generated_at": report.generated_at,
            "window_days": params.window_days,
            "analytics": analytics,
            "records": records,
            "time_series": time_series,
        });

        let json_str = serde_json::to_string_pretty(&out)
            .map_err(|e| internal_err(format!("Serialization error: {e}")))?;
        text_result(json_str)
    }

    /// Read correlated leak incidents without exposing secret values.
    #[tool(
        description = "Return active leak incidents derived from proxy.response_leak audit events. \
            Incidents are correlated by (secret_name, location) within a 24-hour window. \
            min_confidence (default 0.7) filters by confidence score: \
            0.5 = single leak event; 0.95 = same secret leaked >3 times within 1 hour. \
            Each incident includes: incident_id, secret_name (never the value), \
            location_label, first_seen_ts, last_seen_ts, event_count, confidence, remediation. \
            Incidents are cleared automatically when the affected secret is rotated \
            (vault.store event newer than last_seen_ts). Read-only — safe for AI agents."
    )]
    fn phantom_audit_incidents(
        &self,
        Parameters(params): Parameters<AuditIncidentsParams>,
    ) -> Result<CallToolResult, McpError> {
        use phantom_core::leak_correlation::LeakCorrelationEngine;

        let engine = LeakCorrelationEngine::new()
            .map_err(|e| internal_err(format!("Cannot initialise leak correlation engine: {e}")))?;

        // Run correlation to pick up any new events (best-effort; ignore errors).
        let _ = engine.run();

        let incidents = engine
            .active_incidents(params.min_confidence)
            .map_err(|e| internal_err(format!("Failed to read leak incidents: {e}")))?;

        if incidents.is_empty() {
            return text_result(format!(
                "No active leak incidents (min_confidence={:.2}). \
                 Set PHANTOM_AUDIT=1 to enable audit logging.",
                params.min_confidence
            ));
        }

        let out = serde_json::json!({
            "incident_count": incidents.len(),
            "min_confidence": params.min_confidence,
            "incidents": incidents,
        });

        let json_str = serde_json::to_string_pretty(&out)
            .map_err(|e| internal_err(format!("Serialization error: {e}")))?;
        text_result(json_str)
    }

    /// Export raw audit rows or generate a full compliance report.
    #[tool(
        description = "Export audit log data or generate a structured compliance report. \
            Two actions: \
            'export' — return raw audit rows (timestamp, datetime, operation, secret_name, \
            pid, hostname, severity) filtered by date range, secret name, or operation type, \
            in CSV or JSON format; \
            'report' — generate a full compliance report containing: (a) access-frequency \
            heatmap per secret per calendar day, (b) leak-incident timeline with \
            incident_id/secret_name/occurrences, (c) rotation-timing audit showing days since \
            last vault.store per secret, (d) anomaly executive summary of high-score secrets. \
            Use 'from'/'to' (YYYY-MM-DD) to scope the date range. \
            Set 'save: true' to persist the report to ~/.phantom/reports/. \
            Never exposes secret values. Read-only (save=false). Safe for AI agents."
    )]
    fn phantom_audit_export_report(
        &self,
        Parameters(params): Parameters<AuditExportReportParams>,
    ) -> Result<CallToolResult, McpError> {
        use phantom_core::audit_export::{
            AuditExporter, ExportFilter, parse_date_to_ts, parse_date_to_ts_end,
        };

        let exporter = AuditExporter::new()
            .map_err(|e| internal_err(format!("Failed to initialise audit exporter: {e}")))?;

        let from_ts = params.from.as_deref().map(parse_date_to_ts).unwrap_or(0);
        let to_ts = params.to.as_deref().map(parse_date_to_ts_end).unwrap_or(0);

        match params.action.as_str() {
            "export" => {
                let filter = ExportFilter {
                    from_ts,
                    to_ts,
                    secret_name: params.secret_name.clone(),
                    operation: params.operation.clone(),
                    pid: None,
                };
                let rows = exporter
                    .export_rows(&filter)
                    .map_err(|e| internal_err(format!("Export failed: {e}")))?;

                if rows.is_empty() {
                    return text_result(
                        "No audit rows match the requested filters. \
                         Set PHANTOM_AUDIT=1 to enable audit logging."
                            .to_string(),
                    );
                }

                if params.format == "csv" {
                    return text_result(AuditExporter::rows_to_csv(&rows));
                }

                let json = AuditExporter::rows_to_json(&rows)
                    .map_err(|e| internal_err(format!("Serialization error: {e}")))?;
                text_result(json)
            }

            "report" | "" => {
                let report = exporter
                    .generate_compliance_report(from_ts, to_ts)
                    .map_err(|e| internal_err(format!("Report generation failed: {e}")))?;

                let saved_path = if params.save {
                    match exporter.save_report(&report) {
                        Ok(p) => Some(p.to_string_lossy().into_owned()),
                        Err(e) => {
                            // Don't fail the whole call just because save failed.
                            tracing::warn!("Failed to save compliance report: {e}");
                            None
                        }
                    }
                } else {
                    None
                };

                let json = serde_json::to_string_pretty(&report)
                    .map_err(|e| internal_err(format!("Serialization error: {e}")))?;

                if let Some(path) = saved_path {
                    // Prepend a one-line note so the agent sees where it was saved.
                    let output = format!("// saved to: {path}\n{json}");
                    text_result(output)
                } else {
                    text_result(json)
                }
            }

            other => Err(internal_err(format!(
                "Unknown action '{other}'. Use 'export' or 'report'."
            ))),
        }
    }

    /// Return a compliance status badge for the current project.
    #[tool(
        description = "Return the compliance state of the current Phantom project as a \
            structured JSON badge. Checks: vault_accessible (vault can be read), \
            audit_enabled (PHANTOM_AUDIT env var is set), \
            precommit_installed (git pre-commit hook contains phantom check), \
            env_clean (no unprotected real secrets in .env), \
            secrets_have_ttl (all vault secrets have a rotation policy set). \
            Each check is true/false with an optional detail string. \
            Overall 'compliant' is true only when all checks pass. Read-only."
    )]
    fn phantom_compliance_status(
        &self,
        Parameters(_params): Parameters<ComplianceStatusParams>,
    ) -> Result<CallToolResult, McpError> {
        let mut checks: serde_json::Map<String, serde_json::Value> = serde_json::Map::new();
        let mut all_pass = true;

        // Check 1: vault accessible
        let vault_ok = if self.config_path().exists() {
            match self.load_config_and_vault() {
                Ok((_cfg, vault)) => vault.list().is_ok(),
                Err(_) => false,
            }
        } else {
            false
        };
        if !vault_ok { all_pass = false; }
        checks.insert("vault_accessible".to_string(), serde_json::json!({
            "pass": vault_ok,
            "detail": if vault_ok { "Vault backend is reachable." } else { "Vault not accessible — run phantom init." },
        }));

        // Check 2: audit enabled
        let audit_ok = phantom_core::audit::enabled();
        if !audit_ok { all_pass = false; }
        checks.insert("audit_enabled".to_string(), serde_json::json!({
            "pass": audit_ok,
            "detail": if audit_ok { "PHANTOM_AUDIT is set." } else { "Set PHANTOM_AUDIT=1 to enable audit logging." },
        }));

        // Check 3: pre-commit hook installed
        let git_hook = self.project_dir.join(".git/hooks/pre-commit");
        let precommit_ok = if git_hook.exists() {
            std::fs::read_to_string(&git_hook)
                .map(|c| c.contains("phantom"))
                .unwrap_or(false)
        } else {
            false
        };
        if !precommit_ok { all_pass = false; }
        checks.insert("precommit_installed".to_string(), serde_json::json!({
            "pass": precommit_ok,
            "detail": if precommit_ok { "Pre-commit hook includes phantom check." } else { "Run phantom doctor --fix to install the pre-commit hook." },
        }));

        // Check 4: no real secrets in .env
        let env_path = self.env_path();
        let (env_clean, env_detail) = if env_path.exists() {
            match phantom_core::dotenv::DotenvFile::parse_file(&env_path) {
                Ok(dotenv) => {
                    let real = dotenv.real_secret_entries();
                    if real.is_empty() {
                        (true, "No unprotected secrets in .env.".to_string())
                    } else {
                        let names: Vec<&str> = real.iter().map(|e| e.key.as_str()).collect();
                        (false, format!("{} unprotected secret(s): {}", real.len(), names.join(", ")))
                    }
                }
                Err(e) => (false, format!(".env parse error: {e}")),
            }
        } else {
            (true, "No .env file present.".to_string())
        };
        if !env_clean { all_pass = false; }
        checks.insert("env_clean".to_string(), serde_json::json!({
            "pass": env_clean,
            "detail": env_detail,
        }));

        // Check 5: all secrets have TTL
        let (ttl_ok, ttl_detail) = if self.config_path().exists() {
            match self.load_config_and_vault() {
                Ok((_cfg, vault)) => {
                    match vault.list_with_metadata() {
                        Ok(entries) => {
                            let without_ttl: Vec<&str> = entries
                                .iter()
                                .filter(|(_, meta)| {
                                    meta.as_ref().and_then(|m| m.rotation_policy.as_ref()).is_none()
                                })
                                .map(|(name, _)| name.as_str())
                                .collect();
                            if without_ttl.is_empty() {
                                (true, "All secrets have a rotation policy (TTL).".to_string())
                            } else {
                                (false, format!("{} secret(s) have no TTL: {}", without_ttl.len(), without_ttl.join(", ")))
                            }
                        }
                        Err(e) => (false, format!("Failed to list secrets: {e}")),
                    }
                }
                Err(_) => (false, "Vault not accessible.".to_string()),
            }
        } else {
            (false, "Phantom not initialized — run phantom init.".to_string())
        };
        if !ttl_ok { all_pass = false; }
        checks.insert("secrets_have_ttl".to_string(), serde_json::json!({
            "pass": ttl_ok,
            "detail": ttl_detail,
        }));

        let out = serde_json::json!({
            "compliant": all_pass,
            "checks": checks,
        });

        text_result(serde_json::to_string_pretty(&out)
            .map_err(|e| internal_err(format!("Serialization error: {e}")))?)
    }

    /// Query which secrets are due for rotation (TTL approaching or exceeded).
    #[tool(
        description = "Query which secrets in the vault are due for rotation. \
            Returns a JSON object with: due (list of secrets already expired), \
            warning (list of secrets expiring within warn_days, default 7), \
            ok (list of secrets with sufficient TTL remaining), \
            no_ttl (list of secrets with no rotation policy set at all). \
            Each entry has: name, status (expired|warning|ok|no_ttl), \
            days_remaining (null if no TTL), expires_at (ISO-8601 or null). \
            Secret VALUES are never returned. Read-only; no confirm required."
    )]
    fn phantom_secret_rotation_due(
        &self,
        Parameters(params): Parameters<RotationDueParams>,
    ) -> Result<CallToolResult, McpError> {
        let (_config, vault) = self.load_config_and_vault()?;

        let entries = vault
            .list_with_metadata()
            .map_err(|e| internal_err(format!("Failed to list secrets: {e}")))?;

        let mut due: Vec<serde_json::Value> = Vec::new();
        let mut warning: Vec<serde_json::Value> = Vec::new();
        let mut ok: Vec<serde_json::Value> = Vec::new();
        let mut no_ttl: Vec<serde_json::Value> = Vec::new();

        for (name, meta) in &entries {
            match meta {
                None => {
                    no_ttl.push(serde_json::json!({
                        "name": name,
                        "status": "no_ttl",
                        "days_remaining": null,
                        "expires_at": null,
                    }));
                }
                Some(m) => {
                    let expires_iso = m.expires_at.map(phantom_core::analytics::unix_to_iso8601);

                    if m.rotation_policy.is_none() {
                        no_ttl.push(serde_json::json!({
                            "name": name,
                            "status": "no_ttl",
                            "days_remaining": null,
                            "expires_at": expires_iso,
                        }));
                    } else if m.is_expired() {
                        let days = m.days_remaining().unwrap_or(0);
                        due.push(serde_json::json!({
                            "name": name,
                            "status": "expired",
                            "days_remaining": days,
                            "expires_at": expires_iso,
                        }));
                    } else if m.is_expiring_soon(params.warn_days) {
                        let days = m.days_remaining().unwrap_or(0);
                        warning.push(serde_json::json!({
                            "name": name,
                            "status": "warning",
                            "days_remaining": days,
                            "expires_at": expires_iso,
                        }));
                    } else {
                        let days = m.days_remaining();
                        ok.push(serde_json::json!({
                            "name": name,
                            "status": "ok",
                            "days_remaining": days,
                            "expires_at": expires_iso,
                        }));
                    }
                }
            }
        }

        let out = serde_json::json!({
            "warn_days": params.warn_days,
            "due": due,
            "warning": warning,
            "ok": ok,
            "no_ttl": no_ttl,
            "summary": {
                "expired": due.len(),
                "warning": warning.len(),
                "ok": ok.len(),
                "no_ttl": no_ttl.len(),
                "total": entries.len(),
            }
        });

        text_result(serde_json::to_string_pretty(&out)
            .map_err(|e| internal_err(format!("Serialization error: {e}")))?)
    }

    /// Pull a team vault into the current project's local vault.
    #[tool(
        description = "Download and decrypt the team vault for this project into the local vault. Use this (not phantom_cloud_pull) when secrets were shared by a teammate via phantom_team_vault_push. Overwrites local secrets: requires confirm:true."
    )]
    async fn phantom_team_vault_pull(
        &self,
        Parameters(params): Parameters<TeamVaultParams>,
    ) -> Result<CallToolResult, McpError> {
        require_confirm("phantom_team_vault_pull", params.confirm)?;
        let params_json = serde_json::to_string(&params).unwrap_or_default();
        require_approval_token("phantom_team_vault_pull", params.approval_token.as_deref(), &params_json, &self.project_id())?;
        let token = phantom_core::auth::require_token().map_err(|e| internal_err(e.to_string()))?;
        let api_base =
            phantom_core::auth::api_base_url().map_err(|e| internal_err(e.to_string()))?;
        let kp = phantom_core::auth::get_or_create_team_keypair()
            .map_err(|e| internal_err(format!("Failed to load team keypair: {e}")))?;

        let (config, vault) = self.load_config_and_vault()?;
        let project_id = config.phantom.project_id.clone();

        let (secrets, version) = phantom_core::teams_vault::pull_for_project(
            &api_base,
            &token,
            &params.team_id,
            &project_id,
            &kp,
        )
        .await
        .map_err(|e| internal_err(e.to_string()))?;

        let mut written = 0usize;
        for (name, value) in &secrets {
            vault
                .store(name, value)
                .map_err(|e| internal_err(format!("Store {name} failed: {e}")))?;
            written += 1;
        }

        text_result(format!(
            "Pulled {written} secret(s) from team id {} (v{}). Local vault updated.",
            params.team_id, version
        ))
    }

    // ── Validation / drift-detection tools ────────────────────────────

    /// Query the stored validation status for a specific secret (read-only).
    #[tool(
        description = "Query the last-known validation status for a specific secret. \
            Returns: last_check_ts (Unix epoch, 0 = never checked), is_valid (bool), \
            failure_reason (string or null), validator_name (which validator ran), \
            and is_stale (whether the check is older than 24 h). \
            This tool reads persisted ValidationMetadata — it does NOT make a live \
            HTTP request. Use phantom_validate_all to trigger a fresh check. \
            Read-only; no confirm required. Secret VALUES are never returned."
    )]
    fn phantom_validate_secret(
        &self,
        Parameters(params): Parameters<ValidateSecretParams>,
    ) -> Result<CallToolResult, McpError> {
        let (_config, vault) = self.load_config_and_vault()?;

        // Confirm the secret exists.
        let exists = vault
            .exists(&params.name)
            .map_err(|e| internal_err(format!("Vault access failed: {e}")))?;
        if !exists {
            return Err(crate::tools::helpers::invalid_params_err(format!(
                "Secret '{}' not found in vault.",
                params.name
            )));
        }

        // Load validation metadata (may not exist yet — return a "never checked" record).
        let meta = vault
            .get_validation_metadata(&params.name)
            .unwrap_or_default();

        let is_stale = meta.is_stale(phantom_core::validator::DEFAULT_STALE_SECS);

        let out = serde_json::json!({
            "name": params.name,
            "last_check_ts": meta.last_check_ts,
            "is_valid": meta.is_valid,
            "failure_reason": meta.failure_reason,
            "validator_name": meta.validator_name,
            "is_stale": is_stale,
            "never_checked": meta.never_checked(),
        });

        text_result(
            serde_json::to_string_pretty(&out)
                .map_err(|e| internal_err(format!("Serialization error: {e}")))?,
        )
    }

    /// Run live validation checks for all vault secrets and return a compliance report.
    #[tool(
        description = "Run live credential health checks for all secrets in the vault. \
            Each secret is validated against its target API (OpenAI, Stripe, GitHub, \
            Anthropic, AWS, or a generic HTTP check). Returns a JSON compliance report with: \
            total, valid, invalid, unreachable, not_checked counts and per-secret entries \
            (name, validator, status, reason, checked_at). \
            Secret VALUES are never returned or logged. Read-only; no confirm required. \
            Note: this makes real outbound HTTP requests — run during maintenance windows \
            to avoid contributing to rate limits."
    )]
    fn phantom_validate_all(
        &self,
        Parameters(params): Parameters<ValidateAllParams>,
    ) -> Result<CallToolResult, McpError> {
        let (_config, vault) = self.load_config_and_vault()?;

        let names = vault
            .list()
            .map_err(|e| internal_err(format!("Failed to list secrets: {e}")))?;

        if names.is_empty() {
            let out = serde_json::json!({
                "total": 0,
                "valid": 0,
                "invalid": 0,
                "unreachable": 0,
                "not_checked": 0,
                "entries": [],
                "note": "Vault is empty."
            });
            return text_result(
                serde_json::to_string_pretty(&out)
                    .map_err(|e| internal_err(format!("Serialization error: {e}")))?,
            );
        }

        // Retrieve all secrets for validation (zeroized after use).
        let mut secrets: Vec<(String, zeroize::Zeroizing<String>)> = Vec::new();
        for name in &names {
            let value = vault
                .retrieve(name)
                .map_err(|e| internal_err(format!("Failed to retrieve secret '{name}': {e}")))?;
            secrets.push((name.clone(), zeroize::Zeroizing::new(String::from(value.as_str()))));
        }

        let jobs = params.jobs.max(1).min(16);
        let timeout = std::time::Duration::from_secs(10);
        let validators = phantom_core::validator::default_validators();

        let report = phantom_core::validator::run_validation_pipeline(
            secrets, &validators, jobs, timeout,
        );

        // Persist ValidationMetadata for each result so phantom_validate_secret
        // can answer status queries without re-running HTTP checks.
        for entry in &report.entries {
            let meta = match entry.status {
                phantom_core::validator::ValidationStatus::Valid => {
                    phantom_core::validator::ValidationMetadata::mark_valid(&entry.validator)
                }
                phantom_core::validator::ValidationStatus::Invalid => {
                    phantom_core::validator::ValidationMetadata::mark_invalid(
                        &entry.validator,
                        entry.reason.as_deref().unwrap_or("unknown"),
                    )
                }
                phantom_core::validator::ValidationStatus::Unreachable => {
                    phantom_core::validator::ValidationMetadata::mark_unreachable(
                        &entry.validator,
                        entry.reason.as_deref().unwrap_or("unreachable"),
                    )
                }
                _ => continue,
            };
            // Best-effort — don't fail the whole call if metadata persistence fails.
            let _ = vault.set_validation_metadata(&entry.name, meta);
        }

        let out = serde_json::to_string_pretty(&report)
            .map_err(|e| internal_err(format!("Serialization error: {e}")))?;

        text_result(out)
    }

    // ── Validation scheduler tools ────────────────────────────────────────

    /// Get or set the background validation schedule.
    #[tool(
        description = "Get or set the automated background validation schedule. \
            Pass `interval` to update (accepted values: 'hourly', '6h', '12h', 'daily', \
            'daily@2am', 'weekly', 'disabled'). Omit `interval` to read the current \
            schedule and staleness status. Returns schedule, last_run_at, and staleness \
            indicators. Read-only when interval is omitted; no confirm required."
    )]
    fn phantom_validation_schedule(
        &self,
        Parameters(params): Parameters<ValidationScheduleParams>,
    ) -> Result<CallToolResult, McpError> {
        use phantom_core::validation_scheduler::{
            Schedule, SchedulerState, state_file_path,
        };

        let (config, _vault) = self.load_config_and_vault()?;
        let state_path = state_file_path(&config.phantom.project_id);
        let mut state = SchedulerState::load(&state_path)
            .unwrap_or_default();

        // If an interval was provided, update the schedule.
        if let Some(ref interval_str) = params.interval {
            let sched = Schedule::parse(interval_str)
                .map_err(|e| {
                    crate::tools::helpers::invalid_params_err(format!(
                        "Invalid schedule interval: {e}"
                    ))
                })?;
            let description = sched.description();
            state.schedule = Some(sched);
            state.save(&state_path)
                .map_err(|e| internal_err(format!("Failed to persist schedule: {e}")))?;

            return text_result(format!(
                "Validation schedule set to: {description}\nState file: {}",
                state_path.display()
            ));
        }

        // Read-only: return current status.
        let out = serde_json::json!({
            "schedule": state.schedule,
            "schedule_description": state.schedule.as_ref().map(|s| s.description()),
            "last_run_at": state.last_run_at,
            "stale_1h": state.is_stale(3600),
            "stale_24h": state.is_stale(86400),
            "run_count": state.history.len(),
            "last_run": state.last_run,
        });

        text_result(
            serde_json::to_string_pretty(&out)
                .map_err(|e| internal_err(format!("Serialization error: {e}")))?,
        )
    }

    /// Retrieve past validation run history.
    #[tool(
        description = "Retrieve the history of past automated validation runs. \
            Each entry contains: started_at (Unix epoch), finished_at, total, pass, \
            fail, unreachable, not_checked, and an optional error string. \
            Use `limit` (default 20, max 100) to control how many recent entries \
            are returned. Secret VALUES are never returned. Read-only; no confirm required."
    )]
    fn phantom_validation_history(
        &self,
        Parameters(params): Parameters<ValidationHistoryParams>,
    ) -> Result<CallToolResult, McpError> {
        use phantom_core::validation_scheduler::{SchedulerState, state_file_path, MAX_HISTORY};

        let (config, _vault) = self.load_config_and_vault()?;
        let state_path = state_file_path(&config.phantom.project_id);
        let state = SchedulerState::load(&state_path)
            .unwrap_or_default();

        let limit = params.limit.min(MAX_HISTORY);
        let entries: Vec<_> = state.history.iter().rev().take(limit).collect();

        let out = serde_json::json!({
            "total_runs": state.history.len(),
            "returned": entries.len(),
            "entries": entries,
        });

        text_result(
            serde_json::to_string_pretty(&out)
                .map_err(|e| internal_err(format!("Serialization error: {e}")))?,
        )
    }

    // ── Expiry check & auto-rotate tools ─────────────────────────────────

    /// Query the local vault for secrets that are expired or expiring soon.
    #[tool(
        description = "Query the local vault for secrets that are expired or expiring soon. \
            Returns a JSON array where each entry has: name (string), \
            days_remaining (i64 — negative means already expired), \
            expires_at (Unix epoch u64), status (human-readable string). \
            Use the `days` parameter (default 7) to tune the look-ahead window. \
            Secrets with no TTL set are omitted — use phantom_secret_rotation_due \
            to also surface those. Secret VALUES are never returned. Read-only; no confirm required."
    )]
    fn phantom_secrets_expiry_check(
        &self,
        Parameters(params): Parameters<ExpiryCheckParams>,
    ) -> Result<CallToolResult, McpError> {
        let (_config, vault) = self.load_config_and_vault()?;

        let entries = vault
            .list_with_metadata()
            .map_err(|e| internal_err(format!("Failed to list vault metadata: {e}")))?;

        let mut expiring: Vec<serde_json::Value> = entries
            .iter()
            .filter_map(|(name, meta)| {
                let m = meta.as_ref()?;
                let expires_at = m.expires_at?;
                let days_remaining = m.days_remaining()?;
                if days_remaining <= params.days as i64 {
                    Some(serde_json::json!({
                        "name": name,
                        "days_remaining": days_remaining,
                        "expires_at": expires_at,
                        "status": m.ttl_status(),
                    }))
                } else {
                    None
                }
            })
            .collect();

        // Sort most-urgent first.
        expiring.sort_by(|a, b| {
            let da = a["days_remaining"].as_i64().unwrap_or(i64::MAX);
            let db = b["days_remaining"].as_i64().unwrap_or(i64::MAX);
            da.cmp(&db)
        });

        let out = serde_json::json!({
            "days_window": params.days,
            "count": expiring.len(),
            "secrets": expiring,
        });

        text_result(
            serde_json::to_string_pretty(&out)
                .map_err(|e| internal_err(format!("Serialization error: {e}")))?,
        )
    }

    /// Auto-rotate a single secret: extend its TTL metadata and refresh the phantom token.
    #[tool(
        description = "Auto-rotate a named secret: extend its expiry by its existing TTL policy \
            (default 30 days if no policy is set), update `rotated_at` / `expires_at`, and \
            rewrite the .env with a fresh phantom token for that secret. \
            Optionally syncs to all configured deployment platforms (`sync: true`). \
            Emits an audit event `secret.auto_rotated`. \
            MUTATING — rewrites phantom tokens and metadata; requires `confirm: true`. \
            Secret VALUES are never returned or logged."
    )]
    fn phantom_secrets_auto_rotate(
        &self,
        Parameters(params): Parameters<AutoRotateParams>,
    ) -> Result<CallToolResult, McpError> {
        require_confirm("phantom_secrets_auto_rotate", params.confirm)?;
        let params_json = serde_json::to_string(&params).unwrap_or_default();
        require_approval_token("phantom_secrets_auto_rotate", params.approval_token.as_deref(), &params_json, &self.project_id())?;

        let (_config, vault) = self.load_config_and_vault()?;

        // Confirm the secret exists.
        if !vault
            .exists(&params.name)
            .map_err(|e| internal_err(format!("Vault access error: {e}")))?
        {
            return Err(invalid_params_err(format!(
                "Secret '{}' not found in vault.",
                params.name
            )));
        }

        // Load existing metadata to preserve days_ttl.
        let existing_meta = vault
            .get_metadata(&params.name)
            .map_err(|e| internal_err(format!("Failed to read metadata: {e}")))?;

        let days_ttl = existing_meta
            .as_ref()
            .and_then(|m| m.rotation_policy.as_ref())
            .map(|p| p.days_ttl)
            .unwrap_or(30);

        // Build refreshed metadata.
        let now = phantom_vault::metadata::now_secs();
        let new_meta = phantom_vault::metadata::SecretMetadata {
            created_at: existing_meta.as_ref().and_then(|m| m.created_at).or(Some(now)),
            rotated_at: Some(now),
            expires_at: Some(now + days_ttl * 86_400),
            rotation_policy: Some(phantom_vault::metadata::RotationPolicy {
                days_ttl,
                auto_rotate: true,
            }),
            vault_mode: phantom_vault::metadata::VaultMode::ReadWrite,
        };

        vault
            .set_metadata(&params.name, new_meta)
            .map_err(|e| internal_err(format!("Failed to update metadata: {e}")))?;

        phantom_core::audit::log("secret.auto_rotated", Some(&params.name));

        // Rewrite .env with a fresh phantom token for this secret.
        let env_path = self.env_path();
        if env_path.exists() {
            use phantom_core::token::TokenMap;
            let mut token_map = TokenMap::new();
            token_map.insert(params.name.clone());
            if let Ok(dotenv) = phantom_core::dotenv::DotenvFile::parse_file(&env_path) {
                let _ = dotenv.write_phantomized(&token_map, &env_path);
            }
        }

        // Advise on sync if requested (MCP cannot call the CLI sync command directly;
        // the caller should run `phantom sync` after rotating).
        let sync_note = if params.sync {
            " To push the updated token to deployment platforms, run `phantom sync` in the CLI."
        } else {
            ""
        };

        text_result(format!(
            "Auto-rotated '{}': expires_at extended by {days_ttl} day(s) from now.{sync_note}",
            params.name
        ))
    }

    /// Check `.phantom.toml` for expired secrets — returns the list of expired secrets.
    ///
    /// Designed for AI agents that need to trigger rotation workflows when secrets expire.
    /// Read-only; never returns secret values.
    #[tool(
        description = "Scan .phantom.toml for expired secrets and return a structured list. \
            Each entry has: name (string), expires_at (Unix u64), secs_overdue (u64), \
            status (human-readable string). \
            With fail_closed=true, secrets that have no expiry policy set are also included \
            with status='no_expiry_policy'. \
            Returns { expired: [...], ok_count, no_expiry_count, fail_closed, pass }. \
            pass=true means no action is needed. Read-only; no confirm required. \
            Secret VALUES are never returned."
    )]
    fn phantom_expiry_enforce(
        &self,
        Parameters(params): Parameters<PhantomExpiryEnforceParams>,
    ) -> Result<CallToolResult, McpError> {
        use phantom_core::rotation_strategy::{check_expiry, ExpiryStatus};

        let config = self.load_config().map_err(internal_err)?;
        let now = phantom_vault::metadata::now_secs();

        let mut expired: Vec<serde_json::Value> = Vec::new();
        let mut no_expiry_violations: Vec<serde_json::Value> = Vec::new();
        let mut ok_count: usize = 0;
        let mut no_expiry_count: usize = 0;

        for (name, override_cfg) in &config.phantom.secrets {
            match override_cfg.expires_at {
                None => {
                    no_expiry_count += 1;
                    if params.fail_closed {
                        no_expiry_violations.push(serde_json::json!({
                            "name": name,
                            "status": "no_expiry_policy",
                        }));
                    }
                }
                Some(expires_at) => {
                    let status = check_expiry(expires_at, 0, now);
                    if status.is_expired() {
                        let secs_overdue = match &status {
                            ExpiryStatus::Expired { secs_overdue } => *secs_overdue,
                            _ => 0,
                        };
                        expired.push(serde_json::json!({
                            "name": name,
                            "expires_at": expires_at,
                            "secs_overdue": secs_overdue,
                            "status": status.label(),
                        }));
                    } else {
                        ok_count += 1;
                    }
                }
            }
        }

        // Merge no-expiry violations if fail_closed
        let mut all_violations = expired.clone();
        all_violations.extend(no_expiry_violations);

        let pass = all_violations.is_empty();

        let out = serde_json::json!({
            "expired": all_violations,
            "ok_count": ok_count,
            "no_expiry_count": no_expiry_count,
            "fail_closed": params.fail_closed,
            "pass": pass,
        });

        text_result(
            serde_json::to_string_pretty(&out)
                .map_err(|e| internal_err(format!("Serialization error: {e}")))?,
        )
    }

    // ── Rotation schedule next ────────────────────────────────────────────

    /// Return the next scheduled rotation time for a named secret.
    #[tool(
        description = "Return the next scheduled rotation time for a named secret. \
            Reads the secret's effective RotationSchedule (per-secret override or global policy) \
            and computes when rotation is next due. \
            Returns: { name, strategy, next_rotation_unix (u64 or null), \
            next_rotation_iso (ISO-8601 or null), last_rotated_unix (u64 or null), \
            last_rotated_iso (ISO-8601 or null), overdue (bool) }. \
            Read-only; no confirm required. Secret VALUES are never returned."
    )]
    fn phantom_rotation_schedule_next(
        &self,
        Parameters(params): Parameters<RotationScheduleNextParams>,
    ) -> Result<CallToolResult, McpError> {
        use phantom_core::rotation_strategy::next_rotation_after;

        let (config, vault) = self.load_config_and_vault()?;

        // Confirm secret exists.
        let exists = vault
            .exists(&params.name)
            .map_err(|e| internal_err(format!("Vault access failed: {e}")))?;
        if !exists {
            return Err(crate::tools::helpers::invalid_params_err(format!(
                "Secret '{}' not found in vault.",
                params.name
            )));
        }

        let now = phantom_vault::metadata::now_secs();

        let schedule = config.get_rotation_schedule(&params.name);
        let (strategy_label, next_unix, last_rotated_unix, overdue) = match &schedule {
            None => ("none".to_string(), None::<u64>, None::<u64>, false),
            Some(sched) => {
                let next = next_rotation_after(sched, now);
                let last = sched.last_rotated;
                let overdue = sched.should_rotate_now(now);
                (sched.strategy.as_str().to_string(), next, last, overdue)
            }
        };

        let next_iso = next_unix.map(phantom_core::analytics::unix_to_iso8601);
        let last_iso = last_rotated_unix.map(phantom_core::analytics::unix_to_iso8601);

        let out = serde_json::json!({
            "name": params.name,
            "strategy": strategy_label,
            "next_rotation_unix": next_unix,
            "next_rotation_iso": next_iso,
            "last_rotated_unix": last_rotated_unix,
            "last_rotated_iso": last_iso,
            "overdue": overdue,
        });

        text_result(
            serde_json::to_string_pretty(&out)
                .map_err(|e| internal_err(format!("Serialization error: {e}")))?,
        )
    }

    // ── Apply expiry policy (demotion / promotion) ────────────────────────

    /// Scan the vault and demote expired secrets to read-only mode.
    #[tool(
        description = "Scan the vault, apply read-only demotion to secrets whose TTL has expired, \
            and (optionally) re-promote secrets that were demoted but have since been rotated. \
            This is the background enforcement step that prevents stale credentials from being \
            injected by `phantom exec`. \
            Returns: { demoted: [{ name, expires_at, secs_overdue }], \
            promoted: [{ name }], skipped_count, total_scanned }. \
            Requires confirm:true because it writes vault metadata."
    )]
    fn phantom_apply_expiry_policy(
        &self,
        Parameters(params): Parameters<ApplyExpiryPolicyParams>,
    ) -> Result<CallToolResult, McpError> {
        require_confirm("phantom_apply_expiry_policy", params.confirm)?;
        let params_json = serde_json::to_string(&params).unwrap_or_default();
        require_approval_token(
            "phantom_apply_expiry_policy",
            params.approval_token.as_deref(),
            &params_json,
            &self.project_id(),
        )?;

        use phantom_vault::metadata::VaultMode;

        let (_config, vault) = self.load_config_and_vault()?;
        let now = phantom_vault::metadata::now_secs();

        let entries = vault
            .list_with_metadata()
            .map_err(|e| internal_err(format!("Failed to list secrets: {e}")))?;

        let mut demoted: Vec<serde_json::Value> = Vec::new();
        let mut promoted: Vec<serde_json::Value> = Vec::new();
        let mut skipped_count: usize = 0;

        for (name, meta_opt) in &entries {
            let Some(meta) = meta_opt else {
                skipped_count += 1;
                continue;
            };

            // Check promotion path first: was demoted but has since been rotated.
            if params.also_promote_rotated
                && meta.vault_mode.is_read_only()
            {
                let rotated_after_expiry = match (meta.rotated_at, meta.expires_at) {
                    (Some(r), Some(e)) => r > e,
                    _ => false,
                };
                if rotated_after_expiry {
                    let mut new_meta = meta.clone();
                    new_meta.vault_mode = VaultMode::ReadWrite;
                    vault
                        .set_metadata(name, new_meta)
                        .map_err(|e| internal_err(format!("Failed to promote {name}: {e}")))?;
                    phantom_core::audit::log(
                        "secret.expiry_policy.promoted",
                        Some(name),
                    );
                    promoted.push(serde_json::json!({ "name": name }));
                    continue;
                }
            }

            // Demotion path: expired and currently ReadWrite → demote to ReadOnly.
            if !meta.vault_mode.is_read_only() {
                if let Some(exp) = meta.expires_at {
                    if now >= exp {
                        let secs_overdue = now - exp;
                        let mut new_meta = meta.clone();
                        new_meta.vault_mode = VaultMode::ReadOnly;
                        vault
                            .set_metadata(name, new_meta)
                            .map_err(|e| internal_err(format!("Failed to demote {name}: {e}")))?;
                        phantom_core::audit::log(
                            "secret.expiry_policy.demoted",
                            Some(name),
                        );
                        demoted.push(serde_json::json!({
                            "name": name,
                            "expires_at": exp,
                            "secs_overdue": secs_overdue,
                        }));
                        continue;
                    }
                }
            }

            skipped_count += 1;
        }

        let total_scanned = entries.len();
        let out = serde_json::json!({
            "demoted": demoted,
            "promoted": promoted,
            "skipped_count": skipped_count,
            "total_scanned": total_scanned,
        });

        text_result(
            serde_json::to_string_pretty(&out)
                .map_err(|e| internal_err(format!("Serialization error: {e}")))?,
        )
    }
}

#[tool_handler]
impl ServerHandler for PhantomMcpServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build()).with_instructions(
            "Phantom Secrets manager. Securely manages API keys and secrets. \
                 Use phantom_list_secrets to see what's stored (never shows values). \
                 Use phantom_status to check configuration. \
                 Use phantom_init to protect secrets in .env files. \
                 Use phantom_cloud_push/pull to sync vaults to Phantom Cloud (E2E encrypted)."
                .to_string(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use tempfile::TempDir;

    /// Shared lock so that tests mutating HOME do not race each other.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn setup_test_project() -> (PhantomMcpServer, TempDir) {
        // Force file-vault backend for test hermeticity. Without this, Windows CI
        // runners use the OS keychain, which is isolated across test processes and
        // causes vault.retrieve to return "Secret not found" in subsequent tests.
        // SAFETY: test-only passphrase; process-global side effect is intentional —
        // all MCP tests should use the file backend.
        unsafe {
            std::env::set_var(
                "PHANTOM_VAULT_PASSPHRASE",
                "test-passphrase-do-not-use-in-prod",
            );
            // Skip nonce-based approval in unit tests — the approval flow requires
            // an interactive terminal and a real HOME directory. Integration tests
            // that exercise the full approval flow should unset this.
            std::env::set_var("PHANTOM_MCP_SKIP_APPROVAL", "1");
        }

        let dir = TempDir::new().unwrap();

        // Create a .env file with real secrets
        std::fs::write(
            dir.path().join(".env"),
            "OPENAI_API_KEY=sk-test-key\nDATABASE_URL=postgres://user:pass@localhost/db\nNODE_ENV=production\n",
        )
        .unwrap();

        let server = PhantomMcpServer::with_dir(dir.path().to_path_buf());
        (server, dir)
    }

    fn setup_initialized_project() -> (PhantomMcpServer, TempDir) {
        let (server, dir) = setup_test_project();

        // Run init to set up config and vault
        let params = InitParams {
            env_path: ".env".to_string(),
            confirm: true,
            approval_token: None
        };
        let result = server.phantom_init(Parameters(params)).unwrap();
        let text = get_result_text(&result);
        assert!(
            text.contains("protected"),
            "Init should report protected secrets"
        );

        (server, dir)
    }

    fn get_result_text(result: &CallToolResult) -> String {
        // CallToolResult content is serialized — extract text via debug format
        format!("{:?}", result.content)
    }

    #[test]
    fn test_status_before_init() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let (server, _dir) = setup_test_project();
        let result = server.phantom_status().unwrap();
        let text = get_result_text(&result);
        assert!(text.contains("not initialized"));
    }

    #[test]
    fn test_init_protects_secrets() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let (server, dir) = setup_test_project();

        let result = server
            .phantom_init(Parameters(InitParams {
                env_path: ".env".to_string(),
                confirm: true,
            approval_token: None
            }))
            .unwrap();
        let text = get_result_text(&result);

        // Should report protected secrets
        assert!(text.contains("OPENAI_API_KEY"));
        assert!(text.contains("DATABASE_URL"));
        // NODE_ENV should NOT be listed (non-secret)
        assert!(!text.contains("NODE_ENV"));

        // .env should now contain phantom tokens
        let env_content = std::fs::read_to_string(dir.path().join(".env")).unwrap();
        assert!(env_content.contains("phm_"));
        assert!(!env_content.contains("sk-test-key"));
        // NODE_ENV should be unchanged
        assert!(env_content.contains("NODE_ENV=production"));
    }

    #[test]
    fn test_list_secrets_after_init() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let (server, _dir) = setup_initialized_project();
        let result = server.phantom_list_secrets().unwrap();
        let text = get_result_text(&result);
        assert!(text.contains("OPENAI_API_KEY"));
        assert!(text.contains("DATABASE_URL"));
        // Should never show the actual value
        assert!(!text.contains("sk-test-key"));
    }

    #[test]
    fn test_status_after_init() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let (server, _dir) = setup_initialized_project();
        let result = server.phantom_status().unwrap();
        let text = get_result_text(&result);
        assert!(text.contains("Vault backend:"));
        assert!(text.contains("Secrets stored:"));
    }

    #[test]
    fn test_add_secret_params_rejects_plaintext_value_field() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let parsed = serde_json::from_value::<AddSecretParams>(serde_json::json!({
            "name": "NEW_SECRET",
            "value": "new-value-123",
            "confirm": true
        }));
        assert!(parsed.is_err());
    }

    #[test]
    fn test_add_secret_params_schema_omits_value_field() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let schema = schemars::schema_for!(AddSecretParams);
        let value = serde_json::to_value(schema).unwrap();
        let schema_json = serde_json::to_string(&value).unwrap();
        assert!(schema_json.contains("\"name\""));
        assert!(schema_json.contains("\"confirm\""));
        assert!(!schema_json.contains("\"value\""));
    }

    #[test]
    fn test_destructive_tools_require_confirm() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let (server, _dir) = setup_initialized_project();

        let add_err = server
            .phantom_add_secret(Parameters(AddSecretParams {
                name: "X".to_string(),
                confirm: false,
            approval_token: None
            }))
            .unwrap_err();
        assert_eq!(add_err.code, rmcp::model::ErrorCode::INVALID_PARAMS);
        assert!(add_err.message.contains("confirm: true"));

        let rm_err = server
            .phantom_remove_secret(Parameters(RemoveSecretParams {
                name: "OPENAI_API_KEY".to_string(),
                confirm: false,
            approval_token: None
            }))
            .unwrap_err();
        assert_eq!(rm_err.code, rmcp::model::ErrorCode::INVALID_PARAMS);

        let rotate_err = server
            .phantom_rotate(Parameters(RotateParams { confirm: false,
            approval_token: None }))
            .unwrap_err();
        assert_eq!(rotate_err.code, rmcp::model::ErrorCode::INVALID_PARAMS);
    }

    #[test]
    fn test_copy_secret_rejects_without_confirm() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let (server, _dir) = setup_initialized_project();
        let err = server
            .phantom_copy_secret(Parameters(CopySecretParams {
                name: "OPENAI_API_KEY".to_string(),
                target_dir: ".".to_string(),
                rename: None,
                confirm: false,
            approval_token: None
            }))
            .unwrap_err();
        assert_eq!(err.code, rmcp::model::ErrorCode::INVALID_PARAMS);
        assert!(err.message.contains("confirm"));
    }

    #[test]
    fn test_copy_secret_rejects_dot_dot() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let (server, _dir) = setup_initialized_project();
        for bad in [
            "../other",
            "..",
            "foo/../bar",
            "..\\windows",
            "foo\\..\\bar",
        ] {
            let err = server
                .phantom_copy_secret(Parameters(CopySecretParams {
                    name: "OPENAI_API_KEY".to_string(),
                    target_dir: bad.to_string(),
                    rename: None,
                    confirm: true,
            approval_token: None
                }))
                .unwrap_err();
            assert_eq!(
                err.code,
                rmcp::model::ErrorCode::INVALID_PARAMS,
                "input {bad}"
            );
            assert!(err.message.contains(".."), "input {bad}");
        }
    }

    #[test]
    fn test_copy_secret_rejects_unresolvable_target() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let (server, _dir) = setup_initialized_project();
        let err = server
            .phantom_copy_secret(Parameters(CopySecretParams {
                name: "OPENAI_API_KEY".to_string(),
                target_dir: "definitely/does/not/exist".to_string(),
                rename: None,
                confirm: true,
            approval_token: None
            }))
            .unwrap_err();
        assert_eq!(err.code, rmcp::model::ErrorCode::INVALID_PARAMS);
        assert!(err.message.contains("cannot be resolved"));
    }

    #[test]
    fn test_rotate_tokens() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let (server, dir) = setup_initialized_project();

        // Read .env before rotation
        let before = std::fs::read_to_string(dir.path().join(".env")).unwrap();

        // Rotate
        let result = server
            .phantom_rotate(Parameters(RotateParams { confirm: true,
            approval_token: None }))
            .unwrap();
        let text = get_result_text(&result);
        assert!(text.contains("Rotated"));

        // Read .env after rotation — tokens should be different
        let after = std::fs::read_to_string(dir.path().join(".env")).unwrap();
        assert_ne!(before, after, "Tokens should change after rotation");
        assert!(after.contains("phm_"));
    }

    // ── TTL / Expiry MCP tests ────────────────────────────────────────

    #[test]
    fn test_rotate_with_expiry_requires_confirm() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let (server, _dir) = setup_initialized_project();
        let err = server
            .phantom_rotate_with_expiry(Parameters(RotateWithExpiryParams {
                days_ttl: 7,
                confirm: false,
            approval_token: None
            }))
            .unwrap_err();
        assert_eq!(err.code, rmcp::model::ErrorCode::INVALID_PARAMS);
        assert!(err.message.contains("confirm: true"));
    }

    #[test]
    fn test_rotate_with_expiry_rejects_zero_ttl() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let (server, _dir) = setup_initialized_project();
        let err = server
            .phantom_rotate_with_expiry(Parameters(RotateWithExpiryParams {
                days_ttl: 0,
                confirm: true,
            approval_token: None
            }))
            .unwrap_err();
        assert_eq!(err.code, rmcp::model::ErrorCode::INVALID_PARAMS);
    }

    #[test]
    fn test_rotate_with_expiry_sets_ttl_metadata() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let (server, dir) = setup_initialized_project();

        let result = server
            .phantom_rotate_with_expiry(Parameters(RotateWithExpiryParams {
                days_ttl: 7,
                confirm: true,
            approval_token: None
            }))
            .unwrap();
        let text = get_result_text(&result);
        assert!(text.contains("Rotated"), "should report rotation");
        assert!(text.contains("7-day TTL"), "should mention TTL");

        // .env should still have phantom tokens
        let env_content = std::fs::read_to_string(dir.path().join(".env")).unwrap();
        assert!(env_content.contains("phm_"));

        // TTL metadata should be visible via list_with_expiry
        let list_result = server
            .phantom_list_with_expiry(Parameters(ListWithExpiryParams { show_expiry: true }))
            .unwrap();
        let list_text = get_result_text(&list_result);
        assert!(
            list_text.contains("days remaining") || list_text.contains("expires today"),
            "should show days remaining after TTL set: {list_text}"
        );
        assert!(
            !list_text.contains("EXPIRED"),
            "fresh 7-day TTL should not be expired: {list_text}"
        );
    }

    #[test]
    fn test_list_with_expiry_no_ttl_shows_no_expiry() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let (server, _dir) = setup_initialized_project();
        // No TTL set — all secrets should show "no expiry"
        let result = server
            .phantom_list_with_expiry(Parameters(ListWithExpiryParams { show_expiry: true }))
            .unwrap();
        let text = get_result_text(&result);
        assert!(text.contains("no expiry"), "secrets without TTL: {text}");
    }

    #[test]
    fn test_list_with_expiry_show_expiry_false_omits_ttl() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let (server, _dir) = setup_initialized_project();
        let result = server
            .phantom_list_with_expiry(Parameters(ListWithExpiryParams { show_expiry: false }))
            .unwrap();
        let text = get_result_text(&result);
        // With show_expiry=false, no TTL info should appear
        assert!(!text.contains("days remaining"));
        assert!(!text.contains("no expiry"));
        // But secret names should still appear
        assert!(text.contains("OPENAI_API_KEY") || text.contains("DATABASE_URL"));
    }

    // ── Audit & compliance tool tests ─────────────────────────────────

    /// Write synthetic audit log entries to a temp HOME path (no HMAC chain).
    fn write_synthetic_audit_log(home_dir: &std::path::Path, entries: &[(u64, &str, Option<&str>)]) {
        let log_path = home_dir.join(".phantom").join("audit.log");
        std::fs::create_dir_all(log_path.parent().unwrap()).unwrap();
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_path)
            .unwrap();
        for (ts, op, name) in entries {
            let line = if let Some(n) = name {
                format!(
                    r#"{{"seq":1,"ts":{ts},"op":"{op}","name":"{n}","pid":1,"process":"phantom"}}"#
                )
            } else {
                format!(r#"{{"seq":1,"ts":{ts},"op":"{op}","pid":1,"process":"phantom"}}"#)
            };
            writeln!(f, "{}", line).unwrap();
        }
    }

    /// Extract the raw text string from the first Content item in a CallToolResult.
    fn extract_content_text(result: &CallToolResult) -> String {
        use rmcp::model::RawContent;
        result
            .content
            .iter()
            .find_map(|c| {
                if let RawContent::Text(t) = &c.raw {
                    Some(t.text.clone())
                } else {
                    None
                }
            })
            .unwrap_or_default()
    }

    fn parse_result_json(result: &CallToolResult) -> serde_json::Value {
        let text = extract_content_text(result);
        serde_json::from_str(&text).unwrap_or_else(|_| serde_json::json!({}))
    }

    // ── phantom_audit_recent ──────────────────────────────────────────

    #[test]
    fn test_audit_recent_returns_events_key() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let (server, _dir) = setup_initialized_project();
        let home = tempfile::TempDir::new().unwrap();
        let _env_guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _prev_home = std::env::var("HOME").ok();
        unsafe { std::env::set_var("HOME", home.path()) };
        let now = 1_700_000_000_u64;
        write_synthetic_audit_log(
            home.path(),
            &[
                (now - 200, "vault.store", Some("OPENAI_API_KEY")),
                (now - 100, "vault.retrieve", Some("DATABASE_URL")),
                (now - 50, "cloud.push", None),
            ],
        );

        let result = server
            .phantom_audit_recent(Parameters(AuditRecentParams {
                n: 10,
                op_filter: None,
                name_filter: None,
            }))
            .unwrap();

        let json = parse_result_json(&result);
        assert!(json.get("events").is_some(), "must have 'events' key");
        assert!(json.get("total_returned").is_some(), "must have 'total_returned'");
        assert!(json.get("total_in_log").is_some(), "must have 'total_in_log'");
        let events = json["events"].as_array().unwrap();
        assert_eq!(events.len(), 3);
    }

    #[test]
    fn test_audit_recent_never_exposes_secret_values() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let (server, _dir) = setup_initialized_project();
        let home = tempfile::TempDir::new().unwrap();
        let _env_guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _prev_home = std::env::var("HOME").ok();
        unsafe { std::env::set_var("HOME", home.path()) };
        let now = 1_700_000_000_u64;
        write_synthetic_audit_log(
            home.path(),
            &[(now, "vault.store", Some("OPENAI_API_KEY"))],
        );

        let result = server
            .phantom_audit_recent(Parameters(AuditRecentParams {
                n: 10,
                op_filter: None,
                name_filter: None,
            }))
            .unwrap();

        let text = extract_content_text(&result);
        assert!(!text.contains("sk-test-key"), "must not expose secret value");
        assert!(!text.contains("postgres://user:pass"), "must not expose DB credentials");
        assert!(text.contains("OPENAI_API_KEY"), "should contain secret name");
    }

    #[test]
    fn test_audit_recent_op_filter() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let (server, _dir) = setup_initialized_project();
        let home = tempfile::TempDir::new().unwrap();
        let _env_guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _prev_home = std::env::var("HOME").ok();
        unsafe { std::env::set_var("HOME", home.path()) };
        let now = 1_700_000_000_u64;
        write_synthetic_audit_log(
            home.path(),
            &[
                (now - 200, "vault.store", Some("OPENAI_API_KEY")),
                (now - 100, "vault.retrieve", Some("DATABASE_URL")),
                (now - 50, "cloud.push", None),
            ],
        );

        let result = server
            .phantom_audit_recent(Parameters(AuditRecentParams {
                n: 10,
                op_filter: Some("vault.retrieve".to_string()),
                name_filter: None,
            }))
            .unwrap();

        let json = parse_result_json(&result);
        let events = json["events"].as_array().unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0]["op"], "vault.retrieve");
    }

    #[test]
    fn test_audit_recent_name_filter() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let (server, _dir) = setup_initialized_project();
        let home = tempfile::TempDir::new().unwrap();
        let _env_guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _prev_home = std::env::var("HOME").ok();
        unsafe { std::env::set_var("HOME", home.path()) };
        let now = 1_700_000_000_u64;
        write_synthetic_audit_log(
            home.path(),
            &[
                (now - 200, "vault.store", Some("OPENAI_API_KEY")),
                (now - 100, "vault.retrieve", Some("DATABASE_URL")),
            ],
        );

        let result = server
            .phantom_audit_recent(Parameters(AuditRecentParams {
                n: 10,
                op_filter: None,
                name_filter: Some("DATABASE_URL".to_string()),
            }))
            .unwrap();

        let json = parse_result_json(&result);
        let events = json["events"].as_array().unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0]["name"], "DATABASE_URL");
    }

    #[test]
    fn test_audit_recent_n_limit() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let (server, _dir) = setup_initialized_project();
        let home = tempfile::TempDir::new().unwrap();
        let _env_guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _prev_home = std::env::var("HOME").ok();
        unsafe { std::env::set_var("HOME", home.path()) };
        let now = 1_700_000_000_u64;
        let entries: Vec<(u64, &str, Option<&str>)> = (0..20_u64)
            .map(|i| (now - i * 10, "vault.retrieve", Some("OPENAI_API_KEY")))
            .collect();
        write_synthetic_audit_log(home.path(), &entries);

        let result = server
            .phantom_audit_recent(Parameters(AuditRecentParams {
                n: 5,
                op_filter: None,
                name_filter: None,
            }))
            .unwrap();

        let json = parse_result_json(&result);
        let events = json["events"].as_array().unwrap();
        assert_eq!(events.len(), 5);
        assert_eq!(json["total_in_log"].as_u64().unwrap(), 20);
    }

    #[test]
    fn test_audit_recent_no_log_returns_empty_with_note() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let (server, _dir) = setup_initialized_project();
        let empty_home = tempfile::TempDir::new().unwrap();
        let _env_guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _prev_home = std::env::var("HOME").ok();
        unsafe { std::env::set_var("HOME", empty_home.path()) };

        let result = server
            .phantom_audit_recent(Parameters(AuditRecentParams {
                n: 10,
                op_filter: None,
                name_filter: None,
            }))
            .unwrap();

        let json = parse_result_json(&result);
        let events = json["events"].as_array().unwrap();
        assert_eq!(events.len(), 0, "no events when audit log absent");
        assert!(json.get("note").is_some(), "should include a note");
    }

    #[test]
    fn test_audit_recent_event_has_no_value_field() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let (server, _dir) = setup_initialized_project();
        let home = tempfile::TempDir::new().unwrap();
        let _env_guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _prev_home = std::env::var("HOME").ok();
        unsafe { std::env::set_var("HOME", home.path()) };
        let now = 1_700_000_000_u64;
        write_synthetic_audit_log(
            home.path(),
            &[(now, "vault.store", Some("OPENAI_API_KEY"))],
        );

        let result = server
            .phantom_audit_recent(Parameters(AuditRecentParams {
                n: 10,
                op_filter: None,
                name_filter: None,
            }))
            .unwrap();

        let json = parse_result_json(&result);
        for event in json["events"].as_array().unwrap() {
            assert!(event.get("value").is_none(), "event must not have 'value' field");
        }
    }

    // ── phantom_audit_anomalies ───────────────────────────────────────

    #[test]
    fn test_audit_anomalies_returns_findings_array() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let (server, _dir) = setup_initialized_project();
        let home = tempfile::TempDir::new().unwrap();
        let _env_guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _prev_home = std::env::var("HOME").ok();
        unsafe { std::env::set_var("HOME", home.path()) };

        let result = server
            .phantom_audit_anomalies(Parameters(AuditAnomaliesParams {
                period: "all".to_string(),
                min_score: 0.4,
            }))
            .unwrap();

        let json = parse_result_json(&result);
        assert!(json.get("findings").is_some(), "must have 'findings'");
        assert!(json.get("total_findings").is_some(), "must have 'total_findings'");
        assert!(json.get("generated_at").is_some(), "must have 'generated_at'");
        assert!(json.get("period").is_some(), "must have 'period'");
    }

    #[test]
    fn test_audit_anomalies_detects_spike() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let (server, _dir) = setup_initialized_project();
        let home = tempfile::TempDir::new().unwrap();
        let _env_guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _prev_home = std::env::var("HOME").ok();
        unsafe { std::env::set_var("HOME", home.path()) };

        let base_day = 1_700_000_000_u64 / 86400 * 86400;
        let mut entries: Vec<(u64, &str, Option<&str>)> = Vec::new();
        for i in 1u64..=4 {
            entries.push((base_day + i * 86400, "vault.retrieve", Some("SPIKE_KEY")));
        }
        for j in 0..50u64 {
            entries.push((base_day + 10 + j, "vault.retrieve", Some("SPIKE_KEY")));
        }
        write_synthetic_audit_log(home.path(), &entries);

        let result = server
            .phantom_audit_anomalies(Parameters(AuditAnomaliesParams {
                period: "all".to_string(),
                min_score: 0.4,
            }))
            .unwrap();

        let json = parse_result_json(&result);
        let findings = json["findings"].as_array().unwrap();
        assert!(!findings.is_empty(), "should detect spike anomaly");
        let f = findings.iter().find(|f| f["name"] == "SPIKE_KEY").unwrap();
        assert_eq!(f["anomaly_type"], "spike");
        assert!(f["anomaly_score"].as_f64().unwrap() >= 0.6);
        assert!(f.get("value").is_none(), "finding must not expose secret value");
    }

    #[test]
    fn test_audit_anomalies_detects_dormant() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let (server, _dir) = setup_initialized_project();
        // Use a separate isolated HOME so this test sees only its own audit events.
        let home = tempfile::TempDir::new().unwrap();
        let _env_guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _prev_home = std::env::var("HOME").ok();
        unsafe { std::env::set_var("HOME", home.path()) };

        let t0 = 1_700_000_000_u64;
        let t1 = t0 + 10 * 86400;
        // Two accesses separated by 10 days: only quiet-period rule fires (score 0.5).
        // No spike: both days have count=1, daily_avg=1/(10 days)=0.1, 1 is NOT > 3×0.1=0.3.
        // Wait — 1 > 0.3, so spike also fires! Use a uniform daily spread to avoid spike.
        // Insert one access per day for 10 days + one more 10 days later.
        let mut entries: Vec<(u64, &str, Option<&str>)> = Vec::new();
        // 10 accesses, one per day: daily_avg = 10/10 = 1.0; max_daily = 1; 1 is NOT > 3*1=3
        for i in 0u64..10 {
            entries.push((t0 + i * 86400, "vault.retrieve", Some("DORMANT_KEY")));
        }
        // Now a gap: access after 8 quiet days (>= 7 threshold) → dormant rule fires
        entries.push((t0 + 18 * 86400, "vault.retrieve", Some("DORMANT_KEY")));

        write_synthetic_audit_log(home.path(), &entries);

        let result = server
            .phantom_audit_anomalies(Parameters(AuditAnomaliesParams {
                period: "all".to_string(),
                min_score: 0.4,
            }))
            .unwrap();

        let json = parse_result_json(&result);
        let findings = json["findings"].as_array().unwrap();
        let f = findings.iter().find(|f| f["name"] == "DORMANT_KEY").unwrap();
        // dormant rule: score 0.5; spike: max_daily=1, daily_avg≈0.61, 1 is NOT > 3*0.61=1.83
        // So anomaly_type should be "dormant"
        assert_eq!(f["anomaly_type"], "dormant", "anomaly_type should be dormant: {f}");
        assert!(f["anomaly_score"].as_f64().unwrap() >= 0.5);
    }

    #[test]
    fn test_audit_anomalies_finding_schema_no_value() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let (server, _dir) = setup_initialized_project();
        let home = tempfile::TempDir::new().unwrap();
        let _env_guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _prev_home = std::env::var("HOME").ok();
        unsafe { std::env::set_var("HOME", home.path()) };

        let t0 = 1_700_000_000_u64;
        write_synthetic_audit_log(
            home.path(),
            &[
                (t0, "vault.retrieve", Some("TEST_KEY")),
                (t0 + 10 * 86400, "vault.retrieve", Some("TEST_KEY")),
            ],
        );

        let result = server
            .phantom_audit_anomalies(Parameters(AuditAnomaliesParams {
                period: "all".to_string(),
                min_score: 0.0,
            }))
            .unwrap();

        let json = parse_result_json(&result);
        for f in json["findings"].as_array().unwrap() {
            assert!(f.get("name").is_some(), "finding must have 'name'");
            assert!(f.get("anomaly_type").is_some(), "finding must have 'anomaly_type'");
            assert!(f.get("anomaly_score").is_some(), "finding must have 'anomaly_score'");
            assert!(f.get("access_count").is_some(), "finding must have 'access_count'");
            assert!(f.get("last_access").is_some(), "finding must have 'last_access'");
            assert!(f.get("context").is_some(), "finding must have 'context'");
            assert!(f.get("value").is_none(), "finding must NOT have 'value'");
        }
    }

    #[test]
    fn test_audit_anomalies_min_score_filter() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let (server, _dir) = setup_initialized_project();
        let home = tempfile::TempDir::new().unwrap();
        let _env_guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _prev_home = std::env::var("HOME").ok();
        unsafe { std::env::set_var("HOME", home.path()) };

        // Use uniform pattern (10 daily accesses + 8-day gap) that only triggers dormant (0.5)
        let t0 = 1_700_000_000_u64;
        let mut entries: Vec<(u64, &str, Option<&str>)> = Vec::new();
        for i in 0u64..10 { entries.push((t0 + i * 86400, "vault.retrieve", Some("FILTER_KEY"))); }
        entries.push((t0 + 18 * 86400, "vault.retrieve", Some("FILTER_KEY")));
        write_synthetic_audit_log(home.path(), &entries);

        // min_score=0.9 should filter out dormant findings (~0.5)
        let result = server
            .phantom_audit_anomalies(Parameters(AuditAnomaliesParams {
                period: "all".to_string(),
                min_score: 0.9,
            }))
            .unwrap();

        let json = parse_result_json(&result);
        assert!(
            json["findings"].as_array().unwrap().is_empty(),
            "min_score=0.9 should filter out score~0.5 dormant findings"
        );
    }

    #[test]
    fn test_audit_anomalies_invalid_period_errors() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let (server, _dir) = setup_initialized_project();

        let err = server
            .phantom_audit_anomalies(Parameters(AuditAnomaliesParams {
                period: "invalid".to_string(),
                min_score: 0.4,
            }))
            .unwrap_err();

        assert_eq!(err.code, rmcp::model::ErrorCode::INVALID_PARAMS);
        assert!(err.message.contains("Invalid period"));
    }

    // ── phantom_audit_analytics ──────────────────────────────────────

    #[test]
    fn test_audit_analytics_returns_required_keys() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let (server, _dir) = setup_initialized_project();
        let home = tempfile::TempDir::new().unwrap();
        unsafe { std::env::set_var("HOME", home.path()) };
        let now = 1_700_000_000_u64;
        write_synthetic_audit_log(
            home.path(),
            &[
                (now - 200, "vault.retrieve", Some("KEY_A")),
                (now - 100, "vault.retrieve", Some("KEY_A")),
                (now - 50, "vault.store", Some("KEY_B")),
            ],
        );

        let result = server
            .phantom_audit_analytics(Parameters(AuditAnalyticsParams {
                window_days: 0,
                min_anomaly_score: None,
                format: "json".to_string(),
            }))
            .unwrap();

        let json = parse_result_json(&result);
        assert!(json.get("generated_at").is_some(), "must have 'generated_at'");
        assert!(json.get("analytics").is_some(), "must have 'analytics'");
        assert!(json.get("records").is_some(), "must have 'records'");
        assert!(json.get("time_series").is_some(), "must have 'time_series'");
        assert!(json.get("window_days").is_some(), "must have 'window_days'");

        let analytics = json["analytics"].as_array().unwrap();
        assert_eq!(analytics.len(), 2, "two distinct secrets");
    }

    #[test]
    fn test_audit_analytics_spike_exceeds_threshold() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let (server, _dir) = setup_initialized_project();
        let home = tempfile::TempDir::new().unwrap();
        unsafe { std::env::set_var("HOME", home.path()) };

        let base_day = 1_700_000_000_u64 / 86400 * 86400;
        let mut entries: Vec<(u64, &str, Option<&str>)> = Vec::new();
        // 1 access/day on days 1–4
        for i in 1u64..=4 {
            entries.push((base_day + i * 86400, "vault.retrieve", Some("SPIKE_KEY")));
        }
        // 50 accesses on day 0 (spike)
        for j in 0..50u64 {
            entries.push((base_day + 10 + j, "vault.retrieve", Some("SPIKE_KEY")));
        }
        write_synthetic_audit_log(home.path(), &entries);

        let result = server
            .phantom_audit_analytics(Parameters(AuditAnalyticsParams {
                window_days: 0,
                min_anomaly_score: Some(0.5),
                format: "json".to_string(),
            }))
            .unwrap();

        let json = parse_result_json(&result);
        let analytics = json["analytics"].as_array().unwrap();
        assert!(!analytics.is_empty(), "filtered analytics should include SPIKE_KEY");
        let spike = analytics.iter().find(|s| s["name"] == "SPIKE_KEY").unwrap();
        assert!(
            spike["anomaly_score"].as_f64().unwrap() >= 0.6,
            "spike anomaly_score must be >= 0.6"
        );
        // Records must not expose values
        for rec in json["records"].as_array().unwrap() {
            assert!(rec.get("value").is_none(), "records must never expose secret values");
        }
    }

    #[test]
    fn test_audit_analytics_csv_format() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let (server, _dir) = setup_initialized_project();
        let home = tempfile::TempDir::new().unwrap();
        unsafe { std::env::set_var("HOME", home.path()) };
        let now = 1_700_000_000_u64;
        write_synthetic_audit_log(
            home.path(),
            &[(now - 100, "vault.retrieve", Some("CSV_KEY"))],
        );

        let result = server
            .phantom_audit_analytics(Parameters(AuditAnalyticsParams {
                window_days: 0,
                min_anomaly_score: None,
                format: "csv".to_string(),
            }))
            .unwrap();

        use rmcp::model::RawContent;
        let text = result
            .content
            .iter()
            .find_map(|c| {
                if let RawContent::Text(t) = &c.raw {
                    Some(t.text.clone())
                } else {
                    None
                }
            })
            .unwrap_or_default();

        assert!(text.starts_with("ts,datetime,op,name,process\n"), "CSV must start with header");
        assert!(text.contains("CSV_KEY"), "CSV must include the secret name");
        assert!(text.contains("vault.retrieve"), "CSV must include the op");
    }

    #[test]
    fn test_audit_analytics_no_log_returns_empty() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let (server, _dir) = setup_initialized_project();
        let home = tempfile::TempDir::new().unwrap();
        unsafe { std::env::set_var("HOME", home.path()) };
        // No audit log written.

        let result = server
            .phantom_audit_analytics(Parameters(AuditAnalyticsParams {
                window_days: 0,
                min_anomaly_score: None,
                format: "json".to_string(),
            }))
            .unwrap();

        let json = parse_result_json(&result);
        assert_eq!(
            json["analytics"].as_array().unwrap().len(),
            0,
            "empty analytics when no log"
        );
        assert_eq!(
            json["records"].as_array().unwrap().len(),
            0,
            "empty records when no log"
        );
    }

    // ── phantom_compliance_status ─────────────────────────────────────

    #[test]
    fn test_compliance_status_has_compliant_and_checks() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let (server, _dir) = setup_initialized_project();

        let result = server
            .phantom_compliance_status(Parameters(ComplianceStatusParams {}))
            .unwrap();

        let json = parse_result_json(&result);
        assert!(json.get("compliant").is_some(), "must have 'compliant'");
        assert!(json.get("checks").is_some(), "must have 'checks'");
    }

    #[test]
    fn test_compliance_status_all_required_checks_present() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let (server, _dir) = setup_initialized_project();

        let result = server
            .phantom_compliance_status(Parameters(ComplianceStatusParams {}))
            .unwrap();

        let json = parse_result_json(&result);
        let checks = json["checks"].as_object().unwrap();
        for check_name in &[
            "vault_accessible",
            "audit_enabled",
            "precommit_installed",
            "env_clean",
            "secrets_have_ttl",
        ] {
            assert!(
                checks.contains_key(*check_name),
                "missing check '{check_name}'"
            );
        }
    }

    #[test]
    fn test_compliance_status_each_check_has_pass_and_detail() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let (server, _dir) = setup_initialized_project();

        let result = server
            .phantom_compliance_status(Parameters(ComplianceStatusParams {}))
            .unwrap();

        let json = parse_result_json(&result);
        let checks = json["checks"].as_object().unwrap();
        for (name, check) in checks {
            assert!(check.get("pass").is_some(), "check '{name}' must have 'pass'");
            assert!(check.get("detail").is_some(), "check '{name}' must have 'detail'");
            assert!(check["pass"].is_boolean(), "check '{name}' pass must be boolean");
        }
    }

    #[test]
    fn test_compliance_status_vault_accessible_after_init() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let (server, _dir) = setup_initialized_project();

        let result = server
            .phantom_compliance_status(Parameters(ComplianceStatusParams {}))
            .unwrap();

        let json = parse_result_json(&result);
        assert!(
            json["checks"]["vault_accessible"]["pass"].as_bool().unwrap(),
            "vault_accessible must be true after init"
        );
    }

    #[test]
    fn test_compliance_status_env_clean_after_init() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let (server, _dir) = setup_initialized_project();

        let result = server
            .phantom_compliance_status(Parameters(ComplianceStatusParams {}))
            .unwrap();

        let json = parse_result_json(&result);
        assert!(
            json["checks"]["env_clean"]["pass"].as_bool().unwrap(),
            "env_clean must be true after init replaces secrets with tokens"
        );
    }

    #[test]
    fn test_compliance_status_does_not_expose_secret_values() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let (server, _dir) = setup_initialized_project();

        let result = server
            .phantom_compliance_status(Parameters(ComplianceStatusParams {}))
            .unwrap();

        let text = extract_content_text(&result);
        assert!(!text.contains("sk-test-key"), "must not expose OPENAI secret");
        assert!(!text.contains("postgres://user:pass"), "must not expose DB credentials");
    }

    #[test]
    fn test_compliance_status_secrets_have_ttl_false_without_ttl() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let (server, _dir) = setup_initialized_project();

        let result = server
            .phantom_compliance_status(Parameters(ComplianceStatusParams {}))
            .unwrap();

        let json = parse_result_json(&result);
        assert!(
            !json["checks"]["secrets_have_ttl"]["pass"].as_bool().unwrap(),
            "secrets_have_ttl should be false when no rotation policy set"
        );
        assert!(
            !json["compliant"].as_bool().unwrap(),
            "compliant must be false when any check fails"
        );
    }

    #[test]
    fn test_compliance_status_secrets_have_ttl_true_after_rotate_with_expiry() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let (server, _dir) = setup_initialized_project();

        server
            .phantom_rotate_with_expiry(Parameters(RotateWithExpiryParams {
                days_ttl: 30,
                confirm: true,
            approval_token: None
            }))
            .unwrap();

        let result = server
            .phantom_compliance_status(Parameters(ComplianceStatusParams {}))
            .unwrap();

        let json = parse_result_json(&result);
        assert!(
            json["checks"]["secrets_have_ttl"]["pass"].as_bool().unwrap(),
            "secrets_have_ttl should be true after rotate_with_expiry sets rotation policy"
        );
    }

    // ── phantom_secret_rotation_due ───────────────────────────────────

    #[test]
    fn test_rotation_due_returns_required_keys() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let (server, _dir) = setup_initialized_project();

        let result = server
            .phantom_secret_rotation_due(Parameters(RotationDueParams { warn_days: 7 }))
            .unwrap();

        let json = parse_result_json(&result);
        assert!(json.get("due").is_some(), "must have 'due'");
        assert!(json.get("warning").is_some(), "must have 'warning'");
        assert!(json.get("ok").is_some(), "must have 'ok'");
        assert!(json.get("no_ttl").is_some(), "must have 'no_ttl'");
        assert!(json.get("summary").is_some(), "must have 'summary'");
        assert!(json.get("warn_days").is_some(), "must have 'warn_days'");
    }

    #[test]
    fn test_rotation_due_no_ttl_populated_without_rotation_policy() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let (server, _dir) = setup_initialized_project();

        let result = server
            .phantom_secret_rotation_due(Parameters(RotationDueParams { warn_days: 7 }))
            .unwrap();

        let json = parse_result_json(&result);
        let no_ttl = json["no_ttl"].as_array().unwrap();
        assert!(!no_ttl.is_empty(), "secrets without TTL should appear in no_ttl");
        for entry in no_ttl {
            assert!(entry.get("name").is_some(), "entry must have 'name'");
            assert_eq!(entry["status"], "no_ttl");
        }
    }

    #[test]
    fn test_rotation_due_ok_with_fresh_ttl() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let (server, _dir) = setup_initialized_project();

        server
            .phantom_rotate_with_expiry(Parameters(RotateWithExpiryParams {
                days_ttl: 30,
                confirm: true,
            approval_token: None
            }))
            .unwrap();

        let result = server
            .phantom_secret_rotation_due(Parameters(RotationDueParams { warn_days: 7 }))
            .unwrap();

        let json = parse_result_json(&result);
        let ok = json["ok"].as_array().unwrap();
        assert!(!ok.is_empty(), "fresh 30-day TTL should place secrets in 'ok'");
        for entry in ok {
            assert_eq!(entry["status"], "ok");
            let days = entry["days_remaining"].as_i64().unwrap_or(-1);
            assert!(days > 0, "days_remaining should be positive");
            assert!(entry["expires_at"].is_string(), "expires_at must be a string");
        }
    }

    #[test]
    fn test_rotation_due_never_exposes_secret_values() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let (server, _dir) = setup_initialized_project();

        let result = server
            .phantom_secret_rotation_due(Parameters(RotationDueParams { warn_days: 7 }))
            .unwrap();

        let text = get_result_text(&result);
        assert!(!text.contains("sk-test-key"), "must not expose OPENAI secret");
        assert!(!text.contains("postgres://user:pass"), "must not expose DB credentials");
    }

    #[test]
    fn test_rotation_due_summary_counts_match_arrays() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let (server, _dir) = setup_initialized_project();

        let result = server
            .phantom_secret_rotation_due(Parameters(RotationDueParams { warn_days: 7 }))
            .unwrap();

        let json = parse_result_json(&result);
        let due = json["due"].as_array().unwrap().len() as u64;
        let warn = json["warning"].as_array().unwrap().len() as u64;
        let ok = json["ok"].as_array().unwrap().len() as u64;
        let no_ttl = json["no_ttl"].as_array().unwrap().len() as u64;
        let summary = &json["summary"];

        assert_eq!(summary["expired"].as_u64().unwrap(), due);
        assert_eq!(summary["warning"].as_u64().unwrap(), warn);
        assert_eq!(summary["ok"].as_u64().unwrap(), ok);
        assert_eq!(summary["no_ttl"].as_u64().unwrap(), no_ttl);
        assert_eq!(summary["total"].as_u64().unwrap(), due + warn + ok + no_ttl);
    }

    #[test]
    fn test_rotation_due_entries_have_no_value_field() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let (server, _dir) = setup_initialized_project();

        let result = server
            .phantom_secret_rotation_due(Parameters(RotationDueParams { warn_days: 7 }))
            .unwrap();

        let json = parse_result_json(&result);
        for category in &["due", "warning", "ok", "no_ttl"] {
            if let Some(entries) = json[category].as_array() {
                for entry in entries {
                    assert!(entry.get("value").is_none(), "entry in '{category}' must not have 'value'");
                }
            }
        }
    }

    #[test]
    fn test_rotation_due_warn_days_respected() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let (server, _dir) = setup_initialized_project();

        server
            .phantom_rotate_with_expiry(Parameters(RotateWithExpiryParams {
                days_ttl: 30,
                confirm: true,
            approval_token: None
            }))
            .unwrap();

        // warn_days=31 > ttl=30 → all should be in 'warning'
        let result = server
            .phantom_secret_rotation_due(Parameters(RotationDueParams { warn_days: 31 }))
            .unwrap();

        let json = parse_result_json(&result);
        let warning = json["warning"].as_array().unwrap();
        assert!(!warning.is_empty(), "with warn_days=31, 30-day TTL secrets should be in warning");
        assert!(json["ok"].as_array().unwrap().is_empty(), "ok should be empty");
    }
}
