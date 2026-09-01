use phantom_core::config::PhantomConfig;
use phantom_core::dotenv::{classify, is_public_key, DotenvFile, SecretClassification};
use phantom_core::precommit_hook::{self, HookChange};
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
    AddSecretInteractiveParams, AddSecretParams, ApplyExpiryPolicyParams, ApprovalParams,
    AuditAlertsParams, AuditAnalyticsParams, AuditAnomaliesParams, AuditAnomaliesRealtimeParams,
    AuditExportReportParams, AuditHotspotAlertsParams, AuditIncidentsParams, AuditRecentParams,
    AuditStatsParams, AutoRotateParams, CheckParams, CloudPullParams, CloudPushParams,
    ComplianceStatusParams, CopySecretParams, DoctorParams, EngineeringDoParams,
    EngineeringDoPhase, EnvParams, ExpiryCheckParams, InitParams, LeakIncidentsRealtimeParams,
    ListWithExpiryParams, PhantomExpiryEnforceParams, RemoveSecretParams, RotateParams,
    RotatePromoteParams, RotateProviderParams, RotateWithCandidateParams, RotateWithExpiryParams,
    RotationDueParams, RotationScheduleNextParams, SetupWorkspaceParams, SetupWorkspacePhase,
    SyncParams, TeamCreateParams, TeamIdParams, TeamInviteParams, TeamVaultParams, UnwrapParams,
    ValidateAllParams, ValidateSecretParams, ValidationHistoryParams, ValidationScheduleParams,
    WhyParams, WrapParams,
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
        let vault = phantom_vault::create_vault(config.local_project_id());
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
    /// Canonicalize one exact closed engineering action or report the execution denial.
    #[tool(
        description = "Conversation-native engineering action planning. phase=propose (default) accepts only Phantom's closed Cargo action schema and returns a value-free canonical digest, effect classification, local workspace fingerprint, and exact activation blockers without executing anything. phase=execute is reserved and always hard denied until verified Locus authority, rollback-resistant replay, trusted handles, OS confinement, and correlated evidence are active. There are no bearer or secret-value fields; bounded action selectors are never treated as authority and are never echoed."
    )]
    fn phantom_do(
        &self,
        Parameters(params): Parameters<EngineeringDoParams>,
    ) -> Result<CallToolResult, McpError> {
        use phantom_runtime::EngineeringAction;

        let inspection = phantom_workspace::inspect_workspace(&self.project_dir)
            .map_err(|e| internal_err(format!("Workspace inspection failed: {e}")))?;
        let action_digest = params
            .action
            .canonical_digest()
            .map_err(|e| internal_err(format!("Action canonicalization failed: {e}")))?;
        let (action_kind, scope, filtered) = match &params.action {
            EngineeringAction::CargoCheck { package, .. } => (
                "cargo_check",
                if package.is_some() {
                    "package"
                } else {
                    "workspace"
                },
                false,
            ),
            EngineeringAction::CargoTest {
                package, filter, ..
            } => (
                "cargo_test",
                if package.is_some() {
                    "package"
                } else {
                    "workspace"
                },
                filter.is_some(),
            ),
            EngineeringAction::CargoClippy { package, .. } => (
                "cargo_clippy",
                if package.is_some() {
                    "package"
                } else {
                    "workspace"
                },
                false,
            ),
            EngineeringAction::CargoFmtCheck { .. } => ("cargo_fmt_check", "workspace", false),
        };
        let blockers = [
            "verified_locus_grant_unavailable",
            "peer_authenticated_native_transport_unavailable",
            "monotonic_replay_anchor_unavailable",
            "production_workspace_handle_unavailable",
            "production_toolchain_handle_unavailable",
            "os_confinement_unavailable",
            "externally_trusted_evidence_unavailable",
        ];
        let execute_requested = params.phase == EngineeringDoPhase::Execute;
        let output = serde_json::json!({
            "schema_version": 1,
            "phase": if execute_requested { "execute" } else { "propose" },
            "proposal_valid": true,
            "execution_accepted": false,
            "executed": false,
            "action": {
                "kind": action_kind,
                "scope": scope,
                "filtered": filtered,
                "canonical_args_sha256": action_digest,
                "required_operation": "run_engineering_check",
                "effect_class": "local_write"
            },
            "workspace_fingerprint": inspection.workspace_fingerprint,
            "authority_state": "no_locus_seal",
            "execution_state": "production_unavailable",
            "blockers": blockers,
            "next_step": if execute_requested {
                "Execution is hard denied. Review the blockers; no approval request or legacy mutating tool was created."
            } else {
                "Review this exact value-free action proposal. Execution remains unavailable and no approval request was created."
            }
        });
        text_result(
            serde_json::to_string_pretty(&output)
                .map_err(|e| internal_err(format!("Serialization error: {e}")))?,
        )
    }

    /// Propose setup, request trusted-terminal application, or read request status.
    #[tool(
        description = "Conversation-native, value-blind workspace setup. phase=propose returns an exact sealed plan; if the machine-local plan-seal key is absent, provisioning it requires confirm plus approval_token. phase=request_apply always requires both gates because it persists a bearerless trusted-terminal request. phase=status is read-only. MCP never claims or applies workspace changes."
    )]
    fn phantom_setup_workspace(
        &self,
        Parameters(params): Parameters<SetupWorkspaceParams>,
    ) -> Result<CallToolResult, McpError> {
        let output = match params.phase {
            SetupWorkspacePhase::Propose => {
                if params.plan_id.is_some()
                    || params.pre_state_id.is_some()
                    || params.request_id.is_some()
                {
                    return Err(invalid_params_err(
                        "propose does not accept plan_id, pre_state_id, or request_id",
                    ));
                }
                let inspection = phantom_workspace::inspect_workspace(&self.project_dir)
                    .map_err(|e| internal_err(format!("Workspace inspection failed: {e}")))?;
                let (key, host_state_mutated) =
                    match phantom_core::workspace_request::load_existing_workspace_plan_key() {
                        Ok(key) => (key, false),
                        Err(_) => {
                            require_confirm("phantom_setup_workspace", params.confirm)?;
                            let params_json = serde_json::to_string(&params).unwrap_or_default();
                            require_approval_token(
                                "phantom_setup_workspace",
                                params.approval_token.as_deref(),
                                &params_json,
                                &self.project_id(),
                            )?;
                            phantom_core::workspace_request::load_or_create_workspace_plan_key_with_status()
                                .map_err(|e| internal_err(format!("Plan seal key unavailable: {e}")))?
                        }
                    };
                let seal_key = phantom_workspace::PlanSealKey::from_bytes(*key);
                let sealed_plan =
                    phantom_workspace::build_sealed_setup_plan(&self.project_dir, &seal_key)
                        .map_err(|e| internal_err(format!("Workspace sealing failed: {e}")))?;
                serde_json::json!({
                    "phase": "propose",
                    "applied": false,
                    "workspace_mutated": false,
                    "vault_mutated": false,
                    "machine_local_state_checked_or_hardened": true,
                    "plan_seal_key_provisioned": host_state_mutated,
                    "apply_available": true,
                    "apply_surface": "trusted_terminal_only",
                    "note": "Review this exact sealed plan. MCP cannot claim or apply it; trusted-terminal application requires a separate bearerless request.",
                    "inspection": inspection,
                    "sealed_plan": sealed_plan,
                })
            }
            SetupWorkspacePhase::RequestApply => {
                require_confirm("phantom_setup_workspace", params.confirm)?;
                let params_json = serde_json::to_string(&params).unwrap_or_default();
                require_approval_token(
                    "phantom_setup_workspace",
                    params.approval_token.as_deref(),
                    &params_json,
                    &self.project_id(),
                )?;
                if params.request_id.is_some() {
                    return Err(invalid_params_err(
                        "request_apply does not accept request_id",
                    ));
                }
                let supplied_plan_id = params.plan_id.as_deref().ok_or_else(|| {
                    invalid_params_err("request_apply requires plan_id from propose")
                })?;
                let supplied_pre_state_id = params.pre_state_id.as_deref().ok_or_else(|| {
                    invalid_params_err("request_apply requires pre_state_id from propose")
                })?;
                let key = phantom_core::workspace_request::load_existing_workspace_plan_key()
                    .map_err(|e| internal_err(format!("Plan seal key unavailable: {e}")))?;
                let seal_key = phantom_workspace::PlanSealKey::from_bytes(*key);
                let sealed_plan =
                    phantom_workspace::build_sealed_setup_plan(&self.project_dir, &seal_key)
                        .map_err(|e| internal_err(format!("Workspace sealing failed: {e}")))?;
                let plan_matches = constant_time_eq(
                    supplied_plan_id.as_bytes(),
                    sealed_plan.plan.plan_id.as_bytes(),
                );
                let pre_state_matches = constant_time_eq(
                    supplied_pre_state_id.as_bytes(),
                    sealed_plan.pre_state_id.as_bytes(),
                );
                if !(plan_matches & pre_state_matches) {
                    return Err(invalid_params_err(
                        "sealed setup plan mismatch or workspace drift; run propose again",
                    ));
                }
                let action_summary = phantom_core::workspace_request::SanitizedActionSummary::new(
                    sealed_plan.plan.actions.iter().map(|action| {
                        use phantom_core::workspace_request::WorkspaceActionKind as RequestKind;
                        match action.kind {
                            phantom_workspace::SetupActionKind::InitializeWorkspace => {
                                RequestKind::InitializeWorkspace
                            }
                            phantom_workspace::SetupActionKind::ProtectEnvFile => {
                                RequestKind::ProtectEnvironment
                            }
                            phantom_workspace::SetupActionKind::EnsureEnvIgnoreRules => {
                                RequestKind::UpdateIgnoreRules
                            }
                            phantom_workspace::SetupActionKind::GenerateEnvExample => {
                                RequestKind::GenerateEnvironmentExample
                            }
                            phantom_workspace::SetupActionKind::InstallPreCommitCheck => {
                                RequestKind::InstallPreCommitCheck
                            }
                            phantom_workspace::SetupActionKind::ReviewPlaceBinding => {
                                RequestKind::ReviewPlaceBinding
                            }
                        }
                    }),
                );
                let request_id = phantom_core::workspace_request::create_request(
                    &self.project_dir,
                    &sealed_plan.plan.plan_id,
                    &sealed_plan.pre_state_id,
                    action_summary,
                )
                .map_err(|e| internal_err(format!("Setup request creation failed: {e}")))?;
                serde_json::json!({
                    "phase": "request_apply",
                    "request_id": request_id,
                    "state": "pending",
                    "applied": false,
                    "workspace_mutated": false,
                    "vault_mutated": false,
                    "apply_surface": "trusted_terminal_only",
                    "trusted_terminal_command": format!("phantom workspace apply --request {request_id}"),
                    "note": "The request is only a value-free locator, not a bearer. MCP cannot claim or apply it.",
                })
            }
            SetupWorkspacePhase::Status => {
                if params.plan_id.is_some() || params.pre_state_id.is_some() {
                    return Err(invalid_params_err(
                        "status accepts only phase and request_id",
                    ));
                }
                let request_id = params
                    .request_id
                    .as_deref()
                    .ok_or_else(|| invalid_params_err("status requires request_id"))?;
                let status = phantom_core::workspace_request::get_status(request_id)
                    .map_err(|e| invalid_params_err(format!("Setup request unavailable: {e}")))?;
                let current_scope =
                    phantom_core::workspace_request::workspace_scope_hash(&self.project_dir)
                        .map_err(|e| internal_err(format!("Workspace scope failed: {e}")))?;
                if !constant_time_eq(
                    status.workspace_scope_hash.as_bytes(),
                    current_scope.as_bytes(),
                ) {
                    return Err(invalid_params_err(
                        "Setup request is not available in this workspace",
                    ));
                }
                serde_json::json!({
                    "phase": "status",
                    "applied": status.state == phantom_core::workspace_request::WorkspaceRequestState::Applied,
                    "status": status,
                })
            }
        };
        text_result(
            serde_json::to_string_pretty(&output)
                .map_err(|e| internal_err(format!("Serialization error: {e}")))?,
        )
    }

    /// Describe the exact authority available through the conversation facade.
    #[tool(
        description = "Return a value-free capability card for the small conversation-native facade: allowed local verbs, requestable verbs, place/seal state, expiry, and facade hard denials. This is not a policy oracle for the advanced compatibility catalog, whose mutating tools retain separate legacy confirm plus out-of-band local approval gates and are not Locus-sealed."
    )]
    fn phantom_capability(&self) -> Result<CallToolResult, McpError> {
        let inspection = phantom_workspace::inspect_workspace(&self.project_dir)
            .map_err(|e| internal_err(format!("Workspace inspection failed: {e}")))?;
        let card = phantom_workspace::build_capability_card(&inspection);
        text_result(
            serde_json::to_string_pretty(&card)
                .map_err(|e| internal_err(format!("Serialization error: {e}")))?,
        )
    }

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
        output.push_str(&format!("Project ID: {}\n", config.portable_project_id()));
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
        require_approval_token(
            "phantom_init",
            params.approval_token.as_deref(),
            &params_json,
            &self.project_id(),
        )?;
        let requested_env = std::path::Path::new(&params.env_path);
        if requested_env.is_absolute()
            || requested_env
                .components()
                .any(|component| !matches!(component, std::path::Component::Normal(_)))
        {
            return Err(invalid_params_err(
                "env_path must be a contained project-relative file path",
            ));
        }
        let env_path = self.project_dir.join(requested_env);

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

        let mut token_map = TokenMap::new();
        let secrets = real_entries
            .iter()
            .map(|entry| {
                token_map.insert(entry.key.clone());
                phantom_vault::InitSecret::new(entry.key.clone(), entry.value.clone())
            })
            .collect::<Vec<_>>();
        let (phantomized, mut originals) = dotenv.rewrite_with_phantoms(&token_map);
        for value in originals.values_mut() {
            use zeroize::Zeroize;
            value.zeroize();
        }
        originals.clear();
        let files = vec![
            phantom_vault::InitFile::replace(&env_path, phantomized.into_bytes()).commit_last(),
            phantom_vault::InitFile::replace(
                self.config_path(),
                toml::to_string_pretty(&config)
                    .map_err(|_| internal_err("Failed to serialize config"))?
                    .into_bytes(),
            ),
        ];
        let vault = phantom_vault::create_vault(config.local_project_id());
        let receipt = phantom_vault::commit_init(vault.as_ref(), secrets, files)
            .map_err(|error| internal_err(format!("Initialization transaction failed: {error}")))?;

        let mut output = format!(
            "Phantom initialized! {} secret(s) protected:\n",
            receipt.secret_names.len()
        );
        for name in &receipt.secret_names {
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
        require_approval_token(
            "phantom_add_secret",
            params.approval_token.as_deref(),
            &params_json,
            &self.project_id(),
        )?;
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
        require_approval_token(
            "phantom_add_secret_interactive",
            params.approval_token.as_deref(),
            &params_json,
            &self.project_id(),
        )?;
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
        require_approval_token(
            "phantom_remove_secret",
            params.approval_token.as_deref(),
            &params_json,
            &self.project_id(),
        )?;
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
        require_approval_token(
            "phantom_rotate",
            params.approval_token.as_deref(),
            &params_json,
            &self.project_id(),
        )?;
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

    /// Deprecated compatibility endpoint for the disabled shadow-candidate path.
    #[tool(
        description = "DEPRECATED hard denial: legacy shadow rotation generated only a local phm_cand_ placeholder, not a provider-issued credential. This tool never creates or stores a candidate and ignores compatibility parameters. Use phantom_rotate_provider for a real provider rotation."
    )]
    fn phantom_rotate_with_candidate(
        &self,
        Parameters(params): Parameters<RotateWithCandidateParams>,
    ) -> Result<CallToolResult, McpError> {
        let _ = params;
        Err(invalid_params_err(
            "phantom_rotate_with_candidate is deprecated and disabled: the legacy implementation generated a local phm_cand_ placeholder, not a provider credential. No candidate was created or stored. Use phantom_rotate_provider for a real provider rotation.",
        ))
    }

    /// Deprecated compatibility endpoint for the disabled shadow promotion path.
    #[tool(
        description = "DEPRECATED hard denial: legacy candidates were local phm_cand_ placeholders, not provider-issued credentials. This tool never validates, promotes, or changes a vault value and ignores compatibility parameters. Use phantom_rotate_provider for a real provider rotation."
    )]
    fn phantom_rotate_promote(
        &self,
        Parameters(params): Parameters<RotatePromoteParams>,
    ) -> Result<CallToolResult, McpError> {
        let _ = params;
        Err(invalid_params_err(
            "phantom_rotate_promote is deprecated and disabled: legacy candidates were local phm_cand_ placeholders, not provider-issued credentials. No credential or metadata was changed. Use phantom_rotate_provider for a real provider rotation.",
        ))
    }

    /// Rotate a secret using a vendor-specific provider (Stripe, GitHub, AWS,
    /// Google, Vercel).
    ///
    /// Calls the vendor's API to re-issue the credential, stores the new value
    /// in the vault, and records an audit event. The new secret value is NEVER
    /// returned in the MCP response — only status metadata is exposed.
    #[tool(description = "Rotate a secret via a vendor-specific provider \
            (stripe | github | aws | google | vercel; sentry and supabase report \
            manual-rotation-required with a dashboard link). \
            Calls the vendor API to re-issue the credential server-side, stores the new value \
            in the encrypted vault, and records a signed audit event. The new secret value is \
            NEVER exposed in the MCP response — only provider name, status, and audit metadata \
            are returned. Requires the secret's rotation_provider config to be set in \
            .phantom.toml under [phantom.secrets.{name}.rotation_provider]; the `provider` \
            parameter is optional and defaults to the provider named there. The bootstrap \
            credential named by api_key_env is sourced from the server environment first, \
            then from the vault under the same name — it never crosses the MCP wire. \
            DESTRUCTIVE — permanently invalidates the current key at the vendor. \
            Requires `confirm: true`; the agent must obtain user consent before calling.")]
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

        // Effective provider: explicit param, else the one named in config.
        let effective_provider: String = match (params.provider.as_deref(), provider_config) {
            (Some(requested), Some(cfg)) => {
                if cfg.provider != requested {
                    return Err(invalid_params_err(format!(
                        "Secret '{}' is configured for provider '{}' but '{}' was requested. \
                         Update [phantom.secrets.{}.rotation_provider] in .phantom.toml.",
                        params.name, cfg.provider, requested, params.name
                    )));
                }
                requested.to_string()
            }
            (_, None) => {
                return Err(invalid_params_err(format!(
                    "No rotation_provider configured for secret '{}'. \
                     Add [phantom.secrets.{}.rotation_provider] to .phantom.toml with \
                     provider and api_key_env fields.",
                    params.name, params.name
                )));
            }
            (None, Some(cfg)) => cfg.provider.clone(),
        };

        // Bootstrap credential: environment variable first, then the vault
        // under the same name. Zeroized after the call; never in the response.
        let bootstrap = provider_config
            .and_then(|cfg| cfg.api_key_env.as_deref())
            .filter(|env_name| std::env::var(env_name).is_err())
            .and_then(|env_name| vault.retrieve(env_name).ok());

        // Build the provider list and attempt vendor rotation.
        let providers = phantom_core::rotation_provider::default_rotation_providers();

        // Capture the outgoing value BEFORE overwriting it: providers that
        // revoke the old credential (Vercel) do so only after the new value is
        // durably stored, authenticating with the old value itself.
        let old_value = vault.retrieve(&params.name).ok();

        let new_value = phantom_core::rotation_provider::auto_sync_rotation_with_bootstrap(
            &params.name,
            provider_config,
            &providers,
            bootstrap,
        )
        .map_err(|e| internal_err(format!("Provider rotation failed: {e}")))?;

        match new_value {
            Some(secret) => {
                // Store the new value in vault — secret is zeroized after this.
                vault
                    .store(&params.name, secret.as_str())
                    .map_err(|e| internal_err(format!("Failed to store rotated secret: {e}")))?;

                phantom_core::audit::log("vault.rotation.provider.stored", Some(&params.name));

                // Refresh the phm_ token for this secret in .env — same flow
                // as the CLI — so a client that captured the pre-rotation
                // phm_ token cannot resolve it to the new credential.
                let env_path = self.env_path();
                let mut env_token_refreshed = false;
                if env_path.exists() {
                    let mut token_map = TokenMap::new();
                    token_map.insert(params.name.clone());
                    let dotenv = DotenvFile::parse_file(&env_path)
                        .map_err(|e| internal_err(format!("Failed to parse .env: {e}")))?;
                    dotenv
                        .write_phantomized(&token_map, &env_path)
                        .map_err(|e| internal_err(format!("Failed to rewrite .env: {e}")))?;
                    env_token_refreshed = true;
                }

                // Persist rotation metadata (rotated_at + recomputed
                // expires_at). GitHub App installation tokens expire in 1 h.
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                let expires_override = if effective_provider.eq_ignore_ascii_case("github") {
                    Some(now + phantom_core::rotation_provider::GITHUB_INSTALLATION_TOKEN_TTL_SECS)
                } else {
                    None
                };
                let expires_line = vault
                    .record_provider_rotation(&params.name, expires_override)
                    .unwrap_or(None)
                    .map(|ts| format!("expires_at: {ts}\n"))
                    .unwrap_or_default();

                // New value is durably stored — best-effort revoke of the old
                // credential at the vendor (audited, fail-open).
                if let (Some(provider), Some(cfg)) = (
                    providers
                        .iter()
                        .find(|p| p.name().eq_ignore_ascii_case(&effective_provider)),
                    provider_config,
                ) {
                    let _ = provider.post_store_cleanup(&params.name, cfg, old_value.as_ref());
                }

                text_result(format!(
                    "Provider rotation succeeded for '{}'.\n\
                     provider: {}\n\
                     status: rotated\n\
                     env_token_refreshed: {}\n\
                     {}The new credential has been stored in the vault.\n\
                     The secret value was NOT exposed via MCP.",
                    params.name, effective_provider, env_token_refreshed, expires_line
                ))
            }
            None => {
                // auto_sync returns Ok(None) only for provider = "manual";
                // disabled configs and unknown provider names surface above
                // as distinct errors.
                Err(invalid_params_err(format!(
                    "Secret '{}' is configured with provider = \"manual\" — there is no \
                     vendor API to call. Rotate the credential manually, then store it \
                     with phantom_add_secret.",
                    params.name
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
        require_approval_token(
            "phantom_cloud_push",
            params.approval_token.as_deref(),
            &params_json,
            &self.project_id(),
        )?;
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
            config.portable_project_id(),
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
        require_approval_token(
            "phantom_cloud_pull",
            params.approval_token.as_deref(),
            &params_json,
            &self.project_id(),
        )?;
        use base64::{engine::general_purpose::STANDARD as BASE64, Engine};

        let token = phantom_core::auth::load_token()
            .ok_or_else(|| internal_err("Not logged in. Run `phantom login` first."))?;

        let (config, vault) = self.load_config_and_vault()?;

        let api_base = phantom_core::auth::api_base_url()
            .map_err(|e| internal_err(format!("Invalid cloud API URL: {e}")))?;
        let pull_result =
            phantom_core::cloud::pull(&api_base, &token, config.portable_project_id())
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
        require_approval_token(
            "phantom_copy_secret",
            params.approval_token.as_deref(),
            &params_json,
            &self.project_id(),
        )?;
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

        let target_vault = phantom_vault::create_vault(target_config.local_project_id());
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
            require_approval_token(
                "phantom_doctor",
                params.approval_token.as_deref(),
                &params_json,
                &self.project_id(),
            )?;
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
                        .portable_project_id()
                        .get(..8)
                        .unwrap_or(cfg.portable_project_id());
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
            let vault = phantom_vault::create_vault(cfg.local_project_id());
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

        // ── Check 6: Project-local Claude MCP wiring ───────────────────
        let claude_settings = self.project_dir.join(".claude/settings.local.json");
        if claude_settings.exists() {
            let content = std::fs::read_to_string(&claude_settings).map_err(|e| {
                internal_err(format!(
                    "Refusing to inspect or repair unreadable Claude settings {}: {e}",
                    claude_settings.display()
                ))
            })?;
            if phantom_core::agent::mcp_config_has_local_runtime(&claude_settings) {
                lines.push(
                    "pass: Claude Code MCP server uses a local Phantom executable".to_string(),
                );
            } else if content.contains("phantom") {
                lines.push(
                    "warn: Claude Code Phantom MCP entry is stale or network-capable".to_string(),
                );
                lines.push(
                    "  Fix: Run `phantom setup --client claude` in a trusted terminal".to_string(),
                );
                issues += 1;
            } else {
                lines.push("info: Claude Code settings contain no Phantom MCP entry".to_string());
            }
        }

        // ── Check 7: Pre-commit hook ────────────────────────────────────
        match precommit_hook::inspect(&self.project_dir).map_err(|error| {
            internal_err(format!(
                "Could not inspect the effective Git pre-commit hook: {error}"
            ))
        })? {
            precommit_hook::HookState::Present {
                content,
                executable,
                ..
            } if precommit_hook::is_ready(&content, executable) => {
                lines.push(
                    "pass: Git pre-commit hook runs the local Phantom check first".to_string(),
                );
            }
            precommit_hook::HookState::Present {
                content,
                executable,
                ..
            } => {
                if precommit_hook::is_current(&content) && !executable {
                    lines.push("warn: Git pre-commit hook is not executable".to_string());
                } else if precommit_hook::has_phantom_block(&content) {
                    lines.push("warn: Git pre-commit hook uses a stale Phantom check".to_string());
                } else {
                    lines.push("warn: Git pre-commit hook exists but no phantom check".to_string());
                }
                if params.fix {
                    let change = precommit_hook::install(&self.project_dir)
                        .map_err(|error| {
                            internal_err(format!(
                                "Failed to repair the effective Git pre-commit hook: {error}"
                            ))
                        })?
                        .expect("Git hook state already established a repository");
                    let message = match change {
                        HookChange::Installed => {
                            "  Fixed: Installed local Phantom check before existing hook commands"
                        }
                        HookChange::Repaired => "  Fixed: Repaired stale Phantom pre-commit hook",
                        HookChange::Unchanged => "  Fixed: Phantom pre-commit hook already current",
                    };
                    lines.push(message.to_string());
                    fixed += 1;
                } else {
                    issues += 1;
                }
            }
            precommit_hook::HookState::Missing { .. } => {
                lines.push("warn: No pre-commit hook installed".to_string());
                if params.fix {
                    precommit_hook::install(&self.project_dir).map_err(|error| {
                        internal_err(format!(
                            "Failed to install the effective Git pre-commit hook: {error}"
                        ))
                    })?;
                    lines.push("  Fixed: Installed pre-commit hook".to_string());
                    fixed += 1;
                } else {
                    issues += 1;
                }
            }
            precommit_hook::HookState::NotRepository => {
                lines.push("info: Not a git repo — pre-commit hook not applicable".to_string());
            }
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
            output.push_str(&format!(
                "PROTECTED: '{}' has a phantom token.\n",
                params.key
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

    /// Wrap package.json scripts with the installed local `phantom` binary.
    #[tool(
        description = "Wrap package.json scripts with the installed local `phantom exec --` command so secrets are injected via the proxy at runtime. Saves originals as `script:raw` variants. Uses a heuristic to pick dev/start/build/serve/deploy scripts and skip lint/test/format scripts."
    )]
    fn phantom_wrap(
        &self,
        Parameters(params): Parameters<WrapParams>,
    ) -> Result<CallToolResult, McpError> {
        require_confirm("phantom_wrap", params.confirm)?;
        let params_json = serde_json::to_string(&params).unwrap_or_default();
        require_approval_token(
            "phantom_wrap",
            params.approval_token.as_deref(),
            &params_json,
            &self.project_id(),
        )?;
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
                if value.contains("phantom-secrets") || value.contains("phantom exec") {
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
                serde_json::Value::String(wrapped_script_command(original)),
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
        require_approval_token(
            "phantom_unwrap",
            params.approval_token.as_deref(),
            &params_json,
            &self.project_id(),
        )?;
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
        require_approval_token(
            "phantom_env",
            params.approval_token.as_deref(),
            &params_json,
            &self.project_id(),
        )?;

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
    #[tool(
        description = "Check Phantom Cloud authentication status, plan, and last sync version. This uses the stored cloud credential and makes a provider request; requires confirm plus approval_token."
    )]
    async fn phantom_cloud_status(
        &self,
        Parameters(params): Parameters<ApprovalParams>,
    ) -> Result<CallToolResult, McpError> {
        require_confirm("phantom_cloud_status", params.confirm)?;
        let params_json = serde_json::to_string(&params).unwrap_or_default();
        require_approval_token(
            "phantom_cloud_status",
            params.approval_token.as_deref(),
            &params_json,
            &self.project_id(),
        )?;
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
        description = "List teams the authenticated user belongs to. Returns team id, name, and role. Uses the stored cloud credential and makes a provider request; requires confirm plus approval_token."
    )]
    async fn phantom_team_list(
        &self,
        Parameters(params): Parameters<ApprovalParams>,
    ) -> Result<CallToolResult, McpError> {
        require_confirm("phantom_team_list", params.confirm)?;
        let params_json = serde_json::to_string(&params).unwrap_or_default();
        require_approval_token(
            "phantom_team_list",
            params.approval_token.as_deref(),
            &params_json,
            &self.project_id(),
        )?;
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
        require_approval_token(
            "phantom_team_create",
            params.approval_token.as_deref(),
            &params_json,
            &self.project_id(),
        )?;
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
        description = "List members of a team by team_id. Returns GitHub login, email, and role. Uses the stored cloud credential and makes a provider request; requires confirm plus approval_token."
    )]
    async fn phantom_team_members(
        &self,
        Parameters(params): Parameters<TeamIdParams>,
    ) -> Result<CallToolResult, McpError> {
        require_confirm("phantom_team_members", params.confirm)?;
        let params_json = serde_json::to_string(&params).unwrap_or_default();
        require_approval_token(
            "phantom_team_members",
            params.approval_token.as_deref(),
            &params_json,
            &self.project_id(),
        )?;
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
        description = "Invite someone to a team by GitHub username. The caller must be a team owner or admin; the hosted API permits assigning only member or admin (not owner). Mutating provider request: requires confirm:true plus an out-of-band approval_token."
    )]
    async fn phantom_team_invite(
        &self,
        Parameters(params): Parameters<TeamInviteParams>,
    ) -> Result<CallToolResult, McpError> {
        require_confirm("phantom_team_invite", params.confirm)?;
        let params_json = serde_json::to_string(&params).unwrap_or_default();
        require_approval_token(
            "phantom_team_invite",
            params.approval_token.as_deref(),
            &params_json,
            &self.project_id(),
        )?;
        let role = params.role.as_str();
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
        require_approval_token(
            "phantom_team_key_publish",
            params.approval_token.as_deref(),
            &params_json,
            &self.project_id(),
        )?;
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
        require_approval_token(
            "phantom_team_vault_push",
            params.approval_token.as_deref(),
            &params_json,
            &self.project_id(),
        )?;
        use std::collections::BTreeMap;
        use zeroize::Zeroizing;

        let token = phantom_core::auth::require_token().map_err(|e| internal_err(e.to_string()))?;
        let api_base =
            phantom_core::auth::api_base_url().map_err(|e| internal_err(e.to_string()))?;
        let kp = phantom_core::auth::get_or_create_team_keypair()
            .map_err(|e| internal_err(format!("Failed to load team keypair: {e}")))?;

        let (config, vault) = self.load_config_and_vault()?;
        let project_id = config.portable_project_id().to_string();

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

    /// Deprecated compatibility tool that remaps all local Phantom tokens.
    #[tool(
        description = "DEPRECATED compatibility name: atomically remap all local phm_ \
            placeholders. The legacy days_ttl field is validated but no longer renews \
            `rotated_at`, `expires_at`, or rotation_policy because no provider credential \
            changes. Provider credentials and incident state remain unchanged. MUTATING — \
            invalidates current Phantom placeholders; requires confirm:true plus an \
            out-of-band approval_token."
    )]
    fn phantom_rotate_with_expiry(
        &self,
        Parameters(params): Parameters<RotateWithExpiryParams>,
    ) -> Result<CallToolResult, McpError> {
        require_confirm("phantom_rotate_with_expiry", params.confirm)?;
        let params_json = serde_json::to_string(&params).unwrap_or_default();
        require_approval_token(
            "phantom_rotate_with_expiry",
            params.approval_token.as_deref(),
            &params_json,
            &self.project_id(),
        )?;

        if params.days_ttl == 0 {
            return Err(invalid_params_err("days_ttl must be > 0"));
        }

        let (_config, vault) = self.load_config_and_vault()?;
        let names = vault
            .list()
            .map_err(|e| internal_err(format!("Failed to list secrets: {e}")))?;

        if names.is_empty() {
            return text_result("No Phantom tokens to remap.");
        }

        let env_path = self.env_path();
        if !env_path.exists() {
            return Err(invalid_params_err(format!(
                "Cannot remap Phantom tokens: {} does not exist.",
                env_path.display()
            )));
        }
        let dotenv = phantom_core::dotenv::DotenvFile::parse_file(&env_path)
            .map_err(|e| internal_err(format!("Failed to parse {}: {e}", env_path.display())))?;
        for name in &names {
            let entry = dotenv
                .entries()
                .into_iter()
                .find(|entry| entry.key == *name)
                .ok_or_else(|| {
                    invalid_params_err(format!(
                        "Cannot remap '{name}': it is not present in {}.",
                        env_path.display()
                    ))
                })?;
            if !entry.is_phantom {
                return Err(invalid_params_err(format!(
                    "Cannot remap '{name}': its value in {} is not a protected phm_ token.",
                    env_path.display()
                )));
            }
        }

        use phantom_core::token::TokenMap;
        let mut token_map = TokenMap::new();
        for name in &names {
            token_map.insert(name.clone());
        }
        dotenv
            .write_phantomized(&token_map, &env_path)
            .map_err(|e| internal_err(format!("Failed to atomically rewrite .env: {e}")))?;
        for name in &names {
            phantom_core::audit::log("secret.token_remapped", Some(name));
        }

        text_result(format!(
            "Remapped {} local Phantom token(s). Provider credentials and all expiry/rotation metadata are unchanged; days_ttl={} was retained only for legacy schema compatibility.",
            names.len(), params.days_ttl
        ))
    }

    /// List secrets with TTL/expiry countdown.
    #[tool(description = "List all secret names with their TTL/expiry status. \
            Shows days remaining, EXPIRED flag, or 'no expiry' for each secret. \
            Never returns secret values. Use it to audit which credentials need an \
            explicit provider rotation or local expiry-policy review.")]
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
                            " [EXPIRED]".to_string()
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
            output.push_str(
                "Rotate expired provider credentials through phantom_rotate_provider; a local token remap does not refresh TTLs.",
            );
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

        let report = phantom_core::analytics::compute_analytics(period).map_err(|e| {
            crate::tools::helpers::internal_err(format!("Failed to compute analytics: {e}"))
        })?;

        let secrets: Vec<&phantom_core::analytics::SecretAnalytics> = report
            .secrets
            .iter()
            .filter(|s| {
                params
                    .min_anomaly_score
                    .is_none_or(|min| s.anomaly_score >= min)
            })
            .collect();

        let out = serde_json::json!({
            "generated_at": report.generated_at,
            "secrets": secrets,
        });

        let json_str = serde_json::to_string_pretty(&out).map_err(|e| {
            crate::tools::helpers::internal_err(format!("Serialization error: {e}"))
        })?;

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
        let n = params.n.clamp(1, 200);

        let log_path = phantom_core::audit::log_path()
            .map_err(|e| internal_err(format!("Cannot resolve audit log path: {e}")))?;

        if !log_path.exists() {
            let out = serde_json::json!({
                "events": [],
                "total_returned": 0,
                "note": "Audit log does not exist. Set PHANTOM_AUDIT=1 to enable logging."
            });
            return text_result(
                serde_json::to_string_pretty(&out)
                    .map_err(|e| internal_err(format!("Serialization error: {e}")))?,
            );
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
            let name = v
                .get("name")
                .and_then(|n| n.as_str())
                .map(|s| s.to_string());
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

        text_result(
            serde_json::to_string_pretty(&out)
                .map_err(|e| internal_err(format!("Serialization error: {e}")))?,
        )
    }

    /// Query for suspicious access patterns in the audit log.
    #[tool(description = "Query the audit log for suspicious access patterns. \
            Returns a findings array where each entry has: name (secret name), \
            anomaly_type (spike | dormant | first_access), anomaly_score (0.0–1.0), \
            access_count, last_access (ISO-8601), daily_avg, and context (human-readable \
            explanation). Secret VALUES are never returned. Read-only; no confirm required. \
            Anomaly types: 'spike' = single day >3x daily average; \
            'dormant' = access after >=7 consecutive quiet days. \
            Use min_score to filter (default 0.4). Use period to limit the window.")]
    fn phantom_audit_anomalies(
        &self,
        Parameters(params): Parameters<AuditAnomaliesParams>,
    ) -> Result<CallToolResult, McpError> {
        let period = phantom_core::analytics::Period::parse(&params.period).ok_or_else(|| {
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

        text_result(
            serde_json::to_string_pretty(&out)
                .map_err(|e| internal_err(format!("Serialization error: {e}")))?,
        )
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
        use phantom_core::analytics::{compute_windowed_anomalies, AuditThresholdConfig};

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

        let results =
            compute_windowed_anomalies(params.name.as_deref(), thresholds.as_ref(), threshold)
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

    /// Hotspot alert inspection and acknowledgement tool.
    #[tool(
        description = "Inspect per-secret access-velocity spike alerts without manually parsing \
            the audit log. Returns alerts for secrets whose access count in the rolling 24-hour \
            window either (a) exceeds 5× the 7-day mean baseline, or (b) includes a burst of \
            ≥100 accesses within any 5-minute window. Each alert record contains: secret_name, \
            current_velocity (24h count), baseline_velocity (7-day daily mean), alert_level \
            (always 'high'), first_spike_ts (ISO-8601), ack_status ('unacked'|'acked'|'snoozed'), \
            peak_5m_count, and trigger (human-readable description). \
            Secret VALUES are never returned. \
            Set ack=true to acknowledge all returned alerts (removes them from the active list). \
            Set snooze_seconds>0 with ack=true to snooze instead of fully acknowledging. \
            Pass include_acked=true to also return already-acknowledged or snoozed alerts. \
            Use secret_name to filter to a specific secret. Read-only when ack=false; \
            ack=true persists acknowledgement state and requires confirm plus approval_token."
    )]
    fn phantom_audit_hotspot_alerts(
        &self,
        Parameters(params): Parameters<AuditHotspotAlertsParams>,
    ) -> Result<CallToolResult, McpError> {
        use phantom_core::audit::{
            acknowledge_hotspot_alert, detect_hotspot_alerts, HotspotAckStatus,
        };

        if params.ack {
            require_confirm("phantom_audit_hotspot_alerts", params.confirm)?;
            let params_json = serde_json::to_string(&params).unwrap_or_default();
            require_approval_token(
                "phantom_audit_hotspot_alerts",
                params.approval_token.as_deref(),
                &params_json,
                &self.project_id(),
            )?;
        }

        // Detect current alerts.
        let mut alerts = detect_hotspot_alerts()
            .map_err(|e| internal_err(format!("Failed to detect hotspot alerts: {e}")))?;

        // Filter by secret name if requested.
        if let Some(ref name) = params.secret_name {
            alerts.retain(|a| &a.secret_name == name);
        }

        // Acknowledge unacked alerts if requested.
        if params.ack {
            for alert in alerts
                .iter()
                .filter(|a| a.ack_status == HotspotAckStatus::Unacked)
            {
                acknowledge_hotspot_alert(&alert.secret_name, params.snooze_seconds).map_err(
                    |e| {
                        internal_err(format!(
                            "Failed to persist acknowledgement for '{}': {e}",
                            alert.secret_name
                        ))
                    },
                )?;
            }
            // Re-detect so the returned list reflects the new ack states.
            alerts = detect_hotspot_alerts()
                .map_err(|e| internal_err(format!("Failed to re-detect hotspot alerts: {e}")))?;
            if let Some(ref name) = params.secret_name {
                alerts.retain(|a| &a.secret_name == name);
            }
        }

        // Filter out acked/snoozed unless caller asked to include them.
        if !params.include_acked {
            alerts.retain(|a| a.ack_status == HotspotAckStatus::Unacked);
        }

        let now_ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let alert_records: Vec<serde_json::Value> = alerts
            .iter()
            .map(|a| {
                serde_json::json!({
                    "secret_name": a.secret_name,
                    "current_velocity": a.current_velocity,
                    "baseline_velocity": a.baseline_velocity,
                    "alert_level": a.alert_level,
                    "first_spike_ts": phantom_core::analytics::unix_to_iso8601(a.first_spike_ts),
                    "ack_status": a.ack_status.as_str(),
                    "peak_5m_count": a.peak_5m_count,
                    "trigger": a.trigger,
                })
            })
            .collect();

        let out = serde_json::json!({
            "generated_at": phantom_core::analytics::unix_to_iso8601(now_ts),
            "total_alerts": alert_records.len(),
            "ack_performed": params.ack,
            "snooze_seconds": params.snooze_seconds,
            "alerts": alert_records,
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
        use phantom_core::analytics::{compute_analytics, export_records, records_to_csv, Period};

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
                    .is_none_or(|min| s.anomaly_score >= min)
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
            Incidents whose secret was subsequently stored are omitted. Reads only the persisted incident \
            store; it does not run correlation or write state."
    )]
    fn phantom_audit_incidents(
        &self,
        Parameters(params): Parameters<AuditIncidentsParams>,
    ) -> Result<CallToolResult, McpError> {
        use phantom_core::leak_correlation::LeakCorrelationEngine;

        let engine = LeakCorrelationEngine::new()
            .map_err(|e| internal_err(format!("Cannot initialise leak correlation engine: {e}")))?;

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

    /// Real-time leak incident dashboard for AI agents and users.
    ///
    /// Queries active incidents (confidence > 0.5, < 24 h old) from
    /// `~/.phantom/leak-incidents.jsonl` and returns structured summaries.
    /// This dashboard is deliberately read-only. Rotation remains available
    /// through the separately approved rotation tools.
    #[tool(
        description = "Query active leak incidents for a real-time security dashboard. \
            Returns incidents with confidence > 0.5 seen within the last 24 hours, \
            sorted by confidence descending. Each entry contains: \
            secret_name (never the value), location_label, confidence, \
            first_seen (ISO-8601), last_seen (ISO-8601), incident_id. \
            Set min_confidence (default 0.5) to narrow results. \
            Reads only persisted incidents and never rotates, writes correlation state, \
            or exposes secret values. Use a separately approved rotation tool to remediate."
    )]
    fn phantom_leak_incidents_realtime(
        &self,
        Parameters(params): Parameters<LeakIncidentsRealtimeParams>,
    ) -> Result<CallToolResult, McpError> {
        use phantom_core::leak_correlation::LeakCorrelationEngine;

        let engine = LeakCorrelationEngine::new()
            .map_err(|e| internal_err(format!("Cannot initialise leak correlation engine: {e}")))?;

        // Retrieve active incidents: confidence >= min_confidence, < 24 h old.
        let incidents = engine
            .active_incidents(params.min_confidence)
            .map_err(|e| internal_err(format!("Failed to read leak incidents: {e}")))?;

        if incidents.is_empty() {
            return text_result(format!(
                "No active leak incidents (min_confidence={:.2}, window=24h). \
                 Set PHANTOM_AUDIT=1 to enable audit logging.",
                params.min_confidence
            ));
        }

        // Build structured incident summaries (no secret values exposed).
        let mut summaries: Vec<serde_json::Value> = incidents
            .iter()
            .map(|inc| {
                serde_json::json!({
                    "incident_id":    inc.incident_id,
                    "secret_name":    inc.secret_name,
                    "location_label": inc.location_label,
                    "confidence":     inc.confidence,
                    "first_seen":     iso8601(inc.first_seen_ts),
                    "last_seen":      iso8601(inc.last_seen_ts),
                    "event_count":    inc.event_count,
                    "remediation":    inc.remediation,
                })
            })
            .collect();

        // Sort by confidence descending so the most critical are first.
        summaries.sort_by(|a, b| {
            b["confidence"]
                .as_f64()
                .unwrap_or(0.0)
                .partial_cmp(&a["confidence"].as_f64().unwrap_or(0.0))
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        let out = serde_json::json!({
            "incident_count": summaries.len(),
            "min_confidence": params.min_confidence,
            "effect": "read_only",
            "rotation_performed": false,
            "incidents": summaries,
        });

        let json_str = serde_json::to_string_pretty(&out)
            .map_err(|e| internal_err(format!("Serialization error: {e}")))?;
        text_result(json_str)
    }

    /// Retrieve recent leak-incident alert records for Claude Code dashboards.
    #[tool(
        description = "Retrieve persisted leak-incident alert records from ~/.phantom/leak-alerts.jsonl. \
            Each alert represents a high-confidence proxy response leak that was dispatched to \
            configured backends (webhook/Slack/PagerDuty). \
            Set 'backfill: true' to re-run correlation, persist new incidents/alerts, and dispatch \
            configured notifications before returning the list; this requires confirm plus \
            approval_token. \
            Returns the most recent 'last' alerts (default 50) in chronological order, \
            including: secret_name, location_label, confidence, event_count, alerted_at, \
            backends_notified, and remediation advice. \
            Never exposes secret values. Read-only when backfill=false. Safe for AI agents."
    )]
    fn phantom_audit_alerts(
        &self,
        Parameters(params): Parameters<AuditAlertsParams>,
    ) -> Result<CallToolResult, McpError> {
        use phantom_core::leak_correlation::{
            AlertingConfig, HttpAlertDispatch, LeakCorrelationEngine, LeakIncidentAlerter,
        };

        let home = std::env::var("HOME")
            .or_else(|_| std::env::var("USERPROFILE"))
            .map(std::path::PathBuf::from)
            .map_err(|_| internal_err("Cannot resolve home directory"))?;
        let alerts_path = home.join(".phantom").join("leak-alerts.jsonl");

        if params.backfill {
            require_confirm("phantom_audit_alerts", params.confirm)?;
            let params_json = serde_json::to_string(&params).unwrap_or_default();
            require_approval_token(
                "phantom_audit_alerts",
                params.approval_token.as_deref(),
                &params_json,
                &self.project_id(),
            )?;
            let engine = LeakCorrelationEngine::new()
                .map_err(|e| internal_err(format!("Cannot initialise correlation engine: {e}")))?;
            let incidents = engine
                .run()
                .map_err(|e| internal_err(format!("Correlation engine failed: {e}")))?;

            if !incidents.is_empty() {
                // Load alerting config from .phantom.toml in cwd if present.
                let alerting_config = if self.config_path().exists() {
                    self.load_config()
                        .map(|cfg| cfg.alerting)
                        .unwrap_or_default()
                } else {
                    AlertingConfig::default()
                };

                let alerter = LeakIncidentAlerter::with_path(
                    alerting_config,
                    alerts_path.clone(),
                    Box::new(HttpAlertDispatch),
                );
                alerter
                    .process_incidents(&incidents)
                    .map_err(|e| internal_err(format!("Alert dispatch/backfill failed: {e}")))?;
            }
        }

        // Load alerts for display using a no-op dispatcher.
        struct NullDispatch;
        impl phantom_core::leak_correlation::AlertDispatch for NullDispatch {
            fn send_webhook(&self, _: &str, _: &serde_json::Value) -> std::io::Result<()> {
                Ok(())
            }
            fn send_slack(&self, _: &str, _: &serde_json::Value) -> std::io::Result<()> {
                Ok(())
            }
            fn send_pagerduty(&self, _: &str, _: &serde_json::Value) -> std::io::Result<()> {
                Ok(())
            }
        }

        let dummy_config = AlertingConfig {
            enabled: false,
            min_confidence: 0.0,
            backends: vec![],
        };
        let alerter =
            LeakIncidentAlerter::with_path(dummy_config, alerts_path, Box::new(NullDispatch));

        let alerts = alerter
            .load_recent_alerts(params.last)
            .map_err(|e| internal_err(format!("Failed to read alerts: {e}")))?;

        if alerts.is_empty() {
            return text_result(
                "No leak alerts found. Configure [alerting] in .phantom.toml and run \
                 `phantom audit alerts --backfill` to emit pending alerts.",
            );
        }

        let out = serde_json::json!({
            "alert_count": alerts.len(),
            "alerts": alerts,
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
            Set 'save: true' to persist the report to ~/.phantom/reports/; saving requires \
            confirm plus approval_token. \
            Never exposes secret values. Read-only (save=false). Safe for AI agents."
    )]
    fn phantom_audit_export_report(
        &self,
        Parameters(params): Parameters<AuditExportReportParams>,
    ) -> Result<CallToolResult, McpError> {
        use phantom_core::audit_export::{
            parse_date_to_ts, parse_date_to_ts_end, AuditExporter, ExportFilter,
        };

        if params.save {
            if params.action == "export" {
                return Err(invalid_params_err(
                    "save=true is supported only for action='report'",
                ));
            }
            require_confirm("phantom_audit_export_report", params.confirm)?;
            let params_json = serde_json::to_string(&params).unwrap_or_default();
            require_approval_token(
                "phantom_audit_export_report",
                params.approval_token.as_deref(),
                &params_json,
                &self.project_id(),
            )?;
        }

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
                    Some(
                        exporter
                            .save_report(&report)
                            .map_err(|e| internal_err(format!("Failed to save report: {e}")))?
                            .to_string_lossy()
                            .into_owned(),
                    )
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
            precommit_installed (git pre-commit hook contains the current local-only phantom check), \
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
        if !vault_ok {
            all_pass = false;
        }
        checks.insert("vault_accessible".to_string(), serde_json::json!({
            "pass": vault_ok,
            "detail": if vault_ok { "Vault backend is reachable." } else { "Vault not accessible — run phantom init." },
        }));

        // Check 2: audit enabled
        let audit_ok = phantom_core::audit::enabled();
        if !audit_ok {
            all_pass = false;
        }
        checks.insert("audit_enabled".to_string(), serde_json::json!({
            "pass": audit_ok,
            "detail": if audit_ok { "PHANTOM_AUDIT is set." } else { "Set PHANTOM_AUDIT=1 to enable audit logging." },
        }));

        // Check 3: pre-commit hook installed
        let precommit_ok = match precommit_hook::inspect(&self.project_dir) {
            Ok(precommit_hook::HookState::Present {
                content,
                executable,
                ..
            }) => precommit_hook::is_ready(&content, executable),
            Ok(
                precommit_hook::HookState::Missing { .. }
                | precommit_hook::HookState::NotRepository,
            ) => false,
            Err(error) => {
                return Err(internal_err(format!(
                    "Could not inspect the effective Git pre-commit hook: {error}"
                )));
            }
        };
        if !precommit_ok {
            all_pass = false;
        }
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
                        (
                            false,
                            format!("{} unprotected secret(s): {}", real.len(), names.join(", ")),
                        )
                    }
                }
                Err(e) => (false, format!(".env parse error: {e}")),
            }
        } else {
            (true, "No .env file present.".to_string())
        };
        if !env_clean {
            all_pass = false;
        }
        checks.insert(
            "env_clean".to_string(),
            serde_json::json!({
                "pass": env_clean,
                "detail": env_detail,
            }),
        );

        // Check 5: all secrets have TTL
        let (ttl_ok, ttl_detail) = if self.config_path().exists() {
            match self.load_config_and_vault() {
                Ok((_cfg, vault)) => match vault.list_with_metadata() {
                    Ok(entries) => {
                        let without_ttl: Vec<&str> = entries
                            .iter()
                            .filter(|(_, meta)| {
                                meta.as_ref()
                                    .and_then(|m| m.rotation_policy.as_ref())
                                    .is_none()
                            })
                            .map(|(name, _)| name.as_str())
                            .collect();
                        if without_ttl.is_empty() {
                            (
                                true,
                                "All secrets have a rotation policy (TTL).".to_string(),
                            )
                        } else {
                            (
                                false,
                                format!(
                                    "{} secret(s) have no TTL: {}",
                                    without_ttl.len(),
                                    without_ttl.join(", ")
                                ),
                            )
                        }
                    }
                    Err(e) => (false, format!("Failed to list secrets: {e}")),
                },
                Err(_) => (false, "Vault not accessible.".to_string()),
            }
        } else {
            (
                false,
                "Phantom not initialized — run phantom init.".to_string(),
            )
        };
        if !ttl_ok {
            all_pass = false;
        }
        checks.insert(
            "secrets_have_ttl".to_string(),
            serde_json::json!({
                "pass": ttl_ok,
                "detail": ttl_detail,
            }),
        );

        let out = serde_json::json!({
            "compliant": all_pass,
            "checks": checks,
        });

        text_result(
            serde_json::to_string_pretty(&out)
                .map_err(|e| internal_err(format!("Serialization error: {e}")))?,
        )
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

        text_result(
            serde_json::to_string_pretty(&out)
                .map_err(|e| internal_err(format!("Serialization error: {e}")))?,
        )
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
        require_approval_token(
            "phantom_team_vault_pull",
            params.approval_token.as_deref(),
            &params_json,
            &self.project_id(),
        )?;
        let token = phantom_core::auth::require_token().map_err(|e| internal_err(e.to_string()))?;
        let api_base =
            phantom_core::auth::api_base_url().map_err(|e| internal_err(e.to_string()))?;
        let kp = phantom_core::auth::get_or_create_team_keypair()
            .map_err(|e| internal_err(format!("Failed to load team keypair: {e}")))?;

        let (config, vault) = self.load_config_and_vault()?;
        let project_id = config.portable_project_id().to_string();

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
            Secret VALUES are never returned or logged. This retrieves credentials, makes real \
            outbound provider requests, and persists value-free validation metadata; it requires \
            confirm plus approval_token and should run during a maintenance window."
    )]
    fn phantom_validate_all(
        &self,
        Parameters(params): Parameters<ValidateAllParams>,
    ) -> Result<CallToolResult, McpError> {
        require_confirm("phantom_validate_all", params.confirm)?;
        let params_json = serde_json::to_string(&params).unwrap_or_default();
        require_approval_token(
            "phantom_validate_all",
            params.approval_token.as_deref(),
            &params_json,
            &self.project_id(),
        )?;
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
            secrets.push((
                name.clone(),
                zeroize::Zeroizing::new(String::from(value.as_str())),
            ));
        }

        let jobs = params.jobs.clamp(1, 16);
        let timeout = std::time::Duration::from_secs(10);
        let validators = phantom_core::validator::default_validators();

        let report =
            phantom_core::validator::run_validation_pipeline(secrets, &validators, jobs, timeout);

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
            vault
                .set_validation_metadata(&entry.name, meta)
                .map_err(|e| {
                    internal_err(format!(
                        "Validation completed but metadata persistence failed for '{}': {e}",
                        entry.name
                    ))
                })?;
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
            indicators. Read-only when interval is omitted. Providing interval persists scheduler \
            state and requires confirm plus approval_token."
    )]
    fn phantom_validation_schedule(
        &self,
        Parameters(params): Parameters<ValidationScheduleParams>,
    ) -> Result<CallToolResult, McpError> {
        use phantom_core::validation_scheduler::{state_file_path, Schedule, SchedulerState};

        let (config, _vault) = self.load_config_and_vault()?;
        let state_path = state_file_path(config.local_project_id());
        let mut state = SchedulerState::load(&state_path).unwrap_or_default();

        // If an interval was provided, update the schedule.
        if let Some(ref interval_str) = params.interval {
            require_confirm("phantom_validation_schedule", params.confirm)?;
            let params_json = serde_json::to_string(&params).unwrap_or_default();
            require_approval_token(
                "phantom_validation_schedule",
                params.approval_token.as_deref(),
                &params_json,
                &self.project_id(),
            )?;
            let sched = Schedule::parse(interval_str).map_err(|e| {
                crate::tools::helpers::invalid_params_err(format!("Invalid schedule interval: {e}"))
            })?;
            let description = sched.description();
            state.schedule = Some(sched);
            state
                .save(&state_path)
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
        use phantom_core::validation_scheduler::{state_file_path, SchedulerState, MAX_HISTORY};

        let (config, _vault) = self.load_config_and_vault()?;
        let state_path = state_file_path(config.local_project_id());
        let state = SchedulerState::load(&state_path).unwrap_or_default();

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

    /// Deprecated compatibility tool that remaps one local Phantom token.
    #[tool(
        description = "DEPRECATED compatibility name: remap the local phm_ placeholder for one \
            already-protected secret. This does not rotate or validate the provider credential, \
            does not change `rotated_at` / `expires_at` / TTL policy, does not clear leak \
            incidents, and cannot sync an unchanged credential (`sync: true` is rejected). \
            When audit logging is enabled, success records `secret.token_remapped`. MUTATING — atomically rewrites .env and \
            requires `confirm: true` plus an out-of-band approval token. Secret VALUES are \
            never returned or logged."
    )]
    fn phantom_secrets_auto_rotate(
        &self,
        Parameters(params): Parameters<AutoRotateParams>,
    ) -> Result<CallToolResult, McpError> {
        require_confirm("phantom_secrets_auto_rotate", params.confirm)?;
        let params_json = serde_json::to_string(&params).unwrap_or_default();
        require_approval_token(
            "phantom_secrets_auto_rotate",
            params.approval_token.as_deref(),
            &params_json,
            &self.project_id(),
        )?;

        if params.sync {
            return Err(invalid_params_err(
                "sync=true is not valid for a Phantom token remap: the provider credential is unchanged. Use phantom_rotate_provider for a real approved provider rotation and deployment workflow.",
            ));
        }

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

        let env_path = self.env_path();
        if !env_path.exists() {
            return Err(invalid_params_err(format!(
                "Cannot remap '{}': {} does not exist.",
                params.name,
                env_path.display()
            )));
        }
        let dotenv = phantom_core::dotenv::DotenvFile::parse_file(&env_path)
            .map_err(|e| internal_err(format!("Failed to parse {}: {e}", env_path.display())))?;
        let entry = dotenv
            .entries()
            .into_iter()
            .find(|entry| entry.key == params.name)
            .ok_or_else(|| {
                invalid_params_err(format!(
                    "Cannot remap '{}': it is not present in {}.",
                    params.name,
                    env_path.display()
                ))
            })?;
        if !entry.is_phantom {
            return Err(invalid_params_err(format!(
                "Cannot remap '{}': its value in {} is not a protected phm_ token.",
                params.name,
                env_path.display()
            )));
        }

        use phantom_core::token::TokenMap;
        let mut token_map = TokenMap::new();
        token_map.insert(params.name.clone());
        dotenv
            .write_phantomized(&token_map, &env_path)
            .map_err(|e| {
                internal_err(format!(
                    "Failed to atomically rewrite {}: {e}",
                    env_path.display()
                ))
            })?;

        phantom_core::audit::log("secret.token_remapped", Some(&params.name));

        text_result(format!(
            "Remapped the local Phantom token for '{}'. Provider credential, expiry metadata, and incident state are unchanged.",
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
            if params.also_promote_rotated && meta.vault_mode.is_read_only() {
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
                    phantom_core::audit::log("secret.expiry_policy.promoted", Some(name));
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
                        phantom_core::audit::log("secret.expiry_policy.demoted", Some(name));
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

fn wrapped_script_command(original: &str) -> String {
    format!("phantom exec -- {original}")
}

// ── Private helpers ───────────────────────────────────────────────────────────

/// Convert a Unix timestamp to a minimal ISO-8601 string (UTC, no external deps).
fn iso8601(secs: u64) -> String {
    let days = secs / 86400;
    let rem = secs % 86400;
    let hh = rem / 3600;
    let mm = (rem % 3600) / 60;
    let ss = rem % 60;

    let z = days as i64 + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z", y, m, d, hh, mm, ss)
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut difference = 0_u8;
    for (left, right) in left.iter().zip(right.iter()) {
        difference |= left ^ right;
    }
    difference == 0
}

#[tool_handler]
impl ServerHandler for PhantomMcpServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build()).with_instructions(
            "Phantom is a safe execution substrate for AI coding agents. Start with \
                 phantom_capability to learn the exact allowed verbs and hard denials. Use \
                 phantom_do to canonicalize a closed engineering action without executing it, then \
                 phantom_setup_workspace for a value-blind, deterministic setup inspection. \
                 Setup proposals can create bearerless apply requests, but MCP can never claim or apply them; \
                 application remains trusted-terminal-only and must not be described as applied until status proves it. \
                 No Locus seal is active unless the capability card explicitly says so. \
                 Advanced phantom_* tools remain available for compatible operator workflows; \
                 secret values are never returned through MCP."
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

    struct TestHome {
        _dir: TempDir,
        previous: Option<std::ffi::OsString>,
    }

    impl TestHome {
        fn new() -> Self {
            let dir = TempDir::new().unwrap();
            let previous = std::env::var_os("HOME");
            unsafe { std::env::set_var("HOME", dir.path()) };
            Self {
                _dir: dir,
                previous,
            }
        }
    }

    impl Drop for TestHome {
        fn drop(&mut self) {
            unsafe {
                match &self.previous {
                    Some(value) => std::env::set_var("HOME", value),
                    None => std::env::remove_var("HOME"),
                }
            }
        }
    }

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
            approval_token: None,
        };
        let result = server.phantom_init(Parameters(params)).unwrap();
        let text = extract_content_text(&result);
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
    fn shadow_candidate_compatibility_tools_are_side_effect_free_hard_denials() {
        let dir = TempDir::new().unwrap();
        let marker = dir.path().join("marker");
        std::fs::write(&marker, b"unchanged").unwrap();
        let server = PhantomMcpServer::with_dir(dir.path().to_path_buf());

        let create_error = server
            .phantom_rotate_with_candidate(Parameters(RotateWithCandidateParams {
                name: "OPENAI_API_KEY".to_string(),
                auto_promote_ttl_secs: Some(60),
                confirm: true,
                approval_token: Some("ignored".to_string()),
            }))
            .unwrap_err()
            .message;
        assert!(create_error.contains("deprecated and disabled"));
        assert!(create_error.contains("No candidate was created or stored"));

        let promote_error = server
            .phantom_rotate_promote(Parameters(RotatePromoteParams {
                name: "OPENAI_API_KEY".to_string(),
                confirm: true,
                approval_token: Some("ignored".to_string()),
            }))
            .unwrap_err()
            .message;
        assert!(promote_error.contains("deprecated and disabled"));
        assert!(promote_error.contains("No credential or metadata was changed"));
        assert_eq!(std::fs::read(&marker).unwrap(), b"unchanged");
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn mcp_doctor_fix_refuses_to_overwrite_non_utf8_hook() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let (server, dir) = setup_test_project();
        assert!(std::process::Command::new("git")
            .args(["init", "--quiet"])
            .current_dir(dir.path())
            .status()
            .unwrap()
            .success());
        let hook = dir.path().join(".git/hooks/pre-commit");
        std::fs::create_dir_all(hook.parent().unwrap()).unwrap();
        let original = b"#!/bin/sh\necho user-hook\n\xff\n";
        std::fs::write(&hook, original).unwrap();

        let result = server.phantom_doctor(Parameters(DoctorParams {
            fix: true,
            confirm: true,
            approval_token: None,
        }));

        assert!(result.is_err());
        assert_eq!(std::fs::read(hook).unwrap(), original);
    }

    #[test]
    fn mcp_doctor_repairs_custom_effective_hook_path() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let (server, dir) = setup_test_project();
        for args in [
            vec!["init", "--quiet"],
            vec!["config", "core.hooksPath", "effective-hooks"],
        ] {
            assert!(std::process::Command::new("git")
                .args(args)
                .current_dir(dir.path())
                .status()
                .unwrap()
                .success());
        }
        let hook = dir.path().join("effective-hooks/pre-commit");
        std::fs::create_dir_all(hook.parent().unwrap()).unwrap();
        std::fs::write(
            &hook,
            "#!/bin/sh\necho before\nexit 0\n# Phantom Secrets pre-commit hook\nnpx phantom-secrets check --staged\n",
        )
        .unwrap();

        server
            .phantom_doctor(Parameters(DoctorParams {
                fix: true,
                confirm: true,
                approval_token: None,
            }))
            .unwrap();

        let repaired = std::fs::read_to_string(&hook).unwrap();
        assert!(precommit_hook::is_current(&repaired));
        assert!(repaired.find("phantom check").unwrap() < repaired.find("exit 0").unwrap());
        assert!(!dir.path().join(".git/hooks/pre-commit").exists());
    }

    #[test]
    fn mcp_doctor_rejects_legacy_npx_mcp_entry() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let (server, dir) = setup_test_project();
        let settings = dir.path().join(".claude/settings.local.json");
        std::fs::create_dir_all(settings.parent().unwrap()).unwrap();
        std::fs::write(
            settings,
            r#"{"mcpServers":{"phantom":{"command":"npx","args":["-y","phantom-secrets-mcp"]}}}"#,
        )
        .unwrap();

        let result = server
            .phantom_doctor(Parameters(DoctorParams {
                fix: false,
                confirm: false,
                approval_token: None,
            }))
            .unwrap();
        let text = extract_content_text(&result);

        assert!(text.contains("stale or network-capable"), "{text}");
        assert!(text.contains("issue(s) found"), "{text}");
    }

    #[test]
    fn mcp_wrap_generator_uses_installed_local_binary() {
        let wrapped = wrapped_script_command("next dev");
        assert_eq!(wrapped, "phantom exec -- next dev");
        assert!(!wrapped.contains("npx"));
        assert!(!wrapped.contains("npm"));
    }

    #[test]
    fn test_status_before_init() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let (server, _dir) = setup_test_project();
        let result = server.phantom_status().unwrap();
        let text = extract_content_text(&result);
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
                approval_token: None,
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
    fn test_init_rejects_paths_outside_project_without_mutation() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let (server, dir) = setup_test_project();
        let original = std::fs::read(dir.path().join(".env")).unwrap();

        let error = server
            .phantom_init(Parameters(InitParams {
                env_path: "../.env".to_string(),
                confirm: true,
                approval_token: None,
            }))
            .unwrap_err();

        assert_eq!(error.code, rmcp::model::ErrorCode::INVALID_PARAMS);
        assert!(error.message.contains("contained project-relative"));
        assert_eq!(std::fs::read(dir.path().join(".env")).unwrap(), original);
        assert!(!dir.path().join(".phantom.toml").exists());
    }

    #[test]
    fn test_init_requires_real_mcp_approval_and_rejects_replay() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let home = TempDir::new().unwrap();
        let project = TempDir::new().unwrap();

        let prev_home = std::env::var("HOME").ok();
        let prev_passphrase = std::env::var("PHANTOM_VAULT_PASSPHRASE").ok();
        let prev_skip = std::env::var("PHANTOM_MCP_SKIP_APPROVAL").ok();
        let prev_effects = std::env::var("PHANTOM_MCP_EFFECTS").ok();

        unsafe {
            std::env::set_var("HOME", home.path());
            std::env::set_var(
                "PHANTOM_VAULT_PASSPHRASE",
                "test-passphrase-do-not-use-in-prod",
            );
            std::env::remove_var("PHANTOM_MCP_SKIP_APPROVAL");
            std::env::remove_var("PHANTOM_MCP_EFFECTS");
        }

        std::fs::write(project.path().join(".env"), "OPENAI_API_KEY=sk-test-key\n").unwrap();

        let server = PhantomMcpServer::with_dir(project.path().to_path_buf());
        let params = || InitParams {
            env_path: ".env".to_string(),
            confirm: true,
            approval_token: None,
        };

        let disabled_err = server.phantom_init(Parameters(params())).unwrap_err();
        assert_eq!(disabled_err.code, rmcp::model::ErrorCode::INVALID_PARAMS);
        assert!(disabled_err.message.contains("disabled by default"));
        assert!(phantom_core::mcp_approval::list_pending_approvals()
            .unwrap()
            .is_empty());

        unsafe {
            std::env::set_var("PHANTOM_MCP_EFFECTS", "trusted-terminal");
        }
        let first_err = server.phantom_init(Parameters(params())).unwrap_err();
        assert_eq!(first_err.code, rmcp::model::ErrorCode::INVALID_PARAMS);
        assert!(first_err.message.contains("out-of-band approval"));

        let pending = phantom_core::mcp_approval::list_pending_approvals().unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].tool_name, "phantom_init");
        let nonce = pending[0].nonce.clone();

        let approved = phantom_core::mcp_approval::approve_nonce(&nonce).unwrap();
        let approval_token = format!("{}:{}", nonce, approved.approval_token);

        let changed_params_err = server
            .phantom_init(Parameters(InitParams {
                env_path: "other.env".to_string(),
                confirm: true,
                approval_token: Some(approval_token.clone()),
            }))
            .unwrap_err();
        assert_eq!(
            changed_params_err.code,
            rmcp::model::ErrorCode::INVALID_PARAMS
        );
        assert!(changed_params_err.message.contains("parameter mismatch"));

        let result = server
            .phantom_init(Parameters(InitParams {
                approval_token: Some(approval_token.clone()),
                ..params()
            }))
            .unwrap();
        assert!(get_result_text(&result).contains("protected"));

        let replay_err = server
            .phantom_init(Parameters(InitParams {
                approval_token: Some(approval_token),
                ..params()
            }))
            .unwrap_err();
        assert_eq!(replay_err.code, rmcp::model::ErrorCode::INVALID_PARAMS);
        assert!(
            replay_err.message.contains("consumed") || replay_err.message.contains("not found")
        );

        unsafe {
            match prev_home {
                Some(value) => std::env::set_var("HOME", value),
                None => std::env::remove_var("HOME"),
            }
            match prev_passphrase {
                Some(value) => std::env::set_var("PHANTOM_VAULT_PASSPHRASE", value),
                None => std::env::remove_var("PHANTOM_VAULT_PASSPHRASE"),
            }
            match prev_skip {
                Some(value) => std::env::set_var("PHANTOM_MCP_SKIP_APPROVAL", value),
                None => std::env::remove_var("PHANTOM_MCP_SKIP_APPROVAL"),
            }
            match prev_effects {
                Some(value) => std::env::set_var("PHANTOM_MCP_EFFECTS", value),
                None => std::env::remove_var("PHANTOM_MCP_EFFECTS"),
            }
        }
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
    fn test_phantom_do_proposes_closed_value_free_action_without_execution() {
        let (server, _dir) = setup_test_project();
        let result = server
            .phantom_do(Parameters(EngineeringDoParams {
                phase: EngineeringDoPhase::Propose,
                action: phantom_runtime::EngineeringAction::CargoTest {
                    package: Some(phantom_runtime::PackageName::parse("phantom-core").unwrap()),
                    filter: Some(phantom_runtime::TestFilter::parse("audit::tests").unwrap()),
                    cwd: phantom_runtime::RelativeCwd::workspace_root(),
                },
            }))
            .unwrap();
        let text = extract_content_text(&result);
        let value: serde_json::Value = serde_json::from_str(&text).unwrap();

        assert_eq!(value["phase"], "propose");
        assert_eq!(value["proposal_valid"], true);
        assert_eq!(value["execution_accepted"], false);
        assert_eq!(value["executed"], false);
        assert_eq!(value["action"]["kind"], "cargo_test");
        assert_eq!(value["action"]["scope"], "package");
        assert_eq!(value["action"]["filtered"], true);
        assert_eq!(
            value["action"]["canonical_args_sha256"]
                .as_str()
                .unwrap()
                .len(),
            64
        );
        assert_eq!(value["action"]["effect_class"], "local_write");
        assert_eq!(value["execution_state"], "production_unavailable");
        assert_eq!(value["blockers"].as_array().unwrap().len(), 7);
        assert!(!text.contains("phantom-core"));
        assert!(!text.contains("audit::tests"));
        assert!(!text.contains("sk-test-key"));
        assert!(!text.contains("postgres://user:pass@localhost/db"));
    }

    #[test]
    fn test_phantom_do_execute_is_hard_denied_and_non_mutating() {
        let (server, dir) = setup_test_project();
        let before = std::fs::read(dir.path().join(".env")).unwrap();
        let result = server
            .phantom_do(Parameters(EngineeringDoParams {
                phase: EngineeringDoPhase::Execute,
                action: phantom_runtime::EngineeringAction::CargoFmtCheck {
                    cwd: phantom_runtime::RelativeCwd::workspace_root(),
                },
            }))
            .unwrap();
        let text = extract_content_text(&result);
        let value: serde_json::Value = serde_json::from_str(&text).unwrap();

        assert_eq!(value["phase"], "execute");
        assert_eq!(value["proposal_valid"], true);
        assert_eq!(value["execution_accepted"], false);
        assert_eq!(value["executed"], false);
        assert_eq!(value["authority_state"], "no_locus_seal");
        assert!(value["next_step"].as_str().unwrap().contains("hard denied"));
        assert_eq!(std::fs::read(dir.path().join(".env")).unwrap(), before);
        assert!(!dir.path().join(".phantom.toml").exists());
    }

    #[test]
    fn test_phantom_do_schema_is_closed_and_rejects_arbitrary_shell() {
        assert!(
            serde_json::from_value::<EngineeringDoParams>(serde_json::json!({
                "action": { "action": "shell", "command": "curl example.invalid" }
            }))
            .is_err()
        );
        assert!(
            serde_json::from_value::<EngineeringDoParams>(serde_json::json!({
                "action": { "action": "cargo_fmt_check", "cwd": "." },
                "approval_token": "not-accepted"
            }))
            .is_err()
        );

        let schema = serde_json::to_value(schemars::schema_for!(EngineeringDoParams)).unwrap();
        assert_eq!(schema["additionalProperties"], false);
        let phases = schema["$defs"]["EngineeringDoPhase"]["oneOf"]
            .as_array()
            .unwrap()
            .iter()
            .map(|entry| entry["const"].as_str().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(phases, vec!["propose", "execute"]);
    }

    #[test]
    fn test_setup_workspace_empty_args_proposes_value_blind_sealed_plan() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _home = TestHome::new();
        let (server, _dir) = setup_test_project();

        let params: SetupWorkspaceParams = serde_json::from_value(serde_json::json!({})).unwrap();
        let err = server
            .phantom_setup_workspace(Parameters(params))
            .unwrap_err();
        assert!(err.message.contains("confirm: true"));

        let result = server
            .phantom_setup_workspace(Parameters(SetupWorkspaceParams {
                confirm: true,
                ..SetupWorkspaceParams::default()
            }))
            .unwrap();
        let text = extract_content_text(&result);
        let value: serde_json::Value = serde_json::from_str(&text).unwrap();

        assert_eq!(value["phase"], "propose");
        assert_eq!(value["applied"], false);
        assert_eq!(value["workspace_mutated"], false);
        assert_eq!(value["vault_mutated"], false);
        assert_eq!(value["machine_local_state_checked_or_hardened"], true);
        assert_eq!(value["plan_seal_key_provisioned"], true);
        assert_eq!(value["apply_available"], true);
        assert_eq!(value["apply_surface"], "trusted_terminal_only");
        assert!(value["sealed_plan"]["plan"]["plan_id"].as_str().is_some());
        assert!(value["sealed_plan"]["pre_state_id"].as_str().is_some());
        assert!(text.contains("OPENAI_API_KEY"));
        assert!(!text.contains("sk-test-key"));
        assert!(!text.contains("postgres://user:pass@localhost/db"));

        let second = server
            .phantom_setup_workspace(Parameters(SetupWorkspaceParams::default()))
            .unwrap();
        let second: serde_json::Value =
            serde_json::from_str(&extract_content_text(&second)).unwrap();
        assert_eq!(second["machine_local_state_checked_or_hardened"], true);
        assert_eq!(second["plan_seal_key_provisioned"], false);
    }

    #[test]
    fn test_setup_workspace_request_apply_is_bearerless_and_non_mutating() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _home = TestHome::new();
        let (server, dir) = setup_test_project();
        let before_env = std::fs::read(dir.path().join(".env")).unwrap();
        let before_entries = std::fs::read_dir(dir.path()).unwrap().count();

        let proposed = server
            .phantom_setup_workspace(Parameters(SetupWorkspaceParams {
                confirm: true,
                ..SetupWorkspaceParams::default()
            }))
            .unwrap();
        let proposed: serde_json::Value =
            serde_json::from_str(&extract_content_text(&proposed)).unwrap();
        let plan_id = proposed["sealed_plan"]["plan"]["plan_id"]
            .as_str()
            .unwrap()
            .to_string();
        let pre_state_id = proposed["sealed_plan"]["pre_state_id"]
            .as_str()
            .unwrap()
            .to_string();

        let requested = server
            .phantom_setup_workspace(Parameters(SetupWorkspaceParams {
                phase: SetupWorkspacePhase::RequestApply,
                plan_id: Some(plan_id),
                pre_state_id: Some(pre_state_id),
                request_id: None,
                confirm: true,
                approval_token: None,
            }))
            .unwrap();
        let text = extract_content_text(&requested);
        let value: serde_json::Value = serde_json::from_str(&text).unwrap();
        let request_id = value["request_id"].as_str().unwrap();

        assert_eq!(request_id.len(), 64);
        assert_eq!(value["state"], "pending");
        assert_eq!(value["applied"], false);
        assert_eq!(value["workspace_mutated"], false);
        assert_eq!(value["vault_mutated"], false);
        assert!(value["trusted_terminal_command"]
            .as_str()
            .unwrap()
            .ends_with(request_id));
        assert!(!text.contains("approval_token"));
        assert_eq!(std::fs::read(dir.path().join(".env")).unwrap(), before_env);
        assert_eq!(
            std::fs::read_dir(dir.path()).unwrap().count(),
            before_entries
        );
        assert!(!dir.path().join(".phantom.toml").exists());
    }

    #[test]
    fn test_setup_workspace_request_apply_does_not_provision_missing_host_key() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let home = TestHome::new();
        let (server, _dir) = setup_test_project();

        let error = server
            .phantom_setup_workspace(Parameters(SetupWorkspaceParams {
                phase: SetupWorkspacePhase::RequestApply,
                plan_id: Some("0".repeat(64)),
                pre_state_id: Some("1".repeat(64)),
                request_id: None,
                confirm: true,
                approval_token: None,
            }))
            .unwrap_err();

        assert_eq!(error.code, rmcp::model::ErrorCode::INTERNAL_ERROR);
        assert!(!home._dir.path().join(".phantom").exists());
    }

    #[test]
    fn test_setup_workspace_rejects_exact_mismatch_and_drift() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _home = TestHome::new();
        let (server, dir) = setup_test_project();
        let proposed = server
            .phantom_setup_workspace(Parameters(SetupWorkspaceParams {
                confirm: true,
                ..SetupWorkspaceParams::default()
            }))
            .unwrap();
        let proposed: serde_json::Value =
            serde_json::from_str(&extract_content_text(&proposed)).unwrap();
        let plan_id = proposed["sealed_plan"]["plan"]["plan_id"]
            .as_str()
            .unwrap()
            .to_string();
        let pre_state_id = proposed["sealed_plan"]["pre_state_id"]
            .as_str()
            .unwrap()
            .to_string();

        let mismatch = server
            .phantom_setup_workspace(Parameters(SetupWorkspaceParams {
                phase: SetupWorkspacePhase::RequestApply,
                plan_id: Some("0".repeat(64)),
                pre_state_id: Some(pre_state_id.clone()),
                request_id: None,
                confirm: true,
                approval_token: None,
            }))
            .unwrap_err();
        assert_eq!(mismatch.code, rmcp::model::ErrorCode::INVALID_PARAMS);

        std::fs::write(
            dir.path().join(".env"),
            "OPENAI_API_KEY=sk-changed-after-propose\n",
        )
        .unwrap();
        let drift = server
            .phantom_setup_workspace(Parameters(SetupWorkspaceParams {
                phase: SetupWorkspacePhase::RequestApply,
                plan_id: Some(plan_id),
                pre_state_id: Some(pre_state_id),
                request_id: None,
                confirm: true,
                approval_token: None,
            }))
            .unwrap_err();
        assert_eq!(drift.code, rmcp::model::ErrorCode::INVALID_PARAMS);
        assert!(drift.message.contains("drift"));
    }

    #[test]
    fn test_setup_workspace_status_is_authenticated_and_workspace_scoped() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let home = TestHome::new();
        let (server, _dir) = setup_test_project();
        let proposed = server
            .phantom_setup_workspace(Parameters(SetupWorkspaceParams {
                confirm: true,
                ..SetupWorkspaceParams::default()
            }))
            .unwrap();
        let proposed: serde_json::Value =
            serde_json::from_str(&extract_content_text(&proposed)).unwrap();
        let requested = server
            .phantom_setup_workspace(Parameters(SetupWorkspaceParams {
                phase: SetupWorkspacePhase::RequestApply,
                plan_id: Some(
                    proposed["sealed_plan"]["plan"]["plan_id"]
                        .as_str()
                        .unwrap()
                        .to_string(),
                ),
                pre_state_id: Some(
                    proposed["sealed_plan"]["pre_state_id"]
                        .as_str()
                        .unwrap()
                        .to_string(),
                ),
                request_id: None,
                confirm: true,
                approval_token: None,
            }))
            .unwrap();
        let requested: serde_json::Value =
            serde_json::from_str(&extract_content_text(&requested)).unwrap();
        let request_id = requested["request_id"].as_str().unwrap().to_string();

        let status = server
            .phantom_setup_workspace(Parameters(SetupWorkspaceParams {
                phase: SetupWorkspacePhase::Status,
                request_id: Some(request_id.clone()),
                ..SetupWorkspaceParams::default()
            }))
            .unwrap();
        let status: serde_json::Value =
            serde_json::from_str(&extract_content_text(&status)).unwrap();
        assert_eq!(status["status"]["state"], "pending");
        assert_eq!(status["applied"], false);

        let other = TempDir::new().unwrap();
        let other_server = PhantomMcpServer::with_dir(other.path().to_path_buf());
        assert!(other_server
            .phantom_setup_workspace(Parameters(SetupWorkspaceParams {
                phase: SetupWorkspacePhase::Status,
                request_id: Some(request_id.clone()),
                ..SetupWorkspaceParams::default()
            }))
            .is_err());

        let record_path = home
            ._dir
            .path()
            .join(".phantom/workspace-requests")
            .join(format!("{request_id}.json"));
        let mut record: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&record_path).unwrap()).unwrap();
        record["state"] = serde_json::json!("applied");
        phantom_core::fs::atomic_write(&record_path, &serde_json::to_vec(&record).unwrap())
            .unwrap();
        assert!(server
            .phantom_setup_workspace(Parameters(SetupWorkspaceParams {
                phase: SetupWorkspacePhase::Status,
                request_id: Some(request_id),
                ..SetupWorkspaceParams::default()
            }))
            .is_err());
    }

    #[test]
    fn test_setup_workspace_params_accept_authority_fields_and_deny_unknown_fields() {
        assert!(
            serde_json::from_value::<SetupWorkspaceParams>(serde_json::json!({
                "phase": "propose",
                "confirm": true,
                "approval_token": "nonce:token"
            }))
            .is_ok()
        );
        assert!(
            serde_json::from_value::<SetupWorkspaceParams>(serde_json::json!({
                "phase": "propose",
                "bearer_token": "must-never-be-accepted"
            }))
            .is_err()
        );
    }

    #[test]
    fn high_effect_tool_schemas_expose_confirm_and_approval_token() {
        fn assert_dual_gate<T: schemars::JsonSchema>() {
            let schema = serde_json::to_value(schemars::schema_for!(T)).unwrap();
            let properties = schema["properties"].as_object().unwrap();
            assert!(properties.contains_key("confirm"));
            assert!(properties.contains_key("approval_token"));
        }

        assert_dual_gate::<SetupWorkspaceParams>();
        assert_dual_gate::<ApprovalParams>();
        assert_dual_gate::<TeamIdParams>();
        assert_dual_gate::<ValidateAllParams>();
        assert_dual_gate::<ValidationScheduleParams>();
        assert_dual_gate::<AuditAlertsParams>();
        assert_dual_gate::<AuditHotspotAlertsParams>();
        assert_dual_gate::<AuditExportReportParams>();
    }

    #[test]
    fn conditional_effects_fail_before_writes_or_provider_calls_without_confirm() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let home = TestHome::new();
        let (server, _dir) = setup_initialized_project();

        let validate = server
            .phantom_validate_all(Parameters(ValidateAllParams {
                jobs: 1,
                confirm: false,
                approval_token: None,
            }))
            .unwrap_err();
        assert!(validate.message.contains("confirm: true"));

        let schedule_path = phantom_core::validation_scheduler::state_file_path(
            server.load_config().unwrap().local_project_id(),
        );
        let schedule = server
            .phantom_validation_schedule(Parameters(ValidationScheduleParams {
                interval: Some("daily".to_string()),
                confirm: false,
                approval_token: None,
            }))
            .unwrap_err();
        assert!(schedule.message.contains("confirm: true"));
        assert!(!schedule_path.exists());

        let alerts = server
            .phantom_audit_alerts(Parameters(AuditAlertsParams {
                last: 10,
                backfill: true,
                confirm: false,
                approval_token: None,
            }))
            .unwrap_err();
        assert!(alerts.message.contains("confirm: true"));
        assert!(!home._dir.path().join(".phantom/leak-alerts.jsonl").exists());

        let report = server
            .phantom_audit_export_report(Parameters(AuditExportReportParams {
                action: "report".to_string(),
                format: "json".to_string(),
                from: None,
                to: None,
                secret_name: None,
                operation: None,
                save: true,
                confirm: false,
                approval_token: None,
            }))
            .unwrap_err();
        assert!(report.message.contains("confirm: true"));
        assert!(!home._dir.path().join(".phantom/reports").exists());
    }

    #[test]
    fn realtime_incident_params_reject_simulated_auto_rotation() {
        assert!(
            serde_json::from_value::<LeakIncidentsRealtimeParams>(serde_json::json!({
                "min_confidence": 0.9,
                "auto_rotate_on_high": true,
                "confirm": true
            }))
            .is_err()
        );
    }

    #[test]
    fn auto_rotate_compat_schema_is_truthful_about_token_remap() {
        let schema = serde_json::to_value(schemars::schema_for!(AutoRotateParams)).unwrap();
        let text = schema.to_string();
        assert!(text.contains("provider credential is not rotated"));
        assert!(text.contains("truthfully be synced"));
        assert!(!text.contains("extend its expiry"));
    }

    #[test]
    fn auto_rotate_compat_remaps_only_and_rejects_sync_before_write() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let (server, dir) = setup_initialized_project();
        let (_config, vault) = server.load_config_and_vault().unwrap();
        let metadata = phantom_vault::metadata::SecretMetadata {
            created_at: Some(100),
            rotated_at: Some(200),
            expires_at: Some(300),
            rotation_policy: Some(phantom_vault::metadata::RotationPolicy {
                days_ttl: 30,
                auto_rotate: false,
            }),
            vault_mode: phantom_vault::metadata::VaultMode::ReadOnly,
        };
        vault
            .set_metadata("OPENAI_API_KEY", metadata.clone())
            .unwrap();

        let env_path = dir.path().join(".env");
        let before = std::fs::read_to_string(&env_path).unwrap();
        let result = server
            .phantom_secrets_auto_rotate(Parameters(AutoRotateParams {
                name: "OPENAI_API_KEY".to_string(),
                sync: false,
                confirm: true,
                approval_token: None,
            }))
            .unwrap();
        let after = std::fs::read_to_string(&env_path).unwrap();
        assert_ne!(before, after);
        assert!(extract_content_text(&result).contains("Provider credential"));
        assert_eq!(
            vault.get_metadata("OPENAI_API_KEY").unwrap(),
            Some(metadata)
        );

        let before_rejected_sync = std::fs::read_to_string(&env_path).unwrap();
        let error = server
            .phantom_secrets_auto_rotate(Parameters(AutoRotateParams {
                name: "OPENAI_API_KEY".to_string(),
                sync: true,
                confirm: true,
                approval_token: None,
            }))
            .unwrap_err();
        assert!(error.message.contains("provider credential is unchanged"));
        assert_eq!(
            std::fs::read_to_string(&env_path).unwrap(),
            before_rejected_sync
        );
    }

    #[test]
    fn team_invite_role_contract_matches_hosted_api() {
        for role in ["member", "admin"] {
            let parsed = serde_json::from_value::<TeamInviteParams>(serde_json::json!({
                "team_id": "team-id",
                "github_login": "octocat",
                "role": role
            }));
            assert!(parsed.is_ok(), "{role} must remain accepted");
        }
        let owner = serde_json::from_value::<TeamInviteParams>(serde_json::json!({
            "team_id": "team-id",
            "github_login": "octocat",
            "role": "owner"
        }));
        assert!(
            owner.is_err(),
            "owner invitations are not hosted API operations"
        );
    }

    #[test]
    fn test_capability_hard_denies_external_effects_without_locus() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let (server, _dir) = setup_test_project();

        let result = server.phantom_capability().unwrap();
        let text = extract_content_text(&result);
        let value: serde_json::Value = serde_json::from_str(&text).unwrap();

        assert_eq!(value["authority"], "no_locus_seal");
        assert!(value["place"].is_null());
        assert!(value["seal_id"].is_null());
        let hard_nos = value["hard_nos"].as_array().unwrap();
        for verb in [
            "external_mutation",
            "production",
            "delete",
            "share",
            "spend",
            "secret_reveal",
        ] {
            assert!(hard_nos.iter().any(|entry| entry["verb"] == verb));
        }
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
                approval_token: None,
            }))
            .unwrap_err();
        assert_eq!(add_err.code, rmcp::model::ErrorCode::INVALID_PARAMS);
        assert!(add_err.message.contains("confirm: true"));

        let rm_err = server
            .phantom_remove_secret(Parameters(RemoveSecretParams {
                name: "OPENAI_API_KEY".to_string(),
                confirm: false,
                approval_token: None,
            }))
            .unwrap_err();
        assert_eq!(rm_err.code, rmcp::model::ErrorCode::INVALID_PARAMS);

        let rotate_err = server
            .phantom_rotate(Parameters(RotateParams {
                confirm: false,
                approval_token: None,
            }))
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
                approval_token: None,
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
                    approval_token: None,
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
                approval_token: None,
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
            .phantom_rotate(Parameters(RotateParams {
                confirm: true,
                approval_token: None,
            }))
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
                approval_token: None,
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
                approval_token: None,
            }))
            .unwrap_err();
        assert_eq!(err.code, rmcp::model::ErrorCode::INVALID_PARAMS);
    }

    #[test]
    fn test_rotate_with_expiry_compat_remaps_without_ttl_metadata() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let (server, dir) = setup_initialized_project();
        let (_config, vault) = server.load_config_and_vault().unwrap();
        let metadata_before = vault.list_with_metadata().unwrap();
        let env_before = std::fs::read_to_string(dir.path().join(".env")).unwrap();

        let result = server
            .phantom_rotate_with_expiry(Parameters(RotateWithExpiryParams {
                days_ttl: 7,
                confirm: true,
                approval_token: None,
            }))
            .unwrap();
        let text = get_result_text(&result);
        assert!(text.contains("Remapped"), "should report token remap");
        assert!(text.contains("metadata are unchanged"));

        // .env placeholders change, but credential lifecycle metadata does not.
        let env_content = std::fs::read_to_string(dir.path().join(".env")).unwrap();
        assert!(env_content.contains("phm_"));
        assert_ne!(env_content, env_before);
        assert_eq!(vault.list_with_metadata().unwrap(), metadata_before);

        let list_result = server
            .phantom_list_with_expiry(Parameters(ListWithExpiryParams { show_expiry: true }))
            .unwrap();
        let list_text = get_result_text(&list_result);
        assert!(
            list_text.contains("no expiry"),
            "compatibility remap must not manufacture TTL metadata: {list_text}"
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
    fn write_synthetic_audit_log(
        home_dir: &std::path::Path,
        entries: &[(u64, &str, Option<&str>)],
    ) {
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
        assert!(
            json.get("total_returned").is_some(),
            "must have 'total_returned'"
        );
        assert!(
            json.get("total_in_log").is_some(),
            "must have 'total_in_log'"
        );
        let events = json["events"].as_array().unwrap();
        assert_eq!(events.len(), 3);
    }

    #[test]
    fn test_audit_recent_never_exposes_secret_values() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let (server, _dir) = setup_initialized_project();
        let home = tempfile::TempDir::new().unwrap();
        let _prev_home = std::env::var("HOME").ok();
        unsafe { std::env::set_var("HOME", home.path()) };
        let now = 1_700_000_000_u64;
        write_synthetic_audit_log(home.path(), &[(now, "vault.store", Some("OPENAI_API_KEY"))]);

        let result = server
            .phantom_audit_recent(Parameters(AuditRecentParams {
                n: 10,
                op_filter: None,
                name_filter: None,
            }))
            .unwrap();

        let text = extract_content_text(&result);
        assert!(
            !text.contains("sk-test-key"),
            "must not expose secret value"
        );
        assert!(
            !text.contains("postgres://user:pass"),
            "must not expose DB credentials"
        );
        assert!(
            text.contains("OPENAI_API_KEY"),
            "should contain secret name"
        );
    }

    #[test]
    fn test_audit_recent_op_filter() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let (server, _dir) = setup_initialized_project();
        let home = tempfile::TempDir::new().unwrap();
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
        let _prev_home = std::env::var("HOME").ok();
        unsafe { std::env::set_var("HOME", home.path()) };
        let now = 1_700_000_000_u64;
        write_synthetic_audit_log(home.path(), &[(now, "vault.store", Some("OPENAI_API_KEY"))]);

        let result = server
            .phantom_audit_recent(Parameters(AuditRecentParams {
                n: 10,
                op_filter: None,
                name_filter: None,
            }))
            .unwrap();

        let json = parse_result_json(&result);
        for event in json["events"].as_array().unwrap() {
            assert!(
                event.get("value").is_none(),
                "event must not have 'value' field"
            );
        }
    }

    // ── phantom_audit_anomalies ───────────────────────────────────────

    #[test]
    fn test_audit_anomalies_returns_findings_array() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let (server, _dir) = setup_initialized_project();
        let home = tempfile::TempDir::new().unwrap();
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
        assert!(
            json.get("total_findings").is_some(),
            "must have 'total_findings'"
        );
        assert!(
            json.get("generated_at").is_some(),
            "must have 'generated_at'"
        );
        assert!(json.get("period").is_some(), "must have 'period'");
    }

    #[test]
    fn test_audit_anomalies_detects_spike() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let (server, _dir) = setup_initialized_project();
        let home = tempfile::TempDir::new().unwrap();
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
        assert!(
            f.get("value").is_none(),
            "finding must not expose secret value"
        );
    }

    #[test]
    fn test_audit_anomalies_detects_dormant() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let (server, _dir) = setup_initialized_project();
        // Use a separate isolated HOME so this test sees only its own audit events.
        let home = tempfile::TempDir::new().unwrap();
        let _prev_home = std::env::var("HOME").ok();
        unsafe { std::env::set_var("HOME", home.path()) };

        let t0 = 1_700_000_000_u64;
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
        let f = findings
            .iter()
            .find(|f| f["name"] == "DORMANT_KEY")
            .unwrap();
        // dormant rule: score 0.5; spike: max_daily=1, daily_avg≈0.61, 1 is NOT > 3*0.61=1.83
        // So anomaly_type should be "dormant"
        assert_eq!(
            f["anomaly_type"], "dormant",
            "anomaly_type should be dormant: {f}"
        );
        assert!(f["anomaly_score"].as_f64().unwrap() >= 0.5);
    }

    #[test]
    fn test_audit_anomalies_finding_schema_no_value() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let (server, _dir) = setup_initialized_project();
        let home = tempfile::TempDir::new().unwrap();
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
            assert!(
                f.get("anomaly_type").is_some(),
                "finding must have 'anomaly_type'"
            );
            assert!(
                f.get("anomaly_score").is_some(),
                "finding must have 'anomaly_score'"
            );
            assert!(
                f.get("access_count").is_some(),
                "finding must have 'access_count'"
            );
            assert!(
                f.get("last_access").is_some(),
                "finding must have 'last_access'"
            );
            assert!(f.get("context").is_some(), "finding must have 'context'");
            assert!(f.get("value").is_none(), "finding must NOT have 'value'");
        }
    }

    #[test]
    fn test_audit_anomalies_min_score_filter() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let (server, _dir) = setup_initialized_project();
        let home = tempfile::TempDir::new().unwrap();
        let _prev_home = std::env::var("HOME").ok();
        unsafe { std::env::set_var("HOME", home.path()) };

        // Use uniform pattern (10 daily accesses + 8-day gap) that only triggers dormant (0.5)
        let t0 = 1_700_000_000_u64;
        let mut entries: Vec<(u64, &str, Option<&str>)> = Vec::new();
        for i in 0u64..10 {
            entries.push((t0 + i * 86400, "vault.retrieve", Some("FILTER_KEY")));
        }
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

    // ── phantom_audit_hotspot_alerts ─────────────────────────────────

    #[test]
    fn test_hotspot_alerts_returns_required_schema() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let (server, _dir) = setup_initialized_project();
        let home = tempfile::TempDir::new().unwrap();
        unsafe { std::env::set_var("HOME", home.path()) };

        let result = server
            .phantom_audit_hotspot_alerts(Parameters(AuditHotspotAlertsParams {
                secret_name: None,
                ack: false,
                snooze_seconds: 0,
                include_acked: false,
                confirm: false,
                approval_token: None,
            }))
            .unwrap();

        let json = parse_result_json(&result);
        assert!(
            json.get("generated_at").is_some(),
            "must have 'generated_at'"
        );
        assert!(
            json.get("total_alerts").is_some(),
            "must have 'total_alerts'"
        );
        assert!(json.get("alerts").is_some(), "must have 'alerts'");
        assert!(
            json.get("ack_performed").is_some(),
            "must have 'ack_performed'"
        );
        // Empty log → no alerts.
        assert_eq!(json["total_alerts"].as_u64().unwrap(), 0);
    }

    #[test]
    fn test_hotspot_alerts_detects_velocity_spike() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let (server, _dir) = setup_initialized_project();
        let home = tempfile::TempDir::new().unwrap();
        unsafe { std::env::set_var("HOME", home.path()) };

        // Build a spike: 2 accesses/day baseline × 7 days, then 30 in the last 24h.
        // 30 > 5 × 2 = 10 → velocity spike fires.
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let mut entries: Vec<(u64, &str, Option<&str>)> = Vec::new();
        for day in 1u64..=7 {
            for i in 0u64..2 {
                entries.push((
                    now - day * 86400 + i * 1800,
                    "vault.retrieve",
                    Some("HOTKEY"),
                ));
            }
        }
        for i in 0u64..30 {
            entries.push((now - 80000 + i * 2500, "vault.retrieve", Some("HOTKEY")));
        }
        write_synthetic_audit_log(home.path(), &entries);

        let result = server
            .phantom_audit_hotspot_alerts(Parameters(AuditHotspotAlertsParams {
                secret_name: None,
                ack: false,
                snooze_seconds: 0,
                include_acked: false,
                confirm: false,
                approval_token: None,
            }))
            .unwrap();

        let json = parse_result_json(&result);
        let alerts = json["alerts"].as_array().unwrap();
        assert!(
            !alerts.is_empty(),
            "velocity spike should produce a hotspot alert"
        );
        let alert = alerts
            .iter()
            .find(|a| a["secret_name"] == "HOTKEY")
            .unwrap();
        assert_eq!(alert["alert_level"], "high");
        assert!(
            alert.get("value").is_none(),
            "alert must never contain secret value"
        );
        assert!(
            alert.get("secret_name").is_some(),
            "alert must have secret_name"
        );
        assert!(
            alert.get("current_velocity").is_some(),
            "alert must have current_velocity"
        );
        assert!(
            alert.get("baseline_velocity").is_some(),
            "alert must have baseline_velocity"
        );
        assert!(
            alert.get("first_spike_ts").is_some(),
            "alert must have first_spike_ts"
        );
        assert!(
            alert.get("ack_status").is_some(),
            "alert must have ack_status"
        );
        assert_eq!(alert["ack_status"], "unacked");
    }

    #[test]
    fn test_hotspot_alerts_ack_clears_alert() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let (server, _dir) = setup_initialized_project();
        let home = tempfile::TempDir::new().unwrap();
        unsafe { std::env::set_var("HOME", home.path()) };

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let mut entries: Vec<(u64, &str, Option<&str>)> = Vec::new();
        for day in 1u64..=7 {
            entries.push((now - day * 86400, "vault.retrieve", Some("ACKKEY")));
        }
        for i in 0u64..30 {
            entries.push((now - 80000 + i * 2500, "vault.retrieve", Some("ACKKEY")));
        }
        write_synthetic_audit_log(home.path(), &entries);

        // Acknowledge all alerts.
        let result = server
            .phantom_audit_hotspot_alerts(Parameters(AuditHotspotAlertsParams {
                secret_name: None,
                ack: true,
                snooze_seconds: 0,
                include_acked: false,
                confirm: true,
                approval_token: None,
            }))
            .unwrap();

        let json = parse_result_json(&result);
        assert!(json["ack_performed"].as_bool().unwrap());
        // After ack with include_acked=false, active alerts list should be empty.
        assert_eq!(
            json["total_alerts"].as_u64().unwrap(),
            0,
            "after ack, no unacked alerts should remain"
        );
    }

    #[test]
    fn test_hotspot_alerts_secret_name_filter() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let (server, _dir) = setup_initialized_project();
        let home = tempfile::TempDir::new().unwrap();
        unsafe { std::env::set_var("HOME", home.path()) };

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        // Two spiking keys.
        let mut entries: Vec<(u64, &str, Option<&str>)> = Vec::new();
        for day in 1u64..=7 {
            entries.push((now - day * 86400, "vault.retrieve", Some("KEY_A")));
            entries.push((now - day * 86400 + 100, "vault.retrieve", Some("KEY_B")));
        }
        for i in 0u64..30 {
            entries.push((now - 80000 + i * 2500, "vault.retrieve", Some("KEY_A")));
            entries.push((now - 80000 + i * 2500 + 50, "vault.retrieve", Some("KEY_B")));
        }
        write_synthetic_audit_log(home.path(), &entries);

        let result = server
            .phantom_audit_hotspot_alerts(Parameters(AuditHotspotAlertsParams {
                secret_name: Some("KEY_A".to_string()),
                ack: false,
                snooze_seconds: 0,
                include_acked: false,
                confirm: false,
                approval_token: None,
            }))
            .unwrap();

        let json = parse_result_json(&result);
        let alerts = json["alerts"].as_array().unwrap();
        assert!(
            alerts.iter().all(|a| a["secret_name"] == "KEY_A"),
            "filter by secret_name should only return KEY_A alerts"
        );
        assert!(
            alerts.iter().all(|a| a["secret_name"] != "KEY_B"),
            "KEY_B should not appear when filtered to KEY_A"
        );
    }

    #[test]
    fn test_hotspot_alerts_never_exposes_value_field() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let (server, _dir) = setup_initialized_project();
        let home = tempfile::TempDir::new().unwrap();
        unsafe { std::env::set_var("HOME", home.path()) };

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let mut entries: Vec<(u64, &str, Option<&str>)> = Vec::new();
        for day in 1u64..=7 {
            entries.push((now - day * 86400, "vault.retrieve", Some("OPENAI_API_KEY")));
        }
        for i in 0u64..30 {
            entries.push((
                now - 80000 + i * 2500,
                "vault.retrieve",
                Some("OPENAI_API_KEY"),
            ));
        }
        write_synthetic_audit_log(home.path(), &entries);

        let result = server
            .phantom_audit_hotspot_alerts(Parameters(AuditHotspotAlertsParams {
                secret_name: None,
                ack: false,
                snooze_seconds: 0,
                include_acked: false,
                confirm: false,
                approval_token: None,
            }))
            .unwrap();

        let json = parse_result_json(&result);
        for alert in json["alerts"].as_array().unwrap() {
            assert!(
                alert.get("value").is_none(),
                "alert must never expose a 'value' field"
            );
        }
        // Also verify the raw text doesn't contain any secret-shaped value.
        let text = extract_content_text(&result);
        assert!(
            !text.contains("sk-"),
            "result text must not contain OpenAI key pattern"
        );
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
        assert!(
            json.get("generated_at").is_some(),
            "must have 'generated_at'"
        );
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
        assert!(
            !analytics.is_empty(),
            "filtered analytics should include SPIKE_KEY"
        );
        let spike = analytics.iter().find(|s| s["name"] == "SPIKE_KEY").unwrap();
        assert!(
            spike["anomaly_score"].as_f64().unwrap() >= 0.6,
            "spike anomaly_score must be >= 0.6"
        );
        // Records must not expose values
        for rec in json["records"].as_array().unwrap() {
            assert!(
                rec.get("value").is_none(),
                "records must never expose secret values"
            );
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

        assert!(
            text.starts_with("ts,datetime,op,name,process\n"),
            "CSV must start with header"
        );
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
    fn compliance_status_rejects_stale_network_capable_hook() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let (server, dir) = setup_initialized_project();
        assert!(std::process::Command::new("git")
            .args(["init", "--quiet"])
            .current_dir(dir.path())
            .status()
            .unwrap()
            .success());
        std::fs::create_dir_all(dir.path().join(".git/hooks")).unwrap();
        std::fs::write(
            dir.path().join(".git/hooks/pre-commit"),
            "#!/bin/sh\n# Phantom Secrets pre-commit hook\nnpx phantom-secrets check --staged\n",
        )
        .unwrap();

        let result = server
            .phantom_compliance_status(Parameters(ComplianceStatusParams {}))
            .unwrap();

        let json = parse_result_json(&result);
        assert_eq!(json["checks"]["precommit_installed"]["pass"], false);
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
            assert!(
                check.get("pass").is_some(),
                "check '{name}' must have 'pass'"
            );
            assert!(
                check.get("detail").is_some(),
                "check '{name}' must have 'detail'"
            );
            assert!(
                check["pass"].is_boolean(),
                "check '{name}' pass must be boolean"
            );
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
            json["checks"]["vault_accessible"]["pass"]
                .as_bool()
                .unwrap(),
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
        assert!(
            !text.contains("sk-test-key"),
            "must not expose OPENAI secret"
        );
        assert!(
            !text.contains("postgres://user:pass"),
            "must not expose DB credentials"
        );
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
            !json["checks"]["secrets_have_ttl"]["pass"]
                .as_bool()
                .unwrap(),
            "secrets_have_ttl should be false when no rotation policy set"
        );
        assert!(
            !json["compliant"].as_bool().unwrap(),
            "compliant must be false when any check fails"
        );
    }

    #[test]
    fn test_compliance_status_secrets_have_ttl_true_after_explicit_policy_set() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let (server, _dir) = setup_initialized_project();
        let (_config, vault) = server.load_config_and_vault().unwrap();
        for name in vault.list().unwrap() {
            vault.set_rotation_policy(&name, 30).unwrap();
        }

        let result = server
            .phantom_compliance_status(Parameters(ComplianceStatusParams {}))
            .unwrap();

        let json = parse_result_json(&result);
        assert!(
            json["checks"]["secrets_have_ttl"]["pass"]
                .as_bool()
                .unwrap(),
            "secrets_have_ttl should be true after an explicit policy is set"
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
        assert!(
            !no_ttl.is_empty(),
            "secrets without TTL should appear in no_ttl"
        );
        for entry in no_ttl {
            assert!(entry.get("name").is_some(), "entry must have 'name'");
            assert_eq!(entry["status"], "no_ttl");
        }
    }

    #[test]
    fn test_rotation_due_ok_with_fresh_ttl() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let (server, _dir) = setup_initialized_project();

        let (_config, vault) = server.load_config_and_vault().unwrap();
        for name in vault.list().unwrap() {
            vault.set_rotation_policy(&name, 30).unwrap();
        }

        let result = server
            .phantom_secret_rotation_due(Parameters(RotationDueParams { warn_days: 7 }))
            .unwrap();

        let json = parse_result_json(&result);
        let ok = json["ok"].as_array().unwrap();
        assert!(
            !ok.is_empty(),
            "fresh 30-day TTL should place secrets in 'ok'"
        );
        for entry in ok {
            assert_eq!(entry["status"], "ok");
            let days = entry["days_remaining"].as_i64().unwrap_or(-1);
            assert!(days > 0, "days_remaining should be positive");
            assert!(
                entry["expires_at"].is_string(),
                "expires_at must be a string"
            );
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
        assert!(
            !text.contains("sk-test-key"),
            "must not expose OPENAI secret"
        );
        assert!(
            !text.contains("postgres://user:pass"),
            "must not expose DB credentials"
        );
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
                    assert!(
                        entry.get("value").is_none(),
                        "entry in '{category}' must not have 'value'"
                    );
                }
            }
        }
    }

    #[test]
    fn test_rotation_due_warn_days_respected() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let (server, _dir) = setup_initialized_project();

        let (_config, vault) = server.load_config_and_vault().unwrap();
        for name in vault.list().unwrap() {
            vault.set_rotation_policy(&name, 30).unwrap();
        }

        // warn_days=31 > ttl=30 → all should be in 'warning'
        let result = server
            .phantom_secret_rotation_due(Parameters(RotationDueParams { warn_days: 31 }))
            .unwrap();

        let json = parse_result_json(&result);
        let warning = json["warning"].as_array().unwrap();
        assert!(
            !warning.is_empty(),
            "with warn_days=31, 30-day TTL secrets should be in warning"
        );
        assert!(
            json["ok"].as_array().unwrap().is_empty(),
            "ok should be empty"
        );
    }
}
