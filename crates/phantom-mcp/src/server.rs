use phantom_core::config::PhantomConfig;
use phantom_core::dotenv::{classify, is_public_key, DotenvFile, SecretClassification};
use phantom_core::fs::{AnchoredEffect, AnchoredRead, AnchoredTarget, TrustedAnchor};
use phantom_core::precommit_hook::{self, HookChange};
use phantom_core::token::{PhantomToken, TokenMap};
use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::*;
use rmcp::{tool, tool_handler, tool_router, ErrorData as McpError, ServerHandler};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

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

fn commit_mcp_precommit_repair(project_dir: &Path) -> Result<Option<HookChange>, McpError> {
    let Some(plan) = precommit_hook::prepare_install_plan(project_dir).map_err(|error| {
        internal_err(format!(
            "Failed to prepare the exact effective Git pre-commit hook repair: {error}"
        ))
    })?
    else {
        return Ok(None);
    };
    if plan.change() != HookChange::Unchanged && plan.authority().is_external() {
        return Err(invalid_params_err(
            "MCP cannot authorize writes to an external effective Git hook. Run `phantom doctor --fix` in an attached trusted terminal to review and authorize the exact global/system core.hooksPath; no hook was changed.",
        ));
    }
    precommit_hook::commit_prepared_install(project_dir, &plan, None)
        .map(Some)
        .map_err(|error| {
            internal_err(format!(
                "Failed to commit the exact effective Git pre-commit hook repair: {error}"
            ))
        })
}
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

    fn env_path(&self) -> Result<PathBuf, McpError> {
        let (config, vault) = self.load_config_and_vault()?;
        let vault_names = vault
            .list()
            .map_err(|error| internal_err(format!("Failed to list vault secrets: {error}")))?;
        self.resolve_env_path(&config, &vault_names)
    }

    fn resolve_env_path(
        &self,
        config: &PhantomConfig,
        vault_names: &[String],
    ) -> Result<PathBuf, McpError> {
        phantom_core::managed_dotenv::resolve_dotenv(&self.project_dir, config, vault_names)
            .map(|resolved| resolved.path)
            .map_err(|error| internal_err(format!("Failed to resolve managed dotenv: {error}")))
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
        let vault = phantom_vault::try_create_vault(config.local_project_id())
            .map_err(|error| internal_err(format!("Failed to initialize vault: {error}")))?;
        Ok((config, vault))
    }

    fn load_config_and_vault_anchored(
        &self,
    ) -> Result<
        (
            phantom_vault::ProjectTransactionLock,
            PhantomConfig,
            Box<dyn phantom_vault::VaultBackend>,
        ),
        McpError,
    > {
        self.load_config_and_vault_anchored_with(|| {})
    }

    fn load_config_and_vault_anchored_with(
        &self,
        before_project_lock: impl FnOnce(),
    ) -> Result<
        (
            phantom_vault::ProjectTransactionLock,
            PhantomConfig,
            Box<dyn phantom_vault::VaultBackend>,
        ),
        McpError,
    > {
        // Vault construction may take PROCESS_ENV_LOCK while resolving the
        // backend. Finish that process-global work before the per-project lock
        // so no caller can invert the shared lock order.
        let reviewed_project_root = self.project_dir.canonicalize().map_err(|error| {
            internal_err(format!("Failed to resolve canonical project root: {error}"))
        })?;
        let reviewed_project = TrustedAnchor::open(&reviewed_project_root).map_err(|error| {
            internal_err(format!("Failed to retain reviewed project root: {error}"))
        })?;
        let reviewed_local_project_id = PhantomConfig::project_id_from_path(&reviewed_project_root);
        let config_path = reviewed_project_root.join(".phantom.toml");
        let reviewed_config_target = reviewed_project
            .target(".phantom.toml")
            .map_err(|error| internal_err(format!("Failed to retain Phantom config: {error}")))?;
        let reviewed_config = reviewed_config_target
            .read_regular()
            .map_err(|error| internal_err(format!("Failed to safely read config: {error}")))?
            .ok_or_else(|| internal_err("Not initialized. Run `phantom init` first."))?;
        let config = PhantomConfig::load_from_bytes(&config_path, reviewed_config.bytes())
            .map_err(|error| internal_err(format!("Failed to load config: {error}")))?;
        if config.local_project_id() != reviewed_local_project_id {
            return Err(internal_err(
                "Reviewed config did not bind to the canonical local project identity; no project payload was used.",
            ));
        }
        let vault = phantom_vault::try_create_vault(&reviewed_local_project_id)
            .map_err(|error| internal_err(format!("Failed to initialize vault: {error}")))?;

        before_project_lock();
        let transaction_lock = phantom_vault::acquire_project_transaction_lock(
            &reviewed_project_root,
        )
        .map_err(|error| internal_err(format!("Failed to acquire project lock: {error}")))?;
        if transaction_lock.project_root_at_acquisition() != reviewed_project_root {
            return Err(internal_err(
                "Project root changed while acquiring the project lock; no retained project payload was used.",
            ));
        }
        if transaction_lock.project_identity_at_acquisition() != reviewed_project.identity() {
            return Err(internal_err(
                "Project root was replaced while opening its vault; no retained project payload was used.",
            ));
        }

        let config_target = transaction_lock
            .target(&config_path)
            .map_err(|error| internal_err(format!("Failed to retain Phantom config: {error}")))?;
        let retained_config = config_target
            .read_regular()
            .map_err(|error| internal_err(format!("Failed to safely read config: {error}")))?
            .ok_or_else(|| internal_err("Not initialized. Run `phantom init` first."))?;
        if retained_config.identity() != reviewed_config.identity()
            || retained_config.bytes() != reviewed_config.bytes()
            || retained_config.permissions() != reviewed_config.permissions()
        {
            return Err(internal_err(
                "Phantom config changed while opening its vault; no retained project payload was used.",
            ));
        }
        Ok((transaction_lock, config, vault))
    }

    fn save_cloud_version(
        &self,
        vault: &dyn phantom_vault::VaultBackend,
        config: &mut PhantomConfig,
        config_before: Vec<u8>,
        version: u64,
    ) -> Result<(), McpError> {
        let cloud_config = config.cloud.get_or_insert_default();
        cloud_config.version = version;
        cloud_config.reconciliation_required = false;
        cloud_config.reconciliation_remote_version = None;
        let config_after = toml::to_string_pretty(config)
            .map_err(|error| internal_err(format!("Failed to serialize cloud version: {error}")))?
            .into_bytes();
        let config_file = phantom_vault::InitFile::replace_if_unchanged(
            self.config_path(),
            Some(config_before),
            config_after,
        );
        phantom_vault::commit_init(&self.project_dir, vault, Vec::new(), vec![config_file])
            .map_err(|error| {
            internal_err(format!(
                "Cloud upload succeeded at remote version {version}, but the local version could not be recorded: {error}. Do not retry automatically; inspect remote and local versions first."
            ))
        })?;
        Ok(())
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
        description = "Read repository-local Phantom status without opening or provisioning a vault: project ID, managed dotenv protection counts, and configured service mappings. Vault backend and stored-secret inventory are deliberately not inspected; use phantom_list_secrets for the latter."
    )]
    fn phantom_status(&self) -> Result<CallToolResult, McpError> {
        if !self.config_path().exists() {
            return text_result(
                "Phantom is not initialized in this directory.\nRun `phantom init` to get started.",
            );
        }

        let config = self.load_config().map_err(internal_err)?;

        let mut output = String::new();
        output.push_str(&format!("Project ID: {}\n", config.portable_project_id()));
        output.push_str("Vault backend: not inspected (read-only status)\n");
        output.push_str("Secrets stored: not inspected (use phantom_list_secrets)\n");

        // Resolve only repository-local state. Passing no vault names avoids
        // opening/provisioning any credential backend from this status tool.
        let env_path =
            phantom_core::managed_dotenv::resolve_dotenv(&self.project_dir, &config, &[])
                .map_err(|error| {
                    internal_err(format!("Failed to resolve managed dotenv: {error}"))
                })?
                .path;
        if env_path.exists() {
            if let Ok(dotenv) = DotenvFile::parse_file(&env_path) {
                let real = dotenv.real_secret_entries();
                let total = dotenv.entries().len();
                let phantom_count = dotenv.entries().iter().filter(|e| e.is_phantom).count();
                output.push_str(&format!(
                    "{}: {} entries ({} phantom tokens, {} unprotected)\n",
                    env_path.display(),
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
        description = "Initialize Phantom through one exact-before project transaction: read a safe project-local dotenv, compare-and-swap every vault entry, persist config, and rewrite the dotenv with phantom tokens last. Concurrent file or vault changes abort and transaction-owned writes are rolled back where verifiable. Requires confirm plus out-of-band approval."
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
        let env_name = phantom_core::managed_dotenv::validate_dotenv_basename(&params.env_path)
            .map_err(|error| invalid_params_err(error.to_string()))?;
        let env_path = self.project_dir.join(&env_name);
        let env_before = zeroize::Zeroizing::new(
            phantom_core::fs::read_regular_file(&env_path)
                .map_err(|error| {
                    invalid_params_err(format!("Failed to safely read {env_name}: {error}"))
                })?
                .ok_or_else(|| invalid_params_err(format!("{env_name} does not exist")))?,
        );
        let env_text = std::str::from_utf8(env_before.as_slice())
            .map_err(|_| invalid_params_err(format!("{env_name} is not valid UTF-8")))?;
        let dotenv = DotenvFile::parse_str(env_text);

        let real_entries = dotenv.real_secret_entries();
        if real_entries.is_empty() {
            return text_result(
                "No real secrets found in .env (all values are already phantom tokens or non-secret config).",
            );
        }

        let config_path = self.config_path();
        let config_before = phantom_core::fs::read_regular_file(&config_path)
            .map_err(|error| internal_err(format!("Failed to safely read config: {error}")))?;
        let project_id = PhantomConfig::project_id_from_path(&self.project_dir);
        let mut config = if config_before.is_some() {
            let config = PhantomConfig::load(&config_path)
                .map_err(|e| internal_err(format!("Config error: {e}")))?;
            if phantom_core::fs::read_regular_file(&config_path)
                .map_err(|error| internal_err(format!("Failed to recheck config: {error}")))?
                .as_deref()
                != config_before.as_deref()
            {
                return Err(internal_err(
                    ".phantom.toml changed during initialization preflight",
                ));
            }
            config
        } else {
            PhantomConfig::new_with_defaults(project_id.clone())
        };
        config.phantom.dotenv_path = Some(env_name);

        let mut token_map = TokenMap::new();
        for entry in &real_entries {
            token_map.insert(entry.key.clone());
        }
        let (phantomized, mut originals) = dotenv.rewrite_with_phantoms(&token_map);
        for value in originals.values_mut() {
            use zeroize::Zeroize;
            value.zeroize();
        }
        originals.clear();
        let files = vec![
            phantom_vault::InitFile::replace_if_unchanged(
                &env_path,
                Some(env_before.as_slice().to_vec()),
                phantomized.into_bytes(),
            )
            .commit_last(),
            phantom_vault::InitFile::replace_if_unchanged(
                &config_path,
                config_before,
                toml::to_string_pretty(&config)
                    .map_err(|_| internal_err("Failed to serialize config"))?
                    .into_bytes(),
            ),
        ];
        let vault = phantom_vault::try_create_vault(config.local_project_id())
            .map_err(|error| internal_err(format!("Failed to initialize vault: {error}")))?;
        let secrets = real_entries
            .iter()
            .map(|entry| {
                let before = retrieve_optional_secret(
                    vault.as_ref(),
                    &entry.key,
                    "initialization destination",
                )?;
                Ok(phantom_vault::InitSecret::replace_if_unchanged(
                    entry.key.clone(),
                    before.as_ref().map(|value| value.as_str().to_string()),
                    entry.value.clone(),
                ))
            })
            .collect::<Result<Vec<_>, McpError>>()?;
        let receipt = phantom_vault::commit_init(&self.project_dir, vault.as_ref(), secrets, files)
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
        if !receipt.namespace_durability_verified {
            output.push_str(
                "Warning: namespace effects were committed and verified, but directory crash durability is not provable on this platform.\n",
            );
        }
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

    /// Remove a secret and its managed local ownership records.
    #[tool(
        description = "Transactionally remove a secret's vault value, lifecycle configuration, and exact managed-dotenv mapping. DESTRUCTIVE — a successful removal is recoverable only from a separately retained backup. Uses exact before-images and rolls back only transaction-owned changes. Requires `confirm: true` plus an out-of-band `approval_token`; review the exact value-blind effect before approval."
    )]
    fn phantom_remove_secret(
        &self,
        Parameters(params): Parameters<RemoveSecretParams>,
    ) -> Result<CallToolResult, McpError> {
        require_confirm("phantom_remove_secret", params.confirm)?;
        let canonical_project = self.project_dir.canonicalize().map_err(|error| {
            internal_err(format!("Failed to resolve project directory: {error}"))
        })?;
        let config_path = canonical_project.join(".phantom.toml");
        let config_before = phantom_core::fs::read_regular_file(&config_path)
            .map_err(|error| internal_err(format!("Failed to read config safely: {error}")))?
            .ok_or_else(|| internal_err("Project is not initialized"))?;
        let config = PhantomConfig::load_from_bytes(&config_path, &config_before)
            .map_err(|error| internal_err(format!("Failed to parse exact config: {error}")))?;
        let vault = phantom_vault::try_create_vault(config.local_project_id())
            .map_err(|error| internal_err(format!("Failed to open vault: {error}")))?;
        let plan = phantom_vault::ManagedRemovePlan::prepare(
            &canonical_project,
            config_before,
            vault.as_ref(),
            &params.name,
        )
        .map_err(|error| {
            internal_err(format!(
                "Removal preflight failed; no secret value was read and no state changed: {error}"
            ))
        })?;
        let params_json = serde_json::to_string(&serde_json::json!({
            "request": &params,
            "canonical_project": plan.project_dir(),
            "local_project_id": plan.local_project_id(),
            "managed_dotenv": plan.dotenv_path(),
            "before_digest": plan.before_digest(),
        }))
        .map_err(|error| internal_err(format!("Failed to bind removal approval: {error}")))?;
        require_approval_token(
            "phantom_remove_secret",
            params.approval_token.as_deref(),
            &params_json,
            &self.project_id(),
        )?;
        plan.commit(vault.as_ref()).map_err(|error| {
            internal_err(format!(
                "Remove transaction failed; exact transaction-owned state was rolled back where verifiable: {error}"
            ))
        })?;

        text_result(format!(
            "Secret '{}' removed from vault, lifecycle config, and its exact managed-dotenv mapping in one transaction.",
            params.name
        ))
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
        let (transaction_lock, config, vault) = self.load_config_and_vault_anchored()?;
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

        let project_root = transaction_lock.project_root_at_acquisition();
        let env_path = resolve_env_path_anchored(&transaction_lock, project_root, &config, &names)?;
        remap_phantom_tokens_locked(&transaction_lock, &env_path, &names)?;

        text_result(format!(
            "Rotated {} phantom token(s). Old tokens are now invalid.",
            names.len()
        ))
    }

    /// Deprecated compatibility endpoint for the disabled shadow-candidate path.
    #[tool(
        description = "DEPRECATED hard denial: legacy shadow rotation generated only a local phm_cand_ placeholder, not a provider-issued credential. This tool never creates or stores a candidate and ignores compatibility parameters. Live provider issuance is also hard-denied until compensated recovery exists; rotate at the provider and store the replacement interactively."
    )]
    fn phantom_rotate_with_candidate(
        &self,
        Parameters(params): Parameters<RotateWithCandidateParams>,
    ) -> Result<CallToolResult, McpError> {
        let _ = params;
        Err(invalid_params_err(
            "phantom_rotate_with_candidate is deprecated and disabled: the legacy implementation generated a local phm_cand_ placeholder, not a provider credential. No candidate was created or stored. Live provider issuance is also hard-denied until compensated recovery exists; rotate at the provider and store the replacement interactively.",
        ))
    }

    /// Deprecated compatibility endpoint for the disabled shadow promotion path.
    #[tool(
        description = "DEPRECATED hard denial: legacy candidates were local phm_cand_ placeholders, not provider-issued credentials. This tool never validates, promotes, or changes a vault value and ignores compatibility parameters. Live provider issuance is also hard-denied until compensated recovery exists; rotate at the provider and store the replacement interactively."
    )]
    fn phantom_rotate_promote(
        &self,
        Parameters(params): Parameters<RotatePromoteParams>,
    ) -> Result<CallToolResult, McpError> {
        let _ = params;
        Err(invalid_params_err(
            "phantom_rotate_promote is deprecated and disabled: legacy candidates were local phm_cand_ placeholders, not provider-issued credentials. No credential or metadata was changed. Live provider issuance is also hard-denied until compensated recovery exists; rotate at the provider and store the replacement interactively.",
        ))
    }

    /// Rotate a secret using a configured vendor-specific provider.
    ///
    /// Compatibility boundary for future compensated provider rotation.
    #[tool(
        description = "Provider-rotation compatibility boundary. Shipped builds hard-deny \
            automated live provider issuance before credential access or network I/O because \
            the provider contract does not yet preserve a durable value-free recovery handle \
            and verified abort path for local persistence failure. Unit-test mock providers \
            are not production capability evidence. Current calls return a value-blind hard \
            denial without consuming an approval or opening the vault. The confirm and approval \
            fields are reserved for a future effectful, compensated implementation."
    )]
    fn phantom_rotate_provider(
        &self,
        Parameters(params): Parameters<RotateProviderParams>,
    ) -> Result<CallToolResult, McpError> {
        if !phantom_core::rotation_provider::unit_test_mock_issuance_enabled() {
            return Err(invalid_params_err(
                "Automated live provider issuance is disabled before approval consumption, vault access, credential access, or network I/O. Phantom requires a durable value-free provider recovery handle and verified abort path before it can safely persist a successor locally. Rotate at the provider, then store the replacement interactively. Unit-test mock providers are not production capability evidence. Do not retry automatically.",
            ));
        }
        require_confirm("phantom_rotate_provider", params.confirm)?;
        let params_json = serde_json::to_string(&params).unwrap_or_default();
        require_approval_token(
            "phantom_rotate_provider",
            params.approval_token.as_deref(),
            &params_json,
            &self.project_id(),
        )?;

        // Serialize every local stage around the irreversible provider call.
        // This coordinates Phantom writers; an uncooperative same-user process
        // can still mutate provider or filesystem state and is detected by the
        // exact value checks before metadata and cleanup.
        let (rotation_lock, config, vault) = self.load_config_and_vault_anchored()?;

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

        if effective_provider.eq_ignore_ascii_case("stripe")
            && provider_config
                .and_then(|cfg| cfg.api_key_env.as_deref())
                .map(|name| name.to_ascii_uppercase().ends_with("REFRESH_TOKEN"))
                .unwrap_or(false)
        {
            return Err(invalid_params_err(
                "Stripe OAuth refresh rotation is disabled before credential access or provider issuance: Stripe invalidates the current refresh token during exchange, before Phantom can durably verify the successor. A durable verified recovery escrow channel is required. Do not retry automatically.",
            ));
        }
        if effective_provider.eq_ignore_ascii_case("supabase-management")
            && provider_config.is_some_and(|cfg| cfg.account_id.is_none())
        {
            return Err(invalid_params_err(
                "Supabase management refresh-token rotation is disabled before credential access or provider issuance: the refresh exchange invalidates the current token before Phantom can durably verify its successor. A durable verified recovery escrow channel is required. Keep the vaulted enrollment material and obtain fresh operator consent when it expires. Do not retry automatically.",
            ));
        }
        if !phantom_core::rotation_provider::unit_test_mock_issuance_enabled() {
            return Err(invalid_params_err(format!(
                "Automated live provider issuance for '{}' is disabled before credential access or network I/O. Phantom requires a durable value-free provider recovery handle and verified abort path before it can safely persist a successor locally. Rotate at the provider, then store the replacement interactively. Unit-test mock providers are not production capability evidence. Do not retry automatically.",
                effective_provider
            )));
        }

        // Bootstrap credential: environment variable first, then the vault
        // under the same name. Zeroized after the call; never in the response.
        let bootstrap = match provider_config
            .and_then(|cfg| cfg.api_key_env.as_deref())
            .filter(|env_name| std::env::var(env_name).is_err())
        {
            Some(env_name) => {
                retrieve_optional_secret(vault.as_ref(), env_name, "provider bootstrap credential")?
            }
            None => None,
        };

        // Build the provider list and attempt vendor rotation.
        let providers = phantom_core::rotation_provider::default_rotation_providers();

        // Capture the outgoing value BEFORE overwriting it: providers that
        // revoke the old credential (Vercel) do so only after the new value is
        // durably stored, authenticating with the old value itself.
        let old_value =
            retrieve_optional_secret(vault.as_ref(), &params.name, "outgoing provider credential")?;

        let new_value = phantom_core::rotation_provider::auto_sync_rotation_with_bootstrap(
            &params.name,
            provider_config,
            &providers,
            bootstrap,
        )
        .map_err(|e| internal_err(format!("Provider rotation failed: {e}")))?;

        match new_value {
            Some(secret) => {
                let mut stages = ProviderRotationStages {
                    provider_issued: true,
                    ..ProviderRotationStages::default()
                };
                // Bind local persistence to the exact value reviewed before the
                // provider call. A concurrent local writer must never be
                // overwritten after the provider has already issued a value.
                persist_issued_provider_credential(
                    vault.as_ref(),
                    &params.name,
                    old_value.as_ref(),
                    secret.as_str(),
                    &mut stages,
                )?;

                phantom_core::audit::log("vault.rotation.provider.stored", Some(&params.name));

                // Refresh the phm_ token for this secret in .env — same flow
                // as the CLI — so a client that captured the pre-rotation
                // phm_ token cannot resolve it to the new credential.
                let env_path = resolve_env_path_anchored(
                    &rotation_lock,
                    rotation_lock.project_root_at_acquisition(),
                    &config,
                    std::slice::from_ref(&params.name),
                )?;
                remap_phantom_tokens_locked(
                    &rotation_lock,
                    &env_path,
                    std::slice::from_ref(&params.name),
                )
                .map_err(|error| {
                    provider_rotation_partial_error(
                        &params.name,
                        "local Phantom-token remap",
                        &error.message,
                        &stages,
                    )
                })?;
                let env_token_refreshed = true;
                stages.token_remapped = true;

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
                verify_provider_issued_value(
                    vault.as_ref(),
                    &params.name,
                    secret.as_str(),
                    "pre-metadata vault verification",
                    &mut stages,
                )?;
                let expires_line = persist_provider_rotation_metadata(
                    vault.as_ref(),
                    &params.name,
                    expires_override,
                    &mut stages,
                )?
                .map(|ts| format!("expires_at: {ts}\n"))
                .unwrap_or_default();

                // Invoke cleanup only when the provider declares an explicit
                // effect. Errors are returned as partial success and never
                // represented as a completed revocation.
                if let (Some(provider), Some(cfg)) = (
                    providers
                        .iter()
                        .find(|p| p.name().eq_ignore_ascii_case(&effective_provider)),
                    provider_config,
                ) {
                    let cleanup_semantics = provider.cleanup_semantics(cfg);
                    stages.cleanup_semantics = cleanup_semantics;
                    if cleanup_semantics
                        == phantom_core::rotation_provider::CleanupSemantics::NotApplicable
                    {
                        stages.cleanup_outcome =
                            Some(phantom_core::rotation_provider::CleanupOutcome::NotApplicable);
                    } else {
                        verify_provider_issued_value(
                            vault.as_ref(),
                            &params.name,
                            secret.as_str(),
                            "pre-cleanup vault verification",
                            &mut stages,
                        )?;
                        stages.old_cleanup_attempted = true;
                        let cleanup_outcome = provider
                            .post_store_cleanup(&params.name, cfg, old_value.as_ref())
                            .map_err(|error| {
                                provider_rotation_partial_error(
                                    &params.name,
                                    "prior-credential cleanup",
                                    error,
                                    &stages,
                                )
                            })?;
                        stages.cleanup_outcome = Some(cleanup_outcome);
                        stages.old_cleanup_succeeded = cleanup_outcome
                            == phantom_core::rotation_provider::CleanupOutcome::Succeeded;
                        verify_provider_issued_value(
                            vault.as_ref(),
                            &params.name,
                            secret.as_str(),
                            "post-cleanup vault verification",
                            &mut stages,
                        )?;
                    }
                }

                let stage_receipt = serde_json::to_string(&stages)
                    .map_err(|e| internal_err(format!("Receipt serialization failed: {e}")))?;

                text_result(format!(
                    "Provider rotation succeeded for '{}'.\n\
                     provider: {}\n\
                     status: rotated\n\
                     stage_receipt: {}\n\
                     env_token_refreshed: {}\n\
                     {}The new credential has been stored in the vault.\n\
                     The secret value was NOT exposed via MCP.",
                    params.name,
                    effective_provider,
                    stage_receipt,
                    env_token_refreshed,
                    expires_line
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
        use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
        use std::collections::BTreeMap;

        let config_path = self.config_path();
        let (config, config_before) = load_mcp_config_exact(&config_path)?;
        let vault = phantom_vault::try_create_vault(config.local_project_id())
            .map_err(|error| internal_err(format!("Failed to initialize vault: {error}")))?;
        ensure_cloud_push_allowed_mcp(&config)?;
        let mut names = vault
            .list()
            .map_err(|e| internal_err(format!("Failed to list secrets: {e}")))?;
        names.sort();

        if names.is_empty() {
            return text_result("No secrets to push.");
        }

        let version = config
            .cloud
            .as_ref()
            .map(|cloud| cloud.version)
            .unwrap_or(0);
        let params_json = serde_json::to_string(&serde_json::json!({
            "confirm": params.confirm,
            "plan": {
                "canonical_project": self.project_id(),
                "local_project_id": config.local_project_id(),
                "portable_project_id": config.portable_project_id(),
                "config_sha256": hex::encode(Sha256::digest(&config_before)),
                "vault_backend": vault.backend_name(),
                "expected_remote_version": version,
                "secret_count": names.len(),
                "secret_names_sha256": bounded_name_digest(&names)?,
            }
        }))
        .map_err(|error| internal_err(format!("Failed to bind cloud-push approval: {error}")))?;
        require_approval_token(
            "phantom_cloud_push",
            params.approval_token.as_deref(),
            &params_json,
            &self.project_id(),
        )?;

        let token = phantom_core::auth::load_token()
            .ok_or_else(|| internal_err("Not logged in. Run `phantom login` first."))?;
        require_exact_config_before_effect(&config_path, &config_before)?;

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

        let passphrase = zeroize::Zeroizing::new(
            phantom_core::auth::get_or_create_cloud_passphrase()
                .map_err(|e| internal_err(format!("Failed to access cloud key: {e}")))?,
        );

        let encrypted = phantom_vault::crypto::encrypt(plaintext.as_bytes(), &passphrase)
            .map_err(|e| internal_err(format!("Encryption failed: {e}")))?;

        let blob_b64 = BASE64.encode(&encrypted);
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
        self.save_cloud_version(vault.as_ref(), &mut config, config_before, new_version)?;

        text_result(format!(
            "Pushed {} secret(s) to Phantom Cloud (v{new_version}). End-to-end encrypted.",
            names.len()
        ))
    }

    /// Pull vault from Phantom Cloud.
    #[tool(
        description = "Pull and decrypt a personal-vault snapshot from Phantom Cloud. DESTRUCTIVE — writes local vault entries; force=true declares overwrites but never bypasses approval. With force=false, existing entries are skipped; any partial result preserves the prior merge base, records a durable reconciliation requirement, and blocks cloud push until a fully reconciled pull. Requires `confirm: true` plus an out-of-band `approval_token`."
    )]
    async fn phantom_cloud_pull(
        &self,
        Parameters(params): Parameters<CloudPullParams>,
    ) -> Result<CallToolResult, McpError> {
        require_confirm("phantom_cloud_pull", params.confirm)?;
        let config_path = self.config_path();
        let (config, config_before) = load_mcp_config_exact(&config_path)?;
        let vault = phantom_vault::try_create_vault(config.local_project_id())
            .map_err(|error| internal_err(format!("Failed to initialize vault: {error}")))?;
        let params_json = serde_json::to_string(&serde_json::json!({
            "force": params.force,
            "confirm": params.confirm,
            "plan": {
                "canonical_project": self.project_id(),
                "local_project_id": config.local_project_id(),
                "portable_project_id": config.portable_project_id(),
                "config_sha256": hex::encode(Sha256::digest(&config_before)),
                "vault_backend": vault.backend_name(),
                "local_merge_version": config.cloud.as_ref().map(|cloud| cloud.version).unwrap_or(0),
            }
        }))
        .map_err(|error| internal_err(format!("Failed to bind cloud-pull approval: {error}")))?;
        require_approval_token(
            "phantom_cloud_pull",
            params.approval_token.as_deref(),
            &params_json,
            &self.project_id(),
        )?;
        use base64::{engine::general_purpose::STANDARD as BASE64, Engine};

        let token = phantom_core::auth::load_token()
            .ok_or_else(|| internal_err("Not logged in. Run `phantom login` first."))?;
        require_exact_config_before_effect(&config_path, &config_before)?;

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

        let passphrase = zeroize::Zeroizing::new(
            phantom_core::auth::get_or_create_cloud_passphrase()
                .map_err(|e| internal_err(format!("Failed to access cloud key: {e}")))?,
        );

        let encrypted = BASE64
            .decode(&pull_data.encrypted_blob)
            .map_err(|e| internal_err(format!("Invalid cloud data: {e}")))?;

        let plaintext = zeroize::Zeroizing::new(
            phantom_vault::crypto::decrypt(&encrypted, &passphrase)
                .map_err(|e| internal_err(format!("Decryption failed: {e}")))?,
        );

        let secrets = SensitiveSecretMap::parse_json(&plaintext)
            .map_err(|e| internal_err(format!("Invalid vault data: {e}")))?;

        // SensitiveSecretMap owns zeroizing values before TOML serialization,
        // so every early-return path below scrubs the parsed plaintext map.
        let (added, skipped) = apply_cloud_pull_transaction(
            &self.project_dir,
            &config_path,
            vault.as_ref(),
            &secrets,
            params.force,
            config_before,
            config,
            pull_data.version,
        )?;

        let msg = if skipped > 0 {
            format!(
                "Partial reconciliation: pulled {added} secret(s), {skipped} skipped because they already exist. The prior cloud merge base was retained and cloud push is blocked. Run phantom_cloud_pull with force=true, after explicit approval, to fully reconcile remote version {}.",
                pull_data.version
            )
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
        description = "Copy a secret into a distinct initialized target through one exact-before target transaction. Refuses existing target vault, lifecycle-config, or managed-dotenv ownership; never overwrites. On success it creates both the target vault entry and managed-dotenv phantom mapping, with dotenv committed last. This is an exfiltration-capable cross-project write and requires confirm plus an out-of-band approval token before any source value retrieval."
    )]
    fn phantom_copy_secret(
        &self,
        Parameters(params): Parameters<CopySecretParams>,
    ) -> Result<CallToolResult, McpError> {
        require_confirm("phantom_copy_secret", params.confirm)?;
        // Reject `..` in the raw input. Canonicalize below collapses traversal,
        // but only once target_dir exists on disk — and an attacker can stage a
        // missing-path case. Guarding at the textual layer is simplest.
        if params.target_dir.split(['/', '\\']).any(|seg| seg == "..") {
            return Err(invalid_params_err(
                "target_dir must not contain `..` segments; pass the full destination path explicitly.",
            ));
        }

        validate_mcp_secret_name(&params.name)?;
        let target_name = params.rename.as_deref().unwrap_or(&params.name);
        validate_mcp_secret_name(target_name)?;

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
        let source_dir = self.project_dir.canonicalize().map_err(|error| {
            internal_err(format!(
                "Failed to resolve source project directory: {error}"
            ))
        })?;
        if source_dir == target_dir {
            return Err(invalid_params_err(
                "Source and target resolve to the same project; copy refuses ambiguous self-overwrite.",
            ));
        }

        let target_config_path = target_dir.join(".phantom.toml");
        let (target_config, target_config_before) = load_mcp_config_exact(&target_config_path)
            .map_err(|error| {
                invalid_params_err(format!(
                    "Target project at {} is not safely initialized: {}",
                    target_dir.display(),
                    error.message
                ))
            })?;

        let target_vault = phantom_vault::try_create_vault(target_config.local_project_id())
            .map_err(|error| internal_err(format!("Failed to initialize target vault: {error}")))?;
        let target_vault_names = target_vault
            .list()
            .map_err(|error| internal_err(format!("Failed to list target vault: {error}")))?;
        if retrieve_optional_secret(target_vault.as_ref(), target_name, "copy destination")?
            .is_some()
        {
            return Err(invalid_params_err(format!(
                "Target secret '{target_name}' already exists; copy never overwrites"
            )));
        }
        if target_config.phantom.secrets.contains_key(target_name) {
            return Err(invalid_params_err(format!(
                "Target lifecycle config already owns '{target_name}'; copy refuses ambiguous ownership"
            )));
        }
        let target_env = phantom_core::managed_dotenv::resolve_dotenv(
            &target_dir,
            &target_config,
            &target_vault_names,
        )
        .map_err(|error| internal_err(format!("Failed to resolve target dotenv: {error}")))?;
        let target_env_before = phantom_core::fs::read_regular_file(&target_env.path)
            .map_err(|error| internal_err(format!("Failed to snapshot target dotenv: {error}")))?
            .map(zeroize::Zeroizing::new);
        if mcp_dotenv_has_key(
            target_env_before.as_ref().map(|bytes| bytes.as_slice()),
            target_name,
        )? {
            return Err(invalid_params_err(format!(
                "Target managed dotenv already owns '{target_name}'; copy never overwrites"
            )));
        }

        // The approval binds the human-reviewed request to the resolved target
        // vault identity and exact config before-image. Retrying after a path,
        // symlink, config, or managed-dotenv selection swap recomputes a
        // different arg hash and cannot consume the old approval token.
        let approval_params = copy_approval_params_json(
            &params,
            &target_dir,
            target_config.local_project_id(),
            target_name,
            &target_env.path,
            &target_config_before,
        )?;
        require_approval_token(
            "phantom_copy_secret",
            params.approval_token.as_deref(),
            &approval_params,
            &self.project_id(),
        )?;

        let (_config, source_vault) = self.load_config_and_vault()?;
        let secret_value = source_vault
            .retrieve(&params.name)
            .map_err(|e| invalid_params_err(format!("Secret '{}' not found: {e}", params.name)))?;
        apply_mcp_copy_transaction(
            &target_dir,
            &target_config_path,
            target_config,
            target_config_before,
            target_vault.as_ref(),
            target_vault_names,
            target_env.path,
            target_env_before,
            target_name,
            secret_value.as_str(),
        )?;

        text_result(format!(
            "Copied '{}' -> '{}' in {} and created its managed-dotenv mapping. No target ownership was overwritten; secret value was never exposed.",
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
        let mut doctor_files = Vec::new();
        let mut hook_changed = false;

        let config_path = self.config_path();
        let config_before = phantom_core::fs::read_regular_file(&config_path)
            .map_err(|error| internal_err(format!("Failed to read config safely: {error}")))?;
        let config_exists = config_before.is_some();

        // ── Check 1: .phantom.toml ──────────────────────────────────────
        let config = if let Some(bytes) = config_before.as_deref() {
            lines.push("pass: .phantom.toml found".to_string());
            match PhantomConfig::load_from_bytes(&config_path, bytes) {
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
        let mut vault_names = Vec::new();
        if params.fix {
            if let Some(cfg) = &config {
                match phantom_vault::try_create_vault(cfg.local_project_id()) {
                    Ok(vault) => {
                        lines.push(format!("pass: Vault backend: {}", vault.backend_name()));
                        match vault.list() {
                            Ok(names) => {
                                lines.push(format!("pass: {} secret(s) in vault", names.len()));
                                vault_names = names;
                            }
                            Err(e) => {
                                lines.push(format!("FAIL: Vault access failed: {e}"));
                                issues += 1;
                            }
                        }
                    }
                    Err(error) => {
                        lines.push(format!("FAIL: Vault initialization failed: {error}"));
                        issues += 1;
                    }
                }
            }
        } else if config.is_some() {
            lines.push(
                "info: Vault backend and inventory not opened in read-only doctor mode".to_string(),
            );
        }

        // Only an actually absent config may use the legacy `.env` fallback.
        // Configured projects must honor the validated managed-dotenv choice;
        // a malformed config is already reported above and is never bypassed.
        let env_path = if let Some(cfg) = &config {
            match phantom_core::managed_dotenv::resolve_dotenv(&self.project_dir, cfg, &vault_names)
            {
                Ok(resolved) => Some(resolved.path),
                Err(error) => {
                    lines.push(format!("FAIL: Managed dotenv resolution failed: {error}"));
                    issues += 1;
                    None
                }
            }
        } else if !config_exists {
            Some(self.project_dir.join(".env"))
        } else {
            None
        };

        // ── Check 3: .env file ──────────────────────────────────────────
        if let Some(env_path) = env_path.as_ref() {
            let env_before = phantom_core::fs::read_regular_file(env_path)
                .map_err(|error| {
                    internal_err(format!("Failed to read managed dotenv safely: {error}"))
                })?
                .map(zeroize::Zeroizing::new);
            if let Some(bytes) = env_before.as_deref() {
                match std::str::from_utf8(bytes).map(DotenvFile::parse_str) {
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
                    Err(_) => {
                        lines.push("FAIL: .env parse error: file is not valid UTF-8".to_string());
                        issues += 1;
                    }
                }
            } else {
                lines.push(format!(
                    "info: No {} file in current directory",
                    env_path.display()
                ));
            }
        } else {
            lines.push(
                "info: Dotenv checks skipped because no safe managed path was resolved".to_string(),
            );
        }

        // ── Check 4: .gitignore includes .env ───────────────────────────
        let gitignore_path = self.project_dir.join(".gitignore");
        let gitignore_before = phantom_core::fs::read_regular_file(&gitignore_path)
            .map_err(|error| internal_err(format!("Failed to read .gitignore safely: {error}")))?;
        if let Some(before) = gitignore_before {
            let content = String::from_utf8(before.clone())
                .map_err(|_| internal_err("Refusing to repair a non-UTF-8 .gitignore"))?;
            let managed_name = env_path
                .as_ref()
                .and_then(|path| path.file_name())
                .and_then(|name| name.to_str())
                .unwrap_or(".env");
            if content.lines().any(|l| l.trim() == managed_name) {
                lines.push(format!("pass: {managed_name} is in .gitignore"));
            } else {
                lines.push(
                    "warn: .env is NOT in .gitignore — secrets could be committed!".to_string(),
                );
                if params.fix {
                    let mut c = content;
                    if !c.ends_with('\n') {
                        c.push('\n');
                    }
                    c.push_str(managed_name);
                    c.push('\n');
                    doctor_files.push(phantom_vault::InitFile::replace_if_unchanged(
                        &gitignore_path,
                        Some(before),
                        c.into_bytes(),
                    ));
                    lines.push("  Fixed: Added .env to .gitignore".to_string());
                } else {
                    issues += 1;
                }
            }
        } else {
            lines.push("warn: No .gitignore — consider adding one".to_string());
            if params.fix {
                doctor_files.push(phantom_vault::InitFile::replace_if_unchanged(
                    &gitignore_path,
                    None::<Vec<u8>>,
                    ".env\n.env.local\n.env.*.local\n.env.backup\n",
                ));
                lines.push("  Fixed: Created .gitignore with .env patterns".to_string());
            } else {
                issues += 1;
            }
        }

        // ── Check 5: .env.example exists ────────────────────────────────
        let example_path = self.project_dir.join(".env.example");
        let example_before =
            phantom_core::fs::read_regular_file(&example_path).map_err(|error| {
                internal_err(format!("Failed to inspect .env.example safely: {error}"))
            })?;
        if example_before.is_some() {
            lines.push("pass: .env.example found (team onboarding ready)".to_string());
        } else {
            lines.push("warn: No .env.example — team onboarding may be difficult".to_string());
            if params.fix && env_path.is_some() {
                if let Some(env_path) = env_path.as_ref() {
                    if let Some(env_bytes) =
                        phantom_core::fs::read_regular_file(env_path).map_err(|error| {
                            internal_err(format!("Failed to read managed dotenv safely: {error}"))
                        })?
                    {
                        let env_bytes = zeroize::Zeroizing::new(env_bytes);
                        let env_content = std::str::from_utf8(&env_bytes).map_err(|_| {
                            internal_err("Refusing to generate an example from non-UTF-8 dotenv")
                        })?;
                        let dotenv = DotenvFile::parse_str(env_content);
                        let cfg = config.as_ref();
                        let content = dotenv.generate_example_content(cfg);
                        doctor_files.push(phantom_vault::InitFile::replace_if_unchanged(
                            &example_path,
                            None::<Vec<u8>>,
                            content.into_bytes(),
                        ));
                        lines.push("  Fixed: Generated .env.example".to_string());
                    }
                }
            } else if !params.fix {
                issues += 1;
            }
        }

        // ── Check 6: Project-local Claude MCP wiring ───────────────────
        let claude_settings = self.project_dir.join(".claude/settings.local.json");
        if let Some(bytes) = phantom_core::fs::read_regular_file(&claude_settings).map_err(|e| {
            internal_err(format!(
                "Refusing to inspect unreadable Claude settings {}: {e}",
                claude_settings.display()
            ))
        })? {
            let content = String::from_utf8(bytes)
                .map_err(|_| internal_err("Refusing to inspect non-UTF-8 Claude settings"))?;
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
                    let change = commit_mcp_precommit_repair(&self.project_dir)?
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
                    hook_changed = true;
                } else {
                    issues += 1;
                }
            }
            precommit_hook::HookState::Missing { .. } => {
                lines.push("warn: No pre-commit hook installed".to_string());
                if params.fix {
                    commit_mcp_precommit_repair(&self.project_dir)?;
                    lines.push("  Fixed: Installed pre-commit hook".to_string());
                    fixed += 1;
                    hook_changed = true;
                } else {
                    issues += 1;
                }
            }
            precommit_hook::HookState::NotRepository => {
                lines.push("info: Not a git repo — pre-commit hook not applicable".to_string());
            }
        }

        if !doctor_files.is_empty() {
            let count = doctor_files.len() as u32;
            commit_doctor_file_updates(&self.project_dir, doctor_files, hook_changed)?;
            fixed += count;
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
        let env_path = self.env_path()?;
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
        let transaction_lock = phantom_vault::acquire_project_transaction_lock(&self.project_dir)
            .map_err(|error| {
            internal_err(format!("Failed to acquire project lock: {error}"))
        })?;
        let pkg_target = transaction_lock
            .target(&pkg_path)
            .map_err(|error| internal_err(format!("Failed to retain package.json: {error}")))?;
        let (mut pkg, before) = read_package_scripts_anchored(&pkg_target)?;
        let wrapped = wrap_package_scripts(&mut pkg, &params.only, &params.skip)
            .map_err(invalid_params_err)?;

        if wrapped.is_empty() {
            return text_result("No scripts matched for wrapping.");
        }
        write_package_json_anchored(&pkg_target, &pkg, &before)?;

        let mut output = format!("Wrapped {} script(s):\n", wrapped.len());
        for name in &wrapped {
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
        let transaction_lock = phantom_vault::acquire_project_transaction_lock(&self.project_dir)
            .map_err(|error| {
            internal_err(format!("Failed to acquire project lock: {error}"))
        })?;
        let pkg_target = transaction_lock
            .target(&pkg_path)
            .map_err(|error| internal_err(format!("Failed to retain package.json: {error}")))?;
        let (mut pkg, before) = read_package_scripts_anchored(&pkg_target)?;
        let restored = unwrap_package_scripts(&mut pkg);
        if restored.is_empty() {
            return text_result(
                "No Phantom-owned wrapped script pairs found. User-owned `*:raw` scripts were preserved.",
            );
        }

        write_package_json_anchored(&pkg_target, &pkg, &before)?;

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
                "\nClient-supplied headers and bodies never resolve phantom placeholders, even while the proxy is running.\n\
                 `phantom exec -- <command>` can start an authenticated session whose exact configured routes inject only route-owned authentication; review the route mapping before use.",
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
        let params_json = serde_json::to_string(&params).unwrap_or_default();
        require_approval_token(
            "phantom_env",
            params.approval_token.as_deref(),
            &params_json,
            &self.project_id(),
        )?;
        phantom_core::fs::validate_project_filename(&params.output)
            .map_err(|error| invalid_params_err(error.to_string()))?;
        let (transaction_lock, config, vault) = self.load_config_and_vault_anchored()?;
        let project_root = transaction_lock.project_root_at_acquisition();
        let output_path = project_root.join(&params.output);
        let output_target = transaction_lock
            .target(&output_path)
            .map_err(|error| internal_err(format!("Refusing unsafe output target: {error}")))?;
        if output_target
            .read_regular()
            .map_err(|error| internal_err(format!("Refusing unsafe output target: {error}")))?
            .is_some()
        {
            return Err(invalid_params_err(format!(
                "Refusing to overwrite existing output {}. This tool has no overwrite policy; choose a new filename.",
                params.output
            )));
        }
        let vault_names = vault
            .list()
            .map_err(|error| internal_err(format!("Failed to list vault secrets: {error}")))?;
        let env_path =
            resolve_env_path_anchored(&transaction_lock, project_root, &config, &vault_names)?;
        let env_target = transaction_lock
            .target(&env_path)
            .map_err(|error| internal_err(format!("Failed to retain managed dotenv: {error}")))?;
        let env_before = env_target
            .read_regular()
            .map_err(|error| internal_err(format!("Failed to safely read .env: {error}")))?
            .ok_or_else(|| {
                internal_err(format!(
                    "Managed dotenv does not exist: {}",
                    env_path.display()
                ))
            })?;
        let env_text = std::str::from_utf8(env_before.bytes())
            .map_err(|_| internal_err("Failed to read .env: managed dotenv is not valid UTF-8"))?;
        let dotenv = DotenvFile::parse_str(env_text);

        let content = dotenv.generate_example_content(Some(&config));

        write_new_anchored_output(&output_target, &params.output, content.as_bytes())?;

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
        if params.team_id.is_empty()
            || params.team_id.len() > 128
            || !params
                .team_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        {
            return Err(invalid_params_err("team_id is not a valid Phantom team ID"));
        }
        let config_path = self.config_path();
        let (config, config_before) = load_mcp_config_exact(&config_path)?;
        let vault = phantom_vault::try_create_vault(config.local_project_id())
            .map_err(|error| internal_err(format!("Failed to initialize vault: {error}")))?;
        let project_id = config.portable_project_id().to_string();
        let mut names = vault
            .list()
            .map_err(|e| internal_err(format!("Failed to list vault: {e}")))?;
        names.sort();
        if names.is_empty() {
            return text_result("No secrets in this project's vault to push.".to_string());
        }
        let params_json = team_push_approval_params_json(
            &params,
            &self.project_id(),
            &config,
            &config_before,
            vault.backend_name(),
            &names,
        )?;
        require_approval_token(
            "phantom_team_vault_push",
            params.approval_token.as_deref(),
            &params_json,
            &self.project_id(),
        )?;
        use std::collections::BTreeMap;
        use zeroize::Zeroizing;

        require_exact_config_before_effect(&config_path, &config_before)?;
        let mut current_names = vault
            .list()
            .map_err(|e| internal_err(format!("Failed to recheck vault names: {e}")))?;
        current_names.sort();
        if current_names != names {
            return Err(internal_err(
                "Vault names changed after approval; no secret value or provider request was attempted",
            ));
        }

        let token = Zeroizing::new(
            phantom_core::auth::require_token().map_err(|e| internal_err(e.to_string()))?,
        );
        let api_base =
            phantom_core::auth::api_base_url().map_err(|e| internal_err(e.to_string()))?;
        let kp = phantom_core::auth::get_or_create_team_keypair()
            .map_err(|e| internal_err(format!("Failed to load team keypair: {e}")))?;
        let mut secrets: BTreeMap<String, Zeroizing<String>> = BTreeMap::new();
        for name in &names {
            let value = vault
                .retrieve(name)
                .map_err(|e| internal_err(format!("Failed to retrieve {name}: {e}")))?;
            secrets.insert(name.clone(), Zeroizing::new(String::from(value.as_str())));
        }

        let outcome = phantom_core::teams_vault::push_for_project(
            &api_base,
            token.as_str(),
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

        let (transaction_lock, config, vault) = self.load_config_and_vault_anchored()?;
        let names = vault
            .list()
            .map_err(|e| internal_err(format!("Failed to list secrets: {e}")))?;

        if names.is_empty() {
            return text_result("No Phantom tokens to remap.");
        }

        let project_root = transaction_lock.project_root_at_acquisition();
        let env_path = resolve_env_path_anchored(&transaction_lock, project_root, &config, &names)?;
        remap_phantom_tokens_locked(&transaction_lock, &env_path, &names)?;
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
                "Rotate expired credentials at the provider, then store replacements from a trusted terminal; automated live provider issuance is disabled, and a local token remap does not refresh TTLs.",
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
            let config_path = self.config_path();
            let config_before = phantom_core::fs::read_regular_file(&config_path)
                .map_err(|error| internal_err(format!("Failed to safely read config: {error}")))?;
            let alerting_config = match config_before.as_deref() {
                Some(bytes) => {
                    PhantomConfig::load_from_bytes(&config_path, bytes)
                        .map_err(|error| internal_err(format!("Failed to load config: {error}")))?
                        .alerting
                }
                None => AlertingConfig::default(),
            };
            let backend_kinds = alerting_config
                .backends
                .iter()
                .map(|backend| match backend {
                    phantom_core::leak_correlation::AlertBackendConfig::Webhook { .. } => "webhook",
                    phantom_core::leak_correlation::AlertBackendConfig::Slack { .. } => "slack",
                    phantom_core::leak_correlation::AlertBackendConfig::PagerDuty { .. } => {
                        "pagerduty"
                    }
                })
                .collect::<Vec<_>>();
            let destination_origins = sanitized_alert_origins(&alerting_config)?;
            let params_json = serde_json::to_string(&serde_json::json!({
                "last": params.last,
                "backfill": params.backfill,
                "confirm": params.confirm,
                "plan": {
                    "canonical_project": self.project_id(),
                    "config_sha256": config_before.as_deref().map(|bytes| hex::encode(Sha256::digest(bytes))),
                    "alerting_enabled": alerting_config.enabled,
                    "minimum_confidence": alerting_config.min_confidence,
                    "backend_kinds": backend_kinds,
                    "destination_origins": destination_origins,
                    "alert_state_path_sha256": hex::encode(Sha256::digest(alerts_path.to_string_lossy().as_bytes())),
                }
            }))
            .map_err(|error| internal_err(format!("Failed to bind alert approval: {error}")))?;
            require_approval_token(
                "phantom_audit_alerts",
                params.approval_token.as_deref(),
                &params_json,
                &self.project_id(),
            )?;
            let current_config = phantom_core::fs::read_regular_file(&config_path)
                .map_err(|error| internal_err(format!("Failed to recheck config: {error}")))?;
            if current_config != config_before {
                return Err(internal_err(
                    ".phantom.toml changed after alert backfill approval; no correlation or notification effect was attempted",
                ));
            }
            let engine = LeakCorrelationEngine::new()
                .map_err(|e| internal_err(format!("Cannot initialise correlation engine: {e}")))?;
            let incidents = engine
                .run()
                .map_err(|e| internal_err(format!("Correlation engine failed: {e}")))?;

            if !incidents.is_empty() {
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
        let env_path = self.env_path()?;
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
        if params.team_id.is_empty()
            || params.team_id.len() > 128
            || !params
                .team_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        {
            return Err(invalid_params_err("team_id is not a valid Phantom team ID"));
        }
        let config_path = self.config_path();
        let (config, config_before) = load_mcp_config_exact(&config_path)?;
        let vault = phantom_vault::try_create_vault(config.local_project_id())
            .map_err(|error| internal_err(format!("Failed to initialize vault: {error}")))?;
        let project_id = config.portable_project_id().to_string();
        let params_json = serde_json::to_string(&serde_json::json!({
            "team_id": &params.team_id,
            "confirm": params.confirm,
            "plan": {
                "canonical_project": self.project_id(),
                "local_project_id": config.local_project_id(),
                "portable_project_id": &project_id,
                "config_sha256": hex::encode(Sha256::digest(&config_before)),
                "vault_backend": vault.backend_name(),
            }
        }))
        .map_err(|error| internal_err(format!("Failed to bind team-pull approval: {error}")))?;
        require_approval_token(
            "phantom_team_vault_pull",
            params.approval_token.as_deref(),
            &params_json,
            &self.project_id(),
        )?;
        require_exact_config_before_effect(&config_path, &config_before)?;
        let token = phantom_core::auth::require_token().map_err(|e| internal_err(e.to_string()))?;
        let api_base =
            phantom_core::auth::api_base_url().map_err(|e| internal_err(e.to_string()))?;
        let kp = phantom_core::auth::get_or_create_team_keypair()
            .map_err(|e| internal_err(format!("Failed to load team keypair: {e}")))?;

        let (secrets, version) = phantom_core::teams_vault::pull_for_project(
            &api_base,
            &token,
            &params.team_id,
            &project_id,
            &kp,
        )
        .await
        .map(|(secrets, version)| (SensitiveSecretMap::new(secrets), version))
        .map_err(|e| internal_err(e.to_string()))?;

        // Team pull has explicit overwrite semantics: every remote name
        // replaces its matching local name, while unrelated local names are
        // retained. Exact before-images plus commit_init ensure an nth write
        // failure restores transaction-owned changes and a concurrent local
        // change is never overwritten.
        let written = apply_team_vault_pull_transaction(
            &self.project_dir,
            &config_path,
            config_before,
            vault.as_ref(),
            &secrets,
        )?;

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
        let canonical_project = self.project_dir.canonicalize().map_err(|error| {
            internal_err(format!("Failed to resolve project directory: {error}"))
        })?;
        let config_path = canonical_project.join(".phantom.toml");
        let config_before = phantom_core::fs::read_regular_file(&config_path)
            .map_err(|error| internal_err(format!("Failed to read config safely: {error}")))?
            .ok_or_else(|| internal_err("Project is not initialized"))?;
        let config = PhantomConfig::load_from_bytes(&config_path, &config_before)
            .map_err(|error| internal_err(format!("Failed to parse exact config: {error}")))?;
        let vault = phantom_vault::try_create_vault(config.local_project_id())
            .map_err(|error| internal_err(format!("Failed to open vault: {error}")))?;
        let mut names = vault
            .list()
            .map_err(|e| internal_err(format!("Failed to list secrets: {e}")))?;
        names.sort();
        let (names_digest, names_sample) = bounded_validation_name_plan(&names)?;
        let mut metadata_before = std::collections::BTreeMap::new();
        for name in &names {
            metadata_before.insert(
                name.clone(),
                vault.get_validation_metadata_exact(name).map_err(|error| {
                    internal_err(format!(
                        "Failed to snapshot validation metadata for '{name}': {error}"
                    ))
                })?,
            );
        }
        let jobs = params.jobs.clamp(1, 16);
        let timeout_secs = 10_u64;
        let config_digest = hex::encode(Sha256::digest(&config_before));
        let params_json = serde_json::to_string(&serde_json::json!({
            "request": &params,
            "canonical_project": canonical_project,
            "local_project_id": config.local_project_id(),
            "config_sha256": config_digest,
            "selected_name_count": names.len(),
            "selected_names_sha256": names_digest,
            "selected_name_sample": names_sample,
            "jobs": jobs,
            "timeout_secs": timeout_secs,
        }))
        .map_err(|error| internal_err(format!("Failed to bind validation approval: {error}")))?;
        require_approval_token(
            "phantom_validate_all",
            params.approval_token.as_deref(),
            &params_json,
            &self.project_id(),
        )?;
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

        let timeout = std::time::Duration::from_secs(timeout_secs);
        let validators = phantom_core::validator::default_validators();

        let report =
            phantom_core::validator::run_validation_pipeline(secrets, &validators, jobs, timeout);

        // Persist ValidationMetadata for each result so phantom_validate_secret
        // can answer status queries without re-running HTTP checks.
        let mut metadata_changes = Vec::new();
        for entry in &report.entries {
            let replacement = match entry.status {
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
            metadata_changes.push(phantom_vault::ValidationMetadataCas {
                name: entry.name.clone(),
                expected: metadata_before.get(&entry.name).cloned().ok_or_else(|| {
                    internal_err(format!(
                        "Validation completed without a metadata before-image for '{}'",
                        entry.name
                    ))
                })?,
                replacement: Some(replacement),
            });
        }
        if !metadata_changes.is_empty()
            && !vault
                .compare_and_swap_validation_metadata_batch(&metadata_changes)
                .map_err(|error| {
                    internal_err(format!(
                        "Validation completed but metadata did not persist atomically: {error}"
                    ))
                })?
        {
            return Err(internal_err(
                "Validation completed but metadata changed concurrently; no validation metadata was committed",
            ));
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

        let canonical_project = self.project_dir.canonicalize().map_err(|error| {
            internal_err(format!("Failed to resolve project directory: {error}"))
        })?;
        let config_path = canonical_project.join(".phantom.toml");
        let config_before = phantom_core::fs::read_regular_file(&config_path)
            .map_err(|error| internal_err(format!("Failed to read config safely: {error}")))?
            .ok_or_else(|| internal_err("Project is not initialized"))?;
        let config = PhantomConfig::load_from_bytes(&config_path, &config_before)
            .map_err(|error| internal_err(format!("Failed to parse exact config: {error}")))?;
        let state_path = state_file_path(config.local_project_id());
        let (mut state, before) = SchedulerState::load_exact(&state_path)
            .map_err(|e| internal_err(format!("Failed to read scheduler state safely: {e}")))?;

        // If an interval was provided, update the schedule.
        if let Some(ref interval_str) = params.interval {
            require_confirm("phantom_validation_schedule", params.confirm)?;
            let sched = Schedule::parse(interval_str).map_err(|e| {
                crate::tools::helpers::invalid_params_err(format!("Invalid schedule interval: {e}"))
            })?;
            let params_json = serde_json::to_string(&serde_json::json!({
                "request": &params,
                "canonical_project": canonical_project,
                "local_project_id": config.local_project_id(),
                "config_sha256": hex::encode(Sha256::digest(&config_before)),
                "state_path": state_path,
                "state_before_sha256": before.as_ref().map(|bytes| hex::encode(Sha256::digest(bytes))),
                "parsed_schedule": &sched,
            }))
            .map_err(|error| internal_err(format!("Failed to bind schedule approval: {error}")))?;
            require_approval_token(
                "phantom_validation_schedule",
                params.approval_token.as_deref(),
                &params_json,
                &self.project_id(),
            )?;
            let description = sched.description();
            state.schedule = Some(sched);
            state
                .save_if_unchanged(&state_path, before.as_deref())
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

        let canonical_project = self.project_dir.canonicalize().map_err(|error| {
            internal_err(format!("Failed to resolve project directory: {error}"))
        })?;
        let config_path = canonical_project.join(".phantom.toml");
        let config_before = phantom_core::fs::read_regular_file(&config_path)
            .map_err(|error| internal_err(format!("Failed to read config safely: {error}")))?
            .ok_or_else(|| internal_err("Project is not initialized"))?;
        let config = PhantomConfig::load_from_bytes(&config_path, &config_before)
            .map_err(|error| internal_err(format!("Failed to parse exact config: {error}")))?;
        let state_path = state_file_path(config.local_project_id());
        let state = SchedulerState::load(&state_path)
            .map_err(|error| internal_err(format!("Failed to read scheduler state: {error}")))?;

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
                "sync=true is not valid for a Phantom token remap: the provider credential is unchanged. Rotate at the provider, store the replacement from a trusted terminal, then use a separately reviewed deployment workflow; automated live provider issuance is disabled.",
            ));
        }

        let (transaction_lock, config, vault) = self.load_config_and_vault_anchored()?;

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

        let env_path = resolve_env_path_anchored(
            &transaction_lock,
            transaction_lock.project_root_at_acquisition(),
            &config,
            std::slice::from_ref(&params.name),
        )?;
        remap_phantom_tokens_locked(
            &transaction_lock,
            &env_path,
            std::slice::from_ref(&params.name),
        )?;

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
            This blocks future vault retrieval and new `phantom exec`/foreground `phantom start` \
            mapped-secret preflight; it does not recall values already injected or cached. \
            Returns: { demoted: [{ name, expires_at, secs_overdue }], \
            promoted: [{ name }], skipped_count, total_scanned }. \
            Requires confirm:true because it writes vault metadata."
    )]
    fn phantom_apply_expiry_policy(
        &self,
        Parameters(params): Parameters<ApplyExpiryPolicyParams>,
    ) -> Result<CallToolResult, McpError> {
        require_confirm("phantom_apply_expiry_policy", params.confirm)?;
        use phantom_vault::metadata::VaultMode;

        let (config, vault) = self.load_config_and_vault()?;
        let now = phantom_vault::metadata::now_secs();

        let entries = vault
            .list_with_metadata()
            .map_err(|e| internal_err(format!("Failed to list secrets: {e}")))?;

        let mut demoted: Vec<serde_json::Value> = Vec::new();
        let mut promoted: Vec<serde_json::Value> = Vec::new();
        let mut skipped_count: usize = 0;
        let mut changes = Vec::new();

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
                    changes.push(phantom_vault::MetadataCas {
                        name: name.clone(),
                        expected: Some(meta.clone()),
                        replacement: Some(new_meta),
                    });
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
                        changes.push(phantom_vault::MetadataCas {
                            name: name.clone(),
                            expected: Some(meta.clone()),
                            replacement: Some(new_meta),
                        });
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

        let mut entry_names = entries
            .iter()
            .map(|(name, _)| name.clone())
            .collect::<Vec<_>>();
        entry_names.sort();
        let (names_digest, names_sample) = bounded_validation_name_plan(&entry_names)?;
        let change_plan = changes
            .iter()
            .map(|change| {
                serde_json::json!({
                    "name": change.name,
                    "expected": change.expected,
                    "replacement": change.replacement,
                })
            })
            .collect::<Vec<_>>();
        let params_json = serde_json::to_string(&serde_json::json!({
            "request": &params,
            "local_project_id": config.local_project_id(),
            "entry_count": entry_names.len(),
            "entry_names_sha256": names_digest,
            "entry_name_sample": names_sample,
            "changes": change_plan,
        }))
        .map_err(|error| internal_err(format!("Failed to bind expiry approval: {error}")))?;
        require_approval_token(
            "phantom_apply_expiry_policy",
            params.approval_token.as_deref(),
            &params_json,
            &self.project_id(),
        )?;

        if !changes.is_empty()
            && !vault
                .compare_and_swap_metadata_batch(&changes)
                .map_err(|error| {
                    internal_err(format!("Expiry policy did not commit atomically: {error}"))
                })?
        {
            return Err(internal_err(
                "Expiry metadata changed concurrently; no promotion or demotion was committed",
            ));
        }
        for entry in &demoted {
            if let Some(name) = entry.get("name").and_then(|value| value.as_str()) {
                phantom_core::audit::log("secret.expiry_policy.demoted", Some(name));
            }
        }
        for entry in &promoted {
            if let Some(name) = entry.get("name").and_then(|value| value.as_str()) {
                phantom_core::audit::log("secret.expiry_policy.promoted", Some(name));
            }
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

fn read_package_scripts_anchored(
    target: &AnchoredTarget,
) -> Result<(serde_json::Value, AnchoredRead), McpError> {
    let before = target
        .read_regular()
        .map_err(|error| internal_err(format!("Failed to safely read package.json: {error}")))?
        .ok_or_else(|| internal_err("No package.json found in project directory."))?;
    let package = serde_json::from_slice(before.bytes())
        .map_err(|error| internal_err(format!("Failed to parse package.json: {error}")))?;
    Ok((package, before))
}

fn write_package_json_anchored(
    target: &AnchoredTarget,
    package: &serde_json::Value,
    before: &AnchoredRead,
) -> Result<(), McpError> {
    write_package_json_anchored_with(target, package, before, || {})
}

fn write_package_json_anchored_with(
    target: &AnchoredTarget,
    package: &serde_json::Value,
    before: &AnchoredRead,
    before_commit: impl FnOnce(),
) -> Result<(), McpError> {
    let pretty = serde_json::to_string_pretty(package)
        .map_err(|error| internal_err(format!("Failed to serialize package.json: {error}")))?;
    before_commit();
    match target.replace_if_exact_with_permissions(
        Some(before),
        format!("{pretty}\n").as_bytes(),
        before.permissions(),
    ) {
        Ok(AnchoredEffect::Durable(_)) => Ok(()),
        Ok(AnchoredEffect::CommittedVerifiedButDurabilityUncertain { .. }) => {
            eprintln!(
                "warning: package.json replacement committed and was verified, but directory crash durability is not provable on this platform"
            );
            Ok(())
        }
        Ok(AnchoredEffect::CommittedButUncertain { error, .. }) => Err(internal_err(format!(
            "package.json replacement committed, but durability or post-publish verification is uncertain: {error}. Do not assume the write had no effect; reopen package.json before retrying"
        ))),
        Err(error) => Err(internal_err(format!(
            "package.json changed after it was read; refusing to overwrite it: {error}"
        ))),
    }
}

fn write_new_anchored_output(
    target: &AnchoredTarget,
    display_name: &str,
    content: &[u8],
) -> Result<(), McpError> {
    write_new_anchored_output_with(target, display_name, content, || {})
}

fn write_new_anchored_output_with(
    target: &AnchoredTarget,
    display_name: &str,
    content: &[u8],
    before_commit: impl FnOnce(),
) -> Result<(), McpError> {
    before_commit();
    match target.replace_if_exact(None, content) {
        Ok(AnchoredEffect::Durable(_)) => Ok(()),
        Ok(AnchoredEffect::CommittedVerifiedButDurabilityUncertain { .. }) => {
            eprintln!(
                "warning: generated output committed and was verified, but directory crash durability is not provable on this platform"
            );
            Ok(())
        }
        Ok(AnchoredEffect::CommittedButUncertain { error, .. }) => Err(internal_err(format!(
            "Generated {display_name} was published, but durability or post-publish verification is uncertain: {error}. Do not assume the write had no effect; reopen the output before retrying"
        ))),
        Err(error) => Err(internal_err(format!(
            "Output target changed while generating {display_name}; no file was overwritten: {error}"
        ))),
    }
}

fn wrapped_script_command(original: &str) -> String {
    format!("phantom exec -- {original}")
}

fn wrap_package_scripts(
    pkg: &mut serde_json::Value,
    only: &[String],
    skip: &[String],
) -> Result<Vec<String>, String> {
    let Some(scripts) = pkg
        .get_mut("scripts")
        .and_then(serde_json::Value::as_object_mut)
    else {
        return Ok(Vec::new());
    };
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
    let mut candidates = Vec::new();
    for (name, value) in scripts.iter() {
        let Some(original) = value.as_str() else {
            continue;
        };
        if name.ends_with(":raw")
            || original.contains("phantom-secrets")
            || original.contains("phantom exec")
            || skip.iter().any(|skip_name| skip_name == name)
        {
            continue;
        }
        let should_wrap = if only.is_empty() {
            let lower = name.to_lowercase();
            wrap_keywords.iter().any(|keyword| lower.contains(keyword))
                && !skip_keywords.iter().any(|keyword| lower.contains(keyword))
        } else {
            only.iter().any(|only_name| only_name == name)
        };
        if should_wrap {
            let raw_name = format!("{name}:raw");
            if scripts.contains_key(&raw_name) {
                return Err(format!(
                    "Refusing to wrap '{name}': package.json already contains user-owned script '{raw_name}'. No scripts were changed."
                ));
            }
            candidates.push((name.clone(), raw_name, original.to_string()));
        }
    }
    for (name, raw_name, original) in &candidates {
        scripts.insert(
            raw_name.clone(),
            serde_json::Value::String(original.clone()),
        );
        scripts.insert(
            name.clone(),
            serde_json::Value::String(wrapped_script_command(original)),
        );
    }
    Ok(candidates.into_iter().map(|(name, _, _)| name).collect())
}

fn unwrap_package_scripts(pkg: &mut serde_json::Value) -> Vec<String> {
    let Some(scripts) = pkg
        .get_mut("scripts")
        .and_then(serde_json::Value::as_object_mut)
    else {
        return Vec::new();
    };
    let owned = scripts
        .iter()
        .filter_map(|(raw_name, raw_value)| {
            let base_name = raw_name.strip_suffix(":raw")?;
            let original = raw_value.as_str()?;
            let expected = wrapped_script_command(original);
            (scripts.get(base_name).and_then(serde_json::Value::as_str) == Some(&expected)).then(
                || {
                    (
                        base_name.to_string(),
                        raw_name.clone(),
                        original.to_string(),
                    )
                },
            )
        })
        .collect::<Vec<_>>();
    for (base_name, raw_name, original) in &owned {
        scripts.insert(
            base_name.clone(),
            serde_json::Value::String(original.clone()),
        );
        scripts.remove(raw_name);
    }
    owned
        .into_iter()
        .map(|(base_name, _, _)| base_name)
        .collect()
}

struct SensitiveSecretMap(std::collections::BTreeMap<String, zeroize::Zeroizing<String>>);

#[derive(serde::Deserialize)]
struct ParsedSensitiveSecret(String);

impl ParsedSensitiveSecret {
    fn into_zeroizing(mut self) -> zeroize::Zeroizing<String> {
        zeroize::Zeroizing::new(std::mem::take(&mut self.0))
    }
}

impl Drop for ParsedSensitiveSecret {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.0.zeroize();
    }
}

impl SensitiveSecretMap {
    fn new(values: std::collections::BTreeMap<String, zeroize::Zeroizing<String>>) -> Self {
        Self(values)
    }

    fn parse_json(bytes: &[u8]) -> Result<Self, serde_json::Error> {
        let parsed: std::collections::BTreeMap<String, ParsedSensitiveSecret> =
            serde_json::from_slice(bytes)?;
        Ok(Self::new(
            parsed
                .into_iter()
                .map(|(name, value)| (name, value.into_zeroizing()))
                .collect(),
        ))
    }
}

impl std::ops::Deref for SensitiveSecretMap {
    type Target = std::collections::BTreeMap<String, zeroize::Zeroizing<String>>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Drop for SensitiveSecretMap {
    fn drop(&mut self) {
        // Each value is independently Zeroizing; clearing forces every owner
        // to scrub before the map allocation itself is released.
        self.0.clear();
    }
}

// ── Private helpers ───────────────────────────────────────────────────────────

struct DoctorFileOnlyVault;

impl phantom_vault::VaultBackend for DoctorFileOnlyVault {
    fn store(&self, _name: &str, _value: &str) -> phantom_core::error::Result<()> {
        Err(phantom_core::error::PhantomError::VaultError(
            "doctor file transaction cannot mutate vault state".to_string(),
        ))
    }

    fn retrieve(&self, _name: &str) -> phantom_core::error::Result<zeroize::Zeroizing<String>> {
        Err(phantom_core::error::PhantomError::VaultError(
            "doctor file transaction cannot read vault state".to_string(),
        ))
    }

    fn delete(&self, _name: &str) -> phantom_core::error::Result<()> {
        Err(phantom_core::error::PhantomError::VaultError(
            "doctor file transaction cannot mutate vault state".to_string(),
        ))
    }

    fn list(&self) -> phantom_core::error::Result<Vec<String>> {
        Err(phantom_core::error::PhantomError::VaultError(
            "doctor file transaction cannot read vault state".to_string(),
        ))
    }

    fn backend_name(&self) -> &str {
        "doctor-file-only"
    }
}

fn commit_doctor_file_updates(
    project_dir: &Path,
    files: Vec<phantom_vault::InitFile>,
    hook_changed: bool,
) -> Result<(), McpError> {
    phantom_vault::commit_init(project_dir, &DoctorFileOnlyVault, Vec::new(), files)
        .map(|_| ())
        .map_err(|error| {
            let prior_effect = if hook_changed {
                " The pre-commit hook was already repaired before this independent file transaction failed; inspect it before retrying."
            } else {
                ""
            };
            internal_err(format!(
                "Doctor file transaction failed; exact transaction-owned changes were rolled back where verifiable: {error}.{prior_effect}"
            ))
        })
}

fn retrieve_optional_secret(
    vault: &dyn phantom_vault::VaultBackend,
    name: &str,
    purpose: &str,
) -> Result<Option<zeroize::Zeroizing<String>>, McpError> {
    match vault.retrieve(name) {
        Ok(value) => Ok(Some(value)),
        Err(phantom_core::error::PhantomError::SecretNotFound(_)) => Ok(None),
        Err(error) => Err(internal_err(format!(
            "Failed to read {purpose} '{name}' from the vault: {error}"
        ))),
    }
}

fn validate_mcp_secret_name(name: &str) -> Result<(), McpError> {
    let mut bytes = name.bytes();
    if !matches!(bytes.next(), Some(b'A'..=b'Z' | b'a'..=b'z' | b'_'))
        || !bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    {
        return Err(invalid_params_err(
            "Secret names must match [A-Za-z_][A-Za-z0-9_]*",
        ));
    }
    Ok(())
}

fn load_mcp_config_exact(path: &Path) -> Result<(PhantomConfig, Vec<u8>), McpError> {
    let before = phantom_core::fs::read_regular_file(path)
        .map_err(|error| internal_err(format!("Failed to safely read config: {error}")))?
        .ok_or_else(|| invalid_params_err("Target .phantom.toml does not exist"))?;
    let config = PhantomConfig::load_from_bytes(path, &before)
        .map_err(|error| internal_err(format!("Failed to load config: {error}")))?;
    Ok((config, before))
}

fn require_exact_config_before_effect(path: &Path, expected: &[u8]) -> Result<(), McpError> {
    let current = phantom_core::fs::read_regular_file(path)
        .map_err(|error| internal_err(format!("Failed to recheck project config: {error}")))?;
    if current.as_deref() != Some(expected) {
        return Err(internal_err(
            ".phantom.toml changed after approval; no secret value or network effect was attempted",
        ));
    }
    Ok(())
}

fn bounded_name_digest(names: &[String]) -> Result<String, McpError> {
    const MAX_NAMES: usize = 4096;
    const MAX_NAME_BYTES: usize = 256;
    if names.len() > MAX_NAMES
        || names.iter().any(|name| {
            name.is_empty() || name.len() > MAX_NAME_BYTES || name.chars().any(char::is_control)
        })
    {
        return Err(invalid_params_err(
            "vault name set is too large or contains unsafe approval identifiers",
        ));
    }
    let mut digest = Sha256::new();
    digest.update(b"phantom-cloud-vault-names-v1\0");
    for name in names {
        digest.update((name.len() as u64).to_be_bytes());
        digest.update(name.as_bytes());
    }
    Ok(hex::encode(digest.finalize()))
}

fn team_push_approval_params_json(
    params: &TeamVaultParams,
    canonical_project: &str,
    config: &PhantomConfig,
    config_before: &[u8],
    vault_backend: &str,
    names: &[String],
) -> Result<String, McpError> {
    serde_json::to_string(&serde_json::json!({
        "team_id": &params.team_id,
        "confirm": params.confirm,
        "plan": {
            "canonical_project": canonical_project,
            "local_project_id": config.local_project_id(),
            "portable_project_id": config.portable_project_id(),
            "config_sha256": hex::encode(Sha256::digest(config_before)),
            "vault_backend": vault_backend,
            "secret_count": names.len(),
            "secret_names_sha256": bounded_name_digest(names)?,
        }
    }))
    .map_err(|error| internal_err(format!("Failed to bind team-push approval: {error}")))
}

fn sanitized_alert_origins(
    config: &phantom_core::leak_correlation::AlertingConfig,
) -> Result<Vec<String>, McpError> {
    phantom_core::leak_correlation::alert_backend_review_origins(config)
        .map_err(|error| invalid_params_err(error.to_string()))
}

fn mcp_dotenv_has_key(before: Option<&[u8]>, name: &str) -> Result<bool, McpError> {
    let Some(bytes) = before else {
        return Ok(false);
    };
    let content = std::str::from_utf8(bytes)
        .map_err(|_| internal_err("Target managed dotenv is not valid UTF-8"))?;
    Ok(DotenvFile::parse_str(content)
        .entries()
        .iter()
        .any(|entry| entry.key == name))
}

fn copy_approval_params_json(
    params: &CopySecretParams,
    canonical_target: &Path,
    target_local_project_id: &str,
    target_name: &str,
    env_path: &Path,
    config_before: &[u8],
) -> Result<String, McpError> {
    let config_hex = hex::encode(config_before);
    let fingerprint_input = serde_json::json!({ "config_hex": config_hex }).to_string();
    let config_fingerprint = phantom_core::mcp_approval::compute_arg_hash(
        &fingerprint_input,
        b"phantom-copy-target-config-v1",
    );
    let env_name = phantom_core::managed_dotenv::dotenv_basename(canonical_target, env_path)
        .map_err(|error| internal_err(format!("Invalid target dotenv binding: {error}")))?;
    serde_json::to_string(&serde_json::json!({
        "name": params.name,
        "target_dir": params.target_dir,
        "rename": params.rename,
        "confirm": params.confirm,
        "approval_token": params.approval_token,
        "resolved_target": {
            "canonical_path": canonical_target.to_string_lossy(),
            "local_project_id": target_local_project_id,
            "source_name": params.name,
            "target_name": target_name,
            "managed_dotenv": env_name,
            "config_hmac_sha256": config_fingerprint,
        }
    }))
    .map_err(|error| internal_err(format!("Failed to bind copy approval: {error}")))
}

fn bounded_validation_name_plan(names: &[String]) -> Result<(String, Vec<String>), McpError> {
    const MAX_NAMES: usize = 4096;
    const MAX_NAME_BYTES: usize = 128;
    const MAX_TOTAL_BYTES: usize = MAX_NAMES * MAX_NAME_BYTES;
    if names.len() > MAX_NAMES || names.iter().map(String::len).sum::<usize>() > MAX_TOTAL_BYTES {
        return Err(invalid_params_err(
            "validation name set is too large to authorize safely",
        ));
    }
    let mut digest = Sha256::new();
    digest.update(b"phantom-validation-names-v1\0");
    let mut previous: Option<&str> = None;
    for name in names {
        let mut bytes = name.bytes();
        if name.is_empty()
            || name.len() > MAX_NAME_BYTES
            || !matches!(bytes.next(), Some(b'A'..=b'Z' | b'a'..=b'z' | b'_'))
            || !bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
            || previous == Some(name.as_str())
        {
            return Err(invalid_params_err(
                "vault contains a duplicate or unsafe name that cannot be authorized",
            ));
        }
        digest.update((name.len() as u64).to_le_bytes());
        digest.update(name.as_bytes());
        previous = Some(name);
    }
    Ok((
        hex::encode(digest.finalize()),
        names.iter().take(10).cloned().collect(),
    ))
}

#[allow(clippy::too_many_arguments)]
fn apply_mcp_copy_transaction(
    target_dir: &Path,
    config_path: &Path,
    mut config: PhantomConfig,
    config_before: Vec<u8>,
    vault: &dyn phantom_vault::VaultBackend,
    vault_names: Vec<String>,
    env_path: PathBuf,
    env_before: Option<zeroize::Zeroizing<Vec<u8>>>,
    target_name: &str,
    value: &str,
) -> Result<(), McpError> {
    let mut content = zeroize::Zeroizing::new(match env_before.as_deref() {
        Some(bytes) => String::from_utf8(bytes.to_vec())
            .map_err(|_| internal_err("Target managed dotenv is not valid UTF-8"))?,
        None => String::new(),
    });
    if !content.is_empty() && !content.ends_with('\n') {
        content.push('\n');
    }
    let mut tokens = TokenMap::new();
    let token = tokens.insert(target_name.to_string());
    content.push_str(&format!("{target_name}={token}\n"));
    let env_after = std::mem::take(&mut *content).into_bytes();

    let config_after = if config.phantom.dotenv_path.is_none() && vault_names.is_empty() {
        config.phantom.dotenv_path = Some(
            phantom_core::managed_dotenv::dotenv_basename(target_dir, &env_path)
                .map_err(|error| internal_err(format!("Invalid target dotenv: {error}")))?,
        );
        toml::to_string_pretty(&config)
            .map_err(|error| internal_err(format!("Failed to serialize target config: {error}")))?
            .into_bytes()
    } else {
        config_before.clone()
    };
    let files = vec![
        phantom_vault::InitFile::replace_if_unchanged(
            config_path,
            Some(config_before),
            config_after,
        ),
        phantom_vault::InitFile::replace_if_unchanged(
            &env_path,
            env_before.as_ref().map(|bytes| bytes.as_slice().to_vec()),
            env_after,
        )
        .commit_last(),
    ];
    let mutation =
        phantom_vault::InitSecret::replace_if_unchanged(target_name, None::<String>, value);
    phantom_vault::commit_init(target_dir, vault, vec![mutation], files).map_err(|error| {
        internal_err(format!(
            "Target copy transaction failed: {error}. Inspect target vault/config/dotenv before retrying."
        ))
    })?;
    Ok(())
}

fn apply_team_vault_pull_transaction(
    project_dir: &Path,
    config_path: &Path,
    config_before: Vec<u8>,
    vault: &dyn phantom_vault::VaultBackend,
    secrets: &SensitiveSecretMap,
) -> Result<usize, McpError> {
    let mut mutations = Vec::with_capacity(secrets.len());
    for (name, value) in secrets.iter() {
        let before = retrieve_optional_secret(vault, name, "team-vault destination")?;
        mutations.push(phantom_vault::InitSecret::replace_if_unchanged(
            name,
            before.as_ref().map(|value| value.as_str().to_string()),
            value.as_str(),
        ));
    }
    let written = mutations.len();
    let config_guard = phantom_vault::InitFile::replace_if_unchanged(
        config_path,
        Some(config_before.clone()),
        config_before,
    );
    phantom_vault::commit_init(project_dir, vault, mutations, vec![config_guard]).map_err(
        |error| {
            internal_err(format!(
                "Team vault data was fetched, but the exact local config/vault transaction was denied: {error}. No success receipt is valid; inspect local state before retrying."
            ))
        },
    )?;
    Ok(written)
}

fn persist_provider_rotation_metadata(
    vault: &dyn phantom_vault::VaultBackend,
    name: &str,
    expires_override: Option<u64>,
    stages: &mut ProviderRotationStages,
) -> Result<Option<u64>, McpError> {
    let expires_at = vault
        .record_provider_rotation(name, expires_override)
        .map_err(|error| {
            provider_rotation_partial_error(name, "rotation metadata persistence", error, stages)
        })?;
    stages.metadata_committed = true;
    Ok(expires_at)
}

#[derive(Debug, Clone, serde::Serialize)]
struct ProviderRotationStages {
    provider_issued: bool,
    vault_committed: &'static str,
    token_remapped: bool,
    metadata_committed: bool,
    old_cleanup_attempted: bool,
    old_cleanup_succeeded: bool,
    cleanup_semantics: phantom_core::rotation_provider::CleanupSemantics,
    cleanup_outcome: Option<phantom_core::rotation_provider::CleanupOutcome>,
}

impl Default for ProviderRotationStages {
    fn default() -> Self {
        Self {
            provider_issued: false,
            vault_committed: "false",
            token_remapped: false,
            metadata_committed: false,
            old_cleanup_attempted: false,
            old_cleanup_succeeded: false,
            cleanup_semantics: phantom_core::rotation_provider::CleanupSemantics::NotApplicable,
            cleanup_outcome: None,
        }
    }
}

fn provider_rotation_partial_error(
    name: &str,
    failed_stage: &str,
    error: impl std::fmt::Display,
    stages: &ProviderRotationStages,
) -> McpError {
    let receipt = serde_json::to_string(stages).unwrap_or_else(|_| {
        "{\"provider_issued\":true,\"vault_committed\":\"unknown\",\"token_remapped\":false,\"metadata_committed\":false,\"old_cleanup_attempted\":false,\"old_cleanup_succeeded\":false,\"cleanup_semantics\":\"not_applicable\",\"cleanup_outcome\":null}".to_string()
    });
    internal_err(format!(
        "Provider rotation for '{name}' partially succeeded: {failed_stage} failed. stage_receipt: {receipt}. Local and provider state may now differ. Do not retry automatically: first reconcile the provider credential, local vault, Phantom token, rotation metadata, and prior-credential cleanup. Cause: {error}"
    ))
}

fn persist_issued_provider_credential(
    vault: &dyn phantom_vault::VaultBackend,
    name: &str,
    expected_before: Option<&zeroize::Zeroizing<String>>,
    issued_value: &str,
    stages: &mut ProviderRotationStages,
) -> Result<(), McpError> {
    let expected = expected_before.map(|value| value.as_str());
    match vault.compare_and_swap(name, expected, Some(issued_value)) {
        Ok(true) => {}
        Ok(false) => {
            stages.vault_committed = "false";
            return Err(provider_rotation_partial_error(
                name,
                "local vault persistence because the credential changed concurrently",
                "exact before-image no longer matched",
                stages,
            ));
        }
        Err(error) => {
            stages.vault_committed = "unknown";
            return Err(provider_rotation_partial_error(
                name,
                "local vault persistence",
                error,
                stages,
            ));
        }
    }

    match vault.retrieve(name) {
        Ok(stored) if stored.as_str() == issued_value => {
            stages.vault_committed = "true";
            Ok(())
        }
        Ok(_) => {
            stages.vault_committed = "unknown";
            Err(provider_rotation_partial_error(
                name,
                "local vault persistence verification",
                "stored value did not match the provider-issued credential",
                stages,
            ))
        }
        Err(error) => {
            stages.vault_committed = "unknown";
            Err(provider_rotation_partial_error(
                name,
                "local vault persistence verification",
                error,
                stages,
            ))
        }
    }
}

fn verify_provider_issued_value(
    vault: &dyn phantom_vault::VaultBackend,
    name: &str,
    issued_value: &str,
    stage: &str,
    stages: &mut ProviderRotationStages,
) -> Result<(), McpError> {
    match vault.retrieve(name) {
        Ok(value) if value.as_str() == issued_value => Ok(()),
        Ok(_) => {
            stages.vault_committed = "false";
            Err(provider_rotation_partial_error(
                name,
                stage,
                "local vault no longer contains the provider-issued credential",
                stages,
            ))
        }
        Err(error) => {
            stages.vault_committed = "unknown";
            Err(provider_rotation_partial_error(name, stage, error, stages))
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn apply_cloud_pull_transaction(
    project_dir: &Path,
    config_path: &Path,
    vault: &dyn phantom_vault::VaultBackend,
    secrets: &SensitiveSecretMap,
    force: bool,
    config_before: Vec<u8>,
    mut config: PhantomConfig,
    remote_version: u64,
) -> Result<(usize, usize), McpError> {
    let mut mutations = Vec::new();
    let mut skipped = 0;
    for (name, value) in secrets.iter() {
        let before = retrieve_optional_secret(vault, name, "local cloud-pull destination")?;
        if before.is_some() && !force {
            skipped += 1;
            continue;
        }
        mutations.push(phantom_vault::InitSecret::replace_if_unchanged(
            name,
            before.as_ref().map(|value| value.as_str().to_string()),
            value.as_str(),
        ));
    }

    update_cloud_reconciliation_mcp(&mut config, remote_version, skipped);
    let config_after = toml::to_string_pretty(&config)
        .map_err(|error| {
            internal_err(format!(
                "Failed to serialize cloud reconciliation state: {error}"
            ))
        })?
        .into_bytes();
    let added = mutations.len();
    let config_file = phantom_vault::InitFile::replace_if_unchanged(
        config_path,
        Some(config_before),
        config_after,
    );
    phantom_vault::commit_init(project_dir, vault, mutations, vec![config_file])
        .map_err(|error| internal_err(format!("Cloud pull transaction failed: {error}")))?;
    Ok((added, skipped))
}

fn update_cloud_reconciliation_mcp(
    config: &mut PhantomConfig,
    remote_version: u64,
    skipped: usize,
) {
    let cloud = config.cloud.get_or_insert_default();
    if skipped == 0 {
        cloud.version = remote_version;
        cloud.reconciliation_required = false;
        cloud.reconciliation_remote_version = None;
    } else {
        // A partial pull is not a valid merge base. Keep the prior version so
        // a later push cannot erase remote values that were deliberately skipped.
        cloud.reconciliation_required = true;
        cloud.reconciliation_remote_version = Some(remote_version);
    }
}

fn ensure_cloud_push_allowed_mcp(config: &PhantomConfig) -> Result<(), McpError> {
    if config
        .cloud
        .as_ref()
        .is_some_and(|cloud| cloud.reconciliation_required)
    {
        return Err(invalid_params_err(
            "Cloud push is blocked because the last pull was only partially reconciled. Run phantom_cloud_pull with force=true after explicit approval, or otherwise fully reconcile every remote secret. Do not retry push automatically."
        ));
    }
    Ok(())
}

fn resolve_env_path_anchored(
    transaction_lock: &phantom_vault::ProjectTransactionLock,
    project_dir: &Path,
    config: &PhantomConfig,
    vault_names: &[String],
) -> Result<PathBuf, McpError> {
    fn read_candidate(
        transaction_lock: &phantom_vault::ProjectTransactionLock,
        path: &Path,
    ) -> Result<Option<DotenvFile>, McpError> {
        let target = transaction_lock.target(path).map_err(|error| {
            internal_err(format!(
                "Failed to retain managed dotenv candidate {}: {error}",
                path.display()
            ))
        })?;
        let Some(read) = target.read_regular().map_err(|error| {
            internal_err(format!(
                "Failed to safely read managed dotenv candidate {}: {error}",
                path.display()
            ))
        })?
        else {
            return Ok(None);
        };
        let text = std::str::from_utf8(read.bytes()).map_err(|_| {
            internal_err(format!(
                "Managed dotenv candidate {} is not valid UTF-8",
                path.display()
            ))
        })?;
        Ok(Some(DotenvFile::parse_str(text)))
    }

    fn has_tokens(dotenv: &DotenvFile) -> bool {
        dotenv.entries().iter().any(|entry| entry.is_phantom)
    }

    let protected_state = !vault_names.is_empty() || !config.phantom.secrets.is_empty();
    if let Some(configured) = config.phantom.dotenv_path.as_deref() {
        let basename = phantom_core::managed_dotenv::validate_dotenv_basename(configured)
            .map_err(|error| internal_err(error.to_string()))?;
        let path = project_dir.join(basename);
        let dotenv = read_candidate(transaction_lock, &path)?.ok_or_else(|| {
            internal_err(format!(
                "Configured protected dotenv does not exist: {}",
                path.display()
            ))
        })?;
        if protected_state && !has_tokens(&dotenv) {
            return Err(internal_err(format!(
                "Protected vault/config state exists, but {} contains no phantom tokens; refusing an unprotected operation",
                path.display()
            )));
        }
        return Ok(path);
    }

    let mut existing = Vec::new();
    let mut token_bearing = Vec::new();
    for name in [
        ".env",
        ".env.local",
        ".env.development",
        ".env.development.local",
    ] {
        let path = project_dir.join(name);
        if let Some(dotenv) = read_candidate(transaction_lock, &path)? {
            if has_tokens(&dotenv) {
                token_bearing.push(path.clone());
            }
            existing.push(path);
        }
    }
    match token_bearing.len() {
        1 => return Ok(token_bearing.pop().expect("length checked")),
        count if count > 1 => {
            return Err(internal_err(format!(
                "Legacy config has {count} token-bearing dotenv files; rerun `phantom init --from <file>` to persist one explicit filename"
            )));
        }
        _ => {}
    }
    if protected_state {
        return Err(internal_err(
            "Protected vault/config state exists, but no token-bearing dotenv file could be resolved; refusing an unprotected operation. Rerun `phantom init --from <file>` to persist the protected filename",
        ));
    }
    Ok(existing
        .into_iter()
        .next()
        .unwrap_or_else(|| project_dir.join(".env")))
}

/// Replace protected placeholders through a retained project capability and
/// an exact effect receipt held under Phantom's project transaction lock.
#[cfg(test)]
fn remap_phantom_tokens_with(
    project_dir: &Path,
    env_path: &Path,
    names: &[String],
    before_commit: impl FnOnce(),
) -> Result<(), McpError> {
    let transaction_lock =
        phantom_vault::acquire_project_transaction_lock(project_dir).map_err(|error| {
            internal_err(format!(
                "Failed to acquire transaction lock for {}: {error}",
                project_dir.display()
            ))
        })?;
    remap_phantom_tokens_locked_with(&transaction_lock, env_path, names, before_commit)
}

fn remap_phantom_tokens_locked(
    transaction_lock: &phantom_vault::ProjectTransactionLock,
    env_path: &Path,
    names: &[String],
) -> Result<(), McpError> {
    remap_phantom_tokens_locked_with(transaction_lock, env_path, names, || {})
}

fn remap_phantom_tokens_locked_with(
    transaction_lock: &phantom_vault::ProjectTransactionLock,
    env_path: &Path,
    names: &[String],
    before_commit: impl FnOnce(),
) -> Result<(), McpError> {
    let target = transaction_lock.target(env_path).map_err(|error| {
        internal_err(format!(
            "Failed to retain managed dotenv {}: {error}",
            env_path.display()
        ))
    })?;
    let before = target
        .read_regular()
        .map_err(|error| {
            internal_err(format!(
                "Failed to snapshot {} through the retained project root: {error}",
                env_path.display()
            ))
        })?
        .ok_or_else(|| {
            invalid_params_err(format!(
                "Cannot remap Phantom tokens: {} does not exist.",
                env_path.display()
            ))
        })?;
    let env_text = std::str::from_utf8(before.bytes()).map_err(|_| {
        internal_err(format!(
            "Failed to parse {}: managed dotenv is not valid UTF-8",
            env_path.display()
        ))
    })?;
    let dotenv = DotenvFile::parse_str(env_text);
    for name in names {
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

    let mut token_map = TokenMap::new();
    for name in names {
        token_map.insert(name.clone());
    }
    let (rewritten, mut originals) = dotenv.rewrite_with_phantoms(&token_map);
    for value in originals.values_mut() {
        zeroize::Zeroize::zeroize(value);
    }
    originals.clear();

    before_commit();
    match target.replace_if_exact_with_permissions(
        Some(&before),
        rewritten.as_bytes(),
        before.permissions(),
    ) {
        Ok(AnchoredEffect::Durable(_)) => Ok(()),
        Ok(AnchoredEffect::CommittedVerifiedButDurabilityUncertain { .. }) => {
            eprintln!(
                "warning: managed dotenv replacement committed and was verified, but directory crash durability is not provable on this platform"
            );
            Ok(())
        }
        Ok(AnchoredEffect::CommittedButUncertain { error, .. }) => Err(internal_err(format!(
            "Managed dotenv replacement committed for {}, but durability or post-publish verification is uncertain: {error}. Do not assume the remap had no effect; reopen the dotenv before retrying",
            env_path.display()
        ))),
        Err(error) => Err(internal_err(format!(
            "Cannot remap Phantom tokens: {} changed after it was read; no Phantom write was committed: {error}",
            env_path.display()
        ))),
    }
}

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
    use phantom_vault::VaultBackend;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tempfile::TempDir;

    /// Share one re-entrant process environment guard with core and vault root
    /// discovery. A crate-local mutex races; a plain shared mutex deadlocks
    /// when transaction root discovery nests inside a guarded test.
    use phantom_core::PROCESS_ENV_LOCK as ENV_LOCK;

    #[test]
    fn validation_name_plan_rejects_spoofing_and_unbounded_sets() {
        assert!(bounded_validation_name_plan(&["SAFE\nSPOOF".into()]).is_err());
        assert!(bounded_validation_name_plan(&["A".repeat(129)]).is_err());
        assert!(bounded_validation_name_plan(&vec!["A".into(); 4097]).is_err());
        let (digest, sample) = bounded_validation_name_plan(&["A".into(), "B".into()]).unwrap();
        assert_eq!(digest.len(), 64);
        assert_eq!(sample, vec!["A", "B"]);
    }

    #[test]
    fn mcp_wrap_collision_preserves_entire_package() {
        let mut package = serde_json::json!({
            "scripts": {
                "build": "next build",
                "dev": "next dev",
                "dev:raw": "user-owned"
            }
        });
        let before = package.clone();

        let error = wrap_package_scripts(&mut package, &[], &[]).unwrap_err();
        assert!(error.contains("user-owned script 'dev:raw'"));
        assert_eq!(package, before);
    }

    #[test]
    fn mcp_unwrap_preserves_unmatched_user_raw_script() {
        let mut package = serde_json::json!({
            "scripts": {
                "build": "phantom exec -- next build",
                "build:raw": "next build",
                "dev": "next dev",
                "dev:raw": "user-owned"
            }
        });

        assert_eq!(unwrap_package_scripts(&mut package), vec!["build"]);
        assert_eq!(package["scripts"]["build"], "next build");
        assert!(package["scripts"].get("build:raw").is_none());
        assert_eq!(package["scripts"]["dev:raw"], "user-owned");
    }

    #[test]
    fn mcp_project_targets_reject_paths_outside_the_retained_root() {
        let container = canonical_temp_dir();
        let project = container.path().join("project");
        std::fs::create_dir(&project).unwrap();
        let outside = container.path().join("outside.json");
        std::fs::write(&outside, b"{}\n").unwrap();

        let transaction_lock = phantom_vault::acquire_project_transaction_lock(&project).unwrap();
        let error = transaction_lock.target(&outside).unwrap_err();

        assert!(error.to_string().contains("outside"));
        assert_eq!(std::fs::read(&outside).unwrap(), b"{}\n");
    }

    #[cfg(unix)]
    #[test]
    fn anchored_loader_rejects_project_replacement_during_vault_open() {
        let _environment = TestEnvironment::new();
        let home = canonical_temp_dir();
        unsafe {
            std::env::set_var("HOME", home.path());
            std::env::set_var(
                "PHANTOM_VAULT_PASSPHRASE",
                "test-passphrase-do-not-use-in-prod",
            );
        }
        let container = canonical_temp_dir();
        let project = container.path().join("project");
        let moved = container.path().join("moved");
        std::fs::create_dir(&project).unwrap();
        PhantomConfig::new_with_defaults(PhantomConfig::project_id_from_path(&project))
            .save(&project.join(".phantom.toml"))
            .unwrap();
        let approved = std::fs::read(project.join(".phantom.toml")).unwrap();
        let server = PhantomMcpServer::with_dir(project.clone());

        let error = server
            .load_config_and_vault_anchored_with(|| {
                std::fs::rename(&project, &moved).unwrap();
                std::fs::create_dir(&project).unwrap();
                std::fs::write(
                    project.join(".phantom.toml"),
                    b"[phantom]\nversion = \"1\"\nproject_id = \"decoy\"\n",
                )
                .unwrap();
            })
            .err()
            .expect("same-path replacement must be rejected");

        assert!(error.message.contains("Project root was replaced"));
        assert_eq!(
            std::fs::read(moved.join(".phantom.toml")).unwrap(),
            approved
        );
        assert!(std::fs::read_to_string(project.join(".phantom.toml"))
            .unwrap()
            .contains("decoy"));
    }

    #[test]
    fn anchored_loader_lock_order_source_contract() {
        let source = include_str!("server.rs");
        let loader = source
            .split("fn load_config_and_vault_anchored_with")
            .nth(1)
            .unwrap()
            .split("fn save_cloud_version")
            .next()
            .unwrap();
        let anchor = loader.find("TrustedAnchor::open").unwrap();
        let vault = loader.find("try_create_vault").unwrap();
        let project_lock = loader.find("acquire_project_transaction_lock").unwrap();
        let identity = loader.find("project_identity_at_acquisition").unwrap();
        let config_read = identity + loader[identity..].find("read_regular").unwrap();
        assert!(anchor < vault && vault < project_lock);
        assert!(project_lock < identity && identity < config_read);
    }

    #[cfg(unix)]
    #[test]
    fn mcp_package_write_follows_retained_root_across_a_rename_decoy() {
        let container = canonical_temp_dir();
        let project = container.path().join("project");
        let moved = container.path().join("moved");
        std::fs::create_dir(&project).unwrap();
        let package_path = project.join("package.json");
        std::fs::write(&package_path, br#"{"scripts":{"build":"next build"}}"#).unwrap();

        let transaction_lock = phantom_vault::acquire_project_transaction_lock(&project).unwrap();
        let target = transaction_lock.target(&package_path).unwrap();
        let (mut package, before) = read_package_scripts_anchored(&target).unwrap();
        package["scripts"]["build"] = serde_json::json!("phantom exec -- next build");

        write_package_json_anchored_with(&target, &package, &before, || {
            std::fs::rename(&project, &moved).unwrap();
            std::fs::create_dir(&project).unwrap();
            std::fs::write(
                project.join("package.json"),
                br#"{"scripts":{"build":"decoy"}}"#,
            )
            .unwrap();
        })
        .unwrap();

        let published: serde_json::Value =
            serde_json::from_slice(&std::fs::read(moved.join("package.json")).unwrap()).unwrap();
        let decoy: serde_json::Value =
            serde_json::from_slice(&std::fs::read(project.join("package.json")).unwrap()).unwrap();
        assert_eq!(published["scripts"]["build"], "phantom exec -- next build");
        assert_eq!(decoy["scripts"]["build"], "decoy");
    }

    #[cfg(unix)]
    #[test]
    fn mcp_new_output_follows_retained_root_across_a_rename_decoy() {
        let container = canonical_temp_dir();
        let project = container.path().join("project");
        let moved = container.path().join("moved");
        std::fs::create_dir(&project).unwrap();
        let output_path = project.join(".env.example");

        let transaction_lock = phantom_vault::acquire_project_transaction_lock(&project).unwrap();
        let target = transaction_lock.target(&output_path).unwrap();
        write_new_anchored_output_with(&target, ".env.example", b"SAFE=example\n", || {
            std::fs::rename(&project, &moved).unwrap();
            std::fs::create_dir(&project).unwrap();
            std::fs::write(project.join(".env.example"), b"DECOY=owner\n").unwrap();
        })
        .unwrap();

        assert_eq!(
            std::fs::read(moved.join(".env.example")).unwrap(),
            b"SAFE=example\n"
        );
        assert_eq!(
            std::fs::read(project.join(".env.example")).unwrap(),
            b"DECOY=owner\n"
        );
    }

    fn cloud_test_config(version: u64) -> PhantomConfig {
        let mut config = PhantomConfig::new_with_defaults("cloud-test-project".to_string());
        config.cloud.get_or_insert_default().version = version;
        config
    }

    fn write_cloud_test_config(path: &Path, config: &PhantomConfig) -> Vec<u8> {
        let bytes = toml::to_string_pretty(config).unwrap().into_bytes();
        std::fs::write(path, &bytes).unwrap();
        bytes
    }

    fn write_copy_test_config(path: &Path) -> (PhantomConfig, Vec<u8>) {
        let config = PhantomConfig::new_with_defaults("copy-target-project".to_string());
        let bytes = toml::to_string_pretty(&config).unwrap().into_bytes();
        std::fs::write(path, &bytes).unwrap();
        (config, bytes)
    }

    struct BackendFailureVault {
        store_calls: AtomicUsize,
    }

    struct ConcurrentCreateVault {
        inner: phantom_vault::file::FileVault,
        injected: std::sync::atomic::AtomicBool,
    }

    struct NthCasFailureVault {
        inner: phantom_vault::file::FileVault,
        fail_at: usize,
        calls: AtomicUsize,
    }

    impl BackendFailureVault {
        fn new() -> Self {
            Self {
                store_calls: AtomicUsize::new(0),
            }
        }
    }

    impl phantom_vault::VaultBackend for BackendFailureVault {
        fn store(&self, _name: &str, _value: &str) -> phantom_core::error::Result<()> {
            self.store_calls.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }

        fn retrieve(&self, _name: &str) -> phantom_core::error::Result<zeroize::Zeroizing<String>> {
            Err(phantom_core::error::PhantomError::VaultError(
                "injected credential read failure".to_string(),
            ))
        }

        fn delete(&self, _name: &str) -> phantom_core::error::Result<()> {
            Ok(())
        }

        fn list(&self) -> phantom_core::error::Result<Vec<String>> {
            Err(phantom_core::error::PhantomError::VaultError(
                "injected vault listing failure".to_string(),
            ))
        }

        fn backend_name(&self) -> &str {
            "backend-failure"
        }

        fn set_metadata(
            &self,
            _name: &str,
            _meta: phantom_vault::SecretMetadata,
        ) -> phantom_core::error::Result<()> {
            Err(phantom_core::error::PhantomError::VaultError(
                "injected metadata write failure".to_string(),
            ))
        }

        fn compare_and_swap_metadata_batch(
            &self,
            _changes: &[phantom_vault::MetadataCas],
        ) -> phantom_core::error::Result<bool> {
            Err(phantom_core::error::PhantomError::VaultError(
                "injected metadata write failure".to_string(),
            ))
        }
    }

    impl phantom_vault::VaultBackend for ConcurrentCreateVault {
        fn store(&self, name: &str, value: &str) -> phantom_core::error::Result<()> {
            self.inner.store(name, value)
        }

        fn retrieve(&self, name: &str) -> phantom_core::error::Result<zeroize::Zeroizing<String>> {
            self.inner.retrieve(name)
        }

        fn delete(&self, name: &str) -> phantom_core::error::Result<()> {
            self.inner.delete(name)
        }

        fn compare_and_swap(
            &self,
            name: &str,
            expected: Option<&str>,
            replacement: Option<&str>,
        ) -> phantom_core::error::Result<bool> {
            if !self
                .injected
                .swap(true, std::sync::atomic::Ordering::SeqCst)
            {
                self.inner.store(name, "concurrent-owner")?;
            }
            self.inner.compare_and_swap(name, expected, replacement)
        }

        fn list(&self) -> phantom_core::error::Result<Vec<String>> {
            self.inner.list()
        }

        fn backend_name(&self) -> &str {
            "concurrent-create"
        }

        fn get_metadata(
            &self,
            name: &str,
        ) -> phantom_core::error::Result<Option<phantom_vault::SecretMetadata>> {
            self.inner.get_metadata(name)
        }

        fn set_metadata(
            &self,
            name: &str,
            metadata: phantom_vault::SecretMetadata,
        ) -> phantom_core::error::Result<()> {
            self.inner.set_metadata(name, metadata)
        }

        fn get_validation_metadata(
            &self,
            name: &str,
        ) -> phantom_core::error::Result<phantom_core::validator::ValidationMetadata> {
            self.inner.get_validation_metadata(name)
        }

        fn set_validation_metadata(
            &self,
            name: &str,
            metadata: phantom_core::validator::ValidationMetadata,
        ) -> phantom_core::error::Result<()> {
            self.inner.set_validation_metadata(name, metadata)
        }
    }

    impl phantom_vault::VaultBackend for NthCasFailureVault {
        fn store(&self, name: &str, value: &str) -> phantom_core::error::Result<()> {
            self.inner.store(name, value)
        }

        fn retrieve(&self, name: &str) -> phantom_core::error::Result<zeroize::Zeroizing<String>> {
            self.inner.retrieve(name)
        }

        fn delete(&self, name: &str) -> phantom_core::error::Result<()> {
            self.inner.delete(name)
        }

        fn compare_and_swap(
            &self,
            name: &str,
            expected: Option<&str>,
            replacement: Option<&str>,
        ) -> phantom_core::error::Result<bool> {
            let call = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
            if call == self.fail_at {
                return Err(phantom_core::error::PhantomError::VaultError(
                    "injected nth team-pull commit failure".to_string(),
                ));
            }
            self.inner.compare_and_swap(name, expected, replacement)
        }

        fn list(&self) -> phantom_core::error::Result<Vec<String>> {
            self.inner.list()
        }

        fn backend_name(&self) -> &str {
            "nth-cas-failure"
        }

        fn get_metadata(
            &self,
            name: &str,
        ) -> phantom_core::error::Result<Option<phantom_vault::SecretMetadata>> {
            self.inner.get_metadata(name)
        }

        fn set_metadata(
            &self,
            name: &str,
            metadata: phantom_vault::SecretMetadata,
        ) -> phantom_core::error::Result<()> {
            self.inner.set_metadata(name, metadata)
        }

        fn get_validation_metadata(
            &self,
            name: &str,
        ) -> phantom_core::error::Result<phantom_core::validator::ValidationMetadata> {
            self.inner.get_validation_metadata(name)
        }

        fn set_validation_metadata(
            &self,
            name: &str,
            metadata: phantom_core::validator::ValidationMetadata,
        ) -> phantom_core::error::Result<()> {
            self.inner.set_validation_metadata(name, metadata)
        }
    }

    #[test]
    fn mcp_copy_transaction_creates_absent_vault_and_dotenv_mapping() {
        let dir = TempDir::new().unwrap();
        let config_path = dir.path().join(".phantom.toml");
        let env_path = dir.path().join(".env");
        let (config, config_before) = write_copy_test_config(&config_path);
        let vault = phantom_vault::file::FileVault::new(
            dir.path(),
            "mcp-copy-success",
            "passphrase".to_string(),
        )
        .unwrap();

        apply_mcp_copy_transaction(
            dir.path(),
            &config_path,
            config,
            config_before,
            &vault,
            Vec::new(),
            env_path.clone(),
            None,
            "COPIED_KEY",
            "source-value",
        )
        .unwrap();

        assert_eq!(
            vault.retrieve("COPIED_KEY").unwrap().as_str(),
            "source-value"
        );
        let dotenv = std::fs::read_to_string(&env_path).unwrap();
        assert!(dotenv.contains("COPIED_KEY=phm_"));
        assert!(!dotenv.contains("source-value"));
        assert_eq!(
            PhantomConfig::load(&config_path)
                .unwrap()
                .phantom
                .dotenv_path
                .as_deref(),
            Some(".env")
        );
    }

    #[test]
    fn mcp_copy_config_drift_aborts_without_vault_or_dotenv_write() {
        let dir = TempDir::new().unwrap();
        let config_path = dir.path().join(".phantom.toml");
        let env_path = dir.path().join(".env");
        let (config, config_before) = write_copy_test_config(&config_path);
        let mut concurrent = config_before.clone();
        concurrent.extend_from_slice(b"\n# concurrent owner\n");
        std::fs::write(&config_path, &concurrent).unwrap();
        let vault = phantom_vault::file::FileVault::new(
            dir.path(),
            "mcp-copy-config-race",
            "passphrase".to_string(),
        )
        .unwrap();

        assert!(apply_mcp_copy_transaction(
            dir.path(),
            &config_path,
            config,
            config_before,
            &vault,
            Vec::new(),
            env_path.clone(),
            None,
            "COPIED_KEY",
            "source-value",
        )
        .is_err());
        assert_eq!(std::fs::read(&config_path).unwrap(), concurrent);
        assert!(!env_path.exists());
        assert!(matches!(
            vault.retrieve("COPIED_KEY"),
            Err(phantom_core::error::PhantomError::SecretNotFound(_))
        ));
    }

    #[test]
    fn mcp_copy_destination_race_preserves_concurrent_owner_and_rolls_back_config() {
        let dir = TempDir::new().unwrap();
        let config_path = dir.path().join(".phantom.toml");
        let env_path = dir.path().join(".env");
        let (config, config_before) = write_copy_test_config(&config_path);
        let inner = phantom_vault::file::FileVault::new(
            dir.path(),
            "mcp-copy-vault-race",
            "passphrase".to_string(),
        )
        .unwrap();
        let vault = ConcurrentCreateVault {
            inner,
            injected: std::sync::atomic::AtomicBool::new(false),
        };

        assert!(apply_mcp_copy_transaction(
            dir.path(),
            &config_path,
            config,
            config_before.clone(),
            &vault,
            Vec::new(),
            env_path.clone(),
            None,
            "COPIED_KEY",
            "source-value",
        )
        .is_err());
        assert_eq!(std::fs::read(&config_path).unwrap(), config_before);
        assert!(!env_path.exists());
        assert_eq!(
            vault.retrieve("COPIED_KEY").unwrap().as_str(),
            "concurrent-owner"
        );
    }

    #[test]
    fn mcp_copy_approval_binding_changes_with_target_identity_or_config() {
        let _environment = TestEnvironment::new();
        let home = canonical_temp_dir();
        let previous_home = std::env::var("HOME").ok();
        unsafe { std::env::set_var("HOME", home.path()) };
        let first = TempDir::new().unwrap();
        let second = TempDir::new().unwrap();
        let first_env = first.path().join(".env");
        let second_env = second.path().join(".env");
        let params = CopySecretParams {
            name: "SOURCE_KEY".to_string(),
            target_dir: first.path().display().to_string(),
            rename: Some("TARGET_KEY".to_string()),
            confirm: true,
            approval_token: None,
        };
        let a = copy_approval_params_json(
            &params,
            first.path(),
            "target-local-a",
            "TARGET_KEY",
            &first_env,
            b"config-a",
        )
        .unwrap();
        let identity_swap = copy_approval_params_json(
            &params,
            second.path(),
            "target-local-b",
            "TARGET_KEY",
            &second_env,
            b"config-a",
        )
        .unwrap();
        let config_swap = copy_approval_params_json(
            &params,
            first.path(),
            "target-local-a",
            "TARGET_KEY",
            &first_env,
            b"config-b",
        )
        .unwrap();
        let key = b"approval-binding-test-key";

        assert_ne!(
            phantom_core::mcp_approval::compute_arg_hash(&a, key),
            phantom_core::mcp_approval::compute_arg_hash(&identity_swap, key)
        );
        assert_ne!(
            phantom_core::mcp_approval::compute_arg_hash(&a, key),
            phantom_core::mcp_approval::compute_arg_hash(&config_swap, key)
        );
        assert!(!a.contains("source-value"));

        let nonce = phantom_core::mcp_approval::generate_pending_approval(
            "phantom_copy_secret",
            &a,
            "source-project",
        )
        .unwrap();
        let approved = phantom_core::mcp_approval::approve_nonce(&nonce).unwrap();
        let mismatch = phantom_core::mcp_approval::validate_and_consume_approval(
            &nonce,
            &approved.approval_token,
            "phantom_copy_secret",
            &identity_swap,
            "source-project",
        )
        .unwrap_err();
        assert!(mismatch.contains("parameter mismatch"));
        phantom_core::mcp_approval::validate_and_consume_approval(
            &nonce,
            &approved.approval_token,
            "phantom_copy_secret",
            &a,
            "source-project",
        )
        .unwrap();

        unsafe {
            match previous_home {
                Some(value) => std::env::set_var("HOME", value),
                None => std::env::remove_var("HOME"),
            }
        }
    }

    #[test]
    fn team_vault_pull_restores_exact_before_images_on_nth_commit_failure() {
        let dir = TempDir::new().unwrap();
        let config_path = dir.path().join(".phantom.toml");
        let config_before = write_cloud_test_config(&config_path, &cloud_test_config(0));
        let inner = phantom_vault::file::FileVault::new(
            dir.path(),
            "team-pull-nth-failure",
            "passphrase".to_string(),
        )
        .unwrap();
        phantom_vault::VaultBackend::store(&inner, "A", "local-a").unwrap();
        phantom_vault::VaultBackend::store(&inner, "B", "local-b").unwrap();
        let vault = NthCasFailureVault {
            inner,
            fail_at: 2,
            calls: AtomicUsize::new(0),
        };
        let secrets = SensitiveSecretMap::new(std::collections::BTreeMap::from([
            (
                "A".to_string(),
                zeroize::Zeroizing::new("remote-a".to_string()),
            ),
            (
                "B".to_string(),
                zeroize::Zeroizing::new("remote-b".to_string()),
            ),
        ]));

        let error = apply_team_vault_pull_transaction(
            dir.path(),
            &config_path,
            config_before,
            &vault,
            &secrets,
        )
        .expect_err("the second commit must fail and roll back the first");

        assert!(error
            .message
            .contains("exact local config/vault transaction"));
        assert_eq!(
            phantom_vault::VaultBackend::retrieve(&vault, "A")
                .unwrap()
                .as_str(),
            "local-a"
        );
        assert_eq!(
            phantom_vault::VaultBackend::retrieve(&vault, "B")
                .unwrap()
                .as_str(),
            "local-b"
        );
        assert!(!error.message.contains("remote-a"));
        assert!(!error.message.contains("remote-b"));
    }

    #[test]
    fn team_vault_pull_config_drift_rolls_back_every_local_secret_write() {
        let dir = TempDir::new().unwrap();
        let config_path = dir.path().join(".phantom.toml");
        let config_before = write_cloud_test_config(&config_path, &cloud_test_config(0));
        let mut concurrent = config_before.clone();
        concurrent.extend_from_slice(b"\n# concurrent owner\n");
        std::fs::write(&config_path, &concurrent).unwrap();
        let vault = phantom_vault::file::FileVault::new(
            dir.path(),
            "team-pull-config-drift",
            "passphrase".to_string(),
        )
        .unwrap();
        let secrets = SensitiveSecretMap::new(std::collections::BTreeMap::from([(
            "REMOTE".to_string(),
            zeroize::Zeroizing::new("remote-value".to_string()),
        )]));

        let error = apply_team_vault_pull_transaction(
            dir.path(),
            &config_path,
            config_before,
            &vault,
            &secrets,
        )
        .expect_err("config drift must deny the local commit");

        assert!(error
            .message
            .contains("exact local config/vault transaction"));
        assert_eq!(std::fs::read(&config_path).unwrap(), concurrent);
        assert!(matches!(
            vault.retrieve("REMOTE"),
            Err(phantom_core::error::PhantomError::SecretNotFound(_))
        ));
        assert!(!error.message.contains("remote-value"));
    }

    #[test]
    fn cloud_push_remote_success_never_overwrites_concurrent_config() {
        let dir = TempDir::new().unwrap();
        let config_path = dir.path().join(".phantom.toml");
        let mut config = cloud_test_config(2);
        let config_before = write_cloud_test_config(&config_path, &config);
        let mut concurrent = config_before.clone();
        concurrent.extend_from_slice(b"\n# concurrent owner\n");
        std::fs::write(&config_path, &concurrent).unwrap();
        let vault = phantom_vault::file::FileVault::new(
            dir.path(),
            "cloud-push-config-drift",
            "passphrase".to_string(),
        )
        .unwrap();
        let server = PhantomMcpServer::with_dir(dir.path().to_path_buf());

        let error = server
            .save_cloud_version(&vault, &mut config, config_before, 3)
            .expect_err("remote success must not overwrite concurrent local config");

        assert!(error
            .message
            .contains("upload succeeded at remote version 3"));
        assert!(error.message.contains("Do not retry automatically"));
        assert_eq!(std::fs::read(&config_path).unwrap(), concurrent);
    }

    #[test]
    fn alert_approval_origins_never_include_secret_destination_components() {
        use phantom_core::leak_correlation::AlertBackendConfig;

        let config = phantom_core::leak_correlation::AlertingConfig {
            enabled: true,
            min_confidence: 0.7,
            backends: vec![
                AlertBackendConfig::Webhook {
                    url: "https://alerts.example:8443/private/secret-path?token=secret-query"
                        .into(),
                },
                AlertBackendConfig::Slack {
                    url: "https://hooks.slack.com/services/secret/path".into(),
                },
                AlertBackendConfig::PagerDuty {
                    integration_key: "secret-routing-key".into(),
                },
            ],
        };
        let origins = sanitized_alert_origins(&config).unwrap();

        assert_eq!(
            origins,
            vec![
                "webhook:https://alerts.example:8443",
                "slack:https://hooks.slack.com",
                "pagerduty:https://events.pagerduty.com",
            ]
        );
        let rendered = origins.join(" ");
        assert!(!rendered.contains("secret"));
        assert!(!rendered.contains("/services"));
        assert!(!rendered.contains('?'));
    }

    #[test]
    fn cloud_name_digest_rejects_terminal_spoofing_names() {
        assert!(bounded_name_digest(&["SAFE".to_string(), "EVIL\nNAME".to_string()]).is_err());
    }

    #[test]
    fn team_push_approval_binds_config_vault_and_exact_name_set_without_values() {
        let params = TeamVaultParams {
            team_id: "team-safe".to_string(),
            confirm: true,
            approval_token: None,
        };
        let config = cloud_test_config(0);
        let names_a = vec!["ALPHA".to_string(), "BETA".to_string()];
        let names_b = vec!["ALPHA".to_string(), "GAMMA".to_string()];
        let a = team_push_approval_params_json(
            &params,
            "/canonical/project",
            &config,
            b"config-a",
            "file",
            &names_a,
        )
        .unwrap();
        let config_swap = team_push_approval_params_json(
            &params,
            "/canonical/project",
            &config,
            b"config-b",
            "file",
            &names_a,
        )
        .unwrap();
        let backend_swap = team_push_approval_params_json(
            &params,
            "/canonical/project",
            &config,
            b"config-a",
            "keychain",
            &names_a,
        )
        .unwrap();
        let names_swap = team_push_approval_params_json(
            &params,
            "/canonical/project",
            &config,
            b"config-a",
            "file",
            &names_b,
        )
        .unwrap();

        assert_ne!(a, config_swap);
        assert_ne!(a, backend_swap);
        assert_ne!(a, names_swap);
        assert!(!a.contains("secret-value"));
        assert!(!a.contains("approval_token"));
    }

    #[test]
    fn mcp_remap_rejects_a_concurrent_env_change_without_overwriting_it() {
        let dir = TempDir::new().unwrap();
        let env_path = dir.path().join(".env");
        let old = format!("phm_{}", "a".repeat(64));
        std::fs::write(&env_path, format!("TARGET={old}\n")).unwrap();

        let error =
            remap_phantom_tokens_with(dir.path(), &env_path, &["TARGET".to_string()], || {
                std::fs::write(&env_path, b"TARGET=concurrent-owner\n").unwrap();
            })
            .unwrap_err();

        assert!(error.message.contains("changed after it was read"));
        assert_eq!(
            std::fs::read(&env_path).unwrap(),
            b"TARGET=concurrent-owner\n"
        );
    }

    #[cfg(unix)]
    #[test]
    fn mcp_remap_follows_retained_root_across_a_rename_decoy() {
        let container = canonical_temp_dir();
        let project = container.path().join("project");
        let moved = container.path().join("moved");
        std::fs::create_dir(&project).unwrap();
        let env_path = project.join(".env");
        let old = format!("phm_{}", "a".repeat(64));
        std::fs::write(&env_path, format!("TARGET={old}\n")).unwrap();

        remap_phantom_tokens_with(&project, &env_path, &["TARGET".to_string()], || {
            std::fs::rename(&project, &moved).unwrap();
            std::fs::create_dir(&project).unwrap();
            std::fs::write(project.join(".env"), b"TARGET=decoy-owner\n").unwrap();
        })
        .unwrap();

        let moved_env = std::fs::read_to_string(moved.join(".env")).unwrap();
        assert!(moved_env.starts_with("TARGET=phm_"));
        assert!(!moved_env.contains(&old));
        assert_eq!(
            std::fs::read(project.join(".env")).unwrap(),
            b"TARGET=decoy-owner\n"
        );
    }

    #[cfg(unix)]
    #[test]
    fn mcp_managed_dotenv_resolution_uses_the_retained_root_not_a_decoy() {
        let container = canonical_temp_dir();
        let project = container.path().join("project");
        let moved = container.path().join("moved");
        std::fs::create_dir(&project).unwrap();
        let old = format!("phm_{}", "a".repeat(64));
        std::fs::write(project.join(".env"), format!("TARGET={old}\n")).unwrap();
        let mut config = PhantomConfig::new_with_defaults("a".repeat(64));
        config.phantom.dotenv_path = Some(".env".to_string());

        let transaction_lock = phantom_vault::acquire_project_transaction_lock(&project).unwrap();
        std::fs::rename(&project, &moved).unwrap();
        std::fs::create_dir(&project).unwrap();
        std::fs::write(project.join(".env"), b"TARGET=decoy-owner\n").unwrap();

        let env_path = resolve_env_path_anchored(
            &transaction_lock,
            &project,
            &config,
            &["TARGET".to_string()],
        )
        .unwrap();
        remap_phantom_tokens_locked(&transaction_lock, &env_path, &["TARGET".to_string()]).unwrap();

        let moved_env = std::fs::read_to_string(moved.join(".env")).unwrap();
        assert!(moved_env.starts_with("TARGET=phm_"));
        assert!(!moved_env.contains(&old));
        assert_eq!(
            std::fs::read(project.join(".env")).unwrap(),
            b"TARGET=decoy-owner\n"
        );
    }

    #[test]
    fn provider_rotation_backend_failures_are_not_rendered_as_success() {
        let vault = BackendFailureVault::new();

        let read_error = retrieve_optional_secret(&vault, "TARGET", "outgoing credential")
            .expect_err("backend read errors must not be treated as a missing secret");
        assert!(read_error
            .message
            .contains("injected credential read failure"));

        let mut metadata_stages = ProviderRotationStages {
            provider_issued: true,
            vault_committed: "true",
            token_remapped: true,
            ..ProviderRotationStages::default()
        };
        let metadata_error =
            persist_provider_rotation_metadata(&vault, "TARGET", None, &mut metadata_stages)
                .expect_err("metadata persistence errors must prevent a success response");
        assert!(metadata_error
            .message
            .contains("rotation metadata persistence failed"));
        assert!(metadata_error.message.contains("partially succeeded"));
        assert!(metadata_error
            .message
            .contains("Do not retry automatically"));
        assert!(metadata_error
            .message
            .contains("injected metadata write failure"));
        assert!(metadata_error.message.contains(
            r#""provider_issued":true,"vault_committed":"true","token_remapped":true,"metadata_committed":false"#
        ));

        let remap_stages = ProviderRotationStages {
            provider_issued: true,
            vault_committed: "true",
            ..ProviderRotationStages::default()
        };
        let remap_error = provider_rotation_partial_error(
            "TARGET",
            "local Phantom-token remap",
            "injected remap failure",
            &remap_stages,
        );
        assert!(remap_error.message.contains("partially succeeded"));
        assert!(remap_error.message.contains("Do not retry automatically"));
        assert!(remap_error.message.contains("injected remap failure"));
    }

    #[test]
    fn provider_issued_value_uses_exact_cas_and_verifies_storage() {
        let dir = TempDir::new().unwrap();
        let vault = phantom_vault::file::FileVault::new(
            dir.path(),
            "provider-cas-success",
            "passphrase".to_string(),
        )
        .unwrap();
        phantom_vault::VaultBackend::store(&vault, "TARGET", "reviewed-old").unwrap();
        let expected = zeroize::Zeroizing::new("reviewed-old".to_string());
        let mut stages = ProviderRotationStages {
            provider_issued: true,
            ..ProviderRotationStages::default()
        };

        persist_issued_provider_credential(
            &vault,
            "TARGET",
            Some(&expected),
            "provider-issued-new",
            &mut stages,
        )
        .unwrap();
        assert_eq!(stages.vault_committed, "true");

        assert_eq!(
            phantom_vault::VaultBackend::retrieve(&vault, "TARGET")
                .unwrap()
                .as_str(),
            "provider-issued-new"
        );
    }

    #[test]
    fn provider_issued_value_never_overwrites_a_concurrent_local_change() {
        let dir = TempDir::new().unwrap();
        let inner = phantom_vault::file::FileVault::new(
            dir.path(),
            "provider-cas-race",
            "passphrase".to_string(),
        )
        .unwrap();
        phantom_vault::VaultBackend::store(&inner, "TARGET", "reviewed-old").unwrap();
        let vault = ConcurrentCreateVault {
            inner,
            injected: std::sync::atomic::AtomicBool::new(false),
        };
        let expected = zeroize::Zeroizing::new("reviewed-old".to_string());
        let mut stages = ProviderRotationStages {
            provider_issued: true,
            ..ProviderRotationStages::default()
        };

        let error = persist_issued_provider_credential(
            &vault,
            "TARGET",
            Some(&expected),
            "provider-issued-new",
            &mut stages,
        )
        .expect_err("a concurrent local owner must defeat the exact CAS");

        assert!(error.message.contains("partially succeeded"));
        assert!(error.message.contains("changed concurrently"));
        assert!(error
            .message
            .contains("Local and provider state may now differ"));
        assert!(error.message.contains("Do not retry automatically"));
        assert!(!error.message.contains("stored it in the local vault"));
        assert!(!error.message.contains("provider-issued-new"));
        assert!(error.message.contains(r#""vault_committed":"false""#));
        assert_eq!(
            phantom_vault::VaultBackend::retrieve(&vault, "TARGET")
                .unwrap()
                .as_str(),
            "concurrent-owner"
        );
    }

    #[test]
    fn provider_issued_value_reports_backend_cas_failure_as_partial_success() {
        let vault = BackendFailureVault::new();
        let mut stages = ProviderRotationStages {
            provider_issued: true,
            ..ProviderRotationStages::default()
        };
        let error = persist_issued_provider_credential(
            &vault,
            "TARGET",
            None,
            "provider-issued-new",
            &mut stages,
        )
        .expect_err("a backend CAS failure follows provider issuance");

        assert!(error.message.contains("partially succeeded"));
        assert!(error.message.contains("local vault persistence"));
        assert!(error
            .message
            .contains("Local and provider state may now differ"));
        assert!(error.message.contains("Do not retry automatically"));
        assert!(!error.message.contains("stored it in the local vault"));
        assert!(!error.message.contains("provider-issued-new"));
        assert!(error.message.contains(r#""vault_committed":"unknown""#));
        assert_eq!(vault.store_calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn cloud_pull_never_stores_when_overwrite_inspection_fails() {
        let dir = TempDir::new().unwrap();
        let config_path = dir.path().join(".phantom.toml");
        let config = cloud_test_config(3);
        let config_before = write_cloud_test_config(&config_path, &config);
        let vault = BackendFailureVault::new();
        let secrets = SensitiveSecretMap::new(std::collections::BTreeMap::from([(
            "EXISTING".to_string(),
            zeroize::Zeroizing::new("replacement".to_string()),
        )]));

        let error = apply_cloud_pull_transaction(
            dir.path(),
            &config_path,
            &vault,
            &secrets,
            false,
            config_before.clone(),
            config,
            9,
        )
        .expect_err("force=false must fail closed when existence cannot be checked");

        assert!(error.message.contains("local cloud-pull destination"));
        assert!(error.message.contains("injected credential read failure"));
        assert_eq!(vault.store_calls.load(Ordering::SeqCst), 0);
        assert_eq!(std::fs::read(&config_path).unwrap(), config_before);
    }

    #[test]
    fn cloud_pull_never_overwrites_a_concurrent_force_false_create() {
        let dir = TempDir::new().unwrap();
        let config_path = dir.path().join(".phantom.toml");
        let config = cloud_test_config(3);
        let config_before = write_cloud_test_config(&config_path, &config);
        let vault = ConcurrentCreateVault {
            inner: phantom_vault::file::FileVault::new(
                dir.path(),
                "cloud-pull-race",
                "passphrase".to_string(),
            )
            .unwrap(),
            injected: std::sync::atomic::AtomicBool::new(false),
        };
        let secrets = SensitiveSecretMap::new(std::collections::BTreeMap::from([(
            "RACE".to_string(),
            zeroize::Zeroizing::new("cloud-value".to_string()),
        )]));

        let error = apply_cloud_pull_transaction(
            dir.path(),
            &config_path,
            &vault,
            &secrets,
            false,
            config_before.clone(),
            config,
            9,
        )
        .expect_err("a concurrent create must make the exact CAS fail");

        assert!(error.message.contains("state changed concurrently"));
        assert_eq!(
            phantom_vault::VaultBackend::retrieve(&vault, "RACE")
                .unwrap()
                .as_str(),
            "concurrent-owner"
        );
        assert_eq!(std::fs::read(&config_path).unwrap(), config_before);
    }

    #[test]
    fn cloud_pull_mixed_result_preserves_base_and_blocks_push() {
        let dir = TempDir::new().unwrap();
        let config_path = dir.path().join(".phantom.toml");
        let config = cloud_test_config(3);
        let config_before = write_cloud_test_config(&config_path, &config);
        let vault = phantom_vault::file::FileVault::new(
            dir.path(),
            "cloud-mixed",
            "passphrase".to_string(),
        )
        .unwrap();
        phantom_vault::VaultBackend::store(&vault, "EXISTING", "local-owner").unwrap();
        let secrets = SensitiveSecretMap::new(std::collections::BTreeMap::from([
            (
                "EXISTING".to_string(),
                zeroize::Zeroizing::new("remote-existing".to_string()),
            ),
            (
                "NEW".to_string(),
                zeroize::Zeroizing::new("remote-new".to_string()),
            ),
        ]));

        let result = apply_cloud_pull_transaction(
            dir.path(),
            &config_path,
            &vault,
            &secrets,
            false,
            config_before,
            config,
            9,
        )
        .unwrap();

        assert_eq!(result, (1, 1));
        assert_eq!(
            phantom_vault::VaultBackend::retrieve(&vault, "EXISTING")
                .unwrap()
                .as_str(),
            "local-owner"
        );
        assert_eq!(
            phantom_vault::VaultBackend::retrieve(&vault, "NEW")
                .unwrap()
                .as_str(),
            "remote-new"
        );
        let persisted = PhantomConfig::load(&config_path).unwrap();
        let cloud = persisted.cloud.as_ref().unwrap();
        assert_eq!(cloud.version, 3);
        assert!(cloud.reconciliation_required);
        assert_eq!(cloud.reconciliation_remote_version, Some(9));
        assert!(ensure_cloud_push_allowed_mcp(&persisted).is_err());
    }

    #[test]
    fn cloud_pull_all_skipped_preserves_base_and_blocks_push() {
        let dir = TempDir::new().unwrap();
        let config_path = dir.path().join(".phantom.toml");
        let config = cloud_test_config(4);
        let config_before = write_cloud_test_config(&config_path, &config);
        let vault = phantom_vault::file::FileVault::new(
            dir.path(),
            "cloud-all-skipped",
            "passphrase".to_string(),
        )
        .unwrap();
        phantom_vault::VaultBackend::store(&vault, "EXISTING", "local-owner").unwrap();
        let secrets = SensitiveSecretMap::new(std::collections::BTreeMap::from([(
            "EXISTING".to_string(),
            zeroize::Zeroizing::new("remote-existing".to_string()),
        )]));

        assert_eq!(
            apply_cloud_pull_transaction(
                dir.path(),
                &config_path,
                &vault,
                &secrets,
                false,
                config_before,
                config,
                10,
            )
            .unwrap(),
            (0, 1)
        );
        let persisted = PhantomConfig::load(&config_path).unwrap();
        let cloud = persisted.cloud.as_ref().unwrap();
        assert_eq!(cloud.version, 4);
        assert!(cloud.reconciliation_required);
        assert_eq!(cloud.reconciliation_remote_version, Some(10));
        assert!(ensure_cloud_push_allowed_mcp(&persisted).is_err());
    }

    #[test]
    fn complete_cloud_pull_advances_base_and_unblocks_push() {
        let dir = TempDir::new().unwrap();
        let config_path = dir.path().join(".phantom.toml");
        let mut config = cloud_test_config(4);
        let cloud = config.cloud.get_or_insert_default();
        cloud.reconciliation_required = true;
        cloud.reconciliation_remote_version = Some(8);
        let config_before = write_cloud_test_config(&config_path, &config);
        let vault = phantom_vault::file::FileVault::new(
            dir.path(),
            "cloud-complete",
            "passphrase".to_string(),
        )
        .unwrap();
        let secrets = SensitiveSecretMap::new(std::collections::BTreeMap::from([(
            "NEW".to_string(),
            zeroize::Zeroizing::new("remote-new".to_string()),
        )]));

        assert_eq!(
            apply_cloud_pull_transaction(
                dir.path(),
                &config_path,
                &vault,
                &secrets,
                true,
                config_before,
                config,
                11,
            )
            .unwrap(),
            (1, 0)
        );
        let persisted = PhantomConfig::load(&config_path).unwrap();
        let cloud = persisted.cloud.as_ref().unwrap();
        assert_eq!(cloud.version, 11);
        assert!(!cloud.reconciliation_required);
        assert_eq!(cloud.reconciliation_remote_version, None);
        ensure_cloud_push_allowed_mcp(&persisted).unwrap();
    }

    fn canonical_temp_dir() -> TempDir {
        let temp_root = std::env::temp_dir()
            .canonicalize()
            .expect("resolve the platform temporary directory");
        tempfile::Builder::new()
            .prefix("phantom-mcp-test-")
            .tempdir_in(temp_root)
            .expect("create a temporary directory under its canonical root")
    }

    struct TestEnvironment {
        _guard: phantom_core::ProcessEnvGuard,
        previous: [(&'static str, Option<std::ffi::OsString>); 5],
    }

    impl TestEnvironment {
        fn new() -> Self {
            let guard = ENV_LOCK
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let previous = [
                ("HOME", std::env::var_os("HOME")),
                ("USERPROFILE", std::env::var_os("USERPROFILE")),
                (
                    "PHANTOM_VAULT_PASSPHRASE",
                    std::env::var_os("PHANTOM_VAULT_PASSPHRASE"),
                ),
                (
                    "PHANTOM_MCP_SKIP_APPROVAL",
                    std::env::var_os("PHANTOM_MCP_SKIP_APPROVAL"),
                ),
                (
                    "PHANTOM_MCP_EFFECTS",
                    std::env::var_os("PHANTOM_MCP_EFFECTS"),
                ),
            ];
            Self {
                _guard: guard,
                previous,
            }
        }
    }

    impl Drop for TestEnvironment {
        fn drop(&mut self) {
            for (name, value) in &self.previous {
                unsafe {
                    match value {
                        Some(value) => std::env::set_var(name, value),
                        None => std::env::remove_var(name),
                    }
                }
            }
        }
    }

    struct TestHome {
        _dir: TempDir,
        previous: Option<std::ffi::OsString>,
    }

    impl TestHome {
        fn new() -> Self {
            let dir = canonical_temp_dir();
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
    fn managed_dotenv_resolves_configured_custom_file() {
        let _environment = TestEnvironment::new();
        let (server, dir) = setup_initialized_project();
        let config_path = dir.path().join(".phantom.toml");
        let custom_path = dir.path().join("custom.env");
        std::fs::rename(dir.path().join(".env"), &custom_path).unwrap();
        let mut config = PhantomConfig::load(&config_path).unwrap();
        config.phantom.dotenv_path = Some("custom.env".to_string());
        config.save(&config_path).unwrap();

        assert_eq!(server.env_path().unwrap(), custom_path);
    }

    #[test]
    fn doctor_uninitialized_project_uses_default_dotenv_for_diagnostics() {
        let _environment = TestEnvironment::new();
        let (server, _dir) = setup_test_project();
        let result = server
            .phantom_doctor(Parameters(DoctorParams {
                fix: false,
                confirm: false,
                approval_token: None,
            }))
            .unwrap();
        let text = extract_content_text(&result);
        assert!(text.contains("No .phantom.toml found"), "{text}");
        assert!(text.contains("unprotected secret"), "{text}");
    }

    #[test]
    fn status_does_not_open_or_provision_a_vault() {
        let dir = TempDir::new().unwrap();
        let mut config = PhantomConfig::new_with_defaults("status-project".to_string());
        config.phantom.dotenv_path = Some(".env".to_string());
        config.save(&dir.path().join(".phantom.toml")).unwrap();
        std::fs::write(
            dir.path().join(".env"),
            format!("A={}\n", phantom_core::token::PhantomToken::generate()),
        )
        .unwrap();
        let before: std::collections::BTreeSet<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        let server = PhantomMcpServer::with_dir(dir.path().to_path_buf());

        let result = server.phantom_status().unwrap();
        let text = extract_content_text(&result);
        let after: std::collections::BTreeSet<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert!(text.contains("not inspected (read-only status)"), "{text}");
        assert_eq!(before, after);
    }

    #[test]
    fn doctor_without_fix_does_not_open_or_provision_a_vault() {
        let dir = TempDir::new().unwrap();
        let mut config = PhantomConfig::new_with_defaults("doctor-read-only-project".to_string());
        config.phantom.dotenv_path = Some(".env".to_string());
        config.save(&dir.path().join(".phantom.toml")).unwrap();
        std::fs::write(
            dir.path().join(".env"),
            format!("A={}\n", phantom_core::token::PhantomToken::generate()),
        )
        .unwrap();
        let before: std::collections::BTreeSet<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        let server = PhantomMcpServer::with_dir(dir.path().to_path_buf());

        let result = server
            .phantom_doctor(Parameters(DoctorParams {
                fix: false,
                confirm: false,
                approval_token: None,
            }))
            .unwrap();
        let text = extract_content_text(&result);
        let after: std::collections::BTreeSet<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert!(
            text.contains("not opened in read-only doctor mode"),
            "{text}"
        );
        assert_eq!(before, after);
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
        let _environment = TestEnvironment::new();
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

    #[cfg(unix)]
    #[test]
    fn mcp_doctor_fix_rejects_gitignore_symlink_without_touching_target() {
        use std::os::unix::fs::symlink;

        let _environment = TestEnvironment::new();
        let (server, dir) = setup_test_project();
        let victim = dir.path().join("outside-owned-file");
        std::fs::write(&victim, b"owner-content\n").unwrap();
        symlink(&victim, dir.path().join(".gitignore")).unwrap();

        let error = server
            .phantom_doctor(Parameters(DoctorParams {
                fix: true,
                confirm: true,
                approval_token: None,
            }))
            .unwrap_err();

        assert!(error.message.contains("symlink"), "{}", error.message);
        assert_eq!(std::fs::read(victim).unwrap(), b"owner-content\n");
        assert!(!dir.path().join(".env.example").exists());
    }

    #[cfg(unix)]
    #[test]
    fn mcp_doctor_fix_rejects_dangling_example_symlink_without_creating_target() {
        use std::os::unix::fs::symlink;

        let _environment = TestEnvironment::new();
        let (server, dir) = setup_test_project();
        std::fs::write(dir.path().join(".gitignore"), b".env\n").unwrap();
        let victim = dir.path().join("not-yet-created");
        symlink(&victim, dir.path().join(".env.example")).unwrap();

        let error = server
            .phantom_doctor(Parameters(DoctorParams {
                fix: true,
                confirm: true,
                approval_token: None,
            }))
            .unwrap_err();

        assert!(error.message.contains("symlink"), "{}", error.message);
        assert!(!victim.exists());
    }

    #[test]
    fn mcp_doctor_repairs_custom_effective_hook_path() {
        let _environment = TestEnvironment::new();
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
    fn mcp_doctor_cannot_authorize_global_external_hook_write() {
        let _environment = TestEnvironment::new();
        let (server, dir) = setup_test_project();
        let home = dir.path().join("operator-home");
        let external = canonical_temp_dir();
        let hooks = external.path().join("operator-hooks");
        std::fs::create_dir(&home).unwrap();
        std::fs::create_dir(&hooks).unwrap();
        unsafe { std::env::set_var("HOME", &home) };
        unsafe { std::env::set_var("USERPROFILE", &home) };
        assert!(std::process::Command::new("git")
            .args(["config", "--file"])
            .arg(home.join(".gitconfig"))
            .arg("core.hooksPath")
            .arg(&hooks)
            .status()
            .unwrap()
            .success());
        assert!(std::process::Command::new("git")
            .args(["init", "--quiet"])
            .current_dir(dir.path())
            .status()
            .unwrap()
            .success());
        let hook = hooks.join("pre-commit");
        let original = b"#!/bin/sh\necho operator-owned\n";
        std::fs::write(&hook, original).unwrap();

        let error = server
            .phantom_doctor(Parameters(DoctorParams {
                fix: true,
                confirm: true,
                approval_token: None,
            }))
            .unwrap_err();

        assert!(error.message.contains("MCP cannot authorize writes"));
        assert!(error.message.contains("attached trusted terminal"));
        assert_eq!(std::fs::read(hook).unwrap(), original);
    }

    #[test]
    fn mcp_doctor_rejects_legacy_npx_mcp_entry() {
        let _environment = TestEnvironment::new();
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
        let _environment = TestEnvironment::new();
        let (server, _dir) = setup_test_project();
        let result = server.phantom_status().unwrap();
        let text = extract_content_text(&result);
        assert!(text.contains("not initialized"));
    }

    #[test]
    fn test_init_protects_secrets() {
        let _environment = TestEnvironment::new();
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
        let _environment = TestEnvironment::new();
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
        assert!(error.message.contains("safe filename"));
        assert_eq!(std::fs::read(dir.path().join(".env")).unwrap(), original);
        assert!(!dir.path().join(".phantom.toml").exists());
    }

    #[test]
    fn test_init_requires_real_mcp_approval_and_rejects_replay() {
        let _environment = TestEnvironment::new();
        let home = canonical_temp_dir();
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
        let _environment = TestEnvironment::new();
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
        let _environment = TestEnvironment::new();
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
        let _environment = TestEnvironment::new();
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
        let _environment = TestEnvironment::new();
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
        let _environment = TestEnvironment::new();
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
        let _environment = TestEnvironment::new();
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
        let _environment = TestEnvironment::new();
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
        let _environment = TestEnvironment::new();
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
        let _environment = TestEnvironment::new();
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
        let _environment = TestEnvironment::new();
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
        let _environment = TestEnvironment::new();
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
        let _environment = TestEnvironment::new();
        let (server, _dir) = setup_initialized_project();
        let result = server.phantom_status().unwrap();
        let text = get_result_text(&result);
        assert!(text.contains("Vault backend:"));
        assert!(text.contains("Secrets stored:"));
    }

    #[test]
    fn test_add_secret_params_rejects_plaintext_value_field() {
        let _environment = TestEnvironment::new();
        let parsed = serde_json::from_value::<AddSecretParams>(serde_json::json!({
            "name": "NEW_SECRET",
            "value": "new-value-123",
            "confirm": true
        }));
        assert!(parsed.is_err());
    }

    #[test]
    fn test_add_secret_params_schema_omits_value_field() {
        let _environment = TestEnvironment::new();
        let schema = schemars::schema_for!(AddSecretParams);
        let value = serde_json::to_value(schema).unwrap();
        let schema_json = serde_json::to_string(&value).unwrap();
        assert!(schema_json.contains("\"name\""));
        assert!(schema_json.contains("\"confirm\""));
        assert!(!schema_json.contains("\"value\""));
    }

    #[test]
    fn test_destructive_tools_require_confirm() {
        let _environment = TestEnvironment::new();
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
        let _environment = TestEnvironment::new();
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
        let _environment = TestEnvironment::new();
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
        let _environment = TestEnvironment::new();
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
        let _environment = TestEnvironment::new();
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
        let _environment = TestEnvironment::new();
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
        let _environment = TestEnvironment::new();
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
        let _environment = TestEnvironment::new();
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
        let _environment = TestEnvironment::new();
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
        let _environment = TestEnvironment::new();
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
        let _environment = TestEnvironment::new();
        let (server, _dir) = setup_initialized_project();
        let home = canonical_temp_dir();
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
        let _environment = TestEnvironment::new();
        let (server, _dir) = setup_initialized_project();
        let home = canonical_temp_dir();
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
        let _environment = TestEnvironment::new();
        let (server, _dir) = setup_initialized_project();
        let home = canonical_temp_dir();
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
        let _environment = TestEnvironment::new();
        let (server, _dir) = setup_initialized_project();
        let home = canonical_temp_dir();
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
        let _environment = TestEnvironment::new();
        let (server, _dir) = setup_initialized_project();
        let home = canonical_temp_dir();
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
        let _environment = TestEnvironment::new();
        let (server, _dir) = setup_initialized_project();
        let empty_home = canonical_temp_dir();
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
        let _environment = TestEnvironment::new();
        let (server, _dir) = setup_initialized_project();
        let home = canonical_temp_dir();
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
        let _environment = TestEnvironment::new();
        let (server, _dir) = setup_initialized_project();
        let home = canonical_temp_dir();
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
        let _environment = TestEnvironment::new();
        let (server, _dir) = setup_initialized_project();
        let home = canonical_temp_dir();
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
        let _environment = TestEnvironment::new();
        let (server, _dir) = setup_initialized_project();
        // Use a separate isolated HOME so this test sees only its own audit events.
        let home = canonical_temp_dir();
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
        let _environment = TestEnvironment::new();
        let (server, _dir) = setup_initialized_project();
        let home = canonical_temp_dir();
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
        let _environment = TestEnvironment::new();
        let (server, _dir) = setup_initialized_project();
        let home = canonical_temp_dir();
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
        let _environment = TestEnvironment::new();
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
        let _environment = TestEnvironment::new();
        let (server, _dir) = setup_initialized_project();
        let home = canonical_temp_dir();
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
        let _environment = TestEnvironment::new();
        let (server, _dir) = setup_initialized_project();
        let home = canonical_temp_dir();
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
        let _environment = TestEnvironment::new();
        let (server, _dir) = setup_initialized_project();
        let home = canonical_temp_dir();
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
        let _environment = TestEnvironment::new();
        let (server, _dir) = setup_initialized_project();
        let home = canonical_temp_dir();
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
        let _environment = TestEnvironment::new();
        let (server, _dir) = setup_initialized_project();
        let home = canonical_temp_dir();
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
        let _environment = TestEnvironment::new();
        let (server, _dir) = setup_initialized_project();
        let home = canonical_temp_dir();
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
        let _environment = TestEnvironment::new();
        let (server, _dir) = setup_initialized_project();
        let home = canonical_temp_dir();
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
        let _environment = TestEnvironment::new();
        let (server, _dir) = setup_initialized_project();
        let home = canonical_temp_dir();
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
        let _environment = TestEnvironment::new();
        let (server, _dir) = setup_initialized_project();
        let home = canonical_temp_dir();
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
        let _environment = TestEnvironment::new();
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
        let _environment = TestEnvironment::new();
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
        let _environment = TestEnvironment::new();
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
        let _environment = TestEnvironment::new();
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
        let _environment = TestEnvironment::new();
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
        let _environment = TestEnvironment::new();
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
        let _environment = TestEnvironment::new();
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
        let _environment = TestEnvironment::new();
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
        let _environment = TestEnvironment::new();
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
        let _environment = TestEnvironment::new();
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
        let _environment = TestEnvironment::new();
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
        let _environment = TestEnvironment::new();
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
        let _environment = TestEnvironment::new();
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
        let _environment = TestEnvironment::new();
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
        let _environment = TestEnvironment::new();
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
        let _environment = TestEnvironment::new();
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
