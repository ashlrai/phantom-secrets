use phantom_core::config::PhantomConfig;
use phantom_core::dotenv::DotenvFile;
use phantom_core::token::{PhantomToken, TokenMap};
use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::*;
use rmcp::{tool, tool_handler, tool_router, ErrorData as McpError, ServerHandler};
use std::path::PathBuf;

// ── Parameter schemas ────────────────────────────────────────────────

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
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct RemoveSecretParams {
    /// Name of the secret to remove
    pub name: String,
}

// ── MCP Server ───────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct PhantomMcpServer {
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
}

#[tool_router]
impl PhantomMcpServer {
    /// List all secret names stored in the vault. Never returns secret values.
    #[tool(
        description = "List all secret names in the Phantom vault. Returns names only — never exposes actual secret values. Use this to see what secrets are configured."
    )]
    fn phantom_list_secrets(&self) -> Result<CallToolResult, McpError> {
        let config = self
            .load_config()
            .map_err(|e| McpError::new(rmcp::model::ErrorCode::INTERNAL_ERROR, e, None))?;

        let vault = phantom_vault::create_vault(&config.phantom.project_id);
        let names = vault.list().map_err(|e| {
            McpError::new(
                rmcp::model::ErrorCode::INTERNAL_ERROR,
                format!("Failed to list secrets: {e}"),
                None,
            )
        })?;

        if names.is_empty() {
            return Ok(CallToolResult::success(vec![Content::text(
                "No secrets stored in vault.",
            )]));
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

        Ok(CallToolResult::success(vec![Content::text(output)]))
    }

    /// Show the current status of Phantom in this project.
    #[tool(
        description = "Show Phantom status: project ID, vault backend, number of secrets, configured services, and proxy state."
    )]
    fn phantom_status(&self) -> Result<CallToolResult, McpError> {
        let config_path = self.config_path();

        if !config_path.exists() {
            return Ok(CallToolResult::success(vec![Content::text(
                "Phantom is not initialized in this directory.\nRun `phantom init` to get started.",
            )]));
        }

        let config = self
            .load_config()
            .map_err(|e| McpError::new(rmcp::model::ErrorCode::INTERNAL_ERROR, e, None))?;

        let vault = phantom_vault::create_vault(&config.phantom.project_id);
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

        Ok(CallToolResult::success(vec![Content::text(output)]))
    }

    /// Initialize Phantom in the current directory.
    #[tool(
        description = "Initialize Phantom: read .env file, store real secrets in the vault, and rewrite .env with phantom tokens. The AI agent will only see phantom tokens after this."
    )]
    fn phantom_init(
        &self,
        Parameters(params): Parameters<InitParams>,
    ) -> Result<CallToolResult, McpError> {
        let env_path = self.project_dir.join(&params.env_path);

        let dotenv = DotenvFile::parse_file(&env_path).map_err(|e| {
            McpError::new(
                rmcp::model::ErrorCode::INVALID_PARAMS,
                format!("Failed to read {}: {e}", params.env_path),
                None,
            )
        })?;

        let real_entries = dotenv.real_secret_entries();
        if real_entries.is_empty() {
            return Ok(CallToolResult::success(vec![Content::text(
                "No real secrets found in .env (all values are already phantom tokens or non-secret config).",
            )]));
        }

        let project_id = PhantomConfig::project_id_from_path(&self.project_dir);
        let config = if self.config_path().exists() {
            PhantomConfig::load(&self.config_path()).map_err(|e| {
                McpError::new(
                    rmcp::model::ErrorCode::INTERNAL_ERROR,
                    format!("Config error: {e}"),
                    None,
                )
            })?
        } else {
            PhantomConfig::new_with_defaults(project_id.clone())
        };

        let vault = phantom_vault::create_vault(&config.phantom.project_id);

        let mut token_map = TokenMap::new();
        let mut stored = Vec::new();
        for entry in &real_entries {
            token_map.insert(entry.key.clone());
            vault.store(&entry.key, &entry.value).map_err(|e| {
                McpError::new(
                    rmcp::model::ErrorCode::INTERNAL_ERROR,
                    format!("Failed to store {}: {e}", entry.key),
                    None,
                )
            })?;
            stored.push(entry.key.clone());
        }

        dotenv
            .write_phantomized(&token_map, &env_path)
            .map_err(|e| {
                McpError::new(
                    rmcp::model::ErrorCode::INTERNAL_ERROR,
                    format!("Failed to rewrite .env: {e}"),
                    None,
                )
            })?;

        config.save(&self.config_path()).map_err(|e| {
            McpError::new(
                rmcp::model::ErrorCode::INTERNAL_ERROR,
                format!("Failed to save config: {e}"),
                None,
            )
        })?;

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

        Ok(CallToolResult::success(vec![Content::text(output)]))
    }

    /// Add a secret to the vault.
    #[tool(
        description = "Add a new secret to the Phantom vault. The secret is stored securely and never exposed to AI agents."
    )]
    fn phantom_add_secret(
        &self,
        Parameters(params): Parameters<AddSecretParams>,
    ) -> Result<CallToolResult, McpError> {
        let config = self
            .load_config()
            .map_err(|e| McpError::new(rmcp::model::ErrorCode::INTERNAL_ERROR, e, None))?;

        let vault = phantom_vault::create_vault(&config.phantom.project_id);
        vault.store(&params.name, &params.value).map_err(|e| {
            McpError::new(
                rmcp::model::ErrorCode::INTERNAL_ERROR,
                format!("Failed to store secret: {e}"),
                None,
            )
        })?;

        // Update .env with phantom token if it exists
        let env_path = self.env_path();
        if env_path.exists() {
            let token = PhantomToken::generate();
            let content = std::fs::read_to_string(&env_path).unwrap_or_default();

            let new_content = if content
                .lines()
                .any(|l| l.trim().starts_with(&format!("{}=", params.name)))
            {
                content
                    .lines()
                    .map(|line| {
                        if line.trim().starts_with(&format!("{}=", params.name)) {
                            format!("{}={}", params.name, token)
                        } else {
                            line.to_string()
                        }
                    })
                    .collect::<Vec<_>>()
                    .join("\n")
            } else {
                let mut c = content;
                if !c.is_empty() && !c.ends_with('\n') {
                    c.push('\n');
                }
                c.push_str(&format!("{}={}\n", params.name, token));
                c
            };
            let _ = std::fs::write(&env_path, new_content);
        }

        Ok(CallToolResult::success(vec![Content::text(format!(
            "Secret '{}' stored in vault. .env updated with phantom token.",
            params.name
        ))]))
    }

    /// Remove a secret from the vault.
    #[tool(description = "Remove a secret from the Phantom vault by name.")]
    fn phantom_remove_secret(
        &self,
        Parameters(params): Parameters<RemoveSecretParams>,
    ) -> Result<CallToolResult, McpError> {
        let config = self
            .load_config()
            .map_err(|e| McpError::new(rmcp::model::ErrorCode::INTERNAL_ERROR, e, None))?;

        let vault = phantom_vault::create_vault(&config.phantom.project_id);
        vault.delete(&params.name).map_err(|e| {
            McpError::new(
                rmcp::model::ErrorCode::INTERNAL_ERROR,
                format!("Failed to remove secret: {e}"),
                None,
            )
        })?;

        Ok(CallToolResult::success(vec![Content::text(format!(
            "Secret '{}' removed from vault.",
            params.name
        ))]))
    }

    /// Rotate all phantom tokens.
    #[tool(
        description = "Regenerate all phantom tokens in .env. Old tokens become invalid. Real secrets in the vault are unchanged."
    )]
    fn phantom_rotate(&self) -> Result<CallToolResult, McpError> {
        let config = self
            .load_config()
            .map_err(|e| McpError::new(rmcp::model::ErrorCode::INTERNAL_ERROR, e, None))?;

        let vault = phantom_vault::create_vault(&config.phantom.project_id);
        let names = vault.list().map_err(|e| {
            McpError::new(
                rmcp::model::ErrorCode::INTERNAL_ERROR,
                format!("Failed to list secrets: {e}"),
                None,
            )
        })?;

        if names.is_empty() {
            return Ok(CallToolResult::success(vec![Content::text(
                "No secrets to rotate.",
            )]));
        }

        let mut token_map = TokenMap::new();
        for name in &names {
            token_map.insert(name.clone());
        }

        let env_path = self.env_path();
        if env_path.exists() {
            let dotenv = DotenvFile::parse_file(&env_path).map_err(|e| {
                McpError::new(
                    rmcp::model::ErrorCode::INTERNAL_ERROR,
                    format!("Failed to read .env: {e}"),
                    None,
                )
            })?;
            dotenv
                .write_phantomized(&token_map, &env_path)
                .map_err(|e| {
                    McpError::new(
                        rmcp::model::ErrorCode::INTERNAL_ERROR,
                        format!("Failed to rewrite .env: {e}"),
                        None,
                    )
                })?;
        }

        Ok(CallToolResult::success(vec![Content::text(format!(
            "Rotated {} phantom token(s). Old tokens are now invalid.",
            names.len()
        ))]))
    }
}

#[tool_handler]
impl ServerHandler for PhantomMcpServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build()).with_instructions(
            "Phantom Secrets manager. Securely manages API keys and secrets. \
                 Use phantom_list_secrets to see what's stored (never shows values). \
                 Use phantom_status to check configuration. \
                 Use phantom_init to protect secrets in .env files."
                .to_string(),
        )
    }
}
