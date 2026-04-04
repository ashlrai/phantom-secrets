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

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct CloudPullParams {
    /// Overwrite existing local secrets (default: false)
    #[serde(default)]
    pub force: bool,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct CopySecretParams {
    /// Name of the secret to copy from the current project
    pub name: String,
    /// Path to the target project directory (must be phantom-initialized)
    pub target_dir: String,
    /// Optional new name for the secret in the target project
    pub rename: Option<String>,
}

// ── Error helpers ───────────────────────────────────────────────────

fn internal_err(msg: impl Into<String>) -> McpError {
    McpError::new(rmcp::model::ErrorCode::INTERNAL_ERROR, msg.into(), None)
}

fn invalid_params_err(msg: impl Into<String>) -> McpError {
    McpError::new(rmcp::model::ErrorCode::INVALID_PARAMS, msg.into(), None)
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
}

#[tool_router]
impl PhantomMcpServer {
    /// List all secret names stored in the vault. Never returns secret values.
    #[tool(
        description = "List all secret names in the Phantom vault. Returns names only — never exposes actual secret values. Use this to see what secrets are configured."
    )]
    fn phantom_list_secrets(&self) -> Result<CallToolResult, McpError> {
        let config = self.load_config().map_err(internal_err)?;

        let vault = phantom_vault::create_vault(&config.phantom.project_id);
        let names = vault
            .list()
            .map_err(|e| internal_err(format!("Failed to list secrets: {e}")))?;

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

        let config = self.load_config().map_err(internal_err)?;

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

        let dotenv = DotenvFile::parse_file(&env_path)
            .map_err(|e| invalid_params_err(format!("Failed to read {}: {e}", params.env_path)))?;

        let real_entries = dotenv.real_secret_entries();
        if real_entries.is_empty() {
            return Ok(CallToolResult::success(vec![Content::text(
                "No real secrets found in .env (all values are already phantom tokens or non-secret config).",
            )]));
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
        let config = self.load_config().map_err(internal_err)?;

        let vault = phantom_vault::create_vault(&config.phantom.project_id);
        vault
            .store(&params.name, &params.value)
            .map_err(|e| internal_err(format!("Failed to store secret: {e}")))?;

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
        let config = self.load_config().map_err(internal_err)?;

        let vault = phantom_vault::create_vault(&config.phantom.project_id);
        vault
            .delete(&params.name)
            .map_err(|e| internal_err(format!("Failed to remove secret: {e}")))?;

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
        let config = self.load_config().map_err(internal_err)?;

        let vault = phantom_vault::create_vault(&config.phantom.project_id);
        let names = vault
            .list()
            .map_err(|e| internal_err(format!("Failed to list secrets: {e}")))?;

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
            let dotenv = DotenvFile::parse_file(&env_path)
                .map_err(|e| internal_err(format!("Failed to read .env: {e}")))?;
            dotenv
                .write_phantomized(&token_map, &env_path)
                .map_err(|e| internal_err(format!("Failed to rewrite .env: {e}")))?;
        }

        Ok(CallToolResult::success(vec![Content::text(format!(
            "Rotated {} phantom token(s). Old tokens are now invalid.",
            names.len()
        ))]))
    }

    /// Push encrypted vault to Phantom Cloud.
    #[tool(
        description = "Push local vault to Phantom Cloud. Encrypts secrets client-side before upload. Server never sees plaintext. Requires phantom login first."
    )]
    async fn phantom_cloud_push(&self) -> Result<CallToolResult, McpError> {
        use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
        use std::collections::BTreeMap;

        let token = phantom_core::auth::load_token()
            .ok_or_else(|| internal_err("Not logged in. Run `phantom login` first."))?;

        let config = self.load_config().map_err(internal_err)?;

        let vault = phantom_vault::create_vault(&config.phantom.project_id);
        let names = vault
            .list()
            .map_err(|e| internal_err(format!("Failed to list secrets: {e}")))?;

        if names.is_empty() {
            return Ok(CallToolResult::success(vec![Content::text(
                "No secrets to push.",
            )]));
        }

        let mut secrets = BTreeMap::new();
        for name in &names {
            let value = vault
                .retrieve(name)
                .map_err(|e| internal_err(format!("Failed to retrieve secret: {e}")))?;
            secrets.insert(name.clone(), value);
        }

        let plaintext = serde_json::to_string(&secrets)
            .map_err(|e| internal_err(format!("Failed to serialize: {e}")))?;

        let passphrase = phantom_core::auth::get_or_create_cloud_passphrase()
            .map_err(|e| internal_err(format!("Failed to access cloud key: {e}")))?;

        let encrypted = phantom_vault::crypto::encrypt(plaintext.as_bytes(), &passphrase)
            .map_err(|e| internal_err(format!("Encryption failed: {e}")))?;

        let blob_b64 = BASE64.encode(&encrypted);
        let version = config.cloud.as_ref().map(|c| c.version).unwrap_or(0);
        let api_base = phantom_core::auth::api_base_url();

        let new_version = phantom_core::cloud::push(
            &api_base,
            &token,
            &config.phantom.project_id,
            &blob_b64,
            version,
        )
        .await
        .map_err(|e| internal_err(format!("Cloud push failed: {e}")))?;

        // Persist new version to config for optimistic concurrency on next push
        let mut config = config;
        let cloud_config = config.cloud.get_or_insert_default();
        cloud_config.version = new_version;
        let _ = config.save(&self.project_dir.join(".phantom.toml"));

        Ok(CallToolResult::success(vec![Content::text(format!(
            "Pushed {} secret(s) to Phantom Cloud (v{new_version}). End-to-end encrypted.",
            names.len()
        ))]))
    }

    /// Pull vault from Phantom Cloud.
    #[tool(
        description = "Pull vault from Phantom Cloud to local machine. Decrypts client-side. Use force=true to overwrite existing secrets."
    )]
    async fn phantom_cloud_pull(
        &self,
        Parameters(params): Parameters<CloudPullParams>,
    ) -> Result<CallToolResult, McpError> {
        use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
        use std::collections::BTreeMap;

        let token = phantom_core::auth::load_token()
            .ok_or_else(|| internal_err("Not logged in. Run `phantom login` first."))?;

        let config = self.load_config().map_err(internal_err)?;

        let api_base = phantom_core::auth::api_base_url();
        let pull_result = phantom_core::cloud::pull(&api_base, &token, &config.phantom.project_id)
            .await
            .map_err(|e| internal_err(format!("Cloud pull failed: {e}")))?;

        let pull_data = match pull_result {
            Some(data) => data,
            None => {
                return Ok(CallToolResult::success(vec![Content::text(
                    "No cloud vault found for this project. Run phantom_cloud_push first.",
                )]));
            }
        };

        let passphrase = phantom_core::auth::get_or_create_cloud_passphrase()
            .map_err(|e| internal_err(format!("Failed to access cloud key: {e}")))?;

        let encrypted = BASE64
            .decode(&pull_data.encrypted_blob)
            .map_err(|e| internal_err(format!("Invalid cloud data: {e}")))?;

        let plaintext = phantom_vault::crypto::decrypt(&encrypted, &passphrase)
            .map_err(|e| internal_err(format!("Decryption failed: {e}")))?;

        let secrets: BTreeMap<String, String> = serde_json::from_slice(&plaintext)
            .map_err(|e| internal_err(format!("Invalid vault data: {e}")))?;

        let vault = phantom_vault::create_vault(&config.phantom.project_id);
        let mut added = 0;
        let mut skipped = 0;
        for (name, value) in &secrets {
            if !params.force && vault.exists(name).unwrap_or(false) {
                skipped += 1;
                continue;
            }
            vault
                .store(name, value)
                .map_err(|e| internal_err(format!("Failed to store secret: {e}")))?;
            added += 1;
        }

        // Persist new version to config
        let mut config = config;
        let cloud_config = config.cloud.get_or_insert_default();
        cloud_config.version = pull_data.version;
        let _ = config.save(&self.project_dir.join(".phantom.toml"));

        let msg = if skipped > 0 {
            format!("Pulled {added} secret(s), {skipped} skipped (already exist, use force=true to overwrite).")
        } else {
            format!(
                "Pulled {added} secret(s) from Phantom Cloud (v{}).",
                pull_data.version
            )
        };

        Ok(CallToolResult::success(vec![Content::text(msg)]))
    }

    /// Copy a secret to another phantom-initialized project without exposing its value.
    #[tool(
        description = "Copy a secret from this project's vault to another project's vault. The secret value is never exposed — it transfers directly between encrypted vaults. The target project must be phantom-initialized."
    )]
    fn phantom_copy_secret(
        &self,
        Parameters(params): Parameters<CopySecretParams>,
    ) -> Result<CallToolResult, McpError> {
        let config = self.load_config().map_err(internal_err)?;

        let source_vault = phantom_vault::create_vault(&config.phantom.project_id);

        // Retrieve from source — Zeroizing<String> auto-zeroizes on all exit paths
        let secret_value =
            zeroize::Zeroizing::new(source_vault.retrieve(&params.name).map_err(|e| {
                invalid_params_err(format!("Secret '{}' not found: {e}", params.name))
            })?);

        // Resolve target directory
        let target_path = std::path::PathBuf::from(&params.target_dir);
        let target_dir = if target_path.is_relative() {
            self.project_dir.join(&target_path)
        } else {
            target_path
        };

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

        let msg = format!(
            "Copied '{}' -> '{}' in {}. Secret value was never exposed.",
            params.name,
            target_name,
            target_dir.display()
        );
        Ok(CallToolResult::success(vec![Content::text(msg)]))
    }

    /// Check cloud auth and sync status.
    #[tool(description = "Check Phantom Cloud authentication status, plan, and last sync version.")]
    async fn phantom_cloud_status(&self) -> Result<CallToolResult, McpError> {
        let api_base = phantom_core::auth::api_base_url();

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

        Ok(CallToolResult::success(vec![Content::text(format!(
            "{status}{config_status}"
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
                 Use phantom_init to protect secrets in .env files. \
                 Use phantom_cloud_push/pull to sync vaults to Phantom Cloud (E2E encrypted)."
                .to_string(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn setup_test_project() -> (PhantomMcpServer, TempDir) {
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
        let (server, _dir) = setup_test_project();
        let result = server.phantom_status().unwrap();
        let text = get_result_text(&result);
        assert!(text.contains("not initialized"));
    }

    #[test]
    fn test_init_protects_secrets() {
        let (server, dir) = setup_test_project();

        let result = server
            .phantom_init(Parameters(InitParams {
                env_path: ".env".to_string(),
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
        let (server, _dir) = setup_initialized_project();
        let result = server.phantom_status().unwrap();
        let text = get_result_text(&result);
        assert!(text.contains("Vault backend:"));
        assert!(text.contains("Secrets stored:"));
    }

    #[test]
    fn test_add_and_remove_secret() {
        let (server, _dir) = setup_initialized_project();

        // Add a new secret
        let result = server
            .phantom_add_secret(Parameters(AddSecretParams {
                name: "NEW_SECRET".to_string(),
                value: "new-value-123".to_string(),
            }))
            .unwrap();
        let text = get_result_text(&result);
        assert!(text.contains("NEW_SECRET"));
        assert!(text.contains("stored"));

        // Verify it appears in list
        let list_result = server.phantom_list_secrets().unwrap();
        let list_text = get_result_text(&list_result);
        assert!(list_text.contains("NEW_SECRET"));

        // Remove it
        let remove_result = server
            .phantom_remove_secret(Parameters(RemoveSecretParams {
                name: "NEW_SECRET".to_string(),
            }))
            .unwrap();
        let remove_text = get_result_text(&remove_result);
        assert!(remove_text.contains("removed"));
    }

    #[test]
    fn test_rotate_tokens() {
        let (server, dir) = setup_initialized_project();

        // Read .env before rotation
        let before = std::fs::read_to_string(dir.path().join(".env")).unwrap();

        // Rotate
        let result = server.phantom_rotate().unwrap();
        let text = get_result_text(&result);
        assert!(text.contains("Rotated"));

        // Read .env after rotation — tokens should be different
        let after = std::fs::read_to_string(dir.path().join(".env")).unwrap();
        assert_ne!(before, after, "Tokens should change after rotation");
        assert!(after.contains("phm_"));
    }
}
