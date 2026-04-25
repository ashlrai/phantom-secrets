use phantom_core::config::PhantomConfig;
use phantom_core::dotenv::{classify, is_public_key, DotenvFile, SecretClassification};
use phantom_core::token::{PhantomToken, TokenMap};
use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::*;
use rmcp::{tool, tool_handler, tool_router, ErrorData as McpError, ServerHandler};
use std::path::PathBuf;

use crate::tools::helpers::{internal_err, invalid_params_err, require_confirm, text_result};
use crate::tools::params::{
    AddSecretParams, CheckParams, CloudPullParams, CloudPushParams, CopySecretParams, DoctorParams,
    EnvParams, InitParams, RemoveSecretParams, RotateParams, SyncParams, UnwrapParams, WhyParams,
    WrapParams,
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
        description = "Add a new secret to the Phantom vault. DESTRUCTIVE — overwrites any existing secret of the same name and rewrites .env. Requires `confirm: true`; the agent must ask the user for explicit consent before calling. See the `confirm` parameter docs for the threat model."
    )]
    fn phantom_add_secret(
        &self,
        Parameters(mut params): Parameters<AddSecretParams>,
    ) -> Result<CallToolResult, McpError> {
        require_confirm("phantom_add_secret", params.confirm)?;
        let (_config, vault) = self.load_config_and_vault()?;

        // Zeroize the secret value on all exit paths
        let secret_value = zeroize::Zeroizing::new(std::mem::take(&mut params.value));

        vault
            .store(&params.name, &secret_value)
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
                    + "\n"
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

        text_result(format!(
            "Secret '{}' stored in vault. .env updated with phantom token.",
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

        // Scrub deserialized secrets — serde produced fresh String allocations
        // that the Zeroizing<plaintext> wrapper does not reach.
        for value in secrets.values_mut() {
            zeroize::Zeroize::zeroize(value);
        }
        drop(secrets);

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
        let secret_value = source_vault.retrieve(&params.name).map_err(|e| {
            invalid_params_err(format!("Secret '{}' not found: {e}", params.name))
        })?;

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
        #[allow(unused_variables)] Parameters(params): Parameters<UnwrapParams>,
    ) -> Result<CallToolResult, McpError> {
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
        let env_path = self.env_path();

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
                confirm: true,
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
                confirm: true,
            }))
            .unwrap();
        let remove_text = get_result_text(&remove_result);
        assert!(remove_text.contains("removed"));
    }

    #[test]
    fn test_destructive_tools_require_confirm() {
        let (server, _dir) = setup_initialized_project();

        let add_err = server
            .phantom_add_secret(Parameters(AddSecretParams {
                name: "X".to_string(),
                value: "y".to_string(),
                confirm: false,
            }))
            .unwrap_err();
        assert_eq!(add_err.code, rmcp::model::ErrorCode::INVALID_PARAMS);
        assert!(add_err.message.contains("confirm: true"));

        let rm_err = server
            .phantom_remove_secret(Parameters(RemoveSecretParams {
                name: "OPENAI_API_KEY".to_string(),
                confirm: false,
            }))
            .unwrap_err();
        assert_eq!(rm_err.code, rmcp::model::ErrorCode::INVALID_PARAMS);

        let rotate_err = server
            .phantom_rotate(Parameters(RotateParams { confirm: false }))
            .unwrap_err();
        assert_eq!(rotate_err.code, rmcp::model::ErrorCode::INVALID_PARAMS);
    }

    #[test]
    fn test_copy_secret_rejects_without_confirm() {
        let (server, _dir) = setup_initialized_project();
        let err = server
            .phantom_copy_secret(Parameters(CopySecretParams {
                name: "OPENAI_API_KEY".to_string(),
                target_dir: ".".to_string(),
                rename: None,
                confirm: false,
            }))
            .unwrap_err();
        assert_eq!(err.code, rmcp::model::ErrorCode::INVALID_PARAMS);
        assert!(err.message.contains("confirm"));
    }

    #[test]
    fn test_copy_secret_rejects_dot_dot() {
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
        let (server, _dir) = setup_initialized_project();
        let err = server
            .phantom_copy_secret(Parameters(CopySecretParams {
                name: "OPENAI_API_KEY".to_string(),
                target_dir: "definitely/does/not/exist".to_string(),
                rename: None,
                confirm: true,
            }))
            .unwrap_err();
        assert_eq!(err.code, rmcp::model::ErrorCode::INVALID_PARAMS);
        assert!(err.message.contains("cannot be resolved"));
    }

    #[test]
    fn test_rotate_tokens() {
        let (server, dir) = setup_initialized_project();

        // Read .env before rotation
        let before = std::fs::read_to_string(dir.path().join(".env")).unwrap();

        // Rotate
        let result = server
            .phantom_rotate(Parameters(RotateParams { confirm: true }))
            .unwrap();
        let text = get_result_text(&result);
        assert!(text.contains("Rotated"));

        // Read .env after rotation — tokens should be different
        let after = std::fs::read_to_string(dir.path().join(".env")).unwrap();
        assert_ne!(before, after, "Tokens should change after rotation");
        assert!(after.contains("phm_"));
    }
}
