use anyhow::{Context, Result};
use colored::Colorize;
use phantom_core::config::PhantomConfig;
use phantom_core::dotenv::DotenvFile;
use phantom_core::env_scope::DEFAULT_ENV;
use phantom_core::token::PhantomToken;
use phantom_proxy::{Interceptor, ProxyConfig, ProxyServer, ServiceRegistry};
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::process::Stdio;

const VAULT_PASSPHRASE_ENV: &str = "PHANTOM_VAULT_PASSPHRASE";

fn header_auth_only() -> bool {
    matches!(
        std::env::var("PHANTOM_PROXY_HEADER_AUTH_ONLY")
            .ok()
            .as_deref(),
        Some("1" | "true" | "TRUE" | "yes" | "YES")
    )
}

pub fn run(cmd: &[String], env: Option<&str>) -> Result<()> {
    if cmd.is_empty() {
        anyhow::bail!("No command specified. Usage: phantom exec -- <command>");
    }

    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(run_async(cmd, env))
}

async fn run_async(cmd: &[String], env_flag: Option<&str>) -> Result<()> {
    let project_dir = std::env::current_dir()?;
    let config_path = project_dir.join(".phantom.toml");

    if !config_path.exists() {
        anyhow::bail!(
            "No .phantom.toml found. Run {} first.",
            "phantom init".cyan().bold()
        );
    }

    let config = PhantomConfig::load(&config_path).context("Failed to load .phantom.toml")?;
    config
        .validate_agentic_proxy_routes()
        .context("Refusing unapproved repository-controlled proxy routing")?;

    let preflight = phantom_core::managed_dotenv::resolve_dotenv(&project_dir, &config, &[])?;
    if let Some(dotenv) = preflight.file.as_ref() {
        dotenv
            .validate_for_mutation()
            .context("Managed dotenv is malformed; child launch stopped before vault access")?;
    }
    let preflight_protected_keys: HashSet<String> = preflight
        .file
        .iter()
        .flat_map(DotenvFile::entries)
        .filter(|entry| PhantomToken::is_phantom_token(&entry.value))
        .map(|entry| entry.key.clone())
        .collect();

    // Connection strings need a protocol-aware broker. Detect them from the
    // protected dotenv/config contract before opening or reading the vault, so
    // a missing entry can never turn this fail-closed decision into a bypass.
    let blocked_connection_strings: Vec<&str> = config
        .connection_string_services()
        .into_iter()
        .filter_map(|(_, service)| {
            (preflight_protected_keys.contains(&service.secret_key)
                || std::env::var_os(&service.secret_key).is_some())
            .then_some(service.secret_key.as_str())
        })
        .collect();
    if !blocked_connection_strings.is_empty() {
        anyhow::bail!(
            "Refusing to expose connection-string secret(s) to the child process: {}. Phantom requires a protocol-aware broker for database credentials; direct environment injection is disabled.",
            blocked_connection_strings.join(", ")
        );
    }

    let vault = phantom_vault::try_create_vault(config.local_project_id())?;
    let vault_names = vault
        .list()
        .context("Failed to list protected vault entries before child launch")?;
    let resolved =
        phantom_core::managed_dotenv::resolve_dotenv(&project_dir, &config, &vault_names)?;
    if let Some(dotenv) = resolved.file.as_ref() {
        dotenv
            .validate_for_mutation()
            .context("Managed dotenv is malformed; child launch stopped before proxy startup")?;
    }
    let active_env = crate::commands::env_scope::effective_env(&project_dir, env_flag);
    let dotenv = resolved.file;
    let protected_env_keys: HashSet<String> = dotenv
        .iter()
        .flat_map(DotenvFile::entries)
        .filter(|entry| PhantomToken::is_phantom_token(&entry.value))
        .map(|entry| entry.key.clone())
        .collect();

    let (child_scrub_env, never_reintroduce) =
        child_environment_policy(&config, &protected_env_keys);

    if protected_env_keys.is_empty() {
        eprintln!(
            "{} No phantom tokens found to proxy. Running command directly with Phantom internal credentials removed.",
            "warn".yellow()
        );
        return run_command_directly(cmd, &child_scrub_env).await;
    }

    // Session-scoped token rotation:
    // Instead of using the persistent phantom tokens from .env directly,
    // we generate FRESH session tokens for this exec session.
    // If a session token leaks (from logs, AI context, etc.), it becomes
    // worthless as soon as this exec session ends.
    let mut session_token_to_secret: HashMap<String, (String, String)> = HashMap::new();
    let mut secret_name_to_value: HashMap<String, String> = HashMap::new();
    let mut env_key_to_session_token: HashMap<String, String> = HashMap::new();
    let mut secret_count = 0;

    if let Some(dotenv) = dotenv.as_ref() {
        for entry in dotenv.entries() {
            if PhantomToken::is_phantom_token(&entry.value) {
                // Build the vault key for this env: try namespaced first, then bare (legacy).
                // Backend errors are distinct from a missing key and must abort
                // before a partially mapped proxy session can start.
                let namespaced = phantom_core::env_scope::namespaced_key(&active_env, &entry.key);
                let real_value =
                    retrieve_required_secret(vault.as_ref(), &namespaced, &entry.key, &active_env)?;

                // Generate a fresh session token for this secret.
                let session_token = PhantomToken::generate();
                session_token_to_secret.insert(
                    session_token.as_str().to_string(),
                    (entry.key.clone(), String::from(real_value.as_str())),
                );
                secret_name_to_value.insert(entry.key.clone(), String::from(real_value.as_str()));
                if !never_reintroduce.contains(&entry.key) {
                    env_key_to_session_token
                        .insert(entry.key.clone(), session_token.as_str().to_string());
                }
                secret_count += 1;
            }
        }
    }

    // Build service registry from config
    let registry = ServiceRegistry::from_config(&config.services);
    let interceptor = Interceptor::new_scoped(session_token_to_secret, secret_name_to_value);

    println!(
        "{} Starting proxy with {} secret(s) (session-scoped tokens, env: {})...",
        "->".blue().bold(),
        secret_count,
        active_env.cyan()
    );

    // Generate proxy session token
    let proxy_token = ProxyServer::generate_proxy_token();
    let header_auth_only = header_auth_only();
    let allow_query_token_auth = !header_auth_only;

    // Start the proxy
    let proxy = ProxyServer::start(
        ProxyConfig {
            port: 0,
            proxy_token: proxy_token.clone(),
            allow_query_token_auth,
            ..ProxyConfig::default()
        },
        registry.clone(),
        interceptor,
    )
    .await
    .map_err(|e| anyhow::anyhow!("Failed to start proxy: {e}"))?;

    let port = proxy.port();
    println!(
        "{} Proxy running on {}",
        "ok".green().bold(),
        format!("127.0.0.1:{port}").cyan()
    );

    // Print service routes
    let overrides = if header_auth_only {
        registry.base_url_overrides(port)
    } else {
        registry.base_url_overrides_with_token(port, Some(&proxy_token))
    };
    for (env_var, url) in &overrides {
        println!("   {} {} = {}", "->".dimmed(), env_var.bold(), url.cyan());
    }
    if header_auth_only {
        println!(
            "   {} {} set for child process",
            "->".dimmed(),
            "PHANTOM_PROXY_TOKEN".bold()
        );
    } else {
        println!(
            "   {} SDK-compatible proxy URLs include a session token; set {} for header-only mode",
            "->".dimmed(),
            "PHANTOM_PROXY_HEADER_AUTH_ONLY=1".bold()
        );
    }

    // --- Framework auto-detection ---
    let mut framework_env_vars: Vec<(String, String)> = Vec::new();
    let package_json_path = project_dir.join("package.json");
    let is_node_project = package_json_path.exists();

    if is_node_project {
        println!("   {} Detected Node.js project", "->".dimmed(),);

        // Detect Next.js: check if the command starts with "next" or package.json
        // lists "next" as a dependency
        let is_nextjs = cmd[0] == "next"
            || (cmd[0] == "npx" && cmd.get(1) == Some(&"next".to_string()))
            || detect_next_dependency(&package_json_path);

        if is_nextjs {
            println!("   {} Detected Next.js framework", "->".dimmed(),);

            // Pass through NEXT_PUBLIC_ prefixed vars from .env unchanged —
            // these are non-secret public vars that the Next.js build expects
            if let Some(dotenv) = dotenv.as_ref() {
                for entry in dotenv.entries() {
                    if entry.key.starts_with("NEXT_PUBLIC_")
                        && !PhantomToken::is_phantom_token(&entry.value)
                        && !never_reintroduce.contains(&entry.key)
                    {
                        framework_env_vars.push((entry.key.clone(), entry.value.clone()));
                    }
                }
            }

            if !framework_env_vars.is_empty() {
                println!(
                    "   {} Passing through {} NEXT_PUBLIC_ env var(s)",
                    "->".dimmed(),
                    framework_env_vars.len(),
                );
            }
        }
    }

    // Summary: proxied secrets vs injected env vars
    let injected_count = framework_env_vars.len();
    println!(
        "\n{} {} secret(s) proxied, {} env var(s) injected directly",
        "->".blue().bold(),
        secret_count,
        injected_count,
    );

    println!(
        "{} Launching: {}\n",
        "->".blue().bold(),
        cmd.join(" ").cyan().bold()
    );

    // Spawn the child process with proxy env vars
    let program = &cmd[0];
    let args = &cmd[1..];

    let mut command = sanitized_child_command(program, args, &child_scrub_env);
    command
        .envs(overrides.iter().map(|(k, v)| (k.as_str(), v.as_str())))
        .envs(
            env_key_to_session_token
                .iter()
                .map(|(k, v)| (k.as_str(), v.as_str())),
        )
        .envs(
            framework_env_vars
                .iter()
                .map(|(k, v)| (k.as_str(), v.as_str())),
        )
        .env("PHANTOM_PROXY_PORT", port.to_string())
        .env("PHANTOM_PROXY_TOKEN", &proxy_token)
        // A protected dotenv key may itself have this reserved name. Never
        // reintroduce either the real vault passphrase or a confusing session
        // token under Phantom's internal decryption-key variable.
        .env_remove(VAULT_PASSPHRASE_ENV)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    let mut child = command
        .spawn()
        .context(format!("Failed to start command: {}", program))?;

    // Wait for the child to exit
    let status = child.wait().await?;

    // Shut down the proxy — session tokens are now invalid
    println!("\n{} Shutting down proxy...", "->".blue().bold());
    proxy.shutdown().await;

    if !status.success() {
        let code = status.code().unwrap_or(1);
        println!("{} Command exited with code {}", "!".yellow().bold(), code);
        std::process::exit(code);
    }

    println!("{} Done.", "ok".green().bold());
    Ok(())
}

fn retrieve_required_secret(
    vault: &dyn phantom_vault::VaultBackend,
    namespaced: &str,
    bare: &str,
    active_env: &str,
) -> Result<zeroize::Zeroizing<String>> {
    match vault.retrieve_for_injection(namespaced) {
        Ok(value) => Ok(value),
        Err(phantom_core::error::PhantomError::SecretNotFound(_))
            if active_env == DEFAULT_ENV =>
        {
            vault
                .retrieve_for_injection(bare)
                .map_err(|error| match error {
                phantom_core::error::PhantomError::SecretNotFound(_) => anyhow::anyhow!(
                    "Protected dotenv key '{bare}' has no vault entry for environment '{active_env}'; refusing to launch the child"
                ),
                other => anyhow::anyhow!(
                    "Failed to read legacy session secret '{bare}' from the vault: {other}"
                ),
                })
        }
        Err(phantom_core::error::PhantomError::SecretNotFound(_)) => Err(anyhow::anyhow!(
            "Protected dotenv key '{bare}' has no vault entry for environment '{active_env}'; refusing to launch the child"
        )),
        Err(error) => Err(anyhow::anyhow!(
            "Failed to read namespaced session secret '{namespaced}' from the vault: {error}"
        )),
    }
}

fn sanitized_child_command(
    program: &str,
    args: &[String],
    scrub_env_keys: &HashSet<String>,
) -> tokio::process::Command {
    let mut command = tokio::process::Command::new(program);
    command.args(args);
    for key in scrub_env_keys {
        command.env_remove(key);
    }
    command
}

fn child_environment_policy(
    config: &PhantomConfig,
    protected_env_keys: &HashSet<String>,
) -> (HashSet<String>, HashSet<String>) {
    let mut scrub = protected_env_keys.clone();
    scrub.extend([
        VAULT_PASSPHRASE_ENV.to_string(),
        "PHANTOM_PROXY_TOKEN".to_string(),
        "PHANTOM_PROXY_PORT".to_string(),
    ]);
    scrub.extend(
        ServiceRegistry::known_override_env_names()
            .iter()
            .map(|name| (*name).to_string()),
    );

    let registry = ServiceRegistry::from_config(&config.services);
    scrub.extend(
        registry
            .base_url_overrides(0)
            .into_iter()
            .map(|(name, _)| name),
    );
    scrub.extend(
        config
            .services
            .values()
            .map(|service| service.secret_key.clone()),
    );

    let mut never_reintroduce = HashSet::new();
    for (_, service) in config.connection_string_services() {
        never_reintroduce.insert(service.secret_key.clone());
    }
    for secret in config.phantom.secrets.values() {
        if let Some(name) = secret
            .rotation_provider
            .as_ref()
            .and_then(|provider| provider.api_key_env.as_ref())
        {
            never_reintroduce.insert(name.clone());
        }
    }
    never_reintroduce.extend(config.sync.iter().map(|target| target.token_env.clone()));
    scrub.extend(never_reintroduce.iter().cloned());
    (scrub, never_reintroduce)
}

/// Check if `package.json` lists `next` as a dependency or devDependency.
/// Uses a lightweight string search to avoid pulling in a JSON parser.
fn detect_next_dependency(package_json: &Path) -> bool {
    let Ok(contents) = std::fs::read_to_string(package_json) else {
        return false;
    };
    // Look for "next" as a key in dependencies or devDependencies.
    // A proper JSON parse would be more robust, but this is intentionally
    // lightweight — we only need a heuristic for framework detection.
    contents.contains("\"next\"")
}

async fn run_command_directly(cmd: &[String], scrub_env_keys: &HashSet<String>) -> Result<()> {
    let program = &cmd[0];
    let args = &cmd[1..];

    let mut command = sanitized_child_command(program, args, scrub_env_keys);
    let status = command
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .await
        .context(format!("Failed to start command: {}", program))?;

    if !status.success() {
        std::process::exit(status.code().unwrap_or(1));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use phantom_core::error::{PhantomError, Result as PhantomResult};
    use zeroize::Zeroizing;

    struct ReadFailingVault;
    struct MissingVault;

    impl phantom_vault::VaultBackend for ReadFailingVault {
        fn store(&self, _name: &str, _value: &str) -> PhantomResult<()> {
            Ok(())
        }

        fn retrieve(&self, _name: &str) -> PhantomResult<Zeroizing<String>> {
            Err(PhantomError::VaultError(
                "injected session credential read failure".to_string(),
            ))
        }

        fn delete(&self, _name: &str) -> PhantomResult<()> {
            Ok(())
        }

        fn list(&self) -> PhantomResult<Vec<String>> {
            Ok(Vec::new())
        }

        fn backend_name(&self) -> &str {
            "read-failing"
        }
    }

    impl phantom_vault::VaultBackend for MissingVault {
        fn store(&self, _name: &str, _value: &str) -> PhantomResult<()> {
            Ok(())
        }

        fn retrieve(&self, name: &str) -> PhantomResult<Zeroizing<String>> {
            Err(PhantomError::SecretNotFound(name.to_string()))
        }

        fn delete(&self, _name: &str) -> PhantomResult<()> {
            Ok(())
        }

        fn list(&self) -> PhantomResult<Vec<String>> {
            Ok(Vec::new())
        }

        fn backend_name(&self) -> &str {
            "missing"
        }
    }

    #[test]
    fn exec_propagates_vault_read_errors_before_starting_a_session() {
        let error = retrieve_required_secret(
            &ReadFailingVault,
            "production/API_KEY",
            "API_KEY",
            "production",
        )
        .expect_err("backend error must not be treated as an absent mapping");

        assert!(error
            .to_string()
            .contains("Failed to read namespaced session secret"));
        assert!(error
            .to_string()
            .contains("injected session credential read failure"));
    }

    #[test]
    fn exec_rejects_a_missing_protected_vault_entry() {
        let error =
            retrieve_required_secret(&MissingVault, "default/API_KEY", "API_KEY", DEFAULT_ENV)
                .unwrap_err()
                .to_string();

        assert!(error.contains("has no vault entry"));
        assert!(error.contains("refusing to launch the child"));
    }

    #[test]
    fn child_command_removes_vault_passphrase_and_protected_ambient_values() {
        let protected = HashSet::from(["API_KEY".to_string(), "DATABASE_URL".to_string()]);
        let mut config = PhantomConfig::new_with_defaults("a".repeat(64));
        let override_config = phantom_core::config::SecretOverride {
            rotation_provider: Some(phantom_core::rotation_provider::RotationProviderConfig {
                provider: "stripe".to_string(),
                api_key_env: Some("ROTATION_ADMIN_TOKEN".to_string()),
                ..Default::default()
            }),
            ..Default::default()
        };
        config
            .phantom
            .secrets
            .insert("API_KEY".to_string(), override_config);
        config.sync.push(phantom_core::sync::SyncTarget {
            platform: phantom_core::sync::Platform::Vercel,
            token_env: "DEPLOY_TOKEN".to_string(),
            project_id: "project".to_string(),
            targets: vec![],
            service_id: None,
            environment_id: None,
            only: vec![],
        });
        let (scrub, never) = child_environment_policy(&config, &protected);
        let command = sanitized_child_command("phantom-child", &[], &scrub);
        let explicit: HashMap<String, Option<String>> = command
            .as_std()
            .get_envs()
            .map(|(key, value)| {
                (
                    key.to_string_lossy().into_owned(),
                    value.map(|value| value.to_string_lossy().into_owned()),
                )
            })
            .collect();

        assert_eq!(explicit.get(VAULT_PASSPHRASE_ENV), Some(&None));
        assert_eq!(explicit.get("API_KEY"), Some(&None));
        assert_eq!(explicit.get("DATABASE_URL"), Some(&None));
        for name in [
            "PHANTOM_PROXY_TOKEN",
            "PHANTOM_PROXY_PORT",
            "OPENAI_BASE_URL",
            "OPENAI_API_KEY",
            "ROTATION_ADMIN_TOKEN",
            "DEPLOY_TOKEN",
        ] {
            assert_eq!(explicit.get(name), Some(&None), "{name} was not scrubbed");
        }
        assert!(never.contains("DATABASE_URL"));
        assert!(never.contains("ROTATION_ADMIN_TOKEN"));
        assert!(never.contains("DEPLOY_TOKEN"));
    }
}
