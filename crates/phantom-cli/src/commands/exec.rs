use anyhow::{Context, Result};
use colored::Colorize;
use phantom_core::config::PhantomConfig;
use phantom_core::dotenv::DotenvFile;
use phantom_core::token::PhantomToken;
use phantom_proxy::{Interceptor, ProxyConfig, ProxyServer, ServiceRegistry};
use std::collections::HashMap;
use std::path::Path;
use std::process::Stdio;

pub fn run(cmd: &[String]) -> Result<()> {
    if cmd.is_empty() {
        anyhow::bail!("No command specified. Usage: phantom exec -- <command>");
    }

    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(run_async(cmd))
}

async fn run_async(cmd: &[String]) -> Result<()> {
    let project_dir = std::env::current_dir()?;
    let config_path = project_dir.join(".phantom.toml");
    let env_path = project_dir.join(".env");

    if !config_path.exists() {
        anyhow::bail!(
            "No .phantom.toml found. Run {} first.",
            "phantom init".cyan().bold()
        );
    }

    let config = PhantomConfig::load(&config_path).context("Failed to load .phantom.toml")?;
    let vault = phantom_vault::create_vault(&config.phantom.project_id);

    // Session-scoped token rotation:
    // Instead of using the persistent phantom tokens from .env directly,
    // we generate FRESH session tokens for this exec session.
    // If a session token leaks (from logs, AI context, etc.), it becomes
    // worthless as soon as this exec session ends.
    let mut session_token_to_secret: HashMap<String, String> = HashMap::new();
    let mut env_key_to_session_token: HashMap<String, String> = HashMap::new();
    let mut secret_count = 0;

    if env_path.exists() {
        let dotenv = DotenvFile::parse_file(&env_path).context("Failed to read .env")?;

        for entry in dotenv.entries() {
            if PhantomToken::is_phantom_token(&entry.value) {
                match vault.retrieve(&entry.key) {
                    Ok(real_value) => {
                        // Generate a fresh session token for this secret
                        let session_token = PhantomToken::generate();
                        session_token_to_secret
                            .insert(session_token.as_str().to_string(), real_value);
                        env_key_to_session_token
                            .insert(entry.key.clone(), session_token.as_str().to_string());
                        secret_count += 1;
                    }
                    Err(_) => {
                        eprintln!(
                            "{} No vault entry for {} (phantom token in .env but not in vault)",
                            "warn".yellow(),
                            entry.key
                        );
                    }
                }
            }
        }
    }

    if session_token_to_secret.is_empty() {
        eprintln!(
            "{} No phantom tokens found to proxy. Running command directly.",
            "warn".yellow()
        );
        return run_command_directly(cmd).await;
    }

    // Build service registry from config
    let registry = ServiceRegistry::from_config(&config.services);
    let interceptor = Interceptor::new(session_token_to_secret);

    println!(
        "{} Starting proxy with {} secret(s) (session-scoped tokens)...",
        "->".blue().bold(),
        secret_count
    );

    // Generate proxy session token
    let proxy_token = ProxyServer::generate_proxy_token();

    // Start the proxy
    let proxy = ProxyServer::start(
        ProxyConfig {
            port: 0,
            proxy_token: proxy_token.clone(),
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
    let overrides = registry.base_url_overrides_with_token(port, Some(&proxy_token));
    for (env_var, url) in &overrides {
        println!("   {} {} = {}", "->".dimmed(), env_var.bold(), url.cyan());
    }

    // Inject connection string secrets as env vars (with real values, not proxied)
    let conn_services = config.connection_string_services();
    let mut conn_env_vars: Vec<(String, String)> = Vec::new();
    for (_name, svc) in &conn_services {
        if let Ok(real_value) = vault.retrieve(&svc.secret_key) {
            conn_env_vars.push((svc.secret_key.clone(), real_value));
            println!(
                "   {} {} (injected as env var)",
                "->".dimmed(),
                svc.secret_key.bold()
            );
        }
    }

    // --- Framework auto-detection ---
    let mut framework_env_vars: Vec<(String, String)> = Vec::new();
    let package_json_path = project_dir.join("package.json");
    let is_node_project = package_json_path.exists();

    if is_node_project {
        println!("   {} Detected Node.js project", "->".dimmed(),);

        // Detect Next.js: check if the command starts with "next" or package.json
        // lists "next" as a dependency
        let is_nextjs = cmd[0].starts_with("next")
            || cmd.iter().any(|arg| arg.contains("next"))
            || detect_next_dependency(&package_json_path);

        if is_nextjs {
            println!("   {} Detected Next.js framework", "->".dimmed(),);

            // Pass through NEXT_PUBLIC_ prefixed vars from .env unchanged —
            // these are non-secret public vars that the Next.js build expects
            if env_path.exists() {
                if let Ok(dotenv) = DotenvFile::parse_file(&env_path) {
                    for entry in dotenv.entries() {
                        if entry.key.starts_with("NEXT_PUBLIC_")
                            && !PhantomToken::is_phantom_token(&entry.value)
                        {
                            framework_env_vars.push((entry.key.clone(), entry.value.clone()));
                        }
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

    // Override .env vars with session tokens for the subprocess
    // This way the subprocess sees session tokens (not the persistent ones),
    // and the proxy maps session tokens to real secrets
    let mut session_env_overrides: Vec<(String, String)> = Vec::new();
    for (key, session_token) in &env_key_to_session_token {
        session_env_overrides.push((key.clone(), session_token.clone()));
    }

    // Summary: proxied secrets vs injected env vars
    let injected_count = conn_env_vars.len() + framework_env_vars.len();
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

    let mut child = tokio::process::Command::new(program)
        .args(args)
        .envs(overrides.iter().map(|(k, v)| (k.as_str(), v.as_str())))
        .envs(conn_env_vars.iter().map(|(k, v)| (k.as_str(), v.as_str())))
        .envs(
            session_env_overrides
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
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
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

async fn run_command_directly(cmd: &[String]) -> Result<()> {
    let program = &cmd[0];
    let args = &cmd[1..];

    let status = tokio::process::Command::new(program)
        .args(args)
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
