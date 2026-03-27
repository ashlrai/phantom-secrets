use anyhow::{Context, Result};
use colored::Colorize;
use phantom_core::config::PhantomConfig;
use phantom_core::dotenv::DotenvFile;
use phantom_core::token::PhantomToken;
use phantom_proxy::{Interceptor, ProxyConfig, ProxyServer, ServiceRegistry};
use std::collections::HashMap;
use std::process::Stdio;

pub fn run(cmd: &[String]) -> Result<()> {
    if cmd.is_empty() {
        anyhow::bail!("No command specified. Usage: phantom exec -- <command>");
    }

    // Use tokio runtime for async proxy
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

    // Build the token-to-secret mapping by reading .env for phantom tokens
    // and resolving real values from the vault
    let mut token_to_secret: HashMap<String, String> = HashMap::new();

    if env_path.exists() {
        let dotenv = DotenvFile::parse_file(&env_path).context("Failed to read .env")?;

        for entry in dotenv.entries() {
            if PhantomToken::is_phantom_token(&entry.value) {
                // This is a phantom token — look up the real value
                match vault.retrieve(&entry.key) {
                    Ok(real_value) => {
                        token_to_secret.insert(entry.value.clone(), real_value);
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

    if token_to_secret.is_empty() {
        eprintln!(
            "{} No phantom tokens found to proxy. Running command directly.",
            "warn".yellow()
        );
        return run_command_directly(cmd).await;
    }

    // Build service registry from config
    let registry = ServiceRegistry::from_config(&config.services);
    let interceptor = Interceptor::new(token_to_secret);

    println!(
        "{} Starting proxy with {} secret(s) mapped...",
        "->".blue().bold(),
        interceptor.len()
    );

    // Generate proxy session token
    let proxy_token = ProxyServer::generate_proxy_token();

    // Start the proxy
    let proxy = ProxyServer::start(
        ProxyConfig {
            port: 0, // ephemeral port
            proxy_token: proxy_token.clone(),
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
    let overrides = registry.base_url_overrides(port);
    for (env_var, url) in &overrides {
        println!("   {} {} = {}", "->".dimmed(), env_var.bold(), url.cyan());
    }

    // Also inject connection string secrets as env vars
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

    println!(
        "\n{} Launching: {}\n",
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
        .env("PHANTOM_PROXY_PORT", port.to_string())
        .env("PHANTOM_PROXY_TOKEN", &proxy_token)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .context(format!("Failed to start command: {}", program))?;

    // Wait for the child to exit
    let status = child.wait().await?;

    // Shut down the proxy
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
