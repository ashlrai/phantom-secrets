use anyhow::Result;
use colored::Colorize;
use phantom_core::config::PhantomConfig;
use phantom_core::dotenv::DotenvFile;
use phantom_core::token::PhantomToken;
use phantom_proxy::{Interceptor, ProxyConfig, ProxyServer, ServiceRegistry};
use std::collections::HashMap;

pub fn run(daemon: bool) -> Result<()> {
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(run_async(daemon))
}

async fn run_async(daemon: bool) -> Result<()> {
    let project_dir = std::env::current_dir()?;
    let config_path = project_dir.join(".phantom.toml");
    let env_path = project_dir.join(".env");
    let pid_path = project_dir.join(".phantom.pid");

    if !config_path.exists() {
        anyhow::bail!(
            "No .phantom.toml found. Run {} first.",
            "phantom init".cyan().bold()
        );
    }

    // Check if already running
    if pid_path.exists() {
        let pid_str = std::fs::read_to_string(&pid_path).unwrap_or_default();
        eprintln!(
            "{} Proxy may already be running (PID file exists: {}). Run {} first.",
            "!".yellow().bold(),
            pid_str.trim(),
            "phantom stop".cyan().bold()
        );
        return Ok(());
    }

    let config = PhantomConfig::load(&config_path)?;
    let vault = phantom_vault::create_vault(&config.phantom.project_id);

    // Build token mapping
    let mut token_to_secret: HashMap<String, String> = HashMap::new();
    if env_path.exists() {
        let dotenv = DotenvFile::parse_file(&env_path)?;
        for entry in dotenv.entries() {
            if PhantomToken::is_phantom_token(&entry.value) {
                if let Ok(real_value) = vault.retrieve(&entry.key) {
                    token_to_secret.insert(entry.value.clone(), real_value);
                }
            }
        }
    }

    if token_to_secret.is_empty() {
        anyhow::bail!(
            "No phantom tokens found. Run {} first.",
            "phantom init".cyan().bold()
        );
    }

    let registry = ServiceRegistry::from_config(&config.services);
    let interceptor = Interceptor::new(token_to_secret.clone());
    let proxy_token = ProxyServer::generate_proxy_token();

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

    // Write PID file with port info
    let pid_info = format!("{}:{}", std::process::id(), port);
    std::fs::write(&pid_path, &pid_info)?;

    println!(
        "{} Proxy started on {}",
        "ok".green().bold(),
        format!("127.0.0.1:{port}").cyan()
    );
    println!(
        "{} {} secret(s) mapped",
        "ok".green().bold(),
        token_to_secret.len()
    );

    // Print export commands
    println!(
        "\n{} Set these env vars in your shell:\n",
        "->".blue().bold()
    );
    let overrides = registry.base_url_overrides(port);
    for (env_var, url) in &overrides {
        println!("  export {}={}", env_var, url);
    }
    println!("  export PHANTOM_PROXY_PORT={}", port);
    println!("  export PHANTOM_PROXY_TOKEN={}", proxy_token);

    if daemon {
        println!(
            "\n{} Running in background. Use {} to stop.",
            "ok".green().bold(),
            "phantom stop".cyan().bold()
        );
        // In daemon mode, we'd ideally fork. For MVP, just keep running.
        // The user can background this with & or use `phantom exec` instead.
        tokio::signal::ctrl_c().await?;
    } else {
        println!("\n{} Press Ctrl-C to stop the proxy.\n", "->".blue().bold());
        tokio::signal::ctrl_c().await?;
        println!();
    }

    // Cleanup
    let _ = std::fs::remove_file(&pid_path);
    proxy.shutdown().await;
    println!("{} Proxy stopped.", "ok".green().bold());

    Ok(())
}
