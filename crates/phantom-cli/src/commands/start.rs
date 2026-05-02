use anyhow::Result;
use colored::Colorize;
use phantom_core::config::PhantomConfig;
use phantom_core::dotenv::DotenvFile;
use phantom_core::token::PhantomToken;
use phantom_proxy::{Interceptor, ProxyConfig, ProxyServer, ServiceRegistry};
use std::collections::HashMap;
use std::process::{Command, Stdio};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ShellSyntax {
    Bash,
    PowerShell,
    #[cfg_attr(not(windows), allow(dead_code))]
    Cmd,
}

fn detect_shell_syntax() -> ShellSyntax {
    // POSIX shells (incl. Git Bash on Windows, WSL, macOS, Linux) set $SHELL.
    if let Ok(sh) = std::env::var("SHELL") {
        let lower = sh.to_lowercase();
        if lower.contains("bash")
            || lower.contains("zsh")
            || lower.contains("fish")
            || lower.ends_with("/sh")
        {
            return ShellSyntax::Bash;
        }
    }
    // $PSModulePath is set by PowerShell on Windows and nowhere else.
    if std::env::var("PSModulePath").is_ok() {
        return ShellSyntax::PowerShell;
    }
    #[cfg(windows)]
    {
        ShellSyntax::Cmd
    }
    #[cfg(not(windows))]
    {
        ShellSyntax::Bash
    }
}

fn format_export(syntax: ShellSyntax, var: &str, value: &str) -> String {
    match syntax {
        ShellSyntax::Bash => format!("  export {}={}", var, value),
        ShellSyntax::PowerShell => format!("  $env:{} = \"{}\"", var, value),
        ShellSyntax::Cmd => format!("  set {}={}", var, value),
    }
}

fn shell_hint(syntax: ShellSyntax) -> &'static str {
    match syntax {
        ShellSyntax::Bash => {
            "  # Detected bash/zsh/fish. PowerShell: `$env:X = \"Y\"`. cmd: `set X=Y`."
        }
        ShellSyntax::PowerShell => "  # Detected PowerShell. bash: `export X=Y`. cmd: `set X=Y`.",
        ShellSyntax::Cmd => {
            "  # Assuming cmd.exe. PowerShell: `$env:X = \"Y\"`. bash: `export X=Y`."
        }
    }
}

pub fn run(daemon: bool) -> Result<()> {
    if daemon {
        return run_daemon();
    }
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(run_async())
}

/// Spawn a detached `phantom start` subprocess (without `--daemon`) and wait
/// for it to write the PID file. Once the PID file appears we read the port
/// and proxy token from it, print the export commands, and exit.
fn run_daemon() -> Result<()> {
    let project_dir = std::env::current_dir()?;
    let config_path = project_dir.join(".phantom.toml");
    let pid_path = project_dir.join(".phantom.pid");

    if !config_path.exists() {
        anyhow::bail!(
            "No .phantom.toml found. Run {} first.",
            "phantom init".cyan().bold()
        );
    }

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

    let exe = std::env::current_exe()?;
    let mut cmd = Command::new(exe);
    cmd.arg("start")
        .current_dir(&project_dir)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .stdin(Stdio::null());

    // Detach the child so it survives the parent exiting.
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        cmd.process_group(0);
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const DETACHED_PROCESS: u32 = 0x00000008;
        const CREATE_NO_WINDOW: u32 = 0x08000000;
        cmd.creation_flags(DETACHED_PROCESS | CREATE_NO_WINDOW);
    }

    cmd.spawn()
        .map_err(|e| anyhow::anyhow!("Failed to spawn daemon process: {e}"))?;

    // Wait for the child to write the PID file (up to 5 seconds).
    let mut attempts = 0;
    while !pid_path.exists() {
        std::thread::sleep(std::time::Duration::from_millis(100));
        attempts += 1;
        if attempts > 50 {
            anyhow::bail!("Timed out waiting for daemon to start (no PID file after 5s)");
        }
    }

    // Small extra delay to let the child finish writing.
    std::thread::sleep(std::time::Duration::from_millis(50));

    let pid_info = std::fs::read_to_string(&pid_path)?;
    let parts: Vec<&str> = pid_info.trim().split(':').collect();
    if parts.len() < 3 {
        anyhow::bail!("PID file has unexpected format: {}", pid_info.trim());
    }
    let pid = parts[0];
    let port: u16 = parts[1]
        .parse()
        .map_err(|_| anyhow::anyhow!("Invalid port in PID file"))?;
    let proxy_token = parts[2];

    // Load config to build the export commands.
    let config = PhantomConfig::load(&config_path)?;
    let registry = ServiceRegistry::from_config(&config.services);

    println!(
        "{} Proxy started on {} (PID {})",
        "ok".green().bold(),
        format!("127.0.0.1:{port}").cyan(),
        pid,
    );

    // Print export commands
    println!(
        "\n{} Set these env vars in your shell:\n",
        "->".blue().bold()
    );
    let syntax = detect_shell_syntax();
    let overrides = registry.base_url_overrides_with_token(port, Some(proxy_token));
    for (env_var, url) in &overrides {
        println!("{}", format_export(syntax, env_var, url));
    }
    println!(
        "{}",
        format_export(syntax, "PHANTOM_PROXY_PORT", &port.to_string())
    );
    println!(
        "{}",
        format_export(syntax, "PHANTOM_PROXY_TOKEN", proxy_token)
    );
    println!("\n{}", shell_hint(syntax));

    println!(
        "\n{} Running in background. Use {} to stop.",
        "ok".green().bold(),
        "phantom stop".cyan().bold()
    );

    Ok(())
}

async fn run_async() -> Result<()> {
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
    let mut secret_name_to_value: HashMap<String, String> = HashMap::new();
    if env_path.exists() {
        let dotenv = DotenvFile::parse_file(&env_path)?;
        for entry in dotenv.entries() {
            if PhantomToken::is_phantom_token(&entry.value) {
                if let Ok(real_value) = vault.retrieve(&entry.key) {
                    token_to_secret.insert(entry.value.clone(), String::from(real_value.as_str()));
                    secret_name_to_value
                        .insert(entry.key.clone(), String::from(real_value.as_str()));
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
    let interceptor = Interceptor::new_with_named(token_to_secret.clone(), secret_name_to_value);
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

    // Write PID file atomically. The PID file contains the proxy auth token,
    // so the tempfile must have restrictive permissions from the moment of
    // creation — not set afterward. phantom_core::fs::atomic_write stages
    // through `tempfile::NamedTempFile` which creates with mode 0o600 on POSIX
    // before the first byte is written, then renames over the target atomically.
    // Fixes F8 from the 0.5.1 security audit (world-readable race window).
    let pid_info = format!("{}:{}:{}", std::process::id(), port, proxy_token);
    phantom_core::fs::atomic_write(&pid_path, pid_info.as_bytes())?;

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
    let syntax = detect_shell_syntax();
    let overrides = registry.base_url_overrides_with_token(port, Some(&proxy_token));
    for (env_var, url) in &overrides {
        println!("{}", format_export(syntax, env_var, url));
    }
    println!(
        "{}",
        format_export(syntax, "PHANTOM_PROXY_PORT", &port.to_string())
    );
    println!(
        "{}",
        format_export(syntax, "PHANTOM_PROXY_TOKEN", &proxy_token)
    );
    println!("\n{}", shell_hint(syntax));

    println!("\n{} Press Ctrl-C to stop the proxy.\n", "->".blue().bold());
    tokio::signal::ctrl_c().await?;
    println!();

    // Cleanup
    let _ = std::fs::remove_file(&pid_path);
    proxy.shutdown().await;
    println!("{} Proxy stopped.", "ok".green().bold());

    Ok(())
}
