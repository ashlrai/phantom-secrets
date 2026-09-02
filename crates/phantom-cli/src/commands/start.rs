use anyhow::{Context, Result};
use colored::Colorize;
use phantom_core::config::PhantomConfig;
use phantom_core::dotenv::DotenvFile;
use phantom_core::env_scope::DEFAULT_ENV;
use phantom_core::token::PhantomToken;
use phantom_proxy::{Interceptor, ProxyConfig, ProxyServer, ServiceRegistry};
use std::collections::HashMap;
use std::io::IsTerminal;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ShellSyntax {
    Bash,
    Fish,
    PowerShell,
    #[cfg_attr(not(windows), allow(dead_code))]
    Cmd,
}

fn detect_shell_syntax() -> ShellSyntax {
    // PHANTOM_SHELL is the explicit override for nested shells. SHELL usually
    // names the login shell and is only a fallback hint.
    if let Ok(shell) = std::env::var("PHANTOM_SHELL") {
        if let Some(syntax) = shell_syntax_from_name(&shell) {
            return syntax;
        }
    }
    if let Ok(shell) = std::env::var("SHELL") {
        if let Some(syntax) = shell_syntax_from_name(&shell) {
            return syntax;
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

fn shell_syntax_from_name(shell: &str) -> Option<ShellSyntax> {
    let lower = shell.to_lowercase();
    if lower.contains("fish") {
        Some(ShellSyntax::Fish)
    } else if lower.contains("powershell") || lower.contains("pwsh") {
        Some(ShellSyntax::PowerShell)
    } else if lower == "cmd" || lower.ends_with("cmd.exe") {
        Some(ShellSyntax::Cmd)
    } else if lower.contains("bash") || lower.contains("zsh") || lower.ends_with("/sh") {
        Some(ShellSyntax::Bash)
    } else {
        None
    }
}

fn format_export(syntax: ShellSyntax, var: &str, value: &str) -> String {
    match syntax {
        ShellSyntax::Bash => format!("  export {}='{}'", var, quote_posix_single(value)),
        ShellSyntax::Fish => format!("  set -gx {} '{}'", var, quote_fish_single(value)),
        ShellSyntax::PowerShell => format!("  $env:{} = '{}'", var, value.replace('\'', "''")),
        ShellSyntax::Cmd => format!("  set {}={}", var, value),
    }
}

fn quote_posix_single(value: &str) -> String {
    value.replace('\'', "'\\''")
}

fn quote_fish_single(value: &str) -> String {
    value.replace('\\', "\\\\").replace('\'', "\\'")
}

fn shell_hint(syntax: ShellSyntax) -> &'static str {
    match syntax {
        ShellSyntax::Bash => "  # Selected bash/zsh syntax from PHANTOM_SHELL or the login-shell hint. For a different nested shell, set PHANTOM_SHELL explicitly.",
        ShellSyntax::Fish => "  # Selected fish syntax from PHANTOM_SHELL or the login-shell hint. For a different nested shell, set PHANTOM_SHELL explicitly.",
        ShellSyntax::PowerShell => "  # Selected PowerShell syntax. For a different nested shell, set PHANTOM_SHELL explicitly.",
        ShellSyntax::Cmd => {
            "  # Selected cmd.exe syntax. For a different nested shell, set PHANTOM_SHELL explicitly."
        }
    }
}

fn header_auth_only() -> bool {
    matches!(
        std::env::var("PHANTOM_PROXY_HEADER_AUTH_ONLY")
            .ok()
            .as_deref(),
        Some("1" | "true" | "TRUE" | "yes" | "YES")
    )
}

pub fn run(daemon: bool) -> Result<()> {
    if daemon {
        anyhow::bail!(
            "Detached proxy mode is disabled: Phantom will not persist a live proxy bearer or external process-control state in the workspace. Use `phantom exec -- <command>` or run `phantom start` in a trusted terminal and keep that terminal open."
        );
    }
    if !(std::io::stdin().is_terminal()
        && std::io::stdout().is_terminal()
        && std::io::stderr().is_terminal())
    {
        anyhow::bail!(
            "Standalone `phantom start` requires stdin, stdout, and stderr to each be attached to a terminal. Headless start is denied before vault access or bearer generation; terminal attachment does not prove who controls a PTY, so use only a trusted terminal. Use `phantom exec -- <command>` for owned automation."
        );
    }
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(run_async())
}

async fn run_async() -> Result<()> {
    let project_dir = std::env::current_dir()?;
    let config_path = project_dir.join(".phantom.toml");

    if !config_path.exists() {
        anyhow::bail!(
            "No .phantom.toml found. Run {} first.",
            "phantom init".cyan().bold()
        );
    }

    let config = PhantomConfig::load(&config_path)?;
    config.validate_agentic_proxy_routes()?;

    let preflight = phantom_core::managed_dotenv::resolve_dotenv(&project_dir, &config, &[])?;
    validate_start_dotenv(&preflight).context(
        "Managed dotenv is malformed; proxy start stopped before lifecycle or vault access",
    )?;
    let preflight_protected_keys: std::collections::HashSet<&str> = preflight
        .file
        .iter()
        .flat_map(DotenvFile::entries)
        .filter(|entry| PhantomToken::is_phantom_token(&entry.value))
        .map(|entry| entry.key.as_str())
        .collect();
    let blocked_connection_strings: Vec<&str> = config
        .connection_string_services()
        .into_iter()
        .filter_map(|(_, service)| {
            (preflight_protected_keys.contains(service.secret_key.as_str())
                || std::env::var_os(&service.secret_key).is_some())
            .then_some(service.secret_key.as_str())
        })
        .collect();
    if !blocked_connection_strings.is_empty() {
        anyhow::bail!(
            "Refusing standalone proxy start for configured connection-string credential(s): {}. Ambient values and phantom tokens require a protocol-aware broker.",
            blocked_connection_strings.join(", ")
        );
    }

    super::legacy_proxy::refuse_start_with_legacy_state(&project_dir)?;

    // This machine-local stable lock is held from preflight through graceful
    // shutdown and is never unlinked. It stores no PID, port, or bearer.
    let proxy_lock = super::proxy_lifecycle::try_acquire(config.local_project_id())?;
    let Some(_proxy_lock) = proxy_lock else {
        anyhow::bail!(
            "Another foreground Phantom proxy session already owns {}. Stop it from its owning terminal with Ctrl-C; external process control is disabled.",
            project_dir.display()
        );
    };

    let vault = phantom_vault::try_create_vault(config.local_project_id())?;
    let vault_names = vault.list().map_err(|error| {
        anyhow::anyhow!("Failed to list protected vault entries before proxy start: {error}")
    })?;
    let resolved =
        phantom_core::managed_dotenv::resolve_dotenv(&project_dir, &config, &vault_names)?;
    validate_start_dotenv(&resolved)
        .context("Managed dotenv is malformed; proxy start stopped before secret resolution")?;

    // Build token mapping
    let mut token_to_secret: HashMap<String, (String, String)> = HashMap::new();
    let mut secret_name_to_value: HashMap<String, String> = HashMap::new();
    if let Some(dotenv) = resolved.file {
        for entry in dotenv.entries() {
            if PhantomToken::is_phantom_token(&entry.value) {
                let real_value = retrieve_required_default_secret(vault.as_ref(), &entry.key)?;
                token_to_secret.insert(
                    entry.value.clone(),
                    (entry.key.clone(), String::from(real_value.as_str())),
                );
                secret_name_to_value.insert(entry.key.clone(), String::from(real_value.as_str()));
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
    let interceptor = Interceptor::new_scoped(token_to_secret.clone(), secret_name_to_value);
    let proxy_token = ProxyServer::generate_proxy_token();

    let proxy = ProxyServer::start(
        ProxyConfig {
            port: 0,
            proxy_token: proxy_token.clone(),
            allow_query_token_auth: !header_auth_only(),
            ..ProxyConfig::default()
        },
        registry.clone(),
        interceptor,
    )
    .await
    .map_err(|e| anyhow::anyhow!("Failed to start proxy: {e}"))?;

    let port = proxy.port();

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
    let header_auth_only = header_auth_only();
    let overrides = if header_auth_only {
        registry.base_url_overrides(port)
    } else {
        registry.base_url_overrides_with_token(port, Some(&proxy_token))
    };
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
    if header_auth_only {
        println!("  # Header-only mode: clients must send x-phantom-proxy-token.");
    } else {
        println!(
            "  # SDK-compatible URLs include /_phantom/TOKEN/. Set PHANTOM_PROXY_HEADER_AUTH_ONLY=1 for header-only mode."
        );
    }
    println!("\n{}", shell_hint(syntax));

    println!(
        "\n{} Keep this trusted terminal open. Press Ctrl-C here to stop the proxy; detached mode and external stop are disabled.\n",
        "->".blue().bold()
    );
    tokio::signal::ctrl_c().await?;
    println!();

    proxy.shutdown().await;
    println!("{} Proxy stopped.", "ok".green().bold());

    Ok(())
}

fn validate_start_dotenv(resolved: &phantom_core::managed_dotenv::ResolvedDotenv) -> Result<()> {
    if let Some(dotenv) = resolved.file.as_ref() {
        dotenv.validate_for_mutation()?;
    }
    Ok(())
}

fn retrieve_required_default_secret(
    vault: &dyn phantom_vault::VaultBackend,
    name: &str,
) -> Result<zeroize::Zeroizing<String>> {
    let namespaced = phantom_core::env_scope::namespaced_key(DEFAULT_ENV, name);
    match vault.retrieve_for_injection(&namespaced) {
        Ok(value) => Ok(value),
        Err(phantom_core::error::PhantomError::SecretNotFound(_)) => {
            vault
                .retrieve_for_injection(name)
                .map_err(|error| match error {
                phantom_core::error::PhantomError::SecretNotFound(_) => anyhow::anyhow!(
                    "Protected dotenv key '{name}' has no vault entry for the default environment; refusing to start a partial proxy"
                ),
                other => anyhow::anyhow!(
                    "Failed to read legacy default secret '{name}' from the vault: {other}"
                ),
                })
        }
        Err(error) => Err(anyhow::anyhow!(
            "Failed to read default secret '{namespaced}' from the vault: {error}"
        )),
    }
}

#[cfg(test)]
mod shell_tests {
    use super::*;
    use phantom_core::error::{PhantomError, Result as PhantomResult};
    use zeroize::Zeroizing;

    struct MissingVault;

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
    fn fish_exports_use_native_syntax_and_escape_values() {
        assert_eq!(
            format_export(ShellSyntax::Fish, "PHANTOM_PROXY_TOKEN", "a'b\\c"),
            "  set -gx PHANTOM_PROXY_TOKEN 'a\\'b\\\\c'"
        );
        assert!(shell_hint(ShellSyntax::Fish).contains("Selected fish"));
        assert_eq!(
            shell_syntax_from_name("/opt/homebrew/bin/fish"),
            Some(ShellSyntax::Fish)
        );
        assert_eq!(
            shell_syntax_from_name("pwsh"),
            Some(ShellSyntax::PowerShell)
        );
    }

    #[test]
    fn posix_and_powershell_exports_quote_values() {
        assert_eq!(
            format_export(ShellSyntax::Bash, "X", "a'b"),
            "  export X='a'\\''b'"
        );
        assert_eq!(
            format_export(ShellSyntax::PowerShell, "X", "a'b"),
            "  $env:X = 'a''b'"
        );
    }

    #[test]
    fn daemon_mode_fails_closed_before_runtime_creation() {
        let error = run(true).unwrap_err().to_string();
        assert!(error.contains("Detached proxy mode is disabled"));
        assert!(error.contains("will not persist a live proxy bearer"));
    }

    #[test]
    fn malformed_dotenv_fails_value_free_before_start_effects() {
        let dir = tempfile::tempdir().unwrap();
        let source = b"API_KEY=plaintext-must-not-escape\nBROKEN_RECORD\n";
        let env_path = dir.path().join(".env");
        std::fs::write(&env_path, source).unwrap();
        let config = PhantomConfig::new_with_defaults("start-malformed".to_string());
        let resolved =
            phantom_core::managed_dotenv::resolve_dotenv(dir.path(), &config, &[]).unwrap();

        let error = validate_start_dotenv(&resolved).unwrap_err().to_string();

        assert!(error.contains("malformed dotenv"));
        assert!(!error.contains("plaintext-must-not-escape"));
        assert_eq!(std::fs::read(&env_path).unwrap(), source);
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    #[test]
    fn strict_start_preflight_precedes_lifecycle_and_vault_source_contract() {
        let source = include_str!("start.rs");
        let preflight = source.find("validate_start_dotenv(&preflight)").unwrap();
        let legacy = source.find("legacy_proxy::refuse_start").unwrap();
        let lifecycle = source.find("proxy_lifecycle::try_acquire").unwrap();
        let vault = source.find("phantom_vault::try_create_vault").unwrap();
        assert!(preflight < legacy && legacy < lifecycle && lifecycle < vault);
    }

    #[test]
    fn foreground_start_rejects_a_missing_protected_vault_entry() {
        let error = retrieve_required_default_secret(&MissingVault, "OPENAI_API_KEY")
            .unwrap_err()
            .to_string();
        assert!(error.contains("has no vault entry"));
        assert!(error.contains("refusing to start a partial proxy"));
    }
}
