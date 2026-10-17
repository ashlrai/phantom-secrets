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

/// Print one of exec's own progress lines.
///
/// Progress goes to stderr so the child's stdout stays byte-for-byte what the
/// child wrote: `phantom exec -- node gen.js > out.json` must produce valid
/// JSON. `--quiet` suppresses these lines entirely; warnings and errors are
/// unaffected.
macro_rules! progress {
    ($quiet:expr, $($arg:tt)*) => {
        if !$quiet {
            eprintln!($($arg)*);
        }
    };
}

pub fn run(cmd: &[String], env: Option<&str>, quiet: bool) -> Result<()> {
    if cmd.is_empty() {
        anyhow::bail!("No command specified. Usage: phantom exec -- <command>");
    }

    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(run_async(cmd, env, quiet))
}

/// Actionable, value-free next steps for the connection-string denial.
fn connection_string_hint(
    blocked: &std::collections::BTreeSet<&str>,
    protected: &HashSet<String>,
) -> String {
    let ambient: Vec<&str> = blocked
        .iter()
        .copied()
        .filter(|key| !protected.contains(*key))
        .collect();
    let mut hint = String::from(
        "Hint: connection strings are vaulted but not proxied yet, so `phantom exec` will not start while one is protected in the managed dotenv or set in the environment. Split database work from API-key work: run database commands (migrations, psql, ORMs) from a terminal you trust, outside `phantom exec`.",
    );
    if !ambient.is_empty() {
        hint.push_str(&format!(
            " {} is set in this shell's environment; unset it before running `phantom exec`.",
            ambient.join(", ")
        ));
    }
    hint.push_str(" Docs: https://phm.dev/docs/getting-started");
    hint
}

async fn run_async(cmd: &[String], env_flag: Option<&str>, quiet: bool) -> Result<()> {
    let project_dir = std::env::current_dir()?;
    let config_path = project_dir.join(".phantom.toml");

    if !config_path.exists() {
        anyhow::bail!(
            "No .phantom.toml found. Run {} first.",
            "phantom init".cyan().bold()
        );
    }

    let config = PhantomConfig::load(&config_path).context("Failed to load .phantom.toml")?;
    validate_routes_for_launch(&config)?;

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
    // BTreeSet: configs written by older init runs can map one key twice.
    // The same check `phantom why` reports as exec.blocked_by, plus the
    // ambient environment that only exec itself can see.
    let blocked_connection_strings: std::collections::BTreeSet<&str> = config
        .exec_connection_string_blockers(|key| {
            preflight_protected_keys.contains(key) || std::env::var_os(key).is_some()
        })
        .into_iter()
        .map(|(_, key)| key)
        .collect();
    if !blocked_connection_strings.is_empty() {
        anyhow::bail!(
            "Refusing to expose connection-string secret(s) to the child process: {}. Phantom requires a protocol-aware broker for database credentials; direct environment injection is disabled.\n{}",
            blocked_connection_strings.iter().copied().collect::<Vec<_>>().join(", "),
            connection_string_hint(&blocked_connection_strings, &preflight_protected_keys)
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
                let real_value = retrieve_required_secret(
                    vault.as_ref(),
                    config.local_project_id(),
                    &namespaced,
                    &entry.key,
                    &active_env,
                )?;

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
    // Export base-URL overrides only for routes this session can serve. An
    // SDK pointed at a route without a loaded credential would receive a
    // proxy 503 for every call instead of reaching its provider.
    let mut exported_routes = registry.clone();
    exported_routes.retain_routes(|route| secret_name_to_value.contains_key(&route.secret_key));
    let interceptor = Interceptor::new_scoped(session_token_to_secret, secret_name_to_value);

    progress!(
        quiet,
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
    progress!(
        quiet,
        "{} Proxy running on {}",
        "ok".green().bold(),
        format!("127.0.0.1:{port}").cyan()
    );

    // Print service routes
    let overrides = if header_auth_only {
        exported_routes.base_url_overrides(port)
    } else {
        exported_routes.base_url_overrides_with_token(port, Some(&proxy_token))
    };
    for (env_var, url) in &overrides {
        progress!(
            quiet,
            "   {} {} = {}",
            "->".dimmed(),
            env_var.bold(),
            redact_session_segment(url).cyan()
        );
    }
    if header_auth_only {
        progress!(
            quiet,
            "   {} {} set for child process",
            "->".dimmed(),
            "PHANTOM_PROXY_TOKEN".bold()
        );
    } else {
        progress!(
            quiet,
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
        progress!(quiet, "   {} Detected Node.js project", "->".dimmed(),);

        // Detect Next.js: check if the command starts with "next" or package.json
        // lists "next" as a dependency
        let is_nextjs = cmd[0] == "next"
            || (cmd[0] == "npx" && cmd.get(1) == Some(&"next".to_string()))
            || detect_next_dependency(&package_json_path);

        if is_nextjs {
            progress!(quiet, "   {} Detected Next.js framework", "->".dimmed(),);

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
                progress!(
                    quiet,
                    "   {} Passing through {} NEXT_PUBLIC_ env var(s)",
                    "->".dimmed(),
                    framework_env_vars.len(),
                );
            }
        }
    }

    // Summary: proxied secrets vs injected env vars. A protected key with
    // no route reaches the child only as a session token that no provider
    // accepts, so it is not counted as proxied and is named in a warning.
    let unrouted = unrouted_session_keys(&registry, env_key_to_session_token.keys());
    // `exported_routes` holds only routes whose credential is loaded.
    let proxied_count = exported_routes
        .services()
        .into_iter()
        .map(|(_, route)| route.secret_key.as_str())
        .collect::<HashSet<_>>()
        .len();
    let injected_count = framework_env_vars.len();
    progress!(
        quiet,
        "\n{} {} secret(s) proxied, {} env var(s) injected directly",
        "->".blue().bold(),
        proxied_count,
        injected_count,
    );
    if !unrouted.is_empty() {
        eprintln!(
            "{} No proxy route for {}: the child gets only a session token for {}, which no provider accepts, so calls that send it will fail. Run `phantom why <KEY>` for details.",
            "warn".yellow(),
            unrouted.join(", ").bold(),
            if unrouted.len() == 1 { "it" } else { "each" },
        );
    }

    progress!(
        quiet,
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
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(error) => {
            // Stop the proxy first: its session tokens must not outlive a
            // launch that never happened.
            proxy.shutdown().await;
            let (code, message) = spawn_failure(program, &error);
            eprintln!("{} {message}", "error".red().bold());
            std::process::exit(code);
        }
    };

    // Wait for the child to exit
    let status = child.wait().await?;

    // Shut down the proxy — session tokens are now invalid
    progress!(quiet, "\n{} Shutting down proxy...", "->".blue().bold());
    proxy.shutdown().await;

    if !status.success() {
        let (code, signal_note) = child_exit_code(&status);
        match signal_note {
            Some(note) => eprintln!("{} {note}", "!".yellow().bold()),
            None => progress!(
                quiet,
                "{} Command exited with code {}",
                "!".yellow().bold(),
                code
            ),
        }
        std::process::exit(code);
    }

    progress!(quiet, "{} Done.", "ok".green().bold());
    Ok(())
}

/// Protected keys the child receives as session tokens that no proxy route
/// injects, sorted. Value-free: compares names only.
fn unrouted_session_keys<'a>(
    registry: &ServiceRegistry,
    session_keys: impl IntoIterator<Item = &'a String>,
) -> Vec<String> {
    let routed: HashSet<&str> = registry
        .services()
        .into_iter()
        .map(|(_, route)| route.secret_key.as_str())
        .collect();
    let mut unrouted: Vec<String> = session_keys
        .into_iter()
        .filter(|key| !routed.contains(key.as_str()))
        .cloned()
        .collect();
    unrouted.sort();
    unrouted
}

fn retrieve_required_secret(
    vault: &dyn phantom_vault::VaultBackend,
    project_id: &str,
    namespaced: &str,
    bare: &str,
    active_env: &str,
) -> Result<zeroize::Zeroizing<String>> {
    let missing = || {
        crate::util::missing_protected_entry(
            vault,
            project_id,
            bare,
            format!(
                "Protected dotenv key '{bare}' has no vault entry for environment '{active_env}'"
            ),
            "refusing to launch the child",
            active_env == DEFAULT_ENV,
        )
    };
    match vault.retrieve_for_injection(namespaced) {
        Ok(value) => Ok(value),
        Err(phantom_core::error::PhantomError::SecretNotFound(_)) if active_env == DEFAULT_ENV => {
            vault
                .retrieve_for_injection(bare)
                .map_err(|error| match error {
                    phantom_core::error::PhantomError::SecretNotFound(_) => missing(),
                    other => anyhow::anyhow!(
                        "Failed to read legacy session secret '{bare}' from the vault: {other}"
                    ),
                })
        }
        Err(phantom_core::error::PhantomError::SecretNotFound(_)) => Err(missing()),
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

    // Shared with `phantom why`, which reports these keys as `withheld`.
    let never_reintroduce: HashSet<String> = config
        .exec_withheld_keys()
        .into_iter()
        .map(str::to_string)
        .collect();
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
    let status = match command
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .await
    {
        Ok(status) => status,
        Err(error) => {
            let (code, message) = spawn_failure(program, &error);
            eprintln!("{} {message}", "error".red().bold());
            std::process::exit(code);
        }
    };

    if !status.success() {
        let (code, signal_note) = child_exit_code(&status);
        if let Some(note) = signal_note {
            eprintln!("{} {note}", "!".yellow().bold());
        }
        std::process::exit(code);
    }

    Ok(())
}

/// Hide the per-session proxy token in printed `*_BASE_URL` lines. The child
/// still receives the full URL; only terminal output is redacted.
fn redact_session_segment(url: &str) -> String {
    const MARKER: &str = "/_phantom/";
    let Some(start) = url.find(MARKER).map(|i| i + MARKER.len()) else {
        return url.to_string();
    };
    let end = url[start..]
        .find('/')
        .map(|i| start + i)
        .unwrap_or(url.len());
    format!("{}<redacted>{}", &url[..start], &url[end..])
}

/// Refuse repository-controlled proxy routing before launch, naming the
/// command that shows which route differs and what Phantom expects.
pub(super) fn validate_routes_for_launch(config: &PhantomConfig) -> Result<()> {
    config.validate_agentic_proxy_routes().context(
        "Refusing unapproved repository-controlled proxy routing. Run `phantom doctor` to see which service in .phantom.toml blocks launch and what to restore; proxied launches run only with Phantom's built-in routes",
    )?;
    Ok(())
}

/// Exit code and message for a child that could not be started, following
/// the shell convention agents already branch on: 127 when the program is not
/// found, 126 when it exists but cannot be executed.
fn spawn_failure(program: &str, error: &std::io::Error) -> (i32, String) {
    match error.kind() {
        std::io::ErrorKind::NotFound => (
            127,
            format!(
                "Command not found: {program}. Check that it is installed and on PATH, or pass its full path after `--`."
            ),
        ),
        std::io::ErrorKind::PermissionDenied => (
            126,
            format!("Command is not executable: {program}. Check its permissions."),
        ),
        _ => (1, format!("Failed to start command {program}: {error}")),
    }
}

/// Exit code to propagate for a failed child, plus a note when a signal ended
/// it. A signal death has no exit code; reporting it as 1 hid OOM kills and
/// timeouts, so use the shell convention 128 + signal number instead.
fn child_exit_code(status: &std::process::ExitStatus) -> (i32, Option<String>) {
    if let Some(code) = status.code() {
        return (code, None);
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        if let Some(signal) = status.signal() {
            let code = 128 + signal;
            return (
                code,
                Some(format!(
                    "Command was terminated by signal {signal}{}; exiting with {code}",
                    signal_name(signal)
                        .map(|name| format!(" ({name})"))
                        .unwrap_or_default()
                )),
            );
        }
    }
    (1, None)
}

#[cfg(unix)]
fn signal_name(signal: i32) -> Option<&'static str> {
    Some(match signal {
        1 => "SIGHUP",
        2 => "SIGINT",
        3 => "SIGQUIT",
        6 => "SIGABRT",
        9 => "SIGKILL",
        11 => "SIGSEGV",
        13 => "SIGPIPE",
        15 => "SIGTERM",
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    #[test]
    fn altered_route_refusal_points_at_doctor() {
        let mut config = PhantomConfig::new_with_defaults("route-test".to_string());
        let service = config
            .services
            .get_mut("openai")
            .expect("built-in openai route");
        service.pattern = Some("api.openai.com.example".to_string());

        let error = format!(
            "{:#}",
            super::validate_routes_for_launch(&config).unwrap_err()
        );

        assert!(error.contains("phantom doctor"), "{error}");
        assert!(error.contains("`openai`"), "{error}");
    }

    #[test]
    fn spawn_failure_uses_shell_exit_codes_and_names_the_fix() {
        let (code, message) = super::spawn_failure(
            "phantom-missing-tool",
            &std::io::Error::from(std::io::ErrorKind::NotFound),
        );
        assert_eq!(code, 127);
        assert!(
            message.contains("Command not found: phantom-missing-tool"),
            "{message}"
        );
        assert!(message.contains("PATH"), "{message}");

        let (code, message) = super::spawn_failure(
            "./script.sh",
            &std::io::Error::from(std::io::ErrorKind::PermissionDenied),
        );
        assert_eq!(code, 126);
        assert!(message.contains("not executable"), "{message}");
    }

    #[cfg(unix)]
    #[test]
    fn child_killed_by_signal_exits_128_plus_signal_with_a_note() {
        use std::os::unix::process::ExitStatusExt;

        let killed = std::process::ExitStatus::from_raw(9);
        let (code, note) = super::child_exit_code(&killed);
        assert_eq!(code, 137);
        let note = note.expect("signal death must be reported");
        assert!(note.contains("signal 9 (SIGKILL)"), "{note}");

        let exited = std::process::ExitStatus::from_raw(3 << 8);
        assert_eq!(super::child_exit_code(&exited), (3, None));
    }

    #[test]
    fn printed_base_url_hides_session_token() {
        let token = "ab".repeat(32);
        let url = format!("http://127.0.0.1:43179/openai/_phantom/{token}/");
        let shown = redact_session_segment(&url);
        assert_eq!(shown, "http://127.0.0.1:43179/openai/_phantom/<redacted>/");
        assert!(!shown.contains(&token));
        assert_eq!(
            redact_session_segment("http://127.0.0.1:1/openai"),
            "http://127.0.0.1:1/openai"
        );
    }

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
            "exec-fixture",
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
    fn exec_names_protected_keys_that_no_route_delivers() {
        use phantom_core::config::ExecDelivery;
        let mut config = PhantomConfig::new_with_defaults("a".repeat(64));
        config.phantom.secrets.insert(
            "STRIPE_SECRET_KEY".to_string(),
            toml::from_str(
                "[rotation_provider]\nprovider = \"stripe\"\napi_key_env = \"STRIPE_ROTATION_API_KEY\"\n",
            )
            .unwrap(),
        );
        // A rotation credential that also has a built-in route: exec still
        // never hands it to the child, so `phantom why` must not say proxied.
        config.phantom.secrets.insert(
            "CLAUDE_KEY".to_string(),
            toml::from_str(
                "[rotation_provider]\nprovider = \"anthropic\"\napi_key_env = \"ANTHROPIC_API_KEY\"\n",
            )
            .unwrap(),
        );
        config.sync.push(
            toml::from_str(
                "platform = \"vercel\"\ntoken_env = \"VERCEL_TOKEN\"\nproject_id = \"p\"\n",
            )
            .unwrap(),
        );
        let registry = ServiceRegistry::from_config(&config.services);
        let protected: HashSet<String> = [
            "OPENAI_API_KEY",
            "NEXTAUTH_SECRET",
            "GROQ_API_KEY",
            "ANTHROPIC_API_KEY",
            "STRIPE_ROTATION_API_KEY",
            "VERCEL_TOKEN",
            "DATABASE_URL",
        ]
        .into_iter()
        .map(str::to_string)
        .collect();
        let (_, never_reintroduce) = child_environment_policy(&config, &protected);
        // Exec hands the child a session token for every other protected key.
        // Plain `assert!`s: nothing here formats key names into output.
        let handed: Vec<&String> = protected
            .iter()
            .filter(|name| !never_reintroduce.contains(*name))
            .collect();
        assert!(
            unrouted_session_keys(&registry, handed.iter().copied())
                == ["GROQ_API_KEY", "NEXTAUTH_SECRET"]
        );
        for name in &protected {
            let delivery = config.exec_delivery_for_key(name);
            // Exec warns about exactly the keys `phantom why` calls no_route.
            let warned = !never_reintroduce.contains(name)
                && unrouted_session_keys(&registry, [name]).len() == 1;
            assert!(warned == (delivery == ExecDelivery::NoRoute));
            // Exec never hands the child exactly the keys `phantom why`
            // reports as withheld or as connection strings it refuses.
            assert!(
                never_reintroduce.contains(name)
                    == matches!(
                        delivery,
                        ExecDelivery::Withheld | ExecDelivery::ConnectionStringRefused { .. }
                    )
            );
        }
    }

    #[test]
    fn exec_rejects_a_missing_protected_vault_entry() {
        let error = retrieve_required_secret(
            &MissingVault,
            "exec-fixture",
            "default/API_KEY",
            "API_KEY",
            DEFAULT_ENV,
        )
        .unwrap_err()
        .to_string();

        assert!(error.contains("has no vault entry"));
        assert!(error.contains("refusing to launch the child"));
        assert!(error.contains("`phantom add API_KEY`"), "{error}");
    }

    /// `phantom add` stores the default environment only, so another
    /// environment's refusal must not send the user there.
    #[test]
    fn exec_missing_entry_outside_the_default_env_has_no_add_hint() {
        let error = retrieve_required_secret(
            &MissingVault,
            "exec-fixture",
            "staging/API_KEY",
            "API_KEY",
            "staging",
        )
        .unwrap_err()
        .to_string();

        assert!(error.contains("for environment 'staging'"), "{error}");
        assert!(!error.contains("phantom add"), "{error}");
    }

    /// With the secrets in an encrypted-file vault this process cannot open,
    /// exec said the protected key "has no vault entry". It still refuses,
    /// and now names the locked vault and the unlock step.
    #[cfg(unix)]
    #[test]
    fn exec_names_a_locked_file_vault_instead_of_a_missing_entry() {
        let project =
            crate::util::test_seam::LockedProject::new(crate::util::test_seam::empty_keychain);
        let error = retrieve_required_secret(
            &MissingVault,
            &project.project_id,
            "default/API_KEY",
            "API_KEY",
            DEFAULT_ENV,
        )
        .unwrap_err()
        .to_string();

        assert!(error.starts_with("Vault locked:"), "{error}");
        assert!(error.contains("refusing to launch the child"), "{error}");
        assert!(error.contains("PHANTOM_VAULT_PASSPHRASE"), "{error}");
        assert!(!error.contains("has no vault entry"), "{error}");
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
