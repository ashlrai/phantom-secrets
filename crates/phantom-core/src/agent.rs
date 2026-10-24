use crate::config::PhantomConfig;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ReadinessStatus {
    Unsafe,
    Protected,
    Verified,
    TeamReady,
    ComplianceReady,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RiskLevel {
    Critical,
    High,
    Medium,
    Low,
    None,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FindingSeverity {
    Critical,
    Warning,
    Info,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReadinessFinding {
    pub id: String,
    pub severity: FindingSeverity,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
    pub requires_approval: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct VaultProbe {
    pub accessible: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub backend: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secret_count: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentReadinessReport {
    pub status: ReadinessStatus,
    pub risk_level: RiskLevel,
    pub findings: Vec<ReadinessFinding>,
    pub fixes: Vec<String>,
    pub commands: Vec<String>,
    pub files: Vec<String>,
    pub requires_approval: bool,
    pub exit_code: i32,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AgentReadinessOptions {
    pub vault: Option<VaultProbe>,
    pub cloud_logged_in: bool,
    pub audit_enabled: bool,
    /// The caller deliberately did not probe the vault (metadata-only
    /// preflight). Report `vault-not-probed` as info instead of treating the
    /// missing probe as an inaccessible vault.
    pub vault_probe_skipped: bool,
}

#[derive(Debug)]
struct Signals {
    has_config: bool,
    config_has_sync: bool,
    vault_accessible: bool,
    has_env_file: bool,
    unprotected_secret_count: usize,
    has_env_example: bool,
    has_gitignore_env: bool,
    has_mcp_wiring: bool,
    has_package_scripts: bool,
    has_wrapped_scripts: bool,
    has_precommit: bool,
}

pub fn build_report(project_dir: &Path, options: AgentReadinessOptions) -> AgentReadinessReport {
    let mut files = Vec::new();
    let mut findings = Vec::new();
    let mut fixes = Vec::new();
    let mut commands = Vec::new();

    let config_path = project_dir.join(".phantom.toml");
    let config_exists = config_path.exists();
    let config = match PhantomConfig::load(&config_path) {
        Ok(config) => {
            files.push(rel(project_dir, &config_path));
            Some(config)
        }
        Err(err) if config_exists => {
            files.push(rel(project_dir, &config_path));
            push_finding(
                &mut findings,
                &mut fixes,
                &mut commands,
                FindingSpec::new(
                    "invalid-config",
                    FindingSeverity::Critical,
                    format!(".phantom.toml could not be loaded: {err}"),
                    "phantom doctor",
                )
                .file(".phantom.toml"),
            );
            None
        }
        Err(_) => None,
    };

    let env_files = discover_env_files(project_dir);
    files.extend(env_files.iter().map(|p| rel(project_dir, p)));
    let mut unprotected = Vec::new();
    // Keys holding a phantom token in a readable dotenv: the same notion of
    // "protected" `phantom exec` uses when it decides whether to start.
    let mut protected_keys = std::collections::HashSet::new();
    // Dotenv files reported below as unreadable (the resolver could not read
    // them either) and as malformed (readable, so the resolver can still pick
    // one), by name relative to the project.
    let mut unreadable_dotenvs = Vec::new();
    let mut malformed_dotenvs = Vec::new();
    for path in &env_files {
        // Listed by a lookup that follows symlinks. The read opens without
        // following one and judges the opened handle, so a linked file is
        // reported as a finding instead of having its target read.
        match crate::managed_dotenv::parse_regular_dotenv(project_dir, &rel(project_dir, path)) {
            // Removed since it was listed.
            Ok(None) => {}
            Ok(Some(dotenv)) => {
                if let Err(err) = dotenv.validate_for_mutation() {
                    malformed_dotenvs.push(rel(project_dir, path));
                    findings.push(ReadinessFinding {
                        id: "env-parse-error".to_string(),
                        severity: FindingSeverity::Critical,
                        message: format!(
                            "Could not safely parse {}: {err}",
                            rel(project_dir, path)
                        ),
                        file: Some(rel(project_dir, path)),
                        command: None,
                        requires_approval: false,
                    });
                    continue;
                }
                for entry in dotenv.real_secret_entries() {
                    unprotected.push((path.clone(), entry.key.clone()));
                }
                protected_keys.extend(
                    dotenv
                        .entries()
                        .into_iter()
                        .filter(|entry| crate::token::PhantomToken::is_phantom_token(&entry.value))
                        .map(|entry| entry.key.clone()),
                );
            }
            Err(err) => {
                unreadable_dotenvs.push(rel(project_dir, path));
                findings.push(ReadinessFinding {
                    id: "env-parse-error".to_string(),
                    severity: FindingSeverity::Critical,
                    message: format!("Could not parse {}: {err}", rel(project_dir, path)),
                    file: Some(rel(project_dir, path)),
                    command: None,
                    requires_approval: false,
                })
            }
        }
    }

    let env_example = project_dir.join(".env.example");
    if env_example.exists() {
        files.push(rel(project_dir, &env_example));
    }

    let gitignore = project_dir.join(".gitignore");
    if gitignore.exists() {
        files.push(rel(project_dir, &gitignore));
    }

    let package_json = project_dir.join("package.json");
    if package_json.exists() {
        files.push(rel(project_dir, &package_json));
    }

    let (has_precommit, precommit_error) = match crate::precommit_hook::inspect(project_dir) {
        Ok(crate::precommit_hook::HookState::Present {
            content,
            executable,
            ..
        }) => (crate::precommit_hook::is_ready(&content, executable), None),
        Ok(
            crate::precommit_hook::HookState::Missing { .. }
            | crate::precommit_hook::HookState::NotRepository,
        ) => (false, None),
        Err(error) => (false, Some(error.to_string())),
    };

    let signals = Signals {
        has_config: config_exists,
        config_has_sync: config.as_ref().is_some_and(|c| !c.sync.is_empty()),
        vault_accessible: options.vault.as_ref().is_some_and(|v| v.accessible),
        has_env_file: !env_files.is_empty(),
        unprotected_secret_count: unprotected.len(),
        has_env_example: env_example.exists(),
        has_gitignore_env: gitignore_has_env(&gitignore),
        has_mcp_wiring: has_any_mcp_wiring(project_dir),
        has_package_scripts: package_json.exists() && package_has_scripts(&package_json),
        has_wrapped_scripts: package_has_wrapped_scripts(&package_json),
        has_precommit,
    };

    // `phantom exec` refuses to start for every key while a connection string
    // is protected (or a route is blocked). Report it here, value-free, so a
    // protected project is not read as ready for `phantom exec`.
    if let Some(blocker) = config
        .as_ref()
        .and_then(|c| c.exec_blocker(|name| protected_keys.contains(name)))
    {
        let key = blocker.key();
        push_finding(
            &mut findings,
            &mut fixes,
            &mut commands,
            FindingSpec::new(
                "exec-blocked",
                FindingSeverity::Warning,
                crate::why::blocked_next_step(&blocker),
                match key {
                    Some(key) => format!("phantom why {key}"),
                    None => "phantom why <KEY>".to_string(),
                },
            )
            .file(".phantom.toml"),
        );
    }

    if let Some(error) = precommit_error {
        push_finding(
            &mut findings,
            &mut fixes,
            &mut commands,
            FindingSpec::new(
                "precommit-inspection-failed",
                FindingSeverity::Critical,
                format!("Could not verify Git's effective pre-commit hook: {error}"),
                "phantom doctor",
            ),
        );
    }

    if !signals.has_config {
        push_finding(
            &mut findings,
            &mut fixes,
            &mut commands,
            FindingSpec::new(
                "missing-config",
                FindingSeverity::Critical,
                "No .phantom.toml found; this repo is not initialized for Phantom.",
                "phantom init",
            )
            .file(".phantom.toml")
            .requires_approval(),
        );
    }

    if let Some(config) = &config {
        for risk in config.service_risks() {
            push_finding(
                &mut findings,
                &mut fixes,
                &mut commands,
                FindingSpec::new(
                    format!("service-route-risk-{}", risk.service),
                    FindingSeverity::Warning,
                    format!("Service route `{}`: {}", risk.service, risk.message),
                    "phantom doctor",
                )
                .file(".phantom.toml"),
            );
        }
    }

    if signals.has_env_file && signals.unprotected_secret_count > 0 {
        let sample = unprotected
            .iter()
            .take(5)
            .map(|(path, key)| format!("{}:{key}", rel(project_dir, path)))
            .collect::<Vec<_>>()
            .join(", ");
        push_finding(
            &mut findings,
            &mut fixes,
            &mut commands,
            FindingSpec::new(
                "unprotected-env-secrets",
                FindingSeverity::Critical,
                format!(
                    "{} unprotected secret(s) found in env files: {sample}",
                    signals.unprotected_secret_count
                ),
                "phantom init",
            )
            .requires_approval(),
        );
    }

    // The managed dotenv is what `phantom exec` resolves before launching. A
    // configured file that is missing (or cannot be chosen unambiguously)
    // fails every protected launch, so it is a critical finding, as it is a
    // failed check in `phantom doctor`. It is not repeated when the parse
    // error above is for the managed dotenv's own path: the configured file,
    // or (without one) a candidate the resolver failed to read. A parse error
    // in any other dotenv does not hide it.
    let managed_dotenv_reported =
        |config: &PhantomConfig| match config.phantom.dotenv_path.as_deref() {
            Some(name) => unreadable_dotenvs
                .iter()
                .chain(&malformed_dotenvs)
                .any(|reported| reported == name),
            None => unreadable_dotenvs
                .iter()
                .any(|reported| crate::managed_dotenv::is_resolver_candidate(reported)),
        };
    if let Some(config) = config
        .as_ref()
        .filter(|config| !managed_dotenv_reported(config))
    {
        if let Err(error) = crate::managed_dotenv::resolve_dotenv(project_dir, config, &[]) {
            push_finding(
                &mut findings,
                &mut fixes,
                &mut commands,
                FindingSpec::new(
                    "managed-dotenv-unresolved",
                    FindingSeverity::Critical,
                    format!(
                        "Managed dotenv could not be resolved: {error:#}. Restore the managed dotenv as a regular file beside .phantom.toml, or rerun `phantom init --from <file>` to choose it."
                    ),
                    "phantom doctor",
                )
                .file(".phantom.toml"),
            );
        }
    }

    if config.is_some() && options.vault.is_none() && options.vault_probe_skipped {
        push_finding(
            &mut findings,
            &mut fixes,
            &mut commands,
            FindingSpec::new(
                "vault-not-probed",
                FindingSeverity::Info,
                "Vault access was not checked; run `phantom agent doctor --json --vault` to probe it."
                    .to_string(),
                "phantom agent doctor --json --vault",
            ),
        );
    } else if config.is_some() && !signals.vault_accessible {
        let message = options
            .vault
            .as_ref()
            .and_then(|v| v.error.as_ref())
            .map(|e| format!("Vault is not accessible: {e}"))
            .unwrap_or_else(|| "Vault status could not be verified.".to_string());
        push_finding(
            &mut findings,
            &mut fixes,
            &mut commands,
            FindingSpec::new(
                "vault-not-accessible",
                FindingSeverity::Critical,
                message,
                "phantom doctor",
            ),
        );
    }

    if signals.has_env_file && !signals.has_env_example {
        push_finding(
            &mut findings,
            &mut fixes,
            &mut commands,
            FindingSpec::new(
                "missing-env-example",
                FindingSeverity::Warning,
                "No .env.example found for safe team onboarding.",
                "phantom env",
            )
            .file(".env.example"),
        );
    }

    if signals.has_env_file && !signals.has_gitignore_env {
        push_finding(
            &mut findings,
            &mut fixes,
            &mut commands,
            FindingSpec::new(
                "env-not-gitignored",
                FindingSeverity::Warning,
                ".env is not covered by .gitignore.",
                "phantom doctor --fix",
            )
            .file(".gitignore"),
        );
    }

    if !signals.has_mcp_wiring {
        push_finding(
            &mut findings,
            &mut fixes,
            &mut commands,
            FindingSpec::new(
                "mcp-not-wired",
                FindingSeverity::Warning,
                "No Phantom MCP client wiring detected for common AI coding tools.",
                "phantom setup --client claude",
            ),
        );
    }

    if signals.has_package_scripts && !signals.has_wrapped_scripts {
        push_finding(
            &mut findings,
            &mut fixes,
            &mut commands,
            FindingSpec::new(
                "package-scripts-not-wrapped",
                FindingSeverity::Info,
                "package.json has scripts, but none are wrapped with phantom exec.",
                "phantom wrap",
            )
            .file("package.json")
            .requires_approval(),
        );
    }

    if !signals.has_precommit {
        push_finding(
            &mut findings,
            &mut fixes,
            &mut commands,
            FindingSpec::new(
                "missing-precommit-check",
                FindingSeverity::Info,
                "No Phantom pre-commit check detected.",
                "phantom init",
            ),
        );
    }

    if !options.cloud_logged_in {
        push_finding(
            &mut findings,
            &mut fixes,
            &mut commands,
            FindingSpec::new(
                "cloud-not-authenticated",
                FindingSeverity::Info,
                "Cloud sync is not authenticated on this machine.",
                "phantom login",
            )
            .requires_approval(),
        );
    }

    if config.is_some() && !signals.config_has_sync {
        push_finding(
            &mut findings,
            &mut fixes,
            &mut commands,
            FindingSpec::new(
                "no-sync-targets",
                FindingSeverity::Info,
                "No deployment sync targets are configured.",
                "phantom sync --platform vercel",
            )
            .file(".phantom.toml")
            .requires_approval(),
        );
    }

    if !options.audit_enabled {
        push_finding(
            &mut findings,
            &mut fixes,
            &mut commands,
            FindingSpec::new(
                "audit-disabled",
                FindingSeverity::Info,
                "Audit logging is disabled; set PHANTOM_AUDIT=1 for compliance evidence.",
                "PHANTOM_AUDIT=1 phantom exec -- <command>",
            ),
        );
    }

    files.sort();
    files.dedup();
    fixes.sort();
    fixes.dedup();
    commands.sort();
    commands.dedup();

    let has_critical = findings
        .iter()
        .any(|f| f.severity == FindingSeverity::Critical);
    let warning_count = findings
        .iter()
        .filter(|f| f.severity == FindingSeverity::Warning)
        .count();

    let status = if has_critical {
        ReadinessStatus::Unsafe
    } else if options.audit_enabled && options.cloud_logged_in && signals.config_has_sync {
        ReadinessStatus::ComplianceReady
    } else if options.cloud_logged_in && signals.config_has_sync {
        ReadinessStatus::TeamReady
    } else if warning_count == 0 && signals.has_mcp_wiring && signals.has_precommit {
        ReadinessStatus::Verified
    } else {
        ReadinessStatus::Protected
    };

    let risk_level = if has_critical {
        RiskLevel::High
    } else if warning_count > 0 {
        RiskLevel::Medium
    } else if findings.is_empty() {
        RiskLevel::None
    } else {
        RiskLevel::Low
    };

    let requires_approval = findings.iter().any(|f| f.requires_approval);
    let exit_code = if has_critical { 1 } else { 0 };

    AgentReadinessReport {
        status,
        risk_level,
        findings,
        fixes,
        commands,
        files,
        requires_approval,
        exit_code,
    }
}

fn discover_env_files(project_dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(project_dir) else {
        return out;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if (name == ".env" || name.starts_with(".env.") || name.ends_with(".env"))
            && name != ".env.example"
        {
            out.push(path);
        }
    }
    out.sort();
    out
}

struct FindingSpec {
    id: String,
    severity: FindingSeverity,
    message: String,
    file: Option<String>,
    command: String,
    requires_approval: bool,
}

impl FindingSpec {
    fn new(
        id: impl Into<String>,
        severity: FindingSeverity,
        message: impl Into<String>,
        command: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            severity,
            message: message.into(),
            file: None,
            command: command.into(),
            requires_approval: false,
        }
    }

    fn file(mut self, file: impl Into<String>) -> Self {
        self.file = Some(file.into());
        self
    }

    fn requires_approval(mut self) -> Self {
        self.requires_approval = true;
        self
    }
}

fn push_finding(
    findings: &mut Vec<ReadinessFinding>,
    fixes: &mut Vec<String>,
    commands: &mut Vec<String>,
    spec: FindingSpec,
) {
    findings.push(ReadinessFinding {
        id: spec.id,
        severity: spec.severity,
        message: spec.message.clone(),
        file: spec.file,
        command: Some(spec.command.clone()),
        requires_approval: spec.requires_approval,
    });
    fixes.push(spec.message);
    commands.push(spec.command);
}

fn rel(project_dir: &Path, path: &Path) -> String {
    path.strip_prefix(project_dir)
        .unwrap_or(path)
        .to_string_lossy()
        .to_string()
}

fn gitignore_has_env(path: &Path) -> bool {
    std::fs::read_to_string(path)
        .ok()
        .is_some_and(|content| content.lines().any(|line| line.trim() == ".env"))
}

fn has_any_mcp_wiring(project_dir: &Path) -> bool {
    has_mcp_wiring_with_home(project_dir, dirs::home_dir().as_deref())
}

fn has_mcp_wiring_with_home(project_dir: &Path, home: Option<&Path>) -> bool {
    let mut candidates = vec![project_dir.join(".mcp.json")];
    if let Some(home) = home {
        candidates.push(home.join(".cursor/mcp.json"));
        candidates.push(home.join(".codeium/windsurf/mcp_config.json"));
        candidates.push(home.join(".codex/config.toml"));
    }

    candidates
        .into_iter()
        .any(|path| mcp_config_has_local_runtime(&path))
}

/// Return true only when a client config's Phantom entry invokes an executable
/// already present on this machine. Registry runners and shell downloaders are
/// intentionally rejected even if their arguments mention Phantom.
pub fn mcp_config_has_local_runtime(path: &Path) -> bool {
    let Ok(content) = std::fs::read_to_string(path) else {
        return false;
    };
    let entry = if path.extension().is_some_and(|ext| ext == "toml") {
        toml::from_str::<toml::Value>(&content)
            .ok()
            .and_then(|value| value.get("mcp_servers")?.get("phantom").cloned())
            .and_then(toml_mcp_command)
    } else {
        serde_json::from_str::<serde_json::Value>(&content)
            .ok()
            .and_then(|value| value.get("mcpServers")?.get("phantom").cloned())
            .and_then(json_mcp_command)
    };
    entry.is_some_and(|(command, args)| local_mcp_command_is_canonical(&command, &args))
}

fn json_mcp_command(entry: serde_json::Value) -> Option<(String, Vec<String>)> {
    let command = entry.get("command")?.as_str()?.to_string();
    let args = entry
        .get("args")
        .and_then(serde_json::Value::as_array)?
        .iter()
        .map(|value| value.as_str().map(ToString::to_string))
        .collect::<Option<Vec<_>>>()?;
    Some((command, args))
}

fn toml_mcp_command(entry: toml::Value) -> Option<(String, Vec<String>)> {
    let command = entry.get("command")?.as_str()?.to_string();
    let args = entry
        .get("args")?
        .as_array()?
        .iter()
        .map(|value| value.as_str().map(ToString::to_string))
        .collect::<Option<Vec<_>>>()?;
    Some((command, args))
}

fn local_mcp_command_is_canonical(command: &str, args: &[String]) -> bool {
    let command_path = Path::new(command);
    if !command_path.is_absolute() || !is_runnable_file(command_path) {
        return false;
    }

    let command_canonical = std::fs::canonicalize(command_path).ok();
    let current_canonical = std::env::current_exe()
        .ok()
        .and_then(|path| std::fs::canonicalize(path).ok());
    if command_canonical.is_some() && command_canonical == current_canonical {
        return args == ["mcp", "serve"];
    }

    let expected_name = format!("phantom-mcp{}", std::env::consts::EXE_SUFFIX);
    command_path
        .file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name == expected_name)
        && args.is_empty()
}

fn is_runnable_file(path: &Path) -> bool {
    let Ok(metadata) = std::fs::metadata(path) else {
        return false;
    };
    if !metadata.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        metadata.permissions().mode() & 0o111 != 0
    }
    #[cfg(not(unix))]
    {
        true
    }
}

fn package_has_scripts(path: &Path) -> bool {
    let Ok(content) = std::fs::read_to_string(path) else {
        return false;
    };
    let Ok(value) = serde_json::from_str::<serde_json::Value>(&content) else {
        return false;
    };
    value
        .get("scripts")
        .and_then(|v| v.as_object())
        .is_some_and(|scripts| !scripts.is_empty())
}

fn package_has_wrapped_scripts(path: &Path) -> bool {
    let Ok(content) = std::fs::read_to_string(path) else {
        return false;
    };
    let Ok(value) = serde_json::from_str::<serde_json::Value>(&content) else {
        return false;
    };
    value
        .get("scripts")
        .and_then(|v| v.as_object())
        .is_some_and(|scripts| {
            scripts.values().any(|script| {
                script.as_str().is_some_and(|s| {
                    s.contains("phantom exec") || s.contains("phantom-secrets exec")
                })
            })
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn claude_wiring_requires_the_supported_project_registration_file() {
        let dir = TempDir::new().unwrap();
        std::fs::create_dir(dir.path().join(".claude")).unwrap();
        let registration = serde_json::to_vec(&serde_json::json!({
            "mcpServers": {"phantom": {
                "command": std::env::current_exe().unwrap(),
                "args": ["mcp", "serve"]
            }}
        }))
        .unwrap();
        std::fs::write(
            dir.path().join(".claude/settings.local.json"),
            &registration,
        )
        .unwrap();
        assert!(!has_mcp_wiring_with_home(dir.path(), None));
        std::fs::write(dir.path().join(".mcp.json"), registration).unwrap();
        assert!(has_mcp_wiring_with_home(dir.path(), None));
    }

    fn init_git_with_custom_hooks(dir: &Path) -> PathBuf {
        for args in [
            vec!["init", "--quiet"],
            vec!["config", "core.hooksPath", "effective-hooks"],
        ] {
            let output = std::process::Command::new("git")
                .args(&args)
                .current_dir(dir)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "git {args:?} failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        let hook = dir.join("effective-hooks/pre-commit");
        std::fs::create_dir_all(hook.parent().unwrap()).unwrap();
        hook
    }

    #[test]
    fn skipped_vault_probe_is_info_not_critical() {
        let dir = tempfile::TempDir::new().unwrap();
        PhantomConfig::new_with_defaults("probe-skip".to_string())
            .save(&dir.path().join(".phantom.toml"))
            .unwrap();
        let skipped = build_report(
            dir.path(),
            AgentReadinessOptions {
                vault_probe_skipped: true,
                ..AgentReadinessOptions::default()
            },
        );
        assert!(skipped
            .findings
            .iter()
            .any(|f| f.id == "vault-not-probed" && f.severity == FindingSeverity::Info));
        assert!(!skipped
            .findings
            .iter()
            .any(|f| f.id == "vault-not-accessible"));

        let unprobed = build_report(dir.path(), AgentReadinessOptions::default());
        assert!(unprobed
            .findings
            .iter()
            .any(|f| f.id == "vault-not-accessible" && f.severity == FindingSeverity::Critical));
        assert!(!unprobed.findings.iter().any(|f| f.id == "vault-not-probed"));
    }

    fn no_vault() -> AgentReadinessOptions {
        AgentReadinessOptions {
            vault: Some(VaultProbe {
                accessible: false,
                backend: None,
                secret_count: None,
                error: Some("missing".to_string()),
            }),
            cloud_logged_in: false,
            audit_enabled: false,
            vault_probe_skipped: false,
        }
    }

    #[test]
    fn reports_unsafe_for_uninitialized_secret_env() {
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join(".env"), "OPENAI_API_KEY=sk-test\n").unwrap();

        let report = build_report(dir.path(), no_vault());

        assert_eq!(report.status, ReadinessStatus::Unsafe);
        assert_eq!(report.exit_code, 1);
        assert!(report
            .findings
            .iter()
            .any(|f| f.id == "unprotected-env-secrets"));
        assert!(report.commands.contains(&"phantom init".to_string()));
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_env_is_a_finding_and_its_target_is_not_read() {
        let dir = TempDir::new().unwrap();
        let outside = TempDir::new().unwrap();
        let target = outside.path().join("elsewhere.env");
        std::fs::write(&target, format!("OPENAI_API_KEY={}-outside\n", "sk")).unwrap();
        std::os::unix::fs::symlink(&target, dir.path().join(".env")).unwrap();

        let report = build_report(dir.path(), no_vault());

        assert!(
            !report
                .findings
                .iter()
                .any(|f| f.id == "unprotected-env-secrets"),
            "the link target was read: {:?}",
            report.findings
        );
        let refused = report
            .findings
            .iter()
            .find(|f| f.id == "env-parse-error")
            .expect("the symlink is reported");
        assert!(refused.message.contains("not a regular, non-symlink file"));
        assert!(!refused
            .message
            .contains(&outside.path().display().to_string()));
    }

    fn init_protected_project(dir: &Path, env: &str) {
        let config = PhantomConfig::new_with_defaults(PhantomConfig::project_id_from_path(
            &std::fs::canonicalize(dir).unwrap(),
        ));
        assert!(config.services.contains_key("database"));
        std::fs::write(
            dir.join(".phantom.toml"),
            toml::to_string_pretty(&config).unwrap(),
        )
        .unwrap();
        std::fs::write(dir.join(".env"), env).unwrap();
    }

    #[test]
    fn protected_connection_string_is_reported_as_blocking_exec() {
        let dir = TempDir::new().unwrap();
        init_protected_project(
            dir.path(),
            "DATABASE_URL=phm_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n",
        );

        let report = build_report(dir.path(), no_vault());

        let finding = report
            .findings
            .iter()
            .find(|f| f.id == "exec-blocked")
            .expect("doctor reports that exec is blocked");
        assert_eq!(finding.severity, FindingSeverity::Warning);
        assert!(finding.message.contains("DATABASE_URL"));
        assert!(finding.message.contains("outside `phantom exec`"));
        assert_eq!(finding.command.as_deref(), Some("phantom why DATABASE_URL"));
        assert_ne!(report.status, ReadinessStatus::Verified);
    }

    #[test]
    fn unprotected_connection_string_key_does_not_report_exec_blocked() {
        let dir = TempDir::new().unwrap();
        init_protected_project(dir.path(), "OPENAI_API_KEY=phm_test\n");

        let report = build_report(dir.path(), no_vault());

        assert!(!report.findings.iter().any(|f| f.id == "exec-blocked"));
    }

    #[test]
    fn reports_verified_when_local_controls_are_present() {
        let dir = TempDir::new().unwrap();
        let _hook = init_git_with_custom_hooks(dir.path());
        let config = PhantomConfig::new_with_defaults(PhantomConfig::project_id_from_path(
            &std::fs::canonicalize(dir.path()).unwrap(),
        ));
        std::fs::write(
            dir.path().join(".phantom.toml"),
            toml::to_string_pretty(&config).unwrap(),
        )
        .unwrap();
        std::fs::write(dir.path().join(".env"), "OPENAI_API_KEY=phm_test\n").unwrap();
        std::fs::write(dir.path().join(".env.example"), "OPENAI_API_KEY=<secret>\n").unwrap();
        std::fs::write(dir.path().join(".gitignore"), ".env\n").unwrap();
        assert_eq!(
            crate::precommit_hook::install(dir.path()).unwrap(),
            Some(crate::precommit_hook::HookChange::Installed)
        );
        std::fs::create_dir_all(dir.path().join(".claude")).unwrap();
        let current_exe = std::env::current_exe().unwrap();
        std::fs::write(
            dir.path().join(".mcp.json"),
            serde_json::to_vec(&serde_json::json!({
                "mcpServers": {"phantom": {
                    "command": current_exe,
                    "args": ["mcp", "serve"]
                }}
            }))
            .unwrap(),
        )
        .unwrap();

        let report = build_report(
            dir.path(),
            AgentReadinessOptions {
                vault: Some(VaultProbe {
                    accessible: true,
                    backend: Some("file".to_string()),
                    secret_count: Some(1),
                    error: None,
                }),
                cloud_logged_in: false,
                audit_enabled: false,
                vault_probe_skipped: false,
            },
        );

        assert_eq!(report.status, ReadinessStatus::Verified);
        assert_eq!(report.exit_code, 0);
    }

    /// `phantom agent report` said Protected for a project whose configured
    /// managed dotenv was gone, so every `phantom exec` would refuse to launch.
    #[test]
    fn missing_managed_dotenv_is_a_critical_finding() {
        let dir = TempDir::new().unwrap();
        let mut config = PhantomConfig::new_with_defaults(PhantomConfig::project_id_from_path(
            &std::fs::canonicalize(dir.path()).unwrap(),
        ));
        config.phantom.dotenv_path = Some(".env".to_string());
        std::fs::write(
            dir.path().join(".phantom.toml"),
            toml::to_string_pretty(&config).unwrap(),
        )
        .unwrap();

        let report = build_report(
            dir.path(),
            AgentReadinessOptions {
                vault: Some(VaultProbe {
                    accessible: true,
                    backend: Some("file".to_string()),
                    secret_count: Some(1),
                    error: None,
                }),
                cloud_logged_in: false,
                audit_enabled: false,
                vault_probe_skipped: false,
            },
        );

        let finding = report
            .findings
            .iter()
            .find(|f| f.id == "managed-dotenv-unresolved")
            .expect("the missing managed dotenv is reported");
        assert_eq!(finding.severity, FindingSeverity::Critical);
        assert!(
            finding.message.contains("does not exist: .env"),
            "{}",
            finding.message
        );
        assert!(finding.message.contains("phantom init --from <file>"));
        assert_eq!(report.status, ReadinessStatus::Unsafe);
        assert_eq!(report.exit_code, 1);
    }

    fn config_with_managed_dotenv(dir: &Path) {
        let mut config = PhantomConfig::new_with_defaults(PhantomConfig::project_id_from_path(
            &std::fs::canonicalize(dir).unwrap(),
        ));
        config.phantom.dotenv_path = Some(".env".to_string());
        std::fs::write(
            dir.join(".phantom.toml"),
            toml::to_string_pretty(&config).unwrap(),
        )
        .unwrap();
    }

    /// Without a configured `dotenv_path` the resolver reads its candidate
    /// names itself. An unreadable candidate is what made it fail, and is
    /// already reported, so the finding is skipped; an unreadable file the
    /// resolver never reads must not hide its failure.
    #[cfg(unix)]
    #[test]
    fn without_a_dotenv_path_only_an_unreadable_resolver_candidate_skips_the_finding() {
        let outside = TempDir::new().unwrap();
        let target = outside.path().join("elsewhere.env");
        std::fs::write(&target, "PORT=3000\n").unwrap();
        let unresolved = |linked: &str| {
            let dir = TempDir::new().unwrap();
            let mut config = PhantomConfig::new_with_defaults(PhantomConfig::project_id_from_path(
                &std::fs::canonicalize(dir.path()).unwrap(),
            ));
            // Protected state with no token-bearing dotenv: the resolver fails.
            config.phantom.secrets.insert(
                "SERVICE_TOKEN".to_string(),
                crate::config::SecretOverride::default(),
            );
            std::fs::write(
                dir.path().join(".phantom.toml"),
                toml::to_string_pretty(&config).unwrap(),
            )
            .unwrap();
            std::os::unix::fs::symlink(&target, dir.path().join(linked)).unwrap();

            let report = build_report(dir.path(), no_vault());
            assert!(
                report
                    .findings
                    .iter()
                    .any(|f| f.id == "env-parse-error" && f.file.as_deref() == Some(linked)),
                "{linked} is reported as unreadable"
            );
            report
                .findings
                .iter()
                .any(|f| f.id == "managed-dotenv-unresolved")
        };

        assert!(
            crate::managed_dotenv::is_resolver_candidate(".env.local")
                && !crate::managed_dotenv::is_resolver_candidate("service.env")
        );
        assert!(
            !unresolved(".env.local"),
            "an unreadable resolver candidate is the failure already reported"
        );
        assert!(
            unresolved("service.env"),
            "a file the resolver never reads must not hide its failure"
        );
    }

    /// Any `env-parse-error` used to suppress the finding, so a malformed
    /// `.env.local` hid that the managed `.env` itself was gone.
    #[test]
    fn a_malformed_other_dotenv_does_not_hide_a_missing_managed_one() {
        let dir = TempDir::new().unwrap();
        config_with_managed_dotenv(dir.path());
        std::fs::write(dir.path().join(".env.local"), "PORT=3000\nBROKEN_RECORD\n").unwrap();

        let report = build_report(dir.path(), no_vault());

        assert!(report
            .findings
            .iter()
            .any(|f| f.id == "env-parse-error" && f.file.as_deref() == Some(".env.local")));
        let unresolved = report
            .findings
            .iter()
            .find(|f| f.id == "managed-dotenv-unresolved")
            .expect("the missing managed .env is still reported");
        assert!(
            unresolved.message.contains("does not exist: .env"),
            "{}",
            unresolved.message
        );
    }

    /// A parse error for the managed dotenv's own path already says what is
    /// wrong with it; the resolver failure is not reported a second time.
    #[cfg(unix)]
    #[test]
    fn a_parse_error_for_the_managed_dotenv_is_reported_once() {
        let dir = TempDir::new().unwrap();
        let outside = TempDir::new().unwrap();
        config_with_managed_dotenv(dir.path());
        let target = outside.path().join("elsewhere.env");
        std::fs::write(&target, "PORT=3000\n").unwrap();
        std::os::unix::fs::symlink(&target, dir.path().join(".env")).unwrap();

        let report = build_report(dir.path(), no_vault());

        assert!(report
            .findings
            .iter()
            .any(|f| f.id == "env-parse-error" && f.file.as_deref() == Some(".env")));
        assert!(!report
            .findings
            .iter()
            .any(|f| f.id == "managed-dotenv-unresolved"));
    }

    #[test]
    fn legacy_network_capable_setup_cannot_report_verified() {
        let dir = TempDir::new().unwrap();
        let hook = init_git_with_custom_hooks(dir.path());
        let config = PhantomConfig::new_with_defaults(PhantomConfig::project_id_from_path(
            &std::fs::canonicalize(dir.path()).unwrap(),
        ));
        std::fs::write(
            dir.path().join(".phantom.toml"),
            toml::to_string_pretty(&config).unwrap(),
        )
        .unwrap();
        std::fs::write(dir.path().join(".env"), "OPENAI_API_KEY=phm_test\n").unwrap();
        std::fs::write(dir.path().join(".env.example"), "OPENAI_API_KEY=<secret>\n").unwrap();
        std::fs::write(dir.path().join(".gitignore"), ".env\n").unwrap();
        std::fs::create_dir_all(hook.parent().unwrap()).unwrap();
        std::fs::write(hook, "#!/bin/sh\nnpx phantom-secrets check --staged\n").unwrap();
        std::fs::create_dir_all(dir.path().join(".claude")).unwrap();
        std::fs::write(
            dir.path().join(".mcp.json"),
            r#"{"mcpServers":{"phantom":{"command":"npx","args":["-y","phantom-secrets-mcp"]}}}"#,
        )
        .unwrap();

        let report = build_report(
            dir.path(),
            AgentReadinessOptions {
                vault: Some(VaultProbe {
                    accessible: true,
                    backend: Some("file".to_string()),
                    secret_count: Some(1),
                    error: None,
                }),
                cloud_logged_in: false,
                audit_enabled: false,
                vault_probe_skipped: false,
            },
        );

        assert_eq!(report.status, ReadinessStatus::Protected);
        assert!(!report
            .findings
            .iter()
            .any(|f| f.id == "managed-dotenv-unresolved"));
        assert!(report.findings.iter().any(|f| f.id == "mcp-not-wired"));
        assert!(report
            .findings
            .iter()
            .any(|f| f.id == "missing-precommit-check"));
    }
}
