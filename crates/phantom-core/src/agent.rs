use crate::config::PhantomConfig;
use crate::dotenv::DotenvFile;
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
    for path in &env_files {
        match DotenvFile::parse_file(path) {
            Ok(dotenv) => {
                for entry in dotenv.real_secret_entries() {
                    unprotected.push((path.clone(), entry.key.clone()));
                }
            }
            Err(err) => findings.push(ReadinessFinding {
                id: "env-parse-error".to_string(),
                severity: FindingSeverity::Critical,
                message: format!("Could not parse {}: {err}", rel(project_dir, path)),
                file: Some(rel(project_dir, path)),
                command: None,
                requires_approval: false,
            }),
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
        Ok(crate::precommit_hook::HookState::Present { content, .. }) => {
            (crate::precommit_hook::is_current(&content), None)
        }
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

    if config.is_some() && !signals.vault_accessible {
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
    let mut candidates = vec![project_dir.join(".claude/settings.local.json")];
    if let Some(home) = dirs::home_dir() {
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
        dir.join("effective-hooks/pre-commit")
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

    #[test]
    fn reports_verified_when_local_controls_are_present() {
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
        std::fs::write(hook, crate::precommit_hook::ensure("").content).unwrap();
        std::fs::create_dir_all(dir.path().join(".claude")).unwrap();
        let current_exe = std::env::current_exe().unwrap();
        std::fs::write(
            dir.path().join(".claude/settings.local.json"),
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
            },
        );

        assert_eq!(report.status, ReadinessStatus::Verified);
        assert_eq!(report.exit_code, 0);
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
            dir.path().join(".claude/settings.local.json"),
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
            },
        );

        assert_eq!(report.status, ReadinessStatus::Protected);
        assert!(report.findings.iter().any(|f| f.id == "mcp-not-wired"));
        assert!(report
            .findings
            .iter()
            .any(|f| f.id == "missing-precommit-check"));
    }
}
