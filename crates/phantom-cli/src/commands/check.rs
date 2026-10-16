use anyhow::{Context, Result};
use colored::Colorize;
use phantom_core::config::PhantomConfig;
use phantom_core::dotenv::{is_example_placeholder, is_example_template_file, DotenvFile};
use phantom_core::token::PhantomToken;
use std::path::{Path, PathBuf};

use phantom_core::report::{
    CheckConfigWarning as ConfigWarning, CheckFinding as Finding, CheckReport as Report,
};

/// Check for unprotected secrets in .env files and staged git files.
/// Returns exit code 1 if found. Designed to be used as a pre-commit hook.
///
/// When `staged_only` is true, checks staged content from the git index,
/// including staged .env files, so pre-commit hooks block newly staged secrets.
///
/// When `runtime` is true, scans the current environment for phantom tokens
/// that haven't been replaced (proxy not running).
///
/// With `json`, prints one machine-readable report on stdout and keeps the
/// same exit status: 0 when clean, 1 when findings exist. An indeterminate
/// scan is still an error with no report.
pub fn run(staged_only: bool, runtime: bool, json: bool) -> Result<()> {
    let (mode, findings, warnings) = if runtime {
        ("runtime", runtime_findings(), Vec::new())
    } else if staged_only {
        let (findings, warnings) = staged_findings()?;
        ("staged", findings, warnings)
    } else {
        (
            "worktree",
            worktree_findings(&std::env::current_dir()?)?,
            Vec::new(),
        )
    };

    if json {
        let report = Report {
            mode,
            clean: findings.is_empty(),
            findings: &findings,
            warnings: &warnings,
            indeterminate: &[],
        };
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        print_warnings(&warnings);
        if runtime {
            print_runtime(&findings);
        } else {
            print_findings(&findings);
        }
    }

    if !findings.is_empty() {
        std::process::exit(1);
    }
    Ok(())
}

fn worktree_findings(project_dir: &Path) -> Result<Vec<Finding>> {
    let mut findings = Vec::new();
    for path in dotenv_scan_paths(project_dir)? {
        // The listing's symlink check and this read are separate lookups, so
        // the read re-checks on the opened handle rather than following a
        // file swapped for a symlink in between.
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .context("dotenv scan target has no file name")?;
        let Some(dotenv) = phantom_core::managed_dotenv::parse_regular_dotenv(project_dir, name)?
        else {
            continue;
        };
        dotenv.validate_for_mutation()?;
        for entry in dotenv.real_secret_entries() {
            findings.push(Finding {
                kind: "dotenv",
                path: Some(path.display().to_string()),
                name: Some(entry.key.clone()),
                label: None,
                pattern: None,
            });
        }
    }
    Ok(findings)
}

/// `--staged` is the pre-commit surface. Ordinary worktree checks remain
/// usable without a Git repository or Git binary.
fn staged_findings() -> Result<(Vec<Finding>, Vec<ConfigWarning>)> {
    let mut findings = Vec::new();
    let mut warnings = Vec::new();
    for file in get_staged_files()? {
        if file.ends_with(".phantom.toml") {
            let content = read_staged_file(&file)?;
            warnings.extend(config_risks(&file, &content));
            continue;
        }

        if is_env_file(&file) {
            // Dotenv is a strict text format. Non-UTF-8 content makes its
            // protection status indeterminate and therefore fails closed.
            let content = read_staged_file(&file)?;
            let dotenv = DotenvFile::parse_str(&content);
            dotenv.validate_for_mutation()?;
            let mut real_secrets = dotenv.real_secret_entries();
            // Committable templates (.env.example etc.) may name secrets
            // as long as each value is an empty or `phantom init`-style
            // placeholder. Any other value is still reported.
            if is_example_template_file(&file) {
                real_secrets.retain(|entry| !is_example_placeholder(&entry.value));
            }
            for entry in real_secrets {
                findings.push(Finding {
                    kind: "staged_dotenv",
                    path: Some(file.clone()),
                    name: Some(entry.key.clone()),
                    label: None,
                    pattern: None,
                });
            }
            continue;
        }

        // Do not decode arbitrary staged blobs: PNG, PDF, and other
        // unrelated binary assets are valid. Git emits a textual binary
        // diff marker and therefore no added lines for those files.
        let scan_content = staged_added_lines(&file)?;
        findings.extend(code_pattern_findings(&file, &scan_content));
    }
    Ok((findings, warnings))
}

const CODE_PATTERNS: [(&str, &str); 9] = [
    ("sk-", "OpenAI API key"),
    ("sk_live_", "Stripe live key"),
    ("sk_test_", "Stripe test key"),
    ("ghp_", "GitHub personal token"),
    ("github_pat_", "GitHub PAT"),
    ("glpat-", "GitLab PAT"),
    ("xoxb-", "Slack bot token"),
    ("xoxp-", "Slack user token"),
    ("AKIA", "AWS access key"),
];

fn code_pattern_findings(file: &str, added: &str) -> Vec<Finding> {
    CODE_PATTERNS
        .iter()
        .filter(|(pattern, _)| added.contains(pattern))
        .map(|(pattern, label)| Finding {
            kind: "staged_code",
            path: Some(file.to_string()),
            name: None,
            label: Some(label),
            pattern: Some(pattern),
        })
        .collect()
}

fn print_findings(findings: &[Finding]) {
    let Some(first) = findings.first() else {
        println!("{} No unprotected secrets found.", "ok".green().bold());
        return;
    };
    if first.kind == "staged_code" {
        eprintln!("\n{} Potential secrets in code!\n", "BLOCKED".red().bold());
    } else {
        eprintln!(
            "\n{} Unprotected secrets detected!\n",
            "BLOCKED".red().bold()
        );
    }

    let mut last_header: Option<(&str, Option<&str>)> = None;
    for finding in findings {
        let path = finding.path.as_deref().unwrap_or_default();
        match finding.kind {
            "staged_code" => eprintln!(
                "  {} {} may contain {} ({})",
                "!".red().bold(),
                path,
                finding.label.unwrap_or_default(),
                finding.pattern.unwrap_or_default()
            ),
            kind => {
                let header = (kind, finding.path.as_deref());
                if last_header != Some(header) {
                    let staged = if kind == "staged_dotenv" {
                        "staged "
                    } else {
                        ""
                    };
                    eprintln!(
                        "  {} {}{} has unprotected secret name(s):",
                        "!".red().bold(),
                        staged,
                        path
                    );
                    last_header = Some(header);
                }
                eprintln!(
                    "    {} {}",
                    "-".dimmed(),
                    finding.name.as_deref().unwrap_or_default().bold()
                );
            }
        }
    }

    eprintln!(
        "\n{} Run {} to protect your secrets.",
        "fix".yellow().bold(),
        "phantom init".cyan().bold()
    );
    eprintln!(
        "{} Or use {} to bypass (not recommended).\n",
        "   ".yellow(),
        "git commit --no-verify".dimmed()
    );
}

/// The same scan list as the MCP compliance `env_clean` check
/// ([`phantom_core::managed_dotenv::SCANNED_DOTENV_NAMES`] plus the configured
/// `dotenv_path`), so the two cannot disagree about which files exist.
fn dotenv_scan_paths(project_dir: &Path) -> Result<Vec<PathBuf>> {
    let config_path = project_dir.join(".phantom.toml");
    let configured = if config_path.exists() {
        PhantomConfig::load(&config_path)?.phantom.dotenv_path
    } else {
        None
    };
    phantom_core::managed_dotenv::scanned_dotenv_paths(project_dir, configured.as_deref())
}

fn config_risks(file: &str, content: &str) -> Vec<ConfigWarning> {
    let Ok(config) = toml::from_str::<PhantomConfig>(content) else {
        return Vec::new();
    };
    config
        .service_risks()
        .into_iter()
        .map(|risk| ConfigWarning {
            path: file.to_string(),
            service: risk.service.to_string(),
            message: risk.message.to_string(),
        })
        .collect()
}

fn print_warnings(warnings: &[ConfigWarning]) {
    let mut last_path: Option<&str> = None;
    for warning in warnings {
        if last_path != Some(warning.path.as_str()) {
            if last_path.is_some() {
                print_config_note();
            }
            eprintln!(
                "\n{} Risky Phantom service route(s) in {}:\n",
                "warn".yellow().bold(),
                warning.path
            );
            last_path = Some(warning.path.as_str());
        }
        eprintln!(
            "  {} {}: {}",
            "!".yellow().bold(),
            warning.service.bold(),
            warning.message
        );
    }
    if last_path.is_some() {
        print_config_note();
    }
}

fn print_config_note() {
    eprintln!(
        "\n{} Review .phantom.toml service mappings before running untrusted code.\n",
        "note".yellow().bold()
    );
}

fn is_env_file(file: &str) -> bool {
    file.rsplit('/')
        .next()
        .is_some_and(|name| name == ".env" || name.starts_with(".env.") || name.ends_with(".env"))
}

/// Common env vars that hold API keys. A phantom token in one of them means
/// the proxy is not running and API calls will fail with auth errors.
const RUNTIME_API_KEY_VARS: [&str; 11] = [
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
    "STRIPE_SECRET_KEY",
    "SUPABASE_SERVICE_ROLE_KEY",
    "SUPABASE_ANON_KEY",
    "DATABASE_URL",
    "RESEND_API_KEY",
    "SENDGRID_API_KEY",
    "TWILIO_AUTH_TOKEN",
    "GITHUB_TOKEN",
    "CLOUDFLARE_API_TOKEN",
];

fn runtime_findings() -> Vec<Finding> {
    RUNTIME_API_KEY_VARS
        .iter()
        .filter(|var| std::env::var(var).is_ok_and(|value| PhantomToken::is_phantom_token(&value)))
        .map(|var| Finding {
            kind: "runtime_env",
            path: None,
            name: Some(var.to_string()),
            label: None,
            pattern: None,
        })
        .collect()
}

fn print_runtime(findings: &[Finding]) {
    if findings.is_empty() {
        println!(
            "{} No phantom tokens in environment (proxy running or secrets injected).",
            "ok".green().bold()
        );
        return;
    }
    eprintln!(
        "\n{} Phantom tokens in environment (proxy not running)!\n",
        "warn".yellow().bold()
    );
    for finding in findings {
        eprintln!(
            "  {} {} contains a phantom token",
            "!".yellow().bold(),
            finding.name.as_deref().unwrap_or_default().bold()
        );
    }
    eprintln!(
        "\n{} Start the proxy with: {}",
        "fix".yellow().bold(),
        "phantom exec -- <your-command>".cyan().bold()
    );
}

fn get_staged_files() -> Result<Vec<String>> {
    let output = std::process::Command::new("git")
        .args([
            "diff",
            "--cached",
            "--name-only",
            "--diff-filter=ACMR",
            "-z",
        ])
        .output()
        .map_err(|_| {
            anyhow::anyhow!("Failed to inspect staged paths; clean status is indeterminate")
        })?;
    if !output.status.success() {
        anyhow::bail!("Failed to inspect staged paths; clean status is indeterminate");
    }
    let paths = String::from_utf8(output.stdout).map_err(|_| {
        anyhow::anyhow!("Staged path list is not valid UTF-8; clean status is indeterminate")
    })?;
    Ok(paths
        .split('\0')
        .filter(|path| !path.is_empty())
        .map(String::from)
        .collect())
}

fn read_staged_file(file: &str) -> Result<String> {
    let output = std::process::Command::new("git")
        .args(["show", &format!(":{file}")])
        .output()
        .map_err(|_| {
            anyhow::anyhow!("Failed to read staged file; clean status is indeterminate")
        })?;
    if !output.status.success() {
        anyhow::bail!("Failed to read staged file; clean status is indeterminate");
    }
    String::from_utf8(output.stdout).map_err(|_| {
        anyhow::anyhow!("Staged file is not valid UTF-8; clean status is indeterminate")
    })
}

fn staged_added_lines(file: &str) -> Result<String> {
    let output = std::process::Command::new("git")
        .args(["diff", "--cached", "--unified=0", "--", file])
        .output()
        .map_err(|_| {
            anyhow::anyhow!("Failed to inspect staged additions; clean status is indeterminate")
        })?;
    if !output.status.success() {
        anyhow::bail!("Failed to inspect staged additions; clean status is indeterminate");
    }
    let diff = String::from_utf8(output.stdout).map_err(|_| {
        anyhow::anyhow!("Staged diff is not valid UTF-8; clean status is indeterminate")
    })?;
    Ok(diff
        .lines()
        .filter_map(|line| {
            line.strip_prefix('+')
                .filter(|_| !line.starts_with("+++ "))
                .map(str::to_string)
        })
        .collect::<Vec<_>>()
        .join("\n"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn worktree_findings_report_names_without_values() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join(".env"),
            "OPENAI_API_KEY=sk-live-value-that-must-not-leak-123456\nPORT=3000\n",
        )
        .unwrap();

        let findings = worktree_findings(dir.path()).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].kind, "dotenv");
        assert_eq!(findings[0].name.as_deref(), Some("OPENAI_API_KEY"));

        let report = Report {
            mode: "worktree",
            clean: false,
            findings: &findings,
            warnings: &[],
            indeterminate: &[],
        };
        let json = serde_json::to_string(&report).unwrap();
        assert!(json.contains("\"name\":\"OPENAI_API_KEY\""));
        assert!(!json.contains("must-not-leak"), "{json}");
        assert!(!json.contains("PORT"), "{json}");
    }

    #[test]
    fn protected_worktree_is_clean() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join(".env"),
            format!("OPENAI_API_KEY={}\n", PhantomToken::generate().as_str()),
        )
        .unwrap();
        assert!(worktree_findings(dir.path()).unwrap().is_empty());
    }

    #[test]
    fn code_patterns_report_label_and_prefix_only() {
        let findings =
            code_pattern_findings("src/app.ts", "const key = \"ghp_abcdefSECRETSUFFIX\";");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].label, Some("GitHub personal token"));
        assert_eq!(findings[0].pattern, Some("ghp_"));
        let json = serde_json::to_string(&findings).unwrap();
        assert!(!json.contains("SECRETSUFFIX"), "{json}");
    }

    #[test]
    fn configured_custom_dotenv_is_scanned_for_real_secrets() {
        let dir = tempfile::tempdir().unwrap();
        let custom = dir.path().join("custom.env");
        std::fs::write(&custom, "OPENAI_API_KEY=example-secret-value\n").unwrap();
        let mut config = PhantomConfig::new_with_defaults("check-custom".to_string());
        config.phantom.dotenv_path = Some("custom.env".to_string());
        config.save(&dir.path().join(".phantom.toml")).unwrap();

        let paths = dotenv_scan_paths(dir.path()).unwrap();
        assert_eq!(paths, vec![custom.clone()]);
        let dotenv = DotenvFile::parse_file(&custom).unwrap();
        let names: Vec<_> = dotenv
            .real_secret_entries()
            .into_iter()
            .map(|entry| entry.key.as_str())
            .collect();
        assert_eq!(names, vec!["OPENAI_API_KEY"]);
    }

    #[test]
    fn scans_production_and_test_dotenvs() {
        let dir = tempfile::tempdir().unwrap();
        for name in [
            ".env.production.local",
            ".env.test",
            ".env.development.local",
        ] {
            std::fs::write(dir.path().join(name), "PORT=3000\n").unwrap();
        }
        let names: Vec<_> = dotenv_scan_paths(dir.path())
            .unwrap()
            .into_iter()
            .map(|path| path.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            names,
            vec![
                ".env.development.local",
                ".env.production.local",
                ".env.test"
            ]
        );
    }

    #[test]
    fn configured_dotenv_traversal_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = PhantomConfig::new_with_defaults("check-traversal".to_string());
        config.phantom.dotenv_path = Some("../outside.env".to_string());
        config.save(&dir.path().join(".phantom.toml")).unwrap();
        assert!(dotenv_scan_paths(dir.path()).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn configured_dotenv_symlink_is_rejected() {
        use std::os::unix::fs::symlink;
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target.env");
        std::fs::write(&target, "OPENAI_API_KEY=example-secret-value\n").unwrap();
        symlink(&target, dir.path().join("custom.env")).unwrap();
        let mut config = PhantomConfig::new_with_defaults("check-symlink".to_string());
        config.phantom.dotenv_path = Some("custom.env".to_string());
        config.save(&dir.path().join(".phantom.toml")).unwrap();
        assert!(dotenv_scan_paths(dir.path()).is_err());
    }
}
