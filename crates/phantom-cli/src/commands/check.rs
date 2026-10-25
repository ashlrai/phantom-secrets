use anyhow::{Context, Result};
use colored::Colorize;
use phantom_core::config::PhantomConfig;
use phantom_core::dotenv::{is_example_placeholder, is_example_template_file, DotenvFile};
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
/// When `runtime` is true, scans every variable of the current environment for
/// phantom tokens left without a proxy. A variable is excused only when a live
/// `phantom exec` / `phantom start` proxy answers for the session variables
/// and the session names that variable as its own (`PHANTOM_SESSION_KEYS`).
///
/// With `json`, prints one machine-readable report on stdout and keeps the
/// same exit status: 0 when clean, 1 when findings exist. An indeterminate
/// scan is still an error with no report.
pub fn run(staged_only: bool, runtime: bool, json: bool) -> Result<()> {
    let mut scan = None;
    let (mode, findings, warnings) = if runtime {
        let mut result = phantom_core::report::scan_runtime_env(
            std::env::vars_os(),
            phantom_core::report::proxy_answers,
        );
        let findings = std::mem::take(&mut result.findings);
        scan = Some(result);
        ("runtime", findings, Vec::new())
    } else if staged_only {
        let (findings, warnings) = staged_findings(&std::env::current_dir()?)?;
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
            proxy_session: scan.as_ref().is_some_and(|scan| scan.proxy_session),
            excused: scan.as_ref().map_or(&[], |scan| scan.excused.as_slice()),
            session_warning: scan.as_ref().and_then(|scan| scan.session_warning()),
        };
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        print_warnings(&warnings);
        if let Some(scan) = &scan {
            print_runtime(&findings, scan);
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
    findings_in_listed(project_dir, dotenv_scan_paths(project_dir)?)
}

/// Read the files a listing returned. Split from the listing so a test can
/// hand it a path that became a symlink after it was listed.
fn findings_in_listed(project_dir: &Path, listed: Vec<PathBuf>) -> Result<Vec<Finding>> {
    let mut findings = Vec::new();
    for path in listed {
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
/// usable without a Git repository or Git binary. `cwd` is where git runs:
/// the work tree root under a hook, any directory of it by hand.
fn staged_findings(cwd: &Path) -> Result<(Vec<Finding>, Vec<ConfigWarning>)> {
    let mut findings = Vec::new();
    let mut warnings = Vec::new();
    for file in get_staged_files(cwd)? {
        if file.ends_with(".phantom.toml") {
            let content = read_staged_file(cwd, &file)?;
            warnings.extend(config_risks(&file, &content));
            continue;
        }

        if is_env_file(&file) {
            // Dotenv is a strict text format. Non-UTF-8 content makes its
            // protection status indeterminate and therefore fails closed.
            let content = read_staged_file(cwd, &file)?;
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
        let scan_content = staged_added_lines(cwd, &file)?;
        findings.extend(code_pattern_findings(&file, &scan_content));
    }
    Ok((findings, warnings))
}

/// Credential shapes looked for in staged code: the prefix, a label for the
/// report, and the shortest tail that can follow the prefix in a real key.
/// A bare prefix is not a key: `task-`, `risk-` and `desk-` all contain `sk-`,
/// so a match must start a token and carry a key-length tail.
struct CodePattern {
    prefix: &'static str,
    label: &'static str,
    min_tail: usize,
    /// AWS access key IDs are upper-case alphanumerics only.
    upper_alnum_only: bool,
}

const CODE_PATTERNS: [CodePattern; 9] = [
    CodePattern {
        prefix: "sk-",
        label: "OpenAI API key",
        min_tail: 20,
        upper_alnum_only: false,
    },
    CodePattern {
        prefix: "sk_live_",
        label: "Stripe live key",
        min_tail: 16,
        upper_alnum_only: false,
    },
    CodePattern {
        prefix: "sk_test_",
        label: "Stripe test key",
        min_tail: 16,
        upper_alnum_only: false,
    },
    CodePattern {
        prefix: "ghp_",
        label: "GitHub personal token",
        min_tail: 30,
        upper_alnum_only: false,
    },
    CodePattern {
        prefix: "github_pat_",
        label: "GitHub PAT",
        min_tail: 30,
        upper_alnum_only: false,
    },
    CodePattern {
        prefix: "glpat-",
        label: "GitLab PAT",
        min_tail: 20,
        upper_alnum_only: false,
    },
    CodePattern {
        prefix: "xoxb-",
        label: "Slack bot token",
        min_tail: 20,
        upper_alnum_only: false,
    },
    CodePattern {
        prefix: "xoxp-",
        label: "Slack user token",
        min_tail: 20,
        upper_alnum_only: false,
    },
    CodePattern {
        prefix: "AKIA",
        label: "AWS access key",
        min_tail: 16,
        upper_alnum_only: true,
    },
];

/// A tail with no digit and no capital is an identifier
/// (`sk-third-party-rollback-race`), not an issued key: twenty random base62
/// characters with neither is a one-in-thirty-million draw.
fn is_identifier_tail(tail: &[u8]) -> bool {
    !tail
        .iter()
        .any(|b| b.is_ascii_digit() || b.is_ascii_uppercase())
}

/// Whether `text` holds `pattern.prefix` at the start of a token, followed by
/// at least `min_tail` key characters that do not read as an identifier.
fn contains_credential(text: &str, pattern: &CodePattern) -> bool {
    let bytes = text.as_bytes();
    text.match_indices(pattern.prefix).any(|(start, _)| {
        if start > 0 && bytes[start - 1].is_ascii_alphanumeric() {
            return false;
        }
        let rest = &bytes[start + pattern.prefix.len()..];
        let len = rest
            .iter()
            .take_while(|b| {
                if pattern.upper_alnum_only {
                    b.is_ascii_uppercase() || b.is_ascii_digit()
                } else {
                    b.is_ascii_alphanumeric() || **b == b'_' || **b == b'-'
                }
            })
            .count();
        len >= pattern.min_tail && !is_identifier_tail(&rest[..len])
    })
}

/// Label for a LiteLLM-shaped key. Shape only: LiteLLM generates virtual keys
/// as `sk-` plus `secrets.token_urlsafe(16)`, which is exactly 22 URL-safe
/// characters (checked in litellm 1.103.5, `key_management_endpoints.py`
/// and `constants.py`; the length is configurable through
/// `LENGTH_OF_LITELLM_GENERATED_KEY`). Legacy OpenAI keys carry a 48-character
/// tail and `sk-proj-` keys are longer, so a 22-character tail is the
/// LiteLLM-shaped case. This is a hint for the report, not proof of origin.
const LITELLM_KEY_LABEL: &str = "LiteLLM-style virtual key (sk- plus 22 characters)";
const LITELLM_TAIL_LEN: usize = 22;

/// Tail lengths of every `sk-` token in `text` that the `sk-` rule accepts.
fn sk_credential_tail_lens(text: &str, pattern: &CodePattern) -> Vec<usize> {
    let bytes = text.as_bytes();
    text.match_indices(pattern.prefix)
        .filter_map(|(start, _)| {
            if start > 0 && bytes[start - 1].is_ascii_alphanumeric() {
                return None;
            }
            let rest = &bytes[start + pattern.prefix.len()..];
            let len = rest
                .iter()
                .take_while(|b| b.is_ascii_alphanumeric() || **b == b'_' || **b == b'-')
                .count();
            (len >= pattern.min_tail && !is_identifier_tail(&rest[..len])).then_some(len)
        })
        .collect()
}

/// The report label for a matched pattern. Only the `sk-` rule can relabel,
/// and only when every accepted token has the LiteLLM tail length, so a file
/// that also holds an OpenAI-shaped key keeps the OpenAI label.
fn finding_label(pattern: &CodePattern, added: &str) -> &'static str {
    if pattern.prefix == "sk-" {
        let tails = sk_credential_tail_lens(added, pattern);
        if !tails.is_empty() && tails.iter().all(|len| *len == LITELLM_TAIL_LEN) {
            return LITELLM_KEY_LABEL;
        }
    }
    pattern.label
}

fn code_pattern_findings(file: &str, added: &str) -> Vec<Finding> {
    CODE_PATTERNS
        .iter()
        .filter(|pattern| contains_credential(added, pattern))
        .map(|pattern| Finding {
            kind: "staged_code",
            path: Some(file.to_string()),
            name: None,
            label: Some(finding_label(pattern, added)),
            pattern: Some(pattern.prefix),
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

fn print_runtime(findings: &[Finding], scan: &phantom_core::report::RuntimeEnvScan) {
    if let Some(warning) = scan.session_warning() {
        eprintln!("{} {}", "warn".yellow().bold(), warning);
    }
    if !scan.excused.is_empty() {
        println!(
            "{} Live Phantom proxy session owns: {}",
            "ok".green().bold(),
            scan.excused
                .iter()
                .map(|name| phantom_core::report::printable_name(name))
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    if findings.is_empty() {
        println!(
            "{} No phantom token outside a live proxy session in any environment variable.",
            "ok".green().bold()
        );
        return;
    }
    eprintln!(
        "\n{} Phantom tokens in environment with no live proxy session that owns them!\n",
        "warn".yellow().bold()
    );
    for finding in findings {
        eprintln!(
            "  {} {} contains a phantom token",
            "!".yellow().bold(),
            phantom_core::report::printable_name(finding.name.as_deref().unwrap_or_default())
                .bold()
        );
    }
    eprintln!(
        "\n{} Start the proxy with: {}",
        "fix".yellow().bold(),
        "phantom exec -- <your-command>".cyan().bold()
    );
}

fn get_staged_files(cwd: &Path) -> Result<Vec<String>> {
    // `--no-relative`: names are always root-relative, as `:<path>` and the
    // `:(top)` pathspec below read them, whatever `diff.relative` says.
    let output = std::process::Command::new("git")
        .current_dir(cwd)
        .args([
            "diff",
            "--cached",
            "--name-only",
            "--no-relative",
            "--diff-filter=ACMR",
            "-z",
        ])
        .output()
        .map_err(|_| {
            anyhow::anyhow!(
                "Failed to inspect staged paths: could not run git (is it on PATH?); clean status is indeterminate"
            )
        })?;
    if !output.status.success() {
        if !inside_git_work_tree(cwd) {
            anyhow::bail!(
                "`phantom check --staged` must run inside a git work tree; clean status is indeterminate. Use `phantom check` to scan .env files here."
            );
        }
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

fn inside_git_work_tree(cwd: &Path) -> bool {
    std::process::Command::new("git")
        .current_dir(cwd)
        .args(["rev-parse", "--is-inside-work-tree"])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .output()
        .is_ok_and(|out| out.status.success() && out.stdout.starts_with(b"true"))
}

fn read_staged_file(cwd: &Path, file: &str) -> Result<String> {
    let output = std::process::Command::new("git")
        .current_dir(cwd)
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

/// The staged added lines of `file`, read as plain unified diff whatever the
/// user's git config says: `color.ui=always` would prefix each `+` line with
/// an escape code, a `diff.external` tool (difftastic) or a textconv driver
/// would replace the diff with its own output, and a cwd-relative pathspec
/// or `diff.relative` would match nothing from a subdirectory. Each of those
/// left no `+` lines, so staged credentials in code were reported clean.
fn staged_added_lines(cwd: &Path, file: &str) -> Result<String> {
    let pathspec = format!(":(top,literal){file}");
    let output = std::process::Command::new("git")
        .current_dir(cwd)
        .args([
            "diff",
            "--cached",
            "--no-color",
            "--no-ext-diff",
            "--no-textconv",
            "--no-relative",
            "--unified=0",
            "--",
            &pathspec,
        ])
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
    use phantom_core::token::PhantomToken;

    /// The liveness probe `--runtime` relies on, against the real proxy rather
    /// than a stand-in: 200 for the session's header, nothing for another
    /// header, and nothing once the proxy has stopped.
    #[test]
    fn runtime_probe_matches_the_real_proxy_health_endpoint() {
        use phantom_core::report::proxy_answers;
        use phantom_proxy::{Interceptor, ProxyConfig, ProxyServer, ServiceRegistry};

        let runtime = tokio::runtime::Runtime::new().unwrap();
        let session_header = ProxyServer::generate_proxy_token();
        let proxy = runtime
            .block_on(ProxyServer::start(
                ProxyConfig {
                    port: 0,
                    proxy_token: session_header.clone(),
                    ..ProxyConfig::default()
                },
                ServiceRegistry::new(),
                Interceptor::new(std::collections::HashMap::new()),
            ))
            .unwrap();
        let port = proxy.port();

        assert!(proxy_answers(port, &session_header));
        assert!(!proxy_answers(port, "another-session"));

        runtime.block_on(proxy.shutdown());
        assert!(!proxy_answers(port, &session_header));
    }

    /// A file listed as regular and then swapped for a symlink is refused at
    /// read time, not followed. Fails if the read goes back to
    /// `DotenvFile::parse_file`, which follows the link and reports the
    /// target's key.
    #[cfg(unix)]
    #[test]
    fn read_refuses_a_listed_file_swapped_for_a_symlink() {
        let dir = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let value = format!("outside-{}", std::process::id());
        std::fs::write(
            outside.path().join("target.env"),
            format!("GITHUB_TOKEN={value}\n"),
        )
        .unwrap();
        std::fs::write(dir.path().join(".env"), "PORT=3000\n").unwrap();
        let listed = dotenv_scan_paths(dir.path()).unwrap();
        assert_eq!(listed, vec![dir.path().join(".env")]);

        std::fs::remove_file(dir.path().join(".env")).unwrap();
        std::os::unix::fs::symlink(outside.path().join("target.env"), dir.path().join(".env"))
            .unwrap();

        let error = findings_in_listed(dir.path(), listed).unwrap_err();
        let message = format!("{error:#}");
        assert!(message.contains("non-symlink file: .env"), "{message}");
        assert!(!message.contains(&value), "{message}");
    }

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
            proxy_session: false,
            excused: &[],
            session_warning: None,
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
        let line = format!(
            "const key = \"{}{}\";",
            "ghp_", "Q7rT2mVx9KpL4wZs8NdY3hBc6FjGu5EaR1oW"
        );
        let findings = code_pattern_findings("src/app.ts", &line);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].label, Some("GitHub personal token"));
        assert_eq!(findings[0].pattern, Some("ghp_"));
        let json = serde_json::to_string(&findings).unwrap();
        assert!(!json.contains("Q7rT2mVx9K"), "{json}");
    }

    #[test]
    fn code_patterns_ignore_prefixes_inside_words_and_short_tails() {
        // `task-`, `risk-` and `desk-` contain `sk-`; none of these is a key.
        for text in [
            "const brief = buildTaskBrief(task-context);",
            "see docs/task-to-pr and risk-register, desk-layout",
            "import { x } from './teams/task-brief-helpers-module.js';",
            "placeholder sk-... or sk-your-key-here",
            "AKIAEXAMPLE is too short; ghp_short",
            "mask_test_value_with_long_suffix_here",
            "fn sk-third-party-rollback-race() and github_pat_grammar_reject_hyphens_identically",
        ] {
            assert!(code_pattern_findings("src/a.ts", text).is_empty(), "{text}");
        }
    }

    #[test]
    fn code_patterns_still_catch_documented_placeholders() {
        // The examples' FAKE_KEY and AWS's documented key must keep failing the
        // gate: a placeholder with digits or capitals is treated like a key.
        for text in [
            format!("{}{}{}", "sk-proj-", "EXAMPLEONLY", "0".repeat(40)),
            format!("{}{}", "AKIA", "IOSFODNN7EXAMPLE"),
        ] {
            assert_eq!(code_pattern_findings("src/a.ts", &text).len(), 1, "{text}");
        }
    }

    #[test]
    fn code_patterns_still_catch_real_key_shapes() {
        // Random-looking tails, built at runtime so no literal key sits in source.
        let cases = [
            (
                format!("OPENAI={}{}", "sk-", "proj-Hq8vN2cW7rT4kLx9ZpM3sJ6d"),
                "sk-",
            ),
            (
                format!("key: '{}{}'", "sk_live_", "51HxYzQ7rT2mVx9KpL4w"),
                "sk_live_",
            ),
            (
                format!("\"{}{}\"", "ghp_", "Q7rT2mVx9KpL4wZs8NdY3hBc6FjGu5EaR1oW"),
                "ghp_",
            ),
            (
                format!("token={}{}", "xoxb-", "7391046285-5810362947-Hq8vN2cW"),
                "xoxb-",
            ),
            (
                format!("aws_access_key_id = {}{}", "AKIA", "Q7RT2MVX9KPL4WZS"),
                "AKIA",
            ),
        ];
        for (text, prefix) in cases {
            let findings = code_pattern_findings("src/a.ts", &text);
            assert_eq!(findings.len(), 1, "{text}");
            assert_eq!(findings[0].pattern, Some(prefix));
        }
    }

    #[test]
    fn litellm_shaped_virtual_key_gets_its_own_label() {
        // 22 URL-safe characters after `sk-`, built at runtime.
        let tail = "Hq8vN2cW7rT4kLx9ZpM3sJ";
        assert_eq!(tail.len(), 22);
        let text = format!("LITELLM_KEY={}{}", "sk-", tail);
        let findings = code_pattern_findings("src/app.ts", &text);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].label, Some(LITELLM_KEY_LABEL));
        assert_eq!(findings[0].pattern, Some("sk-"));
        let json = serde_json::to_string(&findings).unwrap();
        assert!(!json.contains(tail), "{json}");
        // urlsafe alphabet includes `-` and `_`.
        let dashed = format!("{}{}", "sk-", "Hq8vN2cW-rT4kLx9_pM3sJ");
        let findings = code_pattern_findings("src/a.ts", &dashed);
        assert_eq!(findings[0].label, Some(LITELLM_KEY_LABEL));
    }

    #[test]
    fn longer_sk_keys_keep_the_openai_label() {
        for text in [
            format!(
                "{}{}",
                "sk-", "Hq8vN2cW7rT4kLx9ZpM3sJ6dQ1fY5bVn0gXaE8uRt2wK4zP"
            ),
            format!("{}{}", "sk-proj-", "Hq8vN2cW7rT4kLx9ZpM3sJ6dQ1fY"),
            format!("{}{}", "sk-", "Hq8vN2cW7rT4kLx9ZpM3sJa"),
        ] {
            let findings = code_pattern_findings("src/a.ts", &text);
            assert_eq!(findings.len(), 1, "{text}");
            assert_eq!(findings[0].label, Some("OpenAI API key"), "{text}");
        }
        // A file with one LiteLLM-shaped and one longer key keeps the OpenAI label.
        let mixed = format!(
            "a={}{}\nb={}{}",
            "sk-", "Hq8vN2cW7rT4kLx9ZpM3sJ", "sk-", "Hq8vN2cW7rT4kLx9ZpM3sJ6dQ1fY5bVn0gXaE8u"
        );
        let findings = code_pattern_findings("src/a.ts", &mixed);
        assert_eq!(findings[0].label, Some("OpenAI API key"));
    }

    #[test]
    fn litellm_documented_short_example_keys_are_not_flagged() {
        // LiteLLM's docs use short example master keys; a short tail is not a key.
        for text in [
            "master_key: sk-1234",
            "Authorization: Bearer sk-1234",
            "sk-12345678",
        ] {
            assert!(
                code_pattern_findings("config.yaml", text).is_empty(),
                "{text}"
            );
        }
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

    fn git_in(dir: &Path, args: &[&str]) {
        let status = std::process::Command::new("git")
            .current_dir(dir)
            .args(args)
            .status()
            .unwrap();
        assert!(status.success(), "git {args:?}");
    }

    /// A repository with `config` set locally and one staged code file at
    /// `path` holding a GitHub-shaped credential (built at runtime).
    fn repo_with_staged_credential(config: &[(&str, &str)], path: &str) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        git_in(dir.path(), &["init", "-q"]);
        for (name, value) in config {
            git_in(dir.path(), &["config", name, value]);
        }
        let file = dir.path().join(path);
        std::fs::create_dir_all(file.parent().unwrap()).unwrap();
        let line = format!(
            "const key = \"{}{}\";\n",
            "ghp_", "Q7rT2mVx9KpL4wZs8NdY3hBc6FjGu5EaR1oW"
        );
        std::fs::write(&file, line).unwrap();
        git_in(dir.path(), &["add", "--", path]);
        dir
    }

    fn staged_code_labels(cwd: &Path) -> Vec<&'static str> {
        let (findings, _) = staged_findings(cwd).unwrap();
        findings
            .iter()
            .filter(|finding| finding.kind == "staged_code")
            .filter_map(|finding| finding.label)
            .collect()
    }

    #[test]
    fn staged_code_scan_reads_plain_diff_under_color_ui_always() {
        let dir = repo_with_staged_credential(&[("color.ui", "always")], "src/app.ts");
        assert_eq!(staged_code_labels(dir.path()), ["GitHub personal token"]);
    }

    #[test]
    fn staged_code_scan_ignores_an_external_diff_tool() {
        // difftastic's documented setup is `diff.external = difft`; any tool
        // that prints its own format left no `+` lines to scan.
        let dir = repo_with_staged_credential(&[("diff.external", "true")], "src/app.ts");
        assert_eq!(staged_code_labels(dir.path()), ["GitHub personal token"]);
    }

    #[test]
    fn staged_code_scan_ignores_a_textconv_driver() {
        let dir = repo_with_staged_credential(&[("diff.hide.textconv", "true")], "src/app.ts");
        std::fs::write(dir.path().join(".gitattributes"), "*.ts diff=hide\n").unwrap();
        assert_eq!(staged_code_labels(dir.path()), ["GitHub personal token"]);
    }

    #[test]
    fn staged_code_scan_from_a_subdirectory_sees_the_whole_index() {
        // Run from `docs/` with `diff.relative` on: the listing must still
        // name `src/app.ts`, and its diff must be read root-relative.
        let dir = repo_with_staged_credential(&[("diff.relative", "true")], "src/app.ts");
        let subdir = dir.path().join("docs");
        std::fs::create_dir(&subdir).unwrap();
        assert_eq!(staged_code_labels(&subdir), ["GitHub personal token"]);
        let plain = repo_with_staged_credential(&[], "src/app.ts");
        assert_eq!(
            staged_code_labels(&plain.path().join("src")),
            ["GitHub personal token"]
        );
    }
}
