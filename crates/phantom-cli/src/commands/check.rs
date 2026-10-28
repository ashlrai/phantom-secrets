use anyhow::{Context, Result};
use colored::Colorize;
use phantom_core::config::PhantomConfig;
use phantom_core::dotenv::{is_example_placeholder, is_example_template_file, DotenvFile};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use phantom_core::redact::{staged_code_credential_matches, staged_code_patterns};
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
        let pretty = serde_json::to_string_pretty(&report)?;
        println!(
            "{}",
            crate::commands::report_json::with_schema_pretty(
                pretty,
                crate::commands::report_json::CHECK_SCHEMA
            )?
        );
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
    for StagedEntry { path: file, mode } in get_staged_entries(cwd)? {
        match mode {
            // A gitlink records a submodule commit: no blob to read or scan.
            StagedMode::Gitlink => continue,
            // A symlink's blob is its target path, never the dotenv or
            // config text its name suggests, so it is not parsed as either
            // (that failed the hook on commits holding no secret). Its
            // staged diff is still scanned for credential shapes like code.
            StagedMode::Symlink => {
                let scan_content = staged_added_lines(cwd, &file)?;
                findings.extend(code_pattern_findings(&file, &scan_content));
                continue;
            }
            StagedMode::Regular => {}
        }

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

        if is_direnv_file(&file) {
            findings.extend(staged_direnv_findings(cwd, &file)?);
            continue;
        }

        // Any staged blob is valid to commit, PNG and PDF assets included,
        // so its added bytes are scanned for the ASCII credential shapes
        // whatever git thinks of the file (see `staged_added_lines`).
        let scan_content = staged_added_lines(cwd, &file)?;
        findings.extend(code_pattern_findings(&file, &scan_content));
    }
    Ok((findings, warnings))
}

/// A direnv `.envrc` (or the `.envrc.local` it conventionally sources) holds
/// the same `export KEY=value` assignments as a dotenv file, so each
/// assignment the dotenv parser reads is classified exactly as a staged
/// `.env` entry is. It is shell, not dotenv: stdlib calls (`use nix`,
/// `PATH_add bin`), conditionals and repeated names are not parse errors, and
/// a value expanded when direnv loads (`$(op read ...)`, `${VAR}`, backticks)
/// or left empty commits no credential. Lines the parser skips are still
/// covered by the code scan of the staged additions.
///
/// The parser stops at an unterminated quote, and an unclosed quote can pair
/// with the next line's opening quote and swallow that assignment, so every
/// physical line is also parsed on its own and the names are united: a shell
/// typo never hides a later assignment. Multi-line quoted values are still
/// read by the whole-file parse. Each name is reported once.
fn staged_direnv_findings(cwd: &Path, file: &str) -> Result<Vec<Finding>> {
    let added = staged_added_lines(cwd, file)?;
    let mut findings = code_pattern_findings(file, &added);
    let content = read_staged_bytes(cwd, file)?;
    let text = String::from_utf8_lossy(&content);
    let mut names = BTreeSet::new();
    collect_direnv_literal_names(&text, &mut names);
    for line in text.split(['\n', '\r']) {
        collect_direnv_literal_names(line, &mut names);
    }
    findings.extend(names.into_iter().map(|name| Finding {
        kind: "staged_dotenv",
        path: Some(file.to_string()),
        name: Some(name),
        label: None,
        pattern: None,
    }));
    Ok(findings)
}

/// Add the name of each assignment in `source` whose value classifies as a
/// real secret and is literal text: not empty, and not a shell expansion
/// unless single quotes made it literal (`'$2b$...'`, `'$(not run)'`).
fn collect_direnv_literal_names(source: &str, names: &mut BTreeSet<String>) {
    let dotenv = DotenvFile::parse_str(source);
    let real = dotenv.real_secret_entries();
    for (entry, quote) in dotenv.entries_with_quote() {
        if !real.iter().any(|candidate| std::ptr::eq(*candidate, entry)) {
            continue;
        }
        let expanded = quote != Some('\'') && is_shell_expansion(&entry.value);
        if entry.value.is_empty() || expanded {
            continue;
        }
        names.insert(entry.key.clone());
    }
}

fn is_direnv_file(file: &str) -> bool {
    file.rsplit('/')
        .next()
        .is_some_and(|name| matches!(name, ".envrc" | ".envrc.local"))
}

/// A value the shell computes when direnv loads it rather than a literal:
/// command substitution, a variable reference or a backtick command. Only
/// meaningful for an unquoted or double-quoted value; single quotes keep it
/// literal.
fn is_shell_expansion(value: &str) -> bool {
    value.starts_with('`')
        || value.strip_prefix('$').is_some_and(|rest| {
            rest.starts_with(['(', '{'])
                || rest.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_')
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

fn code_pattern_findings(file: &str, added: &str) -> Vec<Finding> {
    let matches = staged_code_credential_matches(added.as_bytes());
    staged_code_patterns()
        .iter()
        .filter_map(|pattern| {
            let matching: Vec<_> = matches
                .iter()
                .filter(|found| found.pattern.prefix == pattern.prefix)
                .collect();
            if matching.is_empty() {
                return None;
            }
            let label = if pattern.prefix == "sk-"
                && matching
                    .iter()
                    .all(|found| found.span.len() - pattern.prefix.len() == LITELLM_TAIL_LEN)
            {
                LITELLM_KEY_LABEL
            } else {
                pattern.label
            };
            Some(Finding {
                kind: "staged_code",
                path: Some(file.to_string()),
                name: None,
                label: Some(label),
                pattern: Some(pattern.prefix),
            })
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
///
/// `.phantom.toml` is read only as a regular, non-symlink file. A symlink
/// (dangling or not) is never "no config": the `dotenv_path` it would name is
/// unknown, and following it reads a file that may lie outside the project. A
/// FIFO or device is refused before it is opened, so it cannot hang the check.
fn dotenv_scan_paths(project_dir: &Path) -> Result<Vec<PathBuf>> {
    let config_path = project_dir.join(".phantom.toml");
    let bytes = phantom_core::fs::read_regular_file(&config_path).map_err(|_| {
        anyhow::anyhow!(
            "Refusing .phantom.toml that is not a readable regular, non-symlink file; clean status is indeterminate"
        )
    })?;
    let configured = match bytes {
        Some(bytes) => {
            PhantomConfig::load_from_bytes(&config_path, &bytes)?
                .phantom
                .dotenv_path
        }
        None => None,
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

/// The staged mode of an index entry, which decides how it is scanned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StagedMode {
    /// `100644` or `100755`: a file whose blob is its content.
    Regular,
    /// `120000`: the blob is the link's target path.
    Symlink,
    /// `160000`: a submodule commit, with no blob in this repository.
    Gitlink,
}

#[derive(Debug)]
struct StagedEntry {
    path: String,
    mode: StagedMode,
}

/// Every added, copied, modified, renamed or type-changed staged path with
/// its staged mode. `T` is listed: a symlink replaced by a regular file
/// holding a credential was otherwise never scanned.
fn get_staged_entries(cwd: &Path) -> Result<Vec<StagedEntry>> {
    // `--no-relative`: names are always root-relative, as `:<path>` and the
    // `:(top)` pathspec below read them, whatever `diff.relative` says.
    let output = std::process::Command::new("git")
        .current_dir(cwd)
        .args([
            "diff",
            "--cached",
            "--raw",
            "--no-relative",
            "--diff-filter=ACMRT",
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
    let raw = String::from_utf8(output.stdout).map_err(|_| {
        anyhow::anyhow!("Staged path list is not valid UTF-8; clean status is indeterminate")
    })?;
    parse_raw_entries(&raw)
}

/// Parse `git diff --raw -z`: `:<src mode> <dst mode> <src> <dst> <status>`
/// then one path, or two (source, destination) for a rename or copy.
/// Anything unexpected fails closed.
fn parse_raw_entries(raw: &str) -> Result<Vec<StagedEntry>> {
    let malformed =
        || anyhow::anyhow!("Unexpected staged path listing; clean status is indeterminate");
    let mut fields = raw.split('\0');
    let mut entries = Vec::new();
    while let Some(header) = fields.next() {
        if header.is_empty() {
            // Only the trailing terminator may be empty.
            if fields.next().is_some() {
                return Err(malformed());
            }
            break;
        }
        let parts: Vec<&str> = header
            .strip_prefix(':')
            .ok_or_else(malformed)?
            .split(' ')
            .collect();
        let [_, dst_mode, _, _, status] = parts[..] else {
            return Err(malformed());
        };
        let mut path = fields
            .next()
            .filter(|p| !p.is_empty())
            .ok_or_else(malformed)?;
        if status.starts_with('R') || status.starts_with('C') {
            path = fields
                .next()
                .filter(|p| !p.is_empty())
                .ok_or_else(malformed)?;
        }
        let mode = match dst_mode {
            "100644" | "100755" => StagedMode::Regular,
            "120000" => StagedMode::Symlink,
            "160000" => StagedMode::Gitlink,
            _ => return Err(malformed()),
        };
        entries.push(StagedEntry {
            path: path.to_string(),
            mode,
        });
    }
    Ok(entries)
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
    String::from_utf8(read_staged_bytes(cwd, file)?).map_err(|_| {
        anyhow::anyhow!("Staged file is not valid UTF-8; clean status is indeterminate")
    })
}

fn read_staged_bytes(cwd: &Path, file: &str) -> Result<Vec<u8>> {
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
    Ok(output.stdout)
}

/// The staged added lines of `file`, read as plain unified diff whatever the
/// user's git config says: `color.ui=always` would prefix each `+` line with
/// an escape code, a `diff.external` tool (difftastic) or a textconv driver
/// would replace the diff with its own output, and a cwd-relative pathspec
/// or `diff.relative` would match nothing from a subdirectory. Each of those
/// left no `+` lines, so staged credentials in code were reported clean.
///
/// `--text` keeps a file git calls binary (a `-diff` or `binary` attribute,
/// or a NUL byte in its content) from collapsing to "Binary files differ"
/// with no `+` lines, which also reported its credentials clean. Every shape
/// in [`CODE_PATTERNS`] is ASCII, so the diff is decoded lossily: a Latin-1
/// or binary line still yields its ASCII runs, and a non-UTF-8 byte is not
/// an indeterminate scan.
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
            "--text",
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
    let diff = String::from_utf8_lossy(&output.stdout);
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

    /// A `.phantom.toml` symlink, even a dangling one, is not "no config":
    /// the configured `dotenv_path` it may name is unknown, so a credential in
    /// that regular file would be missed by a clean report.
    #[cfg(unix)]
    #[test]
    fn dangling_config_symlink_is_refused_not_treated_as_absent() {
        use std::os::unix::fs::symlink;
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("prod.env"),
            "OPENAI_API_KEY=example-value\n",
        )
        .unwrap();
        symlink("missing.toml", dir.path().join(".phantom.toml")).unwrap();
        let message = format!("{:#}", dotenv_scan_paths(dir.path()).unwrap_err());
        assert!(message.contains(".phantom.toml"), "unexpected refusal text");
        assert!(message.contains("non-symlink"), "unexpected refusal text");
    }

    /// A `.phantom.toml` symlink to another project's config must not be read:
    /// that file lies outside this project and would choose the scan list.
    #[cfg(unix)]
    #[test]
    fn config_symlink_outside_the_project_is_not_read() {
        use std::os::unix::fs::symlink;
        let outside = tempfile::tempdir().unwrap();
        let mut config = PhantomConfig::new_with_defaults("check-outside".to_string());
        config.phantom.dotenv_path = Some("prod.env".to_string());
        config.save(&outside.path().join(".phantom.toml")).unwrap();

        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("prod.env"), "PORT=3000\n").unwrap();
        symlink(
            outside.path().join(".phantom.toml"),
            dir.path().join(".phantom.toml"),
        )
        .unwrap();
        let message = format!("{:#}", dotenv_scan_paths(dir.path()).unwrap_err());
        assert!(message.contains(".phantom.toml"), "unexpected refusal text");
        assert!(
            !message.contains(&outside.path().display().to_string()),
            "refusal names the outside path"
        );
    }

    /// A FIFO named `.phantom.toml` is refused at once; opening it for a
    /// plain read would block until a writer appeared, hanging the check.
    #[cfg(unix)]
    #[test]
    fn config_fifo_is_refused_without_blocking() {
        let dir = tempfile::tempdir().unwrap();
        let fifo = dir.path().join(".phantom.toml");
        let status = std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .unwrap();
        assert!(status.success(), "mkfifo failed");

        let (send, receive) = std::sync::mpsc::channel();
        let project = dir.path().to_path_buf();
        std::thread::spawn(move || {
            let outcome = dotenv_scan_paths(&project).map_err(|error| format!("{error:#}"));
            let _ = send.send(outcome);
        });
        let outcome = receive.recv_timeout(std::time::Duration::from_secs(5));
        if outcome.is_err() {
            // Release the blocked reader so the test process can finish.
            drop(std::fs::OpenOptions::new().write(true).open(&fifo));
            panic!("dotenv_scan_paths blocked on a FIFO .phantom.toml");
        }
        let message = outcome.unwrap().unwrap_err();
        assert!(message.contains(".phantom.toml"), "unexpected refusal text");
    }

    #[cfg(unix)]
    #[test]
    fn config_directory_is_refused_with_its_name() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join(".phantom.toml")).unwrap();
        let message = format!("{:#}", dotenv_scan_paths(dir.path()).unwrap_err());
        assert!(message.contains(".phantom.toml"), "unexpected refusal text");
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

    /// A `-diff` or `binary` attribute (common for lockfiles, generated
    /// code and `*.pbxproj`) made git print "Binary files differ" with no
    /// `+` lines, so a credential staged in such a file was reported clean.
    #[test]
    fn staged_code_scan_ignores_binary_and_no_diff_attributes() {
        for attributes in ["*.ts -diff\n", "*.ts binary\n", "*.ts -text -diff\n"] {
            let dir = repo_with_staged_credential(&[], "src/app.ts");
            std::fs::write(dir.path().join(".gitattributes"), attributes).unwrap();
            assert_eq!(
                staged_code_labels(dir.path()),
                ["GitHub personal token"],
                "attributes {attributes:?}"
            );
        }
    }

    /// Stage `bytes` at `path` in a fresh repository.
    fn repo_with_staged_bytes(path: &str, bytes: &[u8]) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        git_in(dir.path(), &["init", "-q"]);
        std::fs::write(dir.path().join(path), bytes).unwrap();
        git_in(dir.path(), &["add", "--", path]);
        dir
    }

    fn credential_line() -> Vec<u8> {
        format!("key={}{}\n", "ghp_", "Q7rT2mVx9KpL4wZs8NdY3hBc6FjGu5EaR1oW").into_bytes()
    }

    /// A NUL byte makes git treat a file as binary by content, which hid a
    /// credential beside it from the scan.
    #[test]
    fn staged_code_scan_reads_a_file_git_detects_as_binary() {
        let mut bytes = b"header\0\n".to_vec();
        bytes.extend(credential_line());
        let dir = repo_with_staged_bytes("dump.dat", &bytes);
        assert_eq!(staged_code_labels(dir.path()), ["GitHub personal token"]);
    }

    /// A Latin-1 text file is valid to commit. Its diff is not UTF-8, which
    /// failed the whole hook as indeterminate even though every credential
    /// shape scanned for is ASCII.
    #[test]
    fn staged_code_scan_reads_non_utf8_text() {
        let dir = repo_with_staged_bytes("notes.txt", b"caf\xe9 au lait\n");
        assert!(staged_code_labels(dir.path()).is_empty());
        let mut bytes = b"caf\xe9 au lait\n".to_vec();
        bytes.extend(credential_line());
        let dir = repo_with_staged_bytes("notes.txt", &bytes);
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

    fn git_out(dir: &Path, args: &[&str], stdin: &str) -> String {
        use std::io::Write;
        let mut child = std::process::Command::new("git")
            .current_dir(dir)
            .args(args)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(stdin.as_bytes())
            .unwrap();
        let out = child.wait_with_output().unwrap();
        assert!(out.status.success(), "git {args:?}");
        String::from_utf8(out.stdout).unwrap().trim().to_string()
    }

    /// Stage `path` with `mode` and blob `content` straight into the index,
    /// so symlinks and gitlinks need no filesystem support or submodule.
    fn stage_entry(dir: &Path, mode: &str, content: &str, path: &str) {
        let object = if mode == "160000" {
            // A gitlink names a commit; any 40-hex object name will do.
            "c84e8522009cc00c7dfce17118514b9dc1c58779".to_string()
        } else {
            git_out(dir, &["hash-object", "-w", "--stdin"], content)
        };
        let cacheinfo = format!("{mode},{object},{path}");
        git_in(dir, &["update-index", "--add", "--cacheinfo", &cacheinfo]);
    }

    fn commit_all(dir: &Path) {
        git_in(
            dir,
            &[
                "-c",
                "user.name=Phantom Test",
                "-c",
                "user.email=test@example.invalid",
                "commit",
                "-q",
                "-m",
                "base",
            ],
        );
    }

    #[test]
    fn staged_type_change_to_a_regular_file_is_scanned() {
        // `app.ts` was committed as a symlink and is now staged as a regular
        // file holding a credential: status `T`, which the listing skipped.
        let dir = tempfile::tempdir().unwrap();
        git_in(dir.path(), &["init", "-q"]);
        stage_entry(dir.path(), "120000", "other.ts", "app.ts");
        commit_all(dir.path());
        let line = format!(
            "const key = \"{}{}\";\n",
            "ghp_", "Q7rT2mVx9KpL4wZs8NdY3hBc6FjGu5EaR1oW"
        );
        stage_entry(dir.path(), "100644", &line, "app.ts");
        assert_eq!(staged_code_labels(dir.path()), ["GitHub personal token"]);
    }

    #[test]
    fn staged_type_change_to_a_regular_dotenv_is_scanned() {
        let dir = tempfile::tempdir().unwrap();
        git_in(dir.path(), &["init", "-q"]);
        stage_entry(dir.path(), "120000", "shared/.env", ".env");
        commit_all(dir.path());
        stage_entry(
            dir.path(),
            "100644",
            "OPENAI_API_KEY=example-real-value-xyz\n",
            ".env",
        );
        let (findings, _) = staged_findings(dir.path()).unwrap();
        let names: Vec<_> = findings
            .iter()
            .filter(|finding| finding.kind == "staged_dotenv")
            .filter_map(|finding| finding.name.as_deref())
            .collect();
        assert_eq!(names, ["OPENAI_API_KEY"]);
    }

    #[test]
    fn staged_dotenv_named_symlink_is_not_parsed_as_dotenv() {
        // The staged blob of a symlink is its target path, not dotenv text;
        // parsing it failed the hook on a commit that holds no secret.
        let dir = tempfile::tempdir().unwrap();
        git_in(dir.path(), &["init", "-q"]);
        stage_entry(dir.path(), "120000", "../outside/.env", ".env");
        stage_entry(dir.path(), "120000", "/etc/hostname", ".phantom.toml");
        let (findings, warnings) = staged_findings(dir.path()).unwrap();
        assert!(findings.is_empty());
        assert!(warnings.is_empty());
    }

    #[test]
    fn staged_symlink_target_text_is_still_scanned_as_code() {
        // Skipping dotenv parsing must not hide a credential-shaped target.
        let dir = tempfile::tempdir().unwrap();
        git_in(dir.path(), &["init", "-q"]);
        let target = format!("{}{}", "ghp_", "Q7rT2mVx9KpL4wZs8NdY3hBc6FjGu5EaR1oW");
        stage_entry(dir.path(), "120000", &target, "prod.env");
        assert_eq!(staged_code_labels(dir.path()), ["GitHub personal token"]);
    }

    #[test]
    fn staged_gitlinks_are_skipped_whatever_their_name() {
        // `git show :<gitlink>` has no blob to print; a submodule named like
        // a dotenv or `.phantom.toml` made the hook fail on a clean commit.
        let dir = tempfile::tempdir().unwrap();
        git_in(dir.path(), &["init", "-q"]);
        stage_entry(dir.path(), "160000", "", "vendor.env");
        stage_entry(dir.path(), "160000", "", ".phantom.toml");
        stage_entry(dir.path(), "160000", "", "deps/lib");
        let (findings, warnings) = staged_findings(dir.path()).unwrap();
        assert!(findings.is_empty());
        assert!(warnings.is_empty());
    }

    #[test]
    fn raw_listing_takes_the_destination_of_renames_and_fails_closed() {
        let raw = ":100644 100644 aaaaaaa bbbbbbb R087\0old.ts\0new.ts\0\
                   :000000 120000 0000000 ccccccc A\0link\0";
        let entries = parse_raw_entries(raw).unwrap();
        let got: Vec<_> = entries.iter().map(|e| (e.path.as_str(), e.mode)).collect();
        assert_eq!(
            got,
            [
                ("new.ts", StagedMode::Regular),
                ("link", StagedMode::Symlink)
            ]
        );
        assert!(parse_raw_entries("").unwrap().is_empty());
        for bad in [
            "100644 100644 a b M\0x\0",
            ":100644 100644 a b M\0",
            ":100644 040000 a b M\0x\0",
            ":100644 100644 a b R100\0only-source\0",
            ":100644 100644 a b M\0x\0\0junk",
        ] {
            assert!(parse_raw_entries(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn staged_type_change_from_dotenv_to_symlink_is_not_parsed() {
        let dir = tempfile::tempdir().unwrap();
        git_in(dir.path(), &["init", "-q"]);
        stage_entry(dir.path(), "100644", "NODE_ENV=development\n", ".env");
        commit_all(dir.path());
        stage_entry(dir.path(), "120000", "/etc/hostname", ".env");
        let (findings, _) = staged_findings(dir.path()).unwrap();
        assert!(findings.is_empty());
    }

    /// Assignment lines holding real-looking values, built at runtime so no
    /// credential-shaped literal lives in the source. The database URL and
    /// the signing value carry no prefix the code scan knows.
    fn direnv_assignment_lines() -> String {
        let db_url = format!("postgres://app:{}@db.internal:5432/app", "Vq8rLm2Xz7Kt");
        let signing = ["9f3c1a7e5b", "2d8f4c6a0e", "1b7d3f9a5c"].concat();
        let openai = ["sk", "-proj-", "Q7rT2mVx9KpL4wZs8NdY3hBc"].concat();
        format!(
            "export DATABASE_URL={db_url}\nWEBHOOK_SIGNING={signing}\nexport OPENAI_API_KEY=\"{openai}\"\n"
        )
    }

    fn staged_dotenv_names(cwd: &Path) -> Vec<String> {
        let (findings, _) = staged_findings(cwd).unwrap();
        let mut names: Vec<String> = findings
            .iter()
            .filter(|finding| finding.kind == "staged_dotenv")
            .filter_map(|finding| finding.name.clone())
            .collect();
        names.sort();
        names
    }

    /// A direnv `.envrc` holds the same `export KEY=value` lines as a dotenv
    /// file, mixed with direnv stdlib calls. Its assignments get the same
    /// dotenv classification by name as `.env`, so a database URL or signing
    /// value with no known prefix is no longer committed unreported.
    #[test]
    fn staged_envrc_assignments_are_classified_like_dotenv() {
        let assignments = direnv_assignment_lines();
        let expected = ["DATABASE_URL", "OPENAI_API_KEY", "WEBHOOK_SIGNING"];

        let dotenv = repo_with_staged_bytes(".env", assignments.as_bytes());
        assert_eq!(staged_dotenv_names(dotenv.path()), expected);

        let envrc = format!(
            "use nix\nlayout python\nPATH_add bin\nexport NODE_ENV=development\nPORT=3000\n{assignments}"
        );
        for path in [".envrc", ".envrc.local", "services/api/.envrc"] {
            let dir = tempfile::tempdir().unwrap();
            git_in(dir.path(), &["init", "-q"]);
            let file = dir.path().join(path);
            std::fs::create_dir_all(file.parent().unwrap()).unwrap();
            std::fs::write(&file, &envrc).unwrap();
            git_in(dir.path(), &["add", "--", path]);
            assert_eq!(staged_dotenv_names(dir.path()), expected, "{path}");
        }
    }

    /// direnv is shell: stdlib calls, conditionals, repeated names and values
    /// fetched at load time (`$(op read ...)`, `${VAR}`) are the documented
    /// way to keep credentials out of `.envrc`. None of it is a finding, and
    /// none of it fails the hook as malformed dotenv.
    #[test]
    fn staged_envrc_shell_lines_and_config_are_clean() {
        let envrc = concat!(
            "#!/usr/bin/env bash\n",
            "use flake\n",
            "layout python3\n",
            "PATH_add bin\n",
            "source_env_if_exists .envrc.local\n",
            "dotenv_if_exists .env.local\n",
            "watch_file flake.nix\n",
            "if [ -f .env ]; then\n",
            "  dotenv\n",
            "fi\n",
            "export NODE_ENV=production\n",
            "export PORT=3000\n",
            "export PORT=3001\n",
            "export PATH=\"$PWD/node_modules/.bin:$PATH\"\n",
            "export OPENAI_API_KEY=\"$(op read op://dev/openai/credential)\"\n",
            "export GITHUB_TOKEN=$(gh auth token)\n",
            "export AWS_SECRET_ACCESS_KEY=${AWS_SECRET_ACCESS_KEY:-}\n",
            "export SENTRY_AUTH_TOKEN=`cat ~/.config/sentry`\n",
            "export STRIPE_API_KEY=\n",
        );
        let dir = repo_with_staged_bytes(".envrc", envrc.as_bytes());
        let (findings, _) = staged_findings(dir.path()).unwrap();
        assert!(findings.is_empty(), "{} finding(s)", findings.len());
    }

    /// A credential on a shell line the dotenv parser cannot read is still
    /// caught by the code scan of the staged additions.
    #[test]
    fn staged_envrc_still_gets_the_code_scan() {
        let line = format!(
            "curl -H \"Authorization: {}{}\" https://example.invalid\n",
            "ghp_", "Q7rT2mVx9KpL4wZs8NdY3hBc6FjGu5EaR1oW"
        );
        let dir = repo_with_staged_bytes(".envrc", line.as_bytes());
        assert_eq!(staged_code_labels(dir.path()), ["GitHub personal token"]);
    }

    /// An unclosed quote is a shell typo, not a reason to stop reading: an
    /// assignment after it is still a committed credential. Unterminated to
    /// end of file, and closed by the next line's opening quote (which
    /// swallowed that line into the bad value), both still report.
    #[test]
    fn staged_envrc_assignments_after_an_unclosed_quote_are_reported() {
        let db_url = format!("postgres://app:{}@db.internal:5432/app", "Vq8rLm2Xz7Kt");
        let signing = ["9f3c1a7e5b", "2d8f4c6a0e", "1b7d3f9a5c"].concat();
        let cases = [
            format!("export BANNER=\"welcome\nexport DATABASE_URL={db_url}\n"),
            format!("export BANNER='welcome\nexport DATABASE_URL={db_url}\n"),
            format!("export BANNER=\"welcome\nexport WEBHOOK_SIGNING=\"{signing}\"\n"),
            format!("export BANNER='welcome\nexport WEBHOOK_SIGNING='{signing}'\n"),
        ];
        let expected = [
            ["DATABASE_URL"],
            ["DATABASE_URL"],
            ["WEBHOOK_SIGNING"],
            ["WEBHOOK_SIGNING"],
        ];
        for (index, (envrc, expected)) in cases.iter().zip(expected).enumerate() {
            let dir = repo_with_staged_bytes(".envrc", envrc.as_bytes());
            assert_eq!(staged_dotenv_names(dir.path()), expected, "case {index}");
        }
    }

    /// Single quotes stop the shell expanding anything, so a single-quoted
    /// value that starts with `$` is the literal text committed. Unquoted and
    /// double-quoted `$VAR`, `${VAR}` and `$(cmd)` stay unflagged.
    #[test]
    fn staged_envrc_single_quoted_dollar_values_are_literals() {
        let literal = ["$Kq9vT2", "mXz7Lp4w", "Rs8NdY3h"].concat();
        let hashed = [
            "$argon2id$v=19$m=65536,t=3,p=1$",
            "c2FsdHNhbHQ$",
            "Q7rT2mVx9KpL4wZs8NdY",
        ]
        .concat();
        let envrc = format!(
            "export DB_PASSWORD='{literal}'\nexport ADMIN_PASSWORD_HASH='{hashed}'\n\
             export API_KEY='$(not run)'\nexport OTHER_KEY=\"$OTHER_KEY\"\n\
             export THIRD_KEY=${{THIRD_KEY}}\nexport FOURTH_KEY=$(op read op://dev/x/y)\n"
        );
        let dir = repo_with_staged_bytes(".envrc", envrc.as_bytes());
        assert_eq!(
            staged_dotenv_names(dir.path()),
            ["ADMIN_PASSWORD_HASH", "API_KEY", "DB_PASSWORD"]
        );
    }

    /// Plain `.env` is strict dotenv: an unclosed quote ahead of an
    /// assignment makes the file unreadable, and both `phantom check` and
    /// `--staged` refuse it (a failed check) rather than reporting it clean.
    #[test]
    fn dotenv_with_an_unclosed_quote_fails_closed_staged_and_worktree() {
        let db_url = format!("postgres://app:{}@db.internal:5432/app", "Vq8rLm2Xz7Kt");
        for opener in ["\"", "'"] {
            let content = format!("BANNER={opener}welcome\nDATABASE_URL={db_url}\n");
            let staged = repo_with_staged_bytes(".env", content.as_bytes());
            assert!(staged_findings(staged.path()).is_err(), "staged {opener}");
            let worktree = tempfile::tempdir().unwrap();
            std::fs::write(worktree.path().join(".env"), &content).unwrap();
            assert!(
                worktree_findings(worktree.path()).is_err(),
                "worktree {opener}"
            );
        }
    }

    /// A name assigned more than once (a default, then an override) is one
    /// finding: the report names the key, so a second entry adds nothing.
    #[test]
    fn staged_envrc_repeated_names_are_reported_once() {
        let first = ["9f3c1a7e5b", "2d8f4c6a0e", "1b7d3f9a5c"].concat();
        let second = ["4e8a2c6f0b", "7d1f5b9e3a", "8c2e6a0d4f"].concat();
        let envrc = format!(
            "export WEBHOOK_SIGNING={first}\nif [ -n \"$CI\" ]; then\n  export WEBHOOK_SIGNING={second}\nfi\n"
        );
        let dir = repo_with_staged_bytes(".envrc", envrc.as_bytes());
        assert_eq!(staged_dotenv_names(dir.path()), ["WEBHOOK_SIGNING"]);
    }
}

#[cfg(test)]
mod shared_redact_tests {
    use super::*;
    use crate::commands::redact_corpus;

    #[test]
    fn shared_golden_corpus_preserves_staged_check_labels() {
        for case in redact_corpus::code_families()
            .into_iter()
            .filter(|case| case.staged)
        {
            let findings = code_pattern_findings("fixture.rs", &case.token);
            assert_eq!(findings.len(), 1, "{}", case.label);
            assert_eq!(findings[0].label, Some(case.label));
            assert_eq!(findings[0].pattern, Some(case.prefix));
            let json = serde_json::to_string(&findings).unwrap();
            assert!(!json.contains(&case.token));
        }
        let findings = code_pattern_findings("fixture.rs", &redact_corpus::litellm());
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].label, Some(LITELLM_KEY_LABEL));
    }
}
