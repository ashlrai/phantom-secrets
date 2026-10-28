use crate::commands::upgrade::{detect_install_source, InstallSource};
use anyhow::{Context, Result};
use colored::Colorize;
use phantom_core::dotenv::DotenvFile;
use phantom_core::precommit_hook::{self, HookChange};
use phantom_core::report::{DoctorMcpClient as McpClientState, DoctorReport};
use std::cell::RefCell;
use zeroize::Zeroizing;

fn doctor_can_open_vault(_fix: bool) -> bool {
    // Diagnostics and repository-local repairs must not provision keychain or
    // vault state merely because --fix was supplied. Commands that explicitly
    // operate on the vault perform their own authenticated preflight.
    false
}

fn commit_precommit_repair(project_dir: &std::path::Path) -> Result<Option<HookChange>> {
    let Some(plan) = precommit_hook::prepare_install_plan(project_dir)? else {
        return Ok(None);
    };
    let authorization = if plan.change() != HookChange::Unchanged && plan.authority().is_external()
    {
        precommit_hook::authorize_external_install_from_terminal(project_dir)?
    } else {
        None
    };
    Ok(Some(precommit_hook::commit_prepared_install(
        project_dir,
        &plan,
        authorization.as_ref(),
    )?))
}

type DotenvRepairGuard = (std::path::PathBuf, Option<Zeroizing<Vec<u8>>>);

fn prepare_dotenv_repair_guard(env_path: &std::path::Path) -> Result<DotenvRepairGuard> {
    let before = phantom_core::fs::read_regular_file(env_path)
        .context("Failed to read managed dotenv before doctor repairs")?
        .map(Zeroizing::new);
    if let Some(bytes) = before.as_deref() {
        let text = std::str::from_utf8(bytes).context("Managed dotenv is not valid UTF-8")?;
        DotenvFile::parse_str(text)
            .validate_for_mutation()
            .context("Managed dotenv is malformed; doctor made no repairs")?;
    }
    Ok((env_path.to_path_buf(), before))
}

fn ensure_dotenv_repair_guard(guard: Option<&DotenvRepairGuard>) -> Result<()> {
    let Some((path, expected)) = guard else {
        return Ok(());
    };
    let current = phantom_core::fs::read_regular_file(path)
        .context("Failed to re-read managed dotenv before doctor repair")?;
    let matches = match (expected.as_deref(), current.as_deref()) {
        (Some(expected), Some(current)) => expected == current,
        (None, None) => true,
        _ => false,
    };
    if !matches {
        anyhow::bail!(
            "Managed dotenv changed after doctor preflight; no further repair was attempted"
        );
    }
    Ok(())
}

/// The managed dotenv as the repair guard read it (`None` when it was
/// absent). Repairs derive from these bytes, which
/// [`ensure_dotenv_repair_guard`] re-compares before any write, never from a
/// second read of the path that could follow a swapped-in symlink.
fn guarded_dotenv(guard: Option<&DotenvRepairGuard>) -> Result<Option<DotenvFile>> {
    let Some(bytes) = guard.and_then(|(_, before)| before.as_deref()) else {
        return Ok(None);
    };
    let text = std::str::from_utf8(bytes).context("Managed dotenv is not valid UTF-8")?;
    Ok(Some(DotenvFile::parse_str(text)))
}

/// Report on the managed dotenv (`env_path`, beside `.phantom.toml`) and
/// return the issues found. It is opened without following a symlink and
/// judged on the opened handle, so a linked file is reported, not followed.
fn check_managed_dotenv(project_dir: &std::path::Path, env_path: &std::path::Path) -> usize {
    let name = env_path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(".env");
    let dotenv = match phantom_core::managed_dotenv::parse_regular_dotenv(project_dir, name) {
        Ok(Some(dotenv)) => dotenv,
        Ok(None) => {
            check_info(&format!("No {name} file in current directory"));
            return 0;
        }
        Err(error) => {
            check_fail(&format!("{name} could not be read: {error:#}"));
            // Only to choose the hint; the read above already decided.
            let special = std::fs::symlink_metadata(env_path)
                .is_ok_and(|metadata| metadata.file_type().is_symlink() || !metadata.is_file());
            if special {
                check_fix(&format!(
                    "Replace {name} with a regular file (not a symlink or special file), then rerun phantom doctor"
                ));
            }
            return 1;
        }
    };
    let entries = dotenv.entries();
    let real_secrets = dotenv.real_secret_entries();
    let issues = if let Err(error) = dotenv.validate_for_mutation() {
        check_fail(&format!("{name} parse error: {error}"));
        1
    } else if real_secrets.is_empty() {
        // A commented-out secret below is still plaintext, so no "all
        // protected" pass for the file then.
        if dotenv.commented_secret_assignments().is_empty() {
            check_pass(&format!(
                "{name} has {} entries, all protected",
                entries.len()
            ));
        }
        0
    } else {
        check_warn(&format!(
            "{name} has {} unprotected secret(s): {}",
            real_secrets.len(),
            real_secrets
                .iter()
                .map(|e| e.key.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ));
        check_fix("Run: phantom init");
        1
    };
    issues + check_commented_entries(&dotenv, name)
}

/// One warning per commented-out assignment that still holds a secret.
/// `phantom init` never touches comments, so such a value stays as plaintext
/// in the file. Key names and line numbers only; the file is not changed.
fn check_commented_entries(dotenv: &DotenvFile, file_label: &str) -> usize {
    let found = dotenv.commented_secret_assignments();
    for (key_name, line) in &found {
        check_warn(&format!(
            "{file_label} line {line}: commented-out {key_name} still holds a plaintext secret"
        ));
        check_fix(&format!(
            "Delete line {line} from {file_label}; if the value is still needed, store it under an unused name with `phantom add <NAME> --stdin` (and rotate it if it was ever shared)"
        ));
    }
    found.len()
}

fn doctor_json(report: &DoctorReport) -> Result<String> {
    let pretty = serde_json::to_string_pretty(report)?;
    crate::commands::report_json::with_schema_pretty(
        pretty,
        crate::commands::report_json::DOCTOR_SCHEMA,
    )
}

/// Run the full doctor suite. Pass `check_expiry = true` to also scan secret
/// TTL metadata and warn about expired or soon-to-expire entries.
pub fn run_doctor(fix: bool, check_expiry: bool, json: bool, strict: bool) -> Result<()> {
    if json {
        let report = collect_report(fix, check_expiry)?;
        println!("{}", doctor_json(&report)?);
        exit_if_strict(strict, report.issues);
        return Ok(());
    }
    let (issues, _) = run_checks(fix, check_expiry)?;
    exit_if_strict(strict, issues);
    Ok(())
}

/// `--strict` turns a finished report that still has issues into exit 2
/// ([`crate::commands::report_json::STRICT_ISSUES_FOUND`]).
/// Every issue counts the same: a warning is an issue, with no severity
/// weighting. The report itself is unchanged. Without the flag, issues keep
/// exit 0. Exit 1 stays a command error.
fn exit_if_strict(strict: bool, issues: usize) {
    if strict && issues > 0 {
        std::process::exit(crate::commands::report_json::STRICT_ISSUES_FOUND);
    }
}

/// `phantom doctor --output <path>`: write the full report (text, or JSON
/// with `--json`) to a new file and print a short summary.
pub fn run_doctor_to_file(
    fix: bool,
    check_expiry: bool,
    json: bool,
    strict: bool,
    path: &std::path::Path,
) -> Result<()> {
    let report = collect_report(fix, check_expiry)?;
    let body = if json {
        doctor_json(&report)? + "\n"
    } else {
        render_text(&report)
    };
    crate::report_file::write_new(path, body.as_bytes())?;
    println!("{}", summary_line(&report, path));
    exit_if_strict(strict, report.issues);
    Ok(())
}

fn summary_line(report: &DoctorReport, path: &std::path::Path) -> String {
    let count = |s: &str| report.checks.iter().filter(|c| c.status == s).count();
    format!(
        "Doctor: {} issue(s); {} checks ({} fail, {} warn). Full report: {}",
        report.issues,
        report.checks.len(),
        count("fail"),
        count("warn"),
        path.display()
    )
}

/// Plain-text form of the report, one line per check, no colors.
fn render_text(report: &DoctorReport) -> String {
    let mut out = String::from("Phantom Doctor\n\n");
    for c in &report.checks {
        out.push_str(&format!("  {:<5} {}\n", c.status, c.message));
        if let Some(fix) = &c.fix {
            out.push_str(&format!("        Fix: {fix}\n"));
        }
        if let Some(fixed) = &c.fixed {
            out.push_str(&format!("        Fixed: {fixed}\n"));
        }
    }
    if !report.mcp_clients.is_empty() {
        out.push_str("\nMCP clients:\n");
        for m in &report.mcp_clients {
            out.push_str(&format!("  {} {} ({})\n", m.client, m.state, m.path));
        }
    }
    out.push_str(&format!(
        "\n{} issue(s), {} fixed\n",
        report.issues, report.fixed
    ));
    out
}

/// Run the checks and return the structured report instead of printing it.
/// Used by `phantom doctor --json` and the combined `phantom doctor --all`.
pub fn collect_report(fix: bool, check_expiry: bool) -> Result<DoctorReport> {
    REPORT.with(|report| *report.borrow_mut() = Some(DoctorReport::default()));
    let outcome = run_checks(fix, check_expiry);
    let taken = REPORT.with(|report| report.borrow_mut().take());
    let (issues, fixed) = outcome?;
    let mut report = taken.unwrap_or_default();
    report.ok = issues == 0;
    report.issues = issues;
    report.fixed = fixed;
    Ok(report)
}

fn run_checks(fix: bool, check_expiry: bool) -> Result<(usize, usize)> {
    let project_dir = crate::util::project_dir()?;
    let config_path = project_dir.join(".phantom.toml");
    // A managed dotenv that cannot be resolved (missing, a symlink, two
    // token-bearing candidates) is a finding for diagnosis. Repairs need a
    // resolved file, so --fix still stops before any of them.
    let mut unresolved_dotenv = None;
    // A config that exists but cannot be read or parsed is not "no config":
    // the managed dotenv it names is unknown, so doctor reports the dotenv
    // as unchecked instead of judging `./.env`, and --fix makes no repairs.
    let (loaded_config, config_error) = match crate::util::load_config_if_present(&config_path) {
        Ok(config) => (config, None),
        Err(error) if fix => {
            return Err(anyhow::Error::new(error).context(
                ".phantom.toml exists but could not be loaded; doctor --fix made no repairs. Fix or restore it, then run `phantom doctor`",
            ))
        }
        Err(error) => (None, Some(error)),
    };
    let config_broken = config_error.is_some();
    let env_path = match loaded_config.as_ref() {
        Some(config) => {
            match phantom_core::managed_dotenv::resolve_dotenv(&project_dir, config, &[]) {
                Ok(resolved) => resolved.path,
                Err(error) if !fix => {
                    unresolved_dotenv = Some(error);
                    project_dir.join(".env")
                }
                Err(error) => {
                    return Err(error.context(
                        "The managed dotenv could not be resolved; doctor --fix made no repairs. Run `phantom doctor` to see the finding",
                    ))
                }
            }
        }
        None => project_dir.join(".env"),
    };
    let repair_dotenv_guard = fix
        .then(|| prepare_dotenv_repair_guard(&env_path))
        .transpose()?;
    let mut issues = 0;
    let mut fixed = 0;
    // A doctor invocation publishes at most one local repair. This prevents a
    // later failure from stranding an earlier unrelated file mutation without
    // a cross-file rollback contract. Re-running --fix advances the next item.
    let mut mutation_applied = false;

    human(|| {
        println!("{}", "Phantom Doctor".bold().underline());
        println!();
    });

    // Check 1: .phantom.toml exists
    // Judge the config read above, never a second read through the path: a
    // symlink is refused there and must not be followed here.
    let config_check = match (loaded_config.as_ref(), config_error.as_ref()) {
        (Some(config), _) => Some(Ok(config)),
        (None, Some(error)) => Some(Err(error)),
        (None, None) => None,
    };
    if let Some(config_check) = config_check {
        check_pass(".phantom.toml found");
        match config_check {
            Ok(config) => {
                check_pass(&format!(
                    "Config valid (project: {})",
                    config
                        .portable_project_id()
                        .get(..8)
                        .unwrap_or(config.portable_project_id())
                ));

                let service_risks = config.service_risks();
                // The same check `phantom exec` and `phantom start` refuse on,
                // so their pointer at doctor always lands on a finding.
                let launch_blocker = config.exec_route_blocker();
                if let Some(blocker) = launch_blocker {
                    check_fail(&launch_blocker_message(&blocker));
                    check_fix(
                        "Restore Phantom's built-in definition for that service (or remove the custom service) in a trusted terminal; `phantom why <KEY> --json` shows the same blocker",
                    );
                    issues += 1;
                }
                if service_risks.is_empty() {
                    if launch_blocker.is_none() {
                        check_pass("Service routes look safe");
                    }
                } else {
                    for risk in &service_risks {
                        check_warn(&format!(
                            "Service route `{}`: {}",
                            risk.service, risk.message
                        ));
                    }
                    check_fix(
                        "Review .phantom.toml service mappings before running untrusted code",
                    );
                    issues += service_risks.len();
                }

                // Opening a backend can provision keychain/file state. Only an
                // explicitly gated --fix run may do that; plain doctor is
                // repository-local and non-provisioning.
                if doctor_can_open_vault(fix) {
                    let vault = phantom_vault::try_create_vault(config.local_project_id())?;
                    check_pass(&format!("Vault backend: {}", vault.backend_name()));
                    match vault.list() {
                        Ok(names)
                            if names.is_empty() && vault.backend_name() != "encrypted-file" =>
                        {
                            match phantom_vault::locked_file_vault_notice(config.local_project_id())
                            {
                                Some(notice) => {
                                    check_warn(&notice);
                                    issues += 1;
                                }
                                None => check_pass("0 secret(s) in vault"),
                            }
                        }
                        Ok(names) => check_pass(&format!("{} secret(s) in vault", names.len())),
                        Err(e) => {
                            check_fail(&format!("Vault access failed: {e}"));
                            issues += 1;
                        }
                    }
                } else {
                    check_info("Vault backend and inventory not opened in read-only doctor mode");
                    if let Some(notice) =
                        phantom_vault::locked_file_vault_notice(config.local_project_id())
                    {
                        check_warn(&notice);
                        issues += 1;
                    }
                }

                // Check sync targets
                if !config.sync.is_empty() {
                    check_pass(&format!("{} sync target(s) configured", config.sync.len()));
                } else {
                    check_info("No sync targets configured");
                    check_fix("Add to .phantom.toml: [[sync]] platform = \"vercel\" project_id = \"your-id\"");
                }
            }
            Err(e) => {
                check_fail(&format!("Config parse error: {e}"));
                check_fix(
                    "Fix or restore .phantom.toml (for example from version control), then rerun phantom doctor",
                );
                issues += 1;
            }
        }
    } else {
        check_warn("No .phantom.toml found");
        check_fix("Run: phantom init");
        issues += 1;
    }

    // Check 3: .env file
    match unresolved_dotenv {
        None if config_broken => {
            check_warn(
                "Managed dotenv not checked: .phantom.toml could not be loaded, so which dotenv it manages is unknown",
            );
        }
        Some(error) => {
            check_fail(&format!("Managed dotenv: {error:#}"));
            check_fix(
                "Restore the managed dotenv as a regular file beside .phantom.toml, or rerun `phantom init --from <file>` to choose it",
            );
            issues += 1;
        }
        None => issues += check_managed_dotenv(&project_dir, &env_path),
    }

    // Check 4: .gitignore, judged for the managed dotenv's own name.
    let dotenv_name = env_path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(".env");
    let gitignore_path = project_dir.join(".gitignore");
    let gitignore_before = phantom_core::fs::read_regular_file(&gitignore_path)
        .map_err(|error| anyhow::anyhow!("Refusing unsafe .gitignore target: {error}"))?;
    if let Some(bytes) = gitignore_before.as_deref() {
        let content = String::from_utf8(bytes.to_vec())
            .map_err(|_| anyhow::anyhow!("Refusing to rewrite non-UTF-8 .gitignore"))?;
        let state = phantom_core::gitignore::dotenv_ignore_state(&content, dotenv_name);
        if state == phantom_core::gitignore::DotenvIgnore::Ignored {
            check_pass(&format!("{dotenv_name} is in .gitignore"));
        } else {
            if state == phantom_core::gitignore::DotenvIgnore::Negated {
                check_warn(&format!(
                    "{dotenv_name} is un-ignored by a later `!` rule in .gitignore — secrets could be committed!"
                ));
            } else {
                check_warn(&format!(
                    "{dotenv_name} is NOT in .gitignore — secrets could be committed!"
                ));
            }
            // Git applies the last matching rule, so an appended name also
            // overrides an earlier negation.
            check_fix(&format!("Run: echo '{dotenv_name}' >> .gitignore"));
            if fix && !mutation_applied {
                ensure_dotenv_repair_guard(repair_dotenv_guard.as_ref())?;
                let mut c = content;
                if !c.ends_with('\n') {
                    c.push('\n');
                }
                c.push_str(dotenv_name);
                c.push('\n');
                write_project_file_exact(
                    &project_dir,
                    &gitignore_path,
                    gitignore_before.as_deref(),
                    c.as_bytes(),
                )?;
                check_fixed(&format!("Added {dotenv_name} to .gitignore"));
                fixed += 1;
                mutation_applied = true;
            } else {
                issues += 1;
            }
        }
    } else {
        check_warn("No .gitignore — consider adding one");
        check_fix("Run: phantom doctor --fix (creates .gitignore with .env patterns)");
        if fix && !mutation_applied {
            ensure_dotenv_repair_guard(repair_dotenv_guard.as_ref())?;
            let mut body = String::from(".env\n.env.local\n.env.*.local\n.env.backup\n");
            if phantom_core::gitignore::dotenv_ignore_state(&body, dotenv_name)
                != phantom_core::gitignore::DotenvIgnore::Ignored
            {
                body.push_str(dotenv_name);
                body.push('\n');
            }
            write_project_file_exact(&project_dir, &gitignore_path, None, body.as_bytes())?;
            check_fixed("Created .gitignore with .env patterns");
            fixed += 1;
            mutation_applied = true;
        } else {
            issues += 1;
        }
    }

    // Check 5: .env.example exists
    let example_path = project_dir.join(".env.example");
    let example_before = phantom_core::fs::read_regular_file(&example_path)
        .map_err(|error| anyhow::anyhow!("Refusing unsafe .env.example target: {error}"))?;
    if example_before.is_some() {
        check_pass(".env.example found (team onboarding ready)");
    } else {
        check_warn("No .env.example — team onboarding may be difficult");
        check_fix("Run: phantom env");
        if fix && !mutation_applied {
            if let Some(dotenv) = guarded_dotenv(repair_dotenv_guard.as_ref())? {
                let content = dotenv
                    .generate_example_content(loaded_config.as_ref())
                    .context("Managed dotenv is malformed; doctor made no .env.example repair")?;
                ensure_dotenv_repair_guard(repair_dotenv_guard.as_ref())?;
                write_project_file_exact(
                    &project_dir,
                    &example_path,
                    example_before.as_deref(),
                    content.as_bytes(),
                )?;
                check_fixed("Generated .env.example");
                fixed += 1;
                mutation_applied = true;
            } else {
                issues += 1;
            }
        } else if fix {
            issues += 1; // Can't fix without .env
        } else {
            issues += 1;
        }
    }

    // Check 6: Claude Code permissions. MCP registrations belong in .mcp.json
    // and are checked separately below; legacy settings entries are ineffective.
    let claude_settings = project_dir.join(".claude/settings.local.json");
    if claude_settings.exists() {
        let content = std::fs::read_to_string(&claude_settings)?;
        let parsed = serde_json::from_str::<serde_json::Value>(&content);
        if parsed.is_err() {
            // An unparseable settings file is not "no legacy grants": the
            // checks below could not run, so this is a finding, never a pass.
            check_warn(
                "Claude Code settings (.claude/settings.local.json) could not be parsed; dotenv read grants and legacy MCP entries were not checked",
            );
            check_fix(
                "Fix the JSON in .claude/settings.local.json (or remove the file), then rerun phantom doctor",
            );
            issues += 1;
        }
        if let Ok(parsed) = parsed {
            if parsed["mcpServers"].get("phantom").is_some() {
                check_warn(
                    "Claude Code Phantom MCP entry is in legacy settings; move it to .mcp.json",
                );
                check_fix("Run: phantom setup --client claude");
                issues += 1;
            }
            let has_legacy_allow = parsed["permissions"]["allow"]
                .as_array()
                .is_some_and(|rules| {
                    rules.iter().any(|value| {
                        matches!(value.as_str(), Some("Read(./.env)" | "Read(./.env.*)"))
                    })
                });
            if has_legacy_allow {
                check_warn("Legacy dotenv read allow grants are configured");
                check_fix("Run: phantom setup");
                issues += 1;
            } else {
                check_pass("Claude Code dotenv read grants remain closed");
            }

            if let Some(deny_arr) = parsed["permissions"]["deny"].as_array() {
                let has_env_deny = deny_arr
                    .iter()
                    .any(|v| v.as_str().is_some_and(|s| s.contains(".env")));
                if has_env_deny {
                    check_pass("Claude Code dotenv deny rules preserved");
                }
            }
        }
    } else {
        check_info("No Claude Code config — run `phantom setup` for auto-mode");
    }

    // Check 7: Cloud auth
    match phantom_core::auth::load_token() {
        Some(_) => {
            check_pass("Cloud: logged in (token stored in keychain)");
        }
        None => {
            check_info("Cloud: not logged in — run `phantom login` for cloud sync");
        }
    }

    // Check 8: Pre-commit hook. This is the last gated repair, so its branches
    // need not set `mutation_applied`; a repair added after it must do so.
    match precommit_hook::inspect(&project_dir)? {
        precommit_hook::HookState::Present {
            content,
            executable,
            ..
        } if precommit_hook::is_ready(&content, executable) => {
            check_pass("Git pre-commit hook runs the local Phantom check first");
        }
        precommit_hook::HookState::Present {
            content,
            executable,
            ..
        } => {
            if precommit_hook::is_current(&content) && !executable {
                check_warn("Git pre-commit hook is not executable");
                check_fix("Run: phantom doctor --fix (repairs hook permissions)");
            } else if precommit_hook::has_phantom_block(&content) {
                check_warn("Git pre-commit hook uses a stale Phantom check");
                check_fix("Run: phantom doctor --fix (uses the installed local binary)");
            } else {
                check_warn("Git pre-commit hook exists but no phantom check");
                check_fix("Run: phantom init (will add a local Phantom check to the hook)");
            }
            if fix && !mutation_applied {
                ensure_dotenv_repair_guard(repair_dotenv_guard.as_ref())?;
                let change = commit_precommit_repair(&project_dir)?
                    .expect("Git hook state already established a repository");
                let message = match change {
                    HookChange::Installed => {
                        "Installed local Phantom check before existing hook commands"
                    }
                    HookChange::Repaired => "Repaired stale Phantom pre-commit hook",
                    HookChange::Unchanged => "Phantom pre-commit hook already current",
                };
                check_fixed(message);
                fixed += 1;
            } else {
                issues += 1;
            }
        }
        precommit_hook::HookState::Missing { .. } => {
            check_warn("No pre-commit hook installed");
            check_fix("Run: phantom init (will install a local Phantom check)");
            if fix && !mutation_applied {
                ensure_dotenv_repair_guard(repair_dotenv_guard.as_ref())?;
                commit_precommit_repair(&project_dir)?;
                check_fixed("Installed pre-commit hook");
                fixed += 1;
            } else {
                issues += 1;
            }
        }
        precommit_hook::HookState::NotRepository => {
            check_info("Not a git repo — pre-commit hook not applicable");
        }
    }

    // Check 9: README mentions Phantom
    let readme_path = project_dir.join("README.md");
    if readme_path.exists() {
        let content = std::fs::read_to_string(&readme_path).unwrap_or_default();
        if content.to_lowercase().contains("phantom")
            || content.to_lowercase().contains("## secrets")
        {
            check_pass("README.md mentions Phantom/secrets setup");
        } else {
            check_info("README.md doesn't mention Phantom");
            check_fix("Run: phantom init (will offer to add Secrets section)");
        }
    }

    // ── New informational rows ────────────────────────────────────────────────

    // Check 10: Install source
    {
        let label = match detect_install_source() {
            InstallSource::Npm => "npm (phantom-secrets package)",
            InstallSource::Homebrew => "Homebrew",
            InstallSource::Cargo => "Cargo (cargo install)",
            InstallSource::Direct => "direct checksum-verifying installer",
            InstallSource::Curl => "legacy standalone installer (~/.local/bin)",
            InstallSource::LegacySharedRoot => "ambiguous legacy shared installer root",
            InstallSource::Unknown => "unknown",
        };
        check_info(&format!("Install source: {label}"));
    }

    // Check 11: Vault backend (informational — also shown inline above when
    // config exists, but surfaced unconditionally here so it's always visible)
    {
        if doctor_can_open_vault(fix) {
            if let Some(config) = loaded_config.as_ref() {
                let vault = phantom_vault::try_create_vault(config.local_project_id())?;
                check_info(&format!("Vault backend: {}", vault.backend_name()));
            } else {
                check_info("Vault backend: n/a (no .phantom.toml)");
            }
        } else {
            check_info("Vault backend: not opened (read-only doctor mode)");
        }
    }

    // Check 11b: Proxy upstream TLS key exchange groups (read from the
    // proxy's provider config; what is negotiated depends on each upstream).
    check_info(&super::pq_report::proxy_tls_doctor_line());

    // Check 12: Audit logging
    {
        if phantom_core::audit::AuditEventEncryption::from_env()
            == phantom_core::audit::AuditEventEncryption::CloudSigned
        {
            check_warn(
                "Cloud-signed audit delivery is not commissioned; legacy requests stay encrypted in the local audit log and perform no network I/O",
            );
            check_fix("Set PHANTOM_AUDIT_ENCRYPTION=local or unset it");
            issues += 1;
        }

        if phantom_core::audit::enabled() {
            match phantom_core::audit::log_path() {
                // Not followed: a symlink or non-regular file at the log
                // path is refused by every audit reader and writer.
                Ok(path) => match std::fs::symlink_metadata(&path) {
                    Ok(meta) if !meta.is_file() => {
                        check_warn(&format!(
                            "Audit log is a symlink or not a regular file and will be refused: {}",
                            path.display()
                        ));
                        check_fix("Remove it so Phantom can create a private audit log");
                        issues += 1;
                    }
                    Ok(meta) => {
                        let bytes = meta.len();
                        let size_str = if bytes >= 1024 {
                            format!("{} KiB", bytes / 1024)
                        } else {
                            format!("{bytes} B")
                        };
                        check_info(&format!(
                            "Audit log: enabled — {} ({})",
                            path.display(),
                            size_str
                        ));
                    }
                    Err(_) => {
                        check_info(&format!(
                            "Audit log: enabled — {} (not yet created)",
                            path.display()
                        ));
                    }
                },
                Err(_) => {
                    check_info("Audit log: enabled (log path unresolvable — HOME not set?)");
                }
            }
        } else {
            check_info("Audit log: disabled (set PHANTOM_AUDIT=1 to enable)");
        }
    }

    // Check 13: Argon2 parameters
    {
        use phantom_vault::crypto::{ARGON2_M_COST_KIB, ARGON2_P_COST, ARGON2_T_COST};
        check_info(&format!(
            "Argon2id params: m={} MiB, t={}, p={} (OWASP balanced)",
            ARGON2_M_COST_KIB / 1024,
            ARGON2_T_COST,
            ARGON2_P_COST,
        ));
    }

    // Check 14 (optional): Validation metadata — surface invalid credentials
    {
        if doctor_can_open_vault(fix) {
            if let Some(config) = loaded_config.as_ref() {
                let vault = phantom_vault::try_create_vault(config.local_project_id())?;
                if let Ok(names) = vault.list() {
                    let mut invalid_count = 0usize;
                    let mut stale_count = 0usize;
                    let mut unchecked_count = 0usize;
                    let mut unreadable_count = 0usize;
                    let mut first_read_error = None;
                    for name in &names {
                        // A read error is not "never checked": the state is
                        // unknown, the same rule as phantom_validate_secret.
                        let meta = match vault.get_validation_metadata(name) {
                            Ok(meta) => meta,
                            Err(error) => {
                                unreadable_count += 1;
                                first_read_error.get_or_insert_with(|| error.to_string());
                                continue;
                            }
                        };
                        if meta.never_checked() {
                            // Not yet validated — not an issue, just informational.
                            unchecked_count += 1;
                        } else if !meta.is_valid {
                            invalid_count += 1;
                            let reason = meta.failure_reason.as_deref().unwrap_or("unknown reason");
                            check_fail(&format!("Secret '{}' FAILED validation: {}", name, reason));
                            check_fix("Run: phantom validate --check-all (then rotate if needed)");
                            issues += 1;
                        } else if meta.is_stale(phantom_core::validator::DEFAULT_STALE_SECS) {
                            stale_count += 1;
                        }
                    }
                    if let Some(error) = first_read_error {
                        check_warn(&format!(
                            "Validation: stored results for {unreadable_count} secret(s) could not be read; their state is unknown ({error})"
                        ));
                    }
                    if invalid_count == 0 && stale_count == 0 && !names.is_empty() {
                        if unchecked_count == 0 && unreadable_count == 0 {
                            check_pass("All secrets passed last validation check");
                        } else if unchecked_count > 0 {
                            check_info(
                            "Validation: run `phantom validate --check-all` to check credential health",
                        );
                        }
                    } else if stale_count > 0 {
                        check_info(&format!(
                            "Validation: {} secret(s) have stale check results (>24 h old)",
                            stale_count
                        ));
                        check_fix("Run: phantom validate --check-all");
                    }
                }
            }
        } else {
            check_info("Validation metadata not read in non-provisioning doctor mode");
        }
    }

    // Check 15 (optional): Secret TTL / expiry status
    if check_expiry && doctor_can_open_vault(fix) {
        if let Some(config) = loaded_config.as_ref() {
            let vault = phantom_vault::try_create_vault(config.local_project_id())?;
            match vault.list_with_metadata() {
                Ok(entries) => {
                    let mut expired = Vec::new();
                    let mut expiring_soon = Vec::new();
                    let mut tracked = 0usize;

                    for (name, meta) in &entries {
                        if let Some(m) = meta {
                            if m.expires_at.is_some() {
                                tracked += 1;
                                if m.is_expired() {
                                    expired.push((name.clone(), m.ttl_status()));
                                } else if m.is_expiring_soon(7) {
                                    expiring_soon.push((name.clone(), m.ttl_status()));
                                }
                            }
                        }
                    }

                    if expired.is_empty() && expiring_soon.is_empty() {
                        if tracked == 0 {
                            check_info("Expiry: no secrets have TTL configured");
                            check_info(
                                "  Tip: phantom rotate --with-expiry 90 to set a 90-day TTL",
                            );
                        } else {
                            check_pass(&format!(
                                "Expiry: {tracked}/{} secret(s) have TTL — all healthy",
                                entries.len()
                            ));
                        }
                    } else {
                        for (name, status) in &expired {
                            check_fail(&format!("Secret '{}' is {}", name, status));
                            issues += 1;
                        }
                        for (name, status) in &expiring_soon {
                            check_warn(&format!("Secret '{}': {}", name, status));
                            check_fix("Run: phantom rotate --with-expiry <days>");
                            issues += 1;
                        }
                    }
                }
                Err(e) => {
                    check_warn(&format!("Could not read expiry metadata: {e}"));
                }
            }
        }
    } else if check_expiry {
        check_info("Expiry metadata not read in non-provisioning doctor mode");
    }

    // Check 13b: LiteLLM routed through Phantom (report-only, never --fix)
    for finding in super::doctor_litellm::findings(&project_dir) {
        let msg = finding.message();
        if finding.is_warning() {
            issues += 1;
            check_warn(&msg);
            if let Some(fix) = finding.fix() {
                check_fix(fix);
            }
        } else {
            check_info(&msg);
        }
    }

    // Check 14: MCP setup status per known client
    {
        human(|| {
            println!();
            println!("  {} MCP client wiring:", "info".blue());
        });

        // The same clients `phantom setup --status` reports, in its order.
        let home = phantom_core::home::home_dir_with_platform_fallback().ok();
        for (name, path, global) in
            super::setup_status::client_config_paths(home.as_deref(), &project_dir)
        {
            issues += usize::from(check_mcp_client(name, &path, global));
        }
    }

    human(|| {
        println!();
        if fix && fixed > 0 {
            println!("{} Auto-fixed {} issue(s)", "ok".green().bold(), fixed);
            if issues > 0 {
                println!(
                    "{} Re-run `phantom doctor --fix` to apply the next isolated repair",
                    "next".blue().bold()
                );
            }
        }
        if issues == 0 {
            println!("{} All checks passed!", "ok".green().bold());
        } else {
            println!(
                "{} {} issue(s) found{}",
                "!".yellow().bold(),
                issues,
                if !fix {
                    " — run `phantom doctor --fix` to auto-fix"
                } else {
                    ""
                }
            );
        }
    });

    Ok((issues, fixed))
}

fn write_project_file_exact(
    project_dir: &std::path::Path,
    path: &std::path::Path,
    before: Option<&[u8]>,
    content: &[u8],
) -> Result<()> {
    write_project_file_exact_with(project_dir, path, before, content, || {})
}

fn write_project_file_exact_with(
    project_dir: &std::path::Path,
    path: &std::path::Path,
    before: Option<&[u8]>,
    content: &[u8],
    before_commit: impl FnOnce(),
) -> Result<()> {
    let lock = phantom_vault::acquire_project_transaction_lock(project_dir)?;
    let target = lock.target(path)?;
    let reviewed = target.read_regular()?;
    if reviewed.as_ref().map(phantom_core::fs::AnchoredRead::bytes) != before {
        anyhow::bail!("{} changed after it was inspected", path.display());
    }
    let permissions = reviewed
        .as_ref()
        .map(phantom_core::fs::AnchoredRead::permissions)
        .unwrap_or_else(phantom_core::fs::AnchoredFilePermissions::private);
    before_commit();
    match target.replace_if_exact_with_permissions(reviewed.as_ref(), content, permissions)? {
        phantom_core::fs::AnchoredEffect::Durable(_) => Ok(()),
        phantom_core::fs::AnchoredEffect::CommittedVerifiedButDurabilityUncertain { .. } => {
            eprintln!(
                "warning: {} was replaced and verified, but directory crash durability is not provable on this platform",
                path.display()
            );
            Ok(())
        }
        phantom_core::fs::AnchoredEffect::CommittedButUncertain { error, .. } => {
            anyhow::bail!(
                "{} was replaced, but durability could not be verified: {error}",
                path.display()
            )
        }
    }
}

/// Check whether a known MCP client config has a canonical local executable.
/// Returns true for a present-but-unsafe or unreadable Phantom configuration.
fn check_mcp_client(name: &str, path: &std::path::Path, global: bool) -> bool {
    let location = if global {
        phantom_core::home::display_home_relative(path)
    } else {
        path.display().to_string()
    };

    if path.exists() {
        let content = match std::fs::read_to_string(path) {
            Ok(content) => content,
            Err(error) => {
                mcp_client(name, &location, "unreadable", || {
                    println!(
                        "       {} {} config cannot be read safely: {} ({})",
                        "FAIL".red().bold(),
                        name,
                        error,
                        location.dimmed()
                    )
                });
                return true;
            }
        };
        if phantom_core::agent::mcp_config_has_local_runtime(path) {
            mcp_client(name, &location, "local_runtime", || {
                println!(
                    "       {} {} uses a local Phantom executable ({})",
                    "ok".green(),
                    name,
                    location.dimmed()
                )
            });
            false
        } else if content.contains("phantom") {
            mcp_client(name, &location, "stale", || {
                println!(
                    "       {} {} Phantom entry is stale or network-capable ({})",
                    "warn".yellow(),
                    name,
                    location.dimmed()
                );
                if <super::setup::Client as clap::ValueEnum>::from_str(name, true).is_ok() {
                    println!(
                        "          {} phantom setup --client {}",
                        "Fix:".dimmed(),
                        name
                    )
                } else {
                    println!(
                        "          {} point its phantom MCP entry at the local phantom-mcp binary",
                        "Fix:".dimmed()
                    )
                }
            });
            true
        } else {
            mcp_client(name, &location, "not_phantom", || {
                println!(
                    "       {} {} config exists but no phantom MCP ({})",
                    "--".dimmed(),
                    name,
                    location.dimmed()
                )
            });
            false
        }
    } else {
        mcp_client(name, &location, "not_configured", || {
            println!(
                "       {} {} not configured ({})",
                "--".dimmed(),
                name,
                location.dimmed()
            )
        });
        false
    }
}

/// Doctor's line for the route that stops `phantom exec` and `phantom start`.
fn launch_blocker_message(blocker: &phantom_core::config::ExecBlocker<'_>) -> String {
    use phantom_core::config::ExecBlocker;
    match blocker {
        ExecBlocker::AlteredBuiltinRoute { service } => format!(
            "Launch blocked: service `{service}` differs from Phantom's built-in route (host pattern, header, header_format, secret_key or secret_type); phantom exec and start refuse to launch until it matches"
        ),
        other => format!(
            "Launch blocked: service `{}` is a custom proxy route; phantom exec and start refuse to launch with it and run only with Phantom's built-in routes",
            other.service()
        ),
    }
}

thread_local! {
    /// `Some` while `phantom doctor --json` collects lines instead of printing.
    static REPORT: RefCell<Option<DoctorReport>> = const { RefCell::new(None) };
}

/// Run `print` only for the human report.
fn human(print: impl FnOnce()) {
    if REPORT.with(|report| report.borrow().is_none()) {
        print();
    }
}

fn record(status: &'static str, msg: &str, print: impl FnOnce()) {
    REPORT.with(|report| match report.borrow_mut().as_mut() {
        Some(report) => report.push(status, msg),
        None => print(),
    });
}

fn mcp_client(name: &str, location: &str, state: &'static str, print: impl FnOnce()) {
    REPORT.with(|report| match report.borrow_mut().as_mut() {
        Some(report) => report.mcp_clients.push(McpClientState {
            client: name.to_string(),
            path: location.to_string(),
            state,
        }),
        None => print(),
    });
}

fn check_pass(msg: &str) {
    record("pass", msg, || println!("  {} {}", "pass".green(), msg));
}

fn check_fail(msg: &str) {
    record("fail", msg, || {
        println!("  {} {}", "FAIL".red().bold(), msg)
    });
}

fn check_warn(msg: &str) {
    record("warn", msg, || println!("  {} {}", "warn".yellow(), msg));
}

fn check_info(msg: &str) {
    record("info", msg, || println!("  {} {}", "info".blue(), msg));
}

fn check_fix(msg: &str) {
    REPORT.with(|report| match report.borrow_mut().as_mut() {
        Some(report) => report.attach_fix(msg),
        None => println!("       {} {}", "Fix:".dimmed(), msg.dimmed()),
    });
}

fn check_fixed(msg: &str) {
    REPORT.with(|report| match report.borrow_mut().as_mut() {
        Some(report) => report.attach_fixed(msg),
        None => println!("       {} {}", "Fixed:".green(), msg),
    });
}

#[cfg(test)]
mod tests {
    use super::{precommit_hook, HookChange};
    use crate::commands::upgrade::{
        detect_install_source, detect_install_source_from, InstallSource,
    };
    use std::path::Path;

    /// Smoke test — detect_install_source() must be stable across two calls.
    #[test]
    fn install_source_is_stable() {
        let a = detect_install_source();
        let b = detect_install_source();
        assert_eq!(a, b);
    }

    #[test]
    fn homebrew_paths_detected() {
        for path in [
            "/usr/local/Cellar/phantom/1.0/bin/phantom",
            "/opt/homebrew/bin/phantom",
            "/home/linuxbrew/.linuxbrew/bin/phantom",
        ] {
            assert_eq!(
                detect_install_source_from(Path::new(path), None),
                InstallSource::Homebrew
            );
        }
    }

    #[test]
    fn cargo_path_detected() {
        assert_eq!(
            detect_install_source_from(
                Path::new("/home/user/.cargo/bin/phantom"),
                Some(Path::new("/home/user")),
            ),
            InstallSource::Cargo
        );
    }

    #[test]
    fn read_only_doctor_never_opens_a_vault_backend() {
        assert!(!super::doctor_can_open_vault(false));
        assert!(!super::doctor_can_open_vault(true));
    }

    #[test]
    fn doctor_repair_guard_rejects_dotenv_drift() {
        let project = tempfile::tempdir().unwrap();
        let env_path = project.path().join(".env");
        std::fs::write(&env_path, b"API_KEY=phm_before\n").unwrap();
        let guard = super::prepare_dotenv_repair_guard(&env_path).unwrap();
        std::fs::write(&env_path, b"BROKEN_RECORD\n").unwrap();

        let error = super::ensure_dotenv_repair_guard(Some(&guard)).unwrap_err();

        assert!(error.to_string().contains("changed after doctor preflight"));
        assert!(!project.path().join(".gitignore").exists());
    }

    /// Run `check_managed_dotenv` with the JSON report capturing its lines.
    /// One captured doctor line: status, message, fix hint.
    type CheckLine = (&'static str, String, Option<String>);

    fn dotenv_check_lines(project: &Path) -> (usize, Vec<CheckLine>) {
        dotenv_check_lines_for(project, ".env")
    }

    fn dotenv_check_lines_for(project: &Path, name: &str) -> (usize, Vec<CheckLine>) {
        super::REPORT.with(|report| {
            *report.borrow_mut() = Some(phantom_core::report::DoctorReport::default())
        });
        let issues = super::check_managed_dotenv(project, &project.join(name));
        let report = super::REPORT
            .with(|report| report.borrow_mut().take())
            .unwrap();
        let lines = report
            .checks
            .into_iter()
            .map(|check| (check.status, check.message, check.fix))
            .collect();
        (issues, lines)
    }

    /// A `.phantom.toml` symlink to a config outside the project used to be
    /// followed by check 1: doctor reported that config as valid and judged
    /// its services, although exec, sync and --fix refuse it.
    #[cfg(unix)]
    #[test]
    fn config_symlink_outside_the_project_is_not_judged_as_valid() {
        let outside = tempfile::tempdir().unwrap();
        phantom_core::config::PhantomConfig::new_with_defaults("doctor-outside".to_string())
            .save(&outside.path().join(".phantom.toml"))
            .unwrap();
        let project = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(
            outside.path().join(".phantom.toml"),
            project.path().join(".phantom.toml"),
        )
        .unwrap();
        let _seam = crate::util::test_seam::TestProject::install(
            project.path().to_path_buf(),
            crate::util::test_seam::empty_keychain,
        );

        let report = super::collect_report(false, false).unwrap();

        assert!(
            !report
                .checks
                .iter()
                .any(|check| check.message.starts_with("Config valid")),
            "doctor judged the symlinked config as valid"
        );
        assert!(
            report.checks.iter().any(|check| check.status == "fail"
                && check.message.contains(crate::util::CONFIG_NOT_REGULAR)),
            "doctor did not report the symlinked config as refused"
        );
    }

    #[cfg(unix)]
    #[test]
    fn dotenv_check_reports_a_symlink_without_reading_its_target() {
        let project = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let target = outside.path().join("elsewhere.env");
        std::fs::write(&target, format!("OPENAI_API_KEY={}-outside\n", "sk")).unwrap();
        std::os::unix::fs::symlink(&target, project.path().join(".env")).unwrap();

        let (issues, lines) = dotenv_check_lines(project.path());

        assert_eq!(issues, 1);
        assert_eq!(lines.len(), 1, "{lines:?}");
        assert_eq!(lines[0].0, "fail");
        assert!(lines[0].1.contains("not a regular, non-symlink file"));
        assert!(!lines[0].1.contains("OPENAI_API_KEY"));
        let fix = lines[0].2.as_deref().expect("a symlink gets a fix hint");
        assert!(fix.contains("Replace .env with a regular file"), "{fix}");
    }

    #[test]
    fn dotenv_check_reads_a_regular_file_and_notes_an_absent_one() {
        let project = tempfile::tempdir().unwrap();
        let (issues, lines) = dotenv_check_lines(project.path());
        assert_eq!((issues, lines[0].0), (0, "info"));

        std::fs::write(
            project.path().join(".env"),
            format!("OPENAI_API_KEY={}-inside\n", "sk"),
        )
        .unwrap();
        let (issues, lines) = dotenv_check_lines(project.path());
        assert_eq!((issues, lines[0].0), (1, "warn"));
        assert!(lines[0].1.contains("OPENAI_API_KEY"));
        assert_eq!(lines[0].2.as_deref(), Some("Run: phantom init"));
    }

    /// A project managing `.env.local` (`phantom init --from .env.local`) was
    /// told about ".env" in every line of this check, a file it may not have.
    #[test]
    fn dotenv_check_names_the_managed_file() {
        let project = tempfile::tempdir().unwrap();
        let (_, lines) = dotenv_check_lines_for(project.path(), ".env.local");
        assert_eq!(lines[0].1, "No .env.local file in current directory");

        std::fs::write(
            project.path().join(".env.local"),
            format!("OPENAI_API_KEY={}-inside\n", "sk"),
        )
        .unwrap();
        let (_, lines) = dotenv_check_lines_for(project.path(), ".env.local");
        assert!(
            lines[0]
                .1
                .starts_with(".env.local has 1 unprotected secret(s)"),
            "{lines:?}"
        );

        std::fs::write(project.path().join(".env.local"), "PORT=3000\n").unwrap();
        let (_, lines) = dotenv_check_lines_for(project.path(), ".env.local");
        assert_eq!(lines[0].1, ".env.local has 1 entries, all protected");

        std::fs::write(project.path().join(".env.local"), "BROKEN_RECORD\n").unwrap();
        let (_, lines) = dotenv_check_lines_for(project.path(), ".env.local");
        assert!(
            lines[0].1.starts_with(".env.local parse error"),
            "{lines:?}"
        );
    }

    #[test]
    fn dotenv_check_names_commented_out_secrets_by_key_and_line() {
        // init protects live entries only; a commented-out credential stays
        // as plaintext in .env, so doctor names it (key and line, no value).
        let project = tempfile::tempdir().unwrap();
        let old = ["sk", "-proj-", "D0ct0rC0mmentedValue0123456789abcdef"].concat();
        let alt = ["ghp", "_", "D0ct0rC0mmentedGitHub0123456789abcde"].concat();
        std::fs::write(
            project.path().join(".env"),
            format!(
                "PORT=3000\n# OPENAI_API_KEY={old}\n# PORT=8080\n# export GITHUB_TOKEN=\"{alt}\"\n"
            ),
        )
        .unwrap();

        let (issues, lines) = dotenv_check_lines(project.path());

        assert_eq!(issues, 2, "{lines:?}");
        assert_eq!(lines.len(), 2, "{lines:?}");
        assert!(lines.iter().all(|line| line.0 != "pass"), "{lines:?}");
        for (line, (key, number)) in lines
            .iter()
            .zip([("OPENAI_API_KEY", 2), ("GITHUB_TOKEN", 4)])
        {
            assert_eq!(line.0, "warn");
            assert!(line.1.contains(key), "{line:?}");
            assert!(line.1.contains(&format!("line {number}")), "{line:?}");
            let fix = line
                .2
                .as_deref()
                .expect("a commented secret gets a fix hint");
            assert!(fix.contains("phantom add"), "{fix}");
        }
        let rendered = format!("{lines:?}");
        assert!(!rendered.contains(&old) && !rendered.contains(&alt));
    }

    /// Run doctor's checks on a project whose config `edit` changes and
    /// return the collected report.
    fn doctor_report_for(
        edit: impl FnOnce(&mut phantom_core::config::PhantomConfig),
    ) -> (
        phantom_core::config::PhantomConfig,
        phantom_core::report::DoctorReport,
    ) {
        let project = tempfile::tempdir().unwrap();
        let dir = project.path().canonicalize().unwrap();
        let mut config =
            phantom_core::config::PhantomConfig::new_with_defaults("doctor-route".to_string());
        edit(&mut config);
        config.save(&dir.join(".phantom.toml")).unwrap();
        let _seam = crate::util::test_seam::TestProject::install(
            dir.clone(),
            crate::util::test_seam::empty_keychain,
        );
        super::REPORT.with(|report| {
            *report.borrow_mut() = Some(phantom_core::report::DoctorReport::default())
        });
        let outcome = super::run_checks(false, false);
        let report = super::REPORT
            .with(|report| report.borrow_mut().take())
            .unwrap();
        outcome.expect("doctor must report, not abort");
        (config, report)
    }

    /// A `.claude/settings.local.json` that does not parse was skipped with no
    /// row and no issue, so doctor could end with "All checks passed!" while
    /// the dotenv read-grant check never ran. It is now a counted warning.
    #[test]
    fn doctor_counts_unparseable_claude_settings_as_an_issue() {
        let run = |settings: Option<&str>| {
            let project = tempfile::tempdir().unwrap();
            let dir = project.path().canonicalize().unwrap();
            phantom_core::config::PhantomConfig::new_with_defaults("doctor-claude".to_string())
                .save(&dir.join(".phantom.toml"))
                .unwrap();
            if let Some(text) = settings {
                std::fs::create_dir_all(dir.join(".claude")).unwrap();
                std::fs::write(dir.join(".claude/settings.local.json"), text).unwrap();
            }
            let _seam = crate::util::test_seam::TestProject::install(
                dir.clone(),
                crate::util::test_seam::empty_keychain,
            );
            super::REPORT.with(|report| {
                *report.borrow_mut() = Some(phantom_core::report::DoctorReport::default())
            });
            let outcome = super::run_checks(false, false);
            let report = super::REPORT
                .with(|report| report.borrow_mut().take())
                .unwrap();
            let (issues, _) = outcome.expect("doctor must report, not abort");
            (issues, report)
        };

        let (baseline, _) = run(Some("{}"));
        let (issues, report) = run(Some("{\"permissions\": {\"allow\": [\"Read(./.env)\"]},"));
        assert_eq!(issues, baseline + 1);
        let line = report
            .checks
            .iter()
            .find(|check| check.message.contains("settings.local.json"))
            .expect("unparseable Claude settings must be a finding");
        assert_eq!(line.status, "warn");
        assert!(line.message.contains("could not be parsed"));
        assert!(line.fix.is_some());
        assert!(!report
            .checks
            .iter()
            .any(|check| check.message == "Claude Code dotenv read grants remain closed"));
    }

    /// exec and start refuse an altered built-in or a custom `api_key` route
    /// and point at `phantom doctor`. Doctor used to check host patterns
    /// only, so a header change or a custom service on a public host printed
    /// "Service routes look safe" while exec refused. It now reports the
    /// same blocker exec uses.
    #[test]
    fn doctor_names_every_route_exec_refuses() {
        type Edit = fn(&mut phantom_core::config::PhantomConfig);
        let cases: [(&str, Edit, &str); 2] = [
            (
                "openai",
                |config| {
                    config.services.get_mut("openai").unwrap().header =
                        Some("X-Api-Key".to_string());
                },
                "differs from Phantom's built-in route",
            ),
            (
                "gateway",
                |config| {
                    config.services.insert(
                        "gateway".to_string(),
                        phantom_core::config::ServiceConfig {
                            secret_key: "GATEWAY_API_KEY".to_string(),
                            pattern: Some("api.gateway.example.com".to_string()),
                            header: Some("Authorization".to_string()),
                            header_format: Some("Bearer {secret}".to_string()),
                            ..config.services["openai"].clone()
                        },
                    );
                },
                "custom proxy route",
            ),
        ];
        for (service, edit, expected) in cases {
            let (config, report) = doctor_report_for(edit);

            let refusal = format!(
                "{:#}",
                super::super::exec::validate_routes_for_launch(&config).unwrap_err()
            );
            assert!(refusal.contains("phantom doctor"), "{refusal}");

            assert!(
                !report
                    .checks
                    .iter()
                    .any(|check| check.message == "Service routes look safe"),
                "{service}: doctor called routes safe while exec refuses"
            );
            let line = report
                .checks
                .iter()
                .find(|check| check.message.contains(&format!("`{service}`")))
                .unwrap_or_else(|| panic!("{service}: doctor has no finding for the route"));
            assert_eq!(line.status, "fail", "{service}");
            assert!(line.message.contains(expected), "{}", line.message);
            assert!(line.message.contains("refuse"), "{}", line.message);
            assert!(line.fix.as_deref().unwrap().contains("phantom why"));
        }

        let (_, report) = doctor_report_for(|_| {});
        assert!(report
            .checks
            .iter()
            .any(|check| check.message == "Service routes look safe"));
    }

    /// `phantom doctor` aborted with the raw resolver error when the
    /// configured managed dotenv was missing: the diagnostic failed on the
    /// state it exists to diagnose. It now reports it as a failed check with a
    /// fix, and `--fix` still stops before any repair.
    #[test]
    fn doctor_reports_a_missing_managed_dotenv_instead_of_aborting() {
        let project = tempfile::tempdir().unwrap();
        let dir = project.path().canonicalize().unwrap();
        let mut config =
            phantom_core::config::PhantomConfig::new_with_defaults("doctor-missing".to_string());
        config.phantom.dotenv_path = Some(".env".to_string());
        config.save(&dir.join(".phantom.toml")).unwrap();
        let _seam = crate::util::test_seam::TestProject::install(
            dir.clone(),
            crate::util::test_seam::empty_keychain,
        );

        super::REPORT.with(|report| {
            *report.borrow_mut() = Some(phantom_core::report::DoctorReport::default())
        });
        let outcome = super::run_checks(false, false);
        let report = super::REPORT
            .with(|report| report.borrow_mut().take())
            .unwrap();
        let (issues, _) = outcome.expect("doctor must report, not abort");
        assert!(issues >= 1);
        let line = report
            .checks
            .iter()
            .find(|check| check.message.starts_with("Managed dotenv:"))
            .expect("the missing dotenv is a finding");
        assert_eq!(line.status, "fail");
        assert!(
            line.message.contains("does not exist: .env"),
            "{}",
            line.message
        );
        assert!(line.fix.as_deref().unwrap().contains("phantom init --from"));

        super::REPORT.with(|report| {
            *report.borrow_mut() = Some(phantom_core::report::DoctorReport::default())
        });
        let error = super::run_checks(true, false).unwrap_err();
        super::REPORT.with(|report| report.borrow_mut().take());
        assert!(
            format!("{error:#}").contains("made no repairs"),
            "{error:#}"
        );
        assert!(!dir.join(".gitignore").exists());
    }

    /// A `.phantom.toml` that exists but does not parse read as "no config"
    /// for the dotenv check and repairs: doctor judged `./.env` and `--fix`
    /// wrote `.gitignore` and `.env.example` from it. Doctor now reports the
    /// broken config with a next step, leaves the managed dotenv unchecked,
    /// and `--fix` makes no repairs.
    #[test]
    fn doctor_reports_a_broken_config_and_fix_makes_no_repairs() {
        let project = tempfile::tempdir().unwrap();
        let dir = project.path().canonicalize().unwrap();
        std::fs::write(dir.join(".phantom.toml"), "[phantom\nversion = ").unwrap();
        std::fs::write(dir.join(".env"), "APP_NAME=demo\n").unwrap();
        let _seam = crate::util::test_seam::TestProject::install(
            dir.clone(),
            crate::util::test_seam::empty_keychain,
        );

        super::REPORT.with(|report| {
            *report.borrow_mut() = Some(phantom_core::report::DoctorReport::default())
        });
        let outcome = super::run_checks(false, false);
        let report = super::REPORT
            .with(|report| report.borrow_mut().take())
            .unwrap();
        let (issues, _) = outcome.expect("doctor must report, not abort");
        assert!(issues >= 1);
        let line = report
            .checks
            .iter()
            .find(|check| check.message.starts_with("Config parse error"))
            .expect("the broken config is a finding");
        assert_eq!(line.status, "fail");
        assert!(line.fix.as_deref().unwrap().contains("Fix or restore"));
        assert!(
            !report
                .checks
                .iter()
                .any(|check| check.message.starts_with(".env has")
                    || check.message.starts_with("No .env file")),
            "doctor judged ./.env while the managed dotenv is unknown"
        );
        assert!(report.checks.iter().any(|check| check.status == "warn"
            && check.message.starts_with("Managed dotenv not checked")));

        super::REPORT.with(|report| {
            *report.borrow_mut() = Some(phantom_core::report::DoctorReport::default())
        });
        let error = super::run_checks(true, false).unwrap_err();
        super::REPORT.with(|report| report.borrow_mut().take());
        assert!(format!("{error:#}").contains("made no repairs"));
        assert!(!dir.join(".gitignore").exists());
        assert!(!dir.join(".env.example").exists());
    }

    /// Doctor judged `.gitignore` by one literal `.env` line: `/.env` and
    /// `.env*` (which Git honours) drew a warning, and a later `!.env` (which
    /// un-ignores it) passed.
    #[test]
    fn gitignore_check_follows_git_rules_not_one_literal_line() {
        let cases: [(&str, &str, &str); 4] = [
            ("/.env\n", "pass", ".env is in .gitignore"),
            (".env*\n", "pass", ".env is in .gitignore"),
            (".env\n!.env\n", "warn", ".env is un-ignored"),
            ("node_modules\n", "warn", ".env is NOT in .gitignore"),
        ];
        for (body, status, message) in cases {
            let project = tempfile::tempdir().unwrap();
            let dir = project.path().canonicalize().unwrap();
            std::fs::write(dir.join(".gitignore"), body).unwrap();
            let _seam = crate::util::test_seam::TestProject::install(
                dir.clone(),
                crate::util::test_seam::empty_keychain,
            );

            super::REPORT.with(|report| {
                *report.borrow_mut() = Some(phantom_core::report::DoctorReport::default())
            });
            let outcome = super::run_checks(false, false);
            let report = super::REPORT
                .with(|report| report.borrow_mut().take())
                .unwrap();
            outcome.expect("doctor must report, not abort");
            let line = report
                .checks
                .iter()
                .find(|check| check.message.contains(".gitignore"))
                .unwrap_or_else(|| panic!("no .gitignore finding for {body:?}"));
            assert_eq!(line.status, status, "{body:?}: {}", line.message);
            assert!(
                line.message.starts_with(message),
                "{body:?}: {}",
                line.message
            );
            assert_eq!(
                std::fs::read_to_string(dir.join(".gitignore")).unwrap(),
                body
            );
        }
    }

    /// Doctor judged `.gitignore` for a literal `.env` even when
    /// `.phantom.toml` manages another file: an unignored `.env.production`
    /// passed because `.env` was listed, and `--fix` appended `.env`.
    #[test]
    fn gitignore_check_uses_the_managed_dotenv_name() {
        let project = tempfile::tempdir().unwrap();
        let dir = project.path().canonicalize().unwrap();
        let mut config =
            phantom_core::config::PhantomConfig::new_with_defaults("doctor-name".to_string());
        config.phantom.dotenv_path = Some(".env.production".to_string());
        config.save(&dir.join(".phantom.toml")).unwrap();
        std::fs::write(dir.join(".env.production"), b"PORT=3000\n").unwrap();
        std::fs::write(dir.join(".gitignore"), b".env\n").unwrap();
        let _seam = crate::util::test_seam::TestProject::install(
            dir.clone(),
            crate::util::test_seam::empty_keychain,
        );

        for fix in [false, true] {
            super::REPORT.with(|report| {
                *report.borrow_mut() = Some(phantom_core::report::DoctorReport::default())
            });
            let outcome = super::run_checks(fix, false);
            let report = super::REPORT
                .with(|report| report.borrow_mut().take())
                .unwrap();
            outcome.expect("doctor must report, not abort");
            let line = report
                .checks
                .iter()
                .find(|check| check.message.contains(".gitignore"))
                .expect("a .gitignore finding");
            assert!(
                line.message
                    .starts_with(".env.production is NOT in .gitignore"),
                "{}",
                line.message
            );
            assert_eq!(
                line.fixed.as_deref(),
                fix.then_some("Added .env.production to .gitignore")
            );
        }
        assert_eq!(
            std::fs::read_to_string(dir.join(".gitignore")).unwrap(),
            ".env\n.env.production\n"
        );
    }

    /// The `.env.example` repair derives from the bytes the guard read, not a
    /// second read of the path: a swap to a symlink afterwards is not followed
    /// (and the guard's re-check refuses the write).
    #[cfg(unix)]
    #[test]
    fn example_repair_uses_the_guarded_bytes_not_a_reread() {
        let project = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let target = outside.path().join("elsewhere.env");
        std::fs::write(&target, "OUTSIDE_ONLY=1\n").unwrap();
        let env_path = project.path().join(".env");
        std::fs::write(&env_path, b"API_KEY=phm_before\n").unwrap();
        let guard = super::prepare_dotenv_repair_guard(&env_path).unwrap();
        std::fs::remove_file(&env_path).unwrap();
        std::os::unix::fs::symlink(&target, &env_path).unwrap();

        let dotenv = super::guarded_dotenv(Some(&guard)).unwrap().unwrap();
        let keys: Vec<_> = dotenv.entries().iter().map(|e| e.key.clone()).collect();
        assert_eq!(keys, ["API_KEY"]);
        assert!(super::ensure_dotenv_repair_guard(Some(&guard)).is_err());

        let absent = tempfile::tempdir().unwrap();
        let guard = super::prepare_dotenv_repair_guard(&absent.path().join(".env")).unwrap();
        assert!(super::guarded_dotenv(Some(&guard)).unwrap().is_none());
    }

    #[test]
    fn exact_doctor_write_preserves_concurrent_owner() {
        let project = tempfile::tempdir().unwrap();
        let target = project.path().join(".gitignore");
        std::fs::write(&target, b"before\n").unwrap();
        let before = phantom_core::fs::read_regular_file(&target)
            .unwrap()
            .unwrap();
        std::fs::write(&target, b"concurrent\n").unwrap();

        assert!(super::write_project_file_exact(
            project.path(),
            &target,
            Some(&before),
            b"phantom\n"
        )
        .is_err());
        assert_eq!(std::fs::read(target).unwrap(), b"concurrent\n");
    }

    #[cfg(unix)]
    #[test]
    fn exact_doctor_write_refuses_symlink_target() {
        use std::os::unix::fs::symlink;

        let project = tempfile::tempdir().unwrap();
        let owner = project.path().join("owner");
        let target = project.path().join(".gitignore");
        std::fs::write(&owner, b"owner").unwrap();
        symlink(&owner, &target).unwrap();

        assert!(
            super::write_project_file_exact(project.path(), &target, None, b"phantom").is_err()
        );
        assert_eq!(std::fs::read(owner).unwrap(), b"owner");
    }

    #[cfg(unix)]
    #[test]
    fn exact_doctor_write_uses_retained_root_after_rename() {
        let container = tempfile::tempdir().unwrap();
        let project = container.path().join("project");
        let moved = container.path().join("moved");
        std::fs::create_dir(&project).unwrap();
        let target = project.join(".gitignore");
        std::fs::write(&target, b"before\n").unwrap();

        super::write_project_file_exact_with(
            &project,
            &target,
            Some(b"before\n"),
            b"after\n",
            || {
                std::fs::rename(&project, &moved).unwrap();
                std::fs::create_dir(&project).unwrap();
                std::fs::write(project.join(".gitignore"), b"decoy\n").unwrap();
            },
        )
        .unwrap();

        assert_eq!(std::fs::read(moved.join(".gitignore")).unwrap(), b"after\n");
        assert_eq!(
            std::fs::read(project.join(".gitignore")).unwrap(),
            b"decoy\n"
        );
    }

    #[test]
    fn doctor_hook_repair_uses_exact_hook_plan_without_project_lock() {
        let project = tempfile::tempdir().unwrap();
        assert!(std::process::Command::new("git")
            .args(["init", "--quiet"])
            .current_dir(project.path())
            .status()
            .unwrap()
            .success());
        let hook = project.path().join(".git/hooks/pre-commit");
        std::fs::write(&hook, "#!/bin/sh\necho stale\n").unwrap();

        assert_eq!(
            super::commit_precommit_repair(project.path()).unwrap(),
            Some(HookChange::Installed)
        );
        assert!(precommit_hook::is_current(
            &std::fs::read_to_string(hook).unwrap()
        ));

        let source = include_str!("doctor.rs");
        let helper = source
            .split("fn commit_precommit_repair")
            .nth(1)
            .unwrap()
            .split("/// Run the full doctor suite")
            .next()
            .unwrap();
        assert!(helper.contains("prepare_install_plan"));
        assert!(helper.contains("authorize_external_install_from_terminal"));
        assert!(helper.contains("commit_prepared_install"));
        assert!(!helper.contains("acquire_project_transaction_lock"));
    }
}
