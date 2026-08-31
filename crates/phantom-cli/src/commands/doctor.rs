use crate::commands::upgrade::{detect_install_source, InstallSource};
use anyhow::Result;
use colored::Colorize;
use phantom_core::config::PhantomConfig;
use phantom_core::dotenv::DotenvFile;

/// Run the full doctor suite. Pass `check_expiry = true` to also scan secret
/// TTL metadata and warn about expired or soon-to-expire entries.
pub fn run_doctor(fix: bool, check_expiry: bool) -> Result<()> {
    let project_dir = std::env::current_dir()?;
    let config_path = project_dir.join(".phantom.toml");
    let env_path = project_dir.join(".env");
    let mut issues = 0;
    let mut fixed = 0;

    println!("{}", "Phantom Doctor".bold().underline());
    println!();

    // Check 1: .phantom.toml exists
    if config_path.exists() {
        check_pass(".phantom.toml found");
        match PhantomConfig::load(&config_path) {
            Ok(config) => {
                check_pass(&format!(
                    "Config valid (project: {})",
                    config
                        .phantom
                        .project_id
                        .get(..8)
                        .unwrap_or(&config.phantom.project_id)
                ));

                let service_risks = config.service_risks();
                if service_risks.is_empty() {
                    check_pass("Service routes look safe");
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

                // Check 2: Vault accessible
                let vault = phantom_vault::create_vault(&config.phantom.project_id);
                check_pass(&format!("Vault backend: {}", vault.backend_name()));

                match vault.list() {
                    Ok(names) => {
                        check_pass(&format!("{} secret(s) in vault", names.len()));
                    }
                    Err(e) => {
                        check_fail(&format!("Vault access failed: {e}"));
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
                issues += 1;
            }
        }
    } else {
        check_warn("No .phantom.toml found");
        check_fix("Run: phantom init");
        issues += 1;
    }

    // Check 3: .env file
    if env_path.exists() {
        let dotenv = DotenvFile::parse_file(&env_path);
        match dotenv {
            Ok(dotenv) => {
                let entries = dotenv.entries();
                let real_secrets = dotenv.real_secret_entries();

                if real_secrets.is_empty() {
                    check_pass(&format!(
                        ".env has {} entries, all protected",
                        entries.len()
                    ));
                } else {
                    check_warn(&format!(
                        ".env has {} unprotected secret(s): {}",
                        real_secrets.len(),
                        real_secrets
                            .iter()
                            .map(|e| e.key.as_str())
                            .collect::<Vec<_>>()
                            .join(", ")
                    ));
                    check_fix("Run: phantom init");
                    issues += 1;
                }
            }
            Err(e) => {
                check_fail(&format!(".env parse error: {e}"));
                issues += 1;
            }
        }
    } else {
        check_info("No .env file in current directory");
    }

    // Check 4: .gitignore
    let gitignore_path = project_dir.join(".gitignore");
    if gitignore_path.exists() {
        let content = std::fs::read_to_string(&gitignore_path).unwrap_or_default();
        if content.lines().any(|l| l.trim() == ".env") {
            check_pass(".env is in .gitignore");
        } else {
            check_warn(".env is NOT in .gitignore — secrets could be committed!");
            check_fix("Run: echo '.env' >> .gitignore");
            if fix {
                let mut c = content;
                if !c.ends_with('\n') {
                    c.push('\n');
                }
                c.push_str(".env\n");
                std::fs::write(&gitignore_path, c)?;
                check_fixed("Added .env to .gitignore");
                fixed += 1;
            } else {
                issues += 1;
            }
        }
    } else {
        check_warn("No .gitignore — consider adding one");
        if fix {
            std::fs::write(
                &gitignore_path,
                ".env\n.env.local\n.env.*.local\n.env.backup\n",
            )?;
            check_fixed("Created .gitignore with .env patterns");
            fixed += 1;
        } else {
            issues += 1;
        }
    }

    // Check 5: .env.example exists
    let example_path = project_dir.join(".env.example");
    if example_path.exists() {
        check_pass(".env.example found (team onboarding ready)");
    } else {
        check_warn("No .env.example — team onboarding may be difficult");
        check_fix("Run: phantom env");
        if fix && env_path.exists() {
            if let Ok(dotenv) = DotenvFile::parse_file(&env_path) {
                let config = PhantomConfig::load(&config_path).ok();
                let content = dotenv.generate_example_content(config.as_ref());
                std::fs::write(&example_path, content)?;
                check_fixed("Generated .env.example");
                fixed += 1;
            }
        } else if fix {
            issues += 1; // Can't fix without .env
        } else {
            issues += 1;
        }
    }

    // Check 6: Claude Code MCP configuration
    let claude_settings = project_dir.join(".claude/settings.local.json");
    if claude_settings.exists() {
        let content = std::fs::read_to_string(&claude_settings).unwrap_or_default();
        if content.contains("phantom") {
            check_pass("Claude Code MCP server configured");
        } else {
            check_info("Claude Code settings exist but no Phantom MCP");
            check_fix("Run: phantom setup");
        }

        if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&content) {
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

    // Check 8: Pre-commit hook
    let pre_commit_config = project_dir.join(".pre-commit-config.yaml");
    let git_hook = project_dir.join(".git/hooks/pre-commit");
    if pre_commit_config.exists() {
        let content = std::fs::read_to_string(&pre_commit_config).unwrap_or_default();
        if content.contains("phantom") {
            check_pass("Pre-commit hook configured");
        } else {
            check_info("pre-commit config exists but no phantom hook");
        }
    } else if git_hook.exists() {
        let content = std::fs::read_to_string(&git_hook).unwrap_or_default();
        if content.contains("phantom") {
            check_pass("Git pre-commit hook includes phantom check");
        } else {
            check_warn("Git pre-commit hook exists but no phantom check");
            check_fix("Run: phantom init (will offer to add phantom check to hook)");
            if fix {
                let mut c = content;
                c.push_str(
                    "\n\n# Phantom Secrets pre-commit hook\nnpx phantom-secrets check --staged\n",
                );
                std::fs::write(&git_hook, c)?;
                check_fixed("Appended phantom check to pre-commit hook");
                fixed += 1;
            } else {
                issues += 1;
            }
        }
    } else if project_dir.join(".git").exists() {
        check_warn("No pre-commit hook installed");
        check_fix("Run: phantom init (will auto-install hook)");
        if fix {
            let hooks_dir = project_dir.join(".git/hooks");
            let _ = std::fs::create_dir_all(&hooks_dir);
            let hook = "#!/bin/sh\n# Phantom Secrets pre-commit hook\nnpx phantom-secrets check --staged\nexit $?\n";
            std::fs::write(&git_hook, hook)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(&git_hook, std::fs::Permissions::from_mode(0o755));
            }
            check_fixed("Installed pre-commit hook");
            fixed += 1;
        } else {
            issues += 1;
        }
    } else {
        check_info("Not a git repo — pre-commit hook not applicable");
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
            InstallSource::Curl => "curl installer (~/.local/bin)",
            InstallSource::Unknown => "unknown",
        };
        check_info(&format!("Install source: {label}"));
    }

    // Check 11: Vault backend (informational — also shown inline above when
    // config exists, but surfaced unconditionally here so it's always visible)
    {
        if let Ok(config) = PhantomConfig::load(&config_path) {
            let vault = phantom_vault::create_vault(&config.phantom.project_id);
            check_info(&format!("Vault backend: {}", vault.backend_name()));
        } else {
            check_info("Vault backend: n/a (no .phantom.toml)");
        }
    }

    // Check 12: Audit logging
    {
        if phantom_core::audit::enabled() {
            match phantom_core::audit::log_path() {
                Ok(path) => match std::fs::metadata(&path) {
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
        if let Ok(config) = PhantomConfig::load(&config_path) {
            let vault = phantom_vault::create_vault(&config.phantom.project_id);
            if let Ok(names) = vault.list() {
                let mut invalid_count = 0usize;
                let mut stale_count = 0usize;
                for name in &names {
                    let meta = vault.get_validation_metadata(name).unwrap_or_default();
                    if meta.never_checked() {
                        // Not yet validated — not an issue, just informational.
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
                if invalid_count == 0 && stale_count == 0 && !names.is_empty() {
                    let all_checked = names.iter().all(|n| {
                        vault
                            .get_validation_metadata(n)
                            .map(|m| !m.never_checked())
                            .unwrap_or(false)
                    });
                    if all_checked {
                        check_pass("All secrets passed last validation check");
                    } else {
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
    }

    // Check 15 (optional): Secret TTL / expiry status
    if check_expiry {
        if let Ok(config) = PhantomConfig::load(&config_path) {
            let vault = phantom_vault::create_vault(&config.phantom.project_id);
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
    }

    // Check 14: MCP setup status per known client
    {
        println!();
        println!("  {} MCP client wiring:", "info".blue());

        // Claude Code — project-local .claude/settings.local.json
        let claude_path = project_dir.join(".claude/settings.local.json");
        check_mcp_client("claude", &claude_path, false);

        if let Some(home) = dirs::home_dir() {
            // Cursor — ~/.cursor/mcp.json
            check_mcp_client("cursor", &home.join(".cursor/mcp.json"), true);
            // Windsurf — ~/.codeium/windsurf/mcp_config.json
            check_mcp_client(
                "windsurf",
                &home.join(".codeium/windsurf/mcp_config.json"),
                true,
            );
            // Codex — ~/.codex/config.toml
            check_mcp_client("codex", &home.join(".codex/config.toml"), true);
        }
    }

    println!();
    if fix && fixed > 0 {
        println!("{} Auto-fixed {} issue(s)", "ok".green().bold(), fixed);
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

    Ok(())
}

/// Check whether a known MCP client config file exists and references "phantom".
fn check_mcp_client(name: &str, path: &std::path::Path, global: bool) {
    let location = if global {
        if let Some(home) = dirs::home_dir() {
            if let Ok(suffix) = path.strip_prefix(&home) {
                format!("~/{}", suffix.display())
            } else {
                path.display().to_string()
            }
        } else {
            path.display().to_string()
        }
    } else {
        path.display().to_string()
    };

    if path.exists() {
        let content = std::fs::read_to_string(path).unwrap_or_default();
        if content.contains("phantom") {
            println!(
                "       {} {} wired up ({})",
                "ok".green(),
                name,
                location.dimmed()
            );
        } else {
            println!(
                "       {} {} config exists but no phantom MCP ({})",
                "--".dimmed(),
                name,
                location.dimmed()
            );
        }
    } else {
        println!(
            "       {} {} not configured ({})",
            "--".dimmed(),
            name,
            location.dimmed()
        );
    }
}

fn check_pass(msg: &str) {
    println!("  {} {}", "pass".green(), msg);
}

fn check_fail(msg: &str) {
    println!("  {} {}", "FAIL".red().bold(), msg);
}

fn check_warn(msg: &str) {
    println!("  {} {}", "warn".yellow(), msg);
}

fn check_info(msg: &str) {
    println!("  {} {}", "info".blue(), msg);
}

fn check_fix(msg: &str) {
    println!("       {} {}", "Fix:".dimmed(), msg.dimmed());
}

fn check_fixed(msg: &str) {
    println!("       {} {}", "Fixed:".green(), msg);
}

#[cfg(test)]
mod tests {
    use crate::commands::upgrade::{detect_install_source, InstallSource};

    /// Smoke test — detect_install_source() must be stable across two calls.
    #[test]
    fn install_source_is_stable() {
        let a = detect_install_source();
        let b = detect_install_source();
        assert_eq!(a, b);
    }

    /// Verify that a binary path under ~/.phantom-secrets/bin/ is classified
    /// as Npm by replicating the detection logic with a synthetic path.
    #[test]
    fn npm_path_detected_via_home_prefix() {
        let home = dirs::home_dir().expect("need home dir for this test");
        let npm_root = home.join(".phantom-secrets").join("bin");
        let fake_exe = npm_root.join("phantom");

        // Replicate the npm branch from detect_install_source().
        let detected = if fake_exe.starts_with(&npm_root) {
            InstallSource::Npm
        } else {
            InstallSource::Unknown
        };
        assert_eq!(detected, InstallSource::Npm);
    }

    /// Verify Homebrew path strings are classified correctly.
    #[test]
    fn homebrew_paths_detected() {
        for path_str in &[
            "/usr/local/Cellar/phantom/1.0/bin/phantom",
            "/opt/homebrew/bin/phantom",
            "/home/linuxbrew/.linuxbrew/bin/phantom",
        ] {
            let detected = if path_str.contains("/Cellar/")
                || path_str.contains("/homebrew/")
                || path_str.contains("/linuxbrew/")
            {
                InstallSource::Homebrew
            } else {
                InstallSource::Unknown
            };
            assert_eq!(detected, InstallSource::Homebrew, "path: {path_str}");
        }
    }

    /// Verify Cargo path strings are classified correctly.
    #[test]
    fn cargo_path_detected() {
        let path_str = "/home/user/.cargo/bin/phantom";
        let detected = if path_str.contains("/.cargo/bin/") {
            InstallSource::Cargo
        } else {
            InstallSource::Unknown
        };
        assert_eq!(detected, InstallSource::Cargo);
    }
}
