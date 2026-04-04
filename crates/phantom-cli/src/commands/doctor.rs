use anyhow::Result;
use colored::Colorize;
use phantom_core::config::PhantomConfig;
use phantom_core::dotenv::DotenvFile;

pub fn run(fix: bool) -> Result<()> {
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

        if content.contains("Read(./.env)") {
            check_pass("Claude Code allowed to read .env (phantom tokens only)");
        } else {
            check_warn(".env not in Claude Code allow rules");
            check_fix("Run: phantom setup");
            issues += 1;
        }

        if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&content) {
            if let Some(deny_arr) = parsed["permissions"]["deny"].as_array() {
                let has_env_deny = deny_arr
                    .iter()
                    .any(|v| v.as_str().is_some_and(|s| s.contains(".env")));
                if has_env_deny {
                    check_warn(".env is in deny rules — after phantom init, .env is safe to read");
                    issues += 1;
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
