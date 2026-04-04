use anyhow::{Context, Result};
use colored::Colorize;
use phantom_core::config::{PhantomConfig, ServiceConfig};
use phantom_core::dotenv::{DotenvFile, EnvEntry, SecretClassification};
use phantom_core::token::TokenMap;
use std::collections::BTreeMap;
use std::path::Path;

pub fn run(env_path_arg: &str) -> Result<()> {
    let cwd = std::env::current_dir()?;

    // Auto-detect .env file if the default wasn't found
    let env_path = if Path::new(env_path_arg).exists() {
        std::path::PathBuf::from(env_path_arg)
    } else {
        find_env_file(&cwd, env_path_arg).ok_or_else(|| {
            anyhow::anyhow!(
                "No .env file found.\n\
                 Checked: .env, .env.local, .env.development, .env.development.local\n\
                 (also searched immediate subdirectories)\n\n\
                 Create a .env file with your secrets, or specify one:\n\
                 {}",
                "phantom init --from .env.local".cyan().bold()
            )
        })?
    };

    // Config and project dir are based on where the .env file lives (not cwd)
    // Canonicalize for stable project IDs regardless of which directory user runs from
    let project_dir = env_path.parent().unwrap_or(&cwd).to_path_buf();
    let project_dir = project_dir
        .canonicalize()
        .unwrap_or_else(|_| cwd.join(&project_dir));
    let config_path = project_dir.join(".phantom.toml");

    // Parse .env file
    println!("{} Reading {}...", "->".blue().bold(), env_path.display());
    let dotenv = DotenvFile::parse_file(&env_path).context("Failed to read .env file")?;

    // Classify all entries
    let classified = dotenv.classified_entries();
    let real_entries: Vec<&EnvEntry> = classified
        .iter()
        .filter(|(_, c)| *c == SecretClassification::Secret)
        .map(|(e, _)| *e)
        .collect();
    let public_entries: Vec<&EnvEntry> = classified
        .iter()
        .filter(|(_, c)| *c == SecretClassification::PublicKey)
        .map(|(e, _)| *e)
        .collect();

    if real_entries.is_empty() {
        println!(
            "{} No real secrets found in {} (all values are already phantom tokens, public keys, or config)",
            "!".yellow().bold(),
            env_path.display()
        );
        if !public_entries.is_empty() {
            println!(
                "\n{} {} public key(s) detected (safe for browser bundles, not protected):",
                "->".blue().bold(),
                public_entries.len()
            );
            for entry in &public_entries {
                println!("   {} {}", "·".dimmed(), entry.key);
            }
        }
        return Ok(());
    }

    println!(
        "{} Found {} secret(s) to protect:",
        "->".blue().bold(),
        real_entries.len()
    );
    for entry in &real_entries {
        println!("   {} {}", "+".cyan().bold(), entry.key.bold());
    }

    if !public_entries.is_empty() {
        println!(
            "\n{} Skipping {} public key(s) (safe for browser bundles):",
            "->".blue().bold(),
            public_entries.len()
        );
        for entry in &public_entries {
            println!("   {} {}", "·".dimmed(), entry.key);
        }
        println!("   Override with: {}", "phantom add --force <KEY>".dimmed());
    }

    // Generate project ID and config
    let project_id = PhantomConfig::project_id_from_path(&project_dir);
    let mut config = if config_path.exists() {
        println!("{} Loading existing .phantom.toml", "->".blue().bold());
        PhantomConfig::load(&config_path)?
    } else {
        PhantomConfig::new_with_defaults(project_id.clone())
    };

    // Auto-detect services from key names
    let detected = auto_detect_services(&real_entries, &config);
    for (name, svc) in detected {
        if let std::collections::btree_map::Entry::Vacant(entry) =
            config.services.entry(name.clone())
        {
            println!(
                "   {} Auto-detected service: {} ({})",
                "+".cyan().bold(),
                name.bold(),
                svc.pattern.as_deref().unwrap_or("env var")
            );
            entry.insert(svc);
        }
    }

    // Create vault
    let vault = phantom_vault::create_vault(&config.phantom.project_id);
    println!(
        "{} Using {} vault backend",
        "->".blue().bold(),
        vault.backend_name().cyan()
    );

    // Generate phantom tokens and store real secrets
    let mut token_map = TokenMap::new();
    for entry in &real_entries {
        let token = token_map.insert(entry.key.clone());
        vault
            .store(&entry.key, &entry.value)
            .context(format!("Failed to store secret: {}", entry.key))?;
        println!(
            "   {} {} -> {}",
            "+".green().bold(),
            entry.key.bold(),
            token.as_str()[..12].dimmed()
        );
    }

    // Backup .env before rewriting (safety net against data loss)
    let backup_path = env_path.with_file_name(".env.backup");
    std::fs::copy(&env_path, &backup_path).context("Failed to create .env backup")?;
    println!(
        "   {} Backed up original .env to {}",
        "+".green().bold(),
        backup_path.display()
    );

    // Rewrite .env with phantom tokens
    let _originals = dotenv
        .write_phantomized(&token_map, &env_path)
        .context("Failed to rewrite .env file")?;

    println!(
        "\n{} Rewrote {} with phantom tokens",
        "ok".green().bold(),
        env_path.display()
    );

    // Persist public key classifications
    if !public_entries.is_empty() {
        config.public_keys = public_entries.iter().map(|e| e.key.clone()).collect();
    }

    // Save config
    config.save(&config_path)?;
    println!("{} Saved .phantom.toml", "ok".green().bold());

    // Add .phantom.toml to .gitignore if needed
    ensure_gitignore(&project_dir)?;

    // Generate .env.example for team onboarding
    let example_path = project_dir.join(".env.example");
    let example_content = dotenv.generate_example_content(Some(&config));
    std::fs::write(&example_path, &example_content)?;
    println!(
        "{} Generated {} (commit this for team onboarding)",
        "ok".green().bold(),
        ".env.example".cyan()
    );

    // Install pre-commit hook if in a git repo
    install_precommit_hook(&project_dir);

    println!(
        "\n{} {} secret(s) are now protected!",
        "done".green().bold(),
        real_entries.len()
    );

    // Auto-configure Claude Code if detected (merges phantom setup into init)
    // Check project_dir first, fall back to cwd (repo root) for monorepos
    auto_setup_claude_code(&project_dir, &cwd);

    // Add Phantom instructions to CLAUDE.md so Claude knows how to use it
    auto_add_claude_md(&project_dir, &cwd);

    // Add development setup section to README.md
    auto_add_readme(&project_dir, &cwd);

    // Detect deployment platforms and suggest sync setup
    detect_platforms(&project_dir, &cwd);

    println!(
        "\n{} Run {} to start coding with AI safely.",
        "next".blue().bold(),
        "phantom exec -- <your-command>".cyan().bold()
    );

    Ok(())
}

/// Auto-detect .env files — checks current dir first, then immediate subdirectories.
fn find_env_file(project_dir: &Path, user_specified: &str) -> Option<std::path::PathBuf> {
    let names = [
        user_specified,
        ".env.local",
        ".env",
        ".env.development",
        ".env.development.local",
    ];

    // Check current directory first
    for name in &names {
        let path = project_dir.join(name);
        if path.exists() {
            return Some(path);
        }
    }

    // Scan immediate subdirectories (monorepo support)
    if let Ok(entries) = std::fs::read_dir(project_dir) {
        for entry in entries.flatten() {
            let sub = entry.path();
            if !sub.is_dir() {
                continue;
            }
            // Skip hidden dirs, node_modules, target, etc.
            let dir_name = sub.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if dir_name.starts_with('.')
                || dir_name == "node_modules"
                || dir_name == "target"
                || dir_name == "dist"
                || dir_name == "build"
            {
                continue;
            }
            for name in &names {
                let path = sub.join(name);
                if path.exists() {
                    println!(
                        "{} Found {} in subdirectory {}",
                        "->".blue().bold(),
                        name.bold(),
                        dir_name.cyan()
                    );
                    return Some(path);
                }
            }
        }
    }

    None
}

fn ensure_gitignore(project_dir: &Path) -> Result<()> {
    let gitignore_path = project_dir.join(".gitignore");

    let mut content = if gitignore_path.exists() {
        std::fs::read_to_string(&gitignore_path)?
    } else {
        String::new()
    };

    let mut added = Vec::new();

    // Ensure .phantom.toml is NOT ignored (it contains no secrets, and teammates need it)
    // But ensure .env is ignored
    for pattern in &[".env", ".env.local", ".env.*.local", ".env.backup"] {
        if !content.lines().any(|l| l.trim() == *pattern) {
            if !content.is_empty() && !content.ends_with('\n') {
                content.push('\n');
            }
            content.push_str(pattern);
            content.push('\n');
            added.push(*pattern);
        }
    }

    if !added.is_empty() {
        std::fs::write(&gitignore_path, &content)?;
        println!(
            "{} Added {} to .gitignore",
            "ok".green().bold(),
            added.join(", ")
        );
    }

    Ok(())
}

/// Auto-detect service configurations from .env key names.
fn auto_detect_services(
    entries: &[&EnvEntry],
    existing_config: &PhantomConfig,
) -> BTreeMap<String, ServiceConfig> {
    let mut detected = BTreeMap::new();

    // Map of key name patterns to service configs
    let known_services: Vec<(&str, &str, &str, &str, &str, &str)> = vec![
        // (key_name, service_name, pattern, header, header_format, type)
        (
            "OPENAI_API_KEY",
            "openai",
            "api.openai.com",
            "Authorization",
            "Bearer {secret}",
            "api_key",
        ),
        (
            "ANTHROPIC_API_KEY",
            "anthropic",
            "api.anthropic.com",
            "x-api-key",
            "{secret}",
            "api_key",
        ),
        (
            "STRIPE_SECRET_KEY",
            "stripe",
            "api.stripe.com",
            "Authorization",
            "Bearer {secret}",
            "api_key",
        ),
        (
            "STRIPE_PUBLISHABLE_KEY",
            "stripe_pub",
            "api.stripe.com",
            "Authorization",
            "Bearer {secret}",
            "api_key",
        ),
        (
            "SUPABASE_SERVICE_ROLE_KEY",
            "supabase",
            "supabase.co",
            "Authorization",
            "Bearer {secret}",
            "api_key",
        ),
        (
            "SUPABASE_ANON_KEY",
            "supabase_anon",
            "supabase.co",
            "apikey",
            "{secret}",
            "api_key",
        ),
        (
            "RESEND_API_KEY",
            "resend",
            "api.resend.com",
            "Authorization",
            "Bearer {secret}",
            "api_key",
        ),
        (
            "SENDGRID_API_KEY",
            "sendgrid",
            "api.sendgrid.com",
            "Authorization",
            "Bearer {secret}",
            "api_key",
        ),
        (
            "TWILIO_AUTH_TOKEN",
            "twilio",
            "api.twilio.com",
            "Authorization",
            "Basic {secret}",
            "api_key",
        ),
        (
            "CLOUDFLARE_API_TOKEN",
            "cloudflare",
            "api.cloudflare.com",
            "Authorization",
            "Bearer {secret}",
            "api_key",
        ),
        (
            "GITHUB_TOKEN",
            "github_api",
            "api.github.com",
            "Authorization",
            "Bearer {secret}",
            "api_key",
        ),
        (
            "PINECONE_API_KEY",
            "pinecone",
            "pinecone.io",
            "Api-Key",
            "{secret}",
            "api_key",
        ),
        (
            "REPLICATE_API_TOKEN",
            "replicate",
            "api.replicate.com",
            "Authorization",
            "Bearer {secret}",
            "api_key",
        ),
    ];

    // Connection string patterns
    let conn_string_keys = [
        "DATABASE_URL",
        "REDIS_URL",
        "MONGO_URL",
        "MONGODB_URI",
        "POSTGRES_URL",
        "MYSQL_URL",
        "AMQP_URL",
        "ELASTICSEARCH_URL",
    ];

    for entry in entries {
        // Check known API services
        for (key_name, svc_name, pattern, header, header_format, svc_type) in &known_services {
            if entry.key == *key_name && !existing_config.services.contains_key(*svc_name) {
                detected.insert(
                    svc_name.to_string(),
                    ServiceConfig {
                        secret_key: key_name.to_string(),
                        pattern: Some(pattern.to_string()),
                        header: Some(header.to_string()),
                        header_format: Some(header_format.to_string()),
                        secret_type: svc_type.to_string(),
                    },
                );
            }
        }

        // Check connection strings
        for conn_key in &conn_string_keys {
            if entry.key == *conn_key
                && !existing_config
                    .services
                    .contains_key(&entry.key.to_lowercase())
            {
                detected.insert(
                    entry.key.to_lowercase(),
                    ServiceConfig {
                        secret_key: entry.key.clone(),
                        pattern: None,
                        header: None,
                        header_format: None,
                        secret_type: "connection_string".to_string(),
                    },
                );
            }
        }
    }

    detected
}

/// Auto-configure Claude Code MCP server and .env permissions if Claude Code is detected.
fn auto_setup_claude_code(project_dir: &Path, cwd: &Path) {
    // .claude dir is typically at the repo root, not in a subdirectory
    let claude_dir = if project_dir.join(".claude").exists() {
        project_dir.join(".claude")
    } else if cwd.join(".claude").exists() {
        cwd.join(".claude")
    } else {
        return; // No .claude dir found anywhere
    };
    let settings_path = claude_dir.join("settings.local.json");

    let mut settings: serde_json::Value = if settings_path.exists() {
        match std::fs::read_to_string(&settings_path) {
            Ok(content) => serde_json::from_str(&content).unwrap_or(serde_json::json!({})),
            Err(_) => return,
        }
    } else {
        serde_json::json!({})
    };

    let obj = match settings.as_object_mut() {
        Some(o) => o,
        None => return,
    };

    let mut changed = false;

    // Add MCP server (use npx for portability)
    let mcp_servers = obj
        .entry("mcpServers")
        .or_insert_with(|| serde_json::json!({}));
    if let Some(servers) = mcp_servers.as_object_mut() {
        if !servers.contains_key("phantom") {
            servers.insert(
                "phantom".to_string(),
                serde_json::json!({
                    "command": "npx",
                    "args": ["phantom-secrets-mcp"]
                }),
            );
            println!("{} Configured Claude Code MCP server", "ok".green().bold());
            changed = true;
        }
    }

    // Add .env read permissions
    let permissions = obj
        .entry("permissions")
        .or_insert_with(|| serde_json::json!({}));
    if let Some(perms) = permissions.as_object_mut() {
        let allow = perms
            .entry("allow")
            .or_insert_with(|| serde_json::json!([]));
        if let Some(allow_arr) = allow.as_array_mut() {
            for rule in &["Read(./.env)", "Read(./.env.*)"] {
                if !allow_arr.iter().any(|v| v.as_str() == Some(rule)) {
                    allow_arr.push(serde_json::json!(rule));
                    changed = true;
                }
            }
            if changed {
                println!(
                    "{} Allowed Claude Code to read .env (phantom tokens only)",
                    "ok".green().bold()
                );
            }
        }
    }

    if changed {
        if let Ok(content) = serde_json::to_string_pretty(&settings) {
            let _ = std::fs::write(&settings_path, content);
        }
    }
}

/// Detect deployment platforms and suggest sync configuration.
fn detect_platforms(project_dir: &Path, cwd: &Path) {
    let checks: Vec<(&str, &[&str])> = vec![
        ("Vercel", &["vercel.json", ".vercel"]),
        ("EAS Build", &["eas.json"]),
        ("GitHub Actions", &[".github/workflows"]),
        ("Fly.io", &["fly.toml"]),
        ("Railway", &["railway.json", "railway.toml"]),
        ("Netlify", &["netlify.toml"]),
        ("Docker", &["Dockerfile"]),
    ];

    let mut detected: Vec<&str> = Vec::new();

    for (platform, files) in &checks {
        for file in *files {
            let exists = project_dir.join(file).exists() || cwd.join(file).exists();
            if exists {
                detected.push(platform);
                break;
            }
        }
    }

    if !detected.is_empty() {
        println!("\n{} Detected deployment platform(s):", "->".blue().bold(),);
        for platform in &detected {
            println!("   {} {}", "·".dimmed(), platform);
        }
        println!(
            "   Configure sync: {}",
            "phantom sync --platform <name>".dimmed()
        );
    }
}

/// Append a section to a file if it doesn't already contain certain marker strings.
/// Searches for the file in `cwd` first, then `project_dir`. If the file doesn't exist
/// in either location, `create_if_missing` controls whether to create it in `project_dir`.
fn append_section_to_file(
    file_name: &str,
    project_dir: &Path,
    cwd: &Path,
    skip_markers: &[&str],
    section: &str,
    success_msg: &str,
    create_if_missing: bool,
) {
    let file_path = if cwd.join(file_name).exists() {
        cwd.join(file_name)
    } else if project_dir.join(file_name).exists() || create_if_missing {
        project_dir.join(file_name)
    } else {
        return;
    };

    let content = if file_path.exists() {
        match std::fs::read_to_string(&file_path) {
            Ok(c) => c,
            Err(_) => return,
        }
    } else {
        String::new()
    };

    let content_lower = content.to_lowercase();
    if skip_markers
        .iter()
        .any(|m| content_lower.contains(&m.to_lowercase()))
    {
        return;
    }

    let mut updated = content;
    if !updated.is_empty() && !updated.ends_with('\n') {
        updated.push('\n');
    }
    updated.push_str(section);

    match std::fs::write(&file_path, &updated) {
        Ok(_) => println!("{} {}", "ok".green().bold(), success_msg),
        Err(e) => println!(
            "{} Could not update {}: {}",
            "warn".yellow().bold(),
            file_name,
            e
        ),
    }
}

/// Add a "Secrets" section to README.md so humans know the project uses Phantom.
fn auto_add_readme(project_dir: &Path, cwd: &Path) {
    let section = r#"
## Secrets

This project uses [Phantom](https://phm.dev) to protect API keys from AI agent leaks.

**Setup (with Phantom):**
```bash
npm i -g phantom-secrets  # or: npx phantom-secrets
phantom cloud pull         # restore team vault
phantom exec -- npm run dev
```

**Setup (manual):**
```bash
cp .env.example .env
# Fill in real API keys
npm run dev
```
"#;

    append_section_to_file(
        "README.md",
        project_dir,
        cwd,
        &["## secrets", "## environment", "phantom"],
        section,
        "Added \"Secrets\" section to README.md",
        false,
    );
}

/// Make a file executable on Unix platforms.
#[cfg(unix)]
fn make_executable(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755));
}

#[cfg(not(unix))]
fn make_executable(_path: &Path) {}

/// Install a pre-commit hook that scans for unprotected secrets.
fn install_precommit_hook(project_dir: &Path) {
    // Find .git directory (check project_dir, then walk up to find repo root)
    let git_dir = if project_dir.join(".git").exists() {
        project_dir.join(".git")
    } else {
        // Walk up to find .git
        let mut dir = project_dir.to_path_buf();
        loop {
            if dir.join(".git").exists() {
                break dir.join(".git");
            }
            if !dir.pop() {
                return; // Not a git repo
            }
        }
    };

    let hooks_dir = git_dir.join("hooks");
    let hook_path = hooks_dir.join("pre-commit");

    // Check if hook already exists
    if hook_path.exists() {
        if let Ok(content) = std::fs::read_to_string(&hook_path) {
            if content.contains("phantom") {
                return; // Already installed
            }
            // Existing hook without phantom — append
            let updated = format!(
                "{}\n\n# Phantom Secrets pre-commit hook\nnpx phantom-secrets check --staged\n",
                content.trim_end()
            );
            if std::fs::write(&hook_path, updated).is_ok() {
                make_executable(&hook_path);
                println!(
                    "{} Appended phantom check to existing pre-commit hook",
                    "ok".green().bold()
                );
            }
            return;
        }
    }

    // Create hooks directory if needed
    let _ = std::fs::create_dir_all(&hooks_dir);

    let hook_content = r#"#!/bin/sh
# Phantom Secrets pre-commit hook
# Scans staged files for unprotected secrets

npx phantom-secrets check --staged
exit $?
"#;

    match std::fs::write(&hook_path, hook_content) {
        Ok(_) => {
            make_executable(&hook_path);
            println!(
                "{} Installed pre-commit hook (scans for leaked secrets)",
                "ok".green().bold()
            );
        }
        Err(e) => {
            println!(
                "{} Could not install pre-commit hook: {}",
                "warn".yellow().bold(),
                e
            );
        }
    }
}

/// Add Phantom usage instructions to the project's CLAUDE.md so Claude knows how to use it.
fn auto_add_claude_md(project_dir: &Path, cwd: &Path) {
    let instructions = r#"
## Phantom Secrets

This project uses [Phantom](https://phm.dev) to protect API keys from AI leaks.

- The `.env` file contains **phantom tokens** (`phm_...`), not real secrets
- Real secrets are in an encrypted vault (OS keychain)
- Use the Phantom MCP tools to manage secrets — never ask the user for raw API key values
- To add a secret: use the `phantom_add_secret` MCP tool
- To list secrets: use the `phantom_list_secrets` MCP tool
- The proxy (`phantom exec`) injects real credentials at the network layer
"#;

    append_section_to_file(
        "CLAUDE.md",
        project_dir,
        cwd,
        &["## Phantom Secrets"],
        instructions,
        "Added Phantom instructions to CLAUDE.md",
        true,
    );
}
