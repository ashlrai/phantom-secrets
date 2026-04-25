use colored::Colorize;
use std::path::Path;

/// Auto-configure Claude Code MCP server and .env permissions if Claude Code is detected.
pub fn auto_setup_claude_code(project_dir: &Path, cwd: &Path) {
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
pub fn detect_platforms(project_dir: &Path, cwd: &Path) {
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
