use anyhow::{Context, Result};
use colored::Colorize;
use std::path::Path;

/// Set up Phantom auto-mode for Claude Code.
/// Configures MCP server and hooks in .claude/settings.local.json.
pub fn run() -> Result<()> {
    let project_dir = std::env::current_dir()?;
    let claude_dir = project_dir.join(".claude");
    let settings_path = claude_dir.join("settings.local.json");

    // Find phantom-mcp binary
    let mcp_binary = find_mcp_binary();

    println!(
        "{} Setting up Phantom auto-mode for Claude Code...",
        "->".blue().bold()
    );

    // Create .claude directory if needed
    std::fs::create_dir_all(&claude_dir)?;

    // Load existing settings or create new
    let mut settings: serde_json::Value = if settings_path.exists() {
        let content = std::fs::read_to_string(&settings_path)?;
        serde_json::from_str(&content).context("Failed to parse .claude/settings.local.json")?
    } else {
        serde_json::json!({})
    };

    // Ensure settings is an object
    let obj = settings
        .as_object_mut()
        .ok_or_else(|| anyhow::anyhow!("settings.local.json is not a JSON object"))?;

    // Add MCP server configuration
    if let Some(mcp_path) = &mcp_binary {
        let mcp_servers = obj
            .entry("mcpServers")
            .or_insert_with(|| serde_json::json!({}));

        if let Some(servers) = mcp_servers.as_object_mut() {
            if !servers.contains_key("phantom") {
                servers.insert(
                    "phantom".to_string(),
                    serde_json::json!({
                        "command": mcp_path,
                        "args": []
                    }),
                );
                println!(
                    "   {} MCP server: {} -> {}",
                    "+".green().bold(),
                    "phantom".bold(),
                    mcp_path.dimmed()
                );
            } else {
                println!("   {} MCP server already configured", "-".dimmed());
            }
        }
    } else {
        println!(
            "   {} phantom-mcp binary not found — install it and re-run",
            "warn".yellow()
        );
    }

    // Write settings
    let content =
        serde_json::to_string_pretty(&settings).context("Failed to serialize settings")?;
    std::fs::write(&settings_path, content)?;

    println!("\n{} Claude Code configured!", "ok".green().bold());

    if mcp_binary.is_some() {
        println!(
            "{} Phantom MCP tools are now available in Claude Code.",
            "->".blue().bold()
        );
        println!(
            "{} Claude can use: phantom_list_secrets, phantom_status, phantom_init, etc.",
            "->".blue().bold()
        );
    }

    println!(
        "\n{} Restart Claude Code to activate.",
        "next".blue().bold()
    );

    Ok(())
}

fn find_mcp_binary() -> Option<String> {
    // Check common locations
    let candidates = [
        // Same directory as phantom binary
        std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(|d| d.join("phantom-mcp")))
            .map(|p| p.to_string_lossy().to_string()),
        // Cargo install location
        dirs_home().map(|h| format!("{h}/.cargo/bin/phantom-mcp")),
        // PATH
        Some("phantom-mcp".to_string()),
    ];

    for candidate in candidates.into_iter().flatten() {
        if candidate == "phantom-mcp" {
            // Check if it's in PATH
            if std::process::Command::new("which")
                .arg("phantom-mcp")
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false)
            {
                return Some(candidate);
            }
        } else if Path::new(&candidate).exists() {
            return Some(candidate);
        }
    }

    None
}

fn dirs_home() -> Option<String> {
    std::env::var("HOME").ok()
}
