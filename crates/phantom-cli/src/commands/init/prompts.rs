use anyhow::Result;
use colored::Colorize;
use std::path::Path;

/// A preflighted Claude Code update. Runtime resolution, config parsing, and
/// serialization all finish before `phantom init` mutates the vault or .env.
pub struct PreparedClaudeSetup {
    mcp: crate::commands::setup::McpCommand,
    plan: crate::commands::setup::ClaudeSettingsPlan,
}

impl PreparedClaudeSetup {
    pub fn transaction_file(&self) -> Option<phantom_vault::InitFile> {
        self.plan.transaction_file()
    }
}

/// Prepare Claude Code MCP configuration when a project-local `.claude`
/// directory is present. This uses the exact local-runtime and settings merge
/// implementation behind `phantom setup --client claude`.
pub fn prepare_auto_setup_claude_code(
    project_dir: &Path,
    cwd: &Path,
) -> Result<Option<PreparedClaudeSetup>> {
    prepare_auto_setup_with(project_dir, cwd, crate::commands::setup::mcp_command_spec)
}

fn prepare_auto_setup_with<F>(
    project_dir: &Path,
    cwd: &Path,
    resolve_mcp: F,
) -> Result<Option<PreparedClaudeSetup>>
where
    F: FnOnce() -> Result<crate::commands::setup::McpCommand>,
{
    // .claude dir is typically at the repo root, not in a subdirectory
    let claude_dir = if project_dir.join(".claude").exists() {
        project_dir.join(".claude")
    } else if cwd.join(".claude").exists() {
        cwd.join(".claude")
    } else {
        return Ok(None); // No .claude dir found anywhere
    };
    let settings_path = claude_dir.join("settings.local.json");
    let mcp = resolve_mcp()?;
    let plan = crate::commands::setup::prepare_claude_settings(&settings_path, &mcp)?;
    Ok(Some(PreparedClaudeSetup { mcp, plan }))
}

/// Report a Claude settings update that was committed by the init transaction.
pub fn finish_auto_setup_claude_code(prepared: &PreparedClaudeSetup) {
    crate::commands::setup::print_claude_changes(&prepared.plan, &prepared.mcp);
    if prepared.plan.transaction_file().is_some() {
        println!("{} Configured Claude Code MCP server", "ok".green().bold());
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

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn missing_runtime_does_not_mutate_existing_config() {
        let tmp = tempdir().unwrap();
        let claude_dir = tmp.path().join(".claude");
        std::fs::create_dir_all(&claude_dir).unwrap();
        let settings_path = claude_dir.join("settings.local.json");
        let original = br#"{"theme":"dark"}"#;
        std::fs::write(&settings_path, original).unwrap();

        let result = prepare_auto_setup_with(tmp.path(), tmp.path(), || {
            anyhow::bail!("Phantom MCP runtime not found")
        });

        assert!(result.is_err());
        assert_eq!(std::fs::read(&settings_path).unwrap(), original);
    }
}
