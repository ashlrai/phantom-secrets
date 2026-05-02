use colored::Colorize;
use std::path::Path;

/// Append a section to a file if it doesn't already contain certain marker strings.
/// Searches for the file in `cwd` first, then `project_dir`. If the file doesn't exist
/// in either location, `create_if_missing` controls whether to create it in `project_dir`.
pub fn append_section_to_file(
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

/// Add Phantom usage instructions to the project's CLAUDE.md so Claude knows how to use it.
pub fn auto_add_claude_md(project_dir: &Path, cwd: &Path) {
    let instructions = r#"
## Phantom Secrets

This project uses [Phantom](https://phm.dev) to protect API keys from AI leaks.

- The `.env` file contains **phantom tokens** (`phm_...`), not real secrets
- Real secrets are in an encrypted vault (OS keychain)
- Use the Phantom MCP tools to manage secrets — never ask the user for raw API key values
- To add a secret: use the `phantom_add_secret_interactive` MCP tool, then type the value only into the trusted terminal prompt
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

/// Add a "Secrets" section to README.md so humans know the project uses Phantom.
pub fn auto_add_readme(project_dir: &Path, cwd: &Path) {
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
