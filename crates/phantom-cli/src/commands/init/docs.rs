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
    let version = env!("CARGO_PKG_VERSION");
    let section = format!(
        r#"
## Secrets

This project uses [Phantom](https://phm.dev) to protect API keys from AI agent leaks.

**Setup (with Phantom):**
```bash
phantom --version          # use the installed local binary that ran `phantom init`
# Reviewed release: https://github.com/ashlrai/phantom-secrets/releases/tag/v{version}

# Personal backup only: restore on the machine holding the original cloud key
phantom cloud pull
# Team vault instead (ordered):
# 1. Member registers this device before any pull
phantom team key-publish <TEAM_ID>
# 2. Owner/admin creates that member's key share after the key is visible
phantom team vault-push <TEAM_ID>
# 3. Member pulls only after the owner/admin push succeeds
phantom team vault-pull <TEAM_ID>

# Current roles do not restrict shared-vault read/write access. Removing a
# member does not revoke previously shared ciphertext; rotate affected secrets.

phantom exec -- npm run dev
```

**Setup (manual):**
```bash
cp .env.example .env
# Fill in real API keys
npm run dev
```
"#
    );

    append_section_to_file(
        "README.md",
        project_dir,
        cwd,
        &["## secrets", "## environment", "phantom"],
        &section,
        "Added \"Secrets\" section to README.md",
        false,
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn generated_readme_uses_verified_local_binary_and_distinguishes_vaults() {
        let project = TempDir::new().unwrap();
        std::fs::write(project.path().join("README.md"), "# Example\n").unwrap();

        auto_add_readme(project.path(), project.path());

        let readme = std::fs::read_to_string(project.path().join("README.md")).unwrap();
        assert!(readme.contains("releases/tag/v"));
        assert!(readme.contains("phantom --version"));
        assert!(readme.contains("Personal backup only"));
        assert!(readme.contains("phantom cloud pull"));
        assert!(readme.contains("phantom team vault-pull <TEAM_ID>"));
        let publish = readme.find("phantom team key-publish <TEAM_ID>").unwrap();
        let push = readme.find("phantom team vault-push <TEAM_ID>").unwrap();
        let pull = readme.find("phantom team vault-pull <TEAM_ID>").unwrap();
        assert!(publish < push && push < pull);
        assert!(readme.contains("roles do not restrict shared-vault read/write access"));
        assert!(readme.contains("rotate affected secrets"));
        assert!(!readme.contains("restore team vault"));
        assert!(!readme.contains("npm i -g phantom-secrets"));
        assert!(!readme.contains("npx phantom-secrets"));
        assert!(!readme.contains("cargo install"));
        assert!(!readme.contains("curl"));
    }
}
