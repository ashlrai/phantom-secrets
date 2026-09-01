use colored::Colorize;
use std::path::Path;

pub struct PreparedGuidance {
    files: Vec<phantom_vault::InitFile>,
    messages: Vec<&'static str>,
}

impl PreparedGuidance {
    pub fn take_files(&mut self) -> Vec<phantom_vault::InitFile> {
        std::mem::take(&mut self.files)
    }

    pub fn finish(&self) {
        for message in &self.messages {
            println!("{} {}", "ok".green().bold(), message);
        }
    }
}

fn prepare_section(
    file_name: &str,
    project_dir: &Path,
    skip_markers: &[&str],
    section: &str,
    success_msg: &'static str,
    create_if_missing: bool,
) -> anyhow::Result<Option<(phantom_vault::InitFile, &'static str)>> {
    let file_path = if project_dir.join(file_name).exists() || create_if_missing {
        project_dir.join(file_name)
    } else {
        return Ok(None);
    };
    let before = phantom_core::fs::read_regular_file(&file_path).map_err(|error| {
        anyhow::anyhow!("Failed to safely read {}: {error}", file_path.display())
    })?;
    let content = before
        .as_deref()
        .map(std::str::from_utf8)
        .transpose()
        .map_err(|_| anyhow::anyhow!("{} is not valid UTF-8", file_path.display()))?
        .unwrap_or_default()
        .to_string();
    let lower = content.to_lowercase();
    if skip_markers
        .iter()
        .any(|marker| lower.contains(&marker.to_lowercase()))
    {
        return Ok(None);
    }
    let mut updated = content;
    if !updated.is_empty() && !updated.ends_with('\n') {
        updated.push('\n');
    }
    updated.push_str(section);
    Ok(Some((
        phantom_vault::InitFile::replace_if_unchanged(file_path, before, updated.into_bytes()),
        success_msg,
    )))
}

pub fn prepare_guidance(project_dir: &Path) -> anyhow::Result<PreparedGuidance> {
    let mut prepared = PreparedGuidance {
        files: Vec::new(),
        messages: Vec::new(),
    };
    if let Some((file, message)) = prepare_section(
        "CLAUDE.md",
        project_dir,
        &["## Phantom Secrets"],
        CLAUDE_INSTRUCTIONS,
        "Added Phantom instructions to CLAUDE.md",
        true,
    )? {
        prepared.files.push(file);
        prepared.messages.push(message);
    }
    let readme = readme_section();
    if let Some((file, message)) = prepare_section(
        "README.md",
        project_dir,
        &["## secrets", "## environment", "phantom"],
        &readme,
        "Added \"Secrets\" section to README.md",
        false,
    )? {
        prepared.files.push(file);
        prepared.messages.push(message);
    }
    Ok(prepared)
}

const CLAUDE_INSTRUCTIONS: &str = r#"
## Phantom Secrets

This project uses [Phantom](https://phm.dev) to protect API keys from AI leaks.

- The `.env` file contains **phantom tokens** (`phm_...`), not real secrets
- Real secrets are in an encrypted vault (OS keychain)
- Use the Phantom MCP tools to manage secrets — never ask the user for raw API key values
- To add a secret: use the `phantom_add_secret_interactive` MCP tool, then type the value only into the trusted terminal prompt
- To list secrets: use the `phantom_list_secrets` MCP tool
- The proxy (`phantom exec`) injects real credentials at the network layer
"#;

fn readme_section() -> String {
    let version = env!("CARGO_PKG_VERSION");
    format!(
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
    )
}

/// Append a section to a file if it doesn't already contain certain marker strings.
/// Searches for the file in `cwd` first, then `project_dir`. If the file doesn't exist
/// in either location, `create_if_missing` controls whether to create it in `project_dir`.
#[cfg(test)]
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

/// Add a "Secrets" section to README.md so humans know the project uses Phantom.
#[cfg(test)]
pub fn auto_add_readme(project_dir: &Path, cwd: &Path) {
    let section = readme_section();

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
    fn child_project_guidance_never_targets_parent_documents() {
        let parent = TempDir::new().unwrap();
        std::fs::write(parent.path().join("CLAUDE.md"), "parent instructions\n").unwrap();
        std::fs::write(parent.path().join("README.md"), "# Parent\n").unwrap();
        let project = parent.path().join("child");
        std::fs::create_dir(&project).unwrap();
        std::fs::write(project.join("README.md"), "# Child\n").unwrap();

        let mut guidance = prepare_guidance(&project).unwrap();
        let planned = format!("{:?}", guidance.take_files());

        assert!(planned.contains(&format!("{:?}", project.join("CLAUDE.md"))));
        assert!(planned.contains(&format!("{:?}", project.join("README.md"))));
        assert!(!planned.contains(&format!("{:?}", parent.path().join("CLAUDE.md"))));
        assert!(!planned.contains(&format!("{:?}", parent.path().join("README.md"))));
    }

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
