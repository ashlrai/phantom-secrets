use colored::Colorize;
use std::path::Path;

/// Make a file executable on Unix platforms.
#[cfg(unix)]
fn make_executable(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755));
}

#[cfg(not(unix))]
fn make_executable(_path: &Path) {}

/// Install a pre-commit hook that scans for unprotected secrets.
pub fn install_precommit_hook(project_dir: &Path) {
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
