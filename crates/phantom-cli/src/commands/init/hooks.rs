use colored::Colorize;
use phantom_core::precommit_hook::{self, HookChange};
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

    // Create hooks directory if needed
    let _ = std::fs::create_dir_all(&hooks_dir);

    let existing = if hook_path.exists() {
        match std::fs::read_to_string(&hook_path) {
            Ok(content) => content,
            Err(e) => {
                println!(
                    "{} Could not inspect pre-commit hook: {}",
                    "warn".yellow().bold(),
                    e
                );
                return;
            }
        }
    } else {
        String::new()
    };
    let update = precommit_hook::ensure(&existing);
    if update.change == HookChange::Unchanged {
        return;
    }

    match std::fs::write(&hook_path, update.content) {
        Ok(_) => {
            make_executable(&hook_path);
            let message = match update.change {
                HookChange::Installed => "Installed pre-commit hook (scans for leaked secrets)",
                HookChange::Repaired => {
                    "Repaired pre-commit hook to use the installed local phantom binary"
                }
                HookChange::Unchanged => unreachable!(),
            };
            println!("{} {}", "ok".green().bold(), message);
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

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn install_repairs_legacy_npx_hook_without_losing_existing_commands() {
        let project = TempDir::new().unwrap();
        let hooks = project.path().join(".git/hooks");
        std::fs::create_dir_all(&hooks).unwrap();
        let hook = hooks.join("pre-commit");
        std::fs::write(
            &hook,
            "#!/bin/sh\necho before\n# Phantom Secrets pre-commit hook\nnpx phantom-secrets check --staged\necho after\n",
        )
        .unwrap();

        install_precommit_hook(project.path());

        let installed = std::fs::read_to_string(hook).unwrap();
        assert!(precommit_hook::is_current(&installed));
        assert!(installed.contains("echo before"));
        assert!(installed.contains("echo after"));
        assert!(!installed.contains("npx phantom-secrets"));
    }

    #[test]
    fn install_is_idempotent() {
        let project = TempDir::new().unwrap();
        std::fs::create_dir_all(project.path().join(".git")).unwrap();
        install_precommit_hook(project.path());
        let hook = project.path().join(".git/hooks/pre-commit");
        let first = std::fs::read_to_string(&hook).unwrap();

        install_precommit_hook(project.path());

        assert_eq!(std::fs::read_to_string(hook).unwrap(), first);
    }
}
