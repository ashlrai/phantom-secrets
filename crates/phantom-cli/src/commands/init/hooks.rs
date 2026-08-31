use colored::Colorize;
use phantom_core::precommit_hook::{self, HookChange};
use std::path::Path;

/// Install a pre-commit hook that scans for unprotected secrets.
pub fn install_precommit_hook(project_dir: &Path) -> anyhow::Result<Option<HookChange>> {
    let change = precommit_hook::install(project_dir)
        .map_err(|error| anyhow::anyhow!("Pre-commit hook setup failed: {error}"))?;
    let Some(change) = change else {
        return Ok(None);
    };
    let message = match change {
        HookChange::Installed => Some("Installed pre-commit hook (scans for leaked secrets)"),
        HookChange::Repaired => {
            Some("Repaired pre-commit hook to use the installed local phantom binary")
        }
        HookChange::Unchanged => None,
    };
    if let Some(message) = message {
        println!("{} {}", "ok".green().bold(), message);
    }
    Ok(Some(change))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn init_git(project: &Path) {
        let output = std::process::Command::new("git")
            .args(["init", "--quiet"])
            .current_dir(project)
            .output()
            .unwrap();
        assert!(output.status.success());
        let output = std::process::Command::new("git")
            .args(["config", "core.hooksPath", ".git/hooks"])
            .current_dir(project)
            .output()
            .unwrap();
        assert!(output.status.success());
    }

    #[test]
    fn install_repairs_legacy_npx_hook_without_losing_existing_commands() {
        let project = TempDir::new().unwrap();
        init_git(project.path());
        let hooks = project.path().join(".git/hooks");
        let hook = hooks.join("pre-commit");
        std::fs::write(
            &hook,
            "#!/bin/sh\necho before\n# Phantom Secrets pre-commit hook\nnpx phantom-secrets check --staged\necho after\n",
        )
        .unwrap();

        install_precommit_hook(project.path()).unwrap();

        let installed = std::fs::read_to_string(hook).unwrap();
        assert!(precommit_hook::is_current(&installed));
        assert!(installed.contains("echo before"));
        assert!(installed.contains("echo after"));
        assert!(!installed.contains("npx phantom-secrets"));
    }

    #[test]
    fn install_is_idempotent() {
        let project = TempDir::new().unwrap();
        init_git(project.path());
        install_precommit_hook(project.path()).unwrap();
        let hook = project.path().join(".git/hooks/pre-commit");
        let first = std::fs::read_to_string(&hook).unwrap();

        install_precommit_hook(project.path()).unwrap();

        assert_eq!(std::fs::read_to_string(hook).unwrap(), first);
    }
}
