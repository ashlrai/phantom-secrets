use colored::Colorize;
use phantom_core::precommit_hook::{self, HookChange};
use std::path::Path;

pub struct PreparedHook {
    file: Option<phantom_vault::InitFile>,
    change: Option<HookChange>,
}

impl PreparedHook {
    pub fn take_file(&mut self) -> Option<phantom_vault::InitFile> {
        self.file.take()
    }

    pub fn finish(&self) {
        let message = match self.change {
            Some(HookChange::Installed) => {
                Some("Installed pre-commit hook (scans for leaked secrets)")
            }
            Some(HookChange::Repaired) => {
                Some("Repaired pre-commit hook to use the installed local phantom binary")
            }
            _ => None,
        };
        if let Some(message) = message {
            println!("{} {}", "ok".green().bold(), message);
        }
    }
}

/// Resolve and fully prepare the effective hook without mutating it.
pub fn prepare_precommit_hook(project_dir: &Path) -> anyhow::Result<PreparedHook> {
    let state = precommit_hook::inspect(project_dir)
        .map_err(|error| anyhow::anyhow!("Pre-commit hook setup failed: {error}"))?;
    let (path, existing, executable) = match state {
        precommit_hook::HookState::NotRepository => {
            return Ok(PreparedHook {
                file: None,
                change: None,
            });
        }
        precommit_hook::HookState::Missing { path } => (path, String::new(), false),
        precommit_hook::HookState::Present {
            path,
            content,
            executable,
        } => (path, content, executable),
    };
    let update = precommit_hook::ensure(&existing);
    let needs_executable_repair = !executable && !existing.is_empty();
    let change = if update.change == HookChange::Unchanged && needs_executable_repair {
        HookChange::Repaired
    } else {
        update.change
    };
    let file = (update.change != HookChange::Unchanged || needs_executable_repair).then(|| {
        phantom_vault::InitFile::replace(path, update.content.into_bytes()).executable(true)
    });
    Ok(PreparedHook {
        file,
        change: Some(change),
    })
}

/// Install a pre-commit hook that scans for unprotected secrets.
#[cfg(test)]
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

    #[cfg(unix)]
    #[test]
    fn prepare_repairs_current_but_non_executable_hook() {
        use std::os::unix::fs::PermissionsExt;

        let project = TempDir::new().unwrap();
        init_git(project.path());
        install_precommit_hook(project.path()).unwrap();
        let hook = project.path().join(".git/hooks/pre-commit");
        std::fs::set_permissions(&hook, std::fs::Permissions::from_mode(0o644)).unwrap();

        let prepared = prepare_precommit_hook(project.path()).unwrap();

        assert_eq!(prepared.change, Some(HookChange::Repaired));
        assert!(prepared.file.is_some());
    }
}
