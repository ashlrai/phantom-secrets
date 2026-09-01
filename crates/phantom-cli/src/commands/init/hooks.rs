use colored::Colorize;
use phantom_core::precommit_hook::{self, HookChange};
use std::path::Path;

pub struct PreparedHook {
    project_dir: std::path::PathBuf,
    plan: Option<precommit_hook::PreparedHookPlan>,
    authorization: Option<precommit_hook::ExternalHookAuthorization>,
    change: Option<HookChange>,
}

impl PreparedHook {
    /// Commit the hook as a separate Git-metadata transaction after the
    /// project-root transaction has completed. This cannot roll back project
    /// files if the independently rooted hook operation fails.
    pub fn commit(&mut self) -> anyhow::Result<()> {
        let Some(plan) = self.plan.as_ref() else {
            return Ok(());
        };
        self.change = Some(
            precommit_hook::commit_prepared_install(
                &self.project_dir,
                plan,
                self.authorization.as_ref(),
            )
            .map_err(|error| anyhow::anyhow!("Pre-commit hook setup failed: {error}"))?,
        );
        Ok(())
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
    let plan = precommit_hook::prepare_install_plan(project_dir)
        .map_err(|error| anyhow::anyhow!("Pre-commit hook setup failed: {error}"))?;
    let authorization = if plan.as_ref().is_some_and(|plan| {
        plan.change() != HookChange::Unchanged && plan.authority().is_external()
    }) {
        precommit_hook::authorize_external_install_from_terminal(project_dir)
            .map_err(|error| anyhow::anyhow!("Pre-commit hook setup failed: {error}"))?
    } else {
        None
    };
    let change = plan.as_ref().map(precommit_hook::PreparedHookPlan::change);
    Ok(PreparedHook {
        project_dir: project_dir.to_path_buf(),
        plan,
        authorization,
        change,
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
    }

    #[test]
    fn commit_rejects_hook_change_after_init_preflight() {
        let project = TempDir::new().unwrap();
        init_git(project.path());
        let hook = project.path().join(".git/hooks/pre-commit");
        std::fs::write(&hook, "#!/bin/sh\necho reviewed\n").unwrap();
        let mut prepared = prepare_precommit_hook(project.path()).unwrap();
        let concurrent = b"#!/bin/sh\necho concurrent-owner\n";
        std::fs::write(&hook, concurrent).unwrap();

        let error = prepared.commit().unwrap_err().to_string();

        assert!(error.contains("changed after init preflight"));
        assert_eq!(std::fs::read(hook).unwrap(), concurrent);
    }

    #[test]
    fn init_reports_independent_hook_failure_without_claiming_project_rollback() {
        let source = include_str!("mod.rs");
        assert!(source.contains("separate Git pre-commit hook transaction is incomplete"));
        assert!(source.contains("project changes were not rolled back"));
        assert!(source.contains("Project files and vault entries were committed"));
    }
}
