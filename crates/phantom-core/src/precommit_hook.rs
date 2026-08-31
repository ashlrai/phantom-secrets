//! Canonical, network-free Phantom pre-commit hook generation.
//!
//! Git executes hooks through a POSIX-compatible shell on Phantom's supported
//! platforms (including Git for Windows). The generated block deliberately
//! resolves only an already-installed `phantom` executable from `PATH`; it
//! never invokes a package runner that could download code during a commit.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::Command;

use thiserror::Error;

/// Start marker used to find and safely repair Phantom-owned hook blocks.
pub const HOOK_MARKER: &str = "# Phantom Secrets pre-commit hook";

/// End marker used by current generators to bound future repairs.
pub const HOOK_END_MARKER: &str = "# End Phantom Secrets pre-commit hook";

const LEGACY_NPX_COMMAND: &str = "npx phantom-secrets check --staged";

/// The current Phantom-owned hook block.
pub const HOOK_BLOCK: &str = r#"# Phantom Secrets pre-commit hook
# Uses an installed local Phantom binary; never downloads packages.
if ! command -v phantom >/dev/null 2>&1; then
  echo "Phantom pre-commit hook: 'phantom' is required but was not found on PATH." >&2
  echo "Install a verified Phantom release, then retry the commit." >&2
  exit 1
fi
phantom check --staged || exit $?
# End Phantom Secrets pre-commit hook"#;

/// Describes whether a caller needs to write the returned hook content.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HookChange {
    Unchanged,
    Installed,
    Repaired,
}

/// Result of ensuring a hook contains exactly one current Phantom block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HookUpdate {
    pub content: String,
    pub change: HookChange,
}

/// Effective pre-commit hook state as resolved by Git itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HookState {
    NotRepository,
    Missing {
        path: PathBuf,
    },
    Present {
        path: PathBuf,
        content: String,
        executable: bool,
    },
}

/// Errors are deliberately specific so init/doctor callers never report a
/// successful hook installation after Git or the filesystem rejected it.
#[derive(Debug, Error)]
pub enum HookError {
    #[error("could not run Git while resolving the pre-commit hook for {project}: {source}")]
    GitUnavailable {
        project: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("Git could not resolve the effective pre-commit hook for {project}: {message}")]
    GitResolution { project: PathBuf, message: String },
    #[error("Git returned an invalid pre-commit hook path for {project}: {reason}")]
    InvalidPath { project: PathBuf, reason: String },
    #[error("refusing to inspect or replace non-file pre-commit hook {path}")]
    UnsafeTarget { path: PathBuf },
    #[error("could not read pre-commit hook {path}: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("pre-commit hook {path} is not valid UTF-8 and cannot be repaired safely")]
    NonUtf8Content { path: PathBuf },
    #[error("could not create pre-commit hook directory {path}: {source}")]
    CreateDirectory {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("could not write pre-commit hook {path}: {source}")]
    Write {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[cfg(unix)]
    #[error("could not make pre-commit hook executable {path}: {source}")]
    Permissions {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

/// Ask Git for its effective hook path. This honors linked worktrees and
/// repository/global `core.hooksPath` configuration without parsing `.git`
/// indirection files or invoking a shell.
pub fn resolve_path(project_dir: &Path) -> Result<Option<PathBuf>, HookError> {
    resolve_path_with_git(project_dir, OsStr::new("git"))
}

fn resolve_path_with_git(
    project_dir: &Path,
    git_program: &OsStr,
) -> Result<Option<PathBuf>, HookError> {
    let absolute_project = if project_dir.is_absolute() {
        project_dir.to_path_buf()
    } else {
        std::env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("."))
            .join(project_dir)
    };
    let inside = Command::new(git_program)
        .arg("-C")
        .arg(&absolute_project)
        .args(["rev-parse", "--is-inside-work-tree"])
        .output()
        .map_err(|source| HookError::GitUnavailable {
            project: absolute_project.clone(),
            source,
        })?;
    if !inside.status.success() {
        return Ok(None);
    }
    if trim_ascii(&inside.stdout) != b"true" {
        return Ok(None);
    }

    let output = Command::new(git_program)
        .arg("-C")
        .arg(&absolute_project)
        .args(["rev-parse", "--git-path", "hooks/pre-commit"])
        .output()
        .map_err(|source| HookError::GitUnavailable {
            project: absolute_project.clone(),
            source,
        })?;
    if !output.status.success() {
        return Err(HookError::GitResolution {
            project: absolute_project,
            message: stderr_message(&output.stderr),
        });
    }
    let raw = trim_git_line(&output.stdout).ok_or_else(|| HookError::InvalidPath {
        project: absolute_project.clone(),
        reason: "path output contained multiple lines or no trailing line terminator".to_string(),
    })?;
    let text = std::str::from_utf8(raw).map_err(|_| HookError::InvalidPath {
        project: absolute_project.clone(),
        reason: "path output was not valid UTF-8".to_string(),
    })?;
    if text.is_empty() {
        return Err(HookError::InvalidPath {
            project: absolute_project,
            reason: "path output was empty".to_string(),
        });
    }
    if text.contains(['\n', '\r', '\0']) {
        return Err(HookError::InvalidPath {
            project: absolute_project,
            reason: "path output contained a line break or NUL byte".to_string(),
        });
    }
    let path = PathBuf::from(text);
    if path.file_name() != Some(OsStr::new("pre-commit")) {
        return Err(HookError::InvalidPath {
            project: absolute_project,
            reason: format!("unexpected filename in {}", path.display()),
        });
    }
    Ok(Some(if path.is_absolute() {
        path
    } else {
        absolute_project.join(path)
    }))
}

/// Read the effective hook without silently treating unreadable or non-UTF-8
/// content as an absent check.
pub fn inspect(project_dir: &Path) -> Result<HookState, HookError> {
    inspect_with_git(project_dir, OsStr::new("git"))
}

fn inspect_with_git(project_dir: &Path, git_program: &OsStr) -> Result<HookState, HookError> {
    let Some(path) = resolve_path_with_git(project_dir, git_program)? else {
        return Ok(HookState::NotRepository);
    };
    let metadata = match std::fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(HookState::Missing { path });
        }
        Err(source) => return Err(HookError::Read { path, source }),
    };
    if !metadata.file_type().is_file() {
        return Err(HookError::UnsafeTarget { path });
    }
    let bytes = std::fs::read(&path).map_err(|source| HookError::Read {
        path: path.clone(),
        source,
    })?;
    let content =
        String::from_utf8(bytes).map_err(|_| HookError::NonUtf8Content { path: path.clone() })?;
    #[cfg(unix)]
    let executable = {
        use std::os::unix::fs::PermissionsExt;
        metadata.permissions().mode() & 0o111 != 0
    };
    #[cfg(not(unix))]
    let executable = true;
    Ok(HookState::Present {
        path,
        content,
        executable,
    })
}

/// Install or repair the canonical hook at Git's effective path.
pub fn install(project_dir: &Path) -> Result<Option<HookChange>, HookError> {
    install_with_git(project_dir, OsStr::new("git"))
}

fn install_with_git(
    project_dir: &Path,
    git_program: &OsStr,
) -> Result<Option<HookChange>, HookError> {
    let state = inspect_with_git(project_dir, git_program)?;
    let (path, existing, executable) = match state {
        HookState::NotRepository => return Ok(None),
        HookState::Missing { path } => (path, String::new(), false),
        HookState::Present {
            path,
            content,
            executable,
        } => (path, content, executable),
    };
    let update = ensure(&existing);
    if update.change != HookChange::Unchanged {
        let parent = path.parent().ok_or_else(|| HookError::InvalidPath {
            project: project_dir.to_path_buf(),
            reason: format!("{} has no parent directory", path.display()),
        })?;
        std::fs::create_dir_all(parent).map_err(|source| HookError::CreateDirectory {
            path: parent.to_path_buf(),
            source,
        })?;
        std::fs::write(&path, update.content).map_err(|source| HookError::Write {
            path: path.clone(),
            source,
        })?;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).map_err(
            |source| HookError::Permissions {
                path: path.clone(),
                source,
            },
        )?;
    }
    let change = if update.change == HookChange::Unchanged && !executable {
        HookChange::Repaired
    } else {
        update.change
    };
    Ok(Some(change))
}

/// A hook is effective only when its canonical block is reachable and Git can
/// execute the file on platforms with executable permission bits.
pub fn is_ready(content: &str, executable: bool) -> bool {
    executable && is_current(content)
}

fn trim_ascii(bytes: &[u8]) -> &[u8] {
    let start = bytes
        .iter()
        .position(|byte| !byte.is_ascii_whitespace())
        .unwrap_or(bytes.len());
    let end = bytes
        .iter()
        .rposition(|byte| !byte.is_ascii_whitespace())
        .map_or(start, |index| index + 1);
    &bytes[start..end]
}

fn trim_git_line(bytes: &[u8]) -> Option<&[u8]> {
    let line = bytes.strip_suffix(b"\n")?;
    let line = line.strip_suffix(b"\r").unwrap_or(line);
    if line.contains(&b'\n') || line.contains(&b'\r') {
        None
    } else {
        Some(line)
    }
}

fn stderr_message(stderr: &[u8]) -> String {
    let message = String::from_utf8_lossy(trim_ascii(stderr));
    if message.is_empty() {
        "Git exited unsuccessfully without an error message".to_string()
    } else {
        message.into_owned()
    }
}

/// Return true only when the complete current block is the first executable
/// content in the hook. Merely finding the block is insufficient: a user hook
/// can contain an earlier `exit`, making an appended Phantom check unreachable.
pub fn is_current(content: &str) -> bool {
    let lines: Vec<&str> = content.lines().collect();
    let block_lines: Vec<&str> = HOOK_BLOCK.lines().collect();
    lines.first().is_some_and(|line| line.starts_with("#!"))
        && lines.get(1..1 + block_lines.len()) == Some(block_lines.as_slice())
        && lines
            .iter()
            .filter(|line| line.trim() == HOOK_MARKER)
            .count()
            == 1
        && !lines
            .iter()
            .any(|line| is_network_capable_phantom_line(line))
}

/// Return true when a known current or legacy Phantom block is present.
pub fn has_phantom_block(content: &str) -> bool {
    content.contains(HOOK_MARKER)
        || content
            .lines()
            .any(|line| line.trim() == LEGACY_NPX_COMMAND || is_network_capable_phantom_line(line))
}

/// Install the canonical block, or replace a known stale Phantom block.
///
/// Non-Phantom hook content is retained in its original order. The canonical
/// block is placed immediately after the shebang so it cannot be bypassed by an
/// earlier `exit`. Current blocks are idempotent. Legacy marker blocks and
/// network-capable Phantom runner lines are removed before the canonical block
/// is installed.
pub fn ensure(content: &str) -> HookUpdate {
    if is_current(content) {
        return HookUpdate {
            content: content.to_string(),
            change: HookChange::Unchanged,
        };
    }

    let lines: Vec<&str> = content.lines().collect();
    let had_phantom = has_phantom_block(content) || content.contains(HOOK_BLOCK);
    let mut preserved = Vec::new();
    let mut index = usize::from(lines.first().is_some_and(|line| line.starts_with("#!")));
    while index < lines.len() {
        let line = lines[index];
        if line.trim() == HOOK_MARKER {
            index = stale_block_end(&lines, index, true);
            continue;
        }
        if line.trim() == LEGACY_NPX_COMMAND || is_network_capable_phantom_line(line) {
            index = stale_block_end(&lines, index, false);
            continue;
        }
        preserved.push(line);
        index += 1;
    }

    let shebang = lines
        .first()
        .filter(|line| line.starts_with("#!"))
        .copied()
        .unwrap_or("#!/bin/sh");
    let mut output = format!("{shebang}\n{HOOK_BLOCK}\n");
    if !preserved.is_empty() {
        output.push('\n');
        append_lines(&mut output, &preserved);
    }
    let change = if had_phantom {
        HookChange::Repaired
    } else {
        HookChange::Installed
    };

    HookUpdate {
        content: output,
        change,
    }
}

fn append_lines(output: &mut String, lines: &[&str]) {
    for line in lines {
        output.push_str(line);
        output.push('\n');
    }
}

fn stale_block_end(lines: &[&str], start: usize, has_marker: bool) -> usize {
    if has_marker {
        if let Some(relative_end) = lines[start..]
            .iter()
            .position(|line| line.trim() == HOOK_END_MARKER)
        {
            return start + relative_end + 1;
        }
    }

    let mut end = start + 1;
    if has_marker {
        while end < lines.len() && is_owned_legacy_line(lines[end]) {
            end += 1;
        }
    } else if end < lines.len() && lines[end].trim() == "exit $?" {
        end += 1;
    }
    end
}

fn is_network_capable_phantom_line(line: &str) -> bool {
    let normalized = line.trim().to_ascii_lowercase();
    normalized.contains("phantom")
        && normalized
            .split_whitespace()
            .map(|token| token.trim_matches(|c: char| !c.is_ascii_alphanumeric()))
            .any(|token| matches!(token, "npx" | "npm" | "curl"))
}

fn is_owned_legacy_line(line: &str) -> bool {
    let trimmed = line.trim();
    trimmed.is_empty()
        || trimmed.starts_with("# Scans staged files for unprotected secrets")
        || trimmed == LEGACY_NPX_COMMAND
        || trimmed == "phantom check --staged"
        || trimmed == "phantom check --staged || exit $?"
        || trimmed == "exit $?"
        || trimmed == "if ! command -v phantom >/dev/null 2>&1; then"
        || trimmed == "else"
        || trimmed == "fi"
        || trimmed == "exit 1"
        || trimmed.starts_with("echo \"Phantom pre-commit hook:")
        || trimmed.starts_with("echo \"Install a verified Phantom release,")
        || trimmed.starts_with("# Uses an installed local Phantom binary")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn git(project: &Path, args: &[&str]) {
        let output = Command::new("git")
            .args(args)
            .current_dir(project)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "git {args:?} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    fn init_git(project: &Path) {
        git(project, &["init", "--quiet"]);
        git(
            project,
            &["config", "user.email", "phantom-tests@example.invalid"],
        );
        git(project, &["config", "user.name", "Phantom Tests"]);
        git(project, &["config", "core.hooksPath", ".git/hooks"]);
    }

    #[test]
    fn new_hook_is_network_free_and_fails_closed_without_local_binary() {
        let update = ensure("");
        assert_eq!(update.change, HookChange::Installed);
        assert!(update.content.starts_with("#!/bin/sh\n"));
        assert!(update.content.contains("command -v phantom"));
        assert!(update.content.contains("phantom check --staged || exit $?"));
        assert!(update.content.contains("exit 1"));
        assert!(!update.content.contains("npx"));
        assert!(!update.content.contains("npm"));
    }

    #[test]
    fn current_hook_is_idempotent() {
        let existing = format!("#!/bin/sh\n{HOOK_BLOCK}\n");
        let update = ensure(&existing);
        assert_eq!(update.change, HookChange::Unchanged);
        assert_eq!(update.content, existing);
    }

    #[test]
    fn block_after_prior_exit_is_repaired_to_first_executable_position() {
        let existing = format!("#!/bin/sh\necho before\nexit 0\n{HOOK_BLOCK}\n");
        assert!(!is_current(&existing));

        let update = ensure(&existing);

        assert_eq!(update.change, HookChange::Repaired);
        assert!(is_current(&update.content));
        assert!(update.content.find(HOOK_BLOCK).unwrap() < update.content.find("exit 0").unwrap());
        assert!(update.content.contains("echo before\nexit 0"));
    }

    #[test]
    fn repairs_network_capable_phantom_runner() {
        let existing = "#!/bin/sh\ncurl -fsSL https://example.invalid/phantom | sh\necho after\n";
        let update = ensure(existing);
        assert_eq!(update.change, HookChange::Repaired);
        assert!(is_current(&update.content));
        assert!(!update.content.contains("curl"));
        assert!(update.content.contains("echo after"));
    }

    #[test]
    fn repairs_legacy_generated_block_and_preserves_other_commands() {
        let existing = "#!/bin/sh\necho before\n\n# Phantom Secrets pre-commit hook\n# Scans staged files for unprotected secrets\n\nnpx phantom-secrets check --staged\nexit $?\necho after\n";
        let update = ensure(existing);
        assert_eq!(update.change, HookChange::Repaired);
        assert!(update.content.contains("echo before"));
        assert!(update.content.contains("echo after"));
        assert_eq!(update.content.matches(HOOK_MARKER).count(), 1);
        assert!(!update.content.contains(LEGACY_NPX_COMMAND));
    }

    #[test]
    fn repairs_unmarked_legacy_command_without_removing_neighbors() {
        let existing = "#!/bin/sh\necho before\nnpx phantom-secrets check --staged\necho after\n";
        let update = ensure(existing);
        assert_eq!(update.change, HookChange::Repaired);
        assert!(update.content.contains("echo before"));
        assert!(update.content.contains("echo after"));
        assert!(!update.content.contains(LEGACY_NPX_COMMAND));
    }

    #[test]
    fn resolves_custom_hooks_path_and_repairs_effective_hook() {
        let project = tempfile::tempdir().unwrap();
        init_git(project.path());
        git(
            project.path(),
            &["config", "core.hooksPath", "custom-hooks"],
        );
        let hook = project.path().join("custom-hooks/pre-commit");
        std::fs::create_dir_all(hook.parent().unwrap()).unwrap();
        std::fs::write(
            &hook,
            "#!/bin/sh\necho before\nexit 0\n# Phantom Secrets pre-commit hook\nnpx phantom-secrets check --staged\n",
        )
        .unwrap();

        assert_eq!(resolve_path(project.path()).unwrap(), Some(hook.clone()));
        assert_eq!(install(project.path()).unwrap(), Some(HookChange::Repaired));
        let content = std::fs::read_to_string(hook).unwrap();
        assert!(is_current(&content));
        assert!(content.find(HOOK_BLOCK).unwrap() < content.find("exit 0").unwrap());
    }

    #[cfg(unix)]
    #[test]
    fn linked_worktree_uses_gits_shared_effective_hook_path() {
        use std::os::unix::fs::PermissionsExt;

        let container = tempfile::tempdir().unwrap();
        let main = container.path().join("main");
        let linked = container.path().join("linked");
        std::fs::create_dir(&main).unwrap();
        init_git(&main);
        git(&main, &["config", "--unset", "core.hooksPath"]);
        std::fs::write(main.join("README.md"), "test\n").unwrap();
        git(&main, &["add", "README.md"]);
        git(&main, &["commit", "--quiet", "-m", "initial"]);
        let linked_text = linked.to_string_lossy().into_owned();
        git(
            &main,
            &["worktree", "add", "--quiet", "-b", "linked", &linked_text],
        );

        let clean_git = container.path().join("git-with-clean-global-config");
        std::fs::write(
            &clean_git,
            "#!/bin/sh\nGIT_CONFIG_GLOBAL=/dev/null exec git \"$@\"\n",
        )
        .unwrap();
        std::fs::set_permissions(&clean_git, std::fs::Permissions::from_mode(0o755)).unwrap();

        let resolved = resolve_path_with_git(&linked, clean_git.as_os_str())
            .unwrap()
            .unwrap();
        assert_eq!(
            resolved,
            main.canonicalize().unwrap().join(".git/hooks/pre-commit")
        );
        assert_eq!(
            install_with_git(&linked, clean_git.as_os_str()).unwrap(),
            Some(HookChange::Installed)
        );
        assert!(matches!(
            inspect_with_git(&linked, clean_git.as_os_str()).unwrap(),
            HookState::Present { content, .. } if is_current(&content)
        ));
    }

    #[test]
    fn missing_git_executable_is_a_clear_error() {
        let project = tempfile::tempdir().unwrap();
        let error = resolve_path_with_git(
            project.path(),
            OsStr::new("phantom-definitely-missing-git-executable"),
        )
        .unwrap_err();
        assert!(matches!(error, HookError::GitUnavailable { .. }));
        assert!(error.to_string().contains("could not run Git"));
    }

    #[test]
    fn non_utf8_hook_content_is_never_overwritten() {
        let project = tempfile::tempdir().unwrap();
        init_git(project.path());
        let hook = resolve_path(project.path()).unwrap().unwrap();
        std::fs::create_dir_all(hook.parent().unwrap()).unwrap();
        let original = b"#!/bin/sh\necho user-hook\n\xff\n";
        std::fs::write(&hook, original).unwrap();

        let error = install(project.path()).unwrap_err();
        assert!(matches!(error, HookError::NonUtf8Content { .. }));
        assert_eq!(std::fs::read(hook).unwrap(), original);
    }

    #[test]
    fn non_file_hook_target_is_rejected_without_mutation() {
        let project = tempfile::tempdir().unwrap();
        init_git(project.path());
        let hook = resolve_path(project.path()).unwrap().unwrap();
        std::fs::create_dir_all(&hook).unwrap();

        assert!(matches!(
            install(project.path()).unwrap_err(),
            HookError::UnsafeTarget { .. }
        ));
        assert!(hook.is_dir());
    }

    #[cfg(unix)]
    #[test]
    fn canonical_but_non_executable_hook_is_repaired() {
        use std::os::unix::fs::PermissionsExt;

        let project = tempfile::tempdir().unwrap();
        init_git(project.path());
        let hook = resolve_path(project.path()).unwrap().unwrap();
        std::fs::create_dir_all(hook.parent().unwrap()).unwrap();
        std::fs::write(&hook, ensure("").content).unwrap();
        std::fs::set_permissions(&hook, std::fs::Permissions::from_mode(0o644)).unwrap();

        assert_eq!(install(project.path()).unwrap(), Some(HookChange::Repaired));
        assert!(matches!(
            inspect(project.path()).unwrap(),
            HookState::Present { content, executable: true, .. } if is_ready(&content, true)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn unreadable_hook_is_reported_and_never_replaced() {
        use std::os::unix::fs::PermissionsExt;

        let project = tempfile::tempdir().unwrap();
        init_git(project.path());
        let hook = resolve_path(project.path()).unwrap().unwrap();
        std::fs::create_dir_all(hook.parent().unwrap()).unwrap();
        let original = b"#!/bin/sh\necho user-hook\n";
        std::fs::write(&hook, original).unwrap();
        std::fs::set_permissions(&hook, std::fs::Permissions::from_mode(0o000)).unwrap();

        let result = install(project.path());

        std::fs::set_permissions(&hook, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(matches!(result.unwrap_err(), HookError::Read { .. }));
        assert_eq!(std::fs::read(hook).unwrap(), original);
    }

    #[cfg(unix)]
    #[test]
    fn non_utf8_git_path_output_is_rejected() {
        use std::os::unix::fs::PermissionsExt;

        let project = tempfile::tempdir().unwrap();
        let fake_git = project.path().join("fake-git");
        std::fs::write(
            &fake_git,
            "#!/bin/sh\ncase \"$*\" in\n  *--is-inside-work-tree*) printf 'true\\n' ;;\n  *) printf '\\377\\n' ;;\nesac\n",
        )
        .unwrap();
        std::fs::set_permissions(&fake_git, std::fs::Permissions::from_mode(0o755)).unwrap();

        let error = resolve_path_with_git(project.path(), fake_git.as_os_str()).unwrap_err();
        assert!(matches!(error, HookError::InvalidPath { .. }));
        assert!(error.to_string().contains("not valid UTF-8"));
    }

    #[cfg(unix)]
    #[test]
    fn generated_hook_fails_clearly_when_phantom_is_unavailable() {
        use std::os::unix::fs::PermissionsExt;
        use std::process::Command;

        let directory = tempfile::tempdir().unwrap();
        let hook = directory.path().join("pre-commit");
        std::fs::write(&hook, ensure("").content).unwrap();
        std::fs::set_permissions(&hook, std::fs::Permissions::from_mode(0o755)).unwrap();

        let output = Command::new("/bin/sh")
            .arg(&hook)
            .env_clear()
            .env("PATH", directory.path())
            .output()
            .unwrap();

        assert_eq!(output.status.code(), Some(1));
        let stderr = String::from_utf8(output.stderr).unwrap();
        assert!(stderr.contains("required but was not found on PATH"));
        assert!(stderr.contains("Install a verified Phantom release"));
    }

    #[cfg(unix)]
    #[test]
    fn generated_hook_invokes_local_binary_and_propagates_failure() {
        use std::os::unix::fs::PermissionsExt;
        use std::process::Command;

        let directory = tempfile::tempdir().unwrap();
        let phantom = directory.path().join("phantom");
        std::fs::write(&phantom, "#!/bin/sh\nexit 7\n").unwrap();
        std::fs::set_permissions(&phantom, std::fs::Permissions::from_mode(0o755)).unwrap();
        let hook = directory.path().join("pre-commit");
        std::fs::write(&hook, ensure("").content).unwrap();
        std::fs::set_permissions(&hook, std::fs::Permissions::from_mode(0o755)).unwrap();

        let status = Command::new("/bin/sh")
            .arg(&hook)
            .env_clear()
            .env("PATH", directory.path())
            .status()
            .unwrap();

        assert_eq!(status.code(), Some(7));
    }
}
