//! Canonical, network-free Phantom pre-commit hook generation.
//!
//! Git executes hooks through a POSIX-compatible shell on Phantom's supported
//! platforms (including Git for Windows). The generated block deliberately
//! resolves only an already-installed `phantom` executable from `PATH`; it
//! never invokes a package runner that could download code during a commit.

use std::ffi::OsStr;
use std::hash::{DefaultHasher, Hash, Hasher};
use std::io::{BufRead, IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Mutex, MutexGuard, OnceLock};

use thiserror::Error;

use crate::fs::{
    AnchoredEffect, AnchoredFilePermissions, AnchoredLock, AnchoredRead, AnchoredTarget,
    TrustedAnchor,
};

/// Start marker used to find and safely repair Phantom-owned hook blocks.
pub const HOOK_MARKER: &str = "# Phantom Secrets pre-commit hook";

/// End marker used by current generators to bound future repairs.
pub const HOOK_END_MARKER: &str = "# End Phantom Secrets pre-commit hook";

const LEGACY_NPX_COMMAND: &str = "npx phantom-secrets check --staged";
const HOOK_LOCK_NAME: &str = ".phantom-precommit.lock";
const PROCESS_LOCK_SHARDS: usize = 64;

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
        authority: HookAuthority,
    },
    Present {
        path: PathBuf,
        content: String,
        executable: bool,
        authority: HookAuthority,
    },
}

/// Why Git's effective hook parent is eligible (or ineligible) for mutation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HookAuthority {
    Project,
    GitCommon,
    ExternalOperatorConfig { scope: String, origin: String },
    ExternalDenied { scope: String, origin: String },
}

impl HookAuthority {
    pub fn is_external(&self) -> bool {
        matches!(
            self,
            Self::ExternalOperatorConfig { .. } | Self::ExternalDenied { .. }
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct HookLocation {
    path: PathBuf,
    parent: PathBuf,
    authority: HookAuthority,
    authority_root: Option<PathBuf>,
    relative_parent: Option<PathBuf>,
}

/// Privately constructed proof that this process received an exact
/// trusted-terminal confirmation for one operator-configured external hook
/// location. Same-user process and terminal compromise remain out of scope.
#[derive(Debug)]
pub struct ExternalHookAuthorization {
    location: HookLocation,
    parent_identity: crate::fs::FileIdentity,
}

#[derive(Debug)]
struct HookBeforeImage {
    read: AnchoredRead,
}

/// Exact preflight plan for one independently rooted hook transaction.
/// Commit rejects identity, byte, permission, path, or provenance drift.
#[derive(Debug)]
pub struct PreparedHookPlan {
    location: HookLocation,
    before: Option<HookBeforeImage>,
    content: Vec<u8>,
    change: HookChange,
}

impl PreparedHookPlan {
    pub fn change(&self) -> HookChange {
        self.change
    }

    pub fn authority(&self) -> &HookAuthority {
        &self.location.authority
    }

    fn requires_write(&self) -> bool {
        self.change != HookChange::Unchanged
    }
}

struct HookTransaction {
    _process: MutexGuard<'static, ()>,
    _lock: AnchoredLock,
    _parent: TrustedAnchor,
    target: AnchoredTarget,
    location: HookLocation,
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
    #[error(
        "pre-commit hook {path} changed after init preflight; project changes were not rolled back"
    )]
    ReviewedStateChanged { path: PathBuf },
    #[error("effective external pre-commit hook {path} is controlled by {scope} config from {origin}; repository/worktree/command config cannot authorize an external write")]
    ExternalWriteDenied {
        path: PathBuf,
        scope: String,
        origin: String,
    },
    #[error("external pre-commit hook authorization requires attached stdin, stdout, and stderr terminals")]
    TrustedTerminalRequired,
    #[error("external pre-commit hook authorization did not match exactly; no hook was changed")]
    AuthorizationRejected,
    #[error("external pre-commit hook parent changed after authorization; no hook was changed")]
    AuthorizationDrift,
    #[error("could not read or render external pre-commit hook authorization: {0}")]
    AuthorizationIo(#[source] std::io::Error),
    #[error("could not acquire the cooperative pre-commit hook lock in {path}: {source}")]
    Lock {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("pre-commit hook {path} was replaced, but durability could not be verified: {source}")]
    CommittedButUncertain {
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
    Ok(resolve_location_with_git(project_dir, OsStr::new("git"))?.map(|location| location.path))
}

#[cfg(test)]
fn resolve_path_with_git(
    project_dir: &Path,
    git_program: &OsStr,
) -> Result<Option<PathBuf>, HookError> {
    Ok(resolve_location_with_git(project_dir, git_program)?.map(|location| location.path))
}

fn resolve_location_with_git(
    project_dir: &Path,
    git_program: &OsStr,
) -> Result<Option<HookLocation>, HookError> {
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
    let path = if path.is_absolute() {
        path
    } else {
        absolute_project.join(path)
    };
    if path
        .components()
        .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        return Err(HookError::InvalidPath {
            project: absolute_project,
            reason: format!("hook path contains parent traversal: {}", path.display()),
        });
    }
    let canonical_project =
        absolute_project
            .canonicalize()
            .map_err(|source| HookError::InvalidPath {
                project: absolute_project.clone(),
                reason: format!("could not canonicalize project root: {source}"),
            })?;
    let common_output = Command::new(git_program)
        .arg("-C")
        .arg(&absolute_project)
        .args(["rev-parse", "--path-format=absolute", "--git-common-dir"])
        .output()
        .map_err(|source| HookError::GitUnavailable {
            project: absolute_project.clone(),
            source,
        })?;
    if !common_output.status.success() {
        return Err(HookError::GitResolution {
            project: absolute_project,
            message: stderr_message(&common_output.stderr),
        });
    }
    let common_raw =
        trim_git_line(&common_output.stdout).ok_or_else(|| HookError::InvalidPath {
            project: absolute_project.clone(),
            reason: "Git returned an invalid common-directory path".to_string(),
        })?;
    let common_text = std::str::from_utf8(common_raw).map_err(|_| HookError::InvalidPath {
        project: absolute_project.clone(),
        reason: "Git common-directory path was not valid UTF-8".to_string(),
    })?;
    let common_path = PathBuf::from(common_text);
    let common_dir = common_path
        .canonicalize()
        .map_err(|source| HookError::InvalidPath {
            project: absolute_project.clone(),
            reason: format!("could not canonicalize Git common directory: {source}"),
        })?;
    let (authority, authority_root, relative_hook) =
        if let Ok(relative) = path.strip_prefix(&canonical_project) {
            (
                HookAuthority::Project,
                Some(canonical_project.clone()),
                Some(relative.to_path_buf()),
            )
        } else if let Ok(relative) = path.strip_prefix(&absolute_project) {
            (
                HookAuthority::Project,
                Some(canonical_project),
                Some(relative.to_path_buf()),
            )
        } else if let Ok(relative) = path.strip_prefix(&common_dir) {
            (
                HookAuthority::GitCommon,
                Some(common_dir.clone()),
                Some(relative.to_path_buf()),
            )
        } else if let Ok(relative) = path.strip_prefix(&common_path) {
            (
                HookAuthority::GitCommon,
                Some(common_dir),
                Some(relative.to_path_buf()),
            )
        } else {
            (
                resolve_external_authority(&absolute_project, git_program, &path)?,
                None,
                None,
            )
        };
    let parent = path.parent().ok_or_else(|| HookError::InvalidPath {
        project: absolute_project,
        reason: format!("{} has no parent directory", path.display()),
    })?;
    Ok(Some(HookLocation {
        path: path.clone(),
        parent: parent.to_path_buf(),
        authority,
        authority_root,
        relative_parent: relative_hook
            .as_deref()
            .and_then(Path::parent)
            .map(Path::to_path_buf),
    }))
}

fn resolve_external_authority(
    project: &Path,
    git_program: &OsStr,
    hook_path: &Path,
) -> Result<HookAuthority, HookError> {
    let output = Command::new(git_program)
        .arg("-C")
        .arg(project)
        .args([
            "config",
            "--null",
            "--show-origin",
            "--show-scope",
            "--get",
            "core.hooksPath",
        ])
        .output()
        .map_err(|source| HookError::GitUnavailable {
            project: project.to_path_buf(),
            source,
        })?;
    if !output.status.success() {
        return Err(HookError::InvalidPath {
            project: project.to_path_buf(),
            reason: format!(
                "external effective hook {} has no attributable core.hooksPath configuration",
                hook_path.display()
            ),
        });
    }
    let fields = output
        .stdout
        .split(|byte| *byte == b'\0')
        .collect::<Vec<_>>();
    if fields.len() != 4 || !fields[3].is_empty() {
        return Err(HookError::InvalidPath {
            project: project.to_path_buf(),
            reason: "Git returned malformed core.hooksPath provenance".to_string(),
        });
    }
    let scope = std::str::from_utf8(fields[0]).map_err(|_| HookError::InvalidPath {
        project: project.to_path_buf(),
        reason: "core.hooksPath scope was not valid UTF-8".to_string(),
    })?;
    let origin = std::str::from_utf8(fields[1]).map_err(|_| HookError::InvalidPath {
        project: project.to_path_buf(),
        reason: "core.hooksPath origin was not valid UTF-8".to_string(),
    })?;
    let configured = std::str::from_utf8(fields[2]).map_err(|_| HookError::InvalidPath {
        project: project.to_path_buf(),
        reason: "core.hooksPath value was not valid UTF-8".to_string(),
    })?;
    if configured.contains(['\n', '\r', '\0'])
        || origin.contains(['\n', '\r', '\0'])
        || scope.contains(['\n', '\r', '\0'])
    {
        return Err(HookError::InvalidPath {
            project: project.to_path_buf(),
            reason: "core.hooksPath provenance contained control separators".to_string(),
        });
    }
    let authority = match scope {
        "global" | "system" => HookAuthority::ExternalOperatorConfig {
            scope: scope.to_string(),
            origin: origin.to_string(),
        },
        _ => HookAuthority::ExternalDenied {
            scope: scope.to_string(),
            origin: origin.to_string(),
        },
    };
    Ok(authority)
}

fn process_lock_for(parent: &Path) -> MutexGuard<'static, ()> {
    static LOCKS: OnceLock<Vec<Mutex<()>>> = OnceLock::new();
    let locks = LOCKS.get_or_init(|| (0..PROCESS_LOCK_SHARDS).map(|_| Mutex::new(())).collect());
    let mut hasher = DefaultHasher::new();
    parent.hash(&mut hasher);
    locks[hasher.finish() as usize % locks.len()]
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn open_hook_parent(location: &HookLocation) -> Result<TrustedAnchor, HookError> {
    if let Some(root) = location.authority_root.as_ref() {
        let anchor = TrustedAnchor::open(root).map_err(|source| HookError::CreateDirectory {
            path: root.clone(),
            source,
        })?;
        let relative = location
            .relative_parent
            .as_deref()
            .unwrap_or_else(|| Path::new(""));
        if relative.as_os_str().is_empty() {
            return Ok(anchor);
        }
        return anchor
            .open_subdirectory(relative)
            .map_err(|source| HookError::CreateDirectory {
                path: location.parent.clone(),
                source,
            });
    }
    let metadata = std::fs::symlink_metadata(&location.parent).map_err(|source| {
        HookError::CreateDirectory {
            path: location.parent.clone(),
            source,
        }
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(HookError::UnsafeTarget {
            path: location.parent.clone(),
        });
    }
    TrustedAnchor::open_canonical(&location.parent).map_err(|source| HookError::CreateDirectory {
        path: location.parent.clone(),
        source,
    })
}

fn acquire_hook_transaction(
    location: HookLocation,
    authorization: Option<&ExternalHookAuthorization>,
) -> Result<HookTransaction, HookError> {
    match &location.authority {
        HookAuthority::Project | HookAuthority::GitCommon => {}
        HookAuthority::ExternalOperatorConfig { scope, origin } => {
            if authorization.map(|proof| &proof.location) != Some(&location) {
                return Err(HookError::ExternalWriteDenied {
                    path: location.path.clone(),
                    scope: scope.clone(),
                    origin: origin.clone(),
                });
            }
        }
        HookAuthority::ExternalDenied { scope, origin } => {
            return Err(HookError::ExternalWriteDenied {
                path: location.path.clone(),
                scope: scope.clone(),
                origin: origin.clone(),
            });
        }
    }
    let process = process_lock_for(&location.parent);
    let parent = open_hook_parent(&location)?;
    if let Some(proof) = authorization {
        if location.authority.is_external() && parent.identity() != proof.parent_identity {
            return Err(HookError::AuthorizationDrift);
        }
    }
    let lock = parent
        .acquire_lock(HOOK_LOCK_NAME)
        .map_err(|source| HookError::Lock {
            path: location.parent.clone(),
            source,
        })?;
    let target = parent
        .target("pre-commit")
        .map_err(|source| HookError::Read {
            path: location.path.clone(),
            source,
        })?;
    Ok(HookTransaction {
        _process: process,
        _lock: lock,
        _parent: parent,
        target,
        location,
    })
}

fn inspect_location(location: HookLocation) -> Result<HookState, HookError> {
    let read = read_location(&location)?;
    let Some(read) = read else {
        return Ok(HookState::Missing {
            path: location.path,
            authority: location.authority,
        });
    };
    state_from_read(location, &read)
}

fn read_location(location: &HookLocation) -> Result<Option<AnchoredRead>, HookError> {
    if let HookAuthority::ExternalDenied { scope, origin } = &location.authority {
        return Err(HookError::ExternalWriteDenied {
            path: location.path.clone(),
            scope: scope.clone(),
            origin: origin.clone(),
        });
    }
    let parent = open_hook_parent(location)?;
    let target = parent
        .target("pre-commit")
        .map_err(|source| HookError::Read {
            path: location.path.clone(),
            source,
        })?;
    target
        .read_regular()
        .map_err(|source| map_hook_read_error(&location.path, source))
}

fn map_hook_read_error(path: &Path, source: std::io::Error) -> HookError {
    let message = source.to_string();
    if message.contains("non-regular")
        || message.contains("reparse")
        || message.contains("symlink")
        || message.contains("multiply-linked")
    {
        HookError::UnsafeTarget {
            path: path.to_path_buf(),
        }
    } else {
        HookError::Read {
            path: path.to_path_buf(),
            source,
        }
    }
}

fn state_from_read(location: HookLocation, read: &AnchoredRead) -> Result<HookState, HookError> {
    let content = std::str::from_utf8(read.bytes())
        .map_err(|_| HookError::NonUtf8Content {
            path: location.path.clone(),
        })?
        .to_string();
    #[cfg(unix)]
    let executable = read.permissions().is_executable();
    #[cfg(not(unix))]
    let executable = true;
    Ok(HookState::Present {
        path: location.path,
        content,
        executable,
        authority: location.authority,
    })
}

/// Read the effective hook without silently treating unreadable or non-UTF-8
/// content as an absent check.
pub fn inspect(project_dir: &Path) -> Result<HookState, HookError> {
    inspect_with_git(project_dir, OsStr::new("git"))
}

fn inspect_with_git(project_dir: &Path, git_program: &OsStr) -> Result<HookState, HookError> {
    let Some(location) = resolve_location_with_git(project_dir, git_program)? else {
        return Ok(HookState::NotRepository);
    };
    inspect_location(location)
}

/// Install or repair the canonical hook at Git's effective path.
pub fn install(project_dir: &Path) -> Result<Option<HookChange>, HookError> {
    install_with_authorization(project_dir, None)
}

/// Install using a trusted-terminal authorization bound to one external
/// global/system `core.hooksPath`. Project/common paths ignore the token.
pub fn install_with_authorization(
    project_dir: &Path,
    authorization: Option<&ExternalHookAuthorization>,
) -> Result<Option<HookChange>, HookError> {
    let Some(plan) = prepare_install_plan(project_dir)? else {
        return Ok(None);
    };
    commit_prepared_install(project_dir, &plan, authorization).map(Some)
}

/// Snapshot the exact effective hook state and intended canonical update
/// without retaining a lock across an independently rooted project commit.
pub fn prepare_install_plan(project_dir: &Path) -> Result<Option<PreparedHookPlan>, HookError> {
    prepare_install_plan_with_git(project_dir, OsStr::new("git"))
}

/// Commit one exact hook plan. Any drift after preflight is rejected rather
/// than silently merged into the independently committed project transaction.
pub fn commit_prepared_install(
    project_dir: &Path,
    plan: &PreparedHookPlan,
    authorization: Option<&ExternalHookAuthorization>,
) -> Result<HookChange, HookError> {
    commit_prepared_with_git_before_commit(
        project_dir,
        OsStr::new("git"),
        plan,
        authorization,
        || {},
    )
}

#[cfg(test)]
fn install_with_git(
    project_dir: &Path,
    git_program: &OsStr,
    authorization: Option<&ExternalHookAuthorization>,
) -> Result<Option<HookChange>, HookError> {
    let Some(plan) = prepare_install_plan_with_git(project_dir, git_program)? else {
        return Ok(None);
    };
    commit_prepared_with_git_before_commit(project_dir, git_program, &plan, authorization, || {})
        .map(Some)
}

#[cfg(test)]
fn install_with_git_before_commit(
    project_dir: &Path,
    git_program: &OsStr,
    authorization: Option<&ExternalHookAuthorization>,
    before_commit: impl FnOnce(),
) -> Result<Option<HookChange>, HookError> {
    let Some(plan) = prepare_install_plan_with_git(project_dir, git_program)? else {
        return Ok(None);
    };
    commit_prepared_with_git_before_commit(
        project_dir,
        git_program,
        &plan,
        authorization,
        before_commit,
    )
    .map(Some)
}

fn prepare_install_plan_with_git(
    project_dir: &Path,
    git_program: &OsStr,
) -> Result<Option<PreparedHookPlan>, HookError> {
    let Some(location) = resolve_location_with_git(project_dir, git_program)? else {
        return Ok(None);
    };
    let before = read_location(&location)?;
    let (existing, executable, before_image) = match before {
        Some(read) => {
            let content = std::str::from_utf8(read.bytes())
                .map_err(|_| HookError::NonUtf8Content {
                    path: location.path.clone(),
                })?
                .to_string();
            #[cfg(unix)]
            let executable = read.permissions().is_executable();
            #[cfg(not(unix))]
            let executable = true;
            (content, executable, Some(HookBeforeImage { read }))
        }
        None => (String::new(), false, None),
    };
    let update = ensure(&existing);
    let change = if update.change == HookChange::Unchanged && !executable {
        HookChange::Repaired
    } else {
        update.change
    };
    Ok(Some(PreparedHookPlan {
        location,
        before: before_image,
        content: update.content.into_bytes(),
        change,
    }))
}

fn commit_prepared_with_git_before_commit(
    project_dir: &Path,
    git_program: &OsStr,
    plan: &PreparedHookPlan,
    authorization: Option<&ExternalHookAuthorization>,
    before_commit: impl FnOnce(),
) -> Result<HookChange, HookError> {
    let current_location = resolve_location_with_git(project_dir, git_program)?;
    if current_location.as_ref() != Some(&plan.location) {
        return Err(HookError::ReviewedStateChanged {
            path: plan.location.path.clone(),
        });
    }
    if !plan.requires_write() {
        let current = read_location(&plan.location)?;
        if !matches_before(plan.before.as_ref(), current.as_ref()) {
            return Err(HookError::ReviewedStateChanged {
                path: plan.location.path.clone(),
            });
        }
        return Ok(plan.change);
    }

    let transaction = acquire_hook_transaction(plan.location.clone(), authorization)?;
    let before = transaction
        .target
        .read_regular()
        .map_err(|source| map_hook_read_error(&transaction.location.path, source))?;
    if !matches_before(plan.before.as_ref(), before.as_ref()) {
        return Err(HookError::ReviewedStateChanged {
            path: plan.location.path.clone(),
        });
    }
    before_commit();
    let effect = transaction
        .target
        .replace_if_exact_with_permissions(
            before.as_ref(),
            &plan.content,
            AnchoredFilePermissions::executable(),
        )
        .map_err(|source| HookError::Write {
            path: transaction.location.path.clone(),
            source,
        })?;
    match effect {
        AnchoredEffect::Durable(_) => {}
        AnchoredEffect::CommittedVerifiedButDurabilityUncertain { .. } => eprintln!(
            "warning: pre-commit hook replacement committed and was verified, but directory crash durability is not provable on this platform"
        ),
        AnchoredEffect::CommittedButUncertain { error, .. } => {
            return Err(HookError::CommittedButUncertain {
                path: transaction.location.path,
                source: error,
            })
        }
    }
    Ok(plan.change)
}

fn matches_before(expected: Option<&HookBeforeImage>, current: Option<&AnchoredRead>) -> bool {
    match (expected, current) {
        (None, None) => true,
        (Some(expected), Some(current)) => expected.read == *current,
        _ => false,
    }
}

/// Request exact trusted-terminal authority for a global/system configured
/// hook parent outside both the project and Git common directory.
///
/// The returned proof is bound to the resolved path, Git provenance, and the
/// retained parent identity. Its fields are private and the production
/// constructor performs this terminal exchange; this is not a sandbox against
/// a compromised same-user process or terminal.
pub fn authorize_external_install_from_terminal(
    project_dir: &Path,
) -> Result<Option<ExternalHookAuthorization>, HookError> {
    authorize_external_install_with(
        project_dir,
        OsStr::new("git"),
        std::io::stdin().is_terminal()
            && std::io::stdout().is_terminal()
            && std::io::stderr().is_terminal(),
        &mut std::io::stdin().lock(),
        &mut std::io::stderr().lock(),
    )
}

fn authorize_external_install_with(
    project_dir: &Path,
    git_program: &OsStr,
    attached: bool,
    input: &mut impl BufRead,
    output: &mut impl Write,
) -> Result<Option<ExternalHookAuthorization>, HookError> {
    let Some(location) = resolve_location_with_git(project_dir, git_program)? else {
        return Ok(None);
    };
    match &location.authority {
        HookAuthority::Project | HookAuthority::GitCommon => return Ok(None),
        HookAuthority::ExternalDenied { scope, origin } => {
            return Err(HookError::ExternalWriteDenied {
                path: location.path.clone(),
                scope: scope.clone(),
                origin: origin.clone(),
            })
        }
        HookAuthority::ExternalOperatorConfig { .. } => {}
    }
    if !attached {
        return Err(HookError::TrustedTerminalRequired);
    }
    let hook = terminal_safe(&location.path)?;
    let (scope, origin) = match &location.authority {
        HookAuthority::ExternalOperatorConfig { scope, origin } => (scope, origin),
        _ => unreachable!("external authority checked above"),
    };
    let origin = terminal_safe(Path::new(origin))?;
    let challenge = format!("AUTHORIZE PHANTOM PRE-COMMIT HOOK {hook} FROM {scope} {origin}");
    writeln!(
        output,
        "Git resolves its pre-commit hook outside this project and Git common directory.\nHook: {hook}\nConfiguration: {scope} {origin}\nType this exact challenge to authorize this one external hook parent:\n{challenge}"
    )
    .map_err(HookError::AuthorizationIo)?;
    write!(output, "> ").map_err(HookError::AuthorizationIo)?;
    output.flush().map_err(HookError::AuthorizationIo)?;
    let mut response = String::new();
    std::io::Read::take(&mut *input, (challenge.len() + 2) as u64)
        .read_line(&mut response)
        .map_err(HookError::AuthorizationIo)?;
    if response.trim_end_matches(['\r', '\n']) != challenge {
        return Err(HookError::AuthorizationRejected);
    }
    let parent = open_hook_parent(&location)?;
    Ok(Some(ExternalHookAuthorization {
        location,
        parent_identity: parent.identity(),
    }))
}

fn terminal_safe(path: &Path) -> Result<String, HookError> {
    let text = path.to_str().ok_or_else(|| HookError::InvalidPath {
        project: path.to_path_buf(),
        reason: "trusted-terminal path was not valid UTF-8".to_string(),
    })?;
    if text.chars().any(char::is_control) || text.len() > 4096 {
        return Err(HookError::InvalidPath {
            project: path.to_path_buf(),
            reason: "trusted-terminal path contained control characters or exceeded 4096 bytes"
                .to_string(),
        });
    }
    Ok(text
        .chars()
        .flat_map(char::escape_default)
        .collect::<String>())
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
            install_with_git(&linked, clean_git.as_os_str(), None).unwrap(),
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

    #[test]
    fn hook_publish_refuses_concurrent_owner() {
        let project = tempfile::tempdir().unwrap();
        init_git(project.path());
        let hook = resolve_path(project.path()).unwrap().unwrap();
        std::fs::write(&hook, b"#!/bin/sh\necho reviewed\n").unwrap();

        assert!(
            install_with_git_before_commit(project.path(), OsStr::new("git"), None, || {
                std::fs::write(&hook, b"#!/bin/sh\necho concurrent\n").unwrap()
            },)
            .is_err()
        );
        assert_eq!(
            std::fs::read(&hook).unwrap(),
            b"#!/bin/sh\necho concurrent\n"
        );
    }

    #[test]
    fn prepared_plan_rejects_same_bytes_replacement_identity() {
        let project = tempfile::tempdir().unwrap();
        init_git(project.path());
        let hook = resolve_path(project.path()).unwrap().unwrap();
        let reviewed = b"#!/bin/sh\necho reviewed\n";
        std::fs::write(&hook, reviewed).unwrap();
        let plan = prepare_install_plan(project.path()).unwrap().unwrap();
        std::fs::remove_file(&hook).unwrap();
        std::fs::write(&hook, reviewed).unwrap();

        assert!(matches!(
            commit_prepared_install(project.path(), &plan, None).unwrap_err(),
            HookError::ReviewedStateChanged { .. }
        ));
        assert_eq!(std::fs::read(hook).unwrap(), reviewed);
    }

    #[cfg(unix)]
    #[test]
    fn install_refuses_symlink_hook_parent() {
        use std::os::unix::fs::symlink;

        let project = tempfile::tempdir().unwrap();
        init_git(project.path());
        let outside = tempfile::tempdir().unwrap();
        symlink(outside.path(), project.path().join("custom-hooks")).unwrap();
        git(
            project.path(),
            &["config", "core.hooksPath", "custom-hooks"],
        );

        assert!(matches!(
            install(project.path()).unwrap_err(),
            HookError::CreateDirectory { .. }
        ));
        assert!(!outside.path().join("pre-commit").exists());
    }

    #[cfg(unix)]
    #[test]
    fn install_refuses_symlinked_hook_parent_ancestor() {
        use std::os::unix::fs::symlink;

        let project = tempfile::tempdir().unwrap();
        init_git(project.path());
        let outside = tempfile::tempdir().unwrap();
        std::fs::create_dir(outside.path().join("hooks")).unwrap();
        std::fs::create_dir(project.path().join("configured")).unwrap();
        symlink(outside.path(), project.path().join("configured/link")).unwrap();
        git(
            project.path(),
            &["config", "core.hooksPath", "configured/link/hooks"],
        );

        assert!(matches!(
            install(project.path()).unwrap_err(),
            HookError::CreateDirectory { .. }
        ));
        assert!(!outside.path().join("hooks/pre-commit").exists());
    }

    #[test]
    fn repository_config_cannot_authorize_external_hook_write() {
        let project = tempfile::tempdir().unwrap();
        init_git(project.path());
        let outside = tempfile::tempdir().unwrap();
        let outside_text = outside.path().to_string_lossy().into_owned();
        git(project.path(), &["config", "core.hooksPath", &outside_text]);

        assert!(matches!(
            inspect(project.path()).unwrap_err(),
            HookError::ExternalWriteDenied { .. }
        ));
        let error = install(project.path()).unwrap_err();

        assert!(matches!(error, HookError::ExternalWriteDenied { .. }));
        assert!(!outside.path().join("pre-commit").exists());
    }

    #[cfg(unix)]
    #[test]
    fn global_external_hook_requires_exact_terminal_authorization() {
        use std::os::unix::fs::PermissionsExt;

        let container = tempfile::tempdir().unwrap();
        let project = container.path().join("project");
        let common = project.join(".git");
        let outside = container.path().join("operator-hooks");
        std::fs::create_dir_all(&common).unwrap();
        std::fs::create_dir(&outside).unwrap();
        let hook = outside.join("pre-commit");
        let fake_git = container.path().join("fake-git");
        let origin = container.path().join("global.gitconfig");
        std::fs::write(
            &fake_git,
            format!(
                "#!/bin/sh\ncase \"$*\" in\n  *--is-inside-work-tree*) printf 'true\\n' ;;\n  *'--git-path hooks/pre-commit'*) printf '%s\\n' '{}' ;;\n  *--git-common-dir*) printf '%s\\n' '{}' ;;\n  *'config --null'*) printf 'global\\000file:{}\\000{}\\000' ;;\n  *) exit 2 ;;\nesac\n",
                hook.display(),
                common.display(),
                origin.display(),
                outside.display(),
            ),
        )
        .unwrap();
        std::fs::set_permissions(&fake_git, std::fs::Permissions::from_mode(0o755)).unwrap();

        assert!(matches!(
            install_with_git(&project, fake_git.as_os_str(), None).unwrap_err(),
            HookError::ExternalWriteDenied { .. }
        ));
        let location = resolve_location_with_git(&project, fake_git.as_os_str())
            .unwrap()
            .unwrap();
        let challenge = format!(
            "AUTHORIZE PHANTOM PRE-COMMIT HOOK {} FROM global file:{}",
            terminal_safe(&hook).unwrap(),
            terminal_safe(&origin).unwrap()
        );
        let mut output = Vec::new();
        let authorization = authorize_external_install_with(
            &project,
            fake_git.as_os_str(),
            true,
            &mut std::io::Cursor::new(format!("{challenge}\n")),
            &mut output,
        )
        .unwrap()
        .unwrap();
        assert_eq!(authorization.location, location);

        assert_eq!(
            install_with_git(&project, fake_git.as_os_str(), Some(&authorization)).unwrap(),
            Some(HookChange::Installed)
        );
        assert!(is_current(&std::fs::read_to_string(hook).unwrap()));
    }

    #[test]
    fn missing_effective_hook_parent_is_not_created_ambiently() {
        let project = tempfile::tempdir().unwrap();
        init_git(project.path());
        git(
            project.path(),
            &["config", "core.hooksPath", "missing-hooks"],
        );

        let error = install(project.path()).unwrap_err();

        assert!(matches!(error, HookError::CreateDirectory { .. }));
        assert!(!project.path().join("missing-hooks").exists());
    }

    #[cfg(unix)]
    #[test]
    fn retained_hook_parent_ignores_rename_replacement_decoy() {
        let container = tempfile::tempdir().unwrap();
        let project = container.path().join("project");
        let moved = container.path().join("moved-hooks");
        std::fs::create_dir(&project).unwrap();
        init_git(&project);
        git(&project, &["config", "core.hooksPath", "custom-hooks"]);
        let hooks = project.join("custom-hooks");
        std::fs::create_dir(&hooks).unwrap();
        let hook = hooks.join("pre-commit");
        std::fs::write(&hook, b"#!/bin/sh\necho reviewed\n").unwrap();

        install_with_git_before_commit(&project, OsStr::new("git"), None, || {
            std::fs::rename(&hooks, &moved).unwrap();
            std::fs::create_dir(&hooks).unwrap();
            std::fs::write(hooks.join("pre-commit"), b"#!/bin/sh\necho decoy\n").unwrap();
        })
        .unwrap();

        assert!(is_current(
            &std::fs::read_to_string(moved.join("pre-commit")).unwrap()
        ));
        assert_eq!(
            std::fs::read(hooks.join("pre-commit")).unwrap(),
            b"#!/bin/sh\necho decoy\n"
        );
    }

    #[test]
    fn retained_hook_transaction_contract_is_cross_platform_visible() {
        let source = include_str!("precommit_hook.rs");
        assert!(source.contains("struct HookTransaction"));
        assert!(source.contains("_parent: TrustedAnchor"));
        assert!(source.contains("_lock: AnchoredLock"));
        assert!(source.contains("replace_if_exact_with_permissions"));
        assert!(source.contains("AnchoredFilePermissions::executable()"));
        assert!(source.contains("CommittedButUncertain"));
        assert!(!source.contains(concat!("ensure_real_parent", "(&path)")));
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
