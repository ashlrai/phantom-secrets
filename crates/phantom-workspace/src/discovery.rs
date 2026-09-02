use crate::{Result, WorkspaceError};
use phantom_core::dotenv::{classify, DotenvFile, SecretClassification};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

const INSPECTION_SCHEMA_VERSION: u8 = 1;
const SKIPPED_DIRECTORIES: &[&str] = &[
    ".git",
    ".next",
    ".turbo",
    "build",
    "dist",
    "node_modules",
    "target",
    "vendor",
];

/// A value-blind description of one dotenv file.
///
/// Only key names and classifications are retained. Values parsed temporarily
/// by `phantom-core` are dropped before this structure is created.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnvFileObservation {
    /// Slash-normalized path relative to the workspace root.
    pub path: String,
    pub entry_names: Vec<String>,
    pub unprotected_secret_names: Vec<String>,
    pub protected_secret_names: Vec<String>,
    pub public_key_names: Vec<String>,
    pub config_names: Vec<String>,
}

/// A normalized remote identity. The raw remote URL is intentionally omitted
/// because URLs can contain embedded credentials.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct GitRemoteIdentity {
    pub name: String,
    pub host: String,
    pub owner: String,
    pub repository: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GitIdentity {
    pub remotes: Vec<GitRemoteIdentity>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlaceHintConfidence {
    Medium,
    High,
}

/// A candidate place inferred from non-secret repository metadata.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct PlaceHint {
    pub label: String,
    pub source: String,
    pub confidence: PlaceHintConfidence,
    pub reason: String,
}

/// Complete value-blind workspace inspection result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkspaceInspection {
    pub schema_version: u8,
    pub workspace_root: String,
    /// Local inspection fingerprint derived from the canonical path.
    /// This is drift detection metadata, not an identity or authority claim.
    pub workspace_fingerprint: String,
    pub phantom_initialized: bool,
    pub env_example_exists: bool,
    pub env_files: Vec<EnvFileObservation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub git: Option<GitIdentity>,
    pub place_hints: Vec<PlaceHint>,
    pub warnings: Vec<String>,
}

/// Inspect a workspace without retaining or returning secret values.
pub fn inspect_workspace(root: impl AsRef<Path>) -> Result<WorkspaceInspection> {
    let requested_root = root.as_ref();
    if !requested_root.is_dir() {
        return Err(WorkspaceError::RootNotDirectory(
            requested_root.to_path_buf(),
        ));
    }

    let canonical_root = requested_root
        .canonicalize()
        .map_err(|source| WorkspaceError::Io {
            path: requested_root.to_path_buf(),
            source,
        })?;

    let mut env_paths = Vec::new();
    collect_env_files(&canonical_root, &canonical_root, &mut env_paths)?;
    env_paths.sort_by_key(|path| relative_path(&canonical_root, path));

    let mut env_files = Vec::with_capacity(env_paths.len());
    for path in env_paths {
        // Dotenv observations feed both authority planning and later vault/file
        // effects. Treating an unreadable or malformed file as a warning would
        // silently omit it from the sealed pre-state, so inspection must fail
        // closed instead.
        env_files.push(inspect_env_file(&canonical_root, &path)?);
    }
    let warnings = Vec::new();

    let git = inspect_git_identity(&canonical_root)?;
    let place_hints = build_place_hints(git.as_ref());
    let workspace_root = canonical_root.to_string_lossy().into_owned();
    let workspace_fingerprint = digest_hex(workspace_root.as_bytes());

    Ok(WorkspaceInspection {
        schema_version: INSPECTION_SCHEMA_VERSION,
        workspace_root,
        workspace_fingerprint,
        phantom_initialized: canonical_root.join(".phantom.toml").is_file(),
        env_example_exists: canonical_root.join(".env.example").is_file(),
        env_files,
        git,
        place_hints,
        warnings,
    })
}

fn collect_env_files(root: &Path, directory: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    let entries = std::fs::read_dir(directory).map_err(|source| WorkspaceError::Io {
        path: directory.to_path_buf(),
        source,
    })?;

    for entry in entries {
        let entry = entry.map_err(|source| WorkspaceError::Io {
            path: directory.to_path_buf(),
            source,
        })?;
        let path = entry.path();
        let file_type = entry.file_type().map_err(|source| WorkspaceError::Io {
            path: path.clone(),
            source,
        })?;

        if file_type.is_symlink() {
            continue;
        }
        if file_type.is_file() {
            if path
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(is_env_file_name)
            {
                out.push(path);
            }
            continue;
        }
        if !file_type.is_dir() {
            continue;
        }

        let name = entry.file_name();
        let name = name.to_string_lossy();
        if SKIPPED_DIRECTORIES.contains(&name.as_ref()) || name.starts_with('.') {
            continue;
        }

        // A nested Git checkout is a separate workspace and must not be
        // absorbed into the caller's setup plan.
        if path != root && path.join(".git").exists() {
            continue;
        }
        collect_env_files(root, &path, out)?;
    }
    Ok(())
}

fn is_env_file_name(name: &str) -> bool {
    if name == ".env" {
        return true;
    }
    if !name.starts_with(".env.") {
        return false;
    }
    !matches!(
        name,
        ".env.example" | ".env.sample" | ".env.template" | ".env.backup"
    ) && !name.ends_with(".example")
        && !name.ends_with(".sample")
        && !name.ends_with(".template")
        && !name.ends_with(".backup")
}

fn inspect_env_file(root: &Path, path: &Path) -> Result<EnvFileObservation> {
    let dotenv = DotenvFile::parse_file(path).map_err(|error| WorkspaceError::Io {
        path: path.to_path_buf(),
        source: std::io::Error::other(error.to_string()),
    })?;
    dotenv
        .validate_for_mutation()
        .map_err(|error| WorkspaceError::Io {
            path: path.to_path_buf(),
            source: std::io::Error::other(error.to_string()),
        })?;

    let mut entry_names = BTreeSet::new();
    let mut unprotected_secret_names = BTreeSet::new();
    let mut protected_secret_names = BTreeSet::new();
    let mut public_key_names = BTreeSet::new();
    let mut config_names = BTreeSet::new();

    for entry in dotenv.entries() {
        entry_names.insert(entry.key.clone());
        if entry.is_phantom {
            protected_secret_names.insert(entry.key.clone());
            continue;
        }
        match classify(entry) {
            SecretClassification::Secret => {
                unprotected_secret_names.insert(entry.key.clone());
            }
            SecretClassification::PublicKey => {
                public_key_names.insert(entry.key.clone());
            }
            SecretClassification::NotSecret => {
                config_names.insert(entry.key.clone());
            }
        }
    }

    Ok(EnvFileObservation {
        path: relative_path(root, path),
        entry_names: entry_names.into_iter().collect(),
        unprotected_secret_names: unprotected_secret_names.into_iter().collect(),
        protected_secret_names: protected_secret_names.into_iter().collect(),
        public_key_names: public_key_names.into_iter().collect(),
        config_names: config_names.into_iter().collect(),
    })
}

fn inspect_git_identity(root: &Path) -> Result<Option<GitIdentity>> {
    let Some(config_path) = git_config_path(root)? else {
        return Ok(None);
    };
    let content = std::fs::read_to_string(&config_path).map_err(|source| WorkspaceError::Io {
        path: config_path,
        source,
    })?;

    let mut current_remote: Option<String> = None;
    let mut remotes = BTreeSet::new();
    for raw_line in content.lines() {
        let line = raw_line.trim();
        if line.starts_with('[') && line.ends_with(']') {
            current_remote = parse_remote_section(line);
            continue;
        }
        let Some(remote_name) = current_remote.as_ref() else {
            continue;
        };
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        if key.trim() != "url" {
            continue;
        }
        if let Some((host, owner, repository)) = normalize_remote(value.trim()) {
            remotes.insert(GitRemoteIdentity {
                name: remote_name.clone(),
                host,
                owner,
                repository,
            });
        }
    }

    if remotes.is_empty() {
        Ok(None)
    } else {
        Ok(Some(GitIdentity {
            remotes: remotes.into_iter().collect(),
        }))
    }
}

fn git_config_path(root: &Path) -> Result<Option<PathBuf>> {
    let dot_git = root.join(".git");
    let metadata = match std::fs::symlink_metadata(&dot_git) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(source) => {
            return Err(WorkspaceError::Io {
                path: dot_git,
                source,
            })
        }
    };
    if metadata.file_type().is_symlink() {
        return Ok(None);
    }
    if metadata.is_dir() {
        return Ok(validated_git_config(&dot_git, &dot_git));
    }
    if !metadata.is_file() || metadata.len() > 4_096 {
        return Ok(None);
    }

    let content = std::fs::read_to_string(&dot_git).map_err(|source| WorkspaceError::Io {
        path: dot_git.clone(),
        source,
    })?;
    let mut lines = content.lines();
    let Some(line) = lines.next() else {
        return Ok(None);
    };
    if lines.any(|line| !line.trim().is_empty()) {
        return Ok(None);
    }
    let Some(raw_git_dir) = line.trim().strip_prefix("gitdir:") else {
        return Ok(None);
    };
    let raw_git_dir = raw_git_dir.trim();
    if raw_git_dir.is_empty() || raw_git_dir.contains('\0') {
        return Ok(None);
    }
    let git_dir = PathBuf::from(raw_git_dir);
    let git_dir = if git_dir.is_absolute() {
        git_dir
    } else {
        root.join(git_dir)
    };
    let canonical_git_dir = match git_dir.canonicalize() {
        Ok(path) if path.is_dir() => path,
        _ => return Ok(None),
    };

    // In-workspace indirection (for example, a `.git-data` separate git dir)
    // is contained by the canonical root. A linked worktree or
    // submodule may legitimately point outside, but only when the gitdir has a
    // canonical backlink to this exact `.git` file.
    if canonical_git_dir.starts_with(root) {
        return Ok(validated_git_config(&canonical_git_dir, &canonical_git_dir));
    }

    let backlink = canonical_git_dir.join("gitdir");
    let Some(backlink_target) = read_git_path_file(&backlink)? else {
        return Ok(None);
    };
    let backlink_target = resolve_git_path(&canonical_git_dir, &backlink_target);
    let canonical_dot_git = match dot_git.canonicalize() {
        Ok(path) => path,
        Err(_) => return Ok(None),
    };
    if backlink_target.canonicalize().ok().as_ref() != Some(&canonical_dot_git) {
        return Ok(None);
    }

    let common_dir_file = canonical_git_dir.join("commondir");
    let common_dir = if common_dir_file.exists() {
        let Some(common_dir) = read_git_path_file(&common_dir_file)? else {
            return Ok(None);
        };
        match resolve_git_path(&canonical_git_dir, &common_dir).canonicalize() {
            Ok(path) if path.is_dir() => path,
            _ => return Ok(None),
        }
    } else {
        canonical_git_dir.clone()
    };
    Ok(validated_git_config(&common_dir, &common_dir))
}

fn parse_remote_section(line: &str) -> Option<String> {
    let inner = line.strip_prefix('[')?.strip_suffix(']')?.trim();
    let name = inner.strip_prefix("remote \"")?.strip_suffix('"')?;
    if !valid_identity_component(name, 100) {
        return None;
    }
    Some(name.to_string())
}

fn normalize_remote(raw: &str) -> Option<(String, String, String)> {
    if raw.is_empty()
        || raw
            .bytes()
            .any(|byte| byte.is_ascii_whitespace() || byte == 0)
        || raw.contains('?')
        || raw.contains('#')
    {
        return None;
    }

    let (host, path) = if let Some((scheme, rest)) = raw.split_once("://") {
        if !matches!(scheme, "http" | "https" | "ssh" | "git") {
            return None;
        }
        let (authority, path) = rest.split_once('/')?;
        // URI userinfo is never needed for a value-blind identity hint and may
        // contain credentials. Ports and IPv6 literals are also omitted rather
        // than risking ambiguous authority parsing.
        if authority.contains('@') || authority.contains(':') {
            return None;
        }
        let host = authority;
        (host, path)
    } else if let Some((authority, path)) = raw.split_once(':') {
        // Accept only the conventional credential-free SCP spelling. An
        // arbitrary username can itself be sensitive and is not an identity.
        let host = authority.strip_prefix("git@")?;
        if host.contains('@') || host.contains(':') {
            return None;
        }
        (host, path)
    } else {
        return None;
    };

    if !valid_git_host(host) || path.starts_with('/') || path.ends_with('/') {
        return None;
    }
    let mut segments = path.split('/');
    let owner = segments.next()?;
    let raw_repository = segments.next()?;
    if segments.next().is_some() {
        return None;
    }
    let repository = raw_repository
        .strip_suffix(".git")
        .unwrap_or(raw_repository);
    if !valid_identity_component(owner, 100) || !valid_identity_component(repository, 255) {
        return None;
    }
    Some((
        host.to_ascii_lowercase(),
        owner.to_string(),
        repository.to_string(),
    ))
}

fn valid_git_host(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= 253
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
                && label
                    .as_bytes()
                    .first()
                    .is_some_and(u8::is_ascii_alphanumeric)
                && label
                    .as_bytes()
                    .last()
                    .is_some_and(u8::is_ascii_alphanumeric)
        })
}

fn valid_identity_component(component: &str, max_len: usize) -> bool {
    !component.is_empty()
        && component.len() <= max_len
        && component != "."
        && component != ".."
        && component
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn read_git_path_file(path: &Path) -> Result<Option<PathBuf>> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(source) => {
            return Err(WorkspaceError::Io {
                path: path.to_path_buf(),
                source,
            })
        }
    };
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > 4_096 {
        return Ok(None);
    }
    let content = std::fs::read_to_string(path).map_err(|source| WorkspaceError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    let value = content.trim();
    if value.is_empty() || value.contains('\0') || value.lines().count() != 1 {
        return Ok(None);
    }
    Ok(Some(PathBuf::from(value)))
}

fn resolve_git_path(base: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        base.join(path)
    }
}

fn validated_git_config(base: &Path, git_dir: &Path) -> Option<PathBuf> {
    let config = git_dir.join("config");
    let metadata = std::fs::symlink_metadata(&config).ok()?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return None;
    }
    let canonical_config = config.canonicalize().ok()?;
    if !canonical_config.starts_with(base) {
        return None;
    }
    Some(canonical_config)
}

fn build_place_hints(git: Option<&GitIdentity>) -> Vec<PlaceHint> {
    let mut hints = BTreeSet::new();
    if let Some(git) = git {
        for remote in &git.remotes {
            hints.insert(PlaceHint {
                label: remote.owner.clone(),
                source: format!("git.remote.{}", remote.name),
                confidence: if remote.name == "origin" {
                    PlaceHintConfidence::High
                } else {
                    PlaceHintConfidence::Medium
                },
                reason: format!(
                    "{} owns {}/{}",
                    remote.host, remote.owner, remote.repository
                ),
            });
        }
    }
    hints.into_iter().collect()
}

fn relative_path(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .components()
        .map(|component| component.as_os_str().to_string_lossy())
        .collect::<Vec<_>>()
        .join("/")
}

pub(crate) fn digest_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
