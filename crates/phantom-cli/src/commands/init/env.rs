use anyhow::{Context, Result};
use colored::Colorize;
use std::path::{Path, PathBuf};

// The persistent foreground lifecycle lock contains no PID, port, or bearer,
// but it is runtime state and does not belong in Git.
const GITIGNORE_PATTERNS: &[&str] = &[
    ".env",
    ".env.local",
    ".env.*.local",
    ".env.backup",
    ".phantom.proxy.lock",
    ".phantom.pid",
    ".phantom.start.lock",
];

/// Auto-detect .env files — checks current dir first, then immediate subdirectories.
pub fn find_env_file(project_dir: &Path, user_specified: &str) -> Option<PathBuf> {
    let project_dir = project_dir.canonicalize().ok()?;
    let mut names = vec![
        ".env.local",
        ".env",
        ".env.development",
        ".env.development.local",
    ];
    if phantom_core::managed_dotenv::validate_dotenv_basename(user_specified).is_ok() {
        names.retain(|name| *name != user_specified);
        names.insert(0, user_specified);
    }

    // Check current directory first
    for name in &names {
        let path = project_dir.join(name);
        if path.exists() {
            return Some(path);
        }
    }

    // Scan immediate subdirectories (monorepo support)
    if let Ok(entries) = std::fs::read_dir(&project_dir) {
        for entry in entries.flatten() {
            // DirEntry::file_type does not follow a symlink. On Windows,
            // directory symlinks and junction/name-surrogate reparse points
            // must not widen one-level auto-discovery authority.
            if !entry.file_type().is_ok_and(|file_type| file_type.is_dir()) {
                continue;
            }
            let sub = entry.path();
            let Ok(sub) = sub.canonicalize() else {
                continue;
            };
            if sub.parent() != Some(project_dir.as_path()) {
                continue;
            }
            // Skip hidden dirs, node_modules, target, etc.
            let dir_name = sub.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if dir_name.starts_with('.')
                || dir_name == "node_modules"
                || dir_name == "target"
                || dir_name == "dist"
                || dir_name == "build"
            {
                continue;
            }
            for name in &names {
                let path = sub.join(name);
                if path.exists() {
                    println!(
                        "{} Found {} in subdirectory {}",
                        "->".blue().bold(),
                        name.bold(),
                        dir_name.cyan()
                    );
                    return Some(path);
                }
            }
        }
    }

    None
}

/// Prepare the exact ignore-file update for inclusion in init's transaction.
pub fn prepare_gitignore(project_dir: &Path) -> Result<Option<phantom_vault::InitFile>> {
    let gitignore_path = project_dir.join(".gitignore");
    let before = phantom_core::fs::read_regular_file(&gitignore_path)
        .with_context(|| format!("Failed to safely read {}", gitignore_path.display()))?;
    let mut content = match before.as_deref() {
        Some(bytes) => std::str::from_utf8(bytes)
            .context(".gitignore is not valid UTF-8; refusing to rewrite it")?
            .to_string(),
        None => String::new(),
    };
    let original = content.clone();
    for pattern in GITIGNORE_PATTERNS {
        if !content.lines().any(|line| line.trim() == *pattern) {
            if !content.is_empty() && !content.ends_with('\n') {
                content.push('\n');
            }
            content.push_str(pattern);
            content.push('\n');
        }
    }
    Ok((content != original).then(|| {
        phantom_vault::InitFile::replace_if_unchanged(gitignore_path, before, content.into_bytes())
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn auto_discovery_accepts_one_real_immediate_subdirectory() {
        let root = tempdir().unwrap();
        let child = root.path().join("api");
        std::fs::create_dir(&child).unwrap();
        std::fs::write(child.join(".env"), "API_KEY=reviewed\n").unwrap();

        assert_eq!(
            find_env_file(root.path(), ".env"),
            Some(child.canonicalize().unwrap().join(".env"))
        );
    }

    #[cfg(unix)]
    #[test]
    fn auto_discovery_does_not_follow_an_outside_directory_symlink() {
        use std::os::unix::fs::symlink;

        let root = tempdir().unwrap();
        let outside = tempdir().unwrap();
        std::fs::write(outside.path().join(".env"), "API_KEY=outside\n").unwrap();
        symlink(outside.path(), root.path().join("linked-api")).unwrap();

        assert_eq!(find_env_file(root.path(), ".env"), None);
    }

    #[test]
    fn portable_source_contract_rejects_linked_or_non_child_directories() {
        let source = include_str!("env.rs");
        assert!(source.contains("entry.file_type().is_ok_and"));
        assert!(source.contains("sub.parent() != Some(project_dir.as_path())"));
    }
}
