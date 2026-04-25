use anyhow::Result;
use colored::Colorize;
use std::path::{Path, PathBuf};

/// Auto-detect .env files — checks current dir first, then immediate subdirectories.
pub fn find_env_file(project_dir: &Path, user_specified: &str) -> Option<PathBuf> {
    let names = [
        user_specified,
        ".env.local",
        ".env",
        ".env.development",
        ".env.development.local",
    ];

    // Check current directory first
    for name in &names {
        let path = project_dir.join(name);
        if path.exists() {
            return Some(path);
        }
    }

    // Scan immediate subdirectories (monorepo support)
    if let Ok(entries) = std::fs::read_dir(project_dir) {
        for entry in entries.flatten() {
            let sub = entry.path();
            if !sub.is_dir() {
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

pub fn ensure_gitignore(project_dir: &Path) -> Result<()> {
    let gitignore_path = project_dir.join(".gitignore");

    let mut content = if gitignore_path.exists() {
        std::fs::read_to_string(&gitignore_path)?
    } else {
        String::new()
    };

    let mut added = Vec::new();

    // Ensure .phantom.toml is NOT ignored (it contains no secrets, and teammates need it)
    // But ensure .env is ignored
    for pattern in &[".env", ".env.local", ".env.*.local", ".env.backup"] {
        if !content.lines().any(|l| l.trim() == *pattern) {
            if !content.is_empty() && !content.ends_with('\n') {
                content.push('\n');
            }
            content.push_str(pattern);
            content.push('\n');
            added.push(*pattern);
        }
    }

    if !added.is_empty() {
        std::fs::write(&gitignore_path, &content)?;
        println!(
            "{} Added {} to .gitignore",
            "ok".green().bold(),
            added.join(", ")
        );
    }

    Ok(())
}
