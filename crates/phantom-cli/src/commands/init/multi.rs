use anyhow::{Context, Result};
use colored::Colorize;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Filenames we treat as "this repo has a .env worth protecting."
const ENV_FILENAMES: &[&str] = &[
    ".env",
    ".env.local",
    ".env.development",
    ".env.development.local",
    ".env.production",
    ".env.production.local",
    ".env.staging",
];

const SKIP_DIRS: &[&str] = &[
    "node_modules",
    "target",
    "dist",
    "build",
    ".next",
    ".nuxt",
    ".venv",
    "venv",
    "__pycache__",
];

const DEFAULT_DEPTH: usize = 5;

pub fn run(root: PathBuf, dry_run: bool) -> Result<()> {
    let root = root
        .canonicalize()
        .with_context(|| format!("Could not resolve {}", root.display()))?;

    println!(
        "{} Scanning {} for repos with .env files...",
        "->".blue().bold(),
        root.display()
    );

    let candidates = find_candidates(&root, DEFAULT_DEPTH);

    if candidates.is_empty() {
        println!("{} No candidate repos found.", "!".yellow().bold());
        return Ok(());
    }

    println!(
        "{} Found {} repo(s):\n",
        "->".blue().bold(),
        candidates.len()
    );

    let mut protected = 0usize;
    let mut skipped = 0usize;
    let mut errored = 0usize;

    for repo in &candidates {
        let rel = repo.strip_prefix(&root).unwrap_or(repo);
        let display = if rel.as_os_str().is_empty() {
            "(this repo)".to_string()
        } else {
            rel.display().to_string()
        };

        if repo.join(".phantom.toml").exists() {
            println!("  {} {} (already protected)", "·".dimmed(), display);
            skipped += 1;
            continue;
        }
        if dry_run {
            println!("  {} {} (would protect)", "+".cyan().bold(), display);
            continue;
        }
        match run_init_for(repo) {
            Ok(count) => {
                println!(
                    "  {} {} ({} secret{} protected)",
                    "ok".green().bold(),
                    display,
                    count,
                    if count == 1 { "" } else { "s" }
                );
                protected += 1;
            }
            Err(e) => {
                println!("  {} {}: {}", "FAIL".red().bold(), display, e);
                errored += 1;
            }
        }
    }

    let summary = if dry_run {
        format!(
            "{} repo(s) would be protected · {} already protected",
            candidates.len() - skipped,
            skipped
        )
    } else {
        format!("protected: {protected} · skipped: {skipped} · errors: {errored}")
    };
    println!("\n{} {}", "done".green().bold(), summary);

    if errored > 0 {
        anyhow::bail!("{errored} repo(s) failed to init — see output above");
    }
    Ok(())
}

/// Walk `root` up to `max_depth` levels. Yield directories that contain both
/// `.git/` AND at least one of `ENV_FILENAMES`. Stop descending once a match
/// is found (don't recurse into a protected repo's subdirs).
fn find_candidates(root: &Path, max_depth: usize) -> Vec<PathBuf> {
    let mut out = Vec::new();
    walk(root, max_depth, &mut out);
    out.sort();
    out.dedup();
    out
}

fn walk(dir: &Path, depth_remaining: usize, out: &mut Vec<PathBuf>) {
    if depth_remaining == 0 {
        return;
    }

    let has_git = dir.join(".git").exists();
    let has_env = ENV_FILENAMES.iter().any(|n| dir.join(n).exists());

    if has_git && has_env {
        out.push(dir.to_path_buf());
        return; // Don't descend into an already-discovered repo.
    }

    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };

    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name();
        let name_str = name.to_string_lossy();

        // Skip dot-dirs entirely (.git, .cache, .vscode, etc.)
        if name_str.starts_with('.') {
            continue;
        }
        // Skip well-known noise dirs.
        if SKIP_DIRS.iter().any(|s| **s == *name_str) {
            continue;
        }

        if let Ok(ft) = entry.file_type() {
            if ft.is_dir() {
                walk(&path, depth_remaining - 1, out);
            }
        }
    }
}

/// Spawn a child `phantom init` in `repo`. Captures output and returns the
/// number of secrets protected (parsed from stdout) on success.
fn run_init_for(repo: &Path) -> Result<usize> {
    let exe = std::env::current_exe().context("Could not resolve current exe")?;
    let output = Command::new(&exe)
        .arg("init")
        .current_dir(repo)
        .output()
        .context("Failed to spawn `phantom init`")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let combined = if stderr.trim().is_empty() {
            String::from_utf8_lossy(&output.stdout).trim().to_string()
        } else {
            stderr.trim().to_string()
        };
        anyhow::bail!("{}", first_line(&combined));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    Ok(parse_secret_count(&stdout))
}

fn first_line(s: &str) -> String {
    s.lines().next().unwrap_or(s).to_string()
}

/// Parse "Found N secret(s) to protect:" from `phantom init` stdout.
/// Returns 0 if not found (still treated as success).
fn parse_secret_count(stdout: &str) -> usize {
    for line in stdout.lines() {
        if let Some(rest) = line.split_once("Found ").map(|(_, r)| r) {
            if let Some((num, _)) = rest.split_once(' ') {
                if let Ok(n) = num.parse::<usize>() {
                    return n;
                }
            }
        }
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn touch(path: &Path) {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(path, "").unwrap();
    }

    #[test]
    fn find_candidates_picks_up_repos_with_env_and_git() {
        let tmp = tempdir().unwrap();
        let root = tmp.path();

        // repo-a: has .git + .env  → should match
        touch(&root.join("repo-a/.git/HEAD"));
        touch(&root.join("repo-a/.env"));

        // repo-b: has .git + .env.local → should match
        touch(&root.join("repo-b/.git/HEAD"));
        touch(&root.join("repo-b/.env.local"));

        // repo-c: has .env but no .git → should NOT match
        touch(&root.join("repo-c/.env"));

        // repo-d: has .git but no .env → should NOT match
        touch(&root.join("repo-d/.git/HEAD"));

        let found = find_candidates(root, 5);
        assert_eq!(found.len(), 2);
        assert!(found.iter().any(|p| p.ends_with("repo-a")));
        assert!(found.iter().any(|p| p.ends_with("repo-b")));
    }

    #[test]
    fn find_candidates_skips_node_modules() {
        let tmp = tempdir().unwrap();
        let root = tmp.path();

        touch(&root.join("node_modules/some-pkg/.git/HEAD"));
        touch(&root.join("node_modules/some-pkg/.env"));

        let found = find_candidates(root, 5);
        assert_eq!(found.len(), 0);
    }

    #[test]
    fn find_candidates_does_not_descend_into_found_repo() {
        let tmp = tempdir().unwrap();
        let root = tmp.path();

        // outer repo
        touch(&root.join("repo/.git/HEAD"));
        touch(&root.join("repo/.env"));
        // inner "repo" should be ignored
        touch(&root.join("repo/inner/.git/HEAD"));
        touch(&root.join("repo/inner/.env"));

        let found = find_candidates(root, 5);
        assert_eq!(found.len(), 1);
        assert!(found[0].ends_with("repo"));
    }

    #[test]
    fn parse_secret_count_extracts_n() {
        let stdout = "-> Reading .env...\n-> Found 5 secret(s) to protect:\n   + OPENAI_API_KEY\n";
        assert_eq!(parse_secret_count(stdout), 5);
    }

    #[test]
    fn parse_secret_count_returns_zero_when_absent() {
        assert_eq!(parse_secret_count("hello world"), 0);
    }
}
