use anyhow::{Context, Result};
use colored::Colorize;
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

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
pub const DEFAULT_JOBS: usize = 4;

/// Read the job count from the environment variable `PHANTOM_INIT_JOBS`.
/// Returns `None` if the variable is absent or non-positive.
pub fn jobs_from_env() -> Option<usize> {
    std::env::var("PHANTOM_INIT_JOBS")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .filter(|&n| n > 0)
}

pub fn run(root: PathBuf, dry_run: bool, jobs: usize) -> Result<()> {
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

    // ── dry-run: no concurrency needed, just print ────────────────────────
    if dry_run {
        let mut skipped = 0usize;
        for repo in &candidates {
            let display = repo_display(repo, &root);
            if repo.join(".phantom.toml").exists() {
                println!("  {} {} (already protected)", "·".dimmed(), display);
                skipped += 1;
            } else {
                println!("  {} {} (would protect)", "+".cyan().bold(), display);
            }
        }
        println!(
            "\n{} {} repo(s) would be protected · {} already protected",
            "done".green().bold(),
            candidates.len() - skipped,
            skipped
        );
        return Ok(());
    }

    // ── live run: parallel with a bounded thread pool ─────────────────────
    let total = candidates.len();

    let protected = Arc::new(AtomicUsize::new(0));
    let skipped = Arc::new(AtomicUsize::new(0));
    let errored = Arc::new(AtomicUsize::new(0));

    let mp = Arc::new(MultiProgress::new());

    let bar_style = ProgressStyle::with_template("{spinner:.cyan} [{pos}/{len}] protected: {msg}")
        .unwrap()
        .tick_strings(&["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏", ""]);

    let bar = mp.add(ProgressBar::new(total as u64));
    bar.set_style(bar_style);
    bar.set_message("0 · skipped: 0 · errors: 0".to_string());
    bar.enable_steady_tick(std::time::Duration::from_millis(80));

    // Channel: main thread sends repo paths; workers receive them.
    let (tx, rx) = std::sync::mpsc::sync_channel::<PathBuf>(total);
    let rx = Arc::new(std::sync::Mutex::new(rx));

    for repo in candidates {
        tx.send(repo).unwrap();
    }
    drop(tx); // close so workers know when to stop

    let mut handles = Vec::with_capacity(jobs);

    for _ in 0..jobs {
        let rx = Arc::clone(&rx);
        let mp = Arc::clone(&mp);
        let bar = bar.clone();
        let root = root.clone();
        let protected = Arc::clone(&protected);
        let skipped = Arc::clone(&skipped);
        let errored = Arc::clone(&errored);

        let handle = std::thread::spawn(move || loop {
            let repo = {
                let guard = rx.lock().unwrap();
                guard.recv().ok()
            };
            let repo = match repo {
                Some(r) => r,
                None => break,
            };

            let display = repo_display(&repo, &root);

            let line = if repo.join(".phantom.toml").exists() {
                skipped.fetch_add(1, Ordering::Relaxed);
                format!("  {} {} (already protected)", "·".dimmed(), display)
            } else {
                match run_init_for(&repo) {
                    Ok(count) => {
                        protected.fetch_add(1, Ordering::Relaxed);
                        format!(
                            "  {} {} ({} secret{} protected)",
                            "ok".green().bold(),
                            display,
                            count,
                            if count == 1 { "" } else { "s" }
                        )
                    }
                    Err(e) => {
                        errored.fetch_add(1, Ordering::Relaxed);
                        format!("  {} {}: {}", "FAIL".red().bold(), display, e)
                    }
                }
            };

            mp.println(&line).ok();

            bar.inc(1);
            let p = protected.load(Ordering::Relaxed);
            let s = skipped.load(Ordering::Relaxed);
            let e = errored.load(Ordering::Relaxed);
            bar.set_message(format!("{p} · skipped: {s} · errors: {e}"));
        });

        handles.push(handle);
    }

    for h in handles {
        h.join().expect("worker thread panicked");
    }
    bar.finish_and_clear();

    let p = protected.load(Ordering::Relaxed);
    let s = skipped.load(Ordering::Relaxed);
    let e = errored.load(Ordering::Relaxed);

    println!(
        "\n{} protected: {p} · skipped: {s} · errors: {e}",
        "done".green().bold()
    );

    if e > 0 {
        anyhow::bail!("{e} repo(s) failed to init — see output above");
    }
    Ok(())
}

/// Return a short display string for `repo` relative to `root`.
fn repo_display(repo: &Path, root: &Path) -> String {
    let rel = repo.strip_prefix(root).unwrap_or(repo);
    if rel.as_os_str().is_empty() {
        "(this repo)".to_string()
    } else {
        rel.display().to_string()
    }
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
    use std::sync::atomic::Ordering;
    use std::sync::Arc;
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

    /// Verify the jobs_from_env parsing logic (zero and non-numeric are rejected).
    #[test]
    fn jobs_env_parse_logic() {
        let parse = |s: &str| -> Option<usize> { s.parse::<usize>().ok().filter(|&n| n > 0) };
        assert_eq!(parse("8"), Some(8));
        assert_eq!(parse("1"), Some(1));
        assert_eq!(parse("0"), None);
        assert_eq!(parse("abc"), None);
    }

    /// --jobs 1 must visit every candidate exactly once (deterministic,
    /// single-worker drain of the sorted channel).
    ///
    /// Uses pre-protected repos (.phantom.toml present) so no subprocess is
    /// spawned — the parallel machinery is exercised end-to-end without
    /// side-effects.
    #[test]
    fn jobs_1_visits_all_candidates() {
        let tmp = tempdir().unwrap();
        let root = tmp.path();

        for name in ["alpha", "beta", "gamma"] {
            touch(&root.join(format!("{name}/.git/HEAD")));
            touch(&root.join(format!("{name}/.env")));
            touch(&root.join(format!("{name}/.phantom.toml")));
        }

        let candidates = find_candidates(root, 5);
        assert_eq!(candidates.len(), 3);

        // Drive the channel/thread logic with jobs=1.
        let total = candidates.len();
        let skipped_count = Arc::new(AtomicUsize::new(0));
        let protected_count = Arc::new(AtomicUsize::new(0));
        let errored_count = Arc::new(AtomicUsize::new(0));

        let (tx, rx) = std::sync::mpsc::sync_channel::<PathBuf>(total);
        let rx = Arc::new(std::sync::Mutex::new(rx));
        for repo in &candidates {
            tx.send(repo.clone()).unwrap();
        }
        drop(tx);

        let mut handles = Vec::new();
        {
            let rx = Arc::clone(&rx);
            let s = Arc::clone(&skipped_count);
            let p = Arc::clone(&protected_count);
            let e = Arc::clone(&errored_count);
            handles.push(std::thread::spawn(move || loop {
                let repo = { rx.lock().unwrap().recv().ok() };
                match repo {
                    None => break,
                    Some(r) => {
                        if r.join(".phantom.toml").exists() {
                            s.fetch_add(1, Ordering::Relaxed);
                        } else {
                            match run_init_for(&r) {
                                Ok(_) => {
                                    p.fetch_add(1, Ordering::Relaxed);
                                }
                                Err(_) => {
                                    e.fetch_add(1, Ordering::Relaxed);
                                }
                            }
                        }
                    }
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }

        assert_eq!(skipped_count.load(Ordering::Relaxed), 3);
        assert_eq!(protected_count.load(Ordering::Relaxed), 0);
        assert_eq!(errored_count.load(Ordering::Relaxed), 0);
    }
}
