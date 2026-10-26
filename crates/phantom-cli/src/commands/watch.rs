use anyhow::{Context, Result};
use colored::Colorize;
use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use phantom_core::config::PhantomConfig;
use phantom_core::dotenv::{DotenvFile, SecretClassification};
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::Duration;

/// Extended entry point used by the CLI `--auto-rotate` flag.
pub fn run_with_rotate(auto: bool, auto_rotate: bool) -> Result<()> {
    if auto_rotate {
        anyhow::bail!(
            "--auto-rotate is deprecated and disabled: the legacy watcher only remapped local phm_ placeholders and marked rotation schedules complete without rotating provider credentials. Automated live provider issuance is disabled in this release; rotate through the provider's trusted interface, then store the successor with trusted-terminal `phantom add`."
        );
    }
    if auto {
        anyhow::bail!(
            "--auto is disabled before any mutation in this release: the legacy watcher could leave vault and dotenv state partially updated after a concurrent edit or write failure. Run `phantom watch` for detection, then review the file and run `phantom init` from a trusted terminal for transactional protection."
        );
    }

    let project_dir = crate::util::project_dir()?;
    let Some(config) = crate::util::load_config_if_present(&project_dir.join(".phantom.toml"))
        .context("Failed to load .phantom.toml")?
    else {
        anyhow::bail!(
            "Not initialized. Run {} first.",
            "phantom init".cyan().bold()
        );
    };
    let watched = watched_dotenv_paths(&project_dir, &config)?;

    if watched.is_empty() {
        anyhow::bail!(
            "No managed or conventional dotenv files found to watch.\n  {}",
            crate::util::docs_url("getting-started")
        );
    }

    validate_watched_dotenvs(&project_dir, &watched)?;

    println!(
        "{} Watching for new secrets in: {}",
        "->".blue().bold(),
        watched
            .iter()
            .map(|path| path.display().to_string())
            .collect::<Vec<_>>()
            .join(", ")
            .cyan()
    );
    println!("   New secrets will be reported; protection requires reviewed `phantom init`.");
    println!("   Press Ctrl+C to stop.\n");

    let (tx, rx) = mpsc::channel();

    let mut watcher: RecommendedWatcher = Watcher::new(
        move |res: notify::Result<Event>| {
            if let Ok(event) = res {
                let _ = tx.send(event);
            }
        },
        notify::Config::default(),
    )
    .context("Failed to create file watcher")?;

    for path in &watched {
        watcher
            .watch(path, RecursiveMode::NonRecursive)
            .with_context(|| format!("Failed to watch {}", path.display()))?;
    }
    let watched: HashSet<PathBuf> = watched.into_iter().collect();

    // Debounce window for file-change events.
    let debounce = Duration::from_millis(200);
    loop {
        match rx.recv_timeout(Duration::from_secs(5)) {
            Ok(event) => {
                let mut pending_paths: std::collections::HashSet<PathBuf> =
                    std::collections::HashSet::new();
                collect_env_paths(&event, &watched, &mut pending_paths);

                while let Ok(extra) = rx.recv_timeout(debounce) {
                    collect_env_paths(&extra, &watched, &mut pending_paths);
                }

                for path in &pending_paths {
                    let _ = handle_env_change(&project_dir, path);
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(e) => {
                eprintln!("{} Watch error: {}", "!".red().bold(), e);
                break;
            }
        }
    }

    Ok(())
}

/// Read one path from [`watched_dotenv_paths`]. That listing checks each path
/// before the watcher starts, and the file can be swapped for a symlink after
/// it; this read opens without following one and judges the opened handle.
/// `Ok(None)` when the file is gone.
fn read_watched(project_dir: &Path, path: &Path) -> Result<Option<DotenvFile>> {
    let name = path
        .strip_prefix(project_dir)
        .ok()
        .and_then(|name| name.to_str())
        .with_context(|| format!("{} is not a dotenv in the project", path.display()))?;
    phantom_core::managed_dotenv::parse_regular_dotenv(project_dir, name)
}

fn validate_watched_dotenvs(project_dir: &Path, watched: &[PathBuf]) -> Result<()> {
    for path in watched {
        read_watched(project_dir, path)
            .with_context(|| format!("Failed to read {} before starting watcher", path.display()))?
            .with_context(|| format!("{} was removed before the watcher started", path.display()))?
            .validate_for_mutation()
            .with_context(|| {
                format!(
                    "{} is malformed; watcher did not announce readiness or start",
                    path.display()
                )
            })?;
    }
    Ok(())
}

fn watched_dotenv_paths(project_dir: &Path, config: &PhantomConfig) -> Result<Vec<PathBuf>> {
    let mut candidates = vec![
        project_dir.join(".env"),
        project_dir.join(".env.local"),
        project_dir.join(".env.development"),
    ];
    if let Some(configured) = config.phantom.dotenv_path.as_deref() {
        let configured = phantom_core::managed_dotenv::validate_dotenv_basename(configured)?;
        candidates.push(project_dir.join(configured));
    }

    let mut watched = Vec::new();
    for path in candidates {
        if watched.contains(&path) {
            continue;
        }
        match std::fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
                anyhow::bail!(
                    "Refusing dotenv watch target that is not a regular, non-symlink file: {}",
                    path.display()
                )
            }
            Ok(_) => watched.push(path),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error).with_context(|| format!("Failed to inspect {}", path.display()))
            }
        }
    }
    Ok(watched)
}

fn collect_env_paths(event: &Event, watched: &HashSet<PathBuf>, paths: &mut HashSet<PathBuf>) {
    if matches!(event.kind, EventKind::Modify(_) | EventKind::Create(_)) {
        for path in &event.paths {
            if watched.contains(path) {
                paths.insert(path.clone());
            }
        }
    }
}

/// What one change event led to; the watcher loop only prints it.
#[derive(Debug, PartialEq, Eq)]
enum ChangeOutcome {
    /// The file is gone.
    Gone,
    /// The file was not read (a symlink or other refusal): BLOCKED.
    Unreadable,
    /// The file was read but is malformed: BLOCKED.
    Malformed,
    /// No unprotected secrets.
    Clean,
    /// This many unprotected secrets were reported.
    Secrets(usize),
}

fn handle_env_change(project_dir: &Path, env_path: &Path) -> ChangeOutcome {
    let dotenv = match read_watched(project_dir, env_path) {
        Ok(Some(dotenv)) => dotenv,
        Ok(None) => return ChangeOutcome::Gone,
        Err(error) => {
            eprintln!(
                "{} {} was not read; secret detection is indeterminate: {:#}",
                "BLOCKED".red().bold(),
                env_path.display(),
                error
            );
            return ChangeOutcome::Unreadable;
        }
    };
    if let Err(error) = dotenv.validate_for_mutation() {
        eprintln!(
            "{} {} is malformed; secret detection is indeterminate: {}",
            "BLOCKED".red().bold(),
            env_path.display(),
            error
        );
        return ChangeOutcome::Malformed;
    }

    let classified = dotenv.classified_entries();
    let new_secrets: Vec<_> = classified
        .iter()
        .filter(|(_, c)| *c == SecretClassification::Secret)
        .map(|(e, _)| e)
        .collect();

    if new_secrets.is_empty() {
        return ChangeOutcome::Clean;
    }

    let file_name = env_path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(".env");

    println!(
        "\n{} Detected {} unprotected secret(s) in {}:",
        "!".yellow().bold(),
        new_secrets.len(),
        file_name.cyan()
    );
    for entry in &new_secrets {
        println!("   {} {}", "+".cyan().bold(), entry.key.bold());
    }

    println!(
        "   {} Review the file, then run {} from a trusted terminal",
        "->".blue().bold(),
        "phantom init".cyan().bold()
    );
    ChangeOutcome::Secrets(new_secrets.len())
}

#[cfg(test)]
mod tests {
    use super::*;
    use notify::event::ModifyKind;

    #[test]
    fn legacy_auto_rotation_fails_before_watcher_or_filesystem_mutation() {
        let error = run_with_rotate(false, true).unwrap_err();
        assert!(error.to_string().contains("deprecated and disabled"));
        assert!(error
            .to_string()
            .contains("without rotating provider credentials"));
    }

    #[test]
    fn legacy_auto_protect_fails_before_watcher_or_filesystem_mutation() {
        let error = run_with_rotate(true, false).unwrap_err();
        assert!(error.to_string().contains("--auto is disabled"));
        assert!(error.to_string().contains("before any mutation"));
        assert!(error.to_string().contains("phantom init"));
    }

    #[test]
    fn configured_custom_dotenv_is_watched_and_collected() {
        let dir = tempfile::tempdir().unwrap();
        let custom = dir.path().join("custom.env");
        std::fs::write(&custom, "API_KEY=phm_placeholder\n").unwrap();
        let mut config = PhantomConfig::new_with_defaults("watch-custom".to_string());
        config.phantom.dotenv_path = Some("custom.env".to_string());

        let watched = watched_dotenv_paths(dir.path(), &config).unwrap();
        assert_eq!(watched, vec![custom.clone()]);

        let watched_set = HashSet::from([custom.clone()]);
        let event = Event::new(EventKind::Modify(ModifyKind::Any)).add_path(custom.clone());
        let mut collected = HashSet::new();
        collect_env_paths(&event, &watched_set, &mut collected);
        assert_eq!(collected, HashSet::from([custom]));
    }

    #[test]
    fn configured_dotenv_traversal_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = PhantomConfig::new_with_defaults("watch-traversal".to_string());
        config.phantom.dotenv_path = Some("../outside.env".to_string());
        assert!(watched_dotenv_paths(dir.path(), &config).is_err());
    }

    #[test]
    fn initial_validation_rejects_malformed_without_touching_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".env");
        let before = b"API_KEY=plaintext-must-not-escape\nBROKEN_RECORD\n";
        std::fs::write(&path, before).unwrap();

        let error = validate_watched_dotenvs(dir.path(), std::slice::from_ref(&path)).unwrap_err();

        assert!(error.to_string().contains("malformed"));
        assert!(!error.to_string().contains("plaintext-must-not-escape"));
        assert_eq!(std::fs::read(path).unwrap(), before);
    }

    #[cfg(unix)]
    #[test]
    fn configured_dotenv_symlink_is_rejected() {
        use std::os::unix::fs::symlink;
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target.env");
        std::fs::write(&target, "API_KEY=real\n").unwrap();
        symlink(&target, dir.path().join("custom.env")).unwrap();
        let mut config = PhantomConfig::new_with_defaults("watch-symlink".to_string());
        config.phantom.dotenv_path = Some("custom.env".to_string());
        assert!(watched_dotenv_paths(dir.path(), &config).is_err());
    }

    /// A watched file swapped for a symlink after it was listed: the start-up
    /// validation must refuse the link rather than validate its target.
    #[cfg(unix)]
    #[test]
    fn initial_validation_refuses_a_listed_file_swapped_for_a_symlink() {
        let dir = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let target = outside.path().join("elsewhere.env");
        std::fs::write(&target, "NODE_ENV=development\n").unwrap();
        let path = dir.path().join(".env");
        std::fs::write(&path, "NODE_ENV=development\n").unwrap();
        let config = PhantomConfig::new_with_defaults("watch-swap".to_string());
        let watched = watched_dotenv_paths(dir.path(), &config).unwrap();
        assert_eq!(watched, vec![path.clone()]);

        std::fs::remove_file(&path).unwrap();
        std::os::unix::fs::symlink(&target, &path).unwrap();

        let error = validate_watched_dotenvs(dir.path(), &watched).unwrap_err();
        assert!(
            format!("{error:#}").contains("not a regular, non-symlink file"),
            "{error:#}"
        );
    }

    /// The change handler reads through the same handle check: a watched
    /// file that is now a symlink is refused, not followed.
    #[cfg(unix)]
    #[test]
    fn change_read_refuses_a_watched_file_now_a_symlink() {
        let dir = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let target = outside.path().join("elsewhere.env");
        std::fs::write(&target, format!("OPENAI_API_KEY={}-outside\n", "sk")).unwrap();
        let path = dir.path().join(".env");
        std::os::unix::fs::symlink(&target, &path).unwrap();

        let error = read_watched(dir.path(), &path).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("not a regular, non-symlink file"),
            "{error:#}"
        );
        assert!(read_watched(dir.path(), &dir.path().join(".env.local"))
            .unwrap()
            .is_none());
    }

    /// A watched file that is a symlink when it changes is reported as
    /// BLOCKED, not skipped silently and not followed.
    #[cfg(unix)]
    #[test]
    fn change_to_a_symlink_is_blocked_not_skipped() {
        let dir = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let target = outside.path().join("elsewhere.env");
        std::fs::write(&target, format!("OPENAI_API_KEY={}-outside\n", "sk")).unwrap();
        let path = dir.path().join(".env");
        std::fs::write(&path, format!("OPENAI_API_KEY={}-inside\n", "sk")).unwrap();
        assert_eq!(
            handle_env_change(dir.path(), &path),
            ChangeOutcome::Secrets(1)
        );

        std::fs::remove_file(&path).unwrap();
        std::os::unix::fs::symlink(&target, &path).unwrap();
        assert_eq!(
            handle_env_change(dir.path(), &path),
            ChangeOutcome::Unreadable
        );

        std::fs::remove_file(&path).unwrap();
        assert_eq!(handle_env_change(dir.path(), &path), ChangeOutcome::Gone);
        std::fs::write(&path, "NODE_ENV=development\n").unwrap();
        assert_eq!(handle_env_change(dir.path(), &path), ChangeOutcome::Clean);
        std::fs::write(&path, "BROKEN_RECORD\n").unwrap();
        assert_eq!(
            handle_env_change(dir.path(), &path),
            ChangeOutcome::Malformed
        );
    }
}
