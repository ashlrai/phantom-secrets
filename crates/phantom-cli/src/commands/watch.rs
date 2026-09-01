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
            "--auto-rotate is deprecated and disabled: the legacy watcher only remapped local phm_ placeholders and marked rotation schedules complete without rotating provider credentials. Automated live provider issuance is disabled in 0.7.4; rotate through the provider's trusted interface, then store the successor with trusted-terminal `phantom add`."
        );
    }
    if auto {
        anyhow::bail!(
            "--auto is disabled before any mutation in 0.7.4: the legacy watcher could leave vault and dotenv state partially updated after a concurrent edit or write failure. Run `phantom watch` for detection, then review the file and run `phantom init` from a trusted terminal for transactional protection."
        );
    }

    let project_dir = std::env::current_dir()?;
    let config_path = project_dir.join(".phantom.toml");

    if !config_path.exists() {
        anyhow::bail!(
            "Not initialized. Run {} first.",
            "phantom init".cyan().bold()
        );
    }

    let config = PhantomConfig::load(&config_path)?;
    let watched = watched_dotenv_paths(&project_dir, &config)?;

    if watched.is_empty() {
        anyhow::bail!(
            "No managed or conventional dotenv files found to watch.\n  {}",
            crate::util::docs_url("getting-started")
        );
    }

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
                    handle_env_change(path);
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

fn handle_env_change(env_path: &Path) {
    match std::fs::symlink_metadata(env_path) {
        Ok(metadata) if !metadata.file_type().is_symlink() && metadata.is_file() => {}
        _ => return,
    }
    let dotenv = match DotenvFile::parse_file(env_path) {
        Ok(d) => d,
        Err(_) => return,
    };

    let classified = dotenv.classified_entries();
    let new_secrets: Vec<_> = classified
        .iter()
        .filter(|(_, c)| *c == SecretClassification::Secret)
        .map(|(e, _)| e)
        .collect();

    if new_secrets.is_empty() {
        return;
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
}
