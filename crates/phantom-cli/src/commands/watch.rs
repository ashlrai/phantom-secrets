use anyhow::{Context, Result};
use colored::Colorize;
use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use phantom_core::config::PhantomConfig;
use phantom_core::dotenv::{DotenvFile, SecretClassification};
use phantom_core::token::TokenMap;
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::Duration;

/// Extended entry point used by the CLI `--auto-rotate` flag.
pub fn run_with_rotate(auto: bool, auto_rotate: bool) -> Result<()> {
    if auto_rotate {
        anyhow::bail!(
            "--auto-rotate is deprecated and disabled: the legacy watcher only remapped local phm_ placeholders and marked rotation schedules complete without rotating provider credentials. Use an explicitly reviewed `phantom rotate --name <NAME> [--provider <PROVIDER>]` transaction."
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

    let env_files = [".env", ".env.local", ".env.development"];
    let watched: Vec<_> = env_files
        .iter()
        .filter(|f| project_dir.join(f).exists())
        .collect();

    if watched.is_empty() {
        anyhow::bail!(
            "No .env files found to watch.\n  {}",
            crate::util::docs_url("getting-started")
        );
    }

    println!(
        "{} Watching for new secrets in: {}",
        "->".blue().bold(),
        watched
            .iter()
            .map(|f| f.to_string())
            .collect::<Vec<_>>()
            .join(", ")
            .cyan()
    );
    if auto {
        println!("   {} Auto-protect mode enabled", "!".yellow().bold());
    } else {
        println!(
            "   New secrets will be reported. Use {} for auto-protect.",
            "--auto".dimmed()
        );
    }
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

    for file in &watched {
        let path = project_dir.join(file);
        watcher
            .watch(&path, RecursiveMode::NonRecursive)
            .context(format!("Failed to watch {}", file))?;
    }

    // Debounce window for file-change events.
    let debounce = Duration::from_millis(200);
    loop {
        match rx.recv_timeout(Duration::from_secs(5)) {
            Ok(event) => {
                let mut pending_paths: std::collections::HashSet<PathBuf> =
                    std::collections::HashSet::new();
                collect_env_paths(&event, &mut pending_paths);

                while let Ok(extra) = rx.recv_timeout(debounce) {
                    collect_env_paths(&extra, &mut pending_paths);
                }

                for path in &pending_paths {
                    handle_env_change(path, &config_path, auto);
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

fn collect_env_paths(event: &Event, paths: &mut std::collections::HashSet<PathBuf>) {
    if matches!(event.kind, EventKind::Modify(_) | EventKind::Create(_)) {
        for path in &event.paths {
            if path
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with(".env"))
            {
                paths.insert(path.clone());
            }
        }
    }
}

fn handle_env_change(env_path: &Path, config_path: &Path, auto: bool) {
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

    if auto {
        if let Ok(config) = PhantomConfig::load(config_path) {
            let vault = phantom_vault::create_vault(config.local_project_id());
            let mut token_map = TokenMap::new();

            for entry in &new_secrets {
                token_map.insert(entry.key.clone());
                let secret = zeroize::Zeroizing::new(entry.value.clone());
                if let Err(e) = vault.store(&entry.key, &secret) {
                    eprintln!(
                        "   {} Failed to store {}: {}",
                        "!".red().bold(),
                        entry.key,
                        e
                    );
                    return;
                }
            }

            if let Ok(_originals) = dotenv.write_phantomized(&token_map, env_path) {
                println!(
                    "   {} Auto-protected {} secret(s)",
                    "ok".green().bold(),
                    new_secrets.len()
                );
            }
        }
    } else {
        println!(
            "   {} Run {} to protect them",
            "->".blue().bold(),
            "phantom init".cyan().bold()
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_auto_rotation_fails_before_watcher_or_filesystem_mutation() {
        let error = run_with_rotate(false, true).unwrap_err();
        assert!(error.to_string().contains("deprecated and disabled"));
        assert!(error
            .to_string()
            .contains("without rotating provider credentials"));
    }
}
