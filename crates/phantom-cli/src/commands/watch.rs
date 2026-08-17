use anyhow::{Context, Result};
use colored::Colorize;
use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use phantom_core::audit;
use phantom_core::config::PhantomConfig;
use phantom_core::dotenv::{DotenvFile, SecretClassification};
use phantom_core::rotation_strategy::overdue_description;
use phantom_core::token::TokenMap;
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::{Duration, Instant};

/// Extended entry point used by the CLI `--auto-rotate` flag.
pub fn run_with_rotate(auto: bool, auto_rotate: bool) -> Result<()> {
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
    if auto_rotate {
        println!(
            "   {} Auto-rotate mode enabled (checks every 30 s)",
            "!".yellow().bold()
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
    // How often to check the rotation schedule (30 s).
    let rotation_check_interval = Duration::from_secs(30);
    let mut last_rotation_check = Instant::now();

    loop {
        // Perform a rotation-schedule check if auto_rotate is enabled and the
        // interval has elapsed.
        if auto_rotate && last_rotation_check.elapsed() >= rotation_check_interval {
            last_rotation_check = Instant::now();
            let env_path = project_dir.join(".env");
            check_and_rotate(&config_path, &env_path);
        }

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
            Err(mpsc::RecvTimeoutError::Timeout) => {
                // Timeout is expected — loop back to check rotation schedule.
            }
            Err(e) => {
                eprintln!("{} Watch error: {}", "!".red().bold(), e);
                break;
            }
        }
    }

    Ok(())
}

/// Check whether any secret is past its rotation schedule and, if so, rotate it.
fn check_and_rotate(config_path: &Path, env_path: &Path) {
    let config = match PhantomConfig::load(config_path) {
        Ok(c) => c,
        Err(_) => return,
    };

    let vault = phantom_vault::create_vault(&config.phantom.project_id);
    let names = match vault.list() {
        Ok(n) => n,
        Err(_) => return,
    };

    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let mut rotated_names: Vec<String> = Vec::new();

    for name in &names {
        let schedule = match config.get_rotation_schedule(name) {
            Some(s) => s,
            None => continue,
        };

        if !schedule.should_rotate_now(now_secs) {
            continue;
        }

        // Describe how overdue this secret is.
        let overdue = overdue_description(&schedule, now_secs)
            .unwrap_or_else(|| "at schedule boundary".to_string());

        println!(
            "{} Rotated {} ({}) — auto-rotate triggered",
            "->".blue().bold(),
            name.bold(),
            overdue.yellow()
        );

        // Audit the rotation event.
        audit::log("rotation.auto", Some(name));

        rotated_names.push(name.clone());
    }

    if rotated_names.is_empty() {
        return;
    }

    // Generate new phantom tokens for the rotated secrets and rewrite .env.
    let mut token_map = TokenMap::new();
    for name in &rotated_names {
        token_map.insert(name.clone());
    }

    if env_path.exists() {
        match DotenvFile::parse_file(env_path) {
            Ok(dotenv) => {
                if let Err(e) = dotenv.write_phantomized(&token_map, env_path) {
                    eprintln!(
                        "{} Failed to rewrite .env after auto-rotate: {}",
                        "!".red().bold(),
                        e
                    );
                } else {
                    println!(
                        "{} .env rewritten with {} new phantom token(s)",
                        "ok".green().bold(),
                        rotated_names.len()
                    );
                }
            }
            Err(e) => {
                eprintln!("{} Failed to parse .env: {}", "!".red().bold(), e);
            }
        }
    }

    // Update last_rotated in the config file so subsequent checks don't
    // immediately re-trigger.
    update_last_rotated(config_path, &rotated_names, now_secs);
}

/// Persist `last_rotated = now_secs` for each rotated secret's schedule entry
/// in `.phantom.toml`. Updates both the global policy (if any) and any
/// per-secret overrides.
fn update_last_rotated(config_path: &Path, names: &[String], now_secs: u64) {
    let mut config = match PhantomConfig::load(config_path) {
        Ok(c) => c,
        Err(_) => return,
    };

    // Update global rotation_policy last_rotated.
    if let Some(ref mut policy) = config.phantom.rotation_policy {
        policy.last_rotated = Some(now_secs);
    }

    // Update per-secret overrides.
    for name in names {
        if let Some(ov) = config.phantom.secrets.get_mut(name) {
            if let Some(ref mut sched) = ov.rotation_schedule {
                sched.last_rotated = Some(now_secs);
            }
        }
    }

    if let Err(e) = config.save(config_path) {
        eprintln!(
            "{} Failed to update .phantom.toml after rotation: {}",
            "!".red().bold(),
            e
        );
    }
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
            let vault = phantom_vault::create_vault(&config.phantom.project_id);
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
