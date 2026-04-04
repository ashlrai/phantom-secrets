use anyhow::{Context, Result};
use colored::Colorize;
use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use phantom_core::config::PhantomConfig;
use phantom_core::dotenv::{DotenvFile, SecretClassification};
use phantom_core::token::TokenMap;
use std::path::Path;
use std::sync::mpsc;

/// Watch .env files for changes and auto-protect new secrets.
pub fn run(auto: bool) -> Result<()> {
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
        anyhow::bail!("No .env files found to watch.");
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

    // Watch each .env file
    for file in &watched {
        let path = project_dir.join(file);
        watcher
            .watch(&path, RecursiveMode::NonRecursive)
            .context(format!("Failed to watch {}", file))?;
    }

    // Process events
    loop {
        match rx.recv() {
            Ok(event) => {
                if matches!(event.kind, EventKind::Modify(_) | EventKind::Create(_)) {
                    for path in &event.paths {
                        if let Some(file_name) = path.file_name().and_then(|n| n.to_str()) {
                            if file_name.starts_with(".env") {
                                handle_env_change(path, &config_path, auto);
                            }
                        }
                    }
                }
            }
            Err(e) => {
                eprintln!("{} Watch error: {}", "!".red().bold(), e);
                break;
            }
        }
    }

    Ok(())
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
        // Auto-protect
        if let Ok(config) = PhantomConfig::load(config_path) {
            let vault = phantom_vault::create_vault(&config.phantom.project_id);
            let mut token_map = TokenMap::new();

            for entry in &new_secrets {
                token_map.insert(entry.key.clone());
                if let Err(e) = vault.store(&entry.key, &entry.value) {
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
