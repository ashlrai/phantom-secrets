use anyhow::{Context, Result};
use colored::Colorize;
use phantom_core::config::PhantomConfig;
use phantom_core::dotenv::DotenvFile;
use phantom_core::token::PhantomToken;
use serde::Serialize;
use std::path::Path;

pub fn run(oneline: bool, json: bool) -> Result<()> {
    let project_dir = std::env::current_dir()?;
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&metadata_status(&project_dir))?
        );
        return Ok(());
    }
    let config_path = project_dir.join(".phantom.toml");

    if !config_path.exists() {
        if oneline {
            println!("not initialized");
        } else {
            println!(
                "{} Not initialized. Run {} to get started.",
                "!".yellow().bold(),
                "phantom init".cyan().bold()
            );
        }
        return Ok(());
    }

    let config = PhantomConfig::load(&config_path).context("Failed to load .phantom.toml")?;
    let legacy = super::legacy_proxy::inspect(&project_dir);
    match &legacy {
        super::legacy_proxy::LegacyState::Missing => {}
        super::legacy_proxy::LegacyState::Authenticated(_) => {
            eprintln!("warning: authenticated legacy v0.7.3 proxy state detected")
        }
        super::legacy_proxy::LegacyState::Unverified(_) => {
            eprintln!("warning: unverified legacy v0.7.3 proxy state detected")
        }
        super::legacy_proxy::LegacyState::Unsafe(_) => {
            eprintln!("warning: unsafe legacy v0.7.3 proxy state detected")
        }
    }
    let managed = phantom_core::managed_dotenv::resolve_dotenv(&project_dir, &config, &[])?;
    if let Some(dotenv) = managed.file.as_ref() {
        dotenv
            .validate_for_mutation()
            .context("Managed dotenv is malformed; status is indeterminate")?;
    }
    let names: Vec<String> = managed
        .file
        .iter()
        .flat_map(DotenvFile::entries)
        .filter(|entry| PhantomToken::is_phantom_token(&entry.value))
        .map(|entry| entry.key.clone())
        .collect();
    let proxy_lock = super::proxy_lifecycle::inspect(config.local_project_id())?;

    if oneline {
        // Compact output for shell prompts
        let legacy_marker = match &legacy {
            super::legacy_proxy::LegacyState::Missing => "no legacy state",
            super::legacy_proxy::LegacyState::Authenticated(_) => {
                "authenticated legacy v0.7.3 state"
            }
            super::legacy_proxy::LegacyState::Unverified(_) => "unverified legacy v0.7.3 state",
            super::legacy_proxy::LegacyState::Unsafe(_) => "unsafe legacy v0.7.3 state",
        };
        println!(
            "{} managed placeholder{} · {} · {}",
            names.len(),
            if names.len() == 1 { "" } else { "s" },
            match proxy_lock {
                super::proxy_lifecycle::ProxyLockState::Held =>
                    "lifecycle lock held (listener not authenticated)",
                super::proxy_lifecycle::ProxyLockState::Missing
                | super::proxy_lifecycle::ProxyLockState::Available => "no lifecycle lock held",
            },
            legacy_marker
        );
        return Ok(());
    }

    println!("{}", "Phantom Status".bold().underline());
    println!();
    println!("  Project ID:  {}", config.portable_project_id().dimmed());
    println!(
        "  Vault:       {}",
        "not opened by read-only status".dimmed()
    );
    println!(
        "  Managed placeholders: {}",
        names.len().to_string().green().bold()
    );
    println!(
        "  Proxy:       {}",
        match proxy_lock {
            super::proxy_lifecycle::ProxyLockState::Held =>
                "machine-local lifecycle lock held; this does not authenticate or identify a listener".yellow(),
            super::proxy_lifecycle::ProxyLockState::Missing =>
                "no machine-local lifecycle lock record (status did not create one)".dimmed(),
            super::proxy_lifecycle::ProxyLockState::Available =>
                "machine-local lifecycle lock is not held".dimmed(),
        }
    );

    match legacy {
        super::legacy_proxy::LegacyState::Missing => {}
        super::legacy_proxy::LegacyState::Authenticated(proxy) => println!(
            "  Legacy:      authenticated v0.7.3 proxy record for PID {}; run `phantom stop` in a trusted terminal",
            proxy.pid
        ),
        super::legacy_proxy::LegacyState::Unverified(proxy) => println!(
            "  Legacy:      unverified/stale-or-reused v0.7.3 record for PID {}; left untouched",
            proxy.pid
        ),
        super::legacy_proxy::LegacyState::Unsafe(error) => println!(
            "  Legacy:      unsafe or malformed .phantom.pid; left untouched ({error})"
        ),
    }

    if !names.is_empty() {
        println!();
        println!(
            "  {}",
            "Managed dotenv placeholders (vault not inspected):".dimmed()
        );
        for name in &names {
            println!("    {} {}", "-".dimmed(), name);
        }
    }

    let proxy_services = config.proxy_services();
    let conn_services = config.connection_string_services();

    println!();
    println!("  {}", "Service mappings:".dimmed());
    for (name, svc) in &proxy_services {
        println!(
            "    {} {} -> {}",
            "-".dimmed(),
            name.cyan(),
            svc.pattern.as_deref().unwrap_or("n/a")
        );
    }
    for (name, _svc) in &conn_services {
        println!(
            "    {} {} ({})",
            "-".dimmed(),
            name.cyan(),
            "blocked for agentic execution; protocol-aware broker required".yellow()
        );
    }

    Ok(())
}

/// An observation contract, not an authorization or vault-health result.
/// Only fixed vocabulary and counts may cross this boundary; config values,
/// managed dotenv contents, and arbitrary filesystem errors stay local.
#[derive(Serialize)]
struct MetadataStatus {
    schema_version: u8,
    initialized: bool,
    inspection: &'static str,
    managed_dotenv: DotenvStatus,
    vault: VaultStatus,
    proxy: ProxyStatus,
    issues: Vec<StatusIssue>,
}

#[derive(Serialize)]
struct VaultStatus {
    inspected: bool,
}

#[derive(Serialize)]
struct DotenvStatus {
    inspected: bool,
}

#[derive(Serialize)]
struct ProxyStatus {
    lifecycle_lock: LifecycleLock,
    listener_authenticated: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "kebab-case")]
enum LifecycleLock {
    NotInspected,
    Missing,
    Available,
    Held,
    Unknown,
}

#[derive(Serialize)]
#[serde(rename_all = "kebab-case")]
enum StatusIssue {
    ConfigMissing,
    ConfigUnreadable,
    ConfigInvalid,
    ProxyLockUnavailable,
}

fn metadata_status(project_dir: &Path) -> MetadataStatus {
    let mut report = MetadataStatus {
        schema_version: 1,
        initialized: false,
        inspection: "metadata-only",
        managed_dotenv: DotenvStatus { inspected: false },
        vault: VaultStatus { inspected: false },
        proxy: ProxyStatus {
            lifecycle_lock: LifecycleLock::NotInspected,
            listener_authenticated: false,
        },
        issues: Vec::new(),
    };
    let config_path = project_dir.join(".phantom.toml");
    // Unlike the legacy human status path, never follow a config symlink or
    // open legacy proxy state (which contains a bearer and contacts a listener).
    let bytes = match phantom_core::fs::read_regular_file(&config_path) {
        Ok(Some(bytes)) => bytes,
        Ok(None) => {
            report.issues.push(StatusIssue::ConfigMissing);
            return report;
        }
        Err(_) => {
            report.issues.push(StatusIssue::ConfigUnreadable);
            return report;
        }
    };
    let config = match PhantomConfig::load_from_bytes(&config_path, &bytes) {
        Ok(config) => config,
        Err(_) => {
            report.issues.push(StatusIssue::ConfigInvalid);
            return report;
        }
    };
    // `initialized` means valid readable configuration only. It does not
    // imply that the vault is accessible or any requested action is allowed.
    report.initialized = true;

    report.proxy.lifecycle_lock = match super::proxy_lifecycle::inspect(config.local_project_id()) {
        Ok(super::proxy_lifecycle::ProxyLockState::Missing) => LifecycleLock::Missing,
        Ok(super::proxy_lifecycle::ProxyLockState::Available) => LifecycleLock::Available,
        Ok(super::proxy_lifecycle::ProxyLockState::Held) => LifecycleLock::Held,
        Err(_) => {
            report.issues.push(StatusIssue::ProxyLockUnavailable);
            LifecycleLock::Unknown
        }
    };
    report
}

#[cfg(test)]
mod tests {
    #[test]
    fn status_source_never_constructs_or_lists_a_vault() {
        let source = include_str!("status.rs");
        let constructor = ["try", "_create_vault"].concat();
        let listing = ["vault", ".list"].concat();
        assert!(!source.contains(&constructor));
        assert!(!source.contains(&listing));
        assert!(source.contains("not opened by read-only status"));
    }

    #[test]
    fn status_mapping_source_does_not_format_the_secret_key_field() {
        let source = include_str!("status.rs");
        let mappings = source.split("Service mappings:").nth(1).unwrap();
        let implementation = mappings.split("#[cfg(test)]").next().unwrap();
        assert!(!implementation.contains("svc.secret_key"));
    }
}
