use anyhow::{Context, Result};
use colored::Colorize;
use phantom_core::config::PhantomConfig;
use phantom_core::dotenv::DotenvFile;
use phantom_core::token::PhantomToken;

pub fn run(oneline: bool) -> Result<()> {
    let project_dir = std::env::current_dir()?;
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
