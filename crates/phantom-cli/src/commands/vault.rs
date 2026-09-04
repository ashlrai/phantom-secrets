#[cfg(any(target_os = "linux", test))]
use anyhow::Context;
use anyhow::Result;
#[cfg(target_os = "linux")]
use phantom_core::config::PhantomConfig;
#[cfg(target_os = "linux")]
use phantom_core::dotenv::DotenvFile;
#[cfg(target_os = "linux")]
use phantom_core::token::PhantomToken;
#[cfg(target_os = "linux")]
use std::collections::BTreeSet;
#[cfg(any(target_os = "linux", test))]
use std::io::BufRead;
#[cfg(target_os = "linux")]
use std::io::{IsTerminal, Write};

#[cfg(any(target_os = "linux", test))]
const MAX_CONFIRMATION_BYTES: usize = 2048;

pub fn run_migrate_linux(json: bool) -> Result<()> {
    #[cfg(not(target_os = "linux"))]
    {
        let _ = json;
        anyhow::bail!("`phantom vault migrate-linux` is available only on Linux");
    }

    #[cfg(target_os = "linux")]
    {
        if !std::io::stdin().is_terminal()
            || !std::io::stdout().is_terminal()
            || !std::io::stderr().is_terminal()
        {
            anyhow::bail!(
                "`phantom vault migrate-linux` requires attached stdin, stdout, and stderr terminals. No vault value was read and no backend state changed"
            );
        }

        let project_dir = std::env::current_dir()?
            .canonicalize()
            .context("Failed to resolve project directory")?;
        let config_path = project_dir.join(".phantom.toml");
        let config_before = phantom_core::fs::read_regular_file(&config_path)?
            .context("Project is not initialized. Run `phantom init --empty` first.")?;
        let config = PhantomConfig::load_from_bytes(&config_path, &config_before)
            .context("Failed to load exact .phantom.toml snapshot")?;
        super::add::validate_managed_dotenv_preflight(&project_dir, &config)?;

        let preview =
            phantom_vault::keychain::preview_linux_persistent_migration(config.local_project_id())?;
        if preview.already_persistent {
            emit_receipt(
                json,
                config.local_project_id(),
                preview.source_secret_count,
                &preview.source_state_id,
                true,
            )?;
            return Ok(());
        }

        // A reboot can empty keyutils while managed dotenv still contains
        // placeholders. Never bless an empty/incomplete snapshot as the new
        // persistent authority in that state.
        let managed = phantom_core::managed_dotenv::resolve_dotenv(&project_dir, &config, &[])?;
        let managed_names: BTreeSet<String> = managed
            .file
            .iter()
            .flat_map(DotenvFile::entries)
            .filter(|entry| PhantomToken::is_phantom_token(&entry.value))
            .map(|entry| entry.key.clone())
            .collect();
        let indexed_names: BTreeSet<&str> =
            preview.indexed_names.iter().map(String::as_str).collect();
        let missing: Vec<&str> = managed_names
            .iter()
            .map(String::as_str)
            .filter(|name| !indexed_names.contains(name))
            .collect();
        if !missing.is_empty() {
            anyhow::bail!(
                "Linux keyutils does not contain {} managed placeholder name(s): {}. It may have been cleared by a reboot. Restore the source vault or use the explicit encrypted-file fallback; no backend marker was written",
                missing.len(),
                missing.join(", ")
            );
        }

        let challenge = format!(
            "MIGRATE LINUX VAULT {} COUNT {} STATE {}",
            config.local_project_id(),
            preview.source_secret_count,
            preview.source_state_id
        );
        eprintln!(
            "This copies the current project's keyutils credentials into the desktop Secret Service, verifies every copy, then selects Secret Service for this project. Existing keyutils entries are retained. If Secret Service is unavailable later, Phantom will fail closed instead of silently using the volatile copy.\nProject: {}\nIndexed secret count: {}\nSource state: {}\nType this exact challenge to continue:\n{}",
            project_dir.display(),
            preview.source_secret_count,
            preview.source_state_id,
            challenge
        );
        eprint!("> ");
        std::io::stderr().flush()?;
        confirm_exact(&challenge, &mut std::io::stdin().lock())?;

        let receipt = phantom_vault::keychain::migrate_linux_to_secret_service(
            config.local_project_id(),
            &preview.source_state_id,
        )?;
        emit_receipt(
            json,
            config.local_project_id(),
            receipt.migrated_secret_count,
            &receipt.source_state_id,
            receipt.already_persistent,
        )
    }
}

#[cfg(any(target_os = "linux", test))]
fn confirm_exact<R: std::io::BufRead>(expected: &str, reader: &mut R) -> Result<()> {
    let mut response = String::new();
    let mut bounded = std::io::Read::take(reader, MAX_CONFIRMATION_BYTES as u64);
    bounded
        .read_line(&mut response)
        .context("Failed to read Linux vault migration confirmation")?;
    if response.trim_end_matches(['\r', '\n']) != expected {
        anyhow::bail!(
            "Linux vault migration confirmation did not match exactly. No vault value was read and no backend state changed"
        );
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn emit_receipt(
    json: bool,
    project_id: &str,
    secret_count: usize,
    source_state_id: &str,
    already_persistent: bool,
) -> Result<()> {
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "backend": "linux-secret-service",
                "project_id": project_id,
                "secret_count": secret_count,
                "source_state_id": source_state_id,
                "already_persistent": already_persistent,
                "source_keyutils_entries_retained": true,
            }))?
        );
    } else if already_persistent {
        println!(
            "Linux vault already uses Secret Service for this project ({} indexed secret(s)).",
            secret_count
        );
    } else {
        println!(
            "Migrated {} indexed secret(s) to Linux Secret Service. Source keyutils entries were retained.",
            secret_count
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_confirmation_is_required() {
        let mut exact = std::io::Cursor::new(b"MIGRATE STATE abc\n");
        confirm_exact("MIGRATE STATE abc", &mut exact).unwrap();

        let mut wrong = std::io::Cursor::new(b"MIGRATE STATE def\n");
        let error = confirm_exact("MIGRATE STATE abc", &mut wrong).unwrap_err();
        assert!(error.to_string().contains("did not match exactly"));
    }

    #[test]
    fn confirmation_input_is_bounded() {
        let expected = "MIGRATE STATE abc";
        let payload = format!("{}{}\n", expected, "X".repeat(8 * 1024));
        let mut reader = std::io::Cursor::new(payload.into_bytes());
        assert!(confirm_exact(expected, &mut reader).is_err());
        assert!(reader.position() <= MAX_CONFIRMATION_BYTES as u64);
    }
}
