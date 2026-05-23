use std::collections::BTreeMap;

use anyhow::{Context, Result};
use colored::Colorize;
use phantom_core::config::PhantomConfig;
use zeroize::Zeroize;

/// Dispatch to the appropriate export mode based on flags.
pub fn run(
    output: Option<&str>,
    passphrase: Option<&str>,
    json: bool,
    allow_plaintext: bool,
) -> Result<()> {
    if json && passphrase.is_some() {
        anyhow::bail!(
            "{} --json and --passphrase are mutually exclusive.\n\
             Use {} for an encrypted file backup, or {} {} for plaintext JSON to stdout.",
            "!".yellow().bold(),
            "--passphrase".bold(),
            "--json".bold(),
            "--allow-plaintext".bold(),
        );
    }

    if json {
        run_json(allow_plaintext)
    } else {
        let out = output.unwrap_or("phantom-export.enc");
        let pass = passphrase.context(
            "Missing --passphrase. Provide a passphrase to encrypt the backup file, \
             or use --json --allow-plaintext for plaintext JSON output.",
        )?;
        run_encrypted(out, pass)
    }
}

/// Emit all secrets as a plaintext JSON object to stdout.
/// Requires `allow_plaintext` to be true; otherwise refuses with an explanatory error.
fn run_json(allow_plaintext: bool) -> Result<()> {
    if !allow_plaintext {
        anyhow::bail!(
            "{} Refusing to emit plaintext secrets.\n\n\
             {} exports ALL vault secrets as unencrypted JSON to stdout. \
             Anyone who can read your terminal history, shell logs, or pipe destination \
             will see the raw secret values.\n\n\
             If you understand the risk and want to proceed, add the {} flag:\n\n  \
             phantom export --json --allow-plaintext\n\n\
             To write an encrypted backup instead, use:\n\n  \
             phantom export --output FILE --passphrase PASS",
            "!".red().bold(),
            "phantom export --json".bold(),
            "--allow-plaintext".bold(),
        );
    }

    let project_dir = std::env::current_dir()?;
    let config_path = project_dir.join(".phantom.toml");

    if !config_path.exists() {
        anyhow::bail!(
            "No .phantom.toml found. Run {} first.",
            "phantom init".cyan().bold()
        );
    }

    let config = PhantomConfig::load(&config_path).context("Failed to load .phantom.toml")?;
    let vault = phantom_vault::create_vault(&config.phantom.project_id);

    phantom_core::audit::log_result("vault.export_plaintext", None)
        .context("Failed to write audit event for plaintext vault export")?;

    let names = vault.list().context("Failed to list secrets")?;

    if names.is_empty() {
        // Still valid JSON; emit an empty object so pipes/parsers don't break.
        println!("{{}}");
        return Ok(());
    }

    // Collect into a sorted map so output is deterministic (alphabetical by key).
    let mut secrets: BTreeMap<String, String> = BTreeMap::new();
    for name in &names {
        let value = vault
            .retrieve(name)
            .context(format!("Failed to retrieve secret: {name}"))?;
        secrets.insert(name.clone(), String::from(value.as_str()));
    }

    // Serialize to pretty JSON.  serde_json may internally copy values before we
    // zeroize; this is best-effort -- the underlying String allocations are wiped
    // below but any intermediate copies inside serde_json are beyond our control.
    let mut json_out =
        serde_json::to_string_pretty(&secrets).context("Failed to serialize secrets to JSON")?;

    // Zeroize the secret values from the map before printing.
    for v in secrets.values_mut() {
        v.zeroize();
    }

    println!("{json_out}");

    json_out.zeroize();

    Ok(())
}

/// Write an encrypted backup file (original behaviour).
fn run_encrypted(output: &str, passphrase: &str) -> Result<()> {
    let project_dir = std::env::current_dir()?;
    let config_path = project_dir.join(".phantom.toml");

    if !config_path.exists() {
        anyhow::bail!(
            "No .phantom.toml found. Run {} first.",
            "phantom init".cyan().bold()
        );
    }

    let config = PhantomConfig::load(&config_path).context("Failed to load .phantom.toml")?;
    let vault = phantom_vault::create_vault(&config.phantom.project_id);

    phantom_core::audit::log_result("vault.export_encrypted", None)
        .context("Failed to write audit event for encrypted vault export")?;

    let names = vault.list().context("Failed to list secrets")?;

    if names.is_empty() {
        println!("{} No secrets to export.", "!".yellow().bold());
        return Ok(());
    }

    // Collect all secrets into a sorted map
    let mut secrets = BTreeMap::new();
    for name in &names {
        let value = vault
            .retrieve(name)
            .context(format!("Failed to retrieve secret: {name}"))?;
        secrets.insert(name.clone(), String::from(value.as_str()));
    }

    // Check if output file already exists
    let output_path = project_dir.join(output);
    if output_path.exists() {
        anyhow::bail!(
            "Output file {} already exists. Delete it first or choose a different name.",
            output.bold()
        );
    }

    // Serialize to JSON
    let mut json = serde_json::to_string(&secrets).context("Failed to serialize secrets")?;

    // Encrypt with passphrase
    let encrypted = phantom_vault::crypto::encrypt(json.as_bytes(), passphrase)
        .context("Failed to encrypt export data")?;
    json.zeroize();

    // Write to output file
    std::fs::write(&output_path, &encrypted)
        .context(format!("Failed to write export file: {output}"))?;

    println!(
        "{} Exported {} secret(s) to {}",
        "ok".green().bold(),
        names.len(),
        output.bold()
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// run() with --json but no --allow-plaintext must refuse with an error.
    #[test]
    fn json_mode_refuses_without_allow_plaintext() {
        let err = run(None, None, true, false).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("Refusing to emit plaintext secrets"),
            "expected refusal message, got: {msg}"
        );
        assert!(
            msg.contains("--allow-plaintext"),
            "expected --allow-plaintext hint in message, got: {msg}"
        );
    }

    /// --json and --passphrase together must be rejected regardless of --allow-plaintext.
    #[test]
    fn json_and_passphrase_are_mutually_exclusive() {
        let err = run(None, Some("secret"), true, true).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("mutually exclusive"),
            "expected mutual-exclusion message, got: {msg}"
        );
    }

    /// Encrypted mode without passphrase should fail with a helpful message.
    #[test]
    fn encrypted_mode_requires_passphrase() {
        let err = run(Some("out.enc"), None, false, false).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("passphrase") || msg.contains("--passphrase"),
            "expected passphrase hint, got: {msg}"
        );
    }
}
