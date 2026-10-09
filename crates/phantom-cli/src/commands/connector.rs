//! `phantom connector` — signed provider connector packs.
//!
//! Packs extend Phantom with provider-specific validators, sync targets, and
//! importers without changing CLI source. Every pack is a *declarative* signed
//! manifest: no third-party code ever runs in the credential path.
//!
//! Trust posture (mirrors the rest of the CLI):
//! - Installing/removing packs and managing trust anchors requires an
//!   attached trusted terminal.
//! - Pack signatures are verified against operator-managed anchors
//!   (`~/.phantom/connectors/anchors/`).
//! - Pack signing keys are read from `PHANTOM_CONNECTOR_SIGNING_KEY` or a
//!   `--key-file`; never from argv (argv is observable) and never committed.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use colored::Colorize;
use phantom_core::connector::{self, Capability, ConnectorManifest, ImportFormat};

use super::export_cmd::require_attached_terminals;

/// `phantom connector add <dir>` — verify and install a pack.
pub fn run_add(dir: &Path) -> Result<()> {
    require_attached_terminals("Connector pack install")?;
    let snapshot = connector::verify_pack_snapshot(dir)?;
    let effect = serde_json::to_string(&serde_json::json!({
        "install_connector": snapshot.manifest(), "sha256": snapshot.sha256_pin(), "signer": snapshot.signer(),
    }))?;
    let challenge = format!(
        "INSTALL CONNECTOR {} SHA256 {} NONCE {:032x}",
        snapshot.manifest().name,
        snapshot.sha256_pin(),
        rand::random::<u128>()
    );
    super::export_cmd::require_trusted_terminal_effect(&effect, &challenge)?;
    let installed =
        connector::install_verified_pack(snapshot).map_err(|e| anyhow::anyhow!("{e}"))?;
    println!(
        "{} Installed connector pack {} v{}",
        "✓".green().bold(),
        installed.name.cyan().bold(),
        installed.version
    );
    println!(
        "  {} {}",
        "capabilities:".dimmed(),
        installed.capabilities.join(", ")
    );
    println!("  {} {}", "sha256 pin:".dimmed(), installed.sha256_pin);
    println!();
    println!(
        "{}",
        "Packs are declarative: no third-party code runs in the credential path.".dimmed()
    );
    Ok(())
}

/// `phantom connector list [--json]`.
pub fn run_list(json: bool) -> Result<()> {
    let packs = connector::list_packs().map_err(|e| anyhow::anyhow!("{e}"))?;
    if json {
        println!("{}", serde_json::to_string_pretty(&packs)?);
        return Ok(());
    }
    if packs.is_empty() {
        println!("No connector packs installed.");
        println!(
            "Run {} to install one, or {} to scaffold a new pack.",
            "phantom connector add <dir>".cyan(),
            "phantom connector pack init <dir> --name <name>".cyan()
        );
        return Ok(());
    }
    println!("{} installed connector pack(s):", packs.len());
    for p in &packs {
        println!(
            "  {} {} {}",
            "•".cyan(),
            p.name.bold(),
            format!("v{}", p.version).dimmed()
        );
        println!(
            "    {} {}",
            "capabilities:".dimmed(),
            p.capabilities.join(", ")
        );
        println!("    {} {}", "sha256:".dimmed(), &p.sha256_pin[..16]);
    }
    Ok(())
}

/// `phantom connector remove <name>`.
pub fn run_remove(name: &str) -> Result<()> {
    require_attached_terminals("Connector pack removal")?;
    super::export_cmd::require_trusted_terminal_effect(
        &serde_json::to_string(&serde_json::json!({"remove_connector": name}))?,
        &format!(
            "REMOVE CONNECTOR {name} NONCE {:032x}",
            rand::random::<u128>()
        ),
    )?;
    connector::remove_pack(name).map_err(|e| anyhow::anyhow!("{e}"))?;
    println!(
        "{} Removed connector pack {}",
        "✓".green().bold(),
        name.cyan()
    );
    Ok(())
}

/// `phantom connector inspect <name>` — value-free manifest details.
pub fn run_inspect(name: &str) -> Result<()> {
    let manifest = connector::load_pack_manifest(name).map_err(|e| anyhow::anyhow!("{e}"))?;
    println!("{} {}", "pack:".dimmed(), manifest.name.bold());
    println!("{} {}", "version:".dimmed(), manifest.version);
    println!("{} {}", "description:".dimmed(), manifest.description);
    for cap in &manifest.capabilities {
        match cap {
            Capability::Validate { validators } => {
                println!("{} validate:", "capability".cyan().bold());
                for v in validators {
                    println!(
                        "    {} {} (keys: {})",
                        "•".dimmed(),
                        v.name,
                        v.key_prefixes.join(", ")
                    );
                    println!(
                        "      {} {} {}",
                        format!("{:?}", v.method).dimmed(),
                        v.url.dimmed(),
                        format!("expect {:?}", v.expect_status).dimmed()
                    );
                }
            }
            Capability::SyncTarget { targets } => {
                println!("{} sync-target:", "capability".cyan().bold());
                for t in targets {
                    println!("    {} {}", "•".dimmed(), t.name);
                    println!(
                        "      {} {} {} (credential: {})",
                        format!("{:?}", t.method).dimmed(),
                        t.url.dimmed(),
                        format!("{}: <vault secret>", t.auth_header).dimmed(),
                        t.credential_name
                    );
                }
            }
            Capability::ImportSource { sources } => {
                println!("{} import-source:", "capability".cyan().bold());
                for s in sources {
                    let fmt = match s.format {
                        ImportFormat::Dotenv => "dotenv",
                        ImportFormat::JsonMap => "json-map",
                    };
                    println!(
                        "    {} {} (format: {}{})",
                        "•".dimmed(),
                        s.name,
                        fmt,
                        if s.pointer.is_empty() {
                            String::new()
                        } else {
                            format!(", pointer: {}", s.pointer)
                        }
                    );
                }
            }
        }
    }
    Ok(())
}

// ── Trust anchors ────────────────────────────────────────────────────────────

/// `phantom connector anchor add --key <hex>`.
pub fn run_anchor_add(key_hex: &str) -> Result<()> {
    require_attached_terminals("Trust anchor registration")?;
    super::export_cmd::require_trusted_terminal_effect(
        &serde_json::to_string(&serde_json::json!({"register_connector_anchor": key_hex}))?,
        &format!(
            "REGISTER CONNECTOR ANCHOR {key_hex} NONCE {:032x}",
            rand::random::<u128>()
        ),
    )?;
    let key_id = connector::add_anchor(key_hex).map_err(|e| anyhow::anyhow!("{e}"))?;
    println!(
        "{} Registered connector trust anchor {}",
        "✓".green().bold(),
        key_id.cyan().bold()
    );
    println!(
        "{}",
        "This anchor vouches for every pack signed with its key. Guard the signing key.".dimmed()
    );
    Ok(())
}

/// `phantom connector anchor list`.
pub fn run_anchor_list() -> Result<()> {
    let anchors = connector::list_anchors().map_err(|e| anyhow::anyhow!("{e}"))?;
    if anchors.is_empty() {
        println!("No connector trust anchors registered.");
        println!(
            "Run {} to register the first one (trust-on-first-use).",
            "phantom connector anchor add --key <hex-pubkey>".cyan()
        );
        return Ok(());
    }
    println!("{} registered trust anchor(s):", anchors.len());
    for id in &anchors {
        println!("  {} {}", "•".cyan(), id.bold());
    }
    Ok(())
}

/// `phantom connector anchor remove <key-id>`.
pub fn run_anchor_remove(key_id: &str) -> Result<()> {
    require_attached_terminals("Trust anchor removal")?;
    super::export_cmd::require_trusted_terminal_effect(
        &serde_json::to_string(&serde_json::json!({"remove_connector_anchor": key_id}))?,
        &format!(
            "REMOVE CONNECTOR ANCHOR {key_id} NONCE {:032x}",
            rand::random::<u128>()
        ),
    )?;
    connector::remove_anchor(key_id).map_err(|e| anyhow::anyhow!("{e}"))?;
    println!(
        "{} Removed trust anchor {}",
        "✓".green().bold(),
        key_id.cyan()
    );
    println!(
        "{}",
        "Installed packs remain, but re-verify against remaining anchors on next use.".dimmed()
    );
    Ok(())
}

// ── Pack authoring ────────────────────────────────────────────────────────────

/// `phantom connector pack init <dir> --name <name>` — scaffold a manifest.
pub fn run_pack_init(dir: &Path, name: &str) -> Result<()> {
    let path = connector::scaffold_pack(dir, name).map_err(|e| anyhow::anyhow!("{e}"))?;
    println!(
        "{} Scaffolded pack manifest at {}",
        "✓".green().bold(),
        path.display()
    );
    println!("Next:");
    println!("  1. Edit the manifest (validators, sync targets, import sources).");
    println!(
        "  2. Sign it: {}",
        "phantom connector pack sign <dir>".cyan()
    );
    println!("  3. Install it: {}", "phantom connector add <dir>".cyan());
    Ok(())
}

/// Resolve the pack signing key: `--key-file` wins, else
/// `PHANTOM_CONNECTOR_SIGNING_KEY` (hex, 32 bytes).
fn resolve_signing_key(key_file: Option<&Path>) -> Result<connector::ConnectorSigningKey> {
    if let Some(path) = key_file {
        let meta = std::fs::metadata(path)
            .with_context(|| format!("cannot read key file {}", path.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = meta.permissions().mode() & 0o777;
            if mode & 0o077 != 0 {
                anyhow::bail!(
                    "Refusing to read signing key from {}: permissions {:o} are too open (use 0600).",
                    path.display(),
                    mode
                );
            }
        }
        let _ = meta;
        let raw = phantom_core::fs::read_regular_file(path)?
            .ok_or_else(|| anyhow::anyhow!("key file disappeared"))?;
        if raw.len() > 128 {
            anyhow::bail!("key file exceeds its size bound");
        }
        let raw = zeroize::Zeroizing::new(raw);
        let hex_key = std::str::from_utf8(&raw).context("key file is not UTF-8")?;
        return connector::signing_key_from_hex(hex_key)
            .map_err(|e| anyhow::anyhow!("key file: {e}"));
    }
    let hex_key =
        zeroize::Zeroizing::new(std::env::var("PHANTOM_CONNECTOR_SIGNING_KEY").map_err(|_| {
            anyhow::anyhow!(
            "No signing key: set PHANTOM_CONNECTOR_SIGNING_KEY (hex) or pass --key-file <path>.\n\
             Generate one with: python3 -c \"import secrets; print(secrets.token_hex(32))\""
        )
        })?);
    connector::signing_key_from_hex(&hex_key)
        .map_err(|e| anyhow::anyhow!("PHANTOM_CONNECTOR_SIGNING_KEY: {e}"))
}

/// `phantom connector pack sign <dir> [--key-file <path>]`.
pub fn run_pack_sign(dir: &Path, key_file: Option<&Path>) -> Result<()> {
    let manifest_path = dir.join("connector.json");
    let raw = std::fs::read(&manifest_path).with_context(|| {
        format!(
            "cannot read {}; run `phantom connector pack init` first",
            manifest_path.display()
        )
    })?;
    let manifest: ConnectorManifest = serde_json::from_slice(&raw).with_context(|| {
        format!(
            "{} is not a valid connector manifest",
            manifest_path.display()
        )
    })?;
    let key = resolve_signing_key(key_file)?;
    let envelope = connector::sign_manifest(&manifest, &key).map_err(|e| anyhow::anyhow!("{e}"))?;
    let sig_path = dir.join("connector.sig");
    std::fs::write(&sig_path, format!("{envelope}\n"))
        .with_context(|| format!("cannot write {}", sig_path.display()))?;
    let (key_id, _) = envelope.split_once(':').unwrap_or(("?", ""));
    println!(
        "{} Signed pack {} (anchor id {})",
        "✓".green().bold(),
        manifest.name.cyan().bold(),
        key_id.yellow()
    );
    println!(
        "  Register the matching public key before installing: {}",
        "phantom connector anchor add --key <hex-pubkey>".cyan()
    );
    Ok(())
}

/// Canonicalize a user-supplied directory for pack commands.
pub fn resolve_pack_dir(dir: &Path) -> Result<PathBuf> {
    let abs = if dir.is_absolute() {
        dir.to_path_buf()
    } else {
        std::env::current_dir()?.join(dir)
    };
    if !abs.is_dir() {
        anyhow::bail!(
            "{} is not a directory. Pass the pack directory containing connector.json.",
            dir.display()
        );
    }
    Ok(abs)
}
