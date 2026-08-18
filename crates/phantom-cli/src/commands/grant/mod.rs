//! `phantom grant` — the one human consent that seeds a perpetual, agent-safe
//! renewal chain (see `docs/grants-spec.md`).
//!
//! Issuance is the *writer* of the `[phantom.secrets.<name>.rotation_provider]`
//! block that the shipped rotation machinery reads. Consent is a **human** act,
//! so issuance is never an agent-callable MCP tool; only read-only status is
//! exposed to agents. Every root credential a grant produces is vaulted through
//! the same encrypted-vault path as `phantom add` and is never printed, never
//! in `--json`, never in an MCP response.

pub mod add;
pub mod list;
pub mod revoke;
pub mod status;

use anyhow::Result;
use phantom_core::issuance::BrowserOpener;
use phantom_core::rotation_provider::RotationProviderConfig;
use std::path::Path;

/// Real browser opener backed by the `open` crate (already a CLI dependency).
/// Lives in the CLI, not core, so `phantom-core` stays free of `open` and
/// hermetically testable.
pub struct OpenCrateBrowser;

impl BrowserOpener for OpenCrateBrowser {
    fn open(&self, url: &str) -> bool {
        open::that(url).is_ok()
    }
}

/// Detect a headless session where launching a browser is pointless: an SSH
/// connection, or (on non-macOS unix) no `$DISPLAY`/`$WAYLAND_DISPLAY`.
pub fn is_headless() -> bool {
    if std::env::var_os("SSH_CONNECTION").is_some() || std::env::var_os("SSH_TTY").is_some() {
        return true;
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        if std::env::var_os("DISPLAY").is_none() && std::env::var_os("WAYLAND_DISPLAY").is_none() {
            return true;
        }
    }
    false
}

/// Write (or replace) the `[phantom.secrets.<secret_name>.rotation_provider]`
/// block from an issued [`RotationProviderConfig`]. Grants configure rotation;
/// they never store a secret value in `.phantom.toml` — only the `phm:` *names*
/// travel here (via `api_key_env`), exactly like a hand-written block.
pub fn write_rotation_provider_block(
    config_path: &Path,
    secret_name: &str,
    rotation_config: &RotationProviderConfig,
) -> Result<()> {
    use phantom_core::config::PhantomConfig;

    let mut config = PhantomConfig::load(config_path)?;
    let entry = config
        .phantom
        .secrets
        .entry(secret_name.to_string())
        .or_default();
    entry.rotation_provider = Some(rotation_config.clone());
    config.save(config_path)?;
    Ok(())
}
