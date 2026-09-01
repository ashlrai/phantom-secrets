use colored::Colorize;
use rand::RngCore;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::io::{BufRead, IsTerminal, Read, Write};
use std::path::{Path, PathBuf};

const INSTALL_SOURCE_RECEIPT: &str = ".phantom-install-source.json";
const NPM_SOURCE_MARKERS: [&str; 2] = [
    ".phantom-install-source.npm-cli",
    ".phantom-install-source.npm-mcp",
];
const MAX_INSTALL_BINARY_BYTES: u64 = 256 * 1024 * 1024;

/// Where each install method roots its binaries. Used to give an actionable
/// hint when self-update isn't the right path (e.g. npm-installed phantom
/// gets reverted on the next `npm install` if we replace the cached binary).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum InstallSource {
    Npm,
    Homebrew,
    Cargo,
    Direct,
    Curl,
    LegacySharedRoot,
    Unknown,
}

fn release_archive_name(target: &str) -> String {
    let extension = if target.contains("windows") {
        "zip"
    } else {
        "tar.gz"
    };
    format!("phantom-{target}.{extension}")
}

fn select_release_asset(
    assets: &[self_update::ReleaseAsset],
    expected_name: &str,
) -> Option<self_update::ReleaseAsset> {
    assets
        .iter()
        .find(|asset| asset.name() == expected_name)
        .cloned()
}

fn reviewed_release_url(version: &str) -> String {
    format!("https://github.com/ashlrai/phantom-secrets/releases/tag/v{version}")
}

fn permission_denied_guidance(source: InstallSource, version: &str) -> String {
    match source {
        InstallSource::Homebrew => "Use the reviewed tap and fully qualified formula:\n\
             brew upgrade ashlrai/tap/phantom-secrets"
            .to_string(),
        _ => format!(
            "Use the checksum-verifiable assets from the reviewed release: {}",
            reviewed_release_url(version)
        ),
    }
}

fn regular_small_file(path: &Path) -> Option<String> {
    let bytes = phantom_core::fs::read_regular_file(path).ok()??;
    if bytes.len() > 4096 {
        return None;
    }
    String::from_utf8(bytes).ok()
}

fn shared_root_source(exe: &Path) -> InstallSource {
    let Some(root) = exe.parent() else {
        return InstallSource::LegacySharedRoot;
    };
    for marker_name in NPM_SOURCE_MARKERS {
        let marker = root.join(marker_name);
        match std::fs::symlink_metadata(&marker) {
            Ok(_) => {
                return if regular_small_file(&marker).as_deref() == Some("npm\n") {
                    InstallSource::Npm
                } else {
                    InstallSource::LegacySharedRoot
                };
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return InstallSource::LegacySharedRoot,
        }
    }
    if let Some(contents) = regular_small_file(&root.join(INSTALL_SOURCE_RECEIPT)) {
        let receipt = serde_json::from_str::<serde_json::Value>(&contents).ok();
        let schema = receipt
            .as_ref()
            .and_then(|value| value.get("schema_version"))
            .and_then(serde_json::Value::as_u64);
        let source = receipt
            .as_ref()
            .and_then(|value| value.get("source"))
            .and_then(serde_json::Value::as_str);
        return match (schema, source) {
            (Some(1), Some("direct")) => InstallSource::Direct,
            (Some(1), Some("npm")) => InstallSource::Npm,
            _ => InstallSource::LegacySharedRoot,
        };
    }

    // npm wrappers published before the source receipt maintain a bounded
    // per-binary manifest. Treat only a structurally valid legacy manifest as
    // npm; a bare shared-root binary is ambiguous and therefore fails closed.
    let manifest_path = exe.with_file_name(format!(
        "{}.manifest.json",
        exe.file_name().unwrap_or_default().to_string_lossy()
    ));
    if let Some(contents) = regular_small_file(&manifest_path) {
        if let Ok(manifest) = serde_json::from_str::<serde_json::Value>(&contents) {
            let version_ok = manifest
                .get("version")
                .and_then(serde_json::Value::as_str)
                .is_some_and(|version| !version.is_empty() && version.len() <= 128);
            let digest_ok = manifest
                .get("sha256")
                .and_then(serde_json::Value::as_str)
                .is_some_and(|digest| {
                    digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit())
                });
            if manifest.as_object().is_some_and(|object| object.len() == 2)
                && version_ok
                && digest_ok
            {
                return InstallSource::Npm;
            }
        }
    }
    InstallSource::LegacySharedRoot
}

fn verified_standalone_source(exe: &Path) -> bool {
    let Some(root) = exe.parent() else {
        return false;
    };
    let Some(contents) = regular_small_file(&root.join(INSTALL_SOURCE_RECEIPT)) else {
        return false;
    };
    let Ok(receipt) = serde_json::from_str::<serde_json::Value>(&contents) else {
        return false;
    };
    receipt.as_object().is_some_and(|object| object.len() == 4)
        && receipt
            .get("schema_version")
            .and_then(|value| value.as_u64())
            == Some(1)
        && receipt.get("source").and_then(|value| value.as_str()) == Some("curl")
        && receipt
            .get("version")
            .and_then(|value| value.as_str())
            .is_some_and(|value| !value.is_empty() && value.len() <= 128)
        && receipt
            .get("target")
            .and_then(|value| value.as_str())
            .is_some_and(|value| !value.is_empty() && value.len() <= 128)
}

pub(crate) fn detect_install_source_from(exe: &Path, home: Option<&Path>) -> InstallSource {
    let path = exe.to_string_lossy();

    // Direct installers and npm wrappers intentionally share this private
    // root. A source receipt (or a legacy npm manifest) disambiguates them.
    if let Some(home) = home {
        let shared_root = home.join(".phantom-secrets").join("bin");
        if exe.parent() == Some(shared_root.as_path()) {
            return shared_root_source(exe);
        }
    }
    if path.contains("/Cellar/") || path.contains("/homebrew/") || path.contains("/linuxbrew/") {
        return InstallSource::Homebrew;
    }
    if path.contains("/.cargo/bin/") {
        return InstallSource::Cargo;
    }
    if path.contains("/.local/bin/") {
        return if verified_standalone_source(exe) {
            InstallSource::Curl
        } else {
            InstallSource::Unknown
        };
    }
    InstallSource::Unknown
}

pub(crate) fn detect_install_source() -> InstallSource {
    let exe = match std::env::current_exe() {
        Ok(path) => path,
        Err(_) => return InstallSource::Unknown,
    };
    let home = dirs::home_dir();
    detect_install_source_from(&exe, home.as_deref())
}

pub fn run(force: bool, check_only: bool) -> anyhow::Result<()> {
    if force {
        anyhow::bail!(
            "`phantom upgrade --force` is disabled because it bypassed human authorization. Run `phantom upgrade` from a trusted attached terminal and complete both fresh exact challenges."
        );
    }
    let current = env!("CARGO_PKG_VERSION");
    let source = detect_install_source();

    match source {
        InstallSource::Npm => {
            println!(
                "{} phantom is managed by the npm wrapper; a direct binary replacement would be reverted.",
                "->".blue().bold(),
            );
            println!(
                "  {}",
                format!(
                    "Use a reviewed npm package when one is published, or switch both binaries with the checksum-verifiable release installer: {}",
                    reviewed_release_url(current)
                )
                .cyan()
                .bold()
            );
            return Ok(());
        }
        InstallSource::Direct => {
            println!(
                "{} phantom is managed by the direct installer as a phantom + phantom-mcp pair.",
                "->".blue().bold(),
            );
            println!(
                "  {}",
                format!(
                    "Download, checksum, inspect, and run the installer from the reviewed release to upgrade both binaries together: {}",
                    reviewed_release_url(current)
                )
                .cyan()
                .bold()
            );
            return Ok(());
        }
        InstallSource::LegacySharedRoot => {
            println!(
                "{} phantom is in the shared installer root, but its install source receipt is missing or invalid.",
                "->".blue().bold(),
            );
            println!(
                "  {}",
                format!(
                    "Refusing an ambiguous in-place update. Re-run a checksum-verified reviewed installer to restore a source receipt: {}",
                    reviewed_release_url(current)
                )
                .cyan()
                .bold()
            );
            return Ok(());
        }
        InstallSource::Homebrew => {
            println!(
                "{} phantom is managed by Homebrew; refusing single-binary self-replacement{}.",
                "->".blue().bold(),
                if check_only {
                    " or a GitHub metadata check"
                } else {
                    ""
                }
            );
            println!(
                "  {}",
                "Use the reviewed owner command: brew upgrade ashlrai/tap/phantom-secrets"
                    .cyan()
                    .bold()
            );
            return Ok(());
        }
        InstallSource::Cargo => {
            println!(
                "{} phantom is Cargo-managed; refusing single-binary self-replacement{} because the registry version and source revision must be reviewed together.",
                "->".blue().bold(),
                if check_only { " or a GitHub metadata check" } else { "" }
            );
            println!(
                "  {}",
                format!(
                    "Use a checksum-verifiable reviewed release or a commit-pinned `cargo install --git ... --rev <reviewed-sha>` from {}",
                    reviewed_release_url(current)
                )
                .cyan()
                .bold()
            );
            return Ok(());
        }
        InstallSource::Unknown => {
            anyhow::bail!(
                "Phantom install ownership is unknown; refusing {}. Reinstall from a checksum-verified reviewed release to establish an ownership receipt: {}",
                if check_only {
                    "an ownership-ambiguous update check"
                } else {
                    "ambiguous self-replacement"
                },
                reviewed_release_url(current)
            );
        }
        // Only the legacy standalone location with an exact local `curl`
        // ownership receipt can enter the self-replacement flow.
        InstallSource::Curl => {}
    }

    let target = self_update::get_target();
    let expected_archive = release_archive_name(target);

    if check_only {
        let matcher_archive = expected_archive.clone();
        let update = self_update::backends::github::Update::configure()
            .repo_owner("ashlrai")
            .repo_name("phantom-secrets")
            .bin_name("phantom")
            .current_version(current)
            .target(target)
            .asset_matcher(move |assets| select_release_asset(assets, &matcher_archive))
            .checksum_from_asset("SHA256SUMS")
            .no_confirm(true)
            .build()?;
        let releases = update.get_latest_release()?;
        let latest = releases
            .latest()
            .ok_or_else(|| anyhow::anyhow!("GitHub returned no Phantom releases"))?;
        let latest_ver = latest.version().trim_start_matches('v');
        if releases.is_update_available()? {
            println!(
                "{} phantom {} is available (you have {}). Run `phantom upgrade` to install.",
                "->".blue().bold(),
                latest_ver.green().bold(),
                current,
            );
        } else {
            println!(
                "{} phantom {} is already at the latest version.",
                "ok".green().bold(),
                current,
            );
        }
        return Ok(());
    }

    require_upgrade_terminals()?;
    let install_path = current_install_path()?;
    let initial_plan =
        build_upgrade_plan(&install_path, current, "latest-unresolved", target, source)?;
    require_trusted_terminal_upgrade(&initial_plan, "release-metadata")?;

    // This is the first network operation in the mutating flow. It occurs
    // only after the user has authorized exact current install identity and a
    // metadata-only lookup for the unresolved latest release.
    let matcher_archive = expected_archive.clone();
    let update = self_update::backends::github::Update::configure()
        .repo_owner("ashlrai")
        .repo_name("phantom-secrets")
        .bin_name("phantom")
        .current_version(current)
        .target(target)
        .asset_matcher(move |assets| select_release_asset(assets, &matcher_archive))
        .checksum_from_asset("SHA256SUMS")
        .no_confirm(true)
        .build()?;
    let releases = update.get_latest_release()?;
    let latest = releases
        .latest()
        .ok_or_else(|| anyhow::anyhow!("GitHub returned no Phantom releases"))?;
    if !releases.is_update_available()? {
        println!(
            "{} phantom {} is already at the latest version.",
            "ok".green().bold(),
            current,
        );
        return Ok(());
    }
    let latest_version = latest.version().to_string();
    if select_release_asset(latest.assets(), &expected_archive).is_none()
        || !latest
            .assets()
            .iter()
            .any(|asset| asset.name() == "SHA256SUMS")
    {
        anyhow::bail!(
            "Release v{} is missing the exact {} archive or SHA256SUMS; no download or replacement was attempted",
            latest_version,
            expected_archive
        );
    }

    let reviewed_plan =
        build_upgrade_plan(&install_path, current, &latest_version, target, source)?;
    if reviewed_plan.install != initial_plan.install {
        anyhow::bail!(
            "The installed Phantom binary changed during release lookup; refusing to authorize or download an update"
        );
    }
    require_trusted_terminal_upgrade(&reviewed_plan, "verified-replacement")?;
    let final_plan = build_upgrade_plan(&install_path, current, &latest_version, target, source)?;
    if final_plan != reviewed_plan {
        anyhow::bail!(
            "The reviewed upgrade plan changed after confirmation; no download or replacement was attempted"
        );
    }

    let matcher_archive = expected_archive.clone();
    let pinned_tag = format!("v{latest_version}");
    let pinned_update = self_update::backends::github::Update::configure()
        .repo_owner("ashlrai")
        .repo_name("phantom-secrets")
        .bin_name("phantom")
        .bin_install_path(&install_path)
        .check_install_path_writable(true)
        .current_version(current)
        .release_tag(pinned_tag)
        .target(target)
        .asset_matcher(move |assets| select_release_asset(assets, &matcher_archive))
        .checksum_from_asset("SHA256SUMS")
        .show_download_progress(true)
        .no_confirm(true)
        .build()?;

    match pinned_update.update() {
        Ok(status) => match status {
            self_update::VersionStatus::UpToDate(v) => {
                println!(
                    "{} phantom {} is already at the latest version.",
                    "ok".green().bold(),
                    v
                );
            }
            self_update::VersionStatus::Updated(v) => {
                let installed = inspect_install_identity(&install_path).map_err(|error| {
                    anyhow::anyhow!(
                        "Updater reported v{v} installed, but the replacement target could not be verified: {error}"
                    )
                })?;
                println!(
                    "{} phantom updated to {} (sha256={}, bytes={}).",
                    "ok".green().bold(),
                    v.green().bold(),
                    installed.sha256,
                    installed.bytes
                );
            }
            _ => anyhow::bail!("self-update returned an unsupported status"),
        },
        Err(self_update::errors::Error::Io(e))
            if e.kind() == std::io::ErrorKind::PermissionDenied =>
        {
            let guidance = permission_denied_guidance(source, &latest_version);
            println!(
                "{} Permission denied. {}",
                "!".red().bold(),
                guidance.yellow(),
            );
            report_failed_upgrade_state(&reviewed_plan);
            anyhow::bail!("Upgrade was not completed because the install target was not writable");
        }
        Err(self_update::errors::Error::InstallPathNotWritable { .. }) => {
            let guidance = permission_denied_guidance(source, &latest_version);
            println!(
                "{} Install target is not writable. {}",
                "!".red().bold(),
                guidance.yellow(),
            );
            report_failed_upgrade_state(&reviewed_plan);
            anyhow::bail!("Upgrade was not completed because the install target was not writable");
        }
        Err(error) => {
            let state = failed_upgrade_state(&reviewed_plan);
            return Err(anyhow::anyhow!(
                "Upgrade failed: {error}. Replacement state: {state}"
            ));
        }
    }

    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct InstallIdentity {
    canonical_path: String,
    sha256: String,
    bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct UpgradePlan {
    operation: &'static str,
    phase_target_version: String,
    current_version: String,
    target_triple: String,
    install_source: &'static str,
    install_source_receipt_sha256: Option<String>,
    expected_archive: String,
    install: InstallIdentity,
}

fn install_source_label(source: InstallSource) -> &'static str {
    match source {
        InstallSource::Npm => "npm",
        InstallSource::Homebrew => "homebrew",
        InstallSource::Cargo => "cargo",
        InstallSource::Direct => "direct",
        InstallSource::Curl => "curl",
        InstallSource::LegacySharedRoot => "legacy-shared-root",
        InstallSource::Unknown => "unknown",
    }
}

fn current_install_path() -> anyhow::Result<PathBuf> {
    let path = std::env::current_exe()?;
    validate_install_target(&path)
}

fn validate_install_target(path: &Path) -> anyhow::Result<PathBuf> {
    let metadata = std::fs::symlink_metadata(path).map_err(|error| {
        anyhow::anyhow!(
            "Could not inspect installed Phantom binary {}: {error}",
            path.display()
        )
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        anyhow::bail!(
            "Refusing to self-replace symlink or non-regular install target {}",
            path.display()
        );
    }
    let canonical = path.canonicalize()?;
    let canonical_metadata = std::fs::symlink_metadata(&canonical)?;
    if canonical_metadata.file_type().is_symlink() || !canonical_metadata.is_file() {
        anyhow::bail!(
            "Refusing unsafe canonical install target {}",
            canonical.display()
        );
    }
    Ok(canonical)
}

fn inspect_install_identity(path: &Path) -> anyhow::Result<InstallIdentity> {
    let canonical = validate_install_target(path)?;
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.custom_flags(windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let mut file = options.open(&canonical)?;
    let metadata = file.metadata()?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        anyhow::bail!(
            "Refusing non-regular installed Phantom binary {}",
            canonical.display()
        );
    }
    if metadata.len() > MAX_INSTALL_BINARY_BYTES {
        anyhow::bail!(
            "Installed Phantom binary is {} bytes; refusing to hash more than {} bytes",
            metadata.len(),
            MAX_INSTALL_BINARY_BYTES
        );
    }
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    let mut bytes = 0_u64;
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        bytes = bytes.saturating_add(read as u64);
        if bytes > MAX_INSTALL_BINARY_BYTES {
            anyhow::bail!("Installed Phantom binary grew beyond the hashing limit");
        }
        hasher.update(&buffer[..read]);
    }
    if bytes != metadata.len() {
        anyhow::bail!("Installed Phantom binary changed while its identity was inspected");
    }
    Ok(InstallIdentity {
        canonical_path: canonical.display().to_string(),
        sha256: hex::encode(hasher.finalize()),
        bytes,
    })
}

fn build_upgrade_plan(
    install_path: &Path,
    current_version: &str,
    target_version: &str,
    target_triple: &str,
    source: InstallSource,
) -> anyhow::Result<UpgradePlan> {
    let source_receipt = match source {
        InstallSource::Curl => {
            let root = install_path.parent().ok_or_else(|| {
                anyhow::anyhow!("Standalone install target has no ownership receipt directory")
            })?;
            let receipt_path = root.join(INSTALL_SOURCE_RECEIPT);
            let receipt = phantom_core::fs::read_regular_file(&receipt_path)?
                .ok_or_else(|| anyhow::anyhow!("Standalone ownership receipt disappeared"))?;
            if receipt.len() > 4096 || !verified_standalone_source(install_path) {
                anyhow::bail!("Standalone ownership receipt is invalid or changed");
            }
            Some(hex::encode(Sha256::digest(&receipt)))
        }
        _ => None,
    };
    Ok(UpgradePlan {
        operation: "replace-local-phantom-binary",
        phase_target_version: target_version.to_string(),
        current_version: current_version.to_string(),
        target_triple: target_triple.to_string(),
        install_source: install_source_label(source),
        install_source_receipt_sha256: source_receipt,
        expected_archive: release_archive_name(target_triple),
        install: inspect_install_identity(install_path)?,
    })
}

fn require_upgrade_terminals() -> anyhow::Result<()> {
    validate_upgrade_terminals(
        std::io::stdin().is_terminal(),
        std::io::stdout().is_terminal(),
        std::io::stderr().is_terminal(),
    )
}

fn validate_upgrade_terminals(stdin: bool, stdout: bool, stderr: bool) -> anyhow::Result<()> {
    if !stdin || !stdout || !stderr {
        anyhow::bail!(
            "Live `phantom upgrade` requires attached stdin, stdout, and stderr terminals and cannot run headlessly. No release metadata was requested, no artifact was downloaded, and no install target was read or replaced. `phantom upgrade --check-only` remains read-only."
        );
    }
    Ok(())
}

fn require_trusted_terminal_upgrade(plan: &UpgradePlan, phase: &str) -> anyhow::Result<()> {
    let mut nonce_bytes = [0_u8; 8];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = hex::encode(nonce_bytes);
    let stdin = std::io::stdin();
    let mut reader = stdin.lock();
    let mut stdout = std::io::stdout();
    let mut stderr = std::io::stderr();
    prompt_upgrade(plan, phase, &nonce, &mut reader, &mut stdout, &mut stderr)
}

fn prompt_upgrade(
    plan: &UpgradePlan,
    phase: &str,
    nonce: &str,
    reader: &mut dyn BufRead,
    prompt: &mut dyn Write,
    diagnostic: &mut dyn Write,
) -> anyhow::Result<()> {
    let plan_json = serde_json::to_string_pretty(plan)?;
    let expected = upgrade_challenge(&plan_json, phase, nonce);
    writeln!(
        diagnostic,
        "Phantom self-upgrade can replace persistent executable code. Terminal attachment does not prove that an AI agent is absent; continue only from a terminal you exclusively control.\nExact upgrade plan:\n{plan_json}\nType this exact challenge to continue:\n{expected}"
    )?;
    write!(prompt, "> ")?;
    prompt.flush()?;
    let mut response = String::new();
    reader.read_line(&mut response)?;
    if response.trim_end_matches(['\r', '\n']) != expected {
        anyhow::bail!("Upgrade cancelled: the fresh exact challenge did not match");
    }
    Ok(())
}

fn upgrade_challenge(plan_json: &str, phase: &str, nonce: &str) -> String {
    let digest = hex::encode(Sha256::digest(plan_json.as_bytes()));
    format!("upgrade {phase} {nonce} {digest}")
}

fn failed_upgrade_state(plan: &UpgradePlan) -> String {
    match inspect_install_identity(Path::new(&plan.install.canonical_path)) {
        Ok(identity) if identity == plan.install => {
            "the reviewed original binary remains byte-identical".to_string()
        }
        Ok(identity) => format!(
            "install target is regular but changed (sha256={}, bytes={}); reinstall a reviewed release before retrying",
            identity.sha256, identity.bytes
        ),
        Err(error) => format!(
            "install target is missing or unsafe ({error}); reinstall a reviewed release before retrying"
        ),
    }
}

fn report_failed_upgrade_state(plan: &UpgradePlan) {
    eprintln!("Replacement state: {}", failed_upgrade_state(plan));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_install_source_returns_a_value() {
        // Smoke test — the function must return without panicking. Exact
        // value depends on where the test binary lives, so we just ensure
        // it's stable across two calls.
        let a = detect_install_source();
        let b = detect_install_source();
        assert_eq!(a, b);
    }

    #[test]
    fn release_asset_selection_is_exact_and_order_independent() {
        let target = "x86_64-unknown-linux-gnu";
        let expected = release_archive_name(target);
        let assets = vec![
            self_update::ReleaseAsset::new(format!("{expected}.spdx.json"), "https://example/sbom"),
            self_update::ReleaseAsset::new(format!("{expected}.sha256"), "https://example/sum"),
            self_update::ReleaseAsset::new(&expected, "https://example/archive"),
        ];
        let selected = select_release_asset(&assets, &expected).unwrap();
        assert_eq!(selected.name(), expected);
        assert_eq!(selected.download_url(), "https://example/archive");
    }

    #[test]
    fn force_is_hard_denied_before_release_access() {
        let error = run(true, false).unwrap_err();
        assert!(error.to_string().contains("--force` is disabled"));
    }

    #[test]
    fn headless_upgrade_is_rejected_before_install_or_network_access() {
        for attached in [
            (false, true, true),
            (true, false, true),
            (true, true, false),
        ] {
            let error = validate_upgrade_terminals(attached.0, attached.1, attached.2).unwrap_err();
            assert!(error
                .to_string()
                .contains("No release metadata was requested"));
            assert!(error.to_string().contains("no install target was read"));
        }

        let source = include_str!("upgrade.rs");
        assert!(
            source.find("require_upgrade_terminals()?").unwrap()
                < source
                    .find("let install_path = current_install_path()?")
                    .unwrap()
        );
        let live_gate = source
            .find("require_trusted_terminal_upgrade(&initial_plan")
            .unwrap();
        assert!(
            live_gate
                < live_gate
                    + source[live_gate..]
                        .find("update.get_latest_release()?")
                        .unwrap()
        );
    }

    #[test]
    fn upgrade_challenge_binds_install_identity_and_target_version() {
        let directory = tempfile::tempdir().unwrap();
        let binary = directory.path().join("phantom");
        std::fs::write(&binary, b"reviewed binary").unwrap();
        let reviewed = build_upgrade_plan(
            &binary,
            "0.7.4",
            "0.7.5",
            "x86_64-unknown-linux-gnu",
            InstallSource::Unknown,
        )
        .unwrap();
        let nonce = "0011223344556677";
        let reviewed_json = serde_json::to_string_pretty(&reviewed).unwrap();
        let input = format!(
            "{}\n",
            upgrade_challenge(&reviewed_json, "verified-replacement", nonce)
        );
        let mut reader = std::io::Cursor::new(input);
        let mut prompt = Vec::new();
        let mut diagnostic = Vec::new();

        prompt_upgrade(
            &reviewed,
            "verified-replacement",
            nonce,
            &mut reader,
            &mut prompt,
            &mut diagnostic,
        )
        .unwrap();

        let changed = build_upgrade_plan(
            &binary,
            "0.7.4",
            "0.7.6",
            "x86_64-unknown-linux-gnu",
            InstallSource::Unknown,
        )
        .unwrap();
        let replay = format!(
            "{}\n",
            upgrade_challenge(&reviewed_json, "verified-replacement", nonce)
        );
        assert!(prompt_upgrade(
            &changed,
            "verified-replacement",
            nonce,
            &mut std::io::Cursor::new(replay),
            &mut Vec::new(),
            &mut Vec::new()
        )
        .is_err());
    }

    #[test]
    fn install_identity_detects_change_after_review() {
        let directory = tempfile::tempdir().unwrap();
        let binary = directory.path().join("phantom");
        std::fs::write(&binary, b"reviewed binary").unwrap();
        let before = inspect_install_identity(&binary).unwrap();
        std::fs::write(&binary, b"concurrent owner").unwrap();
        let after = inspect_install_identity(&binary).unwrap();
        assert_ne!(before, after);
    }

    #[test]
    fn standalone_receipt_change_invalidates_upgrade_plan() {
        let directory = tempfile::tempdir().unwrap();
        let local_bin = directory.path().join(".local/bin");
        std::fs::create_dir_all(&local_bin).unwrap();
        let binary = local_bin.join("phantom");
        let receipt = local_bin.join(INSTALL_SOURCE_RECEIPT);
        std::fs::write(&binary, b"reviewed binary").unwrap();
        std::fs::write(
            &receipt,
            br#"{"schema_version":1,"source":"curl","version":"0.7.4","target":"test"}"#,
        )
        .unwrap();
        let before =
            build_upgrade_plan(&binary, "0.7.4", "0.7.5", "test", InstallSource::Curl).unwrap();
        std::fs::write(
            &receipt,
            br#"{"schema_version":1,"source":"curl","version":"0.7.4-rewritten","target":"test"}"#,
        )
        .unwrap();
        let after =
            build_upgrade_plan(&binary, "0.7.4", "0.7.5", "test", InstallSource::Curl).unwrap();

        assert_ne!(
            before.install_source_receipt_sha256,
            after.install_source_receipt_sha256
        );
        assert_ne!(before, after);
    }

    #[cfg(unix)]
    #[test]
    fn symlink_install_target_is_rejected() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().unwrap();
        let owner = directory.path().join("owner");
        let binary = directory.path().join("phantom");
        std::fs::write(&owner, b"owner").unwrap();
        symlink(&owner, &binary).unwrap();

        assert!(inspect_install_identity(&binary).is_err());
        assert_eq!(std::fs::read(owner).unwrap(), b"owner");
    }

    #[test]
    fn release_archive_name_uses_platform_format() {
        assert_eq!(
            release_archive_name("aarch64-pc-windows-msvc"),
            "phantom-aarch64-pc-windows-msvc.zip"
        );
        assert_eq!(
            release_archive_name("aarch64-apple-darwin"),
            "phantom-aarch64-apple-darwin.tar.gz"
        );
    }

    #[test]
    fn permission_recovery_never_recommends_unreviewed_distribution() {
        for source in [
            InstallSource::Npm,
            InstallSource::Cargo,
            InstallSource::Direct,
            InstallSource::Curl,
            InstallSource::LegacySharedRoot,
            InstallSource::Unknown,
        ] {
            let guide = permission_denied_guidance(source, "0.7.3");
            assert!(guide.contains("releases/tag/v0.7.3"));
            assert!(!guide.contains("cargo install"));
            assert!(!guide.contains("npm install"));
            assert!(!guide.contains("npx "));
            assert!(!guide.contains("brew upgrade phantom"));
        }

        let brew = permission_denied_guidance(InstallSource::Homebrew, "0.7.3");
        assert!(brew.contains("brew upgrade ashlrai/tap/phantom-secrets"));
        assert!(!brew.contains("brew upgrade phantom\n"));
    }

    #[test]
    fn source_routing_only_accepts_receipted_standalone_binary() {
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path();
        let local_bin = home.join(".local/bin");
        std::fs::create_dir_all(&local_bin).unwrap();
        let exe = local_bin.join(if cfg!(windows) {
            "phantom.exe"
        } else {
            "phantom"
        });
        std::fs::write(&exe, b"binary").unwrap();

        assert_eq!(
            detect_install_source_from(&exe, Some(home)),
            InstallSource::Unknown,
            "a path heuristic is not an ownership receipt"
        );

        let receipt = local_bin.join(INSTALL_SOURCE_RECEIPT);
        std::fs::write(
            &receipt,
            br#"{"schema_version":1,"source":"curl","version":"0.7.4","target":"x86_64-unknown-linux-gnu"}"#,
        )
        .unwrap();
        assert_eq!(
            detect_install_source_from(&exe, Some(home)),
            InstallSource::Curl
        );

        std::fs::write(
            &receipt,
            br#"{"schema_version":1,"source":"curl","version":"0.7.4","target":"x86_64-unknown-linux-gnu","extra":true}"#,
        )
        .unwrap();
        assert_eq!(
            detect_install_source_from(&exe, Some(home)),
            InstallSource::Unknown,
            "unknown receipt fields fail closed"
        );

        assert_eq!(
            detect_install_source_from(&home.join(".cargo/bin/phantom"), Some(home)),
            InstallSource::Cargo
        );
        assert_eq!(
            detect_install_source_from(
                Path::new("/opt/homebrew/Cellar/phantom/0.7.4/bin/phantom"),
                Some(home)
            ),
            InstallSource::Homebrew
        );
    }

    #[test]
    fn direct_installer_receipt_disambiguates_the_shared_root() {
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path();
        let root = home.join(".phantom-secrets").join("bin");
        std::fs::create_dir_all(&root).unwrap();
        let exe = root.join(if cfg!(windows) {
            "phantom.exe"
        } else {
            "phantom"
        });
        std::fs::write(&exe, b"binary").unwrap();
        std::fs::write(
            root.join(INSTALL_SOURCE_RECEIPT),
            br#"{"schema_version":1,"source":"direct","version":"0.7.4","target":"test"}"#,
        )
        .unwrap();

        assert_eq!(
            detect_install_source_from(&exe, Some(home)),
            InstallSource::Direct
        );

        std::fs::write(root.join(NPM_SOURCE_MARKERS[0]), b"npm\n").unwrap();
        assert_eq!(
            detect_install_source_from(&exe, Some(home)),
            InstallSource::Npm
        );
    }

    #[test]
    fn shared_root_detection_is_backward_safe_and_fail_closed() {
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path();
        let root = home.join(".phantom-secrets").join("bin");
        std::fs::create_dir_all(&root).unwrap();
        let exe = root.join(if cfg!(windows) {
            "phantom.exe"
        } else {
            "phantom"
        });
        std::fs::write(&exe, b"binary").unwrap();

        assert_eq!(
            detect_install_source_from(&exe, Some(home)),
            InstallSource::LegacySharedRoot
        );

        std::fs::write(
            exe.with_file_name(format!(
                "{}.manifest.json",
                exe.file_name().unwrap().to_string_lossy()
            )),
            format!(
                "{{\"version\":\"0.7.3\",\"sha256\":\"{}\"}}",
                "a".repeat(64)
            ),
        )
        .unwrap();
        assert_eq!(
            detect_install_source_from(&exe, Some(home)),
            InstallSource::Npm
        );

        std::fs::write(root.join(INSTALL_SOURCE_RECEIPT), b"not-json").unwrap();
        assert_eq!(
            detect_install_source_from(&exe, Some(home)),
            InstallSource::LegacySharedRoot
        );
    }
}
