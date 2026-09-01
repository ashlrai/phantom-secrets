use colored::Colorize;
use std::path::Path;

const INSTALL_SOURCE_RECEIPT: &str = ".phantom-install-source.json";
const NPM_SOURCE_MARKERS: [&str; 2] = [
    ".phantom-install-source.npm-cli",
    ".phantom-install-source.npm-mcp",
];

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
             brew tap ashlrai/phantom\n\
             brew trust --formula ashlrai/phantom/phantom\n\
             brew upgrade ashlrai/phantom/phantom"
            .to_string(),
        _ => format!(
            "Use the checksum-verifiable assets from the reviewed release: {}",
            reviewed_release_url(version)
        ),
    }
}

fn regular_small_file(path: &Path) -> Option<String> {
    let metadata = std::fs::symlink_metadata(path).ok()?;
    if !metadata.file_type().is_file() || metadata.len() > 4096 {
        return None;
    }
    std::fs::read_to_string(path).ok()
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
        return InstallSource::Curl;
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
        _ => {}
    }

    let target = self_update::get_target();
    let expected_archive = release_archive_name(target);
    let matcher_archive = expected_archive.clone();
    let update = self_update::backends::github::Update::configure()
        .repo_owner("ashlrai")
        .repo_name("phantom-secrets")
        .bin_name("phantom")
        .current_version(current)
        .target(target)
        .asset_matcher(move |assets| select_release_asset(assets, &matcher_archive))
        // Refuse to install unless the exact selected archive is listed in the
        // release's aggregate digest file. The checksums feature also verifies
        // a provider-supplied release digest when GitHub exposes one.
        .checksum_from_asset("SHA256SUMS")
        .show_download_progress(true)
        .no_confirm(force)
        .build()?;

    if check_only {
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

    match update.update() {
        Ok(status) => match status {
            self_update::VersionStatus::UpToDate(v) => {
                println!(
                    "{} phantom {} is already at the latest version.",
                    "ok".green().bold(),
                    v
                );
            }
            self_update::VersionStatus::Updated(v) => {
                println!(
                    "{} phantom updated to {}.",
                    "ok".green().bold(),
                    v.green().bold()
                );
            }
            _ => anyhow::bail!("self-update returned an unsupported status"),
        },
        Err(self_update::errors::Error::Io(e))
            if e.kind() == std::io::ErrorKind::PermissionDenied =>
        {
            let guidance = permission_denied_guidance(source, current);
            println!(
                "{} Permission denied. {}",
                "!".red().bold(),
                guidance.yellow(),
            );
            std::process::exit(1);
        }
        Err(e) => return Err(e.into()),
    }

    Ok(())
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
        assert!(brew.contains("brew tap ashlrai/phantom"));
        assert!(brew.contains("brew trust --formula ashlrai/phantom/phantom"));
        assert!(brew.contains("brew upgrade ashlrai/phantom/phantom"));
        assert!(!brew.contains("brew upgrade phantom\n"));
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
