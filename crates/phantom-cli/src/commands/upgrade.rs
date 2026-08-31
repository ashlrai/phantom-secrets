use colored::Colorize;

/// Where each install method roots its binaries. Used to give an actionable
/// hint when self-update isn't the right path (e.g. npm-installed phantom
/// gets reverted on the next `npm install` if we replace the cached binary).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum InstallSource {
    Npm,
    Homebrew,
    Cargo,
    Curl,
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

pub(crate) fn detect_install_source() -> InstallSource {
    let exe = match std::env::current_exe() {
        Ok(p) => p,
        Err(_) => return InstallSource::Unknown,
    };
    let path = exe.to_string_lossy();

    // npm wrapper caches the binary under ~/.phantom-secrets/bin/phantom
    if let Some(home) = dirs::home_dir() {
        let npm_root = home.join(".phantom-secrets").join("bin");
        if exe.starts_with(&npm_root) {
            return InstallSource::Npm;
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

pub fn run(force: bool, check_only: bool) -> anyhow::Result<()> {
    let current = env!("CARGO_PKG_VERSION");
    let source = detect_install_source();

    if matches!(source, InstallSource::Npm) {
        println!(
            "{} phantom was installed via the npm wrapper, which this command cannot replace safely.",
            "->".blue().bold(),
        );
        println!(
            "  {}",
            format!(
                "Install the reviewed release: https://github.com/ashlrai/phantom-secrets/releases/tag/v{current}"
            )
            .cyan()
            .bold()
        );
        return Ok(());
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
            let cmd = match source {
                InstallSource::Homebrew => "brew upgrade phantom",
                InstallSource::Cargo => "cargo install phantom-secrets --force",
                _ => "brew upgrade phantom",
            };
            println!(
                "{} Permission denied. Try the package-manager path instead: {}",
                "!".red().bold(),
                cmd.yellow(),
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
}
