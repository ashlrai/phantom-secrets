use colored::Colorize;

/// Where each install method roots its binaries. Used to give an actionable
/// hint when self-update isn't the right path (e.g. npm-installed phantom
/// gets reverted on the next `npm install` if we replace the cached binary).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InstallSource {
    Npm,
    Homebrew,
    Cargo,
    Curl,
    Unknown,
}

fn detect_install_source() -> InstallSource {
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
            "{} phantom was installed via npm. Use the npm package manager to upgrade:",
            "->".blue().bold(),
        );
        println!("    {}", "npm i -g phantom-secrets@latest".cyan().bold());
        println!(
            "  {} (`phantom upgrade` would be reverted on the next `npm install`).",
            "note".dimmed()
        );
        return Ok(());
    }

    let update = self_update::backends::github::Update::configure()
        .repo_owner("ashlrai")
        .repo_name("phantom-secrets")
        .bin_name("phantom")
        .current_version(current)
        .target(self_update::get_target())
        .show_download_progress(true)
        .no_confirm(force)
        .build()?;

    if check_only {
        let latest = update.get_latest_release()?;
        let latest_ver = latest.version.trim_start_matches('v');
        if self_update::version::bump_is_greater(current, latest_ver)? {
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
            self_update::Status::UpToDate(v) => {
                println!(
                    "{} phantom {} is already at the latest version.",
                    "ok".green().bold(),
                    v
                );
            }
            self_update::Status::Updated(v) => {
                println!(
                    "{} phantom updated to {}.",
                    "ok".green().bold(),
                    v.green().bold()
                );
            }
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
}
