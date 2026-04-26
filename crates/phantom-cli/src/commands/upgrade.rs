use colored::Colorize;

pub fn run(force: bool, check_only: bool) -> anyhow::Result<()> {
    let current = env!("CARGO_PKG_VERSION");

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
            println!(
                "{} Permission denied — if phantom was installed via Homebrew, run: {}",
                "!".red().bold(),
                "brew upgrade phantom".yellow(),
            );
            std::process::exit(1);
        }
        Err(e) => return Err(e.into()),
    }

    Ok(())
}
