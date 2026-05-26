use anyhow::Result;
use colored::Colorize;

use super::proxy_state::{read_proxy_state, ProxyState};

pub fn run() -> Result<()> {
    let project_dir = std::env::current_dir()?;
    let pid_path = project_dir.join(".phantom.pid");

    match read_proxy_state(&pid_path) {
        ProxyState::Missing => {
            println!("{} No running proxy found.", "!".yellow().bold());
            return Ok(());
        }
        ProxyState::Stale(pid) => {
            let _ = std::fs::remove_file(&pid_path);
            println!(
                "{} Removed stale proxy PID file (PID {}).",
                "ok".green().bold(),
                pid.pid
            );
            return Ok(());
        }
        ProxyState::Malformed(_) => {
            let _ = std::fs::remove_file(&pid_path);
            println!("{} Removed malformed proxy PID file.", "ok".green().bold());
            return Ok(());
        }
        ProxyState::Running(pid) | ProxyState::Unknown(pid) => {
            // Send stop signal to the proxy process
            #[cfg(unix)]
            {
                let _ = std::process::Command::new("kill")
                    .arg(pid.pid.to_string())
                    .status();
            }
            #[cfg(windows)]
            {
                let _ = std::process::Command::new("taskkill")
                    .args(["/PID", &pid.pid.to_string(), "/F"])
                    .status();
            }
            println!(
                "{} Sent stop signal to proxy (PID {})",
                "ok".green().bold(),
                pid.pid
            );
        }
    }

    // Clean up PID file
    let _ = std::fs::remove_file(&pid_path);
    println!("{} Proxy stopped.", "ok".green().bold());

    Ok(())
}
