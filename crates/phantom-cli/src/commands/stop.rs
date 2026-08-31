use anyhow::Result;
use colored::Colorize;

use super::proxy_state::{read_proxy_state, request_authenticated_shutdown, ProxyState};

pub fn run() -> Result<()> {
    let project_dir = std::env::current_dir()?;
    let pid_path = project_dir.join(".phantom.pid");

    match read_proxy_state(&pid_path) {
        ProxyState::Missing => {
            println!("{} No running proxy found.", "!".yellow().bold());
            Ok(())
        }
        ProxyState::Stale(pid) => {
            std::fs::remove_file(&pid_path)?;
            println!(
                "{} Removed stale proxy PID file (PID {}).",
                "ok".green().bold(),
                pid.pid
            );
            Ok(())
        }
        ProxyState::Malformed(_) => {
            std::fs::remove_file(&pid_path)?;
            println!("{} Removed malformed proxy PID file.", "ok".green().bold());
            Ok(())
        }
        ProxyState::Unknown(pid) => {
            anyhow::bail!(
                "Refusing to stop PID {}: it did not prove ownership of the Phantom proxy session on 127.0.0.1:{}. The PID may have been reused. Inspect the process and remove .phantom.pid manually only if it is stale.",
                pid.pid,
                pid.port
            );
        }
        ProxyState::Running(pid) => {
            request_authenticated_shutdown(&pid).map_err(anyhow::Error::msg)?;
            std::fs::remove_file(&pid_path)?;
            println!(
                "{} Authenticated proxy shutdown accepted (PID {}).",
                "ok".green().bold(),
                pid.pid
            );
            Ok(())
        }
    }
}
