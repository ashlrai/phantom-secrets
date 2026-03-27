use anyhow::Result;
use colored::Colorize;

pub fn run() -> Result<()> {
    let project_dir = std::env::current_dir()?;
    let pid_path = project_dir.join(".phantom.pid");

    if !pid_path.exists() {
        println!("{} No running proxy found.", "!".yellow().bold());
        return Ok(());
    }

    let pid_info = std::fs::read_to_string(&pid_path)?;
    let parts: Vec<&str> = pid_info.trim().split(':').collect();

    if let Some(pid_str) = parts.first() {
        if let Ok(pid) = pid_str.parse::<u32>() {
            // Send SIGTERM to the proxy process
            #[cfg(unix)]
            {
                let _ = std::process::Command::new("kill")
                    .arg(pid.to_string())
                    .status();
            }
            println!(
                "{} Sent stop signal to proxy (PID {})",
                "ok".green().bold(),
                pid
            );
        }
    }

    // Clean up PID file
    let _ = std::fs::remove_file(&pid_path);
    println!("{} Proxy stopped.", "ok".green().bold());

    Ok(())
}
