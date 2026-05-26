use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyPid {
    pub pid: u32,
    pub port: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProxyState {
    Missing,
    Running(ProxyPid),
    Stale(ProxyPid),
    Malformed(String),
    Unknown(ProxyPid),
}

pub fn read_proxy_state(pid_path: &Path) -> ProxyState {
    if !pid_path.exists() {
        return ProxyState::Missing;
    }

    let contents = match std::fs::read_to_string(pid_path) {
        Ok(contents) => contents,
        Err(err) => return ProxyState::Malformed(err.to_string()),
    };

    let parsed = match parse_pid_file(&contents) {
        Ok(parsed) => parsed,
        Err(err) => return ProxyState::Malformed(err),
    };

    match process_liveness(parsed.pid) {
        Liveness::Alive => ProxyState::Running(parsed),
        Liveness::Dead => ProxyState::Stale(parsed),
        Liveness::Unknown => ProxyState::Unknown(parsed),
    }
}

pub fn cleanup_if_stale_or_malformed(pid_path: &Path) -> std::io::Result<bool> {
    match read_proxy_state(pid_path) {
        ProxyState::Stale(_) | ProxyState::Malformed(_) => {
            std::fs::remove_file(pid_path)?;
            Ok(true)
        }
        _ => Ok(false),
    }
}

fn parse_pid_file(contents: &str) -> Result<ProxyPid, String> {
    let parts: Vec<&str> = contents.trim().split(':').collect();
    if parts.len() < 3 {
        return Err("expected pid:port:token".to_string());
    }

    let pid = parts[0]
        .parse::<u32>()
        .map_err(|_| "invalid pid".to_string())?;
    let port = parts[1]
        .parse::<u16>()
        .map_err(|_| "invalid port".to_string())?;

    Ok(ProxyPid { pid, port })
}

enum Liveness {
    Alive,
    Dead,
    Unknown,
}

fn process_liveness(pid: u32) -> Liveness {
    #[cfg(unix)]
    {
        match std::process::Command::new("kill")
            .arg("-0")
            .arg(pid.to_string())
            .status()
        {
            Ok(status) if status.success() => Liveness::Alive,
            Ok(_) => Liveness::Dead,
            Err(_) => Liveness::Unknown,
        }
    }

    #[cfg(windows)]
    {
        match std::process::Command::new("tasklist")
            .args(["/FI", &format!("PID eq {pid}")])
            .output()
        {
            Ok(output) if !output.status.success() => Liveness::Unknown,
            Ok(output) => {
                let stdout = String::from_utf8_lossy(&output.stdout);
                if stdout.contains(&pid.to_string()) {
                    Liveness::Alive
                } else {
                    Liveness::Dead
                }
            }
            Err(_) => Liveness::Unknown,
        }
    }

    #[cfg(not(any(unix, windows)))]
    {
        let _ = pid;
        Liveness::Unknown
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_pid_file_without_exposing_token() {
        let parsed = parse_pid_file("123:4567:secret-token").unwrap();
        assert_eq!(parsed.pid, 123);
        assert_eq!(parsed.port, 4567);
    }

    #[test]
    fn rejects_malformed_pid_file() {
        assert!(parse_pid_file("123:bad:token").is_err());
        assert!(parse_pid_file("123:4567").is_err());
    }
}
