use std::fmt;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddrV4, TcpStream};
use std::path::Path;
use std::time::Duration;

#[derive(Clone, PartialEq, Eq)]
pub struct ProxyPid {
    pub pid: u32,
    pub port: u16,
    pub(crate) token: String,
}

impl fmt::Debug for ProxyPid {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProxyPid")
            .field("pid", &self.pid)
            .field("port", &self.port)
            .field("token", &"[REDACTED]")
            .finish()
    }
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
        Liveness::Alive if authenticated_health_check(&parsed) => ProxyState::Running(parsed),
        Liveness::Alive => ProxyState::Unknown(parsed),
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
    if parts.len() != 3 {
        return Err("expected pid:port:token".to_string());
    }

    let pid = parts[0]
        .parse::<u32>()
        .map_err(|_| "invalid pid".to_string())?;
    let port = parts[1]
        .parse::<u16>()
        .map_err(|_| "invalid port".to_string())?;
    let token = parts[2];
    if token.len() != 64 || !token.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("invalid proxy token".to_string());
    }

    Ok(ProxyPid {
        pid,
        port,
        token: token.to_string(),
    })
}

const PROXY_CONTROL_TIMEOUT: Duration = Duration::from_millis(750);
const HEALTH_BODY: &str = r#"{"status":"ok","service":"phantom-proxy"}"#;
const SHUTDOWN_BODY: &str = r#"{"status":"shutting_down","service":"phantom-proxy"}"#;

fn authenticated_health_check(proxy: &ProxyPid) -> bool {
    authenticated_control_request(proxy, "GET", "/phantom/health", HEALTH_BODY).is_ok()
}

pub(crate) fn request_authenticated_shutdown(proxy: &ProxyPid) -> Result<(), String> {
    authenticated_control_request(proxy, "POST", "/phantom/shutdown", SHUTDOWN_BODY)
}

fn authenticated_control_request(
    proxy: &ProxyPid,
    method: &str,
    path: &str,
    expected_body: &str,
) -> Result<(), String> {
    let address = SocketAddrV4::new(Ipv4Addr::LOCALHOST, proxy.port);
    let mut stream = TcpStream::connect_timeout(&address.into(), PROXY_CONTROL_TIMEOUT)
        .map_err(|error| format!("could not connect to authenticated proxy: {error}"))?;
    stream
        .set_read_timeout(Some(PROXY_CONTROL_TIMEOUT))
        .map_err(|error| format!("could not set proxy read timeout: {error}"))?;
    stream
        .set_write_timeout(Some(PROXY_CONTROL_TIMEOUT))
        .map_err(|error| format!("could not set proxy write timeout: {error}"))?;

    let request = format!(
        "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nx-phantom-proxy-token: {}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        proxy.port, proxy.token
    );
    stream
        .write_all(request.as_bytes())
        .map_err(|error| format!("could not write authenticated proxy request: {error}"))?;

    let mut response = String::new();
    stream
        .take(4096)
        .read_to_string(&mut response)
        .map_err(|error| format!("could not read authenticated proxy response: {error}"))?;
    let (headers, body) = response
        .split_once("\r\n\r\n")
        .ok_or_else(|| "authenticated proxy returned a malformed HTTP response".to_string())?;
    let status_line = headers.lines().next().unwrap_or_default();
    if !status_line.starts_with("HTTP/1.1 200 ") || body != expected_body {
        return Err("process did not prove ownership of this Phantom proxy session".to_string());
    }
    Ok(())
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
        let token = "a".repeat(64);
        let parsed = parse_pid_file(&format!("123:4567:{token}")).unwrap();
        assert_eq!(parsed.pid, 123);
        assert_eq!(parsed.port, 4567);
        assert!(!format!("{parsed:?}").contains(&token));
    }

    #[test]
    fn rejects_malformed_pid_file() {
        assert!(parse_pid_file("123:bad:token").is_err());
        assert!(parse_pid_file("123:4567").is_err());
        assert!(parse_pid_file("123:4567:not-hex").is_err());
    }

    #[test]
    fn live_reused_pid_without_authenticated_proxy_is_unknown() {
        use std::net::TcpListener;
        use std::thread;

        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let responder = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0u8; 2048];
            let _ = stream.read(&mut request).unwrap();
            stream
                .write_all(
                    b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 24\r\nConnection: close\r\n\r\n{\"error\":\"not_phantom\"}",
                )
                .unwrap();
        });
        let temp = tempfile::TempDir::new().unwrap();
        let pid_path = temp.path().join(".phantom.pid");
        std::fs::write(
            &pid_path,
            format!("{}:{port}:{}", std::process::id(), "a".repeat(64)),
        )
        .unwrap();

        assert!(matches!(
            read_proxy_state(&pid_path),
            ProxyState::Unknown(_)
        ));
        responder.join().unwrap();
    }
}
