use anyhow::Result;
use std::fmt;
use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddrV4, TcpStream};
use std::path::Path;
use std::time::Duration;

const CONTROL_TIMEOUT: Duration = Duration::from_millis(750);
const HEALTH_BODY: &str = r#"{"status":"ok","service":"phantom-proxy"}"#;
const SHUTDOWN_BODY: &str = r#"{"status":"shutting_down","service":"phantom-proxy"}"#;

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct LegacyProxy {
    pub pid: u32,
    pub port: u16,
    token: String,
}

impl fmt::Debug for LegacyProxy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LegacyProxy")
            .field("pid", &self.pid)
            .field("port", &self.port)
            .field("token", &"[REDACTED]")
            .finish()
    }
}

#[derive(Debug)]
pub(crate) enum LegacyState {
    Missing,
    Authenticated(LegacyProxy),
    Unverified(LegacyProxy),
    Unsafe(String),
}

fn open_legacy_state(path: &Path) -> std::io::Result<std::fs::File> {
    let metadata = std::fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() > 512 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "legacy state must be one bounded regular, non-symlink file",
        ));
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    options.open(path)
}

fn parse(contents: &str) -> std::result::Result<LegacyProxy, String> {
    let parts: Vec<&str> = contents.trim().split(':').collect();
    if parts.len() != 3 {
        return Err("expected pid:port:bearer".to_string());
    }
    let pid = parts[0]
        .parse::<u32>()
        .map_err(|_| "invalid pid".to_string())?;
    let port = parts[1]
        .parse::<u16>()
        .map_err(|_| "invalid port".to_string())?;
    let token = parts[2];
    if pid == 0
        || port == 0
        || token.len() != 64
        || !token.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err("invalid pid, port, or bearer".to_string());
    }
    Ok(LegacyProxy {
        pid,
        port,
        token: token.to_string(),
    })
}

pub(crate) fn inspect(project_dir: &Path) -> LegacyState {
    let path = project_dir.join(".phantom.pid");
    let file = match open_legacy_state(&path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return LegacyState::Missing,
        Err(error) => return LegacyState::Unsafe(error.to_string()),
    };
    let mut contents = String::new();
    if let Err(error) = file.take(513).read_to_string(&mut contents) {
        return LegacyState::Unsafe(error.to_string());
    }
    let proxy = match parse(&contents) {
        Ok(proxy) => proxy,
        Err(error) => return LegacyState::Unsafe(error),
    };
    if control_request(&proxy, "GET", "/phantom/health", HEALTH_BODY).is_ok() {
        LegacyState::Authenticated(proxy)
    } else {
        LegacyState::Unverified(proxy)
    }
}

pub(crate) fn refuse_start_with_legacy_state(project_dir: &Path) -> Result<()> {
    match inspect(project_dir) {
        LegacyState::Missing => Ok(()),
        LegacyState::Authenticated(proxy) => anyhow::bail!(
            "Authenticated legacy v0.7.3 proxy state exists for PID {}. Run `phantom stop` from a trusted interactive terminal to migrate it before starting a new proxy.",
            proxy.pid
        ),
        LegacyState::Unverified(proxy) => anyhow::bail!(
            "Unverified legacy .phantom.pid state exists for PID {}; refusing to start because the PID may be stale or reused. Inspect it manually and remove only after proving no legacy proxy owns it.",
            proxy.pid
        ),
        LegacyState::Unsafe(error) => anyhow::bail!(
            "Unsafe or malformed legacy .phantom.pid state; refusing to start and leaving it untouched: {error}"
        ),
    }
}

pub(crate) fn authenticated_shutdown(proxy: &LegacyProxy) -> Result<()> {
    control_request(proxy, "POST", "/phantom/shutdown", SHUTDOWN_BODY).map_err(anyhow::Error::msg)
}

fn control_request(
    proxy: &LegacyProxy,
    method: &str,
    path: &str,
    expected_body: &str,
) -> std::result::Result<(), String> {
    let address = SocketAddrV4::new(Ipv4Addr::LOCALHOST, proxy.port);
    let mut stream = TcpStream::connect_timeout(&address.into(), CONTROL_TIMEOUT)
        .map_err(|error| format!("could not connect to authenticated legacy proxy: {error}"))?;
    stream
        .set_read_timeout(Some(CONTROL_TIMEOUT))
        .map_err(|error| format!("could not set read timeout: {error}"))?;
    stream
        .set_write_timeout(Some(CONTROL_TIMEOUT))
        .map_err(|error| format!("could not set write timeout: {error}"))?;
    let request = format!(
        "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nx-phantom-proxy-token: {}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        proxy.port, proxy.token
    );
    stream
        .write_all(request.as_bytes())
        .map_err(|error| format!("could not write authenticated request: {error}"))?;
    let mut response = String::new();
    stream
        .take(4096)
        .read_to_string(&mut response)
        .map_err(|error| format!("could not read authenticated response: {error}"))?;
    let (headers, body) = response
        .split_once("\r\n\r\n")
        .ok_or_else(|| "legacy proxy returned a malformed HTTP response".to_string())?;
    if !headers
        .lines()
        .next()
        .unwrap_or_default()
        .starts_with("HTTP/1.1 200 ")
        || body != expected_body
    {
        return Err("process did not prove ownership of the legacy Phantom proxy session".into());
    }
    Ok(())
}

pub(crate) fn wait_for_owner_cleanup(project_dir: &Path) -> Result<()> {
    let path = project_dir.join(".phantom.pid");
    for _ in 0..20 {
        if !path.exists() {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    anyhow::bail!(
        "Legacy proxy accepted shutdown but did not remove .phantom.pid. It was left untouched to avoid deleting replaced state; inspect it manually."
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parser_redacts_and_rejects_malformed_records() {
        let token = "a".repeat(64);
        let parsed = parse(&format!("123:4567:{token}")).unwrap();
        assert!(!format!("{parsed:?}").contains(&token));
        for bad in ["123:4567", "0:4567:abc", "123:0:abc", "bad"] {
            assert!(parse(bad).is_err());
        }
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_legacy_state_is_never_followed() {
        use std::os::unix::fs::symlink;
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target");
        std::fs::write(&target, format!("1:1:{}", "a".repeat(64))).unwrap();
        symlink(&target, dir.path().join(".phantom.pid")).unwrap();
        assert!(matches!(inspect(dir.path()), LegacyState::Unsafe(_)));
        assert!(target.exists());
    }

    #[test]
    fn authenticated_legacy_owner_controls_shutdown_and_removes_its_record() {
        use std::net::TcpListener;
        use std::thread;

        let dir = tempfile::tempdir().unwrap();
        let pid_path = dir.path().join(".phantom.pid");
        let token = "b".repeat(64);
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        std::fs::write(&pid_path, format!("{}:{port}:{token}", std::process::id())).unwrap();
        let owner_path = pid_path.clone();
        let owner_token = token.clone();
        let owner = thread::spawn(move || {
            for (expected_path, body) in [
                ("/phantom/health", HEALTH_BODY),
                ("/phantom/shutdown", SHUTDOWN_BODY),
            ] {
                let (mut stream, _) = listener.accept().unwrap();
                let mut request = [0u8; 2048];
                let count = stream.read(&mut request).unwrap();
                let request = String::from_utf8_lossy(&request[..count]);
                assert!(request.contains(expected_path));
                assert!(request.contains(&format!("x-phantom-proxy-token: {owner_token}")));
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                stream.write_all(response.as_bytes()).unwrap();
            }
            std::fs::remove_file(owner_path).unwrap();
        });

        let proxy = match inspect(dir.path()) {
            LegacyState::Authenticated(proxy) => proxy,
            other => panic!("unexpected legacy state: {other:?}"),
        };
        authenticated_shutdown(&proxy).unwrap();
        wait_for_owner_cleanup(dir.path()).unwrap();
        owner.join().unwrap();
    }
}
