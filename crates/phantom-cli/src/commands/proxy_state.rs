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
    if pid == 0 {
        return Err("invalid pid".to_string());
    }
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Liveness {
    Alive,
    Dead,
    Unknown,
}

fn process_liveness(pid: u32) -> Liveness {
    #[cfg(unix)]
    {
        let Ok(native_pid) = libc::pid_t::try_from(pid) else {
            return Liveness::Unknown;
        };
        // SAFETY: signal 0 never delivers a signal. `native_pid` is a checked
        // scalar process identifier and no pointers cross the FFI boundary.
        if unsafe { libc::kill(native_pid, 0) } == 0 {
            return Liveness::Alive;
        }
        match std::io::Error::last_os_error().raw_os_error() {
            Some(libc::ESRCH) => Liveness::Dead,
            // A permissions failure proves that the PID exists even though
            // this user cannot inspect or signal it.
            Some(libc::EPERM) => Liveness::Alive,
            _ => Liveness::Unknown,
        }
    }

    #[cfg(windows)]
    {
        use windows_sys::Win32::Foundation::{
            CloseHandle, GetLastError, ERROR_ACCESS_DENIED, ERROR_INVALID_PARAMETER, WAIT_OBJECT_0,
            WAIT_TIMEOUT,
        };
        use windows_sys::Win32::System::Threading::{
            OpenProcess, WaitForSingleObject, PROCESS_QUERY_LIMITED_INFORMATION,
        };
        const SYNCHRONIZE_ACCESS: u32 = 0x0010_0000;

        // SAFETY: OpenProcess receives a numeric PID and requests only query
        // and synchronization access. Every non-null handle is closed once.
        let handle = unsafe {
            OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE_ACCESS,
                0,
                pid,
            )
        };
        if handle.is_null() {
            // SAFETY: GetLastError is read immediately after the failed call.
            return match unsafe { GetLastError() } {
                ERROR_INVALID_PARAMETER => Liveness::Dead,
                ERROR_ACCESS_DENIED => Liveness::Alive,
                _ => Liveness::Unknown,
            };
        }

        // SAFETY: waiting for zero milliseconds is a non-blocking state query;
        // the process handle includes synchronization access and stays valid.
        let wait_state = unsafe { WaitForSingleObject(handle, 0) };
        // SAFETY: `handle` is the unique non-null handle returned above.
        let _ = unsafe { CloseHandle(handle) };
        match wait_state {
            WAIT_TIMEOUT => Liveness::Alive,
            WAIT_OBJECT_0 => Liveness::Dead,
            _ => Liveness::Unknown,
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
        assert!(parse_pid_file(&format!("0:4567:{}", "a".repeat(64))).is_err());
    }

    #[test]
    fn current_process_is_alive_via_native_api() {
        assert_eq!(process_liveness(std::process::id()), Liveness::Alive);
    }

    #[test]
    fn exited_child_is_dead_via_native_api() {
        let test_binary = std::env::current_exe().unwrap();
        let mut child = std::process::Command::new(test_binary)
            .args(["--exact", "proxy_state_nonexistent_test_filter"])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let pid = child.id();
        assert!(child.wait().unwrap().success());
        assert_eq!(process_liveness(pid), Liveness::Dead);
    }

    #[test]
    fn liveness_implementation_has_no_ambient_process_tools() {
        let source = include_str!("proxy_state.rs");
        let command = ["Command", "::new"].concat();
        assert!(!source.contains(&format!(r#"{command}("{}")"#, "kill")));
        assert!(!source.contains(&format!(r#"{command}("{}")"#, "tasklist")));
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
