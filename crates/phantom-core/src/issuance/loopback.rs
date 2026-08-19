//! Loopback redirect capture (RFC 8252 §7.3).
//!
//! Binds an ephemeral listener on **`127.0.0.1:0`** (never `0.0.0.0`, never a
//! public host), serves an optional self-submitting launch page on `GET /`, and
//! captures the single `GET /callback?code=…&state=…` redirect the browser is
//! sent back to. One request, then it closes — matching the proxy's
//! "127.0.0.1 only" rule.
//!
//! A [`MockLoopbackListener`] stands in for the socket in tests (and in the
//! `assert_cmd` e2e harness, where there is no human to click "Authorize"),
//! returning a canned code + echoed state deterministically.

use super::IssuanceError;
use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

/// Where the loopback listener bound.
#[derive(Debug, Clone)]
pub struct LoopbackBinding {
    /// The ephemeral port the OS assigned.
    pub port: u16,
    /// The full redirect URI to hand the provider, e.g.
    /// `http://127.0.0.1:{port}/callback`.
    pub redirect_uri: String,
}

/// The captured authorization redirect.
pub struct CapturedCode {
    /// The one-time authorization/manifest code — `Zeroizing`, never logged.
    pub code: Zeroizing<String>,
    /// The `state` the browser echoed back (the engine verifies it == its own).
    pub state: String,
    /// Extra (non-secret) redirect query params keyed by name, e.g. Sentry's
    /// `installationId`. `code`/`state` are surfaced above and excluded here.
    pub extra: BTreeMap<String, String>,
}

/// Binds the loopback listener and blocks for the redirect. Injected so core is
/// hermetically testable.
pub trait LoopbackListener: Send + Sync {
    /// Bind `127.0.0.1:0` and report the assigned port + redirect URI.
    fn bind(&self) -> Result<LoopbackBinding, IssuanceError>;

    /// Block until the browser hits `/callback` (or `timeout` elapses).
    ///
    /// `expected_state` is the CSRF `state` the engine generated; the real
    /// listener still returns the *observed* state so the engine performs the
    /// comparison, but a faithful mock echoes `expected_state` on its happy
    /// path. `launch_html`, when `Some`, is served on `GET /` (the
    /// self-submitting manifest launch page) until the redirect arrives.
    fn wait(
        &self,
        expected_state: &str,
        launch_html: Option<&str>,
        timeout: Duration,
    ) -> Result<CapturedCode, IssuanceError>;
}

// ── Real listener ───────────────────────────────────────────────────────────

/// Real `127.0.0.1:0` listener backed by [`std::net::TcpListener`].
///
/// The bound socket is held between [`bind`](LoopbackListener::bind) and
/// [`wait`](LoopbackListener::wait) via interior mutability so the ephemeral
/// port stays reserved.
#[derive(Default)]
pub struct StdLoopbackListener {
    listener: Mutex<Option<TcpListener>>,
    port: Mutex<u16>,
}

impl StdLoopbackListener {
    pub fn new() -> Self {
        Self::default()
    }
}

impl LoopbackListener for StdLoopbackListener {
    fn bind(&self) -> Result<LoopbackBinding, IssuanceError> {
        let listener =
            TcpListener::bind("127.0.0.1:0").map_err(|e| IssuanceError::LoopbackBindFailed {
                reason: e.to_string(),
            })?;
        let port = listener
            .local_addr()
            .map_err(|e| IssuanceError::LoopbackBindFailed {
                reason: e.to_string(),
            })?
            .port();
        listener
            .set_nonblocking(true)
            .map_err(|e| IssuanceError::LoopbackBindFailed {
                reason: e.to_string(),
            })?;
        *self.listener.lock().unwrap() = Some(listener);
        *self.port.lock().unwrap() = port;
        Ok(LoopbackBinding {
            port,
            redirect_uri: format!("http://127.0.0.1:{port}/callback"),
        })
    }

    fn wait(
        &self,
        _expected_state: &str,
        launch_html: Option<&str>,
        timeout: Duration,
    ) -> Result<CapturedCode, IssuanceError> {
        let listener = self.listener.lock().unwrap().take().ok_or_else(|| {
            IssuanceError::LoopbackBindFailed {
                reason: "wait() called before bind()".to_string(),
            }
        })?;

        let deadline = Instant::now() + timeout;
        loop {
            if Instant::now() >= deadline {
                return Err(IssuanceError::ConsentTimeout {
                    waited_secs: timeout.as_secs(),
                });
            }
            match listener.accept() {
                Ok((stream, _addr)) => {
                    // Serve blocking on this accepted connection.
                    stream
                        .set_nonblocking(false)
                        .and_then(|()| stream.set_read_timeout(Some(Duration::from_secs(5))))
                        .ok();
                    if let Some(captured) = handle_connection(stream, launch_html) {
                        return Ok(captured);
                    }
                    // A `GET /` (launch page) was served; keep waiting for the
                    // redirect back to `/callback`.
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(50));
                }
                Err(e) => {
                    return Err(IssuanceError::LoopbackBindFailed {
                        reason: e.to_string(),
                    });
                }
            }
        }
    }
}

/// Handle one accepted connection. Returns `Some(CapturedCode)` when the
/// request was the `/callback` redirect; `None` when it was the launch page
/// (which we served) or an ignorable request.
fn handle_connection(
    stream: std::net::TcpStream,
    launch_html: Option<&str>,
) -> Option<CapturedCode> {
    let mut reader = BufReader::new(stream);
    let mut request_line = String::new();
    if reader.read_line(&mut request_line).is_err() {
        return None;
    }
    // "GET /callback?code=..&state=.. HTTP/1.1"
    let path = request_line.split_whitespace().nth(1).unwrap_or("/");

    let mut stream = reader.into_inner();
    if let Some((_, query)) = path.split_once('?') {
        if path.starts_with("/callback") {
            let code = query_param(query, "code");
            let state = query_param(query, "state").unwrap_or_default();
            if let Some(code) = code {
                // Collect any other (non-secret) params the provider appended,
                // e.g. Sentry's `installationId`. `code`/`state` are surfaced on
                // their own fields, so exclude them from `extra`.
                let mut extra = BTreeMap::new();
                for pair in query.split('&') {
                    if let Some((k, v)) = pair.split_once('=') {
                        if k != "code" && k != "state" {
                            extra.insert(k.to_string(), percent_decode(v));
                        }
                    }
                }
                let _ = write_response(
                    &mut stream,
                    "200 OK",
                    "text/plain",
                    "Phantom received the authorization. You may close this tab.",
                );
                return Some(CapturedCode {
                    code: Zeroizing::new(code),
                    state,
                    extra,
                });
            }
        }
    }

    // Not the callback — serve the launch page (or a minimal ack) and keep going.
    if let Some(html) = launch_html {
        let _ = write_response(&mut stream, "200 OK", "text/html", html);
    } else {
        let _ = write_response(&mut stream, "200 OK", "text/plain", "phantom loopback");
    }
    None
}

fn write_response(
    stream: &mut std::net::TcpStream,
    status: &str,
    content_type: &str,
    body: &str,
) -> std::io::Result<()> {
    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}; charset=utf-8\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(response.as_bytes())?;
    stream.flush()
}

/// Extract a query parameter value with minimal percent-decoding.
fn query_param(query: &str, key: &str) -> Option<String> {
    for pair in query.split('&') {
        if let Some((k, v)) = pair.split_once('=') {
            if k == key {
                return Some(percent_decode(v));
            }
        }
    }
    None
}

/// Minimal `application/x-www-form-urlencoded` decode (`+` → space, `%XX`).
fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < bytes.len() => {
                let hi = (bytes[i + 1] as char).to_digit(16);
                let lo = (bytes[i + 2] as char).to_digit(16);
                if let (Some(hi), Some(lo)) = (hi, lo) {
                    out.push((hi * 16 + lo) as u8);
                    i += 3;
                } else {
                    out.push(bytes[i]);
                    i += 1;
                }
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

// ── Mock listener (tests + e2e harness) ─────────────────────────────────────

/// How the mock listener produces the `state` it returns.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MockStateMode {
    /// Echo the engine's `expected_state` — the happy path (CSRF passes).
    Echo,
    /// Return a deliberately different state — drives the CSRF-mismatch test.
    Tamper,
}

/// Deterministic stand-in for the loopback socket: returns a canned code and a
/// state chosen by [`MockStateMode`], with no real port or browser involved.
pub struct MockLoopbackListener {
    code: String,
    state_mode: MockStateMode,
    extra: BTreeMap<String, String>,
}

impl MockLoopbackListener {
    /// Construct with an explicit code and state behaviour.
    pub fn new(code: impl Into<String>, state_mode: MockStateMode) -> Self {
        Self {
            code: code.into(),
            state_mode,
            extra: BTreeMap::new(),
        }
    }

    /// Add an extra (non-secret) redirect param the mock will surface in
    /// [`CapturedCode::extra`], e.g. Sentry's `installationId`.
    pub fn with_extra_param(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.extra.insert(key.into(), value.into());
        self
    }

    /// Build from the test harness env: `PHANTOM_ISSUANCE_MOCK_CODE`
    /// (default `"mock_code"`), always echoing state. When
    /// `PHANTOM_ISSUANCE_MOCK_INSTALLATION_ID` is set it is surfaced as the
    /// `installationId` extra param (the Sentry install landing).
    pub fn from_env() -> Self {
        let code =
            std::env::var("PHANTOM_ISSUANCE_MOCK_CODE").unwrap_or_else(|_| "mock_code".to_string());
        let mut listener = Self::new(code, MockStateMode::Echo);
        if let Ok(uuid) = std::env::var("PHANTOM_ISSUANCE_MOCK_INSTALLATION_ID") {
            if !uuid.is_empty() {
                listener = listener.with_extra_param("installationId", uuid);
            }
        }
        listener
    }
}

impl LoopbackListener for MockLoopbackListener {
    fn bind(&self) -> Result<LoopbackBinding, IssuanceError> {
        Ok(LoopbackBinding {
            port: 0,
            redirect_uri: "http://127.0.0.1:0/callback".to_string(),
        })
    }

    fn wait(
        &self,
        expected_state: &str,
        _launch_html: Option<&str>,
        _timeout: Duration,
    ) -> Result<CapturedCode, IssuanceError> {
        let state = match self.state_mode {
            MockStateMode::Echo => expected_state.to_string(),
            MockStateMode::Tamper => format!("{expected_state}-tampered"),
        };
        Ok(CapturedCode {
            code: Zeroizing::new(self.code.clone()),
            state,
            extra: self.extra.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mock_echo_matches_expected_state() {
        let l = MockLoopbackListener::new("abc123", MockStateMode::Echo);
        let cap = l.wait("the-state", None, Duration::from_secs(1)).unwrap();
        assert_eq!(cap.code.as_str(), "abc123");
        assert_eq!(cap.state, "the-state");
    }

    #[test]
    fn mock_tamper_mismatches() {
        let l = MockLoopbackListener::new("abc123", MockStateMode::Tamper);
        let cap = l.wait("the-state", None, Duration::from_secs(1)).unwrap();
        assert_ne!(cap.state, "the-state");
    }

    #[test]
    fn query_param_decodes() {
        assert_eq!(
            query_param("code=abc%2Fdef&state=x", "code").as_deref(),
            Some("abc/def")
        );
        assert_eq!(
            query_param("code=abc&state=xyz", "state").as_deref(),
            Some("xyz")
        );
        assert_eq!(query_param("code=abc", "missing"), None);
    }

    #[test]
    fn std_listener_binds_ephemeral_loopback() {
        let l = StdLoopbackListener::new();
        let b = l.bind().unwrap();
        assert!(b.port > 0);
        assert!(b.redirect_uri.starts_with("http://127.0.0.1:"));
        assert!(b.redirect_uri.ends_with("/callback"));
    }
}
