//! Machine-readable, value-blind report shapes shared by `phantom check --json`,
//! `phantom doctor --json`, and the MCP `phantom_check` / `phantom_doctor` tools.
//!
//! Every field carries names, paths, labels, or fixed diagnostic text. Secret
//! values and phantom token values are never recorded in these types.

use serde::Serialize;

/// One unprotected-secret finding.
#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct CheckFinding {
    /// `dotenv`, `staged_dotenv`, `staged_code`, or `runtime_env`.
    pub kind: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pattern: Option<&'static str>,
}

/// A risky `.phantom.toml` service route found in the staged config.
#[derive(Debug, Serialize)]
pub struct CheckConfigWarning {
    pub path: String,
    pub service: String,
    pub message: String,
}

/// A scanned file whose protection status could not be determined (for
/// example a malformed dotenv). The CLI fails closed with an error instead;
/// the MCP tool reports it here and never marks the scan clean.
#[derive(Debug, Serialize)]
pub struct CheckIndeterminate {
    pub path: String,
    pub reason: String,
}

/// The `check` report. `indeterminate`, `excused` and `session_warning` are
/// omitted when empty and `proxy_session` when false, so CLI output keeps
/// exactly the `{mode, clean, findings, warnings}` shape outside a session.
#[derive(Debug, Serialize)]
pub struct CheckReport<'a> {
    pub mode: &'a str,
    pub clean: bool,
    pub findings: &'a [CheckFinding],
    pub warnings: &'a [CheckConfigWarning],
    #[serde(skip_serializing_if = "<[_]>::is_empty")]
    pub indeterminate: &'a [CheckIndeterminate],
    /// Runtime mode only: a live `phantom exec` / `phantom start` proxy
    /// answered for the session variables in this environment.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub proxy_session: bool,
    /// Runtime mode only: variables holding a phantom token that the live
    /// session names as its own, so they are not findings. Names only.
    #[serde(skip_serializing_if = "<[_]>::is_empty")]
    pub excused: &'a [String],
    /// Runtime mode only: why session variables did not excuse anything.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_warning: Option<&'a str>,
}

/// The variables `phantom exec` and `phantom start` set for a proxy session:
/// the proxy's port and the header value it requires.
pub const PROXY_SESSION_VARS: [&str; 2] = ["PHANTOM_PROXY_PORT", "PHANTOM_PROXY_TOKEN"];

/// Comma-separated names of the variables a proxy session filled with its own
/// phantom tokens. Set by `phantom exec` for its child and printed by
/// `phantom start`. Names only, never values.
pub const SESSION_KEYS_VAR: &str = "PHANTOM_SESSION_KEYS";

/// Shown when session variables are set but no proxy answered for them.
pub const STALE_SESSION_WARNING: &str = "PHANTOM_PROXY_PORT and PHANTOM_PROXY_TOKEN are set, but no Phantom proxy answered for them, so the session variables look stale (for example a `phantom start` that has since stopped). No variable was excused.";

/// A runtime scan of an environment for phantom tokens.
#[derive(Debug, PartialEq, Eq)]
pub struct RuntimeEnvScan {
    /// One `runtime_env` finding per variable holding a phantom token that a
    /// live session does not own, by name, sorted.
    pub findings: Vec<CheckFinding>,
    /// A live proxy answered for the session variables.
    pub proxy_session: bool,
    /// Variables holding a phantom token that the live session owns, sorted.
    pub excused: Vec<String>,
    /// Session variables were set but did not lead to a live proxy.
    pub stale_session: bool,
}

impl RuntimeEnvScan {
    /// The value-free warning for the report, if any.
    pub fn session_warning(&self) -> Option<&'static str> {
        self.stale_session.then_some(STALE_SESSION_WARNING)
    }
}

/// Scan every variable of an environment for a phantom token.
///
/// `phantom check --runtime` and the MCP `phantom_check` used to look only at
/// a fixed list of well-known names (and two different lists), so a token in
/// any other variable, such as one `phantom init` wrote for a custom key,
/// was reported clean. Names are recorded; values never are.
///
/// A variable is excused only when both [`PROXY_SESSION_VARS`] are set,
/// `proxy_answers(port, header)` reports that proxy alive, and
/// [`SESSION_KEYS_VAR`] names the variable. The probe is passed in so this
/// stays pure; production callers pass [`proxy_answers`].
pub fn scan_runtime_env<I, P>(vars: I, proxy_answers: P) -> RuntimeEnvScan
where
    I: IntoIterator<Item = (std::ffi::OsString, std::ffi::OsString)>,
    P: FnOnce(u16, &str) -> bool,
{
    let mut names = std::collections::BTreeSet::new();
    let mut port_raw: Option<std::ffi::OsString> = None;
    let mut header_raw: Option<std::ffi::OsString> = None;
    let mut owned_raw: Option<std::ffi::OsString> = None;
    for (key, raw) in vars {
        if raw
            .as_encoded_bytes()
            .starts_with(crate::token::PHANTOM_PREFIX.as_bytes())
        {
            names.insert(key.to_string_lossy().into_owned());
        }
        if key == PROXY_SESSION_VARS[0] {
            port_raw = Some(raw);
        } else if key == PROXY_SESSION_VARS[1] {
            header_raw = Some(raw);
        } else if key == SESSION_KEYS_VAR {
            owned_raw = Some(raw);
        }
    }

    let set = |raw: &Option<std::ffi::OsString>| raw.as_ref().is_some_and(|v| !v.is_empty());
    let session_vars_set = set(&port_raw) && set(&header_raw);
    let live = session_vars_set && {
        let port = port_raw
            .as_deref()
            .and_then(|v| v.to_str())
            .and_then(|v| v.trim().parse::<u16>().ok())
            .filter(|port| *port != 0);
        let header = header_raw.as_deref().and_then(|v| v.to_str());
        match (port, header) {
            (Some(port), Some(header)) => proxy_answers(port, header),
            _ => false,
        }
    };
    let owned: std::collections::BTreeSet<String> = if live {
        owned_raw
            .as_deref()
            .and_then(|v| v.to_str())
            .unwrap_or_default()
            .split(',')
            .map(str::trim)
            .filter(|name| !name.is_empty())
            .map(str::to_string)
            .collect()
    } else {
        Default::default()
    };

    let (excused, flagged): (Vec<String>, Vec<String>) =
        names.into_iter().partition(|name| owned.contains(name));
    RuntimeEnvScan {
        findings: flagged
            .into_iter()
            .map(|name| CheckFinding {
                kind: "runtime_env",
                path: None,
                name: Some(name),
                label: None,
                pattern: None,
            })
            .collect(),
        proxy_session: live,
        excused,
        stale_session: session_vars_set && !live,
    }
}

/// A variable name as text output may show it: control characters (a name
/// can hold any byte but `=` and NUL) are escaped, so a crafted name cannot
/// move the cursor, clear the screen, or fake another line of the report.
/// JSON output is escaped by its serializer and does not need this.
pub fn printable_name(name: &str) -> String {
    name.chars()
        .map(|c| {
            if c.is_control() {
                c.escape_default().to_string()
            } else {
                c.to_string()
            }
        })
        .collect()
}

/// Whether a Phantom proxy on `127.0.0.1:port` answers its health endpoint
/// for this session: `GET /phantom/health` with the `x-phantom-proxy-token`
/// header must return 200 with a body naming `"service":"phantom-proxy"`,
/// within a short timeout and a bounded read. Loopback only; nothing is
/// logged or returned but the answer.
pub fn proxy_answers(port: u16, header: &str) -> bool {
    use std::io::{Read, Write};
    use std::time::Duration;

    if header.is_empty() || header.bytes().any(|b| b == b'\r' || b == b'\n') {
        return false;
    }
    let address = std::net::SocketAddr::from(([127, 0, 0, 1], port));
    let Ok(mut stream) = std::net::TcpStream::connect_timeout(&address, Duration::from_millis(500))
    else {
        return false;
    };
    let wait = Some(Duration::from_millis(1500));
    if stream.set_read_timeout(wait).is_err() || stream.set_write_timeout(wait).is_err() {
        return false;
    }
    let request = format!(
        "GET /phantom/health HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nx-phantom-proxy-token: {header}\r\nConnection: close\r\n\r\n"
    );
    if stream.write_all(request.as_bytes()).is_err() {
        return false;
    }
    // Bounded: the proxy's health answer is a short JSON document. Another
    // local server answering 200 on a reused port must not count, so the
    // body has to name the proxy too.
    let mut response = Vec::new();
    let mut chunk = [0u8; 512];
    while response.len() < HEALTH_RESPONSE_LIMIT {
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(read) => response.extend_from_slice(&chunk[..read]),
            Err(_) => return false,
        }
    }
    response.truncate(HEALTH_RESPONSE_LIMIT);
    let ok_status =
        response.starts_with(b"HTTP/1.1 200 ") || response.starts_with(b"HTTP/1.0 200 ");
    let body = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|end| &response[end + 4..]);
    ok_status
        && body.is_some_and(|body| {
            body.windows(HEALTH_SERVICE_MARKER.len())
                .any(|window| window == HEALTH_SERVICE_MARKER)
        })
}

/// Most bytes of a health answer [`proxy_answers`] reads.
const HEALTH_RESPONSE_LIMIT: usize = 4096;

/// What the proxy's `/phantom/health` body says about itself.
const HEALTH_SERVICE_MARKER: &[u8] = br#""service":"phantom-proxy""#;

/// One doctor line. Messages are the same value-blind text the human report
/// prints; a following `Fix:`/`Fixed:` hint attaches to the check it explains.
#[derive(Debug, Serialize)]
pub struct DoctorCheck {
    /// `pass`, `fail`, `warn`, or `info`.
    pub status: &'static str,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fix: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fixed: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct DoctorMcpClient {
    pub client: String,
    pub path: String,
    /// `local_runtime`, `stale`, `unreadable`, `not_phantom`, or `not_configured`.
    pub state: &'static str,
}

#[derive(Debug, Default, Serialize)]
pub struct DoctorReport {
    pub ok: bool,
    pub issues: usize,
    pub fixed: usize,
    pub checks: Vec<DoctorCheck>,
    pub mcp_clients: Vec<DoctorMcpClient>,
}

impl DoctorReport {
    /// Record a new check line.
    pub fn push(&mut self, status: &'static str, message: &str) {
        self.checks.push(DoctorCheck {
            status,
            message: message.to_string(),
            fix: None,
            fixed: None,
        });
    }

    /// Attach a `Fix:` hint. One hint can follow a run of findings (each
    /// risky service route is its own warning), so it explains every trailing
    /// finding that has no hint yet.
    pub fn attach_fix(&mut self, msg: &str) {
        let mut trailing = self.checks.iter_mut().rev();
        let Some(last) = trailing.next() else { return };
        let finding = matches!(last.status, "warn" | "fail");
        last.fix = Some(msg.to_string());
        if finding {
            for check in trailing {
                if check.fix.is_some() || !matches!(check.status, "warn" | "fail") {
                    break;
                }
                check.fix = Some(msg.to_string());
            }
        }
    }

    /// Attach a `Fixed:` note to the most recent check.
    pub fn attach_fixed(&mut self, msg: &str) {
        if let Some(last) = self.checks.last_mut() {
            last.fixed = Some(msg.to_string());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_report_omits_empty_indeterminate() {
        let report = CheckReport {
            mode: "worktree",
            clean: true,
            findings: &[],
            warnings: &[],
            indeterminate: &[],
            proxy_session: false,
            excused: &[],
            session_warning: None,
        };
        assert_eq!(
            serde_json::to_value(&report).unwrap(),
            serde_json::json!({"mode":"worktree","clean":true,"findings":[],"warnings":[]})
        );
    }

    fn env(pairs: &[(&str, &str)]) -> Vec<(std::ffi::OsString, std::ffi::OsString)> {
        pairs
            .iter()
            .map(|(key, raw)| ((*key).into(), (*raw).into()))
            .collect()
    }

    fn names(scan: &RuntimeEnvScan) -> Vec<&str> {
        scan.findings
            .iter()
            .map(|finding| finding.name.as_deref().unwrap_or_default())
            .collect()
    }

    fn alive(_: u16, _: &str) -> bool {
        true
    }

    fn dead(_: u16, _: &str) -> bool {
        false
    }

    #[test]
    fn runtime_scan_finds_a_phantom_token_under_any_name() {
        let placeholder = crate::token::PhantomToken::generate();
        let scan = scan_runtime_env(
            env(&[
                ("BILLING_SERVICE_KEY", placeholder.as_str()),
                ("OPENAI_API_KEY", placeholder.as_str()),
                ("NODE_ENV", "development"),
            ]),
            |_, _| panic!("no session variables, so no probe"),
        );
        assert_eq!(names(&scan), ["BILLING_SERVICE_KEY", "OPENAI_API_KEY"]);
        assert!(!scan.proxy_session && !scan.stale_session);
        assert!(scan.excused.is_empty());
        assert!(scan.findings.iter().all(|f| f.kind == "runtime_env"));
    }

    #[test]
    fn runtime_scan_excuses_only_what_a_live_session_owns() {
        let placeholder = crate::token::PhantomToken::generate();
        let mut seen = None;
        let scan = scan_runtime_env(
            env(&[
                ("OPENAI_API_KEY", placeholder.as_str()),
                ("BILLING_SERVICE_KEY", placeholder.as_str()),
                ("PHANTOM_PROXY_PORT", "43123"),
                ("PHANTOM_PROXY_TOKEN", "session"),
                ("PHANTOM_SESSION_KEYS", "OPENAI_API_KEY, STRIPE_SECRET_KEY"),
            ]),
            |port, header| {
                seen = Some((port, header.len()));
                true
            },
        );
        assert_eq!(seen, Some((43123, "session".len())));
        assert!(scan.proxy_session && !scan.stale_session);
        assert_eq!(scan.excused, ["OPENAI_API_KEY"]);
        assert_eq!(names(&scan), ["BILLING_SERVICE_KEY"]);
    }

    #[test]
    fn runtime_scan_with_a_dead_proxy_reports_findings_and_a_stale_session() {
        let placeholder = crate::token::PhantomToken::generate();
        let scan = scan_runtime_env(
            env(&[
                ("OPENAI_API_KEY", placeholder.as_str()),
                ("PHANTOM_PROXY_PORT", "43123"),
                ("PHANTOM_PROXY_TOKEN", "session"),
                ("PHANTOM_SESSION_KEYS", "OPENAI_API_KEY"),
            ]),
            dead,
        );
        assert!(!scan.proxy_session && scan.stale_session);
        assert!(scan.excused.is_empty());
        assert_eq!(names(&scan), ["OPENAI_API_KEY"]);
        assert_eq!(scan.session_warning(), Some(STALE_SESSION_WARNING));
    }

    #[test]
    fn runtime_scan_needs_both_session_variables() {
        let placeholder = crate::token::PhantomToken::generate();
        for partial in [
            &[("PHANTOM_PROXY_PORT", "43123")][..],
            &[("PHANTOM_PROXY_PORT", "43123"), ("PHANTOM_PROXY_TOKEN", "")][..],
        ] {
            let mut pairs = vec![
                ("OPENAI_API_KEY", placeholder.as_str()),
                ("PHANTOM_SESSION_KEYS", "OPENAI_API_KEY"),
            ];
            pairs.extend_from_slice(partial);
            let scan = scan_runtime_env(env(&pairs), alive);
            assert!(!scan.proxy_session && !scan.stale_session);
            assert_eq!(names(&scan), ["OPENAI_API_KEY"]);
        }
    }

    #[test]
    fn runtime_scan_treats_an_unusable_port_as_stale() {
        let placeholder = crate::token::PhantomToken::generate();
        let scan = scan_runtime_env(
            env(&[
                ("OPENAI_API_KEY", placeholder.as_str()),
                ("PHANTOM_PROXY_PORT", "not-a-port"),
                ("PHANTOM_PROXY_TOKEN", "session"),
                ("PHANTOM_SESSION_KEYS", "OPENAI_API_KEY"),
            ]),
            |_, _| panic!("an unusable port is never probed"),
        );
        assert!(scan.stale_session);
        assert_eq!(names(&scan), ["OPENAI_API_KEY"]);
    }

    /// A one-shot loopback server that answers 200 with `body` only for
    /// `expected`.
    fn health_server(expected: &'static str, body: &'static str) -> u16 {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut request = Vec::new();
                let mut chunk = [0u8; 512];
                while !request.windows(4).any(|w| w == b"\r\n\r\n") {
                    match stream.read(&mut chunk) {
                        Ok(0) | Err(_) => break,
                        Ok(read) => request.extend_from_slice(&chunk[..read]),
                    }
                }
                let text = String::from_utf8_lossy(&request);
                let ok = text.starts_with("GET /phantom/health ")
                    && text.contains(&format!("x-phantom-proxy-token: {expected}\r\n"));
                let reply = if ok { body } else { "" };
                let status = if ok { "200 OK" } else { "401 Unauthorized" };
                let _ = stream.write_all(
                    format!(
                        "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{reply}",
                        reply.len()
                    )
                    .as_bytes(),
                );
            }
        });
        port
    }

    const PROXY_HEALTH_BODY: &str = r#"{"status":"ok","service":"phantom-proxy"}"#;

    #[test]
    fn proxy_answers_requires_a_200_for_this_header() {
        let proxy = |expected| health_server(expected, PROXY_HEALTH_BODY);
        assert!(proxy_answers(proxy("session-a"), "session-a"));
        assert!(!proxy_answers(proxy("session-a"), "session-b"));
        assert!(!proxy_answers(proxy("session-a"), "bad\r\nheader"));
    }

    #[test]
    fn proxy_answers_requires_the_body_to_name_the_proxy() {
        let other = health_server("session-a", r#"{"status":"ok","service":"something-else"}"#);
        assert!(!proxy_answers(other, "session-a"));
        let empty = health_server("session-a", "");
        assert!(!proxy_answers(empty, "session-a"));
    }

    #[test]
    fn printable_name_escapes_control_characters() {
        assert_eq!(printable_name("OPENAI_API_KEY"), "OPENAI_API_KEY");
        assert_eq!(printable_name("BAD\nKEY"), "BAD\\nKEY");
        assert_eq!(printable_name("ESC\u{1b}[2J"), "ESC\\u{1b}[2J");
        assert!(!printable_name("A\rB\tC\u{7f}")
            .chars()
            .any(char::is_control));
    }

    #[test]
    fn proxy_answers_is_false_when_nothing_listens() {
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        assert!(!proxy_answers(port, "session"));
    }

    #[test]
    fn fix_hint_covers_trailing_findings_only() {
        let mut report = DoctorReport::default();
        report.push("pass", "a");
        report.push("warn", "b");
        report.push("warn", "c");
        report.attach_fix("do it");
        report.attach_fixed("done");
        assert_eq!(report.checks[0].fix, None);
        assert_eq!(report.checks[1].fix.as_deref(), Some("do it"));
        assert_eq!(report.checks[2].fix.as_deref(), Some("do it"));
        assert_eq!(report.checks[2].fixed.as_deref(), Some("done"));
    }
}
