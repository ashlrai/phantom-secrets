//! Report-only LiteLLM checks for `phantom doctor`.
//!
//! When the project holds a LiteLLM proxy config whose `api_base` points at a
//! loopback address (Phantom's proxy) or that carries a `phm_` placeholder,
//! doctor warns about three risky settings:
//!
//! - a pinned LiteLLM version below 1.83.0 (the first release after the
//!   PyPI supply-chain compromise, GHSA-5mg7-485q-xm76),
//! - `allow_client_side_credentials: true` (lets callers override the
//!   upstream and credentials, GHSA-3cv6-jpf6-8222 workaround is `false`),
//! - an explicit non-loopback bind (`--host`, `0.0.0.0`, or a published
//!   Docker port without a loopback host IP).
//!
//! Files are scanned as text and never executed, and nothing is changed.

use std::path::{Path, PathBuf};

/// Minimum LiteLLM version doctor accepts.
pub const MIN_VERSION: (u32, u32, u32) = (1, 83, 0);

const CONFIG_NAMES: &[&str] = &[
    "litellm_config.yaml",
    "litellm_config.yml",
    "litellm.yaml",
    "litellm.yml",
    "config.yaml",
    "config.yml",
];

const PIN_FILES: &[&str] = &[
    "requirements.txt",
    "requirements-litellm.txt",
    "pyproject.toml",
    "Dockerfile",
    "docker-compose.yml",
    "docker-compose.yaml",
    "compose.yml",
    "compose.yaml",
];

const BIND_FILES: &[&str] = &[
    "docker-compose.yml",
    "docker-compose.yaml",
    "compose.yml",
    "compose.yaml",
    "Dockerfile",
    "Procfile",
    "start-litellm.sh",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Finding {
    /// A LiteLLM config routes through Phantom (file name).
    Detected(String),
    /// Pinned version below the minimum (file, version).
    OldVersion(String, String),
    /// No version pin found in the known files.
    VersionUnknown,
    /// `allow_client_side_credentials: true` (config file).
    ClientSideCredentials(String),
    /// Explicit non-loopback bind (file, the offending text).
    PublicBind(String, String),
}

impl Finding {
    pub fn is_warning(&self) -> bool {
        !matches!(self, Finding::Detected(_) | Finding::VersionUnknown)
    }

    pub fn message(&self) -> String {
        match self {
            Finding::Detected(f) => format!("LiteLLM config {f} routes through Phantom"),
            Finding::OldVersion(f, v) => format!(
                "LiteLLM {v} pinned in {f} is below 1.83.0 (first release after the PyPI compromise)"
            ),
            Finding::VersionUnknown => {
                "LiteLLM version not pinned in a known file; pin 1.83.0 or newer".to_string()
            }
            Finding::ClientSideCredentials(f) => format!(
                "{f} sets allow_client_side_credentials: true; callers can redirect the upstream"
            ),
            Finding::PublicBind(f, what) => {
                format!("LiteLLM listens beyond loopback in {f} ({what})")
            }
        }
    }

    pub fn fix(&self) -> Option<&'static str> {
        match self {
            Finding::OldVersion(..) => Some("Pin litellm 1.83.0 or newer (hash-pinned or the signed image)"),
            Finding::ClientSideCredentials(_) => Some("Set general_settings.allow_client_side_credentials: false"),
            Finding::PublicBind(..) => Some("Bind LiteLLM to 127.0.0.1 (--host 127.0.0.1, or \"127.0.0.1:4000:4000\" in Docker)"),
            _ => None,
        }
    }
}

fn read(dir: &Path, name: &str) -> Option<String> {
    let path: PathBuf = dir.join(name);
    let meta = std::fs::symlink_metadata(&path).ok()?;
    if !meta.is_file() || meta.len() > 1024 * 1024 {
        return None;
    }
    std::fs::read_to_string(path).ok()
}

fn strip_comment(line: &str) -> &str {
    match line.find(" #") {
        Some(i) => &line[..i],
        None if line.trim_start().starts_with('#') => "",
        None => line,
    }
}

fn unquote(v: &str) -> &str {
    v.trim().trim_matches(|c| c == '"' || c == '\'')
}

fn is_loopback_host(host: &str) -> bool {
    let h = host.trim_matches(|c| c == '[' || c == ']');
    h == "localhost" || h == "::1" || h.starts_with("127.")
}

fn url_host(url: &str) -> Option<&str> {
    let rest = url.split("://").nth(1)?;
    let authority = rest.split('/').next()?;
    let authority = authority.rsplit('@').next()?;
    if let Some(end) = authority.strip_prefix('[').and_then(|a| a.find(']')) {
        return Some(&authority[..end + 2]);
    }
    Some(authority.split(':').next().unwrap_or(authority))
}

fn is_litellm_config(text: &str) -> bool {
    text.lines()
        .any(|l| strip_comment(l).trim_start().starts_with("model_list:"))
        && text.contains("litellm_params")
}

fn routes_through_phantom(text: &str) -> bool {
    text.lines().any(|l| {
        let l = strip_comment(l).trim();
        if l.contains("phm_") {
            return true;
        }
        l.strip_prefix("api_base:")
            .and_then(|v| url_host(unquote(v)))
            .is_some_and(is_loopback_host)
    })
}

fn parse_version(v: &str) -> Option<(u32, u32, u32)> {
    let v = v.trim().trim_start_matches('v');
    let mut it = v.split(|c: char| !c.is_ascii_digit());
    let a = it.next()?.parse().ok()?;
    let b = it.next()?.parse().ok()?;
    let c = it.next().and_then(|c| c.parse().ok()).unwrap_or(0);
    Some((a, b, c))
}

/// Exact LiteLLM pins found in a file: `litellm==X`, `litellm[proxy]==X`,
/// `"litellm==X"` in pyproject, and `berriai/litellm...:...vX` image tags.
fn version_pins(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    for raw in text.lines() {
        let l = strip_comment(raw);
        let lower = l.to_ascii_lowercase();
        if let Some(i) = lower.find("litellm") {
            let after = &lower[i + "litellm".len()..];
            let after = after.strip_prefix("[proxy]").unwrap_or(after).trim_start();
            if let Some(v) = after.strip_prefix("==") {
                let v: String = v
                    .trim()
                    .chars()
                    .take_while(|c| c.is_ascii_digit() || *c == '.')
                    .collect();
                if !v.is_empty() {
                    out.push(v);
                }
            }
        }
        if let Some(i) = lower.find("berriai/litellm") {
            let image = lower[i..].split_whitespace().next().unwrap_or("");
            if let Some(tag) = image.rsplit_once(':').map(|(_, t)| t) {
                if let Some(j) = tag.find('v') {
                    let v: String = tag[j + 1..]
                        .chars()
                        .take_while(|c| c.is_ascii_digit() || *c == '.')
                        .collect();
                    if parse_version(&v).is_some() {
                        out.push(v);
                    }
                }
            }
        }
    }
    out
}

/// Explicit non-loopback binds in a launch or compose file.
fn public_binds(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut in_ports = false;
    for raw in text.lines() {
        let l = strip_comment(raw);
        let t = l.trim();
        let words: Vec<&str> = t
            .split(|c: char| {
                c.is_whitespace() || c == ',' || c == '[' || c == ']' || c == '"' || c == '\''
            })
            .filter(|w| !w.is_empty())
            .collect();
        for (i, w) in words.iter().enumerate() {
            let host = if let Some(h) = w.strip_prefix("--host=") {
                Some(h)
            } else if *w == "--host" {
                words.get(i + 1).copied()
            } else {
                None
            };
            if let Some(h) = host {
                if !is_loopback_host(h) {
                    out.push(format!("--host {h}"));
                }
            }
        }
        if t.starts_with("ports:") {
            in_ports = true;
            continue;
        }
        if in_ports {
            if let Some(item) = t.strip_prefix('-') {
                let spec = unquote(item);
                let parts: Vec<&str> = spec.split(':').collect();
                // "4000:4000" or "4000" publish on every interface;
                // "0.0.0.0:4000:4000" is explicit.
                let host_ip = if parts.len() >= 3 {
                    Some(parts[0])
                } else {
                    None
                };
                match host_ip {
                    Some(ip) if is_loopback_host(ip) => {}
                    Some(ip) => out.push(format!("port {spec} on {ip}")),
                    None => out.push(format!("port {spec} on all interfaces")),
                }
                continue;
            }
            if !t.is_empty() {
                in_ports = false;
            }
        }
    }
    out
}

/// All LiteLLM findings for `dir`. Empty when no LiteLLM config routes
/// through Phantom.
pub fn findings(dir: &Path) -> Vec<Finding> {
    let mut out = Vec::new();
    let configs: Vec<(&str, String)> = CONFIG_NAMES
        .iter()
        .filter_map(|n| read(dir, n).map(|t| (*n, t)))
        .filter(|(_, t)| is_litellm_config(t) && routes_through_phantom(t))
        .collect();
    if configs.is_empty() {
        return out;
    }
    for (name, text) in &configs {
        out.push(Finding::Detected((*name).to_string()));
        let client_side = text.lines().any(|l| {
            let l = strip_comment(l).trim();
            l.strip_prefix("allow_client_side_credentials:")
                .is_some_and(|v| unquote(v).eq_ignore_ascii_case("true"))
        });
        if client_side {
            out.push(Finding::ClientSideCredentials((*name).to_string()));
        }
    }
    let mut pinned = false;
    for name in PIN_FILES {
        if let Some(text) = read(dir, name) {
            for v in version_pins(&text) {
                pinned = true;
                if parse_version(&v).is_some_and(|p| p < MIN_VERSION) {
                    out.push(Finding::OldVersion((*name).to_string(), v));
                }
            }
        }
    }
    if !pinned {
        out.push(Finding::VersionUnknown);
    }
    for name in BIND_FILES {
        if let Some(text) = read(dir, name) {
            if !text.to_ascii_lowercase().contains("litellm") {
                continue;
            }
            for what in public_binds(&text) {
                out.push(Finding::PublicBind((*name).to_string(), what));
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const CFG: &str = "model_list:\n  - model_name: gpt\n    litellm_params:\n      model: openai/gpt-4o\n      api_base: http://127.0.0.1:8765/openai/v1\n      api_key: os.environ/OPENAI_API_KEY\n";

    fn dir_with(files: &[(&str, &str)]) -> tempfile::TempDir {
        let d = tempfile::tempdir().unwrap();
        for (n, t) in files {
            std::fs::write(d.path().join(n), t).unwrap();
        }
        d
    }

    #[test]
    fn no_config_or_non_phantom_config_reports_nothing() {
        assert!(findings(dir_with(&[]).path()).is_empty());
        let remote = CFG.replace("http://127.0.0.1:8765", "https://api.openai.com");
        assert!(findings(dir_with(&[("config.yaml", &remote)]).path()).is_empty());
        // A non-LiteLLM config.yaml is ignored.
        assert!(
            findings(dir_with(&[("config.yaml", "api_base: http://127.0.0.1\n")]).path())
                .is_empty()
        );
    }

    #[test]
    fn safe_setup_has_no_warnings() {
        let d = dir_with(&[
            ("litellm_config.yaml", &format!("{CFG}general_settings:\n  allow_client_side_credentials: false\n")),
            ("requirements.txt", "litellm[proxy]==1.83.0\n"),
            ("docker-compose.yml", "services:\n  litellm:\n    image: ghcr.io/berriai/litellm:main-v1.103.1\n    ports:\n      - \"127.0.0.1:4000:4000\"\n    command: [\"--config\", \"/app/config.yaml\", \"--host\", \"127.0.0.1\"]\n"),
        ]);
        let f = findings(d.path());
        assert_eq!(
            f,
            vec![Finding::Detected("litellm_config.yaml".into())],
            "{f:?}"
        );
    }

    #[test]
    fn warns_on_old_version_client_side_credentials_and_public_bind() {
        let d = dir_with(&[
            ("config.yaml", &format!("{CFG}general_settings:\n  allow_client_side_credentials: true # risky\n")),
            ("requirements.txt", "litellm==1.82.6\n"),
            ("docker-compose.yml", "services:\n  litellm:\n    image: ghcr.io/berriai/litellm:main-v1.82.8\n    ports:\n      - \"4000:4000\"\n      - \"0.0.0.0:4001:4001\"\n    command: --config /app/config.yaml --host 0.0.0.0\n"),
        ]);
        let f = findings(d.path());
        assert!(
            f.contains(&Finding::ClientSideCredentials("config.yaml".into())),
            "{f:?}"
        );
        assert!(
            f.contains(&Finding::OldVersion(
                "requirements.txt".into(),
                "1.82.6".into()
            )),
            "{f:?}"
        );
        assert!(
            f.contains(&Finding::OldVersion(
                "docker-compose.yml".into(),
                "1.82.8".into()
            )),
            "{f:?}"
        );
        assert!(
            f.contains(&Finding::PublicBind(
                "docker-compose.yml".into(),
                "--host 0.0.0.0".into()
            )),
            "{f:?}"
        );
        assert!(
            f.contains(&Finding::PublicBind(
                "docker-compose.yml".into(),
                "port 4000:4000 on all interfaces".into()
            )),
            "{f:?}"
        );
        assert!(
            f.contains(&Finding::PublicBind(
                "docker-compose.yml".into(),
                "port 0.0.0.0:4001:4001 on 0.0.0.0".into()
            )),
            "{f:?}"
        );
        assert!(!f.contains(&Finding::VersionUnknown));
        assert_eq!(f.iter().filter(|x| x.is_warning()).count(), 6, "{f:?}");
    }

    #[test]
    fn placeholder_key_counts_as_routing_through_phantom() {
        let cfg = CFG
            .replace("http://127.0.0.1:8765", "https://api.openai.com")
            .replace("os.environ/OPENAI_API_KEY", "phm_fake0000000000000000");
        let f = findings(dir_with(&[("litellm.yaml", &cfg)]).path());
        assert_eq!(
            f,
            vec![
                Finding::Detected("litellm.yaml".into()),
                Finding::VersionUnknown
            ]
        );
    }

    #[test]
    fn version_parsing_and_boundaries() {
        assert!(parse_version("1.82.99").unwrap() < MIN_VERSION);
        assert!(parse_version("1.83.0").unwrap() >= MIN_VERSION);
        assert!(parse_version("v1.103.5").unwrap() >= MIN_VERSION);
        assert_eq!(version_pins("litellm>=1.80\n"), Vec::<String>::new());
        assert!(
            is_loopback_host("[::1]")
                && is_loopback_host("127.0.0.2")
                && !is_loopback_host("10.0.0.1")
        );
    }
}
