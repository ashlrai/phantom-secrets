use thiserror::Error;

#[derive(Error, Debug)]
pub enum PhantomError {
    #[error("Config file not found: {0}")]
    ConfigNotFound(String),

    #[error("Failed to parse config: {0}")]
    ConfigParseError(String),

    #[error("Failed to parse .env file: {0}")]
    DotenvParseError(String),

    #[error(".env file not found: {0}")]
    DotenvNotFound(String),

    #[error("Secret not found: {0}")]
    SecretNotFound(String),

    #[error("Secret already exists: {0}")]
    SecretAlreadyExists(String),

    #[error("Vault error: {0}")]
    VaultError(String),

    #[error("Proxy error: {0}")]
    ProxyError(String),

    #[error("Authentication required. Run `phantom login` first.")]
    AuthRequired,

    #[error("Authentication failed: {0}")]
    AuthError(String),

    #[error("Cloud API error ({status}): {message}")]
    CloudError { status: u16, message: String },

    #[error("Pro plan required. Upgrade at https://phm.dev/pricing")]
    PlanRequired,

    /// Phantom Cloud refused a team vault push because the team has a member
    /// with a hybrid post-quantum key and this client cannot wrap for it. The
    /// text is built here, not echoed from the server; only a validated
    /// version string is taken from the response.
    #[error("{}", client_upgrade_message(.min_client_version.as_deref()))]
    ClientUpgradeRequired { min_client_version: Option<String> },

    #[error("Version conflict: local version {local} != remote version {remote}. Run `phantom cloud pull` first.")]
    VersionConflict { local: u64, remote: u64 },

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// Catch-all for high-level flows that need to surface a contextual
    /// message but don't fit any of the typed variants above. Use
    /// sparingly — prefer a typed variant when one exists.
    #[error("{0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, PhantomError>;

/// Upgrade instructions shown when a client is too old for a team.
pub const PHANTOM_UPGRADE_HINT: &str = "Upgrade Phantom: on macOS run `brew upgrade ashlrai/phantom/phantom`; on Linux or Windows download the matching asset from https://github.com/ashlrai/phantom-secrets/releases.";

/// Accept a server-supplied minimum version only if it looks like a version
/// (1 to 32 chars of ASCII letters, digits, `.`, `-`, `+`). Anything else is
/// dropped, so server text never reaches the terminal unchecked.
pub fn sanitize_min_client_version(raw: Option<&str>) -> Option<String> {
    let v = raw?;
    let ok = !v.is_empty()
        && v.len() <= 32
        && v.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'+'));
    ok.then(|| v.to_string())
}

fn client_upgrade_message(min_client_version: Option<&str>) -> String {
    let need = match min_client_version {
        Some(v) => format!("Phantom {v} or later is required to push to this team."),
        None => "No released Phantom version is known to support hybrid team keys yet.".to_string(),
    };
    format!(
        "Team vault push refused (client_upgrade_required): this team has a member with a hybrid post-quantum team key, and this Phantom version ({}) cannot wrap the vault key for that member. Phantom never falls back to classic-only wrapping. {need} {PHANTOM_UPGRADE_HINT}",
        env!("CARGO_PKG_VERSION")
    )
}

impl PhantomError {
    /// A short, value-free class for a Phantom Cloud request failure that is
    /// not an auth rejection, so a network or server fault is not reported as
    /// an expired login. It never includes the error's message text.
    pub fn cloud_failure_class(&self) -> String {
        match self {
            PhantomError::AuthError(_) => "could not reach Phantom Cloud".to_string(),
            PhantomError::CloudError { status: 0, .. } => {
                "could not reach Phantom Cloud: HTTP client unavailable".to_string()
            }
            PhantomError::CloudError { status, .. } if (200..300).contains(status) => {
                format!("unexpected response from Phantom Cloud, HTTP {status}")
            }
            PhantomError::CloudError { status, .. } if *status >= 500 => {
                format!("Phantom Cloud server error, HTTP {status}")
            }
            PhantomError::CloudError { status, .. } => {
                format!("Phantom Cloud refused the request, HTTP {status}")
            }
            PhantomError::ClientUpgradeRequired { .. } => {
                "Phantom Cloud refused the request, HTTP 426: client upgrade required".to_string()
            }
            _ => "Phantom Cloud request failed".to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cloud_failure_class_names_the_failure_without_its_message() {
        let cases = [
            (
                PhantomError::AuthError("connection refused by host".to_string()),
                "could not reach Phantom Cloud",
            ),
            (
                PhantomError::CloudError {
                    status: 0,
                    message: "client build failed".to_string(),
                },
                "could not reach Phantom Cloud: HTTP client unavailable",
            ),
            (
                PhantomError::CloudError {
                    status: 200,
                    message: "response was invalid JSON".to_string(),
                },
                "unexpected response from Phantom Cloud, HTTP 200",
            ),
            (
                PhantomError::CloudError {
                    status: 502,
                    message: "bad gateway".to_string(),
                },
                "Phantom Cloud server error, HTTP 502",
            ),
            (
                PhantomError::CloudError {
                    status: 403,
                    message: "forbidden".to_string(),
                },
                "Phantom Cloud refused the request, HTTP 403",
            ),
            (
                PhantomError::Other("something odd".to_string()),
                "Phantom Cloud request failed",
            ),
        ];
        for (error, expected) in cases {
            assert_eq!(error.cloud_failure_class(), expected);
        }
    }
}
