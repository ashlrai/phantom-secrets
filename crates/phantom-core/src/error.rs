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

impl PhantomError {
    /// The same failure class as [`Self::cloud_failure_class`] without the
    /// HTTP status, as a fixed string. Terminal output uses this so that
    /// nothing it prints is carried over from the failed request.
    pub fn cloud_failure_kind(&self) -> &'static str {
        match self {
            PhantomError::AuthError(_) => "could not reach Phantom Cloud",
            PhantomError::CloudError { status: 0, .. } => {
                "could not reach Phantom Cloud: HTTP client unavailable"
            }
            PhantomError::CloudError { status, .. } if (200..300).contains(status) => {
                "unexpected response from Phantom Cloud"
            }
            PhantomError::CloudError { status, .. } if *status >= 500 => {
                "Phantom Cloud server error"
            }
            PhantomError::CloudError { .. } => "Phantom Cloud refused the request",
            _ => "Phantom Cloud request failed",
        }
    }

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

    #[test]
    fn cloud_failure_kind_matches_the_class_without_the_status() {
        let cases = [
            PhantomError::AuthError("connection refused by host".to_string()),
            PhantomError::CloudError {
                status: 0,
                message: "client build failed".to_string(),
            },
            PhantomError::CloudError {
                status: 200,
                message: "response was invalid JSON".to_string(),
            },
            PhantomError::CloudError {
                status: 502,
                message: "bad gateway".to_string(),
            },
            PhantomError::CloudError {
                status: 403,
                message: "forbidden".to_string(),
            },
            PhantomError::Other("something odd".to_string()),
        ];
        for error in cases {
            let kind = error.cloud_failure_kind();
            assert!(error.cloud_failure_class().starts_with(kind));
            assert!(
                !kind.contains("HTTP 5") && !kind.contains("HTTP 4") && !kind.contains("HTTP 2")
            );
        }
    }
}
