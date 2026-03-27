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

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, PhantomError>;
