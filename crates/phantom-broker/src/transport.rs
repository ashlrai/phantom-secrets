use crate::protocol::ValidatedBrokerEnvelope;
use phantom_authority::Sha256Digest;
use std::time::Duration;

pub const BROKER_IO_TIMEOUT: Duration = Duration::from_secs(2);

pub trait BrokerTransport: Send + Sync {
    fn exchange(
        &self,
        _message: &ValidatedBrokerEnvelope,
    ) -> Result<ValidatedBrokerEnvelope, TransportError>;
}

#[derive(Debug, Clone, Copy, Default)]
pub struct DenyAllTransport;

impl BrokerTransport for DenyAllTransport {
    fn exchange(
        &self,
        _message: &ValidatedBrokerEnvelope,
    ) -> Result<ValidatedBrokerEnvelope, TransportError> {
        Err(TransportError::AuthorityUnavailable)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportKind {
    UnixSocket,
    WindowsNamedPipe,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnixSocketDescriptor {
    endpoint_sha256: Sha256Digest,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowsNamedPipeDescriptor {
    endpoint_sha256: Sha256Digest,
}

impl UnixSocketDescriptor {
    pub fn new(endpoint_sha256: Sha256Digest) -> Self {
        Self { endpoint_sha256 }
    }

    pub fn endpoint_sha256(&self) -> &Sha256Digest {
        &self.endpoint_sha256
    }
}

impl WindowsNamedPipeDescriptor {
    pub fn new(endpoint_sha256: Sha256Digest) -> Self {
        Self { endpoint_sha256 }
    }

    pub fn endpoint_sha256(&self) -> &Sha256Digest {
        &self.endpoint_sha256
    }
}

impl BrokerTransport for UnixSocketDescriptor {
    fn exchange(
        &self,
        _message: &ValidatedBrokerEnvelope,
    ) -> Result<ValidatedBrokerEnvelope, TransportError> {
        Err(TransportError::AuthorityUnavailable)
    }
}

impl BrokerTransport for WindowsNamedPipeDescriptor {
    fn exchange(
        &self,
        _message: &ValidatedBrokerEnvelope,
    ) -> Result<ValidatedBrokerEnvelope, TransportError> {
        Err(TransportError::WindowsAuthorityUnavailable)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TransportError {
    #[error("authority broker transport is unavailable")]
    AuthorityUnavailable,
    #[error("native peer-authenticated Windows named-pipe authority is unavailable")]
    WindowsAuthorityUnavailable,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{BrokerMessageV1, HelloV1};

    fn message() -> ValidatedBrokerEnvelope {
        let id = "01".repeat(16);
        ValidatedBrokerEnvelope::try_new(BrokerMessageV1::Hello(HelloV1 {
            installation_id: format!("ins_{id}").parse().unwrap(),
            broker_epoch_sha256: "ab".repeat(32).parse().unwrap(),
            executable_sha256: "cd".repeat(32).parse().unwrap(),
            supported_versions: vec![1],
        }))
        .unwrap()
    }

    #[test]
    fn transports_have_two_second_budget_and_no_active_fallback() {
        assert_eq!(BROKER_IO_TIMEOUT, Duration::from_secs(2));
        let digest = "ab".repeat(32).parse().unwrap();
        let unix = UnixSocketDescriptor::new(digest);
        assert!(matches!(
            unix.exchange(&message()),
            Err(TransportError::AuthorityUnavailable)
        ));

        let windows = WindowsNamedPipeDescriptor::new("cd".repeat(32).parse().unwrap());
        assert!(matches!(
            windows.exchange(&message()),
            Err(TransportError::WindowsAuthorityUnavailable)
        ));
        assert_eq!(
            DenyAllTransport.exchange(&message()).unwrap_err(),
            TransportError::AuthorityUnavailable
        );
    }
}
