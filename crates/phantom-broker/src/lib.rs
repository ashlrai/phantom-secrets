//! Fail-closed, value-free broker protocol and lifecycle primitives.
//!
//! This crate does not authenticate Locus, verify signatures, open local
//! transports, resolve secrets, inject proxy credentials, or accept MCP
//! bearers. Its production transport is deliberately unavailable.
//! Value-bearing locators and signatures remain private and undecodable; the
//! broker must stay deny-all until an authenticated Locus contract replaces
//! remaining human-readable authority labels with shared opaque identifiers.

mod codec;
mod lease;
mod lifecycle;
mod protocol;
mod replay_storage;
mod replay_store;
#[cfg(test)]
mod test_ledger;
mod transport;

pub use codec::{decode_frame, encode_frame, BrokerCodecError, MAX_BROKER_MESSAGE_BYTES};
pub use lease::{LeaseBinding, LeaseBindingError};
pub use lifecycle::{LifecycleError, RequestLifecycle, RequestState};
pub use protocol::{
    AuthorityRequestV1, BrokerMessageV1, ChallengeV1, GrantEnvelopeMetadataV1, HelloV1,
    LeaseReadyV1, ProtocolValidationError, ReceiptOutcome, ReceiptV1, RevocationReason,
    RevocationTarget, RevokeV1, ValidatedBrokerEnvelope, BROKER_PROTOCOL_VERSION,
};
pub use replay_store::{
    CompletionWitness, DurableReplayStore, ExecutionPermit, ReplayCompletionReservation,
    ReplayReservation, ReplayStoreError, ReplayUseReservation, ReplayUseState, TerminalDisposition,
};
pub use transport::{
    BrokerTransport, DenyAllTransport, TransportError, TransportKind, UnixSocketDescriptor,
    WindowsNamedPipeDescriptor, BROKER_IO_TIMEOUT,
};
