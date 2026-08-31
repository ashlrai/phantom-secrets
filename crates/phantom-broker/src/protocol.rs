use crate::lifecycle::RequestState;
use phantom_authority::{
    ActionId, ActionIntentV1, ExpectedAuthority, GrantId, InstallationId, LeaseId, SessionId,
    Sha256Digest,
};
use serde::{Deserialize, Serialize};

pub const BROKER_PROTOCOL_VERSION: u16 = 1;

/// Agent-safe, metadata-only broker envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrokerEnvelopeV1 {
    protocol_version: u16,
    message: BrokerMessageV1,
}

impl BrokerEnvelopeV1 {
    pub(crate) fn new(message: BrokerMessageV1) -> Self {
        Self {
            protocol_version: BROKER_PROTOCOL_VERSION,
            message,
        }
    }

    pub fn message(&self) -> &BrokerMessageV1 {
        &self.message
    }
}

/// Opaque envelope that has passed every protocol invariant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedBrokerEnvelope(BrokerEnvelopeV1);

impl ValidatedBrokerEnvelope {
    pub fn try_new(message: BrokerMessageV1) -> Result<Self, ProtocolValidationError> {
        Self::try_from(BrokerEnvelopeV1::new(message))
    }

    pub(crate) fn as_inner(&self) -> &BrokerEnvelopeV1 {
        &self.0
    }
    pub fn message(&self) -> &BrokerMessageV1 {
        self.0.message()
    }
}

impl TryFrom<BrokerEnvelopeV1> for ValidatedBrokerEnvelope {
    type Error = ProtocolValidationError;

    fn try_from(envelope: BrokerEnvelopeV1) -> Result<Self, Self::Error> {
        envelope.validate()?;
        Ok(Self(envelope))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", content = "payload", rename_all = "SCREAMING_SNAKE_CASE")]
#[serde(deny_unknown_fields)]
pub enum BrokerMessageV1 {
    Hello(HelloV1),
    Challenge(ChallengeV1),
    AuthorityRequest(Box<AuthorityRequestV1>),
    GrantEnvelope(GrantEnvelopeMetadataV1),
    LeaseReady(LeaseReadyV1),
    Receipt(ReceiptV1),
    Revoke(RevokeV1),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HelloV1 {
    pub installation_id: InstallationId,
    pub broker_epoch_sha256: Sha256Digest,
    pub executable_sha256: Sha256Digest,
    pub supported_versions: Vec<u16>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChallengeV1 {
    /// Digest-only metadata. An eventual authenticated challenge belongs to a
    /// private wire handshake, not an agent-facing response.
    pub challenge_sha256: Sha256Digest,
    pub issuer_installation_id: InstallationId,
    pub expires_at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityRequestV1 {
    pub intent: ActionIntentV1,
    pub expected: ExpectedAuthority,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GrantEnvelopeMetadataV1 {
    pub grant_id: GrantId,
    pub action_id: ActionId,
    pub issuer_key_id_sha256: Sha256Digest,
    pub nonce_sha256: Sha256Digest,
    pub signature_sha256: Sha256Digest,
    pub expires_at: u64,
    pub authority_generation: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LeaseReadyV1 {
    pub lease_id: LeaseId,
    pub grant_id: GrantId,
    pub action_id: ActionId,
    pub authority_sha256: Sha256Digest,
    pub constraints_sha256: Sha256Digest,
    pub expires_at: u64,
    pub remaining_uses: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptOutcome {
    Completed,
    Failed,
    Denied,
    Expired,
    Cancelled,
    RevokedBeforeSend,
    RevocationRacedAfterSend,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiptV1 {
    /// Digest of the durable execution record, not of this envelope.
    pub execution_record_sha256: Sha256Digest,
    pub action_id: ActionId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lease_id: Option<LeaseId>,
    pub terminal_state: RequestState,
    pub outcome: ReceiptOutcome,
    pub started_at: u64,
    pub finished_at: u64,
    pub upstream_opened: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "id", rename_all = "snake_case")]
#[serde(deny_unknown_fields)]
pub enum RevocationTarget {
    Grant(GrantId),
    Lease(LeaseId),
    Session(SessionId),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RevocationReason {
    Operator,
    PolicyChanged,
    SessionEnded,
    GrantExpired,
    SuspectedCompromise,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevokeV1 {
    pub target: RevocationTarget,
    pub authority_generation: u64,
    pub reason_code: RevocationReason,
    pub revoked_at: u64,
}

impl BrokerEnvelopeV1 {
    /// Validate cross-field invariants before an envelope crosses a broker
    /// boundary. Serde shape validation alone is deliberately insufficient.
    pub fn validate(&self) -> Result<(), ProtocolValidationError> {
        if self.protocol_version != BROKER_PROTOCOL_VERSION {
            return Err(ProtocolValidationError::UnsupportedVersion(
                self.protocol_version,
            ));
        }
        self.message.validate()
    }
}

impl BrokerMessageV1 {
    pub fn validate(&self) -> Result<(), ProtocolValidationError> {
        match self {
            Self::Hello(message) => {
                if message.supported_versions.is_empty()
                    || !message
                        .supported_versions
                        .contains(&BROKER_PROTOCOL_VERSION)
                {
                    return Err(ProtocolValidationError::InvalidSupportedVersions);
                }
            }
            Self::Challenge(message) => {
                if message.expires_at == 0 {
                    return Err(ProtocolValidationError::InvalidExpiry);
                }
            }
            Self::AuthorityRequest(message) => {
                message.intent.validate()?;
                message.expected.validate()?;
                if message.intent.workspace_id != message.expected.workspace_id
                    || message.intent.workspace_manifest_sha256
                        != message.expected.workspace_manifest_sha256
                    || message.intent.constraints.environment != message.expected.environment
                {
                    return Err(ProtocolValidationError::AuthorityBindingMismatch);
                }
            }
            Self::GrantEnvelope(message) => {
                if message.expires_at == 0 || message.authority_generation == 0 {
                    return Err(ProtocolValidationError::InvalidExpiryOrGeneration);
                }
            }
            Self::LeaseReady(message) => {
                if message.remaining_uses == 0 || message.expires_at == 0 {
                    return Err(ProtocolValidationError::InvalidRemainingUses);
                }
            }
            Self::Receipt(message) => message.validate()?,
            Self::Revoke(message) => {
                if message.authority_generation == 0 || message.revoked_at == 0 {
                    return Err(ProtocolValidationError::InvalidRevocation);
                }
            }
        }
        Ok(())
    }
}

impl ReceiptV1 {
    fn validate(&self) -> Result<(), ProtocolValidationError> {
        if self.started_at > self.finished_at {
            return Err(ProtocolValidationError::InvalidTimestampOrder);
        }
        let expected_state = match self.outcome {
            ReceiptOutcome::Completed => RequestState::Completed,
            ReceiptOutcome::Failed => RequestState::Failed,
            ReceiptOutcome::Denied => RequestState::Denied,
            ReceiptOutcome::Expired => RequestState::Expired,
            ReceiptOutcome::Cancelled => RequestState::Cancelled,
            ReceiptOutcome::RevokedBeforeSend | ReceiptOutcome::RevocationRacedAfterSend => {
                RequestState::Revoked
            }
        };
        if self.terminal_state != expected_state || !self.terminal_state.is_terminal() {
            return Err(ProtocolValidationError::InconsistentReceipt);
        }
        if matches!(
            self.outcome,
            ReceiptOutcome::Denied
                | ReceiptOutcome::Expired
                | ReceiptOutcome::Cancelled
                | ReceiptOutcome::RevokedBeforeSend
        ) && self.upstream_opened
        {
            return Err(ProtocolValidationError::InconsistentReceipt);
        }
        match self.outcome {
            ReceiptOutcome::Completed | ReceiptOutcome::RevocationRacedAfterSend
                if self.lease_id.is_none() || !self.upstream_opened =>
            {
                return Err(ProtocolValidationError::InconsistentReceipt);
            }
            ReceiptOutcome::Denied | ReceiptOutcome::Cancelled if self.lease_id.is_some() => {
                return Err(ProtocolValidationError::InconsistentReceipt);
            }
            _ => {}
        }
        Ok(())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ProtocolValidationError {
    #[error("unsupported broker protocol version {0}")]
    UnsupportedVersion(u16),
    #[error("hello does not advertise the active broker protocol")]
    InvalidSupportedVersions,
    #[error("broker message has an invalid expiry")]
    InvalidExpiry,
    #[error("broker message has an invalid expiry or authority generation")]
    InvalidExpiryOrGeneration,
    #[error("authority request fields do not bind to the same workspace and environment")]
    AuthorityBindingMismatch,
    #[error("lease has an invalid remaining-use count")]
    InvalidRemainingUses,
    #[error("receipt timestamps are inverted")]
    InvalidTimestampOrder,
    #[error("receipt state and outcome are inconsistent")]
    InconsistentReceipt,
    #[error("revocation metadata is invalid")]
    InvalidRevocation,
    #[error(transparent)]
    Authority(#[from] phantom_authority::SchemaError),
}

// These types reserve the private transport shape. They are intentionally not
// exported and never appear in BrokerMessageV1 or any agent-facing response.
// There is no decoder or verifier for them in this wave.
#[allow(dead_code)]
mod private_wire {
    use super::GrantEnvelopeMetadataV1;
    use serde::{Deserialize, Serialize};

    #[derive(Serialize, Deserialize)]
    #[serde(transparent)]
    pub(super) struct CredentialSlotLocator(String);

    #[derive(Serialize, Deserialize)]
    #[serde(transparent)]
    pub(super) struct PrivateSignature(Vec<u8>);

    #[derive(Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub(super) struct PrivateGrantEnvelopeWire {
        pub metadata: GrantEnvelopeMetadataV1,
        pub credential_slots: Vec<CredentialSlotLocator>,
        pub signature: PrivateSignature,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_grant_metadata_has_no_locator_or_signature_bytes() {
        let id = "01".repeat(16);
        let digest = "ab".repeat(32);
        let message = BrokerMessageV1::GrantEnvelope(GrantEnvelopeMetadataV1 {
            grant_id: format!("grt_{id}").parse().unwrap(),
            action_id: format!("act_{id}").parse().unwrap(),
            issuer_key_id_sha256: digest.parse().unwrap(),
            nonce_sha256: "cd".repeat(32).parse().unwrap(),
            signature_sha256: "ef".repeat(32).parse().unwrap(),
            expires_at: 2,
            authority_generation: 1,
        });
        let json = serde_json::to_string(&message).unwrap();
        assert!(!json.contains("phm:PRIVATE_LOCATOR_SENTINEL"));
        assert!(!json.contains("signature_bytes"));
        assert!(json.contains("signature_sha256"));
    }

    #[test]
    fn message_payloads_are_closed() {
        let id = "01".repeat(16);
        let digest = "ab".repeat(32);
        let raw = format!(
            r#"{{"protocol_version":1,"message":{{"type":"HELLO","payload":{{"installation_id":"ins_{id}","broker_epoch_sha256":"{digest}","executable_sha256":"{digest}","supported_versions":[1],"bearer":"MUST_REJECT"}}}}}}"#
        );
        assert!(serde_json::from_str::<BrokerEnvelopeV1>(&raw).is_err());
    }

    #[test]
    fn revocation_reason_is_closed_and_cannot_carry_values() {
        let id = "01".repeat(16);
        let raw = format!(
            r#"{{"protocol_version":1,"message":{{"type":"REVOKE","payload":{{"target":{{"kind":"lease","id":"lea_{id}"}},"authority_generation":1,"reason_code":"phm:PRIVATE_SENTINEL","revoked_at":1}}}}}}"#
        );
        assert!(serde_json::from_str::<BrokerEnvelopeV1>(&raw).is_err());
    }

    #[test]
    fn contradictory_receipt_is_rejected_by_validation() {
        let id = "01".repeat(16);
        let receipt = BrokerEnvelopeV1::new(BrokerMessageV1::Receipt(ReceiptV1 {
            execution_record_sha256: "ab".repeat(32).parse().unwrap(),
            action_id: format!("act_{id}").parse().unwrap(),
            lease_id: None,
            terminal_state: RequestState::Completed,
            outcome: ReceiptOutcome::Denied,
            started_at: 2,
            finished_at: 1,
            upstream_opened: true,
        }));
        assert!(receipt.validate().is_err());
    }

    #[test]
    fn successful_and_raced_receipts_require_lease_and_opened_upstream() {
        let id = "01".repeat(16);
        for outcome in [
            ReceiptOutcome::Completed,
            ReceiptOutcome::RevocationRacedAfterSend,
        ] {
            let receipt = BrokerEnvelopeV1::new(BrokerMessageV1::Receipt(ReceiptV1 {
                execution_record_sha256: "ab".repeat(32).parse().unwrap(),
                action_id: format!("act_{id}").parse().unwrap(),
                lease_id: None,
                terminal_state: if outcome == ReceiptOutcome::Completed {
                    RequestState::Completed
                } else {
                    RequestState::Revoked
                },
                outcome,
                started_at: 1,
                finished_at: 2,
                upstream_opened: false,
            }));
            assert!(matches!(
                receipt.validate(),
                Err(ProtocolValidationError::InconsistentReceipt)
            ));
        }
    }
}
