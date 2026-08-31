use crate::constraints::{
    AuthorityConstraints, ByteLimit, ConstraintError, ExactScope, UseCapacity,
};
use crate::ids::{
    ActionId, BindingId, InstallationId, PlaceId, SessionId, Sha256Digest, VaultNamespaceId,
    WorkspaceId,
};
use crate::verbs::{EffectClass, Operation};
use serde::{Deserialize, Serialize};

pub const AUTHORITY_SCHEMA_VERSION: u32 = 1;

/// Untrusted description of one requested action.
///
/// Deserialization never confers authority. A production verifier must bind
/// every field to an independently verified Locus session and policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionIntentV1 {
    pub schema_version: u32,
    pub action_id: ActionId,
    pub workspace_id: WorkspaceId,
    pub workspace_manifest_sha256: Sha256Digest,
    pub operation: Operation,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    pub canonical_args_sha256: Sha256Digest,
    pub requested_at: u64,
    pub constraints: AuthorityConstraints,
}

impl ActionIntentV1 {
    pub fn validate(&self) -> Result<(), SchemaError> {
        if self.schema_version != AUTHORITY_SCHEMA_VERSION {
            return Err(SchemaError::UnsupportedVersion(self.schema_version));
        }
        if self.provider.as_ref().is_some_and(|provider| {
            provider.is_empty()
                || provider.len() > 64
                || !provider
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        }) {
            return Err(SchemaError::InvalidProvider);
        }
        self.constraints.validate()?;
        let network = &self.constraints.network;
        let network_denied = matches!(network.schemes, ExactScope::Denied)
            && matches!(network.hosts, ExactScope::Denied)
            && matches!(network.ports, ExactScope::Denied)
            && matches!(network.methods, ExactScope::Denied)
            && matches!(network.path_prefixes, ExactScope::Denied);
        let expected_read_only = matches!(
            self.operation,
            Operation::Capability | Operation::InspectWorkspace
        );
        if self.constraints.read_only != expected_read_only {
            return Err(SchemaError::OperationConstraintMismatch);
        }
        match self.operation {
            Operation::Share => {
                if self.provider.is_none()
                    || network_denied
                    || matches!(self.constraints.uses.capacity, UseCapacity::Denied)
                    || matches!(self.constraints.uses.max_request_bytes, ByteLimit::Denied)
                    || matches!(self.constraints.uses.max_response_bytes, ByteLimit::Denied)
                    || !self.constraints.spend.is_forbidden()
                {
                    return Err(SchemaError::OperationConstraintMismatch);
                }
            }
            _ => {
                if self.provider.is_some()
                    || !network_denied
                    || !self.constraints.spend.is_forbidden()
                {
                    return Err(SchemaError::OperationConstraintMismatch);
                }
            }
        }
        Ok(())
    }

    pub fn effect_class(&self) -> EffectClass {
        self.operation.effect_class()
    }
}

/// The exact authority subject Phantom expects a future verifier to prove.
///
/// This is also untrusted input. It is comparison material, not a seal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExpectedAuthority {
    pub schema_version: u32,
    pub workspace_id: WorkspaceId,
    pub workspace_manifest_sha256: Sha256Digest,
    pub place_id: PlaceId,
    pub binding_id: BindingId,
    pub tenant_id: String,
    pub principal_id: String,
    pub role: String,
    pub environment: String,
    pub vault_namespace_id: VaultNamespaceId,
    pub installation_id: InstallationId,
    pub session_id: SessionId,
    pub authority_epoch: String,
    pub session_generation: u64,
    pub session_subject_sha256: Sha256Digest,
    pub policy_sha256: Sha256Digest,
}

impl ExpectedAuthority {
    pub fn validate(&self) -> Result<(), SchemaError> {
        if self.schema_version != AUTHORITY_SCHEMA_VERSION {
            return Err(SchemaError::UnsupportedVersion(self.schema_version));
        }
        if !is_label(&self.tenant_id)
            || !is_label(&self.principal_id)
            || !is_label(&self.role)
            || !is_label(&self.environment)
        {
            return Err(SchemaError::InvalidAuthorityLabel);
        }
        if self.authority_epoch.len() != 32
            || !self
                .authority_epoch
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            || self.session_generation == 0
        {
            return Err(SchemaError::InvalidAuthorityGeneration);
        }
        Ok(())
    }
}

fn is_label(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SchemaError {
    #[error("unsupported authority schema version {0}")]
    UnsupportedVersion(u32),
    #[error("invalid provider label")]
    InvalidProvider,
    #[error("invalid authority subject label")]
    InvalidAuthorityLabel,
    #[error("invalid authority epoch or generation")]
    InvalidAuthorityGeneration,
    #[error("operation and authority constraints are inconsistent")]
    OperationConstraintMismatch,
    #[error(transparent)]
    InvalidConstraints(#[from] ConstraintError),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn closed_schema_rejects_unknown_sentinel_field() {
        let raw = format!(
            r#"{{
              "schema_version":1,
              "action_id":"act_{id}",
              "workspace_id":"wrk_{id}",
              "workspace_manifest_sha256":"{digest}",
              "operation":"capability",
              "canonical_args_sha256":"{digest}",
              "requested_at":100,
              "constraints":{{
                "environment":"local",
                "read_only":true,
                "time":{{"not_before":100,"expires_at":200}},
                "uses":{{"capacity":{{"mode":"bounded","max_uses":1,"max_concurrent_uses":1}},"max_request_bytes":{{"mode":"denied"}},"max_response_bytes":{{"mode":"denied"}}}},
                "network":{{"schemes":{{"mode":"denied"}},"hosts":{{"mode":"denied"}},"ports":{{"mode":"denied"}},"methods":{{"mode":"denied"}},"path_prefixes":{{"mode":"denied"}},"allow_redirects":false}},
                "spend":{{"max_minor_units":0}}
              }},
              "secret_value":"PUBLIC_TYPE_SENTINEL_MUST_BE_REJECTED"
            }}"#,
            id = "01".repeat(16),
            digest = "ab".repeat(32),
        );
        let error = serde_json::from_str::<ActionIntentV1>(&raw).unwrap_err();
        assert!(error.to_string().contains("unknown field"));
        assert!(!format!("{error:?}").contains("PUBLIC_TYPE_SENTINEL"));
    }

    #[test]
    fn nested_constraint_schema_rejects_unknown_fields() {
        let raw = r#"{
          "environment":"local",
          "read_only":true,
          "time":{"not_before":1,"expires_at":2,"forever":true},
          "uses":{"capacity":{"mode":"bounded","max_uses":1,"max_concurrent_uses":1},"max_request_bytes":{"mode":"denied"},"max_response_bytes":{"mode":"denied"}},
          "network":{"schemes":{"mode":"denied"},"hosts":{"mode":"denied"},"ports":{"mode":"denied"},"methods":{"mode":"denied"},"path_prefixes":{"mode":"denied"},"allow_redirects":false},
          "spend":{"max_minor_units":0}
        }"#;
        assert!(serde_json::from_str::<AuthorityConstraints>(raw).is_err());
    }
}
