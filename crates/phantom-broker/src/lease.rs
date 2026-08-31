use phantom_authority::{
    ActionId, AuthorityConstraints, ConstraintError, EffectClass, ExpectedAuthority, GrantId,
    LeaseId, Operation, SchemaError, Sha256Digest, UseCapacity, VerifiedGrant,
};
use serde::Serialize;

/// Value-free binding for one prospective lease.
///
/// This contains no secret value, credential locator, proxy bearer, signature,
/// or executable capability. Creating it does not create an active lease.
/// It is intentionally not deserializable; production construction requires a
/// private [`VerifiedGrant`] witness.
///
/// ```compile_fail
/// use phantom_broker::LeaseBinding;
/// let _: LeaseBinding = serde_json::from_str("{}").unwrap();
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LeaseBinding {
    pub(crate) lease_id: LeaseId,
    pub(crate) grant_id: GrantId,
    pub(crate) action_id: ActionId,
    pub(crate) operation: Operation,
    pub(crate) expected_authority: ExpectedAuthority,
    pub(crate) canonical_args_sha256: Sha256Digest,
    pub(crate) broker_generation: u64,
    pub(crate) constraints: AuthorityConstraints,
}

impl LeaseBinding {
    pub fn validate(&self) -> Result<(), LeaseBindingError> {
        self.expected_authority.validate()?;
        self.constraints.validate()?;
        if self.broker_generation == 0 {
            return Err(LeaseBindingError::InvalidBrokerGeneration);
        }
        if self.constraints.environment != self.expected_authority.environment {
            return Err(LeaseBindingError::EnvironmentMismatch);
        }
        if matches!(self.constraints.uses.capacity, UseCapacity::Denied) {
            return Err(LeaseBindingError::NoUsableCapacity);
        }
        let expected_read_only = matches!(
            self.operation.effect_class(),
            EffectClass::Inspect | EffectClass::LocalRead
        );
        if self.constraints.read_only != expected_read_only {
            return Err(LeaseBindingError::OperationConstraintMismatch);
        }
        Ok(())
    }

    pub fn from_verified(
        lease_id: LeaseId,
        grant: &VerifiedGrant,
        broker_generation: u64,
    ) -> Result<Self, LeaseBindingError> {
        let binding = Self {
            lease_id,
            grant_id: grant.grant_id().clone(),
            action_id: grant.action_id().clone(),
            operation: grant.operation(),
            expected_authority: grant.authority().clone(),
            canonical_args_sha256: grant.canonical_args_sha256().clone(),
            broker_generation,
            constraints: grant.constraints().clone(),
        };
        binding.validate()?;
        Ok(binding)
    }

    pub fn lease_id(&self) -> &LeaseId {
        &self.lease_id
    }
    pub fn action_id(&self) -> &ActionId {
        &self.action_id
    }
    pub fn operation(&self) -> Operation {
        self.operation
    }
    pub fn canonical_args_sha256(&self) -> &Sha256Digest {
        &self.canonical_args_sha256
    }
    pub fn workspace_id(&self) -> &phantom_authority::WorkspaceId {
        &self.expected_authority.workspace_id
    }
    pub fn workspace_manifest_sha256(&self) -> &Sha256Digest {
        &self.expected_authority.workspace_manifest_sha256
    }
    pub fn policy_sha256(&self) -> &Sha256Digest {
        &self.expected_authority.policy_sha256
    }
    pub fn broker_generation(&self) -> u64 {
        self.broker_generation
    }
    pub fn constraints(&self) -> &AuthorityConstraints {
        &self.constraints
    }

    pub fn active_at(&self, now_unix: u64) -> bool {
        self.constraints.time.active_at(now_unix)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum LeaseBindingError {
    #[error(transparent)]
    InvalidAuthority(#[from] SchemaError),
    #[error(transparent)]
    InvalidConstraints(#[from] ConstraintError),
    #[error("lease broker generation must be nonzero")]
    InvalidBrokerGeneration,
    #[error("lease environment does not match expected authority")]
    EnvironmentMismatch,
    #[error("lease has no usable use or concurrency capacity")]
    NoUsableCapacity,
    #[error("lease operation and read-only constraint are inconsistent")]
    OperationConstraintMismatch,
}

#[cfg(test)]
pub(crate) mod test_support {
    use super::*;
    use phantom_authority::{
        BindingId, ByteLimit, ExactScope, HttpMethod, InstallationId, NetworkConstraints,
        NetworkScheme, PlaceId, SessionId, SpendConstraints, TimeConstraints, UseCapacity,
        UseConstraints, VaultNamespaceId, WorkspaceId, AUTHORITY_SCHEMA_VERSION,
    };

    fn id(prefix: &str) -> String {
        format!("{prefix}{}", "01".repeat(16))
    }

    pub fn binding() -> LeaseBinding {
        let digest = "ab".repeat(32).parse::<Sha256Digest>().unwrap();
        LeaseBinding {
            lease_id: id("lea_").parse().unwrap(),
            grant_id: id("grt_").parse().unwrap(),
            action_id: id("act_").parse().unwrap(),
            operation: Operation::Capability,
            expected_authority: ExpectedAuthority {
                schema_version: AUTHORITY_SCHEMA_VERSION,
                workspace_id: id("wrk_").parse::<WorkspaceId>().unwrap(),
                workspace_manifest_sha256: digest.clone(),
                place_id: id("plc_").parse::<PlaceId>().unwrap(),
                binding_id: id("bnd_").parse::<BindingId>().unwrap(),
                tenant_id: "example".into(),
                principal_id: "operator".into(),
                role: "developer".into(),
                environment: "local".into(),
                vault_namespace_id: id("vlt_").parse::<VaultNamespaceId>().unwrap(),
                installation_id: id("ins_").parse::<InstallationId>().unwrap(),
                session_id: id("ses_").parse::<SessionId>().unwrap(),
                authority_epoch: "cd".repeat(16),
                session_generation: 1,
                session_subject_sha256: digest.clone(),
                policy_sha256: digest,
            },
            canonical_args_sha256: "ef".repeat(32).parse().unwrap(),
            broker_generation: 1,
            constraints: AuthorityConstraints {
                environment: "local".into(),
                read_only: true,
                time: TimeConstraints {
                    not_before: 10,
                    expires_at: 20,
                },
                uses: UseConstraints {
                    capacity: UseCapacity::Bounded {
                        max_uses: 1,
                        max_concurrent_uses: 1,
                    },
                    max_request_bytes: ByteLimit::Bounded { bytes: 1_024 },
                    max_response_bytes: ByteLimit::Bounded { bytes: 2_048 },
                },
                network: NetworkConstraints {
                    schemes: ExactScope::Exact(vec![NetworkScheme::Https]),
                    hosts: ExactScope::Exact(vec!["api.example.com".into()]),
                    ports: ExactScope::Exact(vec![443]),
                    methods: ExactScope::Exact(vec![HttpMethod::Get]),
                    path_prefixes: ExactScope::Exact(vec!["/v1".into()]),
                    allow_redirects: false,
                },
                spend: SpendConstraints::forbidden(),
            },
        }
    }

    #[test]
    fn binding_validates_generation_environment_and_capacity() {
        let valid = binding();
        valid.validate().unwrap();
        assert!(valid.active_at(10));
        assert!(!valid.active_at(20));
        assert_eq!(valid.action_id().as_str(), id("act_"));
        assert_eq!(valid.operation(), Operation::Capability);
        assert_eq!(valid.canonical_args_sha256().as_str(), "ef".repeat(32));
        assert_eq!(valid.workspace_id().as_str(), id("wrk_"));
        assert_eq!(valid.workspace_manifest_sha256().as_str(), "ab".repeat(32));
        assert_eq!(valid.policy_sha256().as_str(), "ab".repeat(32));

        let mut mismatch = valid.clone();
        mismatch.constraints.environment = "production".into();
        assert!(matches!(
            mismatch.validate(),
            Err(LeaseBindingError::EnvironmentMismatch)
        ));

        let mut empty = valid;
        empty.constraints.uses.capacity = UseCapacity::Denied;
        assert!(matches!(
            empty.validate(),
            Err(LeaseBindingError::NoUsableCapacity)
        ));

        let mut mismatched_operation = binding();
        mismatched_operation.operation = Operation::RunEngineeringCheck;
        assert!(matches!(
            mismatched_operation.validate(),
            Err(LeaseBindingError::OperationConstraintMismatch)
        ));
    }
}
