use crate::constraints::AuthorityConstraints;
use crate::ids::{ActionId, GrantId, Sha256Digest};
use crate::schema::{ActionIntentV1, ExpectedAuthority};
use crate::Operation;

/// Verifies authority for an exact action and expected subject.
///
/// The only production implementation in this wave is [`DenyAllAuthority`].
/// Future active implementations belong inside this crate so only a reviewed,
/// sealed verification path can construct [`VerifiedGrant`].
pub trait AuthorityVerifier: Send + Sync {
    fn verify(
        &self,
        intent: &ActionIntentV1,
        expected: &ExpectedAuthority,
        now_unix: u64,
    ) -> Result<VerifiedGrant, AuthorityError>;
}

/// Production-safe default used until an authenticated Locus broker exists.
#[derive(Debug, Clone, Copy, Default)]
pub struct DenyAllAuthority;

impl AuthorityVerifier for DenyAllAuthority {
    fn verify(
        &self,
        _intent: &ActionIntentV1,
        _expected: &ExpectedAuthority,
        _now_unix: u64,
    ) -> Result<VerifiedGrant, AuthorityError> {
        Err(AuthorityError::AuthorityUnavailable)
    }
}

/// Opaque proof that a verifier completed every authority check.
///
/// It intentionally implements neither `Serialize` nor `Deserialize`, and its
/// fields and constructor are private. Untrusted JSON cannot manufacture this
/// witness.
///
/// ```compile_fail
/// use phantom_authority::VerifiedGrant;
/// let _: VerifiedGrant = serde_json::from_str("{}").unwrap();
/// ```
///
/// ```compile_fail
/// use phantom_authority::VerifiedGrant;
/// let _ = VerifiedGrant {};
/// ```
#[derive(Debug)]
pub struct VerifiedGrant {
    grant_id: GrantId,
    action_id: ActionId,
    operation: Operation,
    authority: ExpectedAuthority,
    constraints: AuthorityConstraints,
    canonical_args_sha256: Sha256Digest,
    verified_at: u64,
    _witness: VerificationWitness,
}

#[derive(Debug)]
struct VerificationWitness;

impl VerifiedGrant {
    #[allow(dead_code)]
    fn from_verified(
        grant_id: GrantId,
        intent: &ActionIntentV1,
        authority: ExpectedAuthority,
        constraints: AuthorityConstraints,
        verified_at: u64,
    ) -> Result<Self, AuthorityError> {
        intent.validate().map_err(|_| AuthorityError::VerbDenied)?;
        authority
            .validate()
            .map_err(|_| AuthorityError::SubjectMismatch)?;
        if intent.workspace_id != authority.workspace_id
            || intent.workspace_manifest_sha256 != authority.workspace_manifest_sha256
            || intent.constraints.environment != authority.environment
        {
            return Err(AuthorityError::SubjectMismatch);
        }
        let constraints = intent
            .constraints
            .intersect(&constraints)
            .map_err(|_| AuthorityError::SubjectMismatch)?;
        if constraints.read_only != intent.constraints.read_only {
            return Err(AuthorityError::SubjectMismatch);
        }
        if !constraints.time.active_at(verified_at) {
            return Err(AuthorityError::Expired);
        }
        Ok(Self {
            grant_id,
            action_id: intent.action_id.clone(),
            operation: intent.operation,
            authority,
            constraints,
            canonical_args_sha256: intent.canonical_args_sha256.clone(),
            verified_at,
            _witness: VerificationWitness,
        })
    }

    pub fn grant_id(&self) -> &GrantId {
        &self.grant_id
    }

    pub fn action_id(&self) -> &ActionId {
        &self.action_id
    }

    pub fn operation(&self) -> Operation {
        self.operation
    }

    pub fn authority(&self) -> &ExpectedAuthority {
        &self.authority
    }

    pub fn constraints(&self) -> &AuthorityConstraints {
        &self.constraints
    }

    pub fn canonical_args_sha256(&self) -> &Sha256Digest {
        &self.canonical_args_sha256
    }

    pub fn verified_at(&self) -> u64 {
        self.verified_at
    }

    #[cfg(test)]
    pub(crate) fn for_test(
        grant_id: GrantId,
        intent: &ActionIntentV1,
        authority: ExpectedAuthority,
        constraints: AuthorityConstraints,
        verified_at: u64,
    ) -> Self {
        Self::from_verified(grant_id, intent, authority, constraints, verified_at).unwrap()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AuthorityError {
    #[error("external authority is unavailable")]
    AuthorityUnavailable,
    #[error("authority subject did not match the requested action")]
    SubjectMismatch,
    #[error("authority expired")]
    Expired,
    #[error("authority grant was replayed")]
    Replay,
    #[error("authority verb is denied")]
    VerbDenied,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constraints::{
        ByteLimit, ExactScope, NetworkConstraints, SpendConstraints, TimeConstraints,
        UseConstraints,
    };
    use crate::ids::{
        BindingId, InstallationId, PlaceId, SessionId, Sha256Digest, VaultNamespaceId, WorkspaceId,
    };
    use crate::{Operation, AUTHORITY_SCHEMA_VERSION};

    fn id(prefix: &str) -> String {
        format!("{prefix}{}", "01".repeat(16))
    }

    fn constraints() -> AuthorityConstraints {
        AuthorityConstraints {
            environment: "local".into(),
            read_only: true,
            time: TimeConstraints {
                not_before: 1,
                expires_at: 2,
            },
            uses: UseConstraints {
                capacity: crate::UseCapacity::Bounded {
                    max_uses: 1,
                    max_concurrent_uses: 1,
                },
                max_request_bytes: ByteLimit::Denied,
                max_response_bytes: ByteLimit::Denied,
            },
            network: NetworkConstraints {
                schemes: ExactScope::Denied,
                hosts: ExactScope::Denied,
                ports: ExactScope::Denied,
                methods: ExactScope::Denied,
                path_prefixes: ExactScope::Denied,
                allow_redirects: false,
            },
            spend: SpendConstraints::forbidden(),
        }
    }

    fn expected() -> ExpectedAuthority {
        let digest = "ab".repeat(32).parse::<Sha256Digest>().unwrap();
        ExpectedAuthority {
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
        }
    }

    fn intent() -> ActionIntentV1 {
        ActionIntentV1 {
            schema_version: AUTHORITY_SCHEMA_VERSION,
            action_id: id("act_").parse::<ActionId>().unwrap(),
            workspace_id: id("wrk_").parse::<WorkspaceId>().unwrap(),
            workspace_manifest_sha256: "ab".repeat(32).parse().unwrap(),
            operation: Operation::Capability,
            provider: None,
            canonical_args_sha256: "cd".repeat(32).parse().unwrap(),
            requested_at: 1,
            constraints: constraints(),
        }
    }

    #[test]
    fn deny_all_is_the_fail_closed_production_default() {
        let verifier = DenyAllAuthority;
        let result = verifier.verify(&intent(), &expected(), 1);
        assert_eq!(result.unwrap_err(), AuthorityError::AuthorityUnavailable);
    }

    #[test]
    fn internal_test_builder_preserves_only_public_contract_metadata() {
        let grant = VerifiedGrant::for_test(
            id("grt_").parse().unwrap(),
            &intent(),
            expected(),
            constraints(),
            1,
        );
        assert_eq!(grant.grant_id().as_str(), id("grt_"));
        assert_eq!(grant.action_id().as_str(), id("act_"));
        assert_eq!(grant.operation(), Operation::Capability);
        assert_eq!(grant.verified_at(), 1);
        assert_eq!(grant.authority().environment, "local");
        assert!(grant.constraints().read_only);
    }

    fn verify_with(
        intent: &ActionIntentV1,
        authority: ExpectedAuthority,
        granted: AuthorityConstraints,
        at: u64,
    ) -> Result<VerifiedGrant, AuthorityError> {
        VerifiedGrant::from_verified(id("grt_").parse().unwrap(), intent, authority, granted, at)
    }

    /// The sealed constructor is the future active path; each of its checks
    /// must hold on its own so activating it can never widen authority.
    #[test]
    fn from_verified_accepts_the_exact_matching_grant() {
        assert!(verify_with(&intent(), expected(), constraints(), 1).is_ok());
    }

    #[test]
    fn from_verified_rejects_each_subject_mismatch() {
        let other_digest: Sha256Digest = "ef".repeat(32).parse().unwrap();
        let mut wrong_workspace = expected();
        wrong_workspace.workspace_id = id("wrk_").replace("01", "02").parse().unwrap();
        let mut wrong_manifest = expected();
        wrong_manifest.workspace_manifest_sha256 = other_digest;
        let mut wrong_env = expected();
        wrong_env.environment = "production".into();
        for (label, authority) in [
            ("workspace", wrong_workspace),
            ("manifest", wrong_manifest),
            ("environment", wrong_env),
        ] {
            assert_eq!(
                verify_with(&intent(), authority, constraints(), 1).unwrap_err(),
                AuthorityError::SubjectMismatch,
                "{label}"
            );
        }
    }

    #[test]
    fn from_verified_rejects_an_invalid_expected_authority() {
        let mut bad = expected();
        bad.schema_version += 1;
        assert_eq!(
            verify_with(&intent(), bad, constraints(), 1).unwrap_err(),
            AuthorityError::SubjectMismatch
        );
    }

    #[test]
    fn from_verified_never_turns_a_write_intent_into_a_read_only_grant() {
        // A valid local-write intent against a read-only grant: the
        // intersection narrows to read-only, which no longer matches what
        // was asked, so the grant must be refused rather than narrowed.
        let mut write_intent = intent();
        write_intent.operation = Operation::SetupWorkspace;
        write_intent.constraints.read_only = false;
        assert!(write_intent.validate().is_ok());
        assert_eq!(
            verify_with(&write_intent, expected(), constraints(), 1).unwrap_err(),
            AuthorityError::SubjectMismatch
        );
    }

    #[test]
    fn from_verified_rejects_outside_the_time_window() {
        for at in [0, 2, 3] {
            assert_eq!(
                verify_with(&intent(), expected(), constraints(), at).unwrap_err(),
                AuthorityError::Expired,
                "at {at}"
            );
        }
    }
}
