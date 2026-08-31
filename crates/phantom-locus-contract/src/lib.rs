//! Inactive compatibility contract between Phantom and candidate Locus authority work.
//!
//! This crate is deliberately not an authority verifier, transport, credential resolver,
//! lease issuer, or activation switch. It records the exact value-free contract Phantom
//! would require and turns every audited mismatch into an explicit, fail-closed blocker.
//! A successful negotiation is metadata evidence only; it cannot construct a Phantom
//! `VerifiedGrant`, activate the broker, or expose a credential locator.

use phantom_authority::{
    canonical_json_v1, decode_closed_json_v1, CanonicalJsonError, Sha256Digest,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::str::FromStr;

pub const CONTRACT_NAME: &str = "phantom-locus-authority";
pub const CONTRACT_VERSION: u16 = 1;

/// Exact schema facts shared by the audited Locus candidates. These constants describe
/// those sources; matching the numbers alone never establishes compatibility.
pub const LOCUS_SESSION_SEAL_VERSION: u32 = 3;
pub const LOCUS_SESSION_BACKING_VERSION: u32 = 1;
pub const LOCUS_AUTHORITY_ANCHOR_VERSION: u32 = 1;
pub const LOCUS_AUTHORITY_ENDPOINT_VERSION: u32 = 3;
pub const LOCUS_EXTERNAL_APPROVAL_ENVELOPE_VERSION: u32 = 1;
pub const LOCUS_MINTED_SESSION_HEX_LEN: usize = 24;
pub const PHANTOM_OPAQUE_ID_HEX_LEN: usize = 32;

/// Audited source candidates. These are provenance, not an endorsed merge plan.
pub const LOCUS_SESSION_SEAL_REVISION: &str = "00162aa75c2a4139f1a6da7018b07a4f04843d88";
pub const LOCUS_CONTAINMENT_REVISION: &str = "1f070a85fd3deb81ddeb07396b84bfde97307a7d";
pub const LOCUS_AUTHORITY_SANDBOX_REVISION: &str = "aa3cebe2dde9ee06c15630c8dc2e67c6dcb51e7e";
pub const LOCUS_APPROVAL_AUTHORITY_REVISION: &str = "0c35b10e5d84baf1e23da842bef2c795110e5753";

/// Stable SHA-256 source hashes from the audited candidates.
pub const LOCUS_SESSION_SOURCE_SHA256: &str =
    "5b246a4fa16f548c9b1ca6914db2d1de5a134f3c90e49fcf0aaced19d7a622ae";
pub const LOCUS_SESSION_ANCHOR_SOURCE_SHA256: &str =
    "d97245d6d4d7ef848f7531f3c81d0746cb16e1f724a5d9ec141b7f0126364919";
pub const LOCUS_APPROVAL_SOURCE_SHA256: &str =
    "06d2dfd1b97ef78012d896e433bbbddf15edb9b35a33118bcc857c1d2e80554e";
pub const LOCUS_INTEGRATED_ANCHOR_SOURCE_SHA256: &str =
    "310311de5a2231c72e1695c8b551aca8bc77ef5ec8e5f93b78f64ac9f5d7531e";
pub const LOCUS_CREDENTIAL_SOURCE_SHA256: &str =
    "10ef267bc620ddd436b39db4c95a759f53f36ab25f813845da25b713321444a3";

/// The exact, scalar-only vector both repositories must reproduce before any signature
/// interop. It is an RFC 8785-compatible subset (ASCII strings, integers, sorted keys),
/// but this crate does not claim to implement general RFC 8785 JCS.
pub const CONTRACT_FIXTURE_V1: &[u8] = br#"{"canonicalization":"rfc8785_jcs_v1","contract":"phantom-locus-authority","contract_version":1,"credential_handoff":"value_free_lease_v1","required_features":["canonical_signed_envelope","exact_session_authority","fail_closed_revocation","human_approval_out_of_band","peer_authenticated_native_transport","replay_safe_nonce","secret_reveal_forbidden","value_free_credential_lease"],"signature_algorithm":"ed25519","transport":"peer_authenticated_native_v1"}"#;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Product {
    Phantom,
    Locus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RequiredFeatureV1 {
    CanonicalSignedEnvelope,
    ExactSessionAuthority,
    FailClosedRevocation,
    HumanApprovalOutOfBand,
    PeerAuthenticatedNativeTransport,
    ReplaySafeNonce,
    SecretRevealForbidden,
    ValueFreeCredentialLease,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CanonicalizationProfile {
    Rfc8785JcsV1,
    /// Current candidates mix sorted JSON and fixed-order session JSON.
    LegacyMixedJson,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IdentityProfile {
    SharedOpaqueIdsV1,
    /// Current Locus IDs allow widths/labels rejected by Phantom IDs.
    LocusLegacyLabels,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialHandoff {
    ValueFreeLeaseV1,
    PlaintextStdoutReveal,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportProfile {
    PeerAuthenticatedNativeV1,
    UnixSocketHmacV3,
    Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalProfile {
    ExternalEd25519NonceStoreV1,
    DisabledSchemaOnly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RevocationProfile {
    CrossRepoAtomicV1,
    SessionGenerationOnly,
    Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignatureAlgorithm {
    Ed25519,
    Unavailable,
}

/// Git source identity for one coherent executable artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceIdentityV1 {
    /// Must identify the one source tree that contains every advertised feature.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub coherent_revision: Option<String>,
    pub component_revisions: Vec<String>,
}

/// A closed, value-free compatibility offer. It contains no capability, nonce value,
/// signature bytes, credential reference, secret name, or secret value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompatibilityOfferV1 {
    pub contract: String,
    pub product: Product,
    pub supported_versions: Vec<u16>,
    pub canonicalization: CanonicalizationProfile,
    pub identity_profile: IdentityProfile,
    pub credential_handoff: CredentialHandoff,
    pub transport: TransportProfile,
    pub approval: ApprovalProfile,
    pub revocation: RevocationProfile,
    pub signature_algorithm: SignatureAlgorithm,
    pub features: BTreeSet<RequiredFeatureV1>,
    pub fixture_sha256: Sha256Digest,
    pub source: SourceIdentityV1,
}

/// Metadata-only result. Possession is never execution authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NegotiatedContractV1 {
    version: u16,
    fixture_sha256: Sha256Digest,
}

impl NegotiatedContractV1 {
    pub fn version(&self) -> u16 {
        self.version
    }

    pub fn fixture_sha256(&self) -> &Sha256Digest {
        &self.fixture_sha256
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum CompatibilityBlocker {
    ContractName,
    SameProduct,
    InvalidVersionAdvertisement,
    NoExactVersion,
    Canonicalization,
    IdentityProfile,
    CredentialHandoff,
    Transport,
    ApprovalVerifier,
    Revocation,
    SignatureAlgorithm,
    RequiredFeature(RequiredFeatureV1),
    FixtureDigest,
    MissingCoherentRevision,
    InvalidSourceRevision,
}

impl std::fmt::Display for CompatibilityBlocker {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RequiredFeature(feature) => {
                write!(formatter, "missing required feature {feature:?}")
            }
            other => write!(formatter, "{other:?}"),
        }
    }
}

#[derive(Debug, thiserror::Error)]
#[error("Phantom-Locus contract is incompatible: {blockers:?}")]
pub struct NegotiationError {
    pub blockers: Vec<CompatibilityBlocker>,
}

pub fn required_features_v1() -> BTreeSet<RequiredFeatureV1> {
    use RequiredFeatureV1::*;
    BTreeSet::from([
        CanonicalSignedEnvelope,
        ExactSessionAuthority,
        FailClosedRevocation,
        HumanApprovalOutOfBand,
        PeerAuthenticatedNativeTransport,
        ReplaySafeNonce,
        SecretRevealForbidden,
        ValueFreeCredentialLease,
    ])
}

pub fn fixture_sha256_v1() -> Sha256Digest {
    let digest = format!("{:x}", Sha256::digest(CONTRACT_FIXTURE_V1));
    Sha256Digest::from_str(&digest).expect("SHA-256 output has a fixed lowercase shape")
}

/// Phantom's inactive offer. It describes requirements only; no caller currently sends it.
pub fn phantom_required_offer_v1(revision: impl Into<String>) -> CompatibilityOfferV1 {
    CompatibilityOfferV1 {
        contract: CONTRACT_NAME.into(),
        product: Product::Phantom,
        supported_versions: vec![CONTRACT_VERSION],
        canonicalization: CanonicalizationProfile::Rfc8785JcsV1,
        identity_profile: IdentityProfile::SharedOpaqueIdsV1,
        credential_handoff: CredentialHandoff::ValueFreeLeaseV1,
        transport: TransportProfile::PeerAuthenticatedNativeV1,
        approval: ApprovalProfile::ExternalEd25519NonceStoreV1,
        revocation: RevocationProfile::CrossRepoAtomicV1,
        signature_algorithm: SignatureAlgorithm::Ed25519,
        features: required_features_v1(),
        fixture_sha256: fixture_sha256_v1(),
        source: SourceIdentityV1 {
            coherent_revision: Some(revision.into()),
            component_revisions: Vec::new(),
        },
    }
}

/// Machine-readable representation of the audited Locus branch mosaic.
/// It intentionally does not pretend the separate revisions form one artifact.
pub fn audited_locus_candidate_offer_v1() -> CompatibilityOfferV1 {
    let features = BTreeSet::from([
        RequiredFeatureV1::ExactSessionAuthority,
        RequiredFeatureV1::HumanApprovalOutOfBand,
    ]);
    CompatibilityOfferV1 {
        contract: CONTRACT_NAME.into(),
        product: Product::Locus,
        supported_versions: vec![CONTRACT_VERSION],
        canonicalization: CanonicalizationProfile::LegacyMixedJson,
        identity_profile: IdentityProfile::LocusLegacyLabels,
        credential_handoff: CredentialHandoff::PlaintextStdoutReveal,
        transport: TransportProfile::UnixSocketHmacV3,
        approval: ApprovalProfile::DisabledSchemaOnly,
        revocation: RevocationProfile::SessionGenerationOnly,
        signature_algorithm: SignatureAlgorithm::Unavailable,
        features,
        fixture_sha256: "00".repeat(32).parse().expect("fixed digest shape"),
        source: SourceIdentityV1 {
            coherent_revision: None,
            component_revisions: vec![
                LOCUS_SESSION_SEAL_REVISION.into(),
                LOCUS_CONTAINMENT_REVISION.into(),
                LOCUS_AUTHORITY_SANDBOX_REVISION.into(),
                LOCUS_APPROVAL_AUTHORITY_REVISION.into(),
            ],
        },
    }
}

pub fn canonical_offer_v1(offer: &CompatibilityOfferV1) -> Result<Vec<u8>, CanonicalJsonError> {
    canonical_json_v1(offer)
}

pub fn decode_canonical_offer_v1(bytes: &[u8]) -> Result<CompatibilityOfferV1, CanonicalJsonError> {
    decode_closed_json_v1(bytes)
}

/// Return every incompatibility rather than allowing callers to fix only the first failure.
pub fn compatibility_blockers(
    local: &CompatibilityOfferV1,
    remote: &CompatibilityOfferV1,
) -> Vec<CompatibilityBlocker> {
    let mut blockers = BTreeSet::new();
    if local.contract != CONTRACT_NAME || remote.contract != CONTRACT_NAME {
        blockers.insert(CompatibilityBlocker::ContractName);
    }
    if local.product == remote.product {
        blockers.insert(CompatibilityBlocker::SameProduct);
    }
    for offer in [local, remote] {
        if !valid_version_advertisement(&offer.supported_versions) {
            blockers.insert(CompatibilityBlocker::InvalidVersionAdvertisement);
        }
        if offer.canonicalization != CanonicalizationProfile::Rfc8785JcsV1 {
            blockers.insert(CompatibilityBlocker::Canonicalization);
        }
        if offer.identity_profile != IdentityProfile::SharedOpaqueIdsV1 {
            blockers.insert(CompatibilityBlocker::IdentityProfile);
        }
        if offer.credential_handoff != CredentialHandoff::ValueFreeLeaseV1 {
            blockers.insert(CompatibilityBlocker::CredentialHandoff);
        }
        if offer.transport != TransportProfile::PeerAuthenticatedNativeV1 {
            blockers.insert(CompatibilityBlocker::Transport);
        }
        if offer.approval != ApprovalProfile::ExternalEd25519NonceStoreV1 {
            blockers.insert(CompatibilityBlocker::ApprovalVerifier);
        }
        if offer.revocation != RevocationProfile::CrossRepoAtomicV1 {
            blockers.insert(CompatibilityBlocker::Revocation);
        }
        if offer.signature_algorithm != SignatureAlgorithm::Ed25519 {
            blockers.insert(CompatibilityBlocker::SignatureAlgorithm);
        }
        for feature in required_features_v1().difference(&offer.features) {
            blockers.insert(CompatibilityBlocker::RequiredFeature(*feature));
        }
        if offer.fixture_sha256 != fixture_sha256_v1() {
            blockers.insert(CompatibilityBlocker::FixtureDigest);
        }
        match &offer.source.coherent_revision {
            None => {
                blockers.insert(CompatibilityBlocker::MissingCoherentRevision);
            }
            Some(revision) if !valid_git_revision(revision) => {
                blockers.insert(CompatibilityBlocker::InvalidSourceRevision);
            }
            Some(_) => {}
        }
        if offer
            .source
            .component_revisions
            .iter()
            .any(|revision| !valid_git_revision(revision))
        {
            blockers.insert(CompatibilityBlocker::InvalidSourceRevision);
        }
    }
    if !local.supported_versions.contains(&CONTRACT_VERSION)
        || !remote.supported_versions.contains(&CONTRACT_VERSION)
    {
        blockers.insert(CompatibilityBlocker::NoExactVersion);
    }
    blockers.into_iter().collect()
}

pub fn negotiate_v1(
    local: &CompatibilityOfferV1,
    remote: &CompatibilityOfferV1,
) -> Result<NegotiatedContractV1, NegotiationError> {
    let blockers = compatibility_blockers(local, remote);
    if !blockers.is_empty() {
        return Err(NegotiationError { blockers });
    }
    Ok(NegotiatedContractV1 {
        version: CONTRACT_VERSION,
        fixture_sha256: fixture_sha256_v1(),
    })
}

fn valid_version_advertisement(versions: &[u16]) -> bool {
    !versions.is_empty()
        && versions.iter().all(|version| *version > 0)
        && versions.windows(2).all(|pair| pair[0] > pair[1])
}

fn valid_git_revision(revision: &str) -> bool {
    revision.len() == 40
        && revision
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    const PHANTOM_REVISION: &str = "1111111111111111111111111111111111111111";
    const LOCUS_REVISION: &str = "2222222222222222222222222222222222222222";

    fn compatible_locus_offer() -> CompatibilityOfferV1 {
        let mut offer = phantom_required_offer_v1(LOCUS_REVISION);
        offer.product = Product::Locus;
        offer
    }

    #[test]
    fn exact_fixture_is_stable_and_hashes_to_the_advertised_digest() {
        let value: Value = serde_json::from_slice(CONTRACT_FIXTURE_V1).unwrap();
        assert_eq!(canonical_json_v1(&value).unwrap(), CONTRACT_FIXTURE_V1);
        assert_eq!(fixture_sha256_v1().as_str().len(), 64);
    }

    #[test]
    fn compatible_exact_v1_metadata_negotiates_but_grants_no_authority() {
        let local = phantom_required_offer_v1(PHANTOM_REVISION);
        let negotiated = negotiate_v1(&local, &compatible_locus_offer()).unwrap();
        assert_eq!(negotiated.version(), CONTRACT_VERSION);
        assert_eq!(negotiated.fixture_sha256(), &fixture_sha256_v1());
    }

    #[test]
    fn audited_locus_candidates_fail_with_all_material_blockers() {
        let local = phantom_required_offer_v1(PHANTOM_REVISION);
        let blockers = compatibility_blockers(&local, &audited_locus_candidate_offer_v1());
        for expected in [
            CompatibilityBlocker::Canonicalization,
            CompatibilityBlocker::IdentityProfile,
            CompatibilityBlocker::CredentialHandoff,
            CompatibilityBlocker::Transport,
            CompatibilityBlocker::ApprovalVerifier,
            CompatibilityBlocker::Revocation,
            CompatibilityBlocker::SignatureAlgorithm,
            CompatibilityBlocker::FixtureDigest,
            CompatibilityBlocker::MissingCoherentRevision,
            CompatibilityBlocker::RequiredFeature(RequiredFeatureV1::SecretRevealForbidden),
            CompatibilityBlocker::RequiredFeature(RequiredFeatureV1::ValueFreeCredentialLease),
        ] {
            assert!(blockers.contains(&expected), "missing blocker {expected:?}");
        }
        assert!(negotiate_v1(&local, &audited_locus_candidate_offer_v1()).is_err());
    }

    #[test]
    fn downgrade_duplicate_and_unsorted_versions_fail_closed() {
        let local = phantom_required_offer_v1(PHANTOM_REVISION);
        for versions in [vec![2], vec![1, 1], vec![1, 2], Vec::new()] {
            let mut remote = compatible_locus_offer();
            remote.supported_versions = versions;
            assert!(negotiate_v1(&local, &remote).is_err());
        }
    }

    #[test]
    fn source_must_be_one_exact_coherent_revision() {
        let local = phantom_required_offer_v1(PHANTOM_REVISION);
        let mut remote = compatible_locus_offer();
        remote.source.coherent_revision = None;
        assert!(compatibility_blockers(&local, &remote)
            .contains(&CompatibilityBlocker::MissingCoherentRevision));

        remote.source.coherent_revision = Some("AA".repeat(20));
        assert!(compatibility_blockers(&local, &remote)
            .contains(&CompatibilityBlocker::InvalidSourceRevision));
    }

    #[test]
    fn canonical_decoder_rejects_unknown_fields_and_noncanonical_input() {
        let offer = phantom_required_offer_v1(PHANTOM_REVISION);
        let bytes = canonical_offer_v1(&offer).unwrap();
        assert_eq!(decode_canonical_offer_v1(&bytes).unwrap(), offer);

        let mut value: Value = serde_json::from_slice(&bytes).unwrap();
        value["approval_token"] = Value::String("must-never-exist".into());
        let unknown = canonical_json_v1(&value).unwrap();
        assert!(decode_canonical_offer_v1(&unknown).is_err());

        let pretty = serde_json::to_vec_pretty(&offer).unwrap();
        assert!(decode_canonical_offer_v1(&pretty).is_err());
    }

    #[test]
    fn offer_is_value_free_and_has_no_plaintext_reveal_surface() {
        let bytes = canonical_offer_v1(&phantom_required_offer_v1(PHANTOM_REVISION)).unwrap();
        let text = String::from_utf8(bytes).unwrap();
        for forbidden in [
            "credential_ref",
            "credential_name",
            "secret_value",
            "approval_token",
            "plaintext_stdout_reveal",
            "--yes",
        ] {
            assert!(!text.contains(forbidden), "leaked field marker {forbidden}");
        }
    }

    #[test]
    fn audited_source_revisions_and_hashes_remain_exact_lowercase_hex() {
        assert_eq!(LOCUS_SESSION_SEAL_VERSION, 3);
        assert_eq!(LOCUS_SESSION_BACKING_VERSION, 1);
        assert_eq!(LOCUS_AUTHORITY_ANCHOR_VERSION, 1);
        assert_eq!(LOCUS_AUTHORITY_ENDPOINT_VERSION, 3);
        assert_eq!(LOCUS_EXTERNAL_APPROVAL_ENVELOPE_VERSION, 1);
        assert_ne!(LOCUS_MINTED_SESSION_HEX_LEN, PHANTOM_OPAQUE_ID_HEX_LEN);
        for revision in [
            LOCUS_SESSION_SEAL_REVISION,
            LOCUS_CONTAINMENT_REVISION,
            LOCUS_AUTHORITY_SANDBOX_REVISION,
            LOCUS_APPROVAL_AUTHORITY_REVISION,
        ] {
            assert!(valid_git_revision(revision));
        }
        for digest in [
            LOCUS_SESSION_SOURCE_SHA256,
            LOCUS_SESSION_ANCHOR_SOURCE_SHA256,
            LOCUS_APPROVAL_SOURCE_SHA256,
            LOCUS_INTEGRATED_ANCHOR_SOURCE_SHA256,
            LOCUS_CREDENTIAL_SOURCE_SHA256,
        ] {
            assert!(Sha256Digest::from_str(digest).is_ok());
        }
    }
}
