//! Fail-closed authority contracts for Phantom's agent-facing workflows.
//!
//! This crate currently provides only untrusted schemas, strict identifiers,
//! deterministic constraint narrowing, and a deny-all verifier boundary. It
//! does not accept Locus snapshots, verify external grants, issue leases, or
//! implement a local broker.
//!
//! Human-readable labels remain bounded comparison material in this inactive
//! schema. They must not become a signed Phantom-Locus wire contract until both
//! repositories adopt shared opaque identifier types and cross-repository test
//! vectors.

mod canonical;
mod constraints;
mod ids;
mod schema;
mod verbs;
mod verifier;

pub use canonical::{canonical_json_v1, decode_closed_json_v1, CanonicalJsonError};
pub use constraints::{
    AuthorityConstraints, ByteLimit, ConstraintError, ExactScope, HttpMethod, NetworkConstraints,
    NetworkScheme, SpendConstraints, TimeConstraints, UseCapacity, UseConstraints,
};
pub use ids::{
    ActionId, BindingId, GrantId, IdParseError, InstallationId, LeaseId, PlaceId, SessionId,
    Sha256Digest, VaultNamespaceId, WorkspaceId,
};
pub use schema::{ActionIntentV1, ExpectedAuthority, SchemaError, AUTHORITY_SCHEMA_VERSION};
pub use verbs::{EffectClass, Operation};
pub use verifier::{AuthorityError, AuthorityVerifier, DenyAllAuthority, VerifiedGrant};
