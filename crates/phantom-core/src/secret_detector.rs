//! Compatibility facade for RQ-PS-LOG-REDACT. New consumers should use [`crate::redact`].

pub use crate::redact::{
    code_credential_matches, credential_spans, known_value_prefix, CredentialMatch,
    CredentialPattern, CREDENTIAL_PATTERNS,
};
