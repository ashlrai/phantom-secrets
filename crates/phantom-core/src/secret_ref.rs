//! `secret://<NAME>` references: how an agent or launcher names a stored
//! secret without ever holding its value.
//!
//! A reference is resolved only at the exec boundary (`phantom exec`), where
//! the child receives a session-scoped phantom token and the local proxy
//! injects the real value into the matched route. Parsing is value-free: a
//! reference carries a name, never a value, and every error names the
//! environment variable that held it, never its contents.
//!
//! Design: `docs/design/builtin-vault.md`.

use crate::dotenv::is_canonical_env_name;

/// The only accepted reference scheme.
pub const SCHEME: &str = "secret://";

/// Upper bound on a referenced name, matching what launchers can pass safely.
pub const MAX_NAME_LEN: usize = 128;

/// A parsed `secret://<NAME>` reference.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SecretRef {
    name: String,
}

/// Why a string that starts with [`SCHEME`] is not a valid reference.
/// Variants carry no input text, so they can be shown or logged safely.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretRefError {
    /// Nothing after `secret://`.
    EmptyName,
    /// The name is not a canonical environment-variable name
    /// (`[A-Za-z_][A-Za-z0-9_]*`) or is longer than [`MAX_NAME_LEN`].
    InvalidName,
}

impl std::fmt::Display for SecretRefError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyName => f.write_str("reference has no secret name after secret://"),
            Self::InvalidName => f.write_str(
                "reference name must match [A-Za-z_][A-Za-z0-9_]* and be at most 128 characters",
            ),
        }
    }
}

impl std::error::Error for SecretRefError {}

impl SecretRef {
    /// Build a reference for a stored secret name.
    pub fn new(name: &str) -> Result<Self, SecretRefError> {
        if name.is_empty() {
            return Err(SecretRefError::EmptyName);
        }
        if name.len() > MAX_NAME_LEN || !is_canonical_env_name(name) {
            return Err(SecretRefError::InvalidName);
        }
        Ok(Self {
            name: name.to_string(),
        })
    }

    /// Parse `text`. Returns `None` when `text` does not use the scheme at
    /// all (an ordinary value), and `Some(Err(_))` when it uses the scheme
    /// but is malformed, so callers can fail closed instead of passing a
    /// broken reference through as a literal.
    pub fn parse(text: &str) -> Option<Result<Self, SecretRefError>> {
        text.strip_prefix(SCHEME).map(Self::new)
    }

    /// The referenced secret name.
    pub fn name(&self) -> &str {
        &self.name
    }
}

impl std::fmt::Display for SecretRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{SCHEME}{}", self.name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_canonical_reference_and_round_trips() {
        let parsed = SecretRef::parse("secret://OPENAI_API_KEY")
            .unwrap()
            .unwrap();
        assert_eq!(parsed.name(), "OPENAI_API_KEY");
        assert_eq!(parsed.to_string(), "secret://OPENAI_API_KEY");
        assert_eq!(SecretRef::new("OPENAI_API_KEY").unwrap(), parsed);
    }

    #[test]
    fn ordinary_values_are_not_references() {
        for text in [
            "",
            "plain",
            "secret:/X",
            "SECRET://X",
            "https://x",
            " secret://X",
        ] {
            assert!(SecretRef::parse(text).is_none());
        }
    }

    #[test]
    fn malformed_references_fail_closed_without_echoing_input() {
        assert_eq!(
            SecretRef::parse("secret://").unwrap().unwrap_err(),
            SecretRefError::EmptyName
        );
        let long = format!("secret://{}", "A".repeat(MAX_NAME_LEN + 1));
        for text in [
            "secret://1ABC",
            "secret://A-B",
            "secret://A B",
            "secret://A/B",
            "secret://A\nB",
            "secret://A=B",
            "secret://../X",
            long.as_str(),
        ] {
            let error = SecretRef::parse(text).unwrap().unwrap_err();
            assert_eq!(error, SecretRefError::InvalidName);
            let shown = error.to_string();
            let tail = text.trim_start_matches(SCHEME);
            assert!(!shown.contains(tail), "refusal echoed its input");
        }
    }

    #[test]
    fn max_length_name_is_accepted() {
        let name = "A".repeat(MAX_NAME_LEN);
        assert!(SecretRef::new(&name).is_ok());
    }
}
