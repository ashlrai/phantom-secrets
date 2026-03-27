use rand::RngCore;
use std::collections::HashMap;
use zeroize::Zeroize;

/// Prefix for all phantom tokens — easily identifiable, never collides with real API key formats.
pub const PHANTOM_PREFIX: &str = "phm_";

/// Length of the random hex portion of a phantom token (32 bytes = 64 hex chars).
const TOKEN_RANDOM_BYTES: usize = 32;

/// A phantom token that replaces a real secret. Contains only the token string, never the real value.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PhantomToken(String);

impl PhantomToken {
    /// Generate a new cryptographically random phantom token.
    pub fn generate() -> Self {
        let mut bytes = vec![0u8; TOKEN_RANDOM_BYTES];
        rand::thread_rng().fill_bytes(&mut bytes);
        let token = format!("{}{}", PHANTOM_PREFIX, hex::encode(&bytes));
        bytes.zeroize();
        Self(token)
    }

    /// Create a PhantomToken from an existing token string.
    /// Returns None if the string doesn't have the phm_ prefix.
    pub fn parse(s: &str) -> Option<Self> {
        if s.starts_with(PHANTOM_PREFIX) {
            Some(Self(s.to_string()))
        } else {
            None
        }
    }

    /// Get the token string.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Check if a string looks like a phantom token.
    pub fn is_phantom_token(s: &str) -> bool {
        s.starts_with(PHANTOM_PREFIX)
    }
}

impl std::fmt::Display for PhantomToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Bidirectional mapping between secret names and their phantom tokens.
#[derive(Debug, Default)]
pub struct TokenMap {
    /// secret_name -> phantom_token
    name_to_token: HashMap<String, PhantomToken>,
    /// phantom_token_string -> secret_name
    token_to_name: HashMap<String, String>,
}

impl TokenMap {
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a mapping. Generates a new phantom token for the given secret name.
    pub fn insert(&mut self, name: String) -> PhantomToken {
        let token = PhantomToken::generate();
        self.token_to_name
            .insert(token.as_str().to_string(), name.clone());
        self.name_to_token.insert(name, token.clone());
        token
    }

    /// Insert a mapping with an existing phantom token.
    pub fn insert_with_token(&mut self, name: String, token: PhantomToken) {
        self.token_to_name
            .insert(token.as_str().to_string(), name.clone());
        self.name_to_token.insert(name, token);
    }

    /// Look up the secret name for a phantom token.
    pub fn resolve_token(&self, token_str: &str) -> Option<&str> {
        self.token_to_name.get(token_str).map(|s| s.as_str())
    }

    /// Get the phantom token for a secret name.
    pub fn get_token(&self, name: &str) -> Option<&PhantomToken> {
        self.name_to_token.get(name)
    }

    /// Get all secret names.
    pub fn secret_names(&self) -> Vec<&str> {
        self.name_to_token.keys().map(|s| s.as_str()).collect()
    }

    /// Number of mappings.
    pub fn len(&self) -> usize {
        self.name_to_token.len()
    }

    /// Whether the map is empty.
    pub fn is_empty(&self) -> bool {
        self.name_to_token.is_empty()
    }

    /// Remove a mapping by secret name.
    pub fn remove(&mut self, name: &str) -> Option<PhantomToken> {
        if let Some(token) = self.name_to_token.remove(name) {
            self.token_to_name.remove(token.as_str());
            Some(token)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_phantom_token_generate() {
        let token = PhantomToken::generate();
        assert!(token.as_str().starts_with(PHANTOM_PREFIX));
        // phm_ (4 chars) + 64 hex chars = 68 total
        assert_eq!(token.as_str().len(), 4 + TOKEN_RANDOM_BYTES * 2);
    }

    #[test]
    fn test_phantom_tokens_are_unique() {
        let t1 = PhantomToken::generate();
        let t2 = PhantomToken::generate();
        assert_ne!(t1, t2);
    }

    #[test]
    fn test_is_phantom_token() {
        assert!(PhantomToken::is_phantom_token("phm_abc123"));
        assert!(!PhantomToken::is_phantom_token("sk-abc123"));
        assert!(!PhantomToken::is_phantom_token(""));
    }

    #[test]
    fn test_from_str() {
        assert!(PhantomToken::parse("phm_abc123").is_some());
        assert!(PhantomToken::parse("sk-abc123").is_none());
    }

    #[test]
    fn test_token_map_insert_and_resolve() {
        let mut map = TokenMap::new();
        let token = map.insert("OPENAI_API_KEY".to_string());

        assert_eq!(map.resolve_token(token.as_str()), Some("OPENAI_API_KEY"));
        assert_eq!(map.get_token("OPENAI_API_KEY"), Some(&token));
        assert_eq!(map.len(), 1);
    }

    #[test]
    fn test_token_map_remove() {
        let mut map = TokenMap::new();
        let token = map.insert("KEY".to_string());
        let removed = map.remove("KEY");
        assert_eq!(removed.as_ref(), Some(&token));
        assert!(map.is_empty());
        assert!(map.resolve_token(token.as_str()).is_none());
    }

    #[test]
    fn test_token_map_secret_names() {
        let mut map = TokenMap::new();
        map.insert("A".to_string());
        map.insert("B".to_string());
        let mut names = map.secret_names();
        names.sort();
        assert_eq!(names, vec!["A", "B"]);
    }
}
