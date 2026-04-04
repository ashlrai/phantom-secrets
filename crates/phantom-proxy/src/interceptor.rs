use std::collections::HashMap;
use zeroize::Zeroize;

/// The interceptor replaces phantom tokens with real secrets in HTTP requests,
/// and scrubs real secrets from API responses to prevent leakage.
#[derive(Clone)]
pub struct Interceptor {
    /// phantom_token_string -> real_secret_value (for outgoing requests)
    token_map: HashMap<String, SecretValue>,
    /// real_secret_value -> phantom_token_string (for response scrubbing)
    reverse_map: HashMap<String, String>,
}

/// A secret value that zeroizes itself when dropped.
#[derive(Clone)]
struct SecretValue {
    value: String,
}

impl Drop for SecretValue {
    fn drop(&mut self) {
        self.value.zeroize();
    }
}

impl Interceptor {
    /// Create a new interceptor with a mapping of phantom tokens to real secrets.
    pub fn new(mappings: HashMap<String, String>) -> Self {
        let reverse_map: HashMap<String, String> = mappings
            .iter()
            .map(|(token, secret)| (secret.clone(), token.clone()))
            .collect();
        let token_map = mappings
            .into_iter()
            .map(|(token, secret)| (token, SecretValue { value: secret }))
            .collect();
        Self {
            token_map,
            reverse_map,
        }
    }

    /// Replace any phantom tokens found in a string with their real values.
    /// Returns the modified string and whether any replacements were made.
    pub fn replace_in_str(&self, input: &str) -> (String, bool) {
        let mut result = input.to_string();
        let mut replaced = false;

        for (token, secret) in &self.token_map {
            if result.contains(token.as_str()) {
                result = result.replace(token.as_str(), &secret.value);
                replaced = true;
            }
        }

        (result, replaced)
    }

    /// Replace phantom tokens in a byte buffer (for request bodies).
    /// Returns the modified bytes and whether any replacements were made.
    pub fn replace_in_bytes(&self, input: &[u8]) -> (Vec<u8>, bool) {
        match std::str::from_utf8(input) {
            Ok(s) => {
                let (replaced, did_replace) = self.replace_in_str(s);
                (replaced.into_bytes(), did_replace)
            }
            Err(_) => {
                let pairs: Vec<(&[u8], &[u8])> = self
                    .token_map
                    .iter()
                    .map(|(t, s)| (t.as_bytes(), s.value.as_bytes()))
                    .collect();
                find_replace_bytes(input, &pairs)
            }
        }
    }

    /// Format a header value by replacing the {secret} placeholder with the real secret.
    pub fn format_header_value(&self, format: &str, phantom_token: &str) -> Option<String> {
        self.token_map
            .get(phantom_token)
            .map(|secret| format.replace("{secret}", &secret.value))
    }

    /// Look up the real secret for a phantom token.
    pub fn resolve(&self, phantom_token: &str) -> Option<&str> {
        self.token_map.get(phantom_token).map(|s| s.value.as_str())
    }

    /// Check if a value contains any phantom tokens.
    pub fn contains_phantom_token(&self, value: &str) -> bool {
        self.token_map
            .keys()
            .any(|token| value.contains(token.as_str()))
    }

    /// Number of token mappings.
    pub fn len(&self) -> usize {
        self.token_map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.token_map.is_empty()
    }

    /// Scrub real secrets from a response string, replacing them with phantom tokens.
    /// Prevents API responses from leaking real credentials back to AI agents.
    pub fn scrub_response_str(&self, input: &str) -> (String, bool) {
        let mut result = input.to_string();
        let mut scrubbed = false;

        for (secret, token) in &self.reverse_map {
            if result.contains(secret.as_str()) {
                result = result.replace(secret.as_str(), token.as_str());
                scrubbed = true;
            }
        }

        (result, scrubbed)
    }

    /// Scrub real secrets from response bytes.
    pub fn scrub_response_bytes(&self, input: &[u8]) -> (Vec<u8>, bool) {
        match std::str::from_utf8(input) {
            Ok(s) => {
                let (scrubbed, did_scrub) = self.scrub_response_str(s);
                (scrubbed.into_bytes(), did_scrub)
            }
            Err(_) => {
                let pairs: Vec<(&[u8], &[u8])> = self
                    .reverse_map
                    .iter()
                    .map(|(s, t)| (s.as_bytes(), t.as_bytes()))
                    .collect();
                find_replace_bytes(input, &pairs)
            }
        }
    }
}

/// Find-and-replace multiple byte patterns in a buffer.
/// Each pair is (needle, replacement). Returns the result and whether any replacement was made.
fn find_replace_bytes(input: &[u8], pairs: &[(&[u8], &[u8])]) -> (Vec<u8>, bool) {
    let mut result = input.to_vec();
    let mut replaced = false;

    for &(needle, replacement) in pairs {
        let mut i = 0;
        let mut new_result = Vec::with_capacity(result.len());
        while i < result.len() {
            if i + needle.len() <= result.len() && &result[i..i + needle.len()] == needle {
                new_result.extend_from_slice(replacement);
                i += needle.len();
                replaced = true;
            } else {
                new_result.push(result[i]);
                i += 1;
            }
        }
        result = new_result;
    }

    (result, replaced)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_interceptor() -> Interceptor {
        let mut mappings = HashMap::new();
        mappings.insert(
            "phm_aaaa1111bbbb2222cccc3333dddd4444eeee5555ffff6666aaaa1111bbbb2222".to_string(),
            "sk-real-openai-key-12345".to_string(),
        );
        mappings.insert(
            "phm_1111222233334444555566667777888899990000aaaabbbbccccddddeeee0000".to_string(),
            "sk-ant-real-anthropic-key".to_string(),
        );
        Interceptor::new(mappings)
    }

    #[test]
    fn test_replace_in_header_value() {
        let interceptor = test_interceptor();
        let (result, replaced) = interceptor.replace_in_str(
            "Bearer phm_aaaa1111bbbb2222cccc3333dddd4444eeee5555ffff6666aaaa1111bbbb2222",
        );
        assert!(replaced);
        assert_eq!(result, "Bearer sk-real-openai-key-12345");
    }

    #[test]
    fn test_replace_in_body() {
        let interceptor = test_interceptor();
        let body = r#"{"api_key": "phm_aaaa1111bbbb2222cccc3333dddd4444eeee5555ffff6666aaaa1111bbbb2222"}"#;
        let (result, replaced) = interceptor.replace_in_bytes(body.as_bytes());
        assert!(replaced);
        let result_str = String::from_utf8(result).unwrap();
        assert!(result_str.contains("sk-real-openai-key-12345"));
        assert!(!result_str.contains("phm_"));
    }

    #[test]
    fn test_no_replacement_needed() {
        let interceptor = test_interceptor();
        let (result, replaced) = interceptor.replace_in_str("Bearer sk-real-key");
        assert!(!replaced);
        assert_eq!(result, "Bearer sk-real-key");
    }

    #[test]
    fn test_contains_phantom_token() {
        let interceptor = test_interceptor();
        assert!(interceptor.contains_phantom_token(
            "Bearer phm_aaaa1111bbbb2222cccc3333dddd4444eeee5555ffff6666aaaa1111bbbb2222"
        ));
        assert!(!interceptor.contains_phantom_token("Bearer sk-real-key"));
    }

    #[test]
    fn test_resolve() {
        let interceptor = test_interceptor();
        assert_eq!(
            interceptor
                .resolve("phm_aaaa1111bbbb2222cccc3333dddd4444eeee5555ffff6666aaaa1111bbbb2222"),
            Some("sk-real-openai-key-12345")
        );
        assert_eq!(interceptor.resolve("phm_nonexistent"), None);
    }

    #[test]
    fn test_scrub_response_str() {
        let interceptor = test_interceptor();
        // Simulate an API response that echoes back the real secret
        let response = r#"{"error":"Invalid key: sk-real-openai-key-12345","status":401}"#;
        let (scrubbed, did_scrub) = interceptor.scrub_response_str(response);
        assert!(did_scrub);
        assert!(scrubbed
            .contains("phm_aaaa1111bbbb2222cccc3333dddd4444eeee5555ffff6666aaaa1111bbbb2222"));
        assert!(!scrubbed.contains("sk-real-openai-key-12345"));
    }

    #[test]
    fn test_scrub_response_bytes() {
        let interceptor = test_interceptor();
        let response = b"key echoed: sk-real-openai-key-12345 in response";
        let (scrubbed, did_scrub) = interceptor.scrub_response_bytes(response);
        assert!(did_scrub);
        let scrubbed_str = String::from_utf8(scrubbed).unwrap();
        assert!(!scrubbed_str.contains("sk-real-openai-key-12345"));
        assert!(scrubbed_str.contains("phm_"));
    }

    #[test]
    fn test_scrub_no_secrets_in_response() {
        let interceptor = test_interceptor();
        let response = r#"{"data":"safe content","status":200}"#;
        let (scrubbed, did_scrub) = interceptor.scrub_response_str(response);
        assert!(!did_scrub);
        assert_eq!(scrubbed, response);
    }

    #[test]
    fn test_multiple_replacements_in_body() {
        let interceptor = test_interceptor();
        let body = "key1=phm_aaaa1111bbbb2222cccc3333dddd4444eeee5555ffff6666aaaa1111bbbb2222&key2=phm_1111222233334444555566667777888899990000aaaabbbbccccddddeeee0000";
        let (result, replaced) = interceptor.replace_in_str(body);
        assert!(replaced);
        assert!(result.contains("sk-real-openai-key-12345"));
        assert!(result.contains("sk-ant-real-anthropic-key"));
        assert!(!result.contains("phm_"));
    }
}
