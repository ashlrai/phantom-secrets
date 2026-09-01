use crate::error::{PhantomError, Result};
use glob::Pattern;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use zeroize::Zeroizing;

use crate::provider_http;

/// Supported deployment platforms for secret syncing.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Platform {
    Vercel,
    Railway,
}

impl std::fmt::Display for Platform {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Platform::Vercel => write!(f, "vercel"),
            Platform::Railway => write!(f, "railway"),
        }
    }
}

impl std::str::FromStr for Platform {
    type Err = PhantomError;
    fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "vercel" => Ok(Platform::Vercel),
            "railway" => Ok(Platform::Railway),
            _ => Err(PhantomError::ConfigParseError(format!(
                "Unknown platform: {s}. Supported: vercel, railway"
            ))),
        }
    }
}

/// Configuration for syncing to a deployment platform.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SyncTarget {
    pub platform: Platform,
    /// Platform API token env var name (e.g., "VERCEL_TOKEN")
    pub token_env: String,
    /// Project identifier on the platform
    pub project_id: String,
    /// Target environments (e.g., ["production", "preview"])
    #[serde(default = "default_targets")]
    pub targets: Vec<String>,
    /// Railway-specific: service ID
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service_id: Option<String>,
    /// Railway-specific: environment ID
    #[serde(skip_serializing_if = "Option::is_none")]
    pub environment_id: Option<String>,
    /// Optional key-name glob patterns. When non-empty only secrets whose
    /// names match at least one pattern are pushed. Patterns use standard
    /// glob syntax (*, ?, [abc]). Example: ["STRIPE_*", "*_KEY"].
    /// Configured via `only = ["STRIPE_*"]` in the [[sync]] toml block.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub only: Vec<String>,
}

fn default_targets() -> Vec<String> {
    vec!["production".to_string(), "preview".to_string()]
}

/// Result of a sync operation for a single secret.
#[derive(Debug)]
pub struct SyncResult {
    pub key: String,
    pub status: SyncStatus,
}

#[derive(Debug)]
pub enum SyncStatus {
    Created,
    Updated,
    Unchanged,
    Error(String),
}

impl std::fmt::Display for SyncStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SyncStatus::Created => write!(f, "created"),
            SyncStatus::Updated => write!(f, "updated"),
            SyncStatus::Unchanged => write!(f, "unchanged"),
            SyncStatus::Error(e) => write!(f, "error: {e}"),
        }
    }
}

/// Filter a secrets map by a list of glob patterns.
///
/// When `patterns` is empty every key passes through (no filter applied).
/// When non-empty a key is included if it matches **any** pattern
/// (patterns are OR-ed together). Invalid glob patterns are silently
/// skipped — callers that need a stable preflight contract should call
/// [`validate_only_patterns`] first and surface the result.
pub fn filter_by_only<'a>(
    secrets: &'a BTreeMap<String, String>,
    patterns: &[String],
) -> BTreeMap<String, &'a String> {
    if patterns.is_empty() {
        // No filter — pass everything through.
        return secrets.iter().map(|(k, v)| (k.clone(), v)).collect();
    }

    // Pre-compile patterns; skip any that are invalid glob syntax.
    // Preflight callers use validate_only_patterns() to report these
    // explicitly without contaminating JSON output with log lines.
    let compiled: Vec<Pattern> = patterns
        .iter()
        .filter_map(|p| Pattern::new(p).ok())
        .collect();

    secrets
        .iter()
        .filter(|(key, _)| compiled.iter().any(|pat| pat.matches(key)))
        .map(|(k, v)| (k.clone(), v))
        .collect()
}

/// Return invalid glob patterns and their parser errors.
pub fn validate_only_patterns(patterns: &[String]) -> Vec<(String, String)> {
    patterns
        .iter()
        .filter_map(|pattern| {
            Pattern::new(pattern)
                .err()
                .map(|err| (pattern.clone(), err.to_string()))
        })
        .collect()
}

/// Sync secrets to Vercel using their REST API.
pub async fn sync_to_vercel(
    token: &str,
    project_id: &str,
    secrets: &BTreeMap<String, String>,
    targets: &[String],
) -> Vec<SyncResult> {
    let client = match provider_http::async_client() {
        Ok(client) => client,
        Err(error) => return error_results(secrets, error),
    };
    let mut results = Vec::new();

    // First, list existing env vars to know what to update vs create
    let existing = match list_vercel_env_vars(&client, token, project_id).await {
        Ok(existing) => existing,
        Err(error) => {
            return secrets
                .keys()
                .map(|key| SyncResult {
                    key: key.clone(),
                    status: SyncStatus::Error(error.clone()),
                })
                .collect();
        }
    };

    for (key, value) in secrets {
        let target_array: Vec<&str> = targets.iter().map(|s| s.as_str()).collect();

        // Check if this key already exists
        let existing_id = existing
            .iter()
            .find(|variable| variable.key == *key)
            .map(|variable| variable.id.clone());

        let result = if let Some(env_id) = existing_id {
            // Update existing
            match update_vercel_env_var(&client, token, project_id, &env_id, value).await {
                Ok(()) => SyncResult {
                    key: key.clone(),
                    status: SyncStatus::Updated,
                },
                Err(e) => SyncResult {
                    key: key.clone(),
                    status: SyncStatus::Error(e),
                },
            }
        } else {
            // Create new
            match create_vercel_env_var(&client, token, project_id, key, value, &target_array).await
            {
                Ok(()) => SyncResult {
                    key: key.clone(),
                    status: SyncStatus::Created,
                },
                Err(e) => SyncResult {
                    key: key.clone(),
                    status: SyncStatus::Error(e),
                },
            }
        };

        results.push(result);
    }

    results
}

#[derive(Debug, Deserialize)]
struct VercelEnvVarMetadata {
    id: String,
    key: String,
}

#[derive(Debug, Deserialize)]
struct VercelEnvMetadataResponse {
    envs: Vec<VercelEnvVarMetadata>,
}

#[derive(Deserialize)]
struct VercelEnvVar {
    key: String,
    #[serde(default)]
    value: Option<PulledSecret>,
}

#[derive(Deserialize)]
struct VercelEnvListResponse {
    envs: Vec<VercelEnvVar>,
}

async fn list_vercel_env_vars(
    client: &reqwest::Client,
    token: &str,
    project_id: &str,
) -> std::result::Result<Vec<VercelEnvVarMetadata>, String> {
    let resp = client
        .get(format!(
            "https://api.vercel.com/v9/projects/{project_id}/env"
        ))
        .bearer_auth(token)
        .send()
        .await
        .map_err(|_| "Vercel environment inventory request failed".to_string())?;

    if !resp.status().is_success() {
        let status = resp.status();
        return Err(format!(
            "Vercel environment inventory request failed (HTTP {status})"
        ));
    }

    let bytes = provider_http::read_bounded_response(resp, "Vercel environment inventory").await?;
    let data: VercelEnvMetadataResponse = serde_json::from_slice(&bytes)
        .map_err(|_| "Vercel environment inventory response was invalid".to_string())?;
    Ok(data.envs)
}

#[derive(Serialize)]
struct VercelCreateRequest<'a> {
    key: &'a str,
    value: &'a str,
    #[serde(rename = "type")]
    secret_type: &'static str,
    target: &'a [&'a str],
}

async fn create_vercel_env_var(
    client: &reqwest::Client,
    token: &str,
    project_id: &str,
    key: &str,
    value: &str,
    targets: &[&str],
) -> std::result::Result<(), String> {
    let body = VercelCreateRequest {
        key,
        value,
        secret_type: "encrypted",
        target: targets,
    };

    let resp = client
        .post(format!(
            "https://api.vercel.com/v10/projects/{project_id}/env"
        ))
        .bearer_auth(token)
        .json(&body)
        .send()
        .await
        .map_err(|_| "Vercel environment create request failed".to_string())?;

    if !resp.status().is_success() {
        let status = resp.status();
        return Err(format!(
            "Vercel environment create request failed (HTTP {status})"
        ));
    }

    Ok(())
}

async fn update_vercel_env_var(
    client: &reqwest::Client,
    token: &str,
    project_id: &str,
    env_id: &str,
    value: &str,
) -> std::result::Result<(), String> {
    #[derive(Serialize)]
    struct UpdateRequest<'a> {
        value: &'a str,
    }
    let body = UpdateRequest { value };

    let resp = client
        .patch(format!(
            "https://api.vercel.com/v9/projects/{project_id}/env/{env_id}"
        ))
        .bearer_auth(token)
        .json(&body)
        .send()
        .await
        .map_err(|_| "Vercel environment update request failed".to_string())?;

    if !resp.status().is_success() {
        let status = resp.status();
        return Err(format!(
            "Vercel environment update request failed (HTTP {status})"
        ));
    }

    Ok(())
}

/// Sync secrets to Railway using their GraphQL API.
pub async fn sync_to_railway(
    token: &str,
    project_id: &str,
    environment_id: &str,
    service_id: Option<&str>,
    secrets: &BTreeMap<String, String>,
) -> Vec<SyncResult> {
    let client = match provider_http::async_client() {
        Ok(client) => client,
        Err(error) => return error_results(secrets, error),
    };

    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct RailwayInput<'a> {
        project_id: &'a str,
        environment_id: &'a str,
        #[serde(skip_serializing_if = "Option::is_none")]
        service_id: Option<&'a str>,
        variables: &'a BTreeMap<String, String>,
    }
    #[derive(Serialize)]
    struct RailwayVariables<'a> {
        input: RailwayInput<'a>,
    }
    #[derive(Serialize)]
    struct RailwayRequest<'a> {
        query: &'static str,
        variables: RailwayVariables<'a>,
    }
    let body = RailwayRequest {
        query: "mutation($input: VariableCollectionUpsertInput!) { variableCollectionUpsert(input: $input) }",
        variables: RailwayVariables {
            input: RailwayInput {
                project_id,
                environment_id,
                service_id,
                variables: secrets,
            },
        },
    };

    let resp = client
        .post("https://backboard.railway.com/graphql/v2")
        .bearer_auth(token)
        .json(&body)
        .send()
        .await;

    match resp {
        Ok(r) => {
            if r.status().is_success() {
                let bytes = match provider_http::read_bounded_response(r, "Railway mutation").await
                {
                    Ok(bytes) => bytes,
                    Err(error) => return error_results(secrets, error),
                };
                if let Err(error) = parse_railway_mutation_response(&bytes) {
                    return error_results(secrets, error);
                }

                // All secrets synced in one request
                secrets
                    .keys()
                    .map(|key| SyncResult {
                        key: key.clone(),
                        status: SyncStatus::Updated, // Upsert = create or update
                    })
                    .collect()
            } else {
                let status = r.status();
                secrets
                    .keys()
                    .map(|key| SyncResult {
                        key: key.clone(),
                        status: SyncStatus::Error(format!(
                            "Railway variable upsert request failed (HTTP {status})"
                        )),
                    })
                    .collect()
            }
        }
        Err(_) => error_results(
            secrets,
            "Railway variable upsert request failed".to_string(),
        ),
    }
}

fn error_results(secrets: &BTreeMap<String, String>, error: String) -> Vec<SyncResult> {
    secrets
        .keys()
        .map(|key| SyncResult {
            key: key.clone(),
            status: SyncStatus::Error(error.clone()),
        })
        .collect()
}

#[derive(Deserialize)]
struct RailwayMutationResponse {
    #[serde(default)]
    data: Option<RailwayMutationData>,
    #[serde(default)]
    errors: Option<serde::de::IgnoredAny>,
}

#[derive(Deserialize)]
struct RailwayMutationData {
    #[serde(rename = "variableCollectionUpsert")]
    variable_collection_upsert: bool,
}

fn parse_railway_mutation_response(bytes: &[u8]) -> std::result::Result<(), String> {
    let response: RailwayMutationResponse = serde_json::from_slice(bytes)
        .map_err(|_| "Railway mutation response was invalid".to_string())?;
    if response.errors.is_some() {
        return Err("Railway mutation returned GraphQL errors".to_string());
    }
    if response
        .data
        .is_none_or(|data| !data.variable_collection_upsert)
    {
        return Err("Railway mutation did not confirm the requested upsert".to_string());
    }
    Ok(())
}

// ── Pull Functions ───────────────────────────────────────────────────

/// Pull secrets from Vercel into a local map.
pub async fn pull_from_vercel(
    token: &str,
    project_id: &str,
) -> std::result::Result<BTreeMap<String, Zeroizing<String>>, String> {
    let client = provider_http::async_client()?;

    // Use decrypt=true to get actual values
    let resp = client
        .get(format!(
            "https://api.vercel.com/v9/projects/{project_id}/env?decrypt=true"
        ))
        .bearer_auth(token)
        .send()
        .await
        .map_err(|_| "Vercel pull request failed".to_string())?;

    if !resp.status().is_success() {
        let status = resp.status();
        return Err(format!("Vercel pull request failed (HTTP {status})"));
    }

    let bytes = provider_http::read_bounded_response(resp, "Vercel pull").await?;
    let data: VercelEnvListResponse = serde_json::from_slice(&bytes)
        .map_err(|_| "Vercel pull response was invalid".to_string())?;

    let mut secrets = BTreeMap::new();
    for env_var in data.envs {
        if let Some(value) = env_var.value {
            let value = value.into_zeroizing();
            if !value.is_empty() {
                secrets.insert(env_var.key, value);
            }
        }
    }

    Ok(secrets)
}

/// Pull secrets from Railway into a local map.
pub async fn pull_from_railway(
    token: &str,
    project_id: &str,
    environment_id: &str,
    service_id: Option<&str>,
) -> std::result::Result<BTreeMap<String, Zeroizing<String>>, String> {
    let client = provider_http::async_client()?;

    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct PullVariables<'a> {
        project_id: &'a str,
        environment_id: &'a str,
        #[serde(skip_serializing_if = "Option::is_none")]
        service_id: Option<&'a str>,
    }
    #[derive(Serialize)]
    struct PullRequest<'a> {
        query: &'static str,
        variables: PullVariables<'a>,
    }

    let query = if service_id.is_some() {
        "query($projectId: String!, $environmentId: String!, $serviceId: String!) { variables(projectId: $projectId, environmentId: $environmentId, serviceId: $serviceId) }"
    } else {
        "query($projectId: String!, $environmentId: String!) { variables(projectId: $projectId, environmentId: $environmentId) }"
    };

    let body = PullRequest {
        query,
        variables: PullVariables {
            project_id,
            environment_id,
            service_id,
        },
    };

    let resp = client
        .post("https://backboard.railway.com/graphql/v2")
        .bearer_auth(token)
        .json(&body)
        .send()
        .await
        .map_err(|_| "Railway pull request failed".to_string())?;

    if !resp.status().is_success() {
        let status = resp.status();
        return Err(format!("Railway pull request failed (HTTP {status})"));
    }

    let bytes = provider_http::read_bounded_response(resp, "Railway pull").await?;
    parse_railway_pull_response(&bytes)
}

#[derive(Deserialize)]
struct PulledSecret(String);

impl PulledSecret {
    fn into_zeroizing(mut self) -> Zeroizing<String> {
        Zeroizing::new(std::mem::take(&mut self.0))
    }
}

impl Drop for PulledSecret {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.0.zeroize();
    }
}

#[derive(Deserialize)]
struct RailwayPullResponse {
    #[serde(default)]
    data: Option<RailwayPullData>,
    #[serde(default)]
    errors: Option<serde::de::IgnoredAny>,
}

#[derive(Deserialize)]
struct RailwayPullData {
    variables: BTreeMap<String, PulledSecret>,
}

fn parse_railway_pull_response(
    bytes: &[u8],
) -> std::result::Result<BTreeMap<String, Zeroizing<String>>, String> {
    let response: RailwayPullResponse = serde_json::from_slice(bytes)
        .map_err(|_| "Railway pull response was invalid".to_string())?;
    if response.errors.is_some() {
        return Err("Railway pull returned GraphQL errors".to_string());
    }
    let data = response
        .data
        .ok_or_else(|| "Railway pull did not return data.variables".to_string())?;
    Ok(data
        .variables
        .into_iter()
        .filter_map(|(name, value)| {
            let value = value.into_zeroizing();
            (!value.is_empty()).then_some((name, value))
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_secrets(keys: &[&str]) -> BTreeMap<String, String> {
        keys.iter()
            .map(|k| (k.to_string(), "dummy".to_string()))
            .collect()
    }

    #[test]
    fn filter_empty_patterns_passes_all() {
        let secrets = make_secrets(&["STRIPE_KEY", "OPENAI_KEY", "DATABASE_URL"]);
        let filtered = filter_by_only(&secrets, &[]);
        assert_eq!(filtered.len(), 3);
    }

    #[test]
    fn filter_stripe_glob_matches_only_stripe() {
        let secrets = make_secrets(&["STRIPE_KEY", "STRIPE_WEBHOOK_SECRET", "OPENAI_KEY"]);
        let patterns = vec!["STRIPE_*".to_string()];
        let filtered = filter_by_only(&secrets, &patterns);
        assert_eq!(filtered.len(), 2);
        assert!(filtered.contains_key("STRIPE_KEY"));
        assert!(filtered.contains_key("STRIPE_WEBHOOK_SECRET"));
        assert!(!filtered.contains_key("OPENAI_KEY"));
    }

    #[test]
    fn filter_key_suffix_glob() {
        let secrets = make_secrets(&["STRIPE_KEY", "OPENAI_KEY", "DATABASE_URL"]);
        let patterns = vec!["*_KEY".to_string()];
        let filtered = filter_by_only(&secrets, &patterns);
        assert_eq!(filtered.len(), 2);
        assert!(filtered.contains_key("STRIPE_KEY"));
        assert!(filtered.contains_key("OPENAI_KEY"));
        assert!(!filtered.contains_key("DATABASE_URL"));
    }

    #[test]
    fn filter_multiple_patterns_are_ored() {
        let secrets = make_secrets(&["STRIPE_KEY", "OPENAI_KEY", "DATABASE_URL"]);
        let patterns = vec!["STRIPE_*".to_string(), "DATABASE_*".to_string()];
        let filtered = filter_by_only(&secrets, &patterns);
        assert_eq!(filtered.len(), 2);
        assert!(filtered.contains_key("STRIPE_KEY"));
        assert!(filtered.contains_key("DATABASE_URL"));
        assert!(!filtered.contains_key("OPENAI_KEY"));
    }

    #[test]
    fn filter_no_matches_returns_empty() {
        let secrets = make_secrets(&["STRIPE_KEY", "OPENAI_KEY"]);
        let patterns = vec!["RAILWAY_*".to_string()];
        let filtered = filter_by_only(&secrets, &patterns);
        assert!(filtered.is_empty());
    }

    #[test]
    fn validate_only_patterns_reports_invalid_globs() {
        let invalid = validate_only_patterns(&["[".to_string(), "STRIPE_*".to_string()]);
        assert_eq!(invalid.len(), 1);
        assert_eq!(invalid[0].0, "[");
    }

    #[test]
    fn railway_secret_echo_is_ignored_and_never_enters_error() {
        let bytes = br#"{"data":null,"errors":[{"message":"echoed-secret-value"}]}"#;
        let error = parse_railway_mutation_response(bytes).unwrap_err();
        assert_eq!(error, "Railway mutation returned GraphQL errors");
        assert!(!error.contains("echoed-secret-value"));
    }

    #[test]
    fn railway_requires_exact_positive_success_field() {
        assert!(parse_railway_mutation_response(br#"{"data":{}}"#).is_err());
        assert!(
            parse_railway_mutation_response(br#"{"data":{"variableCollectionUpsert":false}}"#)
                .is_err()
        );
        assert!(
            parse_railway_mutation_response(br#"{"data":{"variableCollectionUpsert":true}}"#)
                .is_ok()
        );
    }

    #[tokio::test]
    async fn provider_response_content_length_is_bounded_before_read() {
        use std::io::{Read, Write};
        use std::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0_u8; 1024];
            let _ = stream.read(&mut request);
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                provider_http::MAX_PROVIDER_RESPONSE_BYTES + 1
            )
            .unwrap();
        });
        let response = reqwest::get(format!("http://{address}")).await.unwrap();
        let error = provider_http::read_bounded_response(response, "mock provider")
            .await
            .unwrap_err();
        assert!(error.contains("exceeded"));
        server.join().unwrap();
    }

    #[test]
    fn railway_pull_secret_echo_in_errors_is_never_formatted() {
        let error = parse_railway_pull_response(
            br#"{"data":null,"errors":[{"message":"provider-echoed-secret"}]}"#,
        )
        .unwrap_err();
        assert_eq!(error, "Railway pull returned GraphQL errors");
        assert!(!error.contains("provider-echoed-secret"));
    }

    #[test]
    fn railway_pull_returns_zeroizing_values() {
        let pulled = parse_railway_pull_response(
            br#"{"data":{"variables":{"API_KEY":"secret-value","EMPTY":""}}}"#,
        )
        .unwrap();
        let value: &Zeroizing<String> = pulled.get("API_KEY").unwrap();
        assert_eq!(value.as_str(), "secret-value");
        assert!(!pulled.contains_key("EMPTY"));
    }
}
