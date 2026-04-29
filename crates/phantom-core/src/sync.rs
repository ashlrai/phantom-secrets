use crate::error::{PhantomError, Result};
use glob::Pattern;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

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
/// skipped — a warning is emitted via `tracing::warn!`.
pub fn filter_by_only<'a>(
    secrets: &'a BTreeMap<String, String>,
    patterns: &[String],
) -> BTreeMap<String, &'a String> {
    if patterns.is_empty() {
        // No filter — pass everything through.
        return secrets.iter().map(|(k, v)| (k.clone(), v)).collect();
    }

    // Pre-compile patterns; skip any that are invalid glob syntax.
    let compiled: Vec<Pattern> = patterns
        .iter()
        .filter_map(|p| match Pattern::new(p) {
            Ok(pat) => Some(pat),
            Err(e) => {
                tracing::warn!("Ignoring invalid --only pattern {:?}: {}", p, e);
                None
            }
        })
        .collect();

    secrets
        .iter()
        .filter(|(key, _)| compiled.iter().any(|pat| pat.matches(key)))
        .map(|(k, v)| (k.clone(), v))
        .collect()
}

/// Sync secrets to Vercel using their REST API.
pub async fn sync_to_vercel(
    token: &str,
    project_id: &str,
    secrets: &BTreeMap<String, String>,
    targets: &[String],
) -> Vec<SyncResult> {
    let client = reqwest::Client::new();
    let mut results = Vec::new();

    // First, list existing env vars to know what to update vs create
    let existing = list_vercel_env_vars(&client, token, project_id).await;

    for (key, value) in secrets {
        let target_array: Vec<&str> = targets.iter().map(|s| s.as_str()).collect();

        // Check if this key already exists
        let existing_id = existing
            .as_ref()
            .ok()
            .and_then(|vars| vars.iter().find(|v| v.key == *key).map(|v| v.id.clone()));

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
struct VercelEnvVar {
    id: String,
    key: String,
    #[serde(default)]
    value: Option<String>,
}

#[derive(Debug, Deserialize)]
struct VercelEnvListResponse {
    envs: Vec<VercelEnvVar>,
}

async fn list_vercel_env_vars(
    client: &reqwest::Client,
    token: &str,
    project_id: &str,
) -> std::result::Result<Vec<VercelEnvVar>, String> {
    let resp = client
        .get(format!(
            "https://api.vercel.com/v9/projects/{project_id}/env"
        ))
        .bearer_auth(token)
        .send()
        .await
        .map_err(|e| format!("Request failed: {e}"))?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(format!("Vercel API error ({status}): {body}"));
    }

    let data: VercelEnvListResponse = resp.json().await.map_err(|e| format!("Parse error: {e}"))?;
    Ok(data.envs)
}

async fn create_vercel_env_var(
    client: &reqwest::Client,
    token: &str,
    project_id: &str,
    key: &str,
    value: &str,
    targets: &[&str],
) -> std::result::Result<(), String> {
    let body = serde_json::json!({
        "key": key,
        "value": value,
        "type": "encrypted",
        "target": targets,
    });

    let resp = client
        .post(format!(
            "https://api.vercel.com/v10/projects/{project_id}/env"
        ))
        .bearer_auth(token)
        .json(&body)
        .send()
        .await
        .map_err(|e| format!("Request failed: {e}"))?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(format!("Vercel API error ({status}): {body}"));
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
    let body = serde_json::json!({
        "value": value,
    });

    let resp = client
        .patch(format!(
            "https://api.vercel.com/v9/projects/{project_id}/env/{env_id}"
        ))
        .bearer_auth(token)
        .json(&body)
        .send()
        .await
        .map_err(|e| format!("Request failed: {e}"))?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(format!("Vercel API error ({status}): {body}"));
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
    let client = reqwest::Client::new();

    // Use GraphQL variables (not string interpolation) to prevent injection
    let mut input = serde_json::json!({
        "projectId": project_id,
        "environmentId": environment_id,
        "variables": secrets,
    });
    if let Some(svc_id) = service_id {
        input["serviceId"] = serde_json::json!(svc_id);
    }

    let body = serde_json::json!({
        "query": "mutation($input: VariableCollectionUpsertInput!) { variableCollectionUpsert(input: $input) }",
        "variables": { "input": input },
    });

    let resp = client
        .post("https://backboard.railway.com/graphql/v2")
        .bearer_auth(token)
        .json(&body)
        .send()
        .await;

    match resp {
        Ok(r) => {
            if r.status().is_success() {
                let body_text = r.text().await.unwrap_or_default();

                // Check for GraphQL errors
                if body_text.contains("\"errors\"") {
                    return secrets
                        .keys()
                        .map(|key| SyncResult {
                            key: key.clone(),
                            status: SyncStatus::Error(format!("GraphQL error: {body_text}")),
                        })
                        .collect();
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
                let body_text = r.text().await.unwrap_or_default();
                secrets
                    .keys()
                    .map(|key| SyncResult {
                        key: key.clone(),
                        status: SyncStatus::Error(format!(
                            "Railway API error ({status}): {body_text}"
                        )),
                    })
                    .collect()
            }
        }
        Err(e) => secrets
            .keys()
            .map(|key| SyncResult {
                key: key.clone(),
                status: SyncStatus::Error(format!("Request failed: {e}")),
            })
            .collect(),
    }
}

// ── Pull Functions ───────────────────────────────────────────────────

/// Pull secrets from Vercel into a local map.
pub async fn pull_from_vercel(
    token: &str,
    project_id: &str,
) -> std::result::Result<BTreeMap<String, String>, String> {
    let client = reqwest::Client::new();

    // Use decrypt=true to get actual values
    let resp = client
        .get(format!(
            "https://api.vercel.com/v9/projects/{project_id}/env?decrypt=true"
        ))
        .bearer_auth(token)
        .send()
        .await
        .map_err(|e| format!("Request failed: {e}"))?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(format!("Vercel API error ({status}): {body}"));
    }

    let data: VercelEnvListResponse = resp.json().await.map_err(|e| format!("Parse error: {e}"))?;

    let mut secrets = BTreeMap::new();
    for env_var in data.envs {
        if let Some(value) = env_var.value {
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
) -> std::result::Result<BTreeMap<String, String>, String> {
    let client = reqwest::Client::new();

    // Use GraphQL variables to prevent injection
    let mut vars = serde_json::json!({
        "projectId": project_id,
        "environmentId": environment_id,
    });
    if let Some(svc_id) = service_id {
        vars["serviceId"] = serde_json::json!(svc_id);
    }

    let query = if service_id.is_some() {
        "query($projectId: String!, $environmentId: String!, $serviceId: String!) { variables(projectId: $projectId, environmentId: $environmentId, serviceId: $serviceId) }"
    } else {
        "query($projectId: String!, $environmentId: String!) { variables(projectId: $projectId, environmentId: $environmentId) }"
    };

    let body = serde_json::json!({ "query": query, "variables": vars });

    let resp = client
        .post("https://backboard.railway.com/graphql/v2")
        .bearer_auth(token)
        .json(&body)
        .send()
        .await
        .map_err(|e| format!("Request failed: {e}"))?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body_text = resp.text().await.unwrap_or_default();
        return Err(format!("Railway API error ({status}): {body_text}"));
    }

    let resp_body: serde_json::Value =
        resp.json().await.map_err(|e| format!("Parse error: {e}"))?;

    // Check for GraphQL errors
    if let Some(errors) = resp_body.get("errors") {
        return Err(format!("GraphQL errors: {errors}"));
    }

    // Railway returns variables as a flat JSON object: { "KEY": "value", ... }
    let variables = resp_body
        .get("data")
        .and_then(|d| d.get("variables"))
        .ok_or_else(|| "Missing 'data.variables' in response".to_string())?;

    let mut secrets = BTreeMap::new();
    if let Some(obj) = variables.as_object() {
        for (key, value) in obj {
            if let Some(v) = value.as_str() {
                secrets.insert(key.clone(), v.to_string());
            }
        }
    }

    Ok(secrets)
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
}
