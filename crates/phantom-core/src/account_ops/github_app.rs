//! GitHub App installation-token adapter for [`super::AccountOps`].
//!
//! Mints, revokes and inspects GitHub App installation access tokens through
//! the documented REST API:
//!
//! - create / rotate: `POST /app/installations/{installation_id}/access_tokens`
//!   with an App JWT. Tokens expire one hour after creation.
//! - revoke (and compensation): `DELETE /installation/token`, authenticated
//!   with the token being revoked.
//! - status: `GET /app/installations/{installation_id}` with an App JWT.
//!
//! The App JWT is signed in process from the vaulted PEM by
//! [`crate::issuance::mint_app_jwt`] and lives only in [`Zeroizing`] memory.
//! Error reasons carry the HTTP status and the allowlisted fields from
//! [`crate::rotation_provider::summarize_error_body`], never a body or value.

use super::{
    meta_value, AccountOp, AccountProvider, CredentialSource, Issued, OpError, OpRequest,
    ProviderReply,
};
use crate::rotation_provider::summarize_error_body;
use serde::Deserialize;
use std::collections::BTreeMap;
use std::fmt;
use std::time::Duration;
use zeroize::Zeroizing;

/// Registered provider name.
pub const GITHUB_APP_PROVIDER: &str = "github-app";
/// Fixed API origin. There is no runtime override.
pub const GITHUB_API_ORIGIN: &str = "https://api.github.com";
/// REST API version header value.
pub const GITHUB_API_VERSION: &str = "2022-11-28";
/// Installation tokens expire one hour after creation.
pub const INSTALLATION_TOKEN_TTL_SECS: u64 = 3_600;
/// Vault namespace this adapter issues into and revokes from.
pub const INSTALL_TOKEN_NAME_PREFIX: &str = "GITHUB_APP_INSTALL_";
/// Prefix GitHub uses for installation access tokens.
const INSTALL_TOKEN_PREFIX: &str = "ghs_";

/// True when `value` has the installation-token shape: the `ghs_` prefix,
/// then only token characters (the stateless format adds `_` and `.`).
pub(crate) fn is_installation_token(value: &str) -> bool {
    value.len() > INSTALL_TOKEN_PREFIX.len() + 8
        && value.len() <= 4096
        && value.starts_with(INSTALL_TOKEN_PREFIX)
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.' || c == '-')
}

/// The narrow scope every minted token is restricted to. Both parts are
/// required and must be non-empty; there is no "whole installation" default.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GithubTokenScope {
    /// Repository names (without owner) the token may access.
    pub repositories: Vec<String>,
    /// Permission name to level, e.g. `contents` -> `write`.
    pub permissions: BTreeMap<String, String>,
}

impl GithubTokenScope {
    /// Refuse an empty or malformed scope.
    pub fn validate(&self) -> Result<(), OpError> {
        if self.repositories.is_empty() || self.repositories.len() > 500 {
            return Err(OpError::new(
                "token scope needs 1 to 500 repositories; refusing an unscoped token",
            ));
        }
        for r in &self.repositories {
            let ok = !r.is_empty()
                && r.len() <= 100
                && r.chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
                && r != "."
                && r != "..";
            if !ok {
                return Err(OpError::new("token scope has a malformed repository name"));
            }
        }
        if self.permissions.is_empty() {
            return Err(OpError::new(
                "token scope needs at least one permission; refusing an unscoped token",
            ));
        }
        for (k, v) in &self.permissions {
            let name_ok = !k.is_empty()
                && k.len() <= 64
                && k.chars().all(|c| c.is_ascii_lowercase() || c == '_');
            if !name_ok || !matches!(v.as_str(), "read" | "write" | "admin") {
                return Err(OpError::new("token scope has a malformed permission"));
            }
        }
        Ok(())
    }

    /// Value-free label for the plan and the ledger.
    pub fn label(&self) -> String {
        let perms: Vec<String> = self
            .permissions
            .iter()
            .map(|(k, v)| format!("{k}:{v}"))
            .collect();
        format!(
            "repositories={} permissions={}",
            self.repositories.join(","),
            perms.join(",")
        )
    }

    fn body(&self) -> String {
        serde_json::json!({
            "repositories": self.repositories,
            "permissions": self.permissions,
        })
        .to_string()
    }
}

/// HTTP method subset this adapter uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    Get,
    Post,
    Delete,
}

/// A transport reply. `Debug` never renders the body.
pub struct HttpReply {
    pub status: u16,
    pub body: Zeroizing<Vec<u8>>,
}

impl fmt::Debug for HttpReply {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpReply")
            .field("status", &self.status)
            .field("body", &"[redacted]")
            .finish()
    }
}

/// Sends one request to [`GITHUB_API_ORIGIN`]. Tests inject a fake.
pub trait HttpTransport {
    fn send(
        &self,
        method: Method,
        path: &str,
        bearer: &Zeroizing<String>,
        body: Option<&str>,
    ) -> Result<HttpReply, OpError>;
}

/// Live HTTPS transport: https-only, no proxy, no redirects, bounded body,
/// sensitive Authorization header. Blocking; do not call inside an async
/// runtime thread.
#[derive(Debug, Default)]
pub struct GithubHttps;

impl HttpTransport for GithubHttps {
    fn send(
        &self,
        method: Method,
        path: &str,
        bearer: &Zeroizing<String>,
        body: Option<&str>,
    ) -> Result<HttpReply, OpError> {
        use reqwest::header::{HeaderValue, ACCEPT, AUTHORIZATION, CONTENT_TYPE, USER_AGENT};
        if !path.starts_with('/') || path.contains("//") || path.contains("..") {
            return Err(OpError::new("refusing a malformed GitHub API path"));
        }
        let client =
            crate::provider_http::blocking_client(Duration::from_secs(30)).map_err(OpError::new)?;
        let url = format!("{GITHUB_API_ORIGIN}{path}");
        let builder = match method {
            Method::Get => client.get(&url),
            Method::Post => client.post(&url),
            Method::Delete => client.delete(&url),
        };
        let auth = Zeroizing::new(format!("Bearer {}", bearer.as_str()));
        let mut auth_header = HeaderValue::from_str(&auth)
            .map_err(|_| OpError::new("credential is not a valid header value"))?;
        auth_header.set_sensitive(true);
        let mut builder = builder
            .header(AUTHORIZATION, auth_header)
            .header(ACCEPT, "application/vnd.github+json")
            .header("X-GitHub-Api-Version", GITHUB_API_VERSION)
            .header(USER_AGENT, "phantom-secrets-account-ops");
        if let Some(b) = body {
            builder = builder
                .header(CONTENT_TYPE, "application/json")
                .body(b.to_string());
        }
        let response = builder
            .send()
            .map_err(|_| OpError::new("GitHub API request failed (network)"))?;
        let status = response.status().as_u16();
        let body = crate::provider_http::read_bounded_blocking_response(response, "GitHub API")
            .map_err(OpError::new)?;
        Ok(HttpReply { status, body })
    }
}

/// GitHub App installation-token adapter.
pub struct GithubAppInstallationProvider {
    client_id: String,
    pem_name: String,
    scope: GithubTokenScope,
    transport: Box<dyn HttpTransport>,
}

impl GithubAppInstallationProvider {
    /// `client_id` is the App's client id (JWT `iss`, not secret). `pem_name`
    /// is the vault name of the App private key. `scope` is required; an
    /// empty scope is refused at plan time, before any provider call.
    pub fn new(
        client_id: impl Into<String>,
        pem_name: impl Into<String>,
        scope: GithubTokenScope,
        transport: Box<dyn HttpTransport>,
    ) -> Self {
        Self {
            client_id: client_id.into(),
            pem_name: pem_name.into(),
            scope,
            transport,
        }
    }

    fn installation_id(target: &str) -> Result<u64, OpError> {
        target
            .strip_prefix("installation:")
            .filter(|d| !d.is_empty() && d.len() <= 20 && d.chars().all(|c| c.is_ascii_digit()))
            .and_then(|d| d.parse::<u64>().ok())
            .ok_or_else(|| OpError::new("target must be installation:<numeric id>"))
    }

    fn app_jwt(&self, creds: &dyn CredentialSource) -> Result<Zeroizing<String>, OpError> {
        let pem = creds.read(&self.pem_name)?;
        crate::issuance::mint_app_jwt(&pem, &self.client_id)
            .map_err(|_| OpError::new("GitHub App JWT could not be signed from the vaulted key"))
    }

    fn http_error(status: u16, body: &[u8]) -> OpError {
        let text = String::from_utf8_lossy(body);
        OpError::new(format!(
            "GitHub returned HTTP {status} ({})",
            summarize_error_body(&text)
        ))
    }
}

#[derive(Deserialize)]
struct TokenReply {
    token: String,
    expires_at: String,
    #[serde(default)]
    repository_selection: Option<String>,
    #[serde(default)]
    permissions: BTreeMap<String, String>,
}

#[derive(Deserialize)]
struct InstallationReply {
    #[serde(default)]
    app_slug: Option<String>,
    #[serde(default)]
    target_type: Option<String>,
    #[serde(default)]
    repository_selection: Option<String>,
    #[serde(default)]
    suspended_at: Option<String>,
}

impl AccountProvider for GithubAppInstallationProvider {
    fn name(&self) -> &str {
        GITHUB_APP_PROVIDER
    }

    fn supports(&self, _op: AccountOp) -> bool {
        true
    }

    fn owns_name(&self, secret_name: &str) -> bool {
        secret_name.len() > INSTALL_TOKEN_NAME_PREFIX.len()
            && secret_name.starts_with(INSTALL_TOKEN_NAME_PREFIX)
            && secret_name != self.pem_name
    }

    fn plan(&self, req: &OpRequest) -> Result<BTreeMap<String, String>, OpError> {
        let id = Self::installation_id(&req.target)?;
        let mut m = BTreeMap::new();
        let (call, auth) = match req.op {
            AccountOp::Create | AccountOp::Rotate => (
                format!("POST /app/installations/{id}/access_tokens"),
                "app-jwt",
            ),
            AccountOp::Revoke => ("DELETE /installation/token".to_string(), "stored-token"),
            AccountOp::Status => (format!("GET /app/installations/{id}"), "app-jwt"),
        };
        m.insert("call".into(), call);
        m.insert("auth".into(), auth.into());
        if req.op.issues_value() {
            self.scope.validate()?;
            m.insert("ttl_secs".into(), INSTALLATION_TOKEN_TTL_SECS.to_string());
            m.insert("scope".into(), self.scope.label());
        }
        Ok(m)
    }

    fn execute(
        &self,
        req: &OpRequest,
        creds: &dyn CredentialSource,
    ) -> Result<ProviderReply, OpError> {
        let id = Self::installation_id(&req.target)?;
        match req.op {
            AccountOp::Create | AccountOp::Rotate => {
                self.scope.validate()?;
                let jwt = self.app_jwt(creds)?;
                let path = format!("/app/installations/{id}/access_tokens");
                let body = self.scope.body();
                let reply = self
                    .transport
                    .send(Method::Post, &path, &jwt, Some(&body))?;
                if reply.status != 201 {
                    return Err(Self::http_error(reply.status, &reply.body));
                }
                let parsed: TokenReply = serde_json::from_slice(&reply.body)
                    .map_err(|_| OpError::new("GitHub token reply was not the documented shape"))?;
                let value = Zeroizing::new(parsed.token);
                if value.is_empty() {
                    return Err(OpError::new("GitHub returned an empty token"));
                }
                let mut metadata = BTreeMap::new();
                metadata.insert("expires_at".into(), meta_value(&parsed.expires_at));
                if let Some(sel) = parsed.repository_selection {
                    metadata.insert("repository_selection".into(), meta_value(&sel));
                }
                if !parsed.permissions.is_empty() {
                    let perms: Vec<String> = parsed
                        .permissions
                        .iter()
                        .map(|(k, v)| format!("{}={}", meta_value(k), meta_value(v)))
                        .collect();
                    metadata.insert("permissions".into(), perms.join(","));
                }
                Ok(ProviderReply::Issued(Issued { value, metadata }))
            }
            AccountOp::Revoke => {
                let token = creds.read(&req.secret_name)?;
                if !is_installation_token(&token) {
                    return Err(OpError::new(
                        "stored value does not have the installation-token shape; not sending it",
                    ));
                }
                let reply =
                    self.transport
                        .send(Method::Delete, "/installation/token", &token, None)?;
                if reply.status != 204 {
                    return Err(Self::http_error(reply.status, &reply.body));
                }
                let mut m = BTreeMap::new();
                m.insert("revoked".into(), "true".into());
                Ok(ProviderReply::Done(m))
            }
            AccountOp::Status => {
                let jwt = self.app_jwt(creds)?;
                let path = format!("/app/installations/{id}");
                let reply = self.transport.send(Method::Get, &path, &jwt, None)?;
                if reply.status != 200 {
                    return Err(Self::http_error(reply.status, &reply.body));
                }
                let parsed: InstallationReply =
                    serde_json::from_slice(&reply.body).map_err(|_| {
                        OpError::new("GitHub installation reply was not the documented shape")
                    })?;
                let mut m = BTreeMap::new();
                if let Some(v) = parsed.app_slug {
                    m.insert("app_slug".into(), meta_value(&v));
                }
                if let Some(v) = parsed.target_type {
                    m.insert("target_type".into(), meta_value(&v));
                }
                if let Some(v) = parsed.repository_selection {
                    m.insert("repository_selection".into(), meta_value(&v));
                }
                m.insert(
                    "suspended".into(),
                    parsed.suspended_at.is_some().to_string(),
                );
                Ok(ProviderReply::Done(m))
            }
        }
    }

    fn compensate(&self, _req: &OpRequest, issued: &Zeroizing<String>) -> Result<(), OpError> {
        if !is_installation_token(issued) {
            return Err(OpError::new(
                "issued value does not have the installation-token shape; not sending it",
            ));
        }
        let reply = self
            .transport
            .send(Method::Delete, "/installation/token", issued, None)?;
        if reply.status == 204 {
            Ok(())
        } else {
            Err(Self::http_error(reply.status, &reply.body))
        }
    }
}
