//! GitHub App bootstrap — the north-star "FOUR clicks, ever" path.
//!
//! [`GithubAppManifestFlow`] registers a private, least-privilege GitHub App
//! from a **manifest** (docs.github.com: "Registering a GitHub App from a
//! manifest"): it binds a loopback listener, serves a self-submitting HTML page
//! that POSTs the manifest to `github.com/settings/apps/new` (a browser cannot
//! POST a bare URL), captures the redirect `code`, and exchanges it at
//! `POST /app-manifests/{code}/conversions` for the full app credential set —
//! **App id, PEM private key, client id/secret, webhook secret**. The PEM is
//! the perpetual root; every 1-hour `ghs_` installation token thereafter is
//! minted by the shipped [`crate::rotation_provider::GitHubRotationProvider`].
//!
//! This module also closes the grants-spec gap: [`mint_app_jwt`] signs the
//! in-process RS256 App JWT from the vaulted PEM (`iss = client_id`, `exp` <10
//! min), fed to the rotation provider as the bootstrap credential. The JWT is
//! never an env var, never on disk, and is zeroized on drop.

use super::{
    guard_mock_issuance, issuance_mock_allowed, ConsentEngine, GrantType, IssuanceDeps,
    IssuanceError, IssuanceMetadata, IssuanceOutcome, IssuanceRequest, IssuedMaterial,
    MaterialKind,
};
use crate::rotation_provider::{summarize_error_body, RotationProviderConfig};
use serde::Serialize;
use std::collections::BTreeMap;
use std::time::Duration;
use zeroize::Zeroizing;

/// Fixed vault names issuance writes and rotation reads. Keeping them fixed
/// lets `phantom rotate --name <KEY> --provider github` locate the PEM +
/// client id by convention (see the rotate wiring in `phantom-cli`).
pub const GITHUB_APP_PEM_NAME: &str = "GITHUB_APP_PEM";
/// Vault name for the App client id (non-sensitive; needed for JWT `iss`).
pub const GITHUB_APP_CLIENT_ID_NAME: &str = "GITHUB_APP_CLIENT_ID";
/// Vault name for the App client secret.
pub const GITHUB_APP_CLIENT_SECRET_NAME: &str = "GITHUB_APP_CLIENT_SECRET";
/// Vault name for the App webhook secret.
pub const GITHUB_APP_WEBHOOK_SECRET_NAME: &str = "GITHUB_APP_WEBHOOK_SECRET";

/// Default consent timeout for the manifest "Create GitHub App" click.
const MANIFEST_CONSENT_TIMEOUT: Duration = Duration::from_secs(300);

// ── Manifest spec ───────────────────────────────────────────────────────────

/// The manifest Phantom submits to create the App. Built least-privilege by
/// construction: `public:false`, only `contents:write`, `pull_requests:write`,
/// `issues:write`, `metadata:read`.
#[derive(Debug, Clone)]
pub struct GithubManifestSpec {
    /// App name (GitHub requires global uniqueness; the CLI can suffix it).
    pub name: String,
    /// Homepage URL shown on the app.
    pub url: String,
    /// Requested default permissions (`permission → access`).
    pub default_permissions: BTreeMap<String, String>,
    /// Subscribed webhook events (empty by default).
    pub default_events: Vec<String>,
    /// Whether the app is public. Defaults to `false` (private).
    pub public: bool,
    /// Create the app under this org (`/organizations/{org}/settings/apps/new`)
    /// instead of the user account. Not part of the manifest JSON.
    pub org: Option<String>,
}

impl GithubManifestSpec {
    /// Build the least-privilege spec used by `phantom grant add github-app`.
    pub fn least_privilege(name: impl Into<String>, org: Option<String>) -> Self {
        let mut default_permissions = BTreeMap::new();
        default_permissions.insert("contents".to_string(), "write".to_string());
        default_permissions.insert("pull_requests".to_string(), "write".to_string());
        default_permissions.insert("issues".to_string(), "write".to_string());
        default_permissions.insert("metadata".to_string(), "read".to_string());
        Self {
            name: name.into(),
            url: "https://phm.dev".to_string(),
            default_permissions,
            default_events: Vec::new(),
            public: false,
            org,
        }
    }

    /// Serialize to the `manifest` JSON field, injecting the loopback
    /// `redirect_url` (only known after the listener binds).
    fn to_manifest_json(&self, redirect_url: &str) -> serde_json::Value {
        serde_json::json!({
            "name": self.name,
            "url": self.url,
            "redirect_url": redirect_url,
            "public": self.public,
            "default_permissions": self.default_permissions,
            "default_events": self.default_events,
        })
    }

    /// The `github.com` settings URL the manifest is POSTed to.
    fn settings_url(&self, github_web: &str, state: &str) -> String {
        match &self.org {
            Some(org) => {
                format!("{github_web}/organizations/{org}/settings/apps/new?state={state}")
            }
            None => format!("{github_web}/settings/apps/new?state={state}"),
        }
    }
}

// ── Engine ──────────────────────────────────────────────────────────────────

/// The GitHub App manifest consent engine (grant type `AppIdentity`).
pub struct GithubAppManifestFlow;

impl ConsentEngine for GithubAppManifestFlow {
    fn name(&self) -> &str {
        "github-app-manifest"
    }

    fn grant_type(&self) -> GrantType {
        GrantType::AppIdentity
    }

    fn issue(
        &self,
        req: &IssuanceRequest,
        deps: &IssuanceDeps,
    ) -> Result<IssuanceOutcome, IssuanceError> {
        // Fail closed the moment endpoints are overridden to a non-production
        // host: that is only ever the crate's unit-test harness.
        let mock = deps.endpoints.is_overridden();
        if mock {
            guard_mock_issuance()?;
        }

        let spec = req
            .app_manifest
            .clone()
            .unwrap_or_else(|| GithubManifestSpec::least_privilege("phantom-app", None));

        // 1. Bind loopback → gives the ephemeral port baked into redirect_url.
        let binding = deps.loopback.bind()?;
        let state = super::random_state();

        // 2. Build the manifest + the self-submitting launch page. A browser
        //    cannot POST a bare URL, so the loopback listener doubles as the
        //    launch page: GET / returns an auto-POSTing form to github.com.
        let manifest_json = spec.to_manifest_json(&binding.redirect_uri);
        let manifest_str = serde_json::to_string(&manifest_json).map_err(|e| {
            IssuanceError::UnexpectedResponse {
                reason: format!("failed to serialize manifest: {e}"),
            }
        })?;
        let settings_url = spec.settings_url(&deps.endpoints.github_web, &state);
        let launch_html = build_launch_page(&settings_url, &manifest_str);
        let launch_url = format!("http://127.0.0.1:{}/", binding.port);

        // 3. Open the launch page (no-op for NoBrowser / headless) and print the
        //    ONE consent artifact to stderr.
        deps.browser.open(&launch_url);
        eprintln!("Open this URL to create the GitHub App: {launch_url}");

        // 4. Capture the redirect code (Zeroizing), verify CSRF state.
        let captured = deps
            .loopback
            .wait(&state, Some(&launch_html), MANIFEST_CONSENT_TIMEOUT)?;
        if captured.state != state {
            return Err(IssuanceError::ConsentDenied);
        }
        let code = captured.code; // Zeroizing<String>

        // 5. Exchange the code for the full app credential set.
        let conv = exchange_manifest_code(deps, code.as_str())?;

        // 6. Discover installations with an in-process App JWT minted from the
        //    just-issued PEM (never printed, never vaulted, zeroized after use).
        let installation_ids = discover_installations(deps, &conv, mock);

        // 7. Assemble materials (all vaulted by the caller under phm: names).
        let mut materials = vec![
            IssuedMaterial {
                phm_name: GITHUB_APP_PEM_NAME.to_string(),
                value: conv.pem.clone(),
                kind: MaterialKind::Pem,
                sensitive: true,
            },
            IssuedMaterial {
                phm_name: GITHUB_APP_CLIENT_ID_NAME.to_string(),
                value: Zeroizing::new(conv.client_id.clone()),
                kind: MaterialKind::ClientId,
                sensitive: false,
            },
            IssuedMaterial {
                phm_name: GITHUB_APP_CLIENT_SECRET_NAME.to_string(),
                value: conv.client_secret.clone(),
                kind: MaterialKind::ClientSecret,
                sensitive: true,
            },
        ];
        if let Some(webhook) = &conv.webhook_secret {
            materials.push(IssuedMaterial {
                phm_name: GITHUB_APP_WEBHOOK_SECRET_NAME.to_string(),
                value: webhook.clone(),
                kind: MaterialKind::WebhookSecret,
                sensitive: true,
            });
        }

        // 8. Metadata (non-secret) + human next-steps.
        let mut notes = Vec::new();
        if installation_ids.is_empty() {
            notes.push(format!(
                "Install the app to start minting tokens: {}/settings/apps/{}/installations",
                deps.endpoints.github_web,
                conv.slug.as_deref().unwrap_or("<slug>")
            ));
        } else {
            notes.push(format!(
                "App installed on {} account(s). `phantom rotate --name <KEY>` now mints \
                 1-hour ghs_ tokens unattended.",
                installation_ids.len()
            ));
        }
        let metadata = IssuanceMetadata {
            display_name: spec.name.clone(),
            account: spec.org.clone(),
            app_id: conv.id,
            app_slug: conv.slug.clone(),
            installation_ids: installation_ids.clone(),
            scopes: spec.default_permissions.keys().cloned().collect(),
            expires_at: None,
            notes,
        };

        // 9. rotation_provider block: provider identity "github", api_key_env
        //    points at the vaulted PEM (rotate mints the JWT in-process from
        //    it), account_id = the first discovered installation id.
        let rotation_config = RotationProviderConfig {
            provider: "github".to_string(),
            api_key_env: Some(GITHUB_APP_PEM_NAME.to_string()),
            account_id: installation_ids.first().cloned(),
            region: None,
            timeout_secs: 30,
            enabled: true,
        };

        Ok(IssuanceOutcome {
            provider: "github".to_string(),
            grant_type: GrantType::AppIdentity,
            materials,
            rotation_config,
            metadata,
        })
    }
}

// ── Manifest exchange ───────────────────────────────────────────────────────

/// The subset of the `/app-manifests/{code}/conversions` 201 body we consume.
struct Conversion {
    id: Option<u64>,
    slug: Option<String>,
    client_id: String,
    client_secret: Zeroizing<String>,
    pem: Zeroizing<String>,
    webhook_secret: Option<Zeroizing<String>>,
}

fn exchange_manifest_code(deps: &IssuanceDeps, code: &str) -> Result<Conversion, IssuanceError> {
    let url = format!(
        "{}/app-manifests/{code}/conversions",
        deps.endpoints.github_api
    );
    let response = deps
        .http
        .post(&url)
        .header("Accept", "application/vnd.github+json")
        .header("X-GitHub-Api-Version", "2022-11-28")
        .header("User-Agent", "phantom-secrets/0.1")
        .send()
        .map_err(|e| IssuanceError::Network {
            reason: e.to_string(),
        })?;

    let status = response.status().as_u16();
    if status != 201 {
        let body = response.text().unwrap_or_default();
        return Err(IssuanceError::Exchange {
            status,
            reason: summarize_error_body(&body),
        });
    }

    let body: serde_json::Value =
        response
            .json()
            .map_err(|e| IssuanceError::UnexpectedResponse {
                reason: e.to_string(),
            })?;

    let client_id = body
        .get("client_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| IssuanceError::UnexpectedResponse {
            reason: "missing 'client_id' in manifest conversion response".to_string(),
        })?
        .to_string();
    let client_secret = body
        .get("client_secret")
        .and_then(|v| v.as_str())
        .ok_or_else(|| IssuanceError::UnexpectedResponse {
            reason: "missing 'client_secret' in manifest conversion response".to_string(),
        })?
        .to_string();
    let pem = body
        .get("pem")
        .and_then(|v| v.as_str())
        .ok_or_else(|| IssuanceError::UnexpectedResponse {
            reason: "missing 'pem' in manifest conversion response".to_string(),
        })?
        .to_string();

    Ok(Conversion {
        id: body.get("id").and_then(|v| v.as_u64()),
        slug: body
            .get("slug")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string()),
        client_id,
        client_secret: Zeroizing::new(client_secret),
        pem: Zeroizing::new(pem),
        webhook_secret: body
            .get("webhook_secret")
            .and_then(|v| v.as_str())
            .map(|s| Zeroizing::new(s.to_string())),
    })
}

/// Discover installation ids via `GET /app/installations`, authenticated with a
/// fresh in-process App JWT. Non-fatal: a failure (or none installed) simply
/// yields an empty list and a "click Install" note upstream.
fn discover_installations(deps: &IssuanceDeps, conv: &Conversion, mock: bool) -> Vec<String> {
    // In mock mode the returned PEM is a fixture, not a real RSA key, so we do
    // not attempt RS256 signing; the mock server does not verify the bearer.
    let jwt = if mock && issuance_mock_allowed() {
        Zeroizing::new("mock-app-jwt".to_string())
    } else {
        match mint_app_jwt(&conv.pem, &conv.client_id) {
            Ok(jwt) => jwt,
            Err(_) => return Vec::new(),
        }
    };

    let url = format!("{}/app/installations", deps.endpoints.github_api);
    let response = deps
        .http
        .get(&url)
        .header("Authorization", format!("Bearer {}", jwt.as_str()))
        .header("Accept", "application/vnd.github+json")
        .header("X-GitHub-Api-Version", "2022-11-28")
        .header("User-Agent", "phantom-secrets/0.1")
        .send();

    let Ok(response) = response else {
        return Vec::new();
    };
    if !response.status().is_success() {
        return Vec::new();
    }
    let Ok(body) = response.json::<serde_json::Value>() else {
        return Vec::new();
    };
    body.as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|inst| {
                    inst.get("id").map(|id| match id {
                        serde_json::Value::Number(n) => n.to_string(),
                        serde_json::Value::String(s) => s.clone(),
                        other => other.to_string(),
                    })
                })
                .collect()
        })
        .unwrap_or_default()
}

// ── App JWT minting ─────────────────────────────────────────────────────────

/// Mint a fresh RS256 App JWT from the vaulted PEM.
///
/// `iss = client_id`, `iat = now - 60` (clock-skew slack, per GitHub docs),
/// `exp = now + 540` (<10 min). Returned in `Zeroizing`; the caller feeds it to
/// [`crate::rotation_provider::auto_sync_rotation_with_bootstrap`] as the
/// bootstrap credential and drops it immediately. The JWT is never an env var,
/// never on disk.
pub fn mint_app_jwt(
    pem: &Zeroizing<String>,
    client_id: &str,
) -> Result<Zeroizing<String>, IssuanceError> {
    use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};

    #[derive(Serialize)]
    struct Claims {
        iat: u64,
        exp: u64,
        iss: String,
    }

    let now = now_unix();
    let claims = Claims {
        iat: now.saturating_sub(60),
        exp: now + 540,
        iss: client_id.to_string(),
    };

    let key = EncodingKey::from_rsa_pem(pem.as_bytes()).map_err(|e| {
        IssuanceError::UnexpectedResponse {
            reason: format!("invalid GitHub App private key: {e}"),
        }
    })?;
    let token = encode(&Header::new(Algorithm::RS256), &claims, &key).map_err(|e| {
        IssuanceError::UnexpectedResponse {
            reason: format!("App JWT signing failed: {e}"),
        }
    })?;
    Ok(Zeroizing::new(token))
}

// ── Helpers ─────────────────────────────────────────────────────────────────

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Build the self-submitting HTML launch page served on the loopback `GET /`.
/// The form auto-POSTs the manifest to GitHub; a browser cannot POST a bare URL
/// so this page is the mechanism. Fully self-contained (no external assets).
fn build_launch_page(settings_url: &str, manifest_json: &str) -> String {
    let escaped_manifest = html_attr_escape(manifest_json);
    let escaped_action = html_attr_escape(settings_url);
    format!(
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>Phantom · Create GitHub App</title></head>\
         <body onload=\"document.forms[0].submit()\">\
         <form method=\"post\" action=\"{escaped_action}\">\
         <input type=\"hidden\" name=\"manifest\" value=\"{escaped_manifest}\">\
         <noscript><button type=\"submit\">Create GitHub App</button></noscript>\
         </form>\
         <p>Redirecting to GitHub to create your Phantom app…</p>\
         </body></html>"
    )
}

/// Escape a string for safe inclusion in an HTML double-quoted attribute.
fn html_attr_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Generate a fresh, throwaway 2048-bit RSA key at runtime and serialize it
    /// to a PKCS#1 PEM — NOT a real credential and never committed. This keeps
    /// the JWT tests hermetic and offline without a private-key fixture on disk.
    /// (Kept fast via the `opt-level` overrides on the bignum crates in the
    /// workspace `Cargo.toml`; see the note there.)
    fn generate_test_pem() -> Zeroizing<String> {
        use rsa::pkcs1::{EncodeRsaPrivateKey, LineEnding};
        let mut rng = rand::thread_rng();
        let key = rsa::RsaPrivateKey::new(&mut rng, 2048).expect("RSA keygen");
        key.to_pkcs1_pem(LineEnding::LF)
            .expect("serialize PKCS#1 PEM")
    }

    #[test]
    fn least_privilege_manifest_shape() {
        let spec = GithubManifestSpec::least_privilege("phantom-test", None);
        assert!(!spec.public);
        assert_eq!(spec.default_permissions.get("contents").unwrap(), "write");
        assert_eq!(spec.default_permissions.get("metadata").unwrap(), "read");
        let json = spec.to_manifest_json("http://127.0.0.1:12345/callback");
        assert_eq!(json["redirect_url"], "http://127.0.0.1:12345/callback");
        assert_eq!(json["public"], false);
    }

    #[test]
    fn settings_url_switches_on_org() {
        let user = GithubManifestSpec::least_privilege("a", None);
        assert_eq!(
            user.settings_url("https://github.com", "S"),
            "https://github.com/settings/apps/new?state=S"
        );
        let org = GithubManifestSpec::least_privilege("a", Some("ashlrai".to_string()));
        assert_eq!(
            org.settings_url("https://github.com", "S"),
            "https://github.com/organizations/ashlrai/settings/apps/new?state=S"
        );
    }

    #[test]
    fn launch_page_escapes_manifest_json() {
        let page = build_launch_page(
            "https://github.com/settings/apps/new?state=x",
            r#"{"a":"b<>&\""}"#,
        );
        assert!(page.contains("document.forms[0].submit()"));
        assert!(page.contains("name=\"manifest\""));
        // No raw angle brackets from the JSON payload survive into the attr.
        assert!(page.contains("&lt;"));
        assert!(page.contains("&quot;"));
    }

    #[test]
    fn mint_app_jwt_produces_three_part_rs256_token() {
        let pem = generate_test_pem();
        let jwt = mint_app_jwt(&pem, "Iv1.client123").unwrap();
        let parts: Vec<&str> = jwt.split('.').collect();
        assert_eq!(parts.len(), 3, "JWT must have header.payload.signature");
        // Header decodes to RS256.
        use base64::Engine;
        let header = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(parts[0])
            .unwrap();
        let header: serde_json::Value = serde_json::from_slice(&header).unwrap();
        assert_eq!(header["alg"], "RS256");
    }

    #[test]
    fn mint_app_jwt_rejects_garbage_pem() {
        // PEM-shaped but not a real key. The armor is assembled at runtime so no
        // literal `BEGIN … PRIVATE KEY` header is committed to the source tree.
        let label = "RSA PRIVATE KEY";
        let pem = Zeroizing::new(format!(
            "-----BEGIN {label}-----\nnot-a-key\n-----END {label}-----"
        ));
        assert!(mint_app_jwt(&pem, "Iv1.x").is_err());
    }
}
