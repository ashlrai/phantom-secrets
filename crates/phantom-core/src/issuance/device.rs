//! `DeviceFlowEngine` — RFC 8628 device authorization grant.
//!
//! The headless / no-browser path: the human opens a `verification_uri` on any
//! device, types the `user_code`, and approves. No loopback, no redirect URI.
//! The **refresh token** is the durable root (GitHub App device flow yields a
//! `ghr_` that rotates on every use). This is the fallback the CLI names when
//! PKCE loopback is unreachable.
//!
//! Shares the `refresh_token_name` / `now_unix` / `map_oauth_error` helpers with
//! [`super::pkce`] so both OAuth engines emit an identical `OauthRefresh`
//! outcome shape.

use super::pkce::{map_oauth_error, now_unix, refresh_token_name};
use super::{
    guard_mock_issuance, ConsentEngine, GrantType, IssuanceDeps, IssuanceError, IssuanceMetadata,
    IssuanceOutcome, IssuanceRequest, IssuedMaterial, MaterialKind,
};
use crate::rotation_provider::{summarize_error_body, RotationProviderConfig};
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

/// Device authorization grant engine (grant type `OauthRefresh`).
pub struct DeviceFlowEngine;

impl ConsentEngine for DeviceFlowEngine {
    fn name(&self) -> &str {
        "device-flow"
    }

    fn grant_type(&self) -> GrantType {
        GrantType::OauthRefresh
    }

    fn issue(
        &self,
        req: &IssuanceRequest,
        deps: &IssuanceDeps,
    ) -> Result<IssuanceOutcome, IssuanceError> {
        if deps.endpoints.overridden {
            guard_mock_issuance()?;
        }
        if deps.endpoints.device_code.is_empty() || deps.endpoints.token.is_empty() {
            return Err(IssuanceError::NotSupported {
                reason: format!(
                    "no device-code/token endpoints known for provider '{}'; set \
                     PHANTOM_OAUTH_DEVICE_BASE / PHANTOM_OAUTH_TOKEN_BASE",
                    req.provider
                ),
            });
        }
        let client_id = req
            .client_id
            .as_deref()
            .ok_or_else(|| IssuanceError::NotSupported {
                reason: "the device flow requires --client-id (the OAuth app's client id)"
                    .to_string(),
            })?;
        let mock = deps.endpoints.overridden;

        // 1. Request a device code.
        let scope = req.scopes.join(" ");
        let response = deps
            .http
            .post(&deps.endpoints.device_code)
            .header("Accept", "application/json")
            .header("User-Agent", "phantom-secrets/0.1")
            .form(&[("client_id", client_id), ("scope", scope.as_str())])
            .send()
            .map_err(|e| IssuanceError::Network {
                reason: e.to_string(),
            })?;
        let status = response.status().as_u16();
        if !(200..300).contains(&status) {
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

        let device_code = Zeroizing::new(
            body.get("device_code")
                .and_then(|v| v.as_str())
                .ok_or_else(|| IssuanceError::UnexpectedResponse {
                    reason: "device-code response missing device_code".to_string(),
                })?
                .to_string(),
        );
        let user_code = body
            .get("user_code")
            .and_then(|v| v.as_str())
            .unwrap_or("<code>");
        let verification_uri = body
            .get("verification_uri")
            .and_then(|v| v.as_str())
            .unwrap_or("<verification_uri>");
        let expires_in = body
            .get("expires_in")
            .and_then(|v| v.as_u64())
            .unwrap_or(600);
        let mut interval = body.get("interval").and_then(|v| v.as_u64()).unwrap_or(5);

        // 2. Print exactly the two non-secret facts.
        eprintln!("To authorize, visit {verification_uri} and enter code: {user_code}");

        // 3. Poll the token endpoint with a monotonic deadline.
        let deadline = Instant::now() + Duration::from_secs(expires_in);
        loop {
            if Instant::now() >= deadline {
                return Err(IssuanceError::ConsentTimeout {
                    waited_secs: expires_in,
                });
            }
            sleep_interval(interval, mock);

            let poll = deps
                .http
                .post(&deps.endpoints.token)
                .header("Accept", "application/json")
                .header("User-Agent", "phantom-secrets/0.1")
                .form(&[
                    ("client_id", client_id),
                    ("device_code", device_code.as_str()),
                    ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
                ])
                .send()
                .map_err(|e| IssuanceError::Network {
                    reason: e.to_string(),
                })?;

            let poll_body: serde_json::Value =
                poll.json().map_err(|e| IssuanceError::UnexpectedResponse {
                    reason: e.to_string(),
                })?;

            if let Some(err) = poll_body.get("error").and_then(|v| v.as_str()) {
                match err {
                    "authorization_pending" => continue,
                    "slow_down" => {
                        interval = next_interval(interval, true);
                        continue;
                    }
                    "expired_token" => {
                        return Err(IssuanceError::ConsentTimeout {
                            waited_secs: expires_in,
                        })
                    }
                    other => return Err(map_oauth_error(other, 400)),
                }
            }

            // Success — the body carries the tokens.
            return build_device_outcome(&req.provider, &req.scopes, &poll_body);
        }
    }
}

/// Build the `OauthRefresh` outcome (refresh token = durable root; access token
/// is metadata only). Mirrors the shape [`super::pkce`] produces.
fn build_device_outcome(
    provider: &str,
    scopes: &[String],
    body: &serde_json::Value,
) -> Result<IssuanceOutcome, IssuanceError> {
    let refresh_token = body
        .get("refresh_token")
        .and_then(|v| v.as_str())
        .ok_or_else(|| IssuanceError::UnexpectedResponse {
            reason: "token response has no refresh_token — request an offline/refresh scope for a \
                     durable grant"
                .to_string(),
        })?;
    let expires_at = body
        .get("refresh_token_expires_in")
        .and_then(|v| v.as_u64())
        .map(|secs| now_unix().saturating_add(secs));

    let phm_name = refresh_token_name(provider);
    let materials = vec![IssuedMaterial {
        phm_name: phm_name.clone(),
        value: Zeroizing::new(refresh_token.to_string()),
        kind: MaterialKind::RefreshToken,
        sensitive: true,
    }];
    let rotation_config = RotationProviderConfig {
        provider: provider.to_string(),
        api_key_env: Some(phm_name),
        enabled: true,
        ..Default::default()
    };
    Ok(IssuanceOutcome {
        provider: provider.to_string(),
        grant_type: GrantType::OauthRefresh,
        materials,
        rotation_config,
        metadata: IssuanceMetadata {
            display_name: provider.to_string(),
            scopes: scopes.to_vec(),
            expires_at,
            ..Default::default()
        },
    })
}

/// RFC 8628: on `slow_down` the client MUST increase the interval by 5 seconds.
pub(crate) fn next_interval(current: u64, slow_down: bool) -> u64 {
    if slow_down {
        current + 5
    } else {
        current
    }
}

/// Sleep `interval` seconds between polls — skipped in mock mode so tests run
/// in milliseconds.
fn sleep_interval(interval: u64, mock: bool) {
    if mock {
        return;
    }
    std::thread::sleep(Duration::from_secs(interval));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slow_down_bumps_interval_by_five() {
        assert_eq!(next_interval(5, true), 10);
        assert_eq!(next_interval(10, true), 15);
        assert_eq!(next_interval(5, false), 5);
    }

    #[test]
    fn build_device_outcome_extracts_refresh_root() {
        let body = serde_json::json!({
            "access_token": "ghu_access",
            "refresh_token": "ghr_root",
        });
        let out = build_device_outcome("github", &["repo".to_string()], &body).unwrap();
        assert_eq!(out.materials[0].phm_name, "GITHUB_REFRESH_TOKEN");
        assert_eq!(out.materials[0].value.as_str(), "ghr_root");
    }
}
