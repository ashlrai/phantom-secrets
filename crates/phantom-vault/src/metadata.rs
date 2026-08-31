//! Per-secret TTL/expiry metadata for phantom-vault.
//!
//! Each secret can carry an optional [`SecretMetadata`] record that tracks
//! when it was created, last rotated, and when it expires. The
//! [`RotationPolicy`] sub-struct stores the TTL configuration so that
//! tooling can warn when a secret is approaching or past its expiry.

use serde::{Deserialize, Serialize};

/// ISO-8601 timestamp stored as seconds since the Unix epoch (u64).
pub type Timestamp = u64;

/// Returns the current time as seconds since the Unix epoch.
pub fn now_secs() -> Timestamp {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Per-secret rotation / TTL configuration stored alongside the vault entry.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RotationPolicy {
    /// Number of days before the secret expires (TTL).
    pub days_ttl: u64,
    /// Whether the secret should be auto-rotated (reserved for future use).
    #[serde(default)]
    pub auto_rotate: bool,
}

/// Access mode for a vault secret.
///
/// `ReadOnly` is set by `phantom_apply_expiry_policy` when a secret has
/// expired its TTL.  While in `ReadOnly` mode the secret can be read for
/// inspection but `phantom exec` will refuse to inject it into the
/// environment until it is rotated (which resets the mode to `ReadWrite`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum VaultMode {
    /// Normal read-write access — the secret can be injected by `phantom exec`.
    #[default]
    ReadWrite,
    /// Read-only mode — `phantom exec` will refuse to inject this secret until
    /// it is rotated.  Set automatically when a secret TTL expires and
    /// `phantom_apply_expiry_policy` is run.
    ReadOnly,
}

impl VaultMode {
    pub fn is_read_only(&self) -> bool {
        matches!(self, VaultMode::ReadOnly)
    }
}

/// Metadata attached to a single vault secret.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct SecretMetadata {
    /// Unix timestamp when the secret was first stored.
    pub created_at: Option<Timestamp>,
    /// Unix timestamp of the last rotation (token regeneration).
    pub rotated_at: Option<Timestamp>,
    /// Unix timestamp after which the secret is considered expired.
    pub expires_at: Option<Timestamp>,
    /// Rotation policy (TTL configuration).
    pub rotation_policy: Option<RotationPolicy>,
    /// Vault access mode.  Defaults to `ReadWrite`.  Set to `ReadOnly` by
    /// `phantom_apply_expiry_policy` when a secret is expired; reset to
    /// `ReadWrite` on rotation.
    #[serde(default)]
    pub vault_mode: VaultMode,
}

impl SecretMetadata {
    /// Create a new metadata record stamped with the current time.
    pub fn new_now() -> Self {
        Self {
            created_at: Some(now_secs()),
            rotated_at: None,
            expires_at: None,
            rotation_policy: None,
            vault_mode: VaultMode::default(),
        }
    }

    /// Create metadata with an expiry set `days` from now.
    pub fn with_expiry(days: u64) -> Self {
        let now = now_secs();
        let ttl_secs = days * 86_400;
        Self {
            created_at: Some(now),
            rotated_at: Some(now),
            expires_at: Some(now + ttl_secs),
            rotation_policy: Some(RotationPolicy {
                days_ttl: days,
                auto_rotate: false,
            }),
            vault_mode: VaultMode::default(),
        }
    }

    /// Record a rotation event (update `rotated_at` and recalculate `expires_at`).
    /// Also resets `vault_mode` to `ReadWrite` so that a previously demoted
    /// secret becomes injectable again after the rotation is complete.
    pub fn record_rotation(&mut self) {
        let now = now_secs();
        self.rotated_at = Some(now);
        if let Some(ref policy) = self.rotation_policy.clone() {
            self.expires_at = Some(now + policy.days_ttl * 86_400);
        }
        // Reset read-only demotion: rotating a secret makes it valid again.
        self.vault_mode = VaultMode::ReadWrite;
    }

    /// Returns `true` if the secret is currently expired.
    pub fn is_expired(&self) -> bool {
        match self.expires_at {
            Some(exp) => now_secs() >= exp,
            None => false,
        }
    }

    /// Returns the number of days remaining until expiry, or `None` if no
    /// expiry is set. Returns `0` (or would be negative — clamped) when
    /// already expired.
    pub fn days_remaining(&self) -> Option<i64> {
        self.expires_at.map(|exp| {
            let now = now_secs() as i64;
            let secs_left = exp as i64 - now;
            secs_left / 86_400
        })
    }

    /// Returns a human-readable TTL status string for display.
    pub fn ttl_status(&self) -> String {
        match self.expires_at {
            None => "no expiry".to_string(),
            Some(_) => {
                if self.is_expired() {
                    "EXPIRED".to_string()
                } else {
                    let days = self.days_remaining().unwrap_or(0);
                    if days == 0 {
                        "expires today".to_string()
                    } else if days == 1 {
                        "1 day remaining".to_string()
                    } else {
                        format!("{days} days remaining")
                    }
                }
            }
        }
    }

    /// Returns `true` if the secret will expire within `warn_days` days.
    pub fn is_expiring_soon(&self, warn_days: u64) -> bool {
        match self.days_remaining() {
            Some(days) => days >= 0 && days <= warn_days as i64,
            None => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_now_sets_created_at() {
        let before = now_secs();
        let meta = SecretMetadata::new_now();
        let after = now_secs();
        let created = meta.created_at.expect("created_at must be set");
        assert!(created >= before && created <= after);
        assert!(meta.expires_at.is_none());
        assert!(meta.rotation_policy.is_none());
    }

    #[test]
    fn with_expiry_sets_all_fields() {
        let before = now_secs();
        let meta = SecretMetadata::with_expiry(7);
        let after = now_secs();

        let created = meta.created_at.expect("created_at");
        assert!(created >= before && created <= after);

        let rotated = meta.rotated_at.expect("rotated_at");
        assert!(rotated >= before && rotated <= after);

        let expires = meta.expires_at.expect("expires_at");
        let expected_min = before + 7 * 86_400;
        let expected_max = after + 7 * 86_400;
        assert!(
            expires >= expected_min && expires <= expected_max,
            "expires_at {expires} not in [{expected_min}, {expected_max}]"
        );

        let policy = meta.rotation_policy.expect("rotation_policy");
        assert_eq!(policy.days_ttl, 7);
        assert!(!policy.auto_rotate);
    }

    #[test]
    fn not_expired_future() {
        let meta = SecretMetadata {
            expires_at: Some(now_secs() + 86_400),
            ..Default::default()
        };
        assert!(!meta.is_expired());
    }

    #[test]
    fn expired_past() {
        let meta = SecretMetadata {
            expires_at: Some(now_secs() - 1),
            ..Default::default()
        };
        assert!(meta.is_expired());
    }

    #[test]
    fn no_expiry_not_expired() {
        let meta = SecretMetadata::default();
        assert!(!meta.is_expired());
        assert_eq!(meta.days_remaining(), None);
    }

    #[test]
    fn days_remaining_positive() {
        let meta = SecretMetadata {
            expires_at: Some(now_secs() + 10 * 86_400 + 1),
            ..Default::default()
        };
        let days = meta.days_remaining().expect("some");
        assert_eq!(days, 10);
    }

    #[test]
    fn days_remaining_negative_when_expired() {
        let meta = SecretMetadata {
            expires_at: Some(now_secs() - 2 * 86_400),
            ..Default::default()
        };
        let days = meta.days_remaining().expect("some");
        assert!(days < 0);
    }

    #[test]
    fn ttl_status_no_expiry() {
        let meta = SecretMetadata::default();
        assert_eq!(meta.ttl_status(), "no expiry");
    }

    #[test]
    fn ttl_status_expired() {
        let meta = SecretMetadata {
            expires_at: Some(now_secs() - 1),
            ..Default::default()
        };
        assert_eq!(meta.ttl_status(), "EXPIRED");
    }

    #[test]
    fn ttl_status_days_remaining() {
        let meta = SecretMetadata {
            expires_at: Some(now_secs() + 5 * 86_400 + 1),
            ..Default::default()
        };
        assert_eq!(meta.ttl_status(), "5 days remaining");
    }

    #[test]
    fn is_expiring_soon_within_window() {
        let meta = SecretMetadata {
            expires_at: Some(now_secs() + 3 * 86_400),
            ..Default::default()
        };
        assert!(meta.is_expiring_soon(7));
        assert!(!meta.is_expiring_soon(2));
    }

    #[test]
    fn record_rotation_updates_timestamps() {
        let mut meta = SecretMetadata::with_expiry(30);
        let before = now_secs();
        meta.record_rotation();
        let after = now_secs();

        let rotated = meta.rotated_at.expect("rotated_at");
        assert!(rotated >= before && rotated <= after);

        // expires_at should be extended by 30 days from rotation
        let expires = meta.expires_at.expect("expires_at");
        let expected_min = before + 30 * 86_400;
        let expected_max = after + 30 * 86_400;
        assert!(expires >= expected_min && expires <= expected_max);
    }

    #[test]
    fn ttl_serialization_round_trip() {
        let meta = SecretMetadata::with_expiry(7);
        let json = serde_json::to_string(&meta).expect("serialize");
        let back: SecretMetadata = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(meta.created_at, back.created_at);
        assert_eq!(meta.rotated_at, back.rotated_at);
        assert_eq!(meta.expires_at, back.expires_at);
        assert_eq!(meta.rotation_policy, back.rotation_policy);
    }
}
