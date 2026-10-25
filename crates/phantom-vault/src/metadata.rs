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
/// environment, and `phantom sync` will refuse to push it to a deployment
/// platform, until it is rotated (which resets the mode to `ReadWrite`).
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
    /// Unix timestamp of the last confirmed provider credential replacement.
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

    /// Returns the number of whole days remaining until expiry, or `None` if
    /// no expiry is set.
    ///
    /// A non-negative value always means the secret has not expired yet; a
    /// negative value always means it has (`is_expired()` is `true`). The
    /// count is floored, so a secret that expired any time in the last 24 h
    /// reports `-1`, never `0`.
    pub fn days_remaining(&self) -> Option<i64> {
        self.days_remaining_at(now_secs())
    }

    /// [`Self::days_remaining`] evaluated at an explicit `now` (Unix seconds).
    pub fn days_remaining_at(&self, now: Timestamp) -> Option<i64> {
        self.expires_at.map(|exp| {
            let secs_left = exp as i128 - now as i128;
            if secs_left <= 0 {
                // Matches `is_expired` (now >= expires_at): expired is
                // always strictly negative, including the exact instant.
                (secs_left.div_euclid(86_400) as i64).min(-1)
            } else {
                (secs_left / 86_400) as i64
            }
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

/// One expired secret in an [`ExpiryEnforceReport`]. Name and timestamps only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ExpiredEntry {
    pub name: String,
    pub expires_at: Timestamp,
    pub secs_overdue: u64,
    pub status: String,
}

/// One secret with no `expires_at`, listed only under `fail_closed`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct NoExpiryPolicyEntry {
    pub name: String,
    /// Always `"no_expiry_policy"`.
    pub status: &'static str,
}

/// The one answer of `phantom expiry enforce --json` and the
/// `phantom_expiry_enforce` MCP tool, so the two cannot drift.
///
/// `expired` holds only secrets whose expiry instant has passed. Secrets with
/// no expiry set are counted in `no_expiry_count`; with `fail_closed` they are
/// violations and are also named in `no_expiry_policy` (empty otherwise).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ExpiryEnforceReport {
    pub expired: Vec<ExpiredEntry>,
    pub no_expiry_policy: Vec<NoExpiryPolicyEntry>,
    pub ok_count: usize,
    pub no_expiry_count: usize,
    pub fail_closed: bool,
    /// `true` when no action is needed: nothing expired and, under
    /// `fail_closed`, every secret has an expiry.
    pub pass: bool,
}

/// Build the [`ExpiryEnforceReport`] for `entries` at `now`. Reads names and
/// lifecycle metadata only, never secret values.
pub fn expiry_enforce_report(
    entries: &[(String, Option<SecretMetadata>)],
    fail_closed: bool,
    now: Timestamp,
) -> ExpiryEnforceReport {
    use phantom_core::rotation_strategy::{check_expiry, ExpiryStatus};

    let mut expired = Vec::new();
    let mut no_expiry_policy = Vec::new();
    let mut ok_count = 0usize;
    let mut no_expiry_count = 0usize;
    for (name, metadata) in entries {
        match metadata.as_ref().and_then(|metadata| metadata.expires_at) {
            None => {
                no_expiry_count += 1;
                if fail_closed {
                    no_expiry_policy.push(NoExpiryPolicyEntry {
                        name: name.clone(),
                        status: "no_expiry_policy",
                    });
                }
            }
            Some(expires_at) => {
                let status = check_expiry(expires_at, 0, now);
                if let ExpiryStatus::Expired { secs_overdue } = status {
                    expired.push(ExpiredEntry {
                        name: name.clone(),
                        expires_at,
                        secs_overdue,
                        status: status.label(),
                    });
                } else {
                    ok_count += 1;
                }
            }
        }
    }
    let pass = expired.is_empty() && no_expiry_policy.is_empty();
    ExpiryEnforceReport {
        expired,
        no_expiry_policy,
        ok_count,
        no_expiry_count,
        fail_closed,
        pass,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn enforce_entries(now: Timestamp) -> Vec<(String, Option<SecretMetadata>)> {
        let with_expiry = |expires_at| SecretMetadata {
            expires_at: Some(expires_at),
            ..Default::default()
        };
        vec![
            ("EXPIRED_ONE".to_string(), Some(with_expiry(now - 90_000))),
            ("FRESH_ONE".to_string(), Some(with_expiry(now + 90_000))),
            ("NO_POLICY".to_string(), None),
            ("EMPTY_META".to_string(), Some(SecretMetadata::default())),
        ]
    }

    #[test]
    fn enforce_report_keeps_expired_to_truly_expired_secrets() {
        let now = 2_000_000_000;
        for fail_closed in [false, true] {
            let report = expiry_enforce_report(&enforce_entries(now), fail_closed, now);
            let expired: Vec<&str> = report.expired.iter().map(|e| e.name.as_str()).collect();
            assert_eq!(expired, ["EXPIRED_ONE"], "fail_closed={fail_closed}");
            assert_eq!(report.expired[0].secs_overdue, 90_000);
            assert_eq!(report.ok_count, 1);
            assert_eq!(report.no_expiry_count, 2);
            assert!(!report.pass);
        }
    }

    #[test]
    fn enforce_report_names_no_policy_secrets_only_when_fail_closed() {
        let now = 2_000_000_000;
        let open = expiry_enforce_report(&enforce_entries(now)[1..], false, now);
        assert!(open.no_expiry_policy.is_empty());
        assert!(open.pass, "no expired secret and not fail-closed");

        let closed = expiry_enforce_report(&enforce_entries(now)[1..], true, now);
        let names: Vec<&str> = closed
            .no_expiry_policy
            .iter()
            .map(|e| e.name.as_str())
            .collect();
        assert_eq!(names, ["NO_POLICY", "EMPTY_META"]);
        assert!(closed
            .no_expiry_policy
            .iter()
            .all(|e| e.status == "no_expiry_policy"));
        assert!(closed.expired.is_empty());
        assert!(!closed.pass);
    }

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
    fn days_remaining_is_negative_for_any_expired_secret() {
        let now = 1_700_000_000;
        let at = |expires_at| SecretMetadata {
            expires_at: Some(expires_at),
            ..Default::default()
        };
        // Expired one hour ago: used to truncate to 0 and read as "not expired".
        assert_eq!(at(now - 3_600).days_remaining_at(now), Some(-1));
        // Exact expiry instant counts as expired (matches `is_expired`).
        assert_eq!(at(now).days_remaining_at(now), Some(-1));
        assert_eq!(at(now - 86_400).days_remaining_at(now), Some(-1));
        assert_eq!(at(now - 86_401).days_remaining_at(now), Some(-2));
        assert_eq!(at(now - 10 * 86_400).days_remaining_at(now), Some(-10));
        // Not yet expired stays non-negative.
        assert_eq!(at(now + 1).days_remaining_at(now), Some(0));
        assert_eq!(at(now + 3_600).days_remaining_at(now), Some(0));
        assert_eq!(at(now + 86_400).days_remaining_at(now), Some(1));
    }

    #[test]
    fn recently_expired_is_not_expiring_soon() {
        let meta = SecretMetadata {
            expires_at: Some(now_secs() - 3_600),
            ..Default::default()
        };
        assert!(meta.is_expired());
        assert!(meta.days_remaining().expect("some") < 0);
        assert!(!meta.is_expiring_soon(7));
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
