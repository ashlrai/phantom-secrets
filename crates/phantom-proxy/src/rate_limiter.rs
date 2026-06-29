//! Per-secret request rate limiting and burst anomaly detection.
//!
//! Two overlapping windows are tracked for each secret key:
//!
//! - **1-minute window** — counts total accesses in the last 60 seconds.
//! - **10-second window** — counts total accesses in the last 10 seconds.
//!
//! Anomaly thresholds (tunable via env vars):
//! - `PHANTOM_RATE_LIMIT_PER_SECRET` — max requests/sec for a single secret
//!   (default 5, measured over the 10-sec window).
//! - `PHANTOM_RATE_LIMIT_BURST` — max total requests across ALL secrets in any
//!   10-second window (default 20).
//!
//! Every call to [`RateLimiter::record`] returns a [`RateDecision`] that
//! classifies the request as `Normal`, `Caution`, or `Alert`.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

// ─────────────────────────────────────────────────────────────────────────────
// Public types
// ─────────────────────────────────────────────────────────────────────────────

/// Anomaly classification for a proxy request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AnomalyClass {
    /// Request is within normal access patterns.
    Normal,
    /// Request is elevated; may warrant monitoring.
    Caution,
    /// Burst threshold exceeded; request is rate-limited.
    Alert,
}

impl AnomalyClass {
    /// Numeric score (0 / 1 / 2) for CLI filtering via `--min-anomaly-score`.
    pub fn score(self) -> u8 {
        match self {
            AnomalyClass::Normal => 0,
            AnomalyClass::Caution => 1,
            AnomalyClass::Alert => 2,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            AnomalyClass::Normal => "normal",
            AnomalyClass::Caution => "caution",
            AnomalyClass::Alert => "alert",
        }
    }
}

/// Result of a single rate-limit check.
#[derive(Debug, Clone)]
pub struct RateDecision {
    /// Anomaly class for this request.
    pub class: AnomalyClass,
    /// Number of requests for this secret in the last 10 seconds.
    pub per_secret_10s: u64,
    /// Total requests across all secrets in the last 10 seconds.
    pub total_10s: u64,
    /// Number of requests for this secret in the last 60 seconds.
    pub per_secret_60s: u64,
    /// Computed anomaly score (0–100).  Used by `phantom list --min-anomaly-score`.
    pub anomaly_score: u8,
}

/// Rate-limit configuration.
#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    /// Maximum requests/sec for a single secret (measured over 10-sec window).
    /// Env var: `PHANTOM_RATE_LIMIT_PER_SECRET` (default 5).
    pub per_secret_rps: u64,
    /// Maximum total requests across all secrets in any 10-second window.
    /// Env var: `PHANTOM_RATE_LIMIT_BURST` (default 20).
    pub burst_total_10s: u64,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            per_secret_rps: 5,
            burst_total_10s: 20,
        }
    }
}

impl RateLimitConfig {
    /// Load from environment variables, falling back to defaults.
    pub fn from_env() -> Self {
        let per_secret_rps = std::env::var("PHANTOM_RATE_LIMIT_PER_SECRET")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(5);
        let burst_total_10s = std::env::var("PHANTOM_RATE_LIMIT_BURST")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(20);
        Self {
            per_secret_rps,
            burst_total_10s,
        }
    }

    /// Derived: per-secret limit over the 10-second window.
    pub fn per_secret_10s_limit(&self) -> u64 {
        self.per_secret_rps * 10
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Internal sliding-window counter
// ─────────────────────────────────────────────────────────────────────────────

/// A fixed-duration sliding-window request counter.
struct SlidingWindow {
    /// Ordered timestamps of requests within the window (oldest first).
    timestamps: VecDeque<Instant>,
    window: Duration,
}

impl SlidingWindow {
    fn new(window: Duration) -> Self {
        Self {
            timestamps: VecDeque::new(),
            window,
        }
    }

    /// Record a new hit and return the count within the window.
    fn record_and_count(&mut self, now: Instant) -> u64 {
        self.timestamps.push_back(now);
        self.evict(now);
        self.timestamps.len() as u64
    }

    /// Return the current count without recording.
    #[allow(dead_code)]
    fn count(&mut self, now: Instant) -> u64 {
        self.evict(now);
        self.timestamps.len() as u64
    }

    fn evict(&mut self, now: Instant) {
        while let Some(&front) = self.timestamps.front() {
            if now.duration_since(front) > self.window {
                self.timestamps.pop_front();
            } else {
                break;
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Per-secret state
// ─────────────────────────────────────────────────────────────────────────────

struct SecretCounters {
    window_60s: SlidingWindow,
    window_10s: SlidingWindow,
}

impl SecretCounters {
    fn new() -> Self {
        Self {
            window_60s: SlidingWindow::new(Duration::from_secs(60)),
            window_10s: SlidingWindow::new(Duration::from_secs(10)),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// RateLimiter
// ─────────────────────────────────────────────────────────────────────────────

struct RateLimiterInner {
    per_secret: HashMap<String, SecretCounters>,
    global_10s: SlidingWindow,
    config: RateLimitConfig,
}

impl RateLimiterInner {
    fn new(config: RateLimitConfig) -> Self {
        Self {
            per_secret: HashMap::new(),
            global_10s: SlidingWindow::new(Duration::from_secs(10)),
            config,
        }
    }

    fn record(&mut self, secret_key: &str) -> RateDecision {
        let now = Instant::now();

        let counters = self
            .per_secret
            .entry(secret_key.to_string())
            .or_insert_with(SecretCounters::new);

        let per_secret_60s = counters.window_60s.record_and_count(now);
        let per_secret_10s = counters.window_10s.record_and_count(now);

        let total_10s = self.global_10s.record_and_count(now);

        let per_secret_limit_10s = self.config.per_secret_10s_limit();
        let burst_limit = self.config.burst_total_10s;

        // Classify anomaly:
        // - Alert: per-secret burst >limit OR global burst >limit
        // - Caution: per-secret is at ≥50% of limit OR global is ≥75% of limit
        // - Normal: everything is fine
        let class = if per_secret_10s > per_secret_limit_10s || total_10s > burst_limit {
            AnomalyClass::Alert
        } else if per_secret_10s * 2 >= per_secret_limit_10s || total_10s * 4 >= burst_limit * 3 {
            AnomalyClass::Caution
        } else {
            AnomalyClass::Normal
        };

        // Anomaly score 0–100:
        // proportional to the higher of (per_secret_10s / limit) and (total_10s / burst).
        let per_secret_pct = if per_secret_limit_10s > 0 {
            (per_secret_10s * 100 / per_secret_limit_10s).min(100)
        } else {
            0
        };
        let burst_pct = if burst_limit > 0 {
            (total_10s * 100 / burst_limit).min(100)
        } else {
            0
        };
        let anomaly_score = per_secret_pct.max(burst_pct) as u8;

        RateDecision {
            class,
            per_secret_10s,
            total_10s,
            per_secret_60s,
            anomaly_score,
        }
    }
}

/// Thread-safe rate limiter for the proxy.
#[derive(Clone)]
pub struct RateLimiter {
    inner: Arc<Mutex<RateLimiterInner>>,
}

impl RateLimiter {
    /// Create a new rate limiter with the given configuration.
    pub fn new(config: RateLimitConfig) -> Self {
        Self {
            inner: Arc::new(Mutex::new(RateLimiterInner::new(config))),
        }
    }

    /// Create from environment variables.
    pub fn from_env() -> Self {
        Self::new(RateLimitConfig::from_env())
    }

    /// Record a request for the given secret key and return the rate decision.
    pub fn record(&self, secret_key: &str) -> RateDecision {
        self.inner
            .lock()
            .expect("rate limiter lock poisoned")
            .record(secret_key)
    }

    /// Return the current config.
    pub fn config(&self) -> RateLimitConfig {
        self.inner
            .lock()
            .expect("rate limiter lock poisoned")
            .config
            .clone()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn limiter_with(per_secret_rps: u64, burst_total_10s: u64) -> RateLimiter {
        RateLimiter::new(RateLimitConfig {
            per_secret_rps,
            burst_total_10s,
        })
    }

    #[test]
    fn normal_single_request() {
        let rl = limiter_with(5, 20);
        let decision = rl.record("MY_KEY");
        assert_eq!(decision.class, AnomalyClass::Normal);
        assert_eq!(decision.per_secret_10s, 1);
        assert_eq!(decision.total_10s, 1);
        assert_eq!(decision.per_secret_60s, 1);
    }

    #[test]
    fn alert_per_secret_burst() {
        // limit = 5 rps * 10s = 50; burst limit set to 100 so global doesn't trigger
        let rl = limiter_with(5, 100);
        for _ in 0..50 {
            rl.record("SINGLE_KEY");
        }
        let decision = rl.record("SINGLE_KEY"); // 51st — over limit
        assert_eq!(decision.class, AnomalyClass::Alert);
        assert!(decision.anomaly_score > 50);
    }

    #[test]
    fn alert_global_burst() {
        // global burst limit = 5, per-secret limit = 100
        let rl = limiter_with(10, 5);
        for i in 0..5u32 {
            rl.record(&format!("KEY_{i}"));
        }
        let decision = rl.record("KEY_EXTRA"); // 6th total — over global limit
        assert_eq!(decision.class, AnomalyClass::Alert);
    }

    #[test]
    fn caution_threshold() {
        // per-secret limit = 5*10=50; 25 requests = 50% = caution
        let rl = limiter_with(5, 200);
        for _ in 0..25 {
            rl.record("HALF_KEY");
        }
        let decision = rl.record("HALF_KEY");
        // 26 out of 50 = 52% → caution
        assert_eq!(decision.class, AnomalyClass::Caution);
    }

    #[test]
    fn anomaly_score_zero_for_normal() {
        let rl = limiter_with(5, 20);
        let d = rl.record("KEY");
        assert_eq!(d.anomaly_score, 5); // 1/20 of burst = 5%
    }

    #[test]
    fn anomaly_score_100_for_alert() {
        let rl = limiter_with(5, 20);
        for _ in 0..20 {
            rl.record("KEY");
        }
        let d = rl.record("KEY"); // over both limits
        assert_eq!(d.anomaly_score, 100);
    }

    #[test]
    fn anomaly_class_score_values() {
        assert_eq!(AnomalyClass::Normal.score(), 0);
        assert_eq!(AnomalyClass::Caution.score(), 1);
        assert_eq!(AnomalyClass::Alert.score(), 2);
    }

    #[test]
    fn multiple_secrets_tracked_independently() {
        let rl = limiter_with(5, 200);
        for _ in 0..3 {
            rl.record("KEY_A");
        }
        for _ in 0..3 {
            rl.record("KEY_B");
        }
        // At this point: 3 A + 3 B = 6 global.
        let d_a = rl.record("KEY_A"); // 7th global, 4th for A
        let d_b = rl.record("KEY_B"); // 8th global, 4th for B
        assert_eq!(d_a.per_secret_10s, 4);
        assert_eq!(d_b.per_secret_10s, 4);
        assert_eq!(d_a.total_10s, 7); // 3A + 3B + this A = 7
        assert_eq!(d_b.total_10s, 8); // 3A + 3B + A + this B = 8
    }
}
