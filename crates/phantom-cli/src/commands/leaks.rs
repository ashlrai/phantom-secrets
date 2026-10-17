//! `phantom leaks plan` - read-only preview of leak response.
//!
//! Shows what an automated leak response WOULD do for the active leak
//! incidents. It performs no writes (no audit event, no vault access, no
//! incident persistence) and no network calls. Only secret names appear in
//! output, never values. Live revoke and rotation are disabled in shipped
//! builds, so every step is a manual instruction.

use anyhow::Result;
use colored::Colorize;
use phantom_core::config::{LeakResponseConfig, OnLeak, PhantomConfig};
use phantom_core::leak_correlation::{LeakCorrelationEngine, LeakIncident};
use phantom_core::rotation_provider::default_rotation_providers;
use serde::Serialize;

/// Confidence at or above which the plan proposes revoke then rotate.
pub const REVOKE_THRESHOLD: f64 = 0.7;

/// One planned (never executed) response to a leak incident.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct PlannedResponse {
    pub incident_id: String,
    /// Secret name only, never the value.
    pub secret_name: String,
    pub location_label: String,
    pub confidence: f64,
    pub event_count: usize,
    /// Matched provider name, or null when none matches the secret name.
    pub provider: Option<String>,
    /// `revoke_and_rotate` or `review`.
    pub action: String,
    /// Ordered manual steps. Nothing here is executed by this command.
    pub steps: Vec<String>,
}

/// Build the plan for the given incidents. Pure: no I/O.
///
/// `provider_of` maps a secret name to a provider name, if one matches.
pub fn build_plan(
    incidents: &[LeakIncident],
    provider_of: impl Fn(&str) -> Option<String>,
) -> Vec<PlannedResponse> {
    incidents
        .iter()
        .map(|inc| {
            let provider = provider_of(&inc.secret_name);
            let high = inc.confidence >= REVOKE_THRESHOLD;
            let target = provider
                .as_deref()
                .map(|p| format!("{p} dashboard"))
                .unwrap_or_else(|| "the provider that issued it".to_string());
            let mut steps = Vec::new();
            if high {
                steps.push(format!("Revoke the leaked {} at {target}", inc.secret_name));
                steps.push(format!(
                    "Issue a replacement for {} and store it from a trusted terminal",
                    inc.secret_name
                ));
                steps.push("Run `phantom sync` after reviewing the change".to_string());
            } else {
                steps.push(format!(
                    "Review the {} events for {} before changing anything",
                    inc.location_label, inc.secret_name
                ));
                steps.push(format!(
                    "If the leak is real, revoke and replace {} at {target}",
                    inc.secret_name
                ));
            }
            PlannedResponse {
                incident_id: inc.incident_id.clone(),
                secret_name: inc.secret_name.clone(),
                location_label: inc.location_label.clone(),
                confidence: inc.confidence,
                event_count: inc.event_count,
                provider,
                action: if high { "revoke_and_rotate" } else { "review" }.to_string(),
                steps,
            }
        })
        .collect()
}

fn provider_name_for(secret_name: &str) -> Option<String> {
    default_rotation_providers()
        .iter()
        .find(|p| p.matches(secret_name))
        .map(|p| p.name().to_string())
}

/// Read the `[leak_response]` policy from `./.phantom.toml`. No file means the
/// default policy (`plan`). A present but invalid policy is an error.
fn load_policy() -> Result<OnLeak> {
    let path = std::path::Path::new(".phantom.toml");
    if !path.exists() {
        return Ok(OnLeak::default());
    }
    let config =
        PhantomConfig::load(path).map_err(|e| anyhow::anyhow!("Cannot read .phantom.toml: {e}"))?;
    config
        .leak_response
        .effective()
        .map_err(|e| anyhow::anyhow!("{e}"))
}

/// Run `phantom leaks plan`. Reads incidents only; writes nothing.
pub fn run_plan(min_confidence: f64, json: bool) -> Result<()> {
    let policy = load_policy()?;
    if policy == OnLeak::Off {
        if json {
            let out = serde_json::json!({
                "dry_run": true,
                "on_leak": policy.as_str(),
                "live_revoke_available": LeakResponseConfig::live_revoke_available(),
                "min_confidence": min_confidence,
                "plan": [],
            });
            println!("{}", serde_json::to_string_pretty(&out)?);
        } else {
            println!(
                "{}  Leak response is off ([leak_response] on_leak = \"off\"). Nothing to plan.",
                "->".blue().bold()
            );
        }
        return Ok(());
    }
    let engine = LeakCorrelationEngine::new()
        .map_err(|e| anyhow::anyhow!("Cannot initialise leak correlation engine: {e}"))?;
    let incidents = engine
        .active_incidents(min_confidence)
        .map_err(|e| anyhow::anyhow!("Failed to read leak incidents: {e}"))?;
    let plan = build_plan(&incidents, provider_name_for);

    if json {
        let out = serde_json::json!({
            "dry_run": true,
            "on_leak": policy.as_str(),
            "live_revoke_available": LeakResponseConfig::live_revoke_available(),
            "min_confidence": min_confidence,
            "plan": plan,
        });
        println!("{}", serde_json::to_string_pretty(&out)?);
        return Ok(());
    }

    if plan.is_empty() {
        println!(
            "{}  No active leak incidents (min_confidence={:.2}). Nothing to plan.",
            "->".blue().bold(),
            min_confidence
        );
        return Ok(());
    }

    println!(
        "{}  Leak response plan: {} incident(s). Dry run: nothing was changed.",
        "->".blue().bold(),
        plan.len()
    );
    for item in &plan {
        println!();
        println!(
            "  {}  confidence {:.2}  events {}  location {}  provider {}",
            item.secret_name.bold(),
            item.confidence,
            item.event_count,
            item.location_label,
            item.provider.as_deref().unwrap_or("unknown"),
        );
        println!("    action: {}", item.action.yellow());
        for (i, step) in item.steps.iter().enumerate() {
            println!("    {}. {}", i + 1, step);
        }
    }
    println!();
    if policy == OnLeak::Revoke {
        println!("on_leak = \"revoke\" is set, but live revoke is disabled in this build; showing the plan only.");
    }
    println!("Automated revoke and rotation are disabled in this build; these steps are manual.");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn inc(name: &str, conf: f64) -> LeakIncident {
        LeakIncident {
            incident_id: format!("id-{name}"),
            secret_name: name.to_string(),
            location_label: "body".to_string(),
            first_seen_ts: 1,
            last_seen_ts: 2,
            event_count: 4,
            confidence: conf,
            remediation: String::new(),
        }
    }

    #[test]
    fn high_confidence_plans_revoke_and_rotate() {
        let plan = build_plan(&[inc("STRIPE_SECRET_KEY", 0.95)], |_| Some("stripe".into()));
        assert_eq!(plan[0].action, "revoke_and_rotate");
        assert_eq!(plan[0].provider.as_deref(), Some("stripe"));
        assert!(plan[0].steps[0].contains("stripe dashboard"));
    }

    #[test]
    fn low_confidence_plans_review_only() {
        let plan = build_plan(&[inc("FOO_KEY", 0.5)], |_| None);
        assert_eq!(plan[0].action, "review");
        assert_eq!(plan[0].provider, None);
        assert!(plan[0].steps[1].contains("the provider that issued it"));
    }

    #[test]
    fn threshold_is_inclusive() {
        let plan = build_plan(&[inc("A", REVOKE_THRESHOLD)], |_| None);
        assert_eq!(plan[0].action, "revoke_and_rotate");
    }

    #[test]
    fn empty_in_empty_out() {
        assert!(build_plan(&[], |_| None).is_empty());
    }

    #[test]
    fn known_provider_names_resolve() {
        assert_eq!(
            provider_name_for("STRIPE_SECRET_KEY").as_deref(),
            Some("stripe")
        );
        assert_eq!(provider_name_for("TOTALLY_UNRELATED_NAME"), None);
    }
}
