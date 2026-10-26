//! `phantom doctor --all`: one read-only, value-free report.
//!
//! It combines reports that already exist, with no new behavior behind them:
//! the health checks (`phantom doctor`, run without `--fix`), the static
//! post-quantum report (`doctor --pq`), agent readiness (`agent doctor`) and MCP
//! approval status (`agent status`). It adds one small section: which gateway
//! base-URL environment variables are set and whether each points at a loopback
//! host. It never prints a URL, only the variable name and a class, because a
//! URL can carry credentials.
//!
//! Gateway mode itself is not inferred. A base URL on loopback is consistent
//! with a local gateway or the Phantom proxy, but this report cannot tell which
//! one is listening, so it says only what it can verify.

use anyhow::Result;
use serde::Serialize;

/// Variables that agents and SDKs read to redirect model traffic.
const GATEWAY_VARS: [&str; 3] = ["ANTHROPIC_BASE_URL", "OPENAI_BASE_URL", "OLLAMA_HOST"];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HostClass {
    Unset,
    Loopback,
    NonLoopback,
    Unparseable,
}

#[derive(Debug, Clone, Serialize)]
pub struct GatewayVar {
    pub name: &'static str,
    pub class: HostClass,
}

#[derive(Debug, Clone, Serialize)]
pub struct GatewaySection {
    pub vars: Vec<GatewayVar>,
    pub note: &'static str,
}

/// Classify the host part of a base URL (or `host:port`, as OLLAMA_HOST uses).
/// Looks only at the host; never returns or logs the input.
pub fn classify(value: Option<&str>) -> HostClass {
    let Some(raw) = value.map(str::trim).filter(|v| !v.is_empty()) else {
        return HostClass::Unset;
    };
    let rest = raw.split_once("://").map_or(raw, |(_, rest)| rest);
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    // Drop userinfo, which may hold credentials.
    let hostport = authority.rsplit('@').next().unwrap_or("");
    let host = if let Some(stripped) = hostport.strip_prefix('[') {
        match stripped.split_once(']') {
            Some((h, _)) => h,
            None => return HostClass::Unparseable,
        }
    } else {
        hostport.split(':').next().unwrap_or("")
    };
    if host.is_empty() {
        return HostClass::Unparseable;
    }
    let lower = host.to_ascii_lowercase();
    if lower == "localhost" || lower == "::1" {
        return HostClass::Loopback;
    }
    if let Ok(ip) = lower.parse::<std::net::Ipv4Addr>() {
        return if ip.is_loopback() {
            HostClass::Loopback
        } else {
            HostClass::NonLoopback
        };
    }
    if lower.contains(':') {
        return HostClass::Unparseable;
    }
    HostClass::NonLoopback
}

pub fn gateway_section(get: impl Fn(&str) -> Option<String>) -> GatewaySection {
    GatewaySection {
        vars: GATEWAY_VARS
            .iter()
            .map(|name| GatewayVar {
                name,
                class: classify(get(name).as_deref()),
            })
            .collect(),
        note: "Only the host class of each variable is reported, never the URL. Gateway mode is not inferred: loopback is consistent with a local gateway or the Phantom proxy, but this report cannot tell which one is listening.",
    }
}

pub fn run(json: bool) -> Result<()> {
    let health = super::doctor::collect_report(false, false)?;
    let pq = super::pq_report::build(phantom_core::PQ_HYBRID_COMPILED);
    let agent_readiness = super::agent::readiness_for_cwd()?;
    let agent_status = super::agent::status_json()?;
    let gateway = gateway_section(|k| std::env::var(k).ok());

    if json {
        let doc = serde_json::json!({
            "health": health,
            "pq": pq,
            "agent_readiness": agent_readiness,
            "agent_status": agent_status,
            "gateway": gateway,
        });
        println!("{}", serde_json::to_string_pretty(&doc)?);
        return Ok(());
    }

    println!("Phantom doctor (combined, read-only)\n");
    println!(
        "Health: {} ({} issue(s)). Details: phantom doctor",
        if health.ok { "ok" } else { "issues found" },
        health.issues
    );
    println!("Post-quantum: {} Details: phantom doctor --pq", pq.summary);
    println!(
        "Agent readiness: {} findings, requires approval: {}. Details: phantom agent doctor",
        agent_readiness.findings.len(),
        agent_readiness.requires_approval
    );
    let a = &agent_status["approvals"];
    println!(
        "MCP approvals: {} pending, {} approved and unused, {} expired. Details: phantom agent status",
        a["pending"], a["approved_unused"], a["expired"]
    );
    println!("Gateway base URLs (host class only):");
    for v in &gateway.vars {
        println!("  {}: {:?}", v.name, v.class);
    }
    println!("{}", gateway.note);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_hosts() {
        assert_eq!(classify(None), HostClass::Unset);
        assert_eq!(classify(Some("  ")), HostClass::Unset);
        for v in [
            "http://127.0.0.1:4000",
            "http://localhost:4000/v1",
            "http://[::1]:4000",
            "127.0.0.1:11434",
            "http://user:pw@localhost:1/",
        ] {
            assert_eq!(classify(Some(v)), HostClass::Loopback, "{v}");
        }
        for v in [
            "https://api.anthropic.com",
            "http://10.0.0.5:4000",
            "http://localhost.evil.com",
            "http://127.0.0.1@evil.com/",
        ] {
            assert_eq!(classify(Some(v)), HostClass::NonLoopback, "{v}");
        }
        assert_eq!(classify(Some("http://")), HostClass::Unparseable);
    }

    #[test]
    fn section_never_contains_the_url_or_userinfo() {
        let s = gateway_section(|k| {
            (k == "OPENAI_BASE_URL").then(|| "http://user:hunter2@localhost:4000".to_string())
        });
        let json = serde_json::to_string(&s).unwrap();
        assert!(!json.contains("hunter2"));
        assert!(!json.contains("4000"));
        assert!(json.contains("loopback"));
        assert!(!json.contains('\u{2014}'));
    }
}
