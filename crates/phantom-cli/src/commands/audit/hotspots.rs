use super::*;
use phantom_core::audit::HotspotAckStatus;

/// `phantom audit hotspots`: the access-spike alerts the MCP
/// `phantom_audit_hotspot_alerts` tool reports, read without appending to the
/// audit log. Acknowledging or snoozing stays on the approval-gated MCP path.
pub fn run_hotspots(name: Option<&str>, include_acked: bool, json: bool) -> Result<()> {
    let alerts = phantom_core::audit::read_hotspot_alerts()
        .map_err(|e| anyhow::anyhow!("Failed to read audit log: {e}"))?;
    render_hotspots(alerts, name, include_acked, json, &mut std::io::stdout())
}

/// Filter and render the hotspot listing. `alerts` is the full read-only
/// detection result; the name and acked filters apply here so both output
/// forms agree.
fn render_hotspots(
    mut alerts: Vec<phantom_core::audit::HotspotAlert>,
    name: Option<&str>,
    include_acked: bool,
    json: bool,
    out: &mut dyn Write,
) -> Result<()> {
    if let Some(name) = name {
        alerts.retain(|a| a.secret_name == name);
    }
    if !include_acked {
        alerts.retain(|a| a.ack_status == HotspotAckStatus::Unacked);
    }

    if json {
        let now_ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let envelope = serde_json::json!({
            "generated_at": phantom_core::analytics::unix_to_iso8601(now_ts),
            "total_alerts": alerts.len(),
            "alerts": alerts.iter().map(|a| a.to_json()).collect::<Vec<_>>(),
        });
        writeln!(out, "{}", serde_json::to_string_pretty(&envelope)?)?;
        return Ok(());
    }

    if alerts.is_empty() {
        writeln!(
            out,
            "{}  No hotspot alerts. A secret alerts at 5x its 7-day daily baseline, or on 100+ accesses within 5 minutes.",
            "->".blue().bold()
        )?;
        return Ok(());
    }

    let unacked = alerts
        .iter()
        .filter(|a| a.ack_status == HotspotAckStatus::Unacked)
        .count();
    writeln!(
        out,
        "{}  {} hotspot {} · {} unacked",
        "->".blue().bold(),
        alerts.len().to_string().cyan(),
        if alerts.len() == 1 { "alert" } else { "alerts" },
        if unacked > 0 {
            unacked.to_string().red().bold().to_string()
        } else {
            unacked.to_string()
        },
    )?;
    writeln!(out)?;

    let name_w = alerts
        .iter()
        .map(|a| a.secret_name.len())
        .max()
        .unwrap_or(6)
        .max(6);
    writeln!(
        out,
        "  {:<name_w$}  {:<8}  {:>6}  {:>12}  {:>7}  {}",
        "SECRET".bold(),
        "STATUS".bold(),
        "24H".bold(),
        "BASELINE/DAY".bold(),
        "PEAK 5M".bold(),
        "FIRST SPIKE".bold(),
        name_w = name_w,
    )?;
    writeln!(out, "  {}", "-".repeat(name_w + 45))?;

    for a in &alerts {
        let status = match a.ack_status {
            HotspotAckStatus::Unacked => "unacked".red().bold().to_string(),
            HotspotAckStatus::Acked => "acked".dimmed().to_string(),
            HotspotAckStatus::Snoozed => "snoozed".yellow().to_string(),
        };
        writeln!(
            out,
            "  {:<name_w$}  {:<8}  {:>6}  {:>12.1}  {:>7}  {}",
            a.secret_name.bold(),
            status,
            a.current_velocity,
            a.baseline_velocity,
            a.peak_5m_count,
            format_unix_ts(a.first_spike_ts).dimmed(),
            name_w = name_w,
        )?;
        writeln!(
            out,
            "  {:<name_w$}  {}",
            "",
            a.trigger.dimmed(),
            name_w = name_w
        )?;
    }

    writeln!(out)?;
    writeln!(
        out,
        "{}  Acknowledge or snooze with the phantom_audit_hotspot_alerts MCP tool (ack=true; confirm and approval_token required).",
        "->".blue().bold()
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use phantom_core::audit::HotspotAlert;

    fn alert(name: &str, status: HotspotAckStatus) -> HotspotAlert {
        HotspotAlert {
            secret_name: name.to_string(),
            current_velocity: 40,
            baseline_velocity: 2.0,
            alert_level: "high".to_string(),
            first_spike_ts: 1_700_000_000,
            generated_at: 1_700_000_000,
            ack_status: status,
            trigger: "velocity_spike: 40 accesses in 24h > 5x baseline 2.0".to_string(),
            peak_5m_count: 12,
        }
    }

    /// Rendered text with color escapes removed, so assertions see the words
    /// without depending on whether `colored` is active in this test process.
    fn render(
        alerts: Vec<HotspotAlert>,
        name: Option<&str>,
        include_acked: bool,
        json: bool,
    ) -> String {
        let mut out = Vec::new();
        render_hotspots(alerts, name, include_acked, json, &mut out).unwrap();
        let raw = String::from_utf8(out).unwrap();
        let mut plain = String::with_capacity(raw.len());
        let mut in_escape = false;
        for c in raw.chars() {
            match (in_escape, c) {
                (false, '\u{1b}') => in_escape = true,
                (true, 'm') => in_escape = false,
                (true, _) => {}
                (false, _) => plain.push(c),
            }
        }
        plain
    }

    #[test]
    fn json_envelope_uses_the_mcp_keys_and_filters_acked_by_default() {
        let alerts = vec![
            alert("LIVE_KEY", HotspotAckStatus::Unacked),
            alert("DONE_KEY", HotspotAckStatus::Acked),
        ];
        let v: serde_json::Value =
            serde_json::from_str(&render(alerts.clone(), None, false, true)).unwrap();
        assert_eq!(v["total_alerts"], 1);
        assert_eq!(v["alerts"][0]["secret_name"], "LIVE_KEY");
        assert!(v["generated_at"].is_string());

        let all: serde_json::Value =
            serde_json::from_str(&render(alerts, None, true, true)).unwrap();
        assert_eq!(all["total_alerts"], 2);
        assert_eq!(all["alerts"][1]["ack_status"], "acked");
    }

    #[test]
    fn name_filter_is_exact_in_both_forms() {
        let alerts = vec![
            alert("LIVE_KEY", HotspotAckStatus::Unacked),
            alert("LIVE_KEY_2", HotspotAckStatus::Unacked),
        ];
        let v: serde_json::Value =
            serde_json::from_str(&render(alerts.clone(), Some("LIVE_KEY"), false, true)).unwrap();
        assert_eq!(v["total_alerts"], 1);
        assert_eq!(v["alerts"][0]["secret_name"], "LIVE_KEY");

        let human = render(alerts, Some("LIVE_KEY"), false, false);
        assert!(human.contains("LIVE_KEY"), "{human}");
        assert!(!human.contains("LIVE_KEY_2"), "{human}");
    }

    #[test]
    fn human_form_counts_unacked_and_shows_the_trigger() {
        let alerts = vec![
            alert("LIVE_KEY", HotspotAckStatus::Unacked),
            alert("SNOOZED_KEY", HotspotAckStatus::Snoozed),
        ];
        let text = render(alerts, None, true, false);
        assert!(text.contains("hotspot alerts"), "{text}");
        assert!(text.contains("1 unacked"), "{text}");
        assert!(text.contains("velocity_spike: 40 accesses"), "{text}");
        assert!(text.contains("phantom_audit_hotspot_alerts"), "{text}");
    }

    #[test]
    fn empty_human_listing_states_the_alert_rule() {
        let text = render(Vec::new(), None, false, false);
        assert!(text.contains("No hotspot alerts"), "{text}");
        assert!(text.contains("5x") && text.contains("100+"), "{text}");
    }
}
