### Added (`phantom audit hotspots`)

- `phantom audit hotspots` lists the per-secret access-spike alerts that the MCP
  `phantom_audit_hotspot_alerts` tool already reported. It has `--name`,
  `--include-acked`, and `--json`; the JSON keys match the MCP tool.
- Listing is read-only: it never appends `vault.hotspot_alert` events to the
  audit log. Acknowledging or snoozing remains the approval-gated MCP action.
