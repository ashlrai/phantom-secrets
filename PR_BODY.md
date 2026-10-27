Consolidate the RQ-PS-AGENT secret-management changes into one reviewable change.

- Generate local application secrets without returning values or mappings.
- Read secret existence, routing, delivery, and expiry metadata without opening the vault.
- Reserve pending requests and preserve their mappings during fulfillment, including generated fulfillment.
- Rotate locally generated values atomically with bounded rollback history and unchanged lifecycle restrictions.
- Require value-blind usage auditing for agent credential operations, including generated rotation and rollback.
- Exercise CLI, MCP, proxy, and vault paths with synthetic canaries and failure-before-mutation regressions.

Supersedes #488, #490, #502, #533, #536, #537. Leave all six source PRs open; duplicate closure follows only after this consolidation merges.

Validation results and remaining constraints are recorded in BRIDGE_NOTES.md. No GitHub Actions runs were requested.

Before publication, verify the local family heads against the six requested PRs through a repaired Locus session. The added MCP metadata tool also needs an authorized update to the registry publication manifest and release catalog checks. Those protected files are outside this job's edit scope.
