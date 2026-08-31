# Phantom Secrets MCP Server

<!-- mcp-name: io.github.ashlrai/phantom-secrets-mcp -->

Phantom provides value-blind secret metadata and gated lifecycle requests over
MCP stdio. Stored credential values are excluded from MCP responses. This is a
response-contract boundary, not a claim about unrelated files, processes,
tools, terminal output, provider traffic, or values pasted into a conversation.

The legacy `phantom_secrets_auto_rotate` and `phantom_rotate_with_expiry` tool
names now mean only approved local `phm_` token remaps. They never claim
provider rotation, renew credential TTL metadata, clear incidents, or sync an
unchanged credential. Team invites accept only the hosted API's `member` and
`admin` assignment roles.

## Publication status

This directory is publication source, not a publication receipt. As last
independently checked on August 31, 2026:

- the immutable GitHub release and trusted Homebrew formula provide verified
  `v0.7.3` CLI and MCP binaries;
- the npm package and MCP Registry entry remain on the older `0.6.0` track; and
- local `server.json` stages version `0.7.3` and points at a `0.7.3` npm wrapper,
  but neither that file nor its README proves the package or registry entry was
  published.

Do not publish this manifest until the exact npm wrapper is published and
independently verified against the matching native release archives. Do not use
an unpinned npm or package-runner command to configure the current runtime.

## Verified local runtime

Install both binaries from the
[`v0.7.3` GitHub release](https://github.com/ashlrai/phantom-secrets/releases/tag/v0.7.3)
or, on macOS, from the trusted formula:

```bash
brew tap ashlrai/phantom
brew trust --formula ashlrai/phantom/phantom
brew install ashlrai/phantom/phantom
phantom --version
phantom-mcp --version
```

The verified release has archives for macOS arm64/x64, glibc Linux arm64/x64,
and Windows arm64/x64. Artifact existence is not proof that every native
keychain, shell, client, or provider integration has been accepted on every
host. Review the repository's
[platform evidence](https://github.com/ashlrai/phantom-secrets/blob/main/docs/platform-support.md).

Generate client configuration from the installed local CLI:

```bash
phantom setup --client claude
phantom setup --client cursor
phantom setup --client windsurf
phantom setup --client codex
```

Released `v0.7.3` normally records its bundled local `phantom mcp serve`
command. If it cannot resolve that executable, its setup implementation can
fall back to local `phantom-mcp` and finally to an unpinned registry launcher.
That final legacy fallback resolves the older registry track; do not rely on
it. Install both verified `v0.7.3` binaries and inspect the generated command.
Current main removes the network fallback and fails closed when no local MCP
runtime is available. That change is not `v0.7.3` behavior and requires a later
verified release.

Manual stdio configuration can call the reviewed local executable:

```json
{
  "mcpServers": {
    "phantom": {
      "command": "phantom",
      "args": ["mcp", "serve"],
      "transport": "stdio"
    }
  }
}
```

Prefer an absolute executable path where the client supports it.

## Exact current-source tool catalog

The staged `server.json` contains exactly 54 unique tool names generated from
the current Rust server declarations. This list is checked against that JSON in
the web claim-regression suite. The installed runtime's `tools/list` response
remains canonical for that binary.

<!-- tool-catalog:start -->
1. `phantom_add_secret`
2. `phantom_add_secret_interactive`
3. `phantom_apply_expiry_policy`
4. `phantom_audit_alerts`
5. `phantom_audit_analytics`
6. `phantom_audit_anomalies`
7. `phantom_audit_anomalies_realtime`
8. `phantom_audit_export_report`
9. `phantom_audit_hotspot_alerts`
10. `phantom_audit_incidents`
11. `phantom_audit_recent`
12. `phantom_audit_stats`
13. `phantom_capability`
14. `phantom_check`
15. `phantom_cloud_pull`
16. `phantom_cloud_push`
17. `phantom_cloud_status`
18. `phantom_compliance_status`
19. `phantom_copy_secret`
20. `phantom_do`
21. `phantom_doctor`
22. `phantom_env`
23. `phantom_expiry_enforce`
24. `phantom_init`
25. `phantom_leak_incidents_realtime`
26. `phantom_list_secrets`
27. `phantom_list_with_expiry`
28. `phantom_remove_secret`
29. `phantom_rotate`
30. `phantom_rotate_promote`
31. `phantom_rotate_provider`
32. `phantom_rotate_with_candidate`
33. `phantom_rotate_with_expiry`
34. `phantom_rotation_schedule_next`
35. `phantom_secret_rotation_due`
36. `phantom_secrets_auto_rotate`
37. `phantom_secrets_expiry_check`
38. `phantom_setup_workspace`
39. `phantom_status`
40. `phantom_sync`
41. `phantom_team_create`
42. `phantom_team_invite`
43. `phantom_team_key_publish`
44. `phantom_team_list`
45. `phantom_team_members`
46. `phantom_team_vault_pull`
47. `phantom_team_vault_push`
48. `phantom_unwrap`
49. `phantom_validate_all`
50. `phantom_validate_secret`
51. `phantom_validation_history`
52. `phantom_validation_schedule`
53. `phantom_why`
54. `phantom_wrap`
<!-- tool-catalog:end -->

The exact input schemas and effect descriptions are in `server.json`. Some
tools are reads; others can mutate local state, contact providers, persist
metadata, dispatch configured notifications, or create trusted-terminal
requests. A value-free response does not make an operation read-only. Preserve
the live confirmation and approval requirements and review the exact target.

Key authority boundaries:

- `phantom_add_secret` is deprecated and refuses plaintext values through MCP;
  `phantom_add_secret_interactive` creates a trusted-terminal flow.
- `phantom_do` proposes a closed action and does not execute it.
- `phantom_setup_workspace` can propose and request setup, but MCP cannot claim
  or apply the trusted-terminal request.
- Provider consent and credential grants are not MCP tools and confer no Locus,
  broker, deployment, or production execution authority.
- Cloud, validation, rotation, sync, team, scheduling, report-saving, and alert
  paths can have network or persistent effects when their gates are satisfied.

## Token and vault boundary

`phantom init` moves selected values from managed dotenv files into a configured
local vault and writes `phm_` mappings. Under an authenticated local proxy
session, configured HTTP routes can resolve those mappings at the network
boundary. Persistent mappings can therefore remain useful to an active
authorized proxy with the matching vault; rotate them when exposure is
suspected.

Personal Phantom Cloud push/pull can retain a client-encrypted backup for
recovery on the same machine while its keychain-held cloud encryption key
remains available. It is not currently a general cross-machine recovery path.

For each team push, every registered member included in the push receives a
wrapped key share capable of decrypting that vault. Owner and admin roles gate
invitations, but there is no per-secret access partition. Removing a member from
organizational metadata does not revoke a share already distributed to that
member. Offboarding requires rotating affected provider credentials and
publishing a new vault to the intended fixed membership.

## Registry operator workflow

Publication is a separate, authorized release operation. Before invoking the
publisher:

1. Confirm the exact npm package version is live and independently installable.
2. Verify the wrapper downloads only matching attested native archives.
3. Confirm `server.json` names that exact package version and its 54-tool schema
   matches the reviewed runtime.
4. Authenticate the MCP publisher in a trusted operator terminal.
5. Obtain separate authorization for the exact registry version and then
   reconcile the published entry.

These prerequisites do not indicate that npm or MCP Registry publication has
occurred.

## License

MIT
