# Phantom Secrets MCP Server

**Value-blind secret metadata and gated lifecycle requests over MCP.**

[![GitHub release](https://img.shields.io/github/v/release/ashlrai/phantom-secrets)](https://github.com/ashlrai/phantom-secrets/releases)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/ashlrai/phantom-secrets/blob/main/LICENSE)

Phantom's MCP server lets compatible clients inspect protection state and
request secret-management workflows without MCP responses returning stored
credential values. That statement covers the MCP response contract, not other
files, processes, tools, terminal output, network providers, or values pasted
into an agent conversation.

## Install an exact published version

This wrapper is version `0.7.7`. Its manifest and this README do not prove npm,
GitHub, or MCP Registry publication. Verify the exact npm version before
installing it:

```bash
npm view phantom-secrets-mcp@0.7.7 version dist.integrity dist.tarball --registry=https://registry.npmjs.org/
npm install --global phantom-secrets-mcp@0.7.7 --registry=https://registry.npmjs.org/
phantom-mcp --version
```

The first invocation downloads the matching native binary from the exact
[`v0.7.7` GitHub release](https://github.com/ashlrai/phantom-secrets/releases/tag/v0.7.7),
verifies the archive against its `.sha256` sidecar, extracts only the expected
binary from the closed two-binary archive, and records a private local cache
manifest. The wrapper does not itself verify GitHub attestations or publisher
identity. If the npm query, release, checksum, or expected `phantom-mcp 0.7.7`
version is unavailable, stop instead of substituting an unpinned launcher.

The wrapper supports macOS arm64/x64, glibc Linux arm64/x64, and Windows
arm64/x64. Published archives do not by themselves prove every keychain,
shell, editor, or provider integration on every host; review the
[platform support matrix](https://github.com/ashlrai/phantom-secrets/blob/main/docs/platform-support.md).

## Configure a client

Generate configuration with the installed local CLI:

```bash
phantom setup --client claude
phantom setup --client cursor
phantom setup --client windsurf
phantom setup --client codex
```

Version `0.7.7` records the installed local `phantom mcp serve` command when it
can resolve that executable, otherwise it looks for a local `phantom-mcp`.
Setup has no network package-runner fallback and fails closed when neither
local runtime is available. Inspect the generated command before trusting it.

A manual stdio configuration can call the reviewed local CLI directly:

```json
{
  "mcpServers": {
    "phantom": {
      "command": "phantom",
      "args": ["mcp", "serve"]
    }
  }
}
```

Prefer an absolute executable path where supported. Do not substitute an
unpinned package-registry launcher when version parity matters.

## Tool contract

The current source schema contains 54 unique tool names and is generated from
the Rust server declarations. The installed runtime's `tools/list` response is
canonical for that binary. The catalog includes these workflow groups:

- conversation authority, workspace proposals, status, doctor, classification,
  checks, and value-free environment inventory;
- interactive add, remove, token remapping, copy, selective script wrapping,
  and local initialization;
- provider validation and rotation, deployment sync, and personal cloud
  requests;
- team membership and fixed-membership encrypted-vault requests; and
- audit, anomaly, incident, compliance, expiry, and scheduling workflows.

Some names describe reads while others can change local state, contact a
provider, persist metadata, send a notification, or create a trusted-terminal
request. A value-free response does not make an operation read-only. Consult the
tool's live input schema and effect metadata, preserve explicit confirmation and
approval gates, and review its target before invocation.

Important boundaries:

- `phantom_add_secret` is deprecated and refuses plaintext secret values passed
  over MCP. `phantom_add_secret_interactive` creates a trusted-terminal flow.
- `phantom_do` proposes a closed engineering action and does not execute it.
- `phantom_setup_workspace` can propose and request trusted-terminal setup; MCP
  does not claim or apply the request.
- Provider enrollment and live issuance/refresh/renewal/rotation/revocation are
  hard-denied before credential and network access in 0.7.7, including from
  MCP. Protocol source and test mocks confer no Locus, broker, provider,
  production, or deployment authority.
- Validation, deployment sync, cloud, and team tools may
  perform network or persistent effects when their required gates are met.

The exact names and schemas are in
[`mcp-registry/server.json`](https://github.com/ashlrai/phantom-secrets/blob/main/mcp-registry/server.json).

## How the local runtime works

1. The MCP server communicates with the client over stdio.
2. MCP tools return names, protection state, plans, and value-free metadata.
3. A trusted terminal remains the boundary for interactive secret entry and
   explicitly authorized local actions.
   Effectful compatibility tools are disabled by default; enable
   `PHANTOM_MCP_EFFECTS=trusted-terminal` only outside agent authority. The
   approval command requires attached stdin/stderr, displays the exact
   value-blind request, and requires a fresh typed challenge. A same-user shell
   or agent-controlled PTY can defeat it, so leave effects disabled unless the
   approval command and storage are outside agent authority.
4. Application processes use `phm_` mappings under an authenticated local proxy
   session. Client headers and bodies never resolve them; exact configured
   routes inject only their own vault value into a fixed auth header.

Persistent mappings are not provider credentials and are never client-resolved,
but remain sensitive metadata. A stolen live proxy bearer can authorize exact
configured routes; rotate mappings and bearers when exposure is suspected.

## Cloud and team boundaries

These tools expose source-backed protocols, not evidence of a commissioned
public service. Cloud and team requests require a separately verified
deployment and account entitlement; the public hosted service is not currently
commissioned for authenticated use.

Personal Phantom Cloud push/pull can retain a client-encrypted backup for
recovery on the same machine while its keychain-held cloud encryption key
remains available. It is not currently a general cross-machine recovery path.

For a team push, every registered member included in that push receives a
wrapped key share capable of decrypting the shared vault. Owner and admin roles
gate invitations; they do not create per-secret access partitions. Removing a
member from organizational metadata does not revoke an already distributed key
share. Offboarding requires rotating affected provider credentials and pushing
a new vault to the intended fixed membership.

## Publication status

This directory is the source for a thin native-binary wrapper. The local
`package.json` version is not proof of npm publication, native artifact parity,
MCP Registry publication, or platform acceptance. Verify
`phantom-secrets-mcp@0.7.7` with the exact `npm view` command above, then verify
the matching immutable GitHub release. An npm publication still does not prove
the separate MCP Registry entry. Maintainers should follow the guarded
[npm](https://github.com/ashlrai/phantom-secrets/blob/main/docs/npm-publication.md)
and [MCP Registry](https://github.com/ashlrai/phantom-secrets/blob/main/docs/mcp-registry-publication.md)
publication runbooks.

## Links

- [GitHub](https://github.com/ashlrai/phantom-secrets)
- [Security model](https://github.com/ashlrai/phantom-secrets/blob/main/SECURITY.md)
- [Getting started](https://github.com/ashlrai/phantom-secrets/blob/main/docs/getting-started.md)
- [Platform evidence](https://github.com/ashlrai/phantom-secrets/blob/main/docs/platform-support.md)

## License

MIT
