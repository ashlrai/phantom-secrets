# Phantom Secrets MCP Server

**Value-blind secret metadata and gated lifecycle requests over MCP.**

[![GitHub release](https://img.shields.io/github/v/release/ashlrai/phantom-secrets)](https://github.com/ashlrai/phantom-secrets/releases/tag/v0.7.3)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/ashlrai/phantom-secrets/blob/main/LICENSE)

Phantom's MCP server lets compatible clients inspect protection state and
request secret-management workflows without MCP responses returning stored
credential values. That statement covers the MCP response contract, not other
files, processes, tools, terminal output, network providers, or values pasted
into an agent conversation.

## Verified runtime

Use the local MCP runtime from the immutable
[`v0.7.3` GitHub release](https://github.com/ashlrai/phantom-secrets/releases/tag/v0.7.3)
or the trusted Homebrew formula. The npm registry is on an older release track
as of August 31, 2026. This repository's `0.7.4` wrapper manifest is staged
source, not evidence that a matching npm package has been published or accepted.

On macOS:

```bash
brew tap ashlrai/phantom
brew trust --formula ashlrai/phantom/phantom
brew install ashlrai/phantom/phantom
phantom --version
phantom-mcp --version
```

For other release targets, download both matching binaries, checksums, and
attestations from the verified release. `v0.7.3` provides archives for macOS
arm64/x64, glibc Linux arm64/x64, and Windows arm64/x64. Published archives are
not blanket proof of native keychain, shell, editor, or provider acceptance;
review the [platform support matrix](https://github.com/ashlrai/phantom-secrets/blob/main/docs/platform-support.md).

## Configure a client

Generate configuration with the installed local CLI:

```bash
phantom setup --client claude
phantom setup --client cursor
phantom setup --client windsurf
phantom setup --client codex
```

Released `v0.7.3` normally records its bundled local `phantom mcp serve`
command. If it cannot resolve that executable, its setup implementation can
fall back to a local `phantom-mcp` and finally to an unpinned registry launcher.
That final legacy fallback resolves an older registry track; do not rely on it.
Install both verified `v0.7.3` binaries and inspect the generated command.
Current main removes the network fallback and fails closed when no local MCP
runtime is available. That hardening is not `v0.7.3` behavior and requires a
later verified release.

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
- Provider consent and credential grants occur outside MCP and confer no Locus,
  broker, production, or deployment authority.
- Validation, provider rotation, deployment sync, cloud, and team tools may
  perform network or persistent effects when their required gates are met.

The exact names and schemas are in
[`mcp-registry/server.json`](https://github.com/ashlrai/phantom-secrets/blob/main/mcp-registry/server.json).

## How the local runtime works

1. The MCP server communicates with the client over stdio.
2. MCP tools return names, protection state, plans, and value-free metadata.
3. A trusted terminal remains the boundary for interactive secret entry and
   explicitly authorized local actions.
4. Application processes use `phm_` mappings under an authenticated local proxy
   session; configured HTTP routes can then resolve those mappings at the
   network boundary.

Persistent mappings are not provider credentials, but they can be resolved by
an active authorized proxy with the matching vault. Rotate mappings when their
exposure is suspected.

## Cloud and team boundaries

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
MCP Registry publication, or platform acceptance. Until those channels are
independently published and verified, configure the installed local runtime
from the immutable GitHub release or trusted Homebrew formula.

## Links

- [GitHub](https://github.com/ashlrai/phantom-secrets)
- [Security model](https://github.com/ashlrai/phantom-secrets/blob/main/SECURITY.md)
- [Getting started](https://github.com/ashlrai/phantom-secrets/blob/main/docs/getting-started.md)
- [Platform evidence](https://github.com/ashlrai/phantom-secrets/blob/main/docs/platform-support.md)

## License

MIT
