# Phantom Secrets

**Delegate supported API work while reducing credential exposure to agent context.**

[![GitHub release](https://img.shields.io/github/v/release/ashlrai/phantom-secrets)](https://github.com/ashlrai/phantom-secrets/releases/tag/v0.7.3)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/ashlrai/phantom-secrets/blob/main/LICENSE)

AI coding agents with dotenv filesystem access can put API keys into model
context, session logs, malicious tool calls, or generated artifacts. Phantom
moves detected values from managed dotenv files into a local vault and replaces
them with `phm_` mappings. For configured HTTP routes, a local proxy resolves
those mappings at the network boundary. This narrows credential exposure; it
does not control unrelated files, processes, tools, pasted values, or
unsupported traffic.

## Verified installation path

The immutable GitHub release and trusted Homebrew formula are the verified
`v0.7.3` distribution paths. The npm registry is on an older release track as
of August 31, 2026, so do not use an unpinned npm or package-runner command when
you need `v0.7.3` behavior.

On macOS, install the reviewed formula:

```bash
brew tap ashlrai/phantom
brew trust --formula ashlrai/phantom/phantom
brew install ashlrai/phantom/phantom
phantom --version
phantom-mcp --version
```

On macOS, glibc Linux, or Windows, download the matching CLI and MCP archive
from the [verified `v0.7.3` release](https://github.com/ashlrai/phantom-secrets/releases/tag/v0.7.3),
verify it against the release checksums and attestations, and put both local
binaries on `PATH`. The release contains archives for macOS arm64/x64, glibc
Linux arm64/x64, and Windows arm64/x64. That archive matrix does not by itself
prove every keychain, shell, editor, or provider integration on every host; see
the [platform support matrix](https://github.com/ashlrai/phantom-secrets/blob/main/docs/platform-support.md)
for evidence and limits.

## Quick start

```bash
# Inspect every matching project under the current directory without changing it.
phantom init --all . --dry-run

# Protect detected dotenv values after reviewing the plan.
phantom init

# Run a supported application through the local proxy.
phantom exec -- your-command
```

`phantom init` changes managed dotenv files and local vault state. Keep a
recoverable copy before applying it and review the exact files selected by the
command.

## Configure the MCP server

Use the installed local `phantom` binary to generate client configuration:

```bash
phantom setup --client claude
phantom setup --client cursor
phantom setup --client windsurf
phantom setup --client codex
```

Released `v0.7.3` normally records its bundled local `phantom mcp serve`
command. If that executable cannot be resolved, the released setup code can
fall back to a local `phantom-mcp` binary and finally to an unpinned registry
launcher. That final legacy fallback currently resolves an older registry
track; do not rely on it. Install both verified `v0.7.3` binaries and inspect
the generated command. Current main removes the network fallback and fails
closed when no local MCP runtime is available; that hardening is not
`v0.7.3` behavior and requires a later verified release.

For a manual stdio entry, configure the reviewed local executable directly:

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

Prefer the absolute executable path emitted by `phantom setup` when the client
supports it. The current source schema contains 54 unique MCP tool names; the
runtime `tools/list` response from the installed binary is canonical.

## How it works

1. `phantom init` detects candidate values, stores selected values in a local
   keychain or configured encrypted-file vault, and rewrites managed dotenv
   entries with `phm_` mappings.
2. `phantom exec -- <command>` starts a loopback proxy and supplies configured
   service endpoints to the child process.
3. The proxy substitutes mapped credentials on supported request routes and
   forwards those requests over TLS.
4. Persistent project mappings remain resolvable while an authorized proxy has
   access to the matching vault; rotate them when exposure is suspected.

## Selected commands

| Command | Effect |
|---------|--------|
| `phantom init` | Apply dotenv protection to one project |
| `phantom init --all <DIR> --dry-run` | Preview bounded multi-project protection without modifying files or vaults |
| `phantom exec -- <command>` | Run a child process through the local proxy |
| `phantom list` | List stored names, not values |
| `phantom add <NAME>` | Prompt for a value in the trusted terminal |
| `phantom reveal <NAME>` | Intentionally disclose a stored value to the terminal or clipboard |
| `phantom check [--staged]` | Scan selected content for unprotected secret candidates |
| `phantom rotate` | Replace Phantom mappings; it does not rotate provider credentials |
| `phantom wrap [--only <scripts>]` | Wrap scripts selected by its heuristic or explicit filter, preserving `:raw` variants |
| `phantom setup --client <client>` | Write local MCP configuration for a supported client |
| `phantom cloud push` / `pull` | Transfer a client-encrypted personal-vault payload |
| `phantom team ...` | Request fixed-membership shared-vault workflows |

## Cloud and team boundaries

Personal Phantom Cloud push/pull can retain a client-encrypted backup for
recovery on the same machine while its keychain-held cloud encryption key
remains available. It is not currently a general cross-machine recovery path.

Team vaults use per-member key shares. In the current implementation, owner and
admin roles gate invitations, but every registered member included in a vault
push receives a share capable of decrypting that pushed vault. This is not
per-secret access control. Removing a member from organizational metadata does
not revoke an already distributed share; rotate affected provider credentials
and publish a new vault to the intended fixed membership when offboarding.

## Security boundary

- MCP responses are designed to return names and value-free metadata, not
  stored credential values. Other tools and process access remain separate.
- The proxy binds to loopback and applies route and request-size constraints.
- Phantom removes selected values from managed dotenv files during
  initialization, but explicit reveal/export paths and unrelated copies remain
  the operator's responsibility.
- Provider rotation, deployment sync, live validation, cloud operations, and
  team workflows are explicit network or persistent effects with their own
  confirmation and approval requirements.

Read [SECURITY.md](https://github.com/ashlrai/phantom-secrets/blob/main/SECURITY.md)
for the threat model and [Getting Started](https://github.com/ashlrai/phantom-secrets/blob/main/docs/getting-started.md)
for the full workflow.

## Publication status

This directory is source for a thin npm wrapper. Its local `package.json`
version does not prove that the same version is published, signed, or backed by
matching native archives. Use the immutable `v0.7.3` GitHub release or verified
Homebrew formula until the wrapper and native assets are independently
published and accepted.

## License

MIT
