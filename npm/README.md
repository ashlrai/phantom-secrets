# Phantom Secrets

**Delegate supported API work while reducing credential exposure to agent context.**

[![GitHub release](https://img.shields.io/github/v/release/ashlrai/phantom-secrets)](https://github.com/ashlrai/phantom-secrets/releases)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/ashlrai/phantom-secrets/blob/main/LICENSE)

AI coding agents with dotenv filesystem access can put API keys into model
context, session logs, malicious tool calls, or generated artifacts. Phantom
moves detected values from managed dotenv files into a local vault and replaces
them with `phm_` mappings. For configured HTTP routes, an authenticated local
proxy injects only the matched route's vault value into its fixed auth header;
client headers and bodies never resolve mappings. This narrows credential exposure; it
does not control unrelated files, processes, tools, pasted values, or
unsupported traffic.

## Install an exact published version

This wrapper is version `0.7.6`. Its manifest and this README do not prove that
the npm package or matching GitHub release has been published. Verify the exact
npm version before installing it:

```bash
npm view phantom-secrets@0.7.6 version dist.integrity dist.tarball --registry=https://registry.npmjs.org/
npm install --global phantom-secrets@0.7.6 --registry=https://registry.npmjs.org/
phantom --version
```

The first invocation downloads the matching native binary from the exact
[`v0.7.6` GitHub release](https://github.com/ashlrai/phantom-secrets/releases/tag/v0.7.6),
verifies the archive against its `.sha256` sidecar, extracts only the expected
binary from the closed two-binary archive, and records a private local cache
manifest. The wrapper does not itself verify GitHub attestations or publisher
identity. If the npm query, release, checksum, or expected `phantom 0.7.6`
version is unavailable, stop instead of substituting an unpinned package or
release.

The wrapper supports macOS arm64/x64, glibc Linux arm64/x64, and Windows
arm64/x64. Published archives do not by themselves prove every keychain,
shell, editor, or provider integration on every host; see the
[platform support matrix](https://github.com/ashlrai/phantom-secrets/blob/main/docs/platform-support.md).

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

Version `0.7.6` records the installed local `phantom mcp serve` command when it
can resolve that executable, otherwise it looks for a local `phantom-mcp`.
Setup has no network package-runner fallback and fails closed when neither
local runtime is available. Inspect the generated command before trusting it.

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
3. The proxy matches an exact supported route, discards client control of its
   auth header, injects the route-owned value there, and forwards over TLS.
4. Client headers and bodies never resolve persistent project mappings. Rotate
   exposed mappings, and protect the live proxy bearer because it can invoke
   configured routes.

## Selected commands

| Command | Effect |
|---------|--------|
| `phantom init` | Apply dotenv protection to one project; use `--empty` before the first add in a new project |
| `phantom init --all <DIR> --dry-run` | Preview bounded multi-project protection without modifying files or vaults |
| `phantom exec -- <command>` | Run a child process through the local proxy |
| `phantom list` | List stored names, not values |
| `phantom add <NAME>` | Create a new protected name in an initialized project; existing names are denied before value input and never replaced |
| `phantom reveal <NAME>` | Intentionally disclose a stored value to the terminal or clipboard |
| `phantom check [--staged]` | Scan selected content for unprotected secret candidates |
| `phantom rotate` | After an exact attached-terminal challenge, replace all Phantom mappings; headless use is denied and provider credentials are unchanged |
| `phantom wrap [--only <scripts>]` | Wrap scripts selected by its heuristic or explicit filter, preserving `:raw` variants |
| `phantom setup --client <client>` | Write local MCP configuration for a supported client |
| `phantom cloud push` / `pull` | Transfer a client-encrypted personal-vault payload |
| `phantom team ...` | Request fixed-membership shared-vault workflows |

## Cloud and team boundaries

These are source-backed CLI protocols, not evidence of a commissioned public
service. Cloud and team requests require a separately verified deployment and
account entitlement; the public hosted service is not currently commissioned
for authenticated use.

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
- The proxy binds to loopback, applies route/request-size constraints, leaves
  client headers/bodies unresolved, and injects only fixed route-owned auth.
- Phantom removes selected values from managed dotenv files during
  initialization, but explicit reveal/export paths and unrelated copies remain
  the operator's responsibility.
- Live provider issuance/rotation is hard-denied before credential or network
  access in 0.7.6. Deployment sync, live validation, cloud operations, and team
  workflows are separate network/persistent effects with their own gates.

Read [SECURITY.md](https://github.com/ashlrai/phantom-secrets/blob/main/SECURITY.md)
for the threat model and [Getting Started](https://github.com/ashlrai/phantom-secrets/blob/main/docs/getting-started.md)
for the full workflow.

## Publication status

This directory is source for a thin npm wrapper. Its local `package.json`
version does not prove npm publication, matching native-archive publication,
signing, or platform acceptance. Verify `phantom-secrets@0.7.6` with the exact
`npm view` command above and verify the matching immutable GitHub release before
installation. Maintainers should follow the guarded
[npm publication runbook](https://github.com/ashlrai/phantom-secrets/blob/main/docs/npm-publication.md).

## License

MIT
