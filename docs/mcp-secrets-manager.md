# MCP secrets manager for AI coding agents

Phantom exposes a value-blind Model Context Protocol interface for Claude Code,
Cursor, Windsurf, Codex, and other MCP-compatible clients. The interface lets
an agent inspect protected secret names, readiness, and audit metadata without
returning plaintext credential values through MCP.

The key distinction is simple: MCP carries control and value-free status;
Phantom's local vault and authenticated proxy handle credential use. A secret
value must never be accepted as a tool argument, result, log, or chat message.

This guide describes the reviewed public `v0.7.5` release. The runtime
`tools/list` response for the installed binaries is the canonical tool catalog.

## Install both reviewed binaries

On macOS:

```bash
brew tap ashlrai/phantom
brew trust --formula ashlrai/phantom/phantom
brew install ashlrai/phantom/phantom
```

On macOS, Linux, or Windows, you can instead use the exact `v0.7.5` archive for
your platform from [GitHub Releases](https://github.com/ashlrai/phantom-secrets/releases/tag/v0.7.5).
Verify the adjacent SHA-256 checksum and place both `phantom` and `phantom-mcp`
on `PATH`. Unpinned npm, npx, and Cargo installs are not the reviewed `v0.7.5`
release path.

## Connect an MCP client

Run one setup command from a trusted terminal:

```bash
phantom setup --client claude
phantom setup --client cursor
phantom setup --client windsurf
phantom setup --client codex
```

Choose one command for the client you use. To inspect a generic MCP snippet
without writing a client configuration:

```bash
phantom setup --client claude --print
```

Review the exact file and command before restarting the client. The released
setup path requires a local executable and has no network package-runner
fallback.

## Start with value-free inspection

After protecting a project with `phantom init`, an agent can use read-only tools
such as:

- `phantom_list_secrets` to list protected names without values;
- `phantom_status` to inspect project and vault state;
- `phantom_check` to scan supported dotenv content;
- `phantom_doctor` to diagnose the current setup; and
- `phantom_why` to explain why a name is or is not protected.

The agent should use these tools instead of reading `.env`. Persistent `phm_`
placeholders are managed mappings, not broken provider credentials and not
public identifiers.

## Add a credential without sending it through MCP

Never paste a provider key into a tool argument. The legacy
`phantom_add_secret` MCP tool is hard-deprecated and refuses plaintext.

Use `phantom_add_secret_interactive` instead. It requests a trusted-terminal
ceremony so the user enters the value outside the MCP and model context. The
agent may name the required variable and explain why it is needed; it must not
ask the user to paste the value into chat.

Mutating MCP tools require their documented confirmation and out-of-band
approval gates. The exact installed schema—not an old directory listing—is the
source of truth for parameters.

## Use the credential without revealing it

MCP does not deliver the credential to the agent. Launch supported API work
through the CLI boundary:

```bash
phantom agent doctor
phantom exec -- claude
```

The child receives session placeholders and an authenticated loopback route.
When a request matches an implemented route, the proxy discards client control
of that route's auth header and injects the route-owned value. Unsupported
protocols fail closed.

## A safe delegation contract

Give the coding agent an explicit task boundary:

```text
Use Phantom's value-blind MCP tools for secret metadata.
Do not read or print .env values.
Do not ask for a credential in chat or a tool argument.
Run only the named development command through phantom exec.
Do not change provider, billing, production, account, MFA, or recovery state.
Stop and report any unsupported route or approval request.
```

That prompt is guidance, not an authorization system. Human approval and the
runtime's fail-closed controls remain the security boundary.

## Verify the MCP boundary

1. Inspect the installed `phantom` and `phantom-mcp` versions.
2. Review the generated MCP client configuration.
3. Call `tools/list` and compare it with the installed release documentation.
4. Confirm that list, status, doctor, check, and why responses contain no secret
   values.
5. Confirm that the deprecated plaintext-add path refuses the request before a
   value is processed.
6. Run one supported non-production request through `phantom exec` and inspect
   output for disclosure.

Read the [safe delegation quickstart](./delegation-quickstart.md),
[architecture](./architecture.md), and
[threat model](../THREAT_MODEL.md) before widening the workflow.

## Current limits

MCP metadata does not prove that a provider request, deployment, hosted service,
team entitlement, or customer workflow is active. The same-user terminal
approval mechanism is not a phishing-resistant production authorization layer.
Provider account creation, live credential issuance, and the broader execution
kernel remain inactive and fail closed.

Phantom should eventually let agents use short-lived, task-bound capabilities
under a human-approved mandate. It should not let an agent accept legal terms,
enter payment data, bypass CAPTCHA or MFA, alter account recovery, or obtain
root/admin credentials.

Inspect and star the
[Phantom source repository](https://github.com/ashlrai/phantom-secrets) if the
value-blind MCP model fits your workflow.
