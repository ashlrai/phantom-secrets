# How to protect API keys from AI coding agents

AI coding agents are most useful when they can run the application, call APIs,
and verify their work. Giving the agent a plaintext `.env` solves the access
problem by creating a disclosure problem: the value can enter tool output,
shell history, logs, patches, or model context.

Phantom takes a narrower approach. It moves successfully managed dotenv values
into a local vault, leaves non-provider `phm_` placeholders in the project, and
injects a route-owned credential only when an authenticated request matches an
explicitly supported HTTP route. The agent does not receive the real value.

This guide uses the reviewed public `v0.7.5` release. Source may be newer than
that release; verify the release-state notice before choosing an install path.

## The short workflow

On macOS, install the reviewed Homebrew formula:

```bash
brew tap ashlrai/phantom
brew trust --formula ashlrai/phantom/phantom
brew install ashlrai/phantom/phantom
```

For Linux, Windows, or direct verification, download the matching `v0.7.5`
archive and adjacent checksum from the
[`v0.7.5` release](https://github.com/ashlrai/phantom-secrets/releases/tag/v0.7.5).
The [getting-started guide](./getting-started.md#install) lists all six native
targets and verification commands.

From a trusted terminal in one project:

```bash
phantom init
phantom agent doctor
phantom check
phantom exec -- claude
```

Replace `claude` with the supported client or local process you intend to run.
Inside the managed dotenv file, protected entries now contain `phm_...`
placeholders rather than provider credentials.

## What each step proves

### 1. `phantom init`

`phantom init` detects supported secret-shaped dotenv values, stores each real
value in the selected local vault, and atomically rewrites the managed dotenv
entry with a random placeholder. It creates no plaintext project-local backup.
Keep an independent recovery copy in the provider console or an approved
password manager.

The command is a local mutation. Run it from a terminal you control, inspect the
selected project and dotenv path, and stop on any partial or uncertain result.

### 2. `phantom agent doctor`

The agent-readiness report checks the local Phantom configuration and tells you
which conditions still need attention. A green local report is evidence about
that checkout and machine; it is not a certification and does not grant an
agent authority to change provider, production, billing, or account state.

### 3. `phantom check`

`phantom check` scans supported dotenv files for unprotected secret-shaped
values. Use `phantom check --staged` in a pre-commit workflow. The scan is a
bounded detector, not a substitute for repository-wide secret scanning or
provider-side revocation of credentials that were already exposed.

### 4. `phantom exec -- <command>`

`phantom exec` starts an authenticated proxy on `127.0.0.1`, creates a fresh
session authorization, and configures implemented SDK base-URL overrides for
the child process. The proxy injects authentication only after an exact route
match. Client-supplied auth overrides and placeholders in headers or bodies do
not select a secret.

When the proxy exits, its session bearer becomes invalid. Upstream API traffic
still leaves the machine over TLS and reaches the provider.

## Verify that the boundary works

Use synthetic or non-production credentials for the first evaluation.

1. Confirm that the managed `.env` contains `phm_` placeholders, without
   copying those placeholders into chat or a public issue.
2. Run `phantom list` and confirm that it returns names and detected services,
   never values.
3. Run `phantom agent doctor` and resolve only the findings you understand.
4. Launch one supported, bounded API operation through `phantom exec`.
5. Confirm that logs, agent output, patches, and audit records contain no real
   credential value.
6. Stop the proxy and confirm the old session path or bearer no longer works.

For the exact proxy and attacker model, inspect
[`THREAT_MODEL.md`](../THREAT_MODEL.md). For platform-specific evidence and
limits, inspect [platform support](./platform-support.md).

## What Phantom does not protect

Phantom does not make an untrusted same-user process safe. Such a process may
read files the user can read, inspect process state, emulate terminal input, or
interfere with local networking. Phantom also does not erase credentials from
old commits, shell history, screenshots, provider logs, unrelated files, or
another secret manager.

Database connection strings can be detected and vaulted, but database drivers
do not use Phantom's HTTP proxy. `phantom exec` fails closed rather than placing
a protected database URL back into the child environment. Unsupported routes
and protocols are not silently treated as protected.

Phantom's account, provider-issuance, and production authority foundations are
inactive and deny by default. Protecting a local dotenv file does not authorize
an agent to create accounts, accept terms, attach payment methods, change MFA,
or mint production credentials.

## Client-specific setup

- [Claude Code](./claude-code.md)
- [Cursor](./cursor.md)
- [Windsurf](./windsurf.md)
- [Codex](./codex.md)
- [Value-blind MCP secrets manager](./mcp-secrets-manager.md)

If the workflow matches your environment, inspect and star the
[Phantom source repository](https://github.com/ashlrai/phantom-secrets). A star
helps other developers discover the project; it is not evidence that a local
security boundary passed.
