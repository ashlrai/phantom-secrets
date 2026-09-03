# Delegate a coding task without putting real keys in agent context

This guide is for a developer who wants Claude Code, Codex, Cursor, Windsurf,
or GitHub Copilot to work on a repository that uses API credentials. It creates
a bounded delegation contract around Phantom's shipped CLI, vault, local proxy,
and value-blind MCP tools.

Completing this guide protects managed dotenv values and verifies local setup.
It does not grant an agent general production authority, approve provider or
deployment changes, activate Locus, or prove that a customer workflow works.

## Before you begin

You need:

- a Git repository and a supported local shell;
- both `phantom` and `phantom-mcp` from the reviewed `v0.7.4` GitHub/Homebrew distribution;
- the AI client you intend to use; and
- an independent recoverable copy of each real credential, such as the
  provider's credential console or an approved password manager.

Never paste a real credential into chat, a task brief, an agent instruction
file, or a command-line argument. Use secret names such as
`STRIPE_SECRET_KEY`, not values.

## 1. Preview the repository readiness work

From the repository root, run:

```bash
phantom agent setup --dry-run
```

This is a read-only preview. Review the listed files, commands, and any item
marked `requires_approval`. A readiness status is a local configuration signal;
it is not a security certification or permission for the agent to act.

Stop if Phantom reports an unexpected dotenv path, an inaccessible vault, or a
configuration you do not own.

## 2. Protect the project's managed dotenv file

`init` is a local mutation: it stores detected secret values in the selected
vault backend, atomically rewrites the managed dotenv file with `phm_`
placeholders, writes Phantom configuration, generates `.env.example`, and
attempts to install the repository pre-commit check.

Install the reviewed `v0.7.4` release using the platform-specific path in
[getting started](./getting-started.md#install), then run `phantom init`.

If auto-detection selects the wrong file, stop and use an explicit path shown by
`phantom init --help`. Phantom intentionally does not leave a plaintext
project-local backup. Recover a lost provider value from the independent source
named in the prerequisites, not from an agent transcript.

Confirm that secret *names* are present without printing values:

```bash
phantom list
phantom check
```

## 3. Wire the selected client

Previewing prints configuration without changing the client:

```bash
phantom setup --client codex --print
```

Apply one supported setup writer, then restart the client:

| Client | Configure MCP | Start a proxy-scoped session | Detailed guide |
|---|---|---|---|
| Claude Code | `phantom setup --client claude` | `phantom exec -- claude` | [Claude Code](claude-code.md) |
| Codex | `phantom setup --client codex` | `phantom exec -- codex` | [Codex](codex.md) |
| Cursor | `phantom setup --client cursor` | `phantom exec -- cursor .` | [Cursor](cursor.md) |
| Windsurf | `phantom setup --client windsurf` | `phantom exec -- windsurf .` | [Windsurf](windsurf.md) |

For GitHub Copilot, Phantom does not ship a Copilot-specific setup writer.
Repository instructions can live in `.github/copilot-instructions.md`; MCP is
configured through the supported VS Code surface. Keep build or test processes
that need local credentials inside a `phantom exec -- <command>` session.

The setup writers change client configuration. Review the preview first and
retain the previous client file if your organization requires rollback. Phantom
merges its MCP entry, but it is not a general client-configuration manager.

## 4. Verify the boundary before delegating

```bash
phantom agent doctor
phantom agent report --json
```

Resolve critical findings before continuing. The JSON report can return
`unsafe`, `protected`, `verified`, `team-ready`, or `compliance-ready`.
Those names describe Phantom's local readiness policy:

- `unsafe` means a critical local finding remains;
- `protected` means critical findings are absent but optional or verification
  work remains;
- `verified` additionally requires MCP wiring, a pre-commit check, and no
  warning findings;
- `team-ready` additionally observes cloud login and configured sync targets;
- `compliance-ready` additionally observes audit mode.

None of these states proves a deployment, provider permission, regulatory
certification, organizational control, or customer acceptance.

## 5. Give the agent an explicit task contract

Copy the [agent policy](../examples/agent-delegation/AGENT_POLICY.md) into the
instruction surface your repository already uses, and fill in the
[task brief](../examples/agent-delegation/TASK_BRIEF.md) for the specific job.

At minimum, state:

1. the exact repository, branch, and objective;
2. which files and external systems are in scope;
3. secret names the task may depend on, without values;
4. allowed read-only actions;
5. mutations that require a fresh human approval;
6. forbidden actions; and
7. the tests and evidence required for completion.

A useful first task is narrow and reversible, for example:

> Add a provider client behind the existing interface and test it with a local
> stub. You may inspect value-blind Phantom metadata. Do not reveal credentials,
> contact the live provider, deploy, sync secrets, rotate keys, or publish.

## 6. Run the task through Phantom

Start the selected client with the local proxy active. For example:

```bash
phantom exec -- codex
```

Application or test processes launched inside this session receive Phantom's
proxy routing. The child process can use the authenticated loopback proxy while
the session is alive, so `phantom exec` is a credential-injection boundary, not
a process sandbox.

Agents can inspect secret names and protection state through MCP. If a secret is
missing, the agent should request `phantom_add_secret_interactive`; enter the
value only in the trusted terminal prompt. A `confirm: true` MCP parameter is a
tool gate, not standing permission for unrelated changes.

## 7. Close the task with evidence

Before accepting the result:

```bash
phantom check
phantom agent doctor
git diff --check
git status --short
```

Also run the repository's focused tests and review the diff. Record separately:

- source changes and local tests;
- any built artifact;
- any deployment or provider operation;
- any live acceptance; and
- anything skipped or blocked.

Local source and tests do not prove the later layers. If the task requires a
deployment, secret sync, credential rotation, provider grant, cloud/team write,
or workspace apply, stop and obtain approval for that exact target and recovery
plan.

## Failure and recovery

- **A real value entered chat or logs:** stop, remove it from the active surface
  where possible, rotate it at the provider, then update the Phantom vault.
- **A readiness check becomes `unsafe`:** stop agent work and resolve the
  critical finding before retrying.
- **The proxy is unavailable:** stop network-dependent tests; do not bypass it
  by exposing a real credential to the agent.
- **Client configuration is wrong:** restore the reviewed prior client config,
  use `phantom setup --client <client> --print`, and reconcile the exact MCP
  entry before restarting.
- **A live mutation was not authorized:** stop, preserve logs without secret
  values, reconcile the affected provider or platform, and use its approved
  rollback path.

For a multi-person rollout, continue with the
[enterprise adoption guide](enterprise-adoption.md).
