# First-run delegation FAQ

These answers describe Phantom v0.7.9's supported local, value-blind workflow.
For the full procedure and a task contract, see the [delegation quickstart](delegation-quickstart.md).

## Can I try delegation before adding a real credential?

Yes. Run `node examples/first-five-minutes/run.mjs` from the repository root.
This read-only example uses a checked-in placeholder and makes no network
request. It demonstrates a value-free task contract; it does not initialize a
vault or prove proxy injection or provider acceptance. See the
[walkthrough](../examples/first-five-minutes/README.md).

## What should I do before giving an agent a task?

Keep an independent recoverable copy of each credential, then run
`phantom agent setup --dry-run` from the project root and review its proposed
files and approvals. This preview does not apply changes, but can probe the
configured vault and cloud-login state. Stop on an unexpected path or an
inaccessible vault. Run `phantom init` in your own terminal to protect the
managed dotenv file, then check names and protection with `phantom list` and
`phantom check`. Managed `phm_` mappings are sensitive metadata; do not share
them in chat or logs.

## How do I connect my client and start a session?

Preview the configuration with `phantom setup --client codex --print`, replacing
`codex` with your supported client. Apply the appropriate setup command, restart
the client, and start it through Phantom, for example `phantom exec -- codex`.
See the [client table](delegation-quickstart.md#3-wire-the-selected-client) for
other clients and their setup details. Run `phantom agent doctor` and
`phantom agent report --json` and resolve critical findings before delegating.
Readiness states are local signals, not proof of provider access or acceptance.

## What can the agent see and do with a secret?

Value-blind MCP tools can report secret names and protection state. A supported,
matched proxy route injects its own vault value into its fixed authentication
header; client headers and bodies do not resolve mappings. The child can use
the authenticated local proxy while its session is alive, so `phantom exec` is
not a process sandbox. Scope the task and network authority accordingly. Keep
real values, persistent mappings, and the session proxy bearer out of chat, logs,
and task instructions.

## What if a needed secret is missing or the vault is locked?

Ask the agent to report the secret name only. In a trusted terminal outside the
agent's control, run `phantom add SECRET_NAME` and enter the value at the hidden
prompt. `phantom_add_secret_interactive` only returns that command; it does not
store a value. If MCP reports a locked vault, do not assume it is empty: unlock
the configured vault outside agent authority and retry. Never paste a credential
into chat, source code, or a command argument.

## Why does a request return 401?

Run `phantom why SECRET_NAME` and inspect `exec.delivery`. `no_route` means no
built-in proxy route injects that secret; the child has only a session token.
Check the provider configuration and permissions through an authorized path.
Do not bypass the boundary by exposing the real value to the agent.

## Can the agent change secrets or call a provider automatically?

MCP state-writing, credential-using, and provider/network effects are disabled
by default. Trusted-terminal effects require explicit operator configuration,
confirmation, and a one-use approval token after a typed challenge. A same-user
shell or agent-controlled PTY can defeat that ceremony: leave effects disabled
unless the approval command and approval storage are outside the agent's
authority. Live provider rotation is hard-denied in v0.7.9. Cloud and team tools
require a separately commissioned service; tool availability does not prove one
is reachable or authorized.

## What should the first task and its completion evidence include?

Specify the repository, objective, allowed files and read-only actions, secret
names, forbidden actions, approval boundaries, and required tests. Start with a
narrow task using a local stub, without live provider access. Review the diff,
run focused tests, `phantom check`, `phantom agent doctor`, and
`git diff --check`. Record local evidence separately from any deployment or
live acceptance; local tests do not prove either. If a real value reaches chat
or logs, stop and rotate it at the provider before updating the vault.
