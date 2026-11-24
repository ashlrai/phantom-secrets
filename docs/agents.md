# Agents and `phantom exec`: keeping secrets out of model context

An AI coding agent's context window is a leak path. Anything the agent can
read — `.env` files, environment variables, command output — can end up in a
prompt, a transcript, or a tool call. Phantom keeps real key values out of
that path with three mechanisms:

- **Placeholders** — managed dotenv files and the agent's own environment
  carry `phm_` tokens, never values.
- **Routes** — a loopback proxy injects the real value only into one route's
  fixed auth header, only on the way to that route's upstream.
- **Refusals** — the operations that would expose a value (reveal, positional
  argv, repository-authored routes, connection strings) fail closed.

Every `sh` block on this page is executed in order against a scratch project
by `scripts/test-docs-agents.sh`; run `bash scripts/test-docs-agents.sh`
after editing. The harness sets `PHANTOM_VAULT_PASSPHRASE` so Phantom uses
the encrypted-file vault, the same backend CI and headless setups use. On a
developer laptop the OS keychain is used instead and no passphrase variable
is needed. Commands prefixed with `!` are expected to fail — a refusal is
the feature being demonstrated.

## 1. A project with secrets

Inside your project directory, start from a typical `.env`:

```sh
cat > .env <<'EOF'
OPENAI_API_KEY=EXAMPLE_KEY_VALUE
INTERNAL_SIGNING_KEY=doc-demo-signing-key-not-real
NODE_ENV=development
EOF
phantom init --from .env
```

`init` stores each real value in the vault and rewrites `.env` with
persistent `phm_` mappings. Config values like `NODE_ENV` are left alone.
Check protection without printing the file or its mappings:

```sh
phantom check --json
```

The report's `clean` field is `true` and its `findings` list is empty.

The managed `.env` holds placeholders. Keep dotenv reads denied and use
Phantom's value-blind commands to inspect protection. Persistent `phm_`
mappings are sensitive metadata, so do not print or copy them into a
transcript. No provider accepts a mapping, and the proxy never resolves one
from a client header or body.

## 2. Inventory and status never expose a value

```sh
phantom status
phantom list
```

`status` reports the project without opening the vault; `list` prints names
and route bindings only. An agent can answer "which keys exist" without ever
holding a value.

## 3. Routes decide what a placeholder can do

```sh
phantom why OPENAI_API_KEY
phantom why INTERNAL_SIGNING_KEY
```

Output, abbreviated:

```text
-> OPENAI_API_KEY is PROTECTED
   Service: openai (api.openai.com)
   Exec:   proxied (the real value is injected for its provider)

-> INTERNAL_SIGNING_KEY is PROTECTED
   Exec:   no route (the child gets a session token no provider accepts)
```

A protected key with no built-in route still gets a placeholder, but the
placeholder resolves nowhere — `phantom exec` prints a warning naming it.
Sending it to a provider fails; it is inert by construction.

## 4. `phantom exec`: inspect the environment without printing credentials

Wrap the agent command with `phantom exec -- <your agent command>`. Managed
keys in the child's environment contain fresh, per-session `phm_`
placeholders. This check validates the placeholder's shape and prints only
the result:

```sh
phantom exec -- sh -c '
  token=${OPENAI_API_KEY#phm_}
  test "$token" != "$OPENAI_API_KEY" && test "${#token}" -eq 64 || exit 1
  case "$token" in *[!0-9a-f]*) exit 1 ;; esac
  printf "%s\n" "OPENAI_API_KEY: session placeholder present"
'
```

```text
OPENAI_API_KEY: session placeholder present
```

Each routed service also gets a loopback base URL for the SDK. By default,
that URL contains the session's proxy bearer. The child also receives the
bearer in `PHANTOM_PROXY_TOKEN`; it authorizes requests while the proxy is
running. Do not print either variable. Check the route and its authentication
segment in the child, then print only a fixed result:

```sh
phantom exec -- sh -c '
  test -n "$PHANTOM_PROXY_TOKEN" || exit 1
  route=${OPENAI_BASE_URL#http://127.0.0.1:}
  test "$route" != "$OPENAI_BASE_URL" || exit 1
  port=${route%%/*}
  case "$port" in ""|*[!0-9]*) exit 1 ;; esac
  test "${#port}" -le 5 && test "$port" -ge 1 && test "$port" -le 65535 || exit 1
  test "$OPENAI_BASE_URL" = "http://127.0.0.1:$port/openai/_phantom/$PHANTOM_PROXY_TOKEN/" || exit 1
  printf "%s\n" "OPENAI_BASE_URL: authenticated loopback route present"
'
```

```text
OPENAI_BASE_URL: authenticated loopback route present
```

The proxy binds `127.0.0.1` only, authenticates the session, matches
Phantom's exact built-in routes, and injects the route-owned vault value
into that route's fixed auth header. Client headers and bodies are never
resolved — a `phm_` token pasted into a request body stays a `phm_` token,
and a provider that echoes the real key back has it scrubbed before the
agent sees the response. The merged tests behind those wire-level claims are
named in [phantom-with-agents.md](phantom-with-agents.md).

Secrets used to launch the session are withheld too: `phantom exec` removes
`PHANTOM_VAULT_PASSPHRASE` from the child's environment, so the vault
passphrase is not inherited. Verify absence without printing its value:

```sh
phantom exec -- sh -c '
  test "${PHANTOM_VAULT_PASSPHRASE+x}" != x || exit 1
  printf "%s\n" "PHANTOM_VAULT_PASSPHRASE: absent"
'
```

```text
PHANTOM_VAULT_PASSPHRASE: absent
```

The agent's own stdout is passed through byte for byte — Phantom's progress
lines go to stderr — and its exit code propagates:

```sh
! phantom exec -- false   # the child's failure is not masked: exits non-zero
```

## 5. Adding a key without putting it in argv or chat

`phantom add` refuses positional values — argv is observable by process
inspection and lands in shell history:

```sh
! phantom add BACKUP_KEY sk-value-in-argv
```

```text
Error: Positional secret values are disabled …
```

Piped stdin is the scriptable path that keeps the value out of argv (an
interactive prompt is used when a terminal is attached):

```sh
printf 'EXAMPLE_SECOND_KEY_VALUE\n' | phantom add MISTRAL_API_KEY --stdin
```

The MCP surface refuses plaintext the same way: `phantom_add_secret` accepts
no value — with `generate: true` it creates a new locally generated secret and
returns only a value-free receipt (see
[generated-secrets.md](generated-secrets.md)) — and
`phantom_add_secret_interactive` returns a trusted-terminal command instead.

## 6. Refusals are the point

### Reveal needs a trusted terminal

```sh
! phantom reveal OPENAI_API_KEY
```

```text
Error: Refusing to reveal a secret without attached stdin and stderr terminals
```

There is no stdout path by which an agent turns a `phm_` back into a value.
Reveal requires an attached terminal and an exact typed confirmation — which
is also why an agent must not run the ceremony through a shell or PTY it
controls.

### Repository-authored routes are refused

`phantom exec` launches an agent, and anything in the repository —
`.phantom.toml` included — may have been written by that agent or an
untrusted change. A custom route in repo config would be a self-issued
exfiltration channel, so exec runs only Phantom's exact built-in routes:

```sh
cp .phantom.toml .phantom.toml.bak
cat >> .phantom.toml <<'EOF'

[services.my_gateway]
secret_key = "OPENAI_API_KEY"
pattern = "gateway.internal.example"
header = "Authorization"
header_format = "Bearer {secret}"
secret_type = "api_key"
EOF
! phantom exec -- true
phantom why OPENAI_API_KEY
mv .phantom.toml.bak .phantom.toml
```

```text
Error: Refusing unapproved repository-controlled proxy routing. …
```

`phantom start` runs the same check before it opens the vault, so no
command serves a custom route from `.phantom.toml` today: the file has no
integrity protection, and approving a custom route is not supported yet.
`phantom doctor` names the service that blocks launch. See
[litellm.md](litellm.md) for the LiteLLM case.

### Connection strings are withheld entirely

A `postgres://…`-style URL is vaulted but never proxied: database
credentials need a protocol-aware broker, and `phantom exec` refuses to
start while one is protected in the managed dotenv — for every key, not
just the connection string:

```sh
mkdir db-demo
cd db-demo
cat > .env <<'EOF'
DATABASE_URL=postgres://EXAMPLE_USER@localhost:5432/docdb
OPENAI_API_KEY=EXAMPLE_KEY_VALUE
EOF
phantom init --from .env
! phantom exec -- true
phantom why DATABASE_URL
cd ..
```

```text
Error: Refusing to expose connection-string secret(s) to the child process: DATABASE_URL. …
```

Run database work (migrations, `psql`, ORMs) from a terminal you trust,
outside `phantom exec`.

## 7. Audit the result

```sh
phantom check
phantom doctor
phantom agent doctor
```

- `check` is the pre-commit scan: it fails if any managed file still holds
  plaintext secrets.
- `doctor` reports repo-local health — `.env` ignored, `.env.example`
  present, route safety — without opening the vault.
- `agent doctor` reports readiness for AI tooling: MCP client wiring,
  pre-commit hook, audit posture.

## What the model context ends up holding

The walkthrough prints:

- protection results and fixed confirmations about the child environment,
- names, routes, and verdicts from `status`, `list`, `why`, `doctor`,
- refusal messages where a person is required.

These checks do not print managed mappings, the vault passphrase, or the
session's proxy bearer. The child still holds the bearer and authenticated
base URLs in its environment, and it can use the active proxy. Phantom is
not a same-user sandbox; keep those variables and managed dotenv files out
of transcripts. For proxy-side guarantees covering header enforcement, body
pass-through, echo scrubbing, and streaming, see
[phantom-with-agents.md](phantom-with-agents.md); for installation and
vault backends see [getting-started.md](getting-started.md).
