# Phantom + Claude Code

## Why this combination exists

Claude Code can inspect files that its workspace permissions allow. If those permissions include a dotenv file with real values, the credentials can enter agent context, transcripts, tool logs, or generated code.

Phantom removes real values from managed dotenv files, keeps dotenv read permissions closed, and exposes value-blind MCP metadata instead. Application and test processes load `phm_` placeholders. On supported HTTP paths, the authenticated proxy matches an exact route and injects only that route's vault value into its fixed auth header; client headers and bodies never resolve placeholders.

The MCP integration goes further: Claude gains the release-schema-verified tool
catalog for value-free secret workflows. The current release contract enforces
54 unique tools; runtime `tools/list` is canonical.

---

## Install

### Step 1: install Phantom

Install the reviewed `v0.7.9` binary using the platform-specific, checksum-
verified path in [getting started](./getting-started.md#install), then run
`phantom init` in the project.

### Step 2: wire up Claude Code (one command)

```bash
phantom setup --client claude
```

In `v0.7.9`, this merges the `phantom` MCP server
into the project's `.mcp.json`. Separately, it removes only the legacy Phantom
MCP entry and Phantom-managed dotenv read grants from
`.claude/settings.local.json`, preserving unrelated servers and permission
rules. Dotenv denies remain a defense-in-depth boundary.

**Release compatibility:** `v0.7.9` is the first release with this correction.
`v0.7.8` and earlier binaries (including the Homebrew formula until it is bumped
to `v0.7.9`) wrote MCP registration into `.claude/settings.local.json`, which is
not Claude Code's supported MCP registration location. After upgrading to
`v0.7.9`, rerun `phantom setup --client claude` to migrate the legacy entry. If
you must stay on `v0.7.8`, run `phantom setup --client claude --print` and
manually merge only its `mcpServers.phantom` entry into `.mcp.json`. Keep
permission settings in `.claude/settings.local.json`; do not copy them into
`.mcp.json` or overwrite unrelated server entries.

The corrected setup validates both files before writing and uses exact
before-images to avoid overwriting concurrent edits. It attempts rollback after
an observed later write failure; separate file replacements are not a
crash-atomic filesystem operation. If setup reports a partial or uncertain
result, inspect both files locally before retrying.

Claude Code uses `.mcp.json` for project-scoped registration. In interactive
sessions, review and approve the server when Claude prompts; Phantom setup
does not grant that approval. Headless client behavior differs, so inspect the
configuration before starting automated sessions. See the
[Claude Code MCP scope documentation](https://code.claude.com/docs/en/mcp#project-scope).
The generated command is a machine-local executable path; review it before
sharing `.mcp.json` with teammates, whose installed paths may differ.

Install both `v0.7.9` release binaries before setup. Version `0.7.9` records the
running `phantom` executable with `mcp serve` when it can resolve that runtime,
otherwise it looks for a local `phantom-mcp`. Setup has no network
package-runner fallback and fails closed when neither local runtime is
executable. Keep both verified binaries installed and inspect the generated
entry.

Verify it registered:

```bash
claude mcp list
claude mcp get phantom
```

Check that `phantom` is connected, not merely listed or pending approval.

### Step 3: run Claude with the proxy active

```bash
phantom exec -- claude
```

The proxy starts on `127.0.0.1`, `*_BASE_URL` environment variables are set, and Claude launches with the full Phantom environment. When your code runs API calls inside the Claude Code session, the proxy handles credential injection.

### Step 4: verify agent readiness

```bash
phantom agent doctor
phantom agent report --json
```

Use this before giving Claude broad autonomy. It checks the repo's `.env` files, Phantom config, vault access, unprotected secrets, MCP wiring, package script wrapping, pre-commit protection, cloud login, team state, audit status, and sync targets. The report returns one state: `unsafe`, `protected`, `verified`, `team-ready`, or `compliance-ready`.

---

## Core MCP tools Claude can use

Once `phantom` is registered, Claude can call the full runtime
catalog. The following table highlights the core workflows; use MCP
`tools/list` for the canonical catalog.

### Read-only (safe to call any time)

Status tools return three forms: a short human summary text block, the same
value-blind report as JSON text, and that report as MCP `structuredContent`.
Reports carry names, counts, and states only, never secret values or phantom
tokens, and include `next_step` where the agent has something to do next.
Tools whose whole answer was already JSON (`phantom_capability`, `phantom_do`,
`phantom_setup_workspace`, the audit, leak-incident,
compliance, validation, expiry, and rotation-schedule tools)
keep that JSON as their only text block and now also attach it as
`structuredContent`.

| Tool | What it does |
|------|-------------|
| `phantom_list_secrets` | List secret names in the vault. Never returns values. JSON: `{count, secrets: [{name, service}]}`. Before `phantom init` it opens no vault and returns `initialized: false` with a `next_step`. With a locked encrypted-file vault it says "Vault locked, not empty." and names the unlock step instead of reporting an empty vault. |
| `phantom_list_with_expiry` | List secret names with TTL state. JSON: `{count, show_expiry, expired, expiring_soon, secrets: [{name, service, status?, expires_at?, days_remaining?}]}`; `status` is `expired`, `expiring_soon`, `ok`, or `no_expiry`. Before init and with a locked vault it behaves like `phantom_list_secrets`. |
| `phantom_status` | Show project ID, managed `.env` protection counts, and service mappings without opening the vault. JSON: `{initialized, project_id, vault_inspected: false, dotenv: {path, entries, phantom_tokens, unprotected} \| null, services: [{name, secret_key, pattern}], next_step}`. |
| `phantom_why` | Explain why a specific `.env` key is or isn't classified as a secret (shows the matching heuristic). Never opens the vault, and works before `phantom init` (it then classifies `./.env`, as `phantom why` does, with `exec: null`). JSON: `{key, dotenv_exists, found, classification, protected, reason, matched_pattern, service, exec, next_step}`; `classification` is `protected`, `public_key`, `secret_unprotected`, or `not_secret`. For a protected key, `exec.delivery` judges that key alone: `proxied` (a built-in route injects the real value for `exec.upstream`), `no_route` (the child gets only a session token that no provider accepts), `withheld` (a rotation-provider or sync credential exec never hands the child), `connection_string_refused`, or `custom_route_refused`. `exec.blocked_by` is non-null when the config stops `phantom exec` from starting for every key: `{service, reason, key}` with reason `custom_route`, `altered_builtin_route` or `connection_string`. `next_step` explains anything but an unblocked `proxied`. A connection-string key set in the shell environment that runs `phantom exec` also blocks it, and a static check cannot see that. |
| `phantom_check` | Scan `.env` files for unprotected real secrets, or scan the runtime environment for phantom tokens without an active proxy. Returns a short summary plus the value-blind `phantom check --json` report (`mode`, `clean`, `findings`, `warnings`, and `indeterminate` when a dotenv could not be judged) as JSON text and MCP `structuredContent`. A symlinked dotenv is never followed; it is listed under `indeterminate` with a reason. |
| `phantom_sync` | Show sync configuration and which secrets would be pushed to Vercel or Railway. Informational only — does not execute the sync. JSON: `{configured, platform_filter, configured_platforms, vault_secret_count, targets: [{platform, project_id, token_env, environments, service_id, environment_id, secrets}], live_gate_refusal, next_step}`. `live_gate_refusal` is the refusal the live `phantom sync` would return for the selection (overdue enforced rotation, read-only, unreadable metadata; names only), or null. |
| `phantom_add_secret_interactive` | Return the `phantom add NAME` command for adding a new secret out-of-band, so the real value is typed only into a trusted terminal prompt. Effect-free: takes a name only, never a value, stores nothing, and needs neither `confirm` nor approval, so it works with `PHANTOM_MCP_EFFECTS` unset. |
| `phantom_doctor` | Run repository-local health checks: config validity, `.env` protection, `.gitignore`, `.env.example`, pre-commit hook. It does not open the vault (use `phantom doctor` in a terminal for vault checks). Pass `fix=true` to auto-fix safe issues (`fix=true` is effectful and needs both gates below). Returns a short summary plus the value-blind `phantom doctor --json` report (`ok`, `issues`, `fixed`, `checks`, `mcp_clients`) as JSON text and MCP `structuredContent`. |

#### When a tool refuses: locked vault, not initialized

Errors the user can fix come back as MCP error `-32600` with the next step in
the message; `-32603` is kept for real server faults.

- **Locked vault.** When the project's secrets are in an encrypted-file vault
  and the MCP server's environment has no `PHANTOM_VAULT_PASSPHRASE`, the
  server opens the OS keychain instead. Tools that would answer from that empty
  view (`phantom_secrets_expiry_check`, `phantom_secret_rotation_due`,
  `phantom_validate_secret`, `phantom_rotation_schedule_next`) refuse with
  "Vault locked: ..." and the unlock step. When the keychain holds some
  entries, they answer but add a `vault_note` saying the answer covers only the
  keychain. Fix it by setting `PHANTOM_VAULT_PASSPHRASE` in the server's env
  config and restarting the server.
- **Wrong passphrase.** A decryption failure names both causes: a wrong
  `PHANTOM_VAULT_PASSPHRASE` in the server's env, or a corrupt vault file.
- **Not initialized.** `phantom_why`, `phantom_status`, `phantom_check`,
  `phantom_list_secrets`, `phantom_list_with_expiry`, and
  `phantom_compliance_status` still answer before `phantom init`. Other vault
  tools return the `phantom init` next step.

### Initialization

| Tool | What it does |
|------|-------------|
| `phantom_init` | Apply one exact-before transaction across config, managed dotenv, gitignore, hook, generated client files, and vault CAS operations. |
| `phantom_env` | Generate `.env.example` from current `.env` — secrets replaced with placeholders, non-secrets preserved. |

### Effectful — require `confirm: true` and out-of-band approval

Claude must ask for explicit user consent before calling any of these. Calling
without `confirm: true` and a valid one-use `approval_token` returns an error.
The token comes from a separate attached-terminal `phantom mcp-approve`
ceremony that displays the exact value-blind effect; keep that command outside
Claude's shell and PTY authority.

| Tool | What it does |
|------|-------------|
| `phantom_add_secret` | Deprecated compatibility tool. Refuses plaintext values passed through MCP; with `generate: true`, creates a local random secret and returns only its name and fingerprint. |
| `phantom_remove_secret` | Transactionally remove the vault value, lifecycle record, and exact managed-dotenv mapping. |
| `phantom_rotate` | Regenerate all phantom tokens in `.env`. Old tokens become invalid immediately - any running dev server that cached them will break until it reloads. Real secrets are unchanged. With `generate: true` plus `name`, atomically replaces a named local value in the encrypted file vault; no provider issuance. |
| `phantom_cloud_push` | With a separately commissioned hosted deployment and entitled account, encrypt and upload the local vault. The public hosted service is not currently commissioned for authenticated use. Overwrites the existing cloud copy and requires `phantom login` first. |
| `phantom_cloud_pull` | With a separately commissioned hosted deployment and entitled account, download and decrypt a vault. The public hosted service is not currently commissioned for authenticated use. With `force=false`, skipped entries preserve the prior merge base and block push until full reconciliation; `force=true` declares overwrites but does not bypass approval. |
| `phantom_copy_secret` | Copy into another initialized project using exact config/vault/managed-dotenv before-images. Existing target ownership and traversal are refused. |
| `phantom_wrap` | Wrap `package.json` scripts with the installed local `phantom exec --` runtime so secrets are injected at runtime. Saves originals as `script:raw` variants. |
| `phantom_unwrap` | Reverse `phantom_wrap` — restore original scripts from `:raw` variants and remove the `:raw` entries. |

Provider requests and other effectful operations are disabled by default.
They can reach both `confirm: true` and one-use `approval_token` gates only
when `PHANTOM_MCP_EFFECTS=trusted-terminal` is configured outside Claude's
authority. `phantom mcp-approve` requires attached stdin/stderr, shows the
value-blind effect and exact parameters, and requires a fresh typed challenge.
A same-user shell or Claude-controlled PTY can defeat the ceremony; leave MCP
effects disabled unless approval command and storage are outside its authority.
This includes `phantom_cloud_status`, `phantom_team_list`,
`phantom_team_members`, and `phantom_validate_all`. Conditional operations keep
their inspection mode read-only, but require both gates for schedule updates,
alert backfill/dispatch, hotspot acknowledgement, and saved reports. Runtime
`tools/list` is the exact parameter contract; every tool whose schema takes
`approval_token` says so in its description.

#### Enabling effectful tools (`PHANTOM_MCP_EFFECTS`)

With `PHANTOM_MCP_EFFECTS` unset (the default), every approval-gated tool
refuses with a message naming the variable. To enable them:

1. Set `PHANTOM_MCP_EFFECTS=trusted-terminal` in the environment that launches
   the Phantom MCP server, somewhere Claude cannot edit, for example a
   user-scoped registration:
   `claude mcp add --scope user -e PHANTOM_MCP_EFFECTS=trusted-terminal phantom -- phantom mcp serve`.
   A project `.mcp.json` that Claude can write is not outside its authority.
2. Claude calls the tool with `confirm: true` after asking you. The first call
   has no `approval_token`; the server prints a nonce on its stderr and the
   call fails with "requires out-of-band approval".
3. In your own trusted terminal (not Claude's shell or PTY), run
   `phantom mcp-approve <NONCE>`, review the value-blind effect and exact
   parameters, and type the challenge.
4. Claude retries the identical call with `approval_token: "<nonce>:<token>"`.
   The token is one-use and bound to those exact parameters.

You never need this to add a secret: `phantom_add_secret_interactive` is
effect-free, and `phantom add NAME` in your terminal does the actual write.

---

## Example workflow: integrating a new API

Here is a typical conversation that shows how the tools compose in practice.

```
You: I need to add a Stripe secret key to this project.

Claude: [calls phantom_add_secret_interactive with name STRIPE_SECRET_KEY;
        no value, no approval needed because it stores nothing]
        Run `phantom add STRIPE_SECRET_KEY` in your terminal and enter the
        real value at the prompt. Do not paste it into chat.

You: can you check our vault is healthy?

Claude: [calls phantom_doctor]
        All checks pass. Config valid, .env fully protected, .env is in
        .gitignore, .env.example exists.

You: after our hosted pilot is commissioned, back up this vault so I can restore
     it on this keychain machine later

Claude: I first need to verify that the hosted deployment and your entitlement
        are commissioned. If they are, the push overwrites the existing cloud copy.
        Approve the exact effect outside my shell authority. [calls
        phantom_cloud_push with confirm: true and the one-use approval_token]
        [Only after provider acceptance: reports the value-free push result.]
```

---

## Common Claude Code workflows that benefit

### Integrating a new third-party API

1. Tell Claude the secret name, not the value. Claude calls `phantom_add_secret_interactive` (effect-free, no approval) and gives you `phantom add NAME`; you run it in your terminal and enter the value at the prompt.
2. Claude writes the integration code using the env var name (`process.env.MY_API_KEY`).
3. `phantom exec -- claude` ensures API test calls during the session go through the proxy.

### Debugging production issues with real keys

In the supported path, Claude uses value-blind MCP status and reviewed proxy
routes rather than receiving provider credentials. That boundary does not cover
unmanaged files, external tools, provider responses outside configured
scrubbing, or processes launched outside `phantom exec`.

### Deploying to Vercel

Claude can call `phantom_sync` (read-only mode) to show which secrets and targets are configured, then guide you to run `phantom sync --platform vercel --project prj_xxx` in the terminal to execute the actual push.

### Setting up from a deployment provider

```
You: I'm on a new laptop. Help me get set up.

Claude: [calls phantom_status — sees no .phantom.toml]
        Phantom isn't initialized here. Do you have authorized access to the
        project's secrets in Vercel? Personal Phantom Cloud backups cannot be
        decrypted here without the original machine's cloud key.

You: Vercel, project ID is prj_abc123

Claude: Run this to pull secrets from Vercel:
        phantom pull --from vercel --project prj_abc123
        Then I'll run phantom_doctor to verify everything looks good.
```

---

## Gateway mode (optional, experimental)

To run Claude Code through a local LiteLLM gateway that holds no real keys, see [Connect an agent](litellm.md#connect-an-agent) in the LiteLLM guide. Without the gateway, nothing changes: the direct Phantom route above stays the default.

## What Claude cannot do

These limits are intentional and enforced at the protocol level.

**Phantom's MCP does not return real secret values.** `phantom_list_secrets`
returns names only, the deprecated plaintext add tool refuses values, and
interactive entry happens in the trusted terminal. This is a statement about
the Phantom MCP surface, not about unrelated files, shell commands, providers,
or tools that may grant the agent broader access.

**Cannot call listed effectful tools without both gates.** `phantom_init`,
`phantom_remove_secret`, `phantom_rotate`,
`phantom_cloud_push`, `phantom_cloud_pull`, `phantom_copy_secret`,
`phantom_env`, `phantom_wrap`, `phantom_unwrap`, `phantom_doctor` (when
`fix=true`), authenticated provider reads, and team write tools hard-fail if
`confirm: true` or the one-use out-of-band approval is absent. These are tool
gates, not a general prompt-injection defense; keep the approval command and
deployment/provider authority outside the agent's control.

**Cannot receive real secret values through MCP.** Plaintext values passed to `phantom_add_secret` are rejected. New secrets must be entered through the terminal prompt started by `phantom_add_secret_interactive`.

**Cannot execute sync or pull against platforms.** `phantom_sync` is informational only — it shows configuration but does not call Vercel or Railway APIs. Actual sync requires a CLI command you run directly.

**Cannot start or stop the proxy.** There is no MCP tool for proxy lifecycle.
Use `phantom exec` for a child-owned session, or run foreground `phantom start`
in a trusted terminal and press Ctrl-C in that same terminal to stop. Detached
`--daemon` mode and current external process control fail closed; `phantom stop`
authenticates legacy v0.7.3 state only to report manual migration guidance and
never kills a process or deletes the record.

---

## Reference

- MCP setup: `phantom setup --client claude` after installing both `v0.7.9` binaries
- Full command list: [getting-started.md](./getting-started.md)
- Troubleshooting: [troubleshooting.md](./troubleshooting.md)
- GitHub: [https://github.com/ashlrai/phantom-secrets](https://github.com/ashlrai/phantom-secrets)
- Site: [https://phm.dev](https://phm.dev)
