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

Install the reviewed `v0.7.4` binary using the platform-specific, checksum-
verified path in [getting started](./getting-started.md#install), then run
`phantom init` in the project.

### Step 2: wire up Claude Code (one command)

```bash
phantom setup --client claude
```

This writes `.claude/settings.local.json` with two things at once:
- The `phantom` MCP server entry (so Claude can call the Phantom tool catalog)
- Removal of legacy Phantom-managed `.env` read grants; dotenv denies remain a defense-in-depth boundary while MCP exposes value-blind inventory

Install both `v0.7.4` release binaries before setup. Version `0.7.4` records the
running `phantom` executable with `mcp serve` when it can resolve that runtime,
otherwise it looks for a local `phantom-mcp`. Setup has no network
package-runner fallback and fails closed when neither local runtime is
executable. Keep both verified binaries installed and inspect the generated
entry.

Verify it registered:

```bash
claude mcp list
# phantom-secrets-mcp   phantom-mcp   enabled
```

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

Once `phantom-secrets-mcp` is registered, Claude can call the full runtime
catalog. The following table highlights the core workflows; use MCP
`tools/list` for the canonical catalog.

### Read-only (safe to call any time)

| Tool | What it does |
|------|-------------|
| `phantom_list_secrets` | List secret names in the vault. Never returns values. |
| `phantom_status` | Show project ID, vault backend, secret count, service mappings, and `.env` protection state. |
| `phantom_why` | Explain why a specific `.env` key is or isn't classified as a secret (shows the matching heuristic). |
| `phantom_check` | Scan `.env` files for unprotected real secrets, or scan the runtime environment for phantom tokens without an active proxy. |
| `phantom_sync` | Show sync configuration and which secrets would be pushed to Vercel or Railway. Informational only — does not execute the sync. |
| `phantom_doctor` | Run all health checks: config validity, vault access, `.gitignore`, `.env.example`, pre-commit hook. Pass `fix=true` to auto-fix safe issues. |

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
| `phantom_add_secret_interactive` | Return a terminal command for adding a new secret out-of-band, so the real value is typed only into a trusted terminal prompt. |
| `phantom_add_secret` | Deprecated compatibility tool. Refuses plaintext values passed through MCP. |
| `phantom_remove_secret` | Transactionally remove the vault value, lifecycle record, and exact managed-dotenv mapping. |
| `phantom_rotate` | Regenerate all phantom tokens in `.env`. Old tokens become invalid immediately — any running dev server that cached them will break until it reloads. Real secrets are unchanged. |
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
`tools/list` is the exact parameter contract.

---

## Example workflow: integrating a new API

Here is a typical conversation that shows how the tools compose in practice.

```
You: I need to add a Stripe secret key to this project.

Claude: I'll start the safe add flow after you approve its exact value-blind
        effect out of band. [calls phantom_add_secret_interactive with
        confirm: true and the one-use approval_token]

You: yes, go ahead

Claude: Run `phantom add STRIPE_SECRET_KEY` in your terminal and enter the
        real value at the prompt. Do not paste it into chat.

You: can you check our vault is healthy?

Claude: [calls phantom_doctor]
        All checks pass. Config valid, vault accessible, .env fully protected,
        .env is in .gitignore, .env.example exists.

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

1. Tell Claude the secret name, not the value. After the separate MCP approval ceremony, Claude calls `phantom_add_secret_interactive` with both gates, then you enter the value at the terminal prompt.
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

## What Claude cannot do

These limits are intentional and enforced at the protocol level.

**Phantom's MCP does not return real secret values.** `phantom_list_secrets`
returns names only, the deprecated plaintext add tool refuses values, and
interactive entry happens in the trusted terminal. This is a statement about
the Phantom MCP surface, not about unrelated files, shell commands, providers,
or tools that may grant the agent broader access.

**Cannot call listed effectful tools without both gates.** `phantom_init`,
`phantom_add_secret_interactive`, `phantom_remove_secret`, `phantom_rotate`,
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

- MCP setup: `phantom setup --client claude` after installing both `v0.7.4` binaries
- Full command list: [getting-started.md](./getting-started.md)
- Troubleshooting: [troubleshooting.md](./troubleshooting.md)
- GitHub: [https://github.com/ashlrai/phantom-secrets](https://github.com/ashlrai/phantom-secrets)
- Site: [https://phm.dev](https://phm.dev)
