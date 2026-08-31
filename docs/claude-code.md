# Phantom + Claude Code

## Why this combination exists

Claude Code can inspect files that its workspace permissions allow. If those permissions include a dotenv file with real values, the credentials can enter agent context, transcripts, tool logs, or generated code.

Phantom removes real values from managed dotenv files, keeps dotenv read permissions closed, and exposes value-blind MCP metadata instead. Application and test processes load the `phm_` placeholders; when they make an API call, the local Phantom proxy swaps the placeholder for the real credential before the request leaves your machine.

The MCP integration goes further: Claude gains the release-schema-verified tool
catalog for value-free secret workflows. The current release contract enforces
54 unique tools; runtime `tools/list` is canonical.

---

## Install

### Step 1: install Phantom

Install the reviewed `v0.7.3` binary using the platform-specific, checksum-
verified path in [getting started](./getting-started.md#install), then run
`phantom init` in the project.

### Step 2: wire up Claude Code (one command)

```bash
phantom setup --client claude
```

This writes `.claude/settings.local.json` with two things at once:
- The `phantom` MCP server entry (so Claude can call the Phantom tool catalog)
- Removal of legacy Phantom-managed `.env` read grants; dotenv denies remain a defense-in-depth boundary while MCP exposes value-blind inventory

Setup normally records the installed `phantom` executable with `mcp serve`. Its
standalone fallback accepts only an executable local `phantom-mcp`: first on
`PATH`, then beside `phantom` (`phantom-mcp.exe` on Windows), then in
`~/.cargo/bin`. If none is available, setup fails closed with verified `v0.7.3`
install guidance; it never downloads or executes an unpinned registry package.

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
| `phantom_cloud_status` | Check cloud auth status, plan tier, and last sync version. |
| `phantom_why` | Explain why a specific `.env` key is or isn't classified as a secret (shows the matching heuristic). |
| `phantom_check` | Scan `.env` files for unprotected real secrets, or scan the runtime environment for phantom tokens without an active proxy. |
| `phantom_sync` | Show sync configuration and which secrets would be pushed to Vercel or Railway. Informational only — does not execute the sync. |
| `phantom_doctor` | Run all health checks: config validity, vault access, `.gitignore`, `.env.example`, pre-commit hook. Pass `fix=true` to auto-fix safe issues. |

### Initialization

| Tool | What it does |
|------|-------------|
| `phantom_init` | Read `.env`, store real secrets in vault, rewrite `.env` with phantom tokens, write `.phantom.toml`. |
| `phantom_env` | Generate `.env.example` from current `.env` — secrets replaced with placeholders, non-secrets preserved. |

### Destructive — require `confirm: true`

Claude must ask for explicit user consent before calling any of these. Calling without `confirm: true` returns an error.

| Tool | What it does |
|------|-------------|
| `phantom_add_secret_interactive` | Return a terminal command for adding a new secret out-of-band, so the real value is typed only into a trusted terminal prompt. |
| `phantom_add_secret` | Deprecated compatibility tool. Refuses plaintext values passed through MCP. |
| `phantom_remove_secret` | Permanently delete a secret from the vault. Not recoverable unless you have a cloud backup. |
| `phantom_rotate` | Regenerate all phantom tokens in `.env`. Old tokens become invalid immediately — any running dev server that cached them will break until it reloads. Real secrets are unchanged. |
| `phantom_cloud_push` | Encrypt and upload the local vault to Phantom Cloud. Overwrites the existing cloud copy. Requires `phantom login` first. |
| `phantom_cloud_pull` | Download and decrypt a vault from Phantom Cloud. Writes secrets into the local vault. Pass `force=true` to overwrite existing entries. |
| `phantom_copy_secret` | Copy a secret from this project's vault to another phantom-initialized project without exposing the value. Path traversal (`..`) is rejected. |
| `phantom_wrap` | Wrap `package.json` scripts with `npx phantom-secrets exec --` so secrets are injected at runtime. Saves originals as `script:raw` variants. |
| `phantom_unwrap` | Reverse `phantom_wrap` — restore original scripts from `:raw` variants and remove the `:raw` entries. |

---

## Example workflow: integrating a new API

Here is a typical conversation that shows how the tools compose in practice.

```
You: I need to add a Stripe secret key to this project.

Claude: I'll start the safe add flow. [calls phantom_add_secret_interactive
        with confirm: true after asking you to confirm]

You: yes, go ahead

Claude: Run `phantom add STRIPE_SECRET_KEY` in your terminal and enter the
        real value at the prompt. Do not paste it into chat.

You: can you check our vault is healthy?

Claude: [calls phantom_doctor]
        All checks pass. Config valid, vault accessible, .env fully protected,
        .env is in .gitignore, .env.example exists.

You: back up this vault to cloud so I can restore it on this keychain machine later

Claude: I'll push to Phantom Cloud — this overwrites the existing cloud copy. 
        Confirm? [calls phantom_cloud_push with confirm: true after your yes]
        Pushed 4 secrets (v7). End-to-end encrypted.
```

---

## Common Claude Code workflows that benefit

### Integrating a new third-party API

1. Tell Claude the secret name, not the value. Claude calls `phantom_add_secret_interactive` (with confirmation), then you enter the value at the terminal prompt.
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

**Cannot call listed mutating tools without `confirm: true`.** `phantom_init`,
`phantom_add_secret_interactive`, `phantom_remove_secret`, `phantom_rotate`,
`phantom_cloud_push`, `phantom_cloud_pull`, `phantom_copy_secret`,
`phantom_env`, `phantom_wrap`, `phantom_unwrap`, `phantom_doctor` (when
`fix=true`), and team write tools hard-fail if confirmation is absent. This is
a useful mutation gate, not a general prompt-injection defense; review the
exact action and keep deployment/provider authority separately constrained.

**Cannot receive real secret values through MCP.** Plaintext values passed to `phantom_add_secret` are rejected. New secrets must be entered through the terminal prompt started by `phantom_add_secret_interactive`.

**Cannot execute sync or pull against platforms.** `phantom_sync` is informational only — it shows configuration but does not call Vercel or Railway APIs. Actual sync requires a CLI command you run directly.

**Cannot start or stop the proxy.** There is no MCP tool for proxy lifecycle. The proxy is controlled via `phantom exec`, `phantom start`, and `phantom stop` in your terminal. This ensures the proxy only runs in sessions you explicitly start.

---

## Reference

- MCP setup: `phantom setup --client claude` after installing both `v0.7.3` binaries
- Full command list: [getting-started.md](./getting-started.md)
- Troubleshooting: [troubleshooting.md](./troubleshooting.md)
- GitHub: [https://github.com/ashlrai/phantom-secrets](https://github.com/ashlrai/phantom-secrets)
- Site: [https://phm.dev](https://phm.dev)
