# Phantom + Claude Code

## Why this combination exists

Claude Code reads your project directory aggressively. It scans `.env` files, includes them in context, and the real values enter Claude's context window — where they can appear in session transcripts, tool call logs, generated code, and potentially training data.

Phantom solves this at the source: after `phantom init`, your `.env` contains only worthless phantom tokens (`phm_...`). Claude reads the file, sees the tokens, and cannot leak anything. When your code makes an API call at runtime, the local Phantom proxy swaps the token for the real credential before the request leaves your machine — over TLS, never touching Claude's context.

The MCP integration goes further: Claude gains 24 tools to manage secrets directly, so you can ask Claude to add a key, check vault status, or push to cloud sync without leaving the conversation — and without any real secret value ever appearing in the chat.

---

## Install

### Step 1: install Phantom

```bash
npx phantom-secrets init
```

This installs the CLI and initializes your current project in one step.

### Step 2: add the MCP server

```bash
claude mcp add phantom-secrets-mcp -- npx phantom-secrets-mcp
```

Verify it registered:

```bash
claude mcp list
# phantom-secrets-mcp   npx phantom-secrets-mcp   enabled
```

### Step 3: configure Claude Code access (optional but recommended)

`phantom setup` adds `.env` to Claude Code's allow rules so Claude can read the phantomized file:

```bash
phantom setup
```

This writes to `.claude/settings.local.json`. After `phantom init`, the `.env` only contains phantom tokens — it is safe for Claude to read.

### Step 4: run Claude with the proxy active

```bash
phantom exec -- claude
```

The proxy starts on `127.0.0.1`, `*_BASE_URL` environment variables are set, and Claude launches with the full Phantom environment. When your code runs API calls inside the Claude Code session, the proxy handles credential injection.

---

## The 24 MCP tools Claude gets

Once `phantom-secrets-mcp` is registered, Claude can call these tools.

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
| `phantom_add_secret` | Store a new secret in the vault and write its phantom token to `.env`. Overwrites if the name already exists. |
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
You: I need to add a Stripe secret key to this project. Here it is: sk_live_abc123...

Claude: I'll store that securely. [calls phantom_add_secret with confirm: true — 
        pauses and asks you to confirm before proceeding]

You: yes, go ahead

Claude: [stores secret, updates .env with phantom token]
        Done. STRIPE_SECRET_KEY is stored in the vault. Your .env now has the 
        phantom token; the real value never appeared in this conversation.

You: can you check our vault is healthy?

Claude: [calls phantom_doctor]
        All checks pass. Config valid, vault accessible, .env fully protected,
        .env is in .gitignore, .env.example exists.

You: push the vault to cloud so I can sync to my laptop later

Claude: I'll push to Phantom Cloud — this overwrites the existing cloud copy. 
        Confirm? [calls phantom_cloud_push with confirm: true after your yes]
        Pushed 4 secrets (v7). End-to-end encrypted.
```

---

## Common Claude Code workflows that benefit

### Integrating a new third-party API

1. Tell Claude the new API key value. Claude calls `phantom_add_secret` (with confirmation) to store it safely.
2. Claude writes the integration code using the env var name (`process.env.MY_API_KEY`).
3. `phantom exec -- claude` ensures API test calls during the session go through the proxy.

### Debugging production issues with real keys

Real keys are in the vault; Claude never sees them. Claude can call `phantom_status` to confirm the right keys are loaded, then help you trace a bug without any credential exposure in the transcript.

### Deploying to Vercel

Claude can call `phantom_sync` (read-only mode) to show which secrets and targets are configured, then guide you to run `phantom sync --platform vercel --project prj_xxx` in the terminal to execute the actual push.

### Onboarding a new machine

```
You: I'm on a new laptop. Help me get set up.

Claude: [calls phantom_status — sees no .phantom.toml]
        Phantom isn't initialized here. Do you have secrets in cloud sync or on Vercel?

You: Vercel, project ID is prj_abc123

Claude: Run this to pull secrets from Vercel:
        phantom pull --from vercel --project prj_abc123
        Then I'll run phantom_doctor to verify everything looks good.
```

---

## What Claude cannot do

These limits are intentional and enforced at the protocol level.

**Cannot read real secret values.** `phantom_list_secrets` returns names only. There is no MCP tool that returns a secret value. Claude can never retrieve a plaintext credential, even if instructed to.

**Cannot call destructive tools without `confirm: true`.** `phantom_add_secret`, `phantom_remove_secret`, `phantom_rotate`, `phantom_cloud_push`, `phantom_cloud_pull`, `phantom_copy_secret`, `phantom_wrap`, and `phantom_unwrap` all hard-fail if `confirm` is not explicitly set to `true`. Claude must ask you before proceeding — this prevents prompt injection attacks from silently modifying your vault.

**Cannot execute sync or pull against platforms.** `phantom_sync` is informational only — it shows configuration but does not call Vercel or Railway APIs. Actual sync requires a CLI command you run directly.

**Cannot start or stop the proxy.** There is no MCP tool for proxy lifecycle. The proxy is controlled via `phantom exec`, `phantom start`, and `phantom stop` in your terminal. This ensures the proxy only runs in sessions you explicitly start.

---

## Reference

- MCP install: `claude mcp add phantom-secrets-mcp -- npx phantom-secrets-mcp`
- Full command list: [getting-started.md](./getting-started.md)
- Troubleshooting: [troubleshooting.md](./troubleshooting.md)
- GitHub: [https://github.com/ashlrai/phantom-secrets](https://github.com/ashlrai/phantom-secrets)
- Site: [https://phm.dev](https://phm.dev)
