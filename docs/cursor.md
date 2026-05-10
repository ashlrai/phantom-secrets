# Phantom + Cursor

## Why this combination exists

Cursor is an editor-shaped agent. Like Claude Code, it reads your project
directory, opens `.env` files when it needs to, and pulls those values
into the model's context. With real secrets in `.env`, that means a
production API key can land in a chat transcript, a generated code
snippet, or a tool-call argument — exactly the place a secret should
never be.

Phantom solves this at the source: after `phantom init`, your `.env`
contains only worthless phantom tokens (`phm_...`). Cursor reads the
file, sees the tokens, and cannot leak anything. When your code makes
an API call at runtime, the local Phantom proxy on `127.0.0.1` swaps
the token for the real credential before the request leaves your
machine — over TLS, never touching Cursor's context.

The MCP integration goes further: Cursor gains 24 tools to manage
secrets directly, so you can ask Cursor's agent to add a key, check
vault status, or push to cloud sync without leaving the conversation
— and without any real secret value ever appearing in the chat.

---

## Install

### Step 1: install Phantom

```bash
npx phantom-secrets init
```

This installs the CLI and initializes your current project in one step.
After this command runs you'll have:

- `.phantom.toml` — local Phantom config for the project
- `.env` — the same keys you started with, real values replaced with
  `phm_` placeholder tokens
- a vault entry per real secret, stored in your OS keychain

### Step 2: register the MCP server with Cursor

Cursor reads MCP server definitions from `~/.cursor/mcp.json` (global,
applies to every project) or `.cursor/mcp.json` (project-local,
overrides the global file). Either path works; pick whichever matches
how you want Phantom scoped.

**Option A — Cursor UI:** open Cursor → Settings → MCP Servers →
"Add new MCP server" and paste:

```json
{
  "phantom": {
    "command": "npx",
    "args": ["phantom-secrets-mcp"]
  }
}
```

Cursor restarts the server automatically when you save the panel.

**Option B — edit the JSON directly:**

```bash
mkdir -p ~/.cursor
cat > ~/.cursor/mcp.json <<'JSON'
{
  "phantom": {
    "command": "npx",
    "args": ["phantom-secrets-mcp"]
  }
}
JSON
```

Restart Cursor (or use the "Refresh" button in the MCP panel) to pick
up the new server.

### Step 3: run Cursor with the proxy active

```bash
phantom exec -- cursor .
```

`phantom exec` starts the local proxy on `127.0.0.1`, sets the
`*_BASE_URL` environment variables that route HTTP traffic through it,
and then launches `cursor .` with that environment inherited. When code
inside the Cursor session makes an API call, the proxy substitutes the
real credential for the `phm_` token on the way out — Cursor's process
never sees the real value.

If you'd rather start Cursor normally and run code through the proxy
on demand, swap your scripts to use `phantom exec`:

```bash
phantom exec -- npm run dev
phantom exec -- python app.py
```

Or wrap your `package.json` scripts once with the `phantom_wrap` MCP
tool (Cursor can call this on request) so every `npm` script you run
from Cursor's terminal goes through the proxy automatically.

---

## What Cursor gets through the MCP server

Once `phantom` is registered in `mcp.json`, Cursor's agent picker
shows the 24 phantom tools alongside its built-in actions. The full
catalogue is the same as the Claude Code integration; the most
common ones in a Cursor workflow:

| Tool | What Cursor uses it for |
|------|-------------------------|
| `phantom_status` | Quick check that the project is initialised, the vault is reachable, and `.env` is fully tokenised. Cursor calls this when you ask "is Phantom set up here?". |
| `phantom_list_secrets` | List secret names so Cursor can wire them into code. Names only — no values. |
| `phantom_add_secret` | Store a brand-new secret in the vault (requires `confirm: true`). Cursor will pause and ask before calling. |
| `phantom_doctor` | Run all health checks (config valid, vault accessible, `.gitignore`/`.env.example` correct, pre-commit hook present). Pass `fix=true` to auto-fix safe issues. |
| `phantom_check` | Scan `.env` for unprotected real secrets, or scan the running environment for phantom tokens that have no proxy in front of them. |
| `phantom_wrap` | Wrap `package.json` scripts with `npx phantom-secrets exec --` so every `npm run …` from Cursor's terminal injects credentials at runtime. |

The full table (read-only, initialisation, destructive, cloud, teams)
lives in [`docs/claude-code.md`](./claude-code.md#the-24-mcp-tools-claude-gets);
the contract is identical for Cursor.

### Confirmation gates

Mutating tools (`phantom_add_secret`, `phantom_remove_secret`,
`phantom_rotate`, `phantom_cloud_push`, `phantom_cloud_pull`,
`phantom_copy_secret`, `phantom_wrap`, `phantom_unwrap`) hard-fail
without `confirm: true`. Cursor's agent has to surface the request to
you before it can proceed — which is the whole point of the gate, so
prompt-injection attacks can't silently mutate your vault.

---

## Sample workflow: add a Stripe payment endpoint

```
You: I need to add a Stripe payment endpoint. The secret key is sk_live_abc123...

Cursor: Storing this with Phantom so it never enters my context.
        [calls phantom_add_secret with confirm: true; pauses for your confirmation]

You: yes, go ahead

Cursor: [stores the secret; .env now has STRIPE_SECRET_KEY=phm_<token>]
        Done. Writing the endpoint now using process.env.STRIPE_SECRET_KEY.

You: run the dev server and test it

Cursor: [opens terminal] phantom exec -- npm run dev
        [proxy starts, real key is substituted on outbound Stripe calls]
        Server up on :3000. Hitting POST /api/checkout...
        [response shows the test charge succeeded]
```

The Stripe key value never appears in the chat, never lands in a
generated code snippet, and never leaves your machine in plaintext.

---

## Troubleshooting

### MCP server doesn't show up in the picker

- Confirm `~/.cursor/mcp.json` (or `.cursor/mcp.json`) parses as JSON.
  Cursor silently ignores invalid files.
- Restart Cursor fully (Quit, not just close window) after editing the
  file. The MCP runtime is started once at boot.
- Run `npx phantom-secrets-mcp` in a terminal. If the package isn't
  installed yet, `npx` will download it; the first launch can take a
  few seconds. After it's cached, Cursor will start it instantly.

### Tools call out but everything errors with "vault not initialised"

`phantom_status` returns this when the project doesn't have a
`.phantom.toml` yet. Run `npx phantom-secrets init` once at the
repo root (not from a subdirectory) and the file appears.

### Outbound calls fail with TLS or connection errors

The proxy only intercepts traffic when the process inherits the
`*_BASE_URL` variables that `phantom exec` sets. Starting Cursor
without `phantom exec` means the integration's MCP tools still work
(they're stdio, not network), but code launched from Cursor's terminal
won't have credential substitution unless that terminal session was
also started under `phantom exec`. Run `phantom doctor` to confirm the
proxy is running and which env vars are in place.

### "Cursor has cached old phantom tokens"

Run `phantom_rotate` (Cursor will ask for `confirm: true`) to
regenerate `.env`'s `phm_` tokens. Real secrets are unchanged. Any
running dev server that captured the previous tokens will need a
restart to pick up the new ones — same trade-off as in Claude Code.

For other failure modes that aren't Cursor-specific, see
[`docs/troubleshooting.md`](./troubleshooting.md).

---

## Reference

- MCP server entry: `{"phantom": {"command": "npx", "args": ["phantom-secrets-mcp"]}}`
- Cursor MCP file (per-user): `~/.cursor/mcp.json`
- Cursor MCP file (project): `.cursor/mcp.json`
- Full command list: [`docs/getting-started.md`](./getting-started.md)
- Full MCP tool catalogue: [`docs/claude-code.md`](./claude-code.md#the-24-mcp-tools-claude-gets)
- Troubleshooting: [`docs/troubleshooting.md`](./troubleshooting.md)
- GitHub: [https://github.com/ashlrai/phantom-secrets](https://github.com/ashlrai/phantom-secrets)
- Site: [https://phm.dev](https://phm.dev)
