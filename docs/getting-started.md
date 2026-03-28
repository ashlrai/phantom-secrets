# Getting Started with Phantom

This guide walks through the most common Phantom workflow: a solo developer using Claude Code (or Cursor) with a Next.js/Node.js project deployed to Vercel. By the end, your AI coding tools will never see a real secret again.

## 1. Install

Phantom is distributed as a Rust binary. Install from source via Cargo:

```bash
cargo install --git https://github.com/ashlrai/phantom-secrets phantom
```

Or, if you prefer Homebrew (macOS/Linux):

```bash
brew install phantom-secrets/tap/phantom
```

Verify the install:

```bash
phantom --version
```

## 2. Initialize

Navigate to your project directory and run `phantom init`:

```bash
cd my-nextjs-app
phantom init
```

Here is what happens:

1. Phantom reads your `.env` file and identifies secrets using heuristics (key patterns like `*_API_KEY`, `*_SECRET*`, `*_TOKEN`; value patterns like `sk-*`, `ghp_*`, connection strings).
2. Real secret values are stored in your **OS keychain** (macOS Keychain / Linux Secret Service). They never exist on disk inside your project directory again.
3. Your `.env` file is **rewritten in place** -- real values are replaced with phantom tokens (random 256-bit tokens prefixed with `phm_`).
4. A `.phantom.toml` config file is created in your project root.

```
$ phantom init
Found 3 secret(s) to protect: OPENAI_API_KEY, ANTHROPIC_API_KEY, DATABASE_URL
Rewrote .env with phantom tokens
Saved real secrets to OS keychain
```

Your `.env` now looks like this:

```env
# Managed by Phantom -- do not edit phantom tokens manually
OPENAI_API_KEY=phm_a7f3b9e2c4d1f8a3b6e9d2c5f8a1b4e7
ANTHROPIC_API_KEY=phm_d4e7a0b3c6f9e2d5a8c1b4f7e0d3a6c9
DATABASE_URL=phm_b1c4d7e0a3f6b9c2d5e8a1b4c7d0e3f6
NODE_ENV=development
PORT=3000
```

Non-secret values like `NODE_ENV` and `PORT` are left untouched.

If your `.env` is at a non-standard path:

```bash
phantom init --from .env.local
```

## 3. Daily Workflow

Your primary daily command is `phantom exec`. It starts the local proxy, runs your command, and tears everything down when the command exits.

### With Claude Code

```bash
phantom exec -- claude
```

### With Cursor

```bash
phantom exec -- cursor .
```

### What happens under the hood

1. Phantom starts a local HTTP proxy on `127.0.0.1` (ephemeral port).
2. It sets environment variables so SDKs route through the proxy:
   - `OPENAI_BASE_URL=http://127.0.0.1:<port>/openai`
   - `ANTHROPIC_BASE_URL=http://127.0.0.1:<port>/anthropic`
   - (and similar for other configured services)
3. Your AI tool launches. It reads `.env` and sees only `phm_` tokens.
4. When your code makes an API call, the request hits the local proxy. The proxy swaps phantom tokens for real secrets in the request headers/body, then forwards the request over TLS to the real API.
5. When you exit Claude Code (or Cursor), the proxy shuts down. The phantom tokens become inert -- they are meaningless outside the proxy.

**The AI agent never sees, logs, or transmits a real secret.**

## 4. How It Works with Your Code

The key insight: **no code changes are required**. Your application code stays exactly the same.

### Why it just works

The OpenAI and Anthropic SDKs (and most API clients) respect `*_BASE_URL` environment variables. When Phantom sets `OPENAI_BASE_URL`, the SDK sends requests to the local proxy instead of `api.openai.com` directly. The proxy handles the rest.

### Node.js / Next.js example

Your code does not change at all:

```typescript
// This code works identically with or without Phantom
import OpenAI from "openai";

const openai = new OpenAI();
// SDK reads OPENAI_API_KEY (gets phm_ token) and
// OPENAI_BASE_URL (gets http://127.0.0.1:<port>/openai)
// Proxy swaps phm_ for the real key before forwarding

const response = await openai.chat.completions.create({
  model: "gpt-4o",
  messages: [{ role: "user", content: "Hello" }],
});
```

```typescript
// Same for Anthropic
import Anthropic from "@anthropic-ai/sdk";

const anthropic = new Anthropic();
// SDK reads ANTHROPIC_API_KEY (gets phm_ token) and
// ANTHROPIC_BASE_URL (gets http://127.0.0.1:<port>/anthropic)
```

### What about DATABASE_URL?

Database connections are not HTTP-based, so the proxy cannot intercept them. For secrets like `DATABASE_URL`, Phantom injects the real value directly as an environment variable inside the `exec` session. The `.env` file still contains only the phantom token, so the AI never sees the real connection string.

### Custom services

Add custom API services in `.phantom.toml`:

```toml
[services.custom_api]
secret_key = "MY_CUSTOM_KEY"
pattern = "api.example.com"
header = "X-Api-Key"
header_format = "{secret}"
```

## 5. Deploy to Vercel

Phantom can push your real secrets directly to Vercel's environment variables, so you never copy-paste secrets into a web dashboard.

```bash
phantom sync --platform vercel --project prj_abc123def456
```

This reads real secret values from your OS keychain and sets them as environment variables in your Vercel project. Phantom tokens are never uploaded -- Vercel gets the real values.

### Finding your Vercel project ID

Your project ID is in the Vercel dashboard under **Settings > General**, or in your local `.vercel/project.json`:

```bash
cat .vercel/project.json
# {"projectId": "prj_abc123def456", "orgId": "team_xyz"}
```

You can also save the target in `.phantom.toml` so future syncs do not require the `--project` flag:

```toml
[sync.vercel]
project = "prj_abc123def456"
```

Then simply run:

```bash
phantom sync --platform vercel
```

**Note:** You need the Vercel CLI authenticated (`vercel login`) or a `VERCEL_TOKEN` set for this to work.

## 6. New Machine Setup

Starting fresh on a new laptop or CI runner? Pull secrets from a platform you have already synced to:

```bash
phantom pull --from vercel --project prj_abc123def456
```

This fetches the real secret values from Vercel, stores them in your local OS keychain, and writes phantom tokens to your `.env` file.

If you already have some secrets locally and want to overwrite them with the platform values:

```bash
phantom pull --from vercel --project prj_abc123def456 --force
```

### Railway

For Railway projects, specify the environment and optionally a service:

```bash
phantom pull --from railway --project <project-id> --environment production --service <service-id>
```

## 7. Team Onboarding

### Generate .env.example

Phantom can generate a `.env.example` file that lists all required variable names without any values (real or phantom):

```bash
phantom env
```

This creates `.env.example`:

```env
OPENAI_API_KEY=
ANTHROPIC_API_KEY=
DATABASE_URL=
NODE_ENV=development
PORT=3000
```

Non-secret values are preserved as-is. Secret values are left blank.

To write to a different filename:

```bash
phantom env --output .env.template
```

### What to commit

| File | Commit? | Why |
|------|---------|-----|
| `.env.example` | Yes | Shows teammates what variables are needed |
| `.phantom.toml` | Yes | Shares proxy/service config with the team |
| `.env` | No | Contains phantom tokens specific to your vault |
| `.env.local` | No | Same reason |

Add to your `.gitignore`:

```gitignore
.env
.env.local
.env*.local
```

### New teammate workflow

When a new developer joins:

1. They clone the repo and see `.env.example`.
2. They copy it to `.env` and fill in their own API keys.
3. They run `phantom init` to protect those secrets.
4. Or, if secrets are already in Vercel: `phantom pull --from vercel --project prj_abc123def456`.

## 8. Pre-commit Hook

`phantom check` scans staged files for unprotected secrets. Set it up as a git hook to block accidental leaks before they reach your repository.

### With the pre-commit framework

Add to your `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/ashlrai/phantom-secrets
    rev: v0.1.0
    hooks:
      - id: phantom-check
```

Then install:

```bash
pre-commit install
```

### Manual git hook

```bash
echo '#!/bin/sh
phantom check' > .git/hooks/pre-commit
chmod +x .git/hooks/pre-commit
```

### What it catches

- Real API keys in `.env` files (values that should be phantom tokens)
- Hardcoded secrets in staged source files (patterns like `sk-*`, `ghp_*`, `AKIA*`)

```
$ phantom check
BLOCKED Unprotected secrets detected!

  ! .env has 1 unprotected secret(s):
    - OPENAI_API_KEY

fix Run phantom init to protect your secrets.
```

If everything is clean, `phantom check` exits silently with code 0.

## 9. Claude Code MCP Integration

For a deeper integration, Phantom provides an MCP server that lets Claude Code manage secrets natively -- listing, adding, and rotating secrets without ever exposing real values in the conversation.

### Automatic setup

```bash
phantom setup
```

This configures the MCP server in your Claude Code settings and sets up the proxy to start automatically.

### Manual setup

Add to `.claude/settings.json` (project-level) or your global Claude Code settings:

```json
{
  "mcpServers": {
    "phantom": {
      "command": "phantom-mcp",
      "args": []
    }
  }
}
```

### Available MCP tools

Once configured, Claude Code gains these tools:

| Tool | What it does |
|------|-------------|
| `phantom_list_secrets` | List secret names (never shows values) |
| `phantom_status` | Show vault, config, and proxy status |
| `phantom_init` | Initialize Phantom and protect .env secrets |
| `phantom_add_secret` | Add a secret to the vault |
| `phantom_remove_secret` | Remove a secret from the vault |
| `phantom_rotate` | Regenerate all phantom tokens |

Claude can call these tools during a session. For example, if you say "add my new Stripe key," Claude can use `phantom_add_secret` to store it safely -- the real value passes through the MCP protocol but never enters Claude's context window or conversation logs.

## 10. FAQ

### What if I share my project with someone who does not use Phantom?

Everything still works. Your `.env` contains phantom tokens, which are harmless -- they look like gibberish API keys and will simply fail authentication if used directly. The teammate can replace them with their own real keys, or install Phantom themselves.

### What if I need to see a real secret value?

Phantom deliberately never displays real values. This is a security feature. If you absolutely need to retrieve a value:

- **macOS**: Open Keychain Access and search for "phantom"
- **Linux**: Use your Secret Service client (e.g., `secret-tool` or Seahorse)
- **Or**: Check the deployment platform (Vercel dashboard, Railway dashboard) where you synced the secrets

### What if the proxy is not running and my app tries to make an API call?

The app will send the phantom token (`phm_...`) directly to the API, which will reject it as an invalid key. This is by design -- phantom tokens are worthless outside the proxy. Start the proxy with `phantom exec` or `phantom start` before running your app.

### Can I use Phantom in CI/CD?

Yes. In environments without an OS keychain (Docker, CI runners), Phantom falls back to an encrypted file vault. Use `phantom pull` to populate secrets from your deployment platform at the start of the CI job.

### Does Phantom work with monorepos?

Yes. Run `phantom init` in each package/app directory that has its own `.env`. Each gets its own `.phantom.toml` and set of phantom tokens. The proxy handles all of them in a single `phantom exec` session.

### What if I add a new secret to .env after initialization?

Run `phantom init` again. It detects new unprotected secrets, adds them to the vault, and rewrites the `.env`. Existing phantom tokens are preserved.

### How do I rotate my phantom tokens?

```bash
phantom rotate
```

This regenerates all phantom tokens in your `.env` without affecting the real secret values in the vault. Useful if you suspect a token mapping was exposed.

### Is the proxy secure?

The proxy binds to `127.0.0.1` only -- it is never exposed to the network. It uses TLS (via rustls) for all outgoing connections to real APIs. Secrets are zeroized from memory after injection. See [SECURITY.md](../SECURITY.md) for the full threat model.

### How do I check that everything is healthy?

```bash
phantom doctor
```

This verifies your vault, config file, keychain access, and proxy configuration. Run it whenever something feels off.
