# Recipe: Phantom with Claude Code

Protect a project's `.env`, register Phantom as the project's MCP server, and
check what Claude Code (the agent) and your app (the process) each receive.

## Steps in your own project

```text
phantom init                    # .env values -> vault; .env now holds phm_ placeholders
phantom setup --client claude   # writes .mcp.json (phantom mcp serve) + hardens .claude/settings.local.json
phantom agent doctor            # value-free readiness report
```

Restart Claude Code in the project and approve the `phantom` project MCP
server when it asks. Then run your app through the proxy so real requests work
while the agent keeps seeing placeholders:

```text
phantom exec -- npm run dev
```

What each side sees after that:

| Who | Sees | Does not see |
|---|---|---|
| Claude Code, via `.env`, `CLAUDE.md` and MCP tools such as `phantom_list_secrets` | Secret names and `phm_` placeholders | Stored values |
| Your app under `phantom exec` | `OPENAI_API_KEY=phm_…` and `OPENAI_BASE_URL=http://127.0.0.1:<port>/openai/_phantom/…` | Stored values. The proxy adds route-owned auth on the way out |

## Run the recipe

[run.mjs](run.mjs) does all of the above in a disposable workspace and HOME,
using a fake key and an explicit encrypted-file vault. It never touches your
keychain, real Claude config, or any provider.

```text
node examples/claude-code/run.mjs --phantom /absolute/path/to/phantom
```

Output from a real run (workspace build, Sep 29, 2026):

```text
PASS phantom init replaces the real value in .env with a phm_ placeholder
PASS phantom setup --client claude writes a project .mcp.json that runs `phantom mcp serve`
PASS the MCP server Claude Code launches lists the secret by name, never by value
     app saw OPENAI_API_KEY=phm_… and OPENAI_BASE_URL=http://127.0.0.1:41829/openai/_phantom/…
PASS phantom exec gives the app a placeholder plus a local proxy URL, not the value
PASS no file an agent can read holds the value, and the project commits through the pre-commit hook
COMPLETE: Claude Code recipe (5 checks)
```

Exit `0` means every check passed, `1` means a check failed, and `2` means the
binary was missing (incomplete, not passed).

**Known issue in v0.7.9:** the pre-commit hook that `phantom init` installs
blocks the first commit of the generated `.env.example`, so the last check
fails against the v0.7.9 release binary. The fix is on `main` in #119 and ships
in the next release. Until then, commit `.env.example` with
`git commit --no-verify` after checking that it holds only `your_…_here`
placeholders.

## Not covered

This recipe does not show Claude Code's UI approving the server, an upstream
provider accepting a proxied request, or any hosted Phantom service. Check
those in your own project. See [docs/claude-code.md](../../docs/claude-code.md)
for the full setup guide.
