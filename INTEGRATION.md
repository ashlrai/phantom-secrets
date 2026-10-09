# INTEGRATION.md — phantom-secrets × Phantom

How this repository plugs into Phantom (the workbench/orchestrator, formerly
Ashlr Hub). Written from this repo's side only. There is no library
dependency in either direction: integration happens through the CLI, the
local MCP server, and versioned JSON contracts.

## What this repo provides

- **Secret delegation**: `phm_`-prefixed placeholder tokens replace real API
  keys in project files. Real values live in an encrypted local vault (OS
  keychain preferred, encrypted file backend available).
- **Authenticated local proxy**: `phantom exec -- <command>` starts a
  loopback-only proxy (127.0.0.1, ephemeral port, session-scoped bearer).
  Outbound app requests route through it; the proxy injects the matched
  route's vault value into the fixed auth header only. Client headers and
  bodies never resolve placeholders.
- **Value-blind MCP tools** (`phantom-mcp`, 54 tools): inventory, status,
  diagnostics, audit, rotation, and governed requests over secret *names* —
  never values.
- **Machine status contract**: `phantom status --json` (schema v1,
  `docs/hub-status-contract.md`) lets an orchestrator check whether a project
  has valid Phantom configuration without opening the vault or dotenv.
- **`phantom-locus-contract` crate**: an *inactive*, value-free compatibility
  contract for candidate Locus authority work. Metadata evidence only;
  fail-closed; it cannot construct a grant, activate anything, or reveal a
  credential.

## The delegation model (opt-in)

1. **Human, in a trusted terminal**: `phantom init` stores detected secret
   values in the vault, atomically rewrites the managed `.env` with persistent
   `phm_` mappings, writes `.phantom.toml`, generates `.env.example`, and
   installs a pre-commit check. No plaintext project-local backup is kept —
   recovery is from the provider console or password manager.
2. **Human**: `phantom setup --client <claude|cursor|windsurf|codex>` writes
   the MCP client config pointing at the local `phantom-mcp` binary.
   `phantom agent setup --dry-run` previews readiness without changing anything.
3. **Human or orchestrator**: `phantom exec -- <agent-command>` opens a
   session — fresh ephemeral child placeholders plus a separate proxy bearer.
   The agent's tool calls and the app's API traffic flow through the proxy.
4. **Agent, value-blind**: the agent sees secret names via MCP
   (`phantom_list_secrets`, `phantom_status`, `phantom_doctor`, `phantom_why`,
   `phantom_check`). Every state-changing or credential-using tool is disabled
   by default and only reachable via `PHANTOM_MCP_EFFECTS=trusted-terminal` +
   `confirm: true` + a one-use `approval_token` minted by `phantom mcp-approve`
   (typed challenge, attached trusted terminal, outside agent authority).
5. **Rotation / revocation**: `phantom rotate` regenerates every `phm_` mapping
   (old ones become invalid); `phantom remove` deletes a vault entry and its
   mapping; expiry policies demote expired entries to read-only.

```
human (trusted terminal)          agent / orchestrator (untrusted context)
────────────────────────          ──────────────────────────────────────
phantom init ──► vault (real values, encrypted at rest)
        │
        └──► .env rewritten: STRIPE_SECRET_KEY=phm_9f… (persistent mapping,
              sensitive metadata — reveals *which* secrets exist, not values)

phantom exec -- agent-cmd ──► session: fresh child placeholders (inert) +
                              proxy bearer (session-scoped, sensitive)
        │
        ▼
local proxy 127.0.0.1:<ephemeral>
  1. app request arrives with phm_ placeholder
  2. interceptor matches exact route → vault lookup
  3. injects real value ONLY into the fixed auth header
  4. forwards upstream (no agent-controlled proxy env, no redirect following
     with credentials); response scrubber rejects leaked real-secret patterns
```

## Trust boundaries

1. **Trusted terminal vs. agent context.** Real values never cross into agent
   context. `phm_` mappings are sensitive metadata: do not log or publish them.
2. **Vault at rest.** OS keychain preferred. Linux `keyutils` is volatile —
   `init` warns. Memory handling uses `zeroize`; `SecretValue` has no
   `Debug`/`Display`.
3. **Proxy.** Loopback-only, bounded bodies (10 MB default), 256-connection /
   32-request caps, rate-limited, streaming-safe. Upstream requests never
   inherit agent-controlled `HTTP(S)_PROXY`/`ALL_PROXY`.
4. **MCP approval ceremony.** A same-user shell or agent-controlled PTY can
   defeat the typed challenge — approvals must happen outside the requesting
   agent's authority, and `~/.phantom` approval storage must stay outside it too.
5. **Cloud / team sync.** Client-side end-to-end encryption (X25519 device
   keys; private key in OS keychain). The server never sees plaintext — but
   Phantom Cloud is a separately commissioned hosted service; source alone
   proves nothing about it.
6. **Orchestrator reads.** `status --json` is value-free; consumers must reject
   missing/unsupported schema versions and treat parse failures as unknown.
7. **Locus.** The contract crate is inactive by design. Any future activation
   needs both sides to reproduce the contract fixture *and* an explicit,
   separately approved activation design — not a silent upgrade.

## Opting out

- **Per session**: end `phantom exec` — session tokens and the proxy bearer die.
- **Per project**: `phantom remove` each secret from the vault, restore `.env`
  from the independent source, delete `.phantom.toml` and the pre-commit hook.
- **Per client**: delete the MCP config `phantom setup` wrote.
- **Per machine**: uninstall the binaries. Nothing phones home.

## What the orchestrator side must uphold

- Never request, accept, or persist real credential values — use secret names.
- Run `init`, `mcp-approve`, and every mutating flow only in an attended
  trusted terminal; never emulate the ceremony from an agent shell.
- Keep `~/.phantom` outside agent authority.
- Validate `status --json` schema versions; fail closed on mismatch.
- Keep Locus interop value-free until the contract fixture reproduces on both
  sides and Mason approves an activation design.

## Open questions for Mason

- Should the Phantom workbench auto-detect `phantom status --json` per project
  and surface "protected / unprotected / unknown" in its UI?
- Is `phantom exec` session lifecycle owned by the workbench (spawn/kill) or by
  the user (workbench only observes)?
- Does the workbench need a "request approval" bridge that routes an MCP
  approval nonce to the human's trusted terminal?
