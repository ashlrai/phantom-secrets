# INTEGRATION.md — phantom-secrets × Phantom

How this repository plugs into Phantom (the workbench/orchestrator, formerly
Ashlr Hub). Written from this repo's side only. There is no library
dependency in either direction: integration happens through the CLI, the
local MCP server, and versioned JSON contracts.

The reviewed public GitHub release is `v0.8.7`. Source may be newer. See
[distribution status](docs/distribution-status.md) for dated package-channel
evidence. This note does not claim a new release, hosted-service
commissioning, or provider activation.

## What this repo provides

- **Secret delegation**: `phm_`-prefixed placeholder tokens replace real API
  keys in project files. Real values live in an encrypted local vault (OS
  keychain preferred, encrypted file backend available).
- **Authenticated local proxy**: `phantom exec -- <command>` starts a
  loopback-only proxy (127.0.0.1, ephemeral port, session-scoped bearer).
  Outbound app requests route through it; the proxy injects the matched
  route's vault value into the fixed auth header only. Client headers and
  bodies never resolve placeholders. Only supported, configured provider
  routes are eligible; this is not an arbitrary authenticated forwarding proxy.
- **Value-blind MCP tools** (bundled `phantom mcp serve`, with a verified local
  standalone `phantom-mcp` fallback): inventory, status, diagnostics, audit,
  rotation, and governed requests over secret *names*, never values. The
  release schema smoke is the catalog count.
- **Machine status contract**: `phantom status --json` (schema v1,
  [docs/hub-status-contract.md](docs/hub-status-contract.md)) lets an
  orchestrator check whether a project has valid Phantom configuration
  without opening the vault or dotenv. That contract still names Ashlr Hub
  as a consumer; this note uses the Phantom workbench name.
- **`phantom-locus-contract` crate**: an *inactive*, value-free compatibility
  contract for candidate Locus authority work. Metadata evidence only;
  fail-closed; it cannot construct a grant, activate anything, or reveal a
  credential.

## The delegation model (opt-in)

1. **Human, in a trusted terminal**: `phantom init` stores detected secret
   values in the vault, atomically rewrites the managed `.env` with persistent
   `phm_` mappings, writes `.phantom.toml`, generates `.env.example`, and
   installs a pre-commit check. It creates no plaintext project-local backup.
   Recovery is from the provider console or password manager.
2. **Human**: `phantom setup --client <claude|cursor|windsurf|codex|gemini>`
   writes the MCP client config pointing at the bundled `phantom mcp serve`
   entrypoint. A verified local standalone fallback is supported; setup never
   bootstraps a registry package or downloads a runtime.
   `phantom agent setup --dry-run` previews setup actions. Its readiness
   report can open the vault, and opening the vault can reconcile legacy
   keychain sidecars. Use metadata-only `phantom status --json` for
   unattended configuration observation.
3. **Human or orchestrator**: `phantom exec -- <agent-command>` opens a
   session: fresh ephemeral child placeholders plus a separate proxy bearer.
   Supported app API traffic uses the proxy. MCP remains a local stdio
   connection; its presence does not activate provider access.
4. **Agent, value-blind**: the agent sees secret names via MCP
   (`phantom_list_secrets`, `phantom_status`, `phantom_doctor`, `phantom_why`,
   `phantom_check`). Every state-changing or credential-using tool is disabled
   by default and only reachable via `PHANTOM_MCP_EFFECTS=trusted-terminal` +
   `confirm: true` + a one-use `approval_token` minted by `phantom mcp-approve`
   (typed challenge, attached trusted terminal, outside agent authority).
5. **Local placeholder rotation / revocation**: `phantom rotate` regenerates
   every `phm_` mapping (old ones become invalid). `phantom remove` deletes a
   vault entry and its mapping. Expiry policies demote expired entries to
   read-only. Shipped builds hard-deny live provider issuance and rotation
   before credential or network access.

```
human (trusted terminal)          agent / orchestrator (untrusted context)
────────────────────────          ──────────────────────────────────────
phantom init ──► vault (real values, encrypted at rest)
        │
        └──► .env rewritten: STRIPE_SECRET_KEY=phm_... (persistent mapping,
              sensitive metadata: reveals which secrets exist, not values)

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
2. **Vault at rest.** OS keychain preferred. Linux `keyutils` is volatile;
   `init` warns and points at `phantom vault migrate-linux` or the encrypted-file
   fallback. Memory handling uses `zeroize`; `SecretValue` has no
   `Debug`/`Display`.
3. **Proxy.** Loopback-only, bounded bodies (32 MiB default, 320 MiB aggregate),
   256-connection / 32-request caps, rate-limited, streaming-safe. Upstream
   requests never inherit agent-controlled `HTTP(S)_PROXY`/`ALL_PROXY`, and
   the proxy does not follow upstream redirects.
4. **MCP approval ceremony.** A same-user shell or agent-controlled PTY can
   defeat the typed challenge. Approvals must happen outside the requesting
   agent's authority, and `~/.phantom` approval storage must stay outside it too.
5. **Cloud / team sync.** Client-side end-to-end encryption (X25519 device
   keys; private key in OS keychain). The server never sees plaintext. Phantom
   Cloud is a separately commissioned hosted service; source alone proves
   nothing about it.
6. **Orchestrator reads.** `status --json` is value-free; consumers must reject
   missing/unsupported schema versions and treat parse failures as unknown.
7. **Locus.** The contract crate is inactive by design. Any future activation
   needs both sides to reproduce the contract fixture and an explicit,
   separately approved activation design.

Live provider issuance, enrollment exchange, credential rotation, and remote
revocation remain denied before credential or network access. The source and
MCP catalog do not establish hosted-service commissioning or account access.

## Opting out

- **Per session**: end `phantom exec`. Session tokens and the proxy bearer die.
- **Per project**: `phantom remove` each secret from the vault, restore `.env`
  from the independent source, delete `.phantom.toml` and the pre-commit hook.
- **Per client**: delete the MCP config `phantom setup` wrote, or run
  `phantom setup --undo`.
- **Per machine**: uninstall the binaries. Nothing phones home.

## What the orchestrator side must uphold

- Never request, accept, or persist real credential values. Use secret names.
- Run `init`, `mcp-approve`, and every mutating flow only in an attended
  trusted terminal; never emulate the ceremony from an agent shell.
- Keep `~/.phantom` outside agent authority.
- Validate `status --json` schema versions; fail closed on mismatch.
- Keep Locus interop value-free until the contract fixture reproduces on both
  sides and an activation design is approved.

## Open questions

- Should the Phantom workbench auto-detect `phantom status --json` per project
  and surface "protected / unprotected / unknown" in its UI?
- Is `phantom exec` session lifecycle owned by the workbench (spawn/kill) or by
  the user (workbench only observes)?
- Does the workbench need a "request approval" bridge that routes an MCP
  approval nonce to the human's trusted terminal?
