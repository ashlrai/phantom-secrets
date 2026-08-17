# Phantom Grants: One Human Consent, Perpetual Agent-Safe Credential Lifecycle

## Primary Promise

Agents and Phantom do ALL credential lifecycle for you. A human consents
**once per provider**; renewal is Phantom's forever.

## The Invariant

Every vendor gates *issuance* of a root credential behind a human — a
dashboard click, a browser session, an app install. No vendor lets an API key
mint the *first* key. This is not a Phantom limitation; it is provider policy,
verified empirically:

| Provider | Issuance gate (verified against live APIs) |
|----------|--------------------------------------------|
| GitHub | No API to create or rotate classic/fine-grained PATs — dashboard only. App **installation tokens** are mintable via API once an App exists |
| Vercel | `POST /v3/user/tokens` requires a user token; app/integration tokens get **403** |
| Sentry | Token creation is web-session-gated — no token-auth minting endpoint |
| Supabase | Management API is authenticated *with* a PAT and exposes no endpoint to mint or rotate PATs |
| Stripe | No public key-mint/roll API — dashboard only |

Phantom cannot remove the first consent. **Grants** makes it the *last*
consent: the one human action per provider that seeds a renewal chain Phantom
drives forever after — every successor credential minted, verified, stored,
and revoked without a human and without a value ever entering an agent's
context.

A **grant** is that seeded renewal chain, as a first-class product object:
the record of the one consent, the vaulted material it produced, and the
mechanics Phantom uses to renew from it.

## Grant Types

Provider mechanics dictate four grant shapes. Every provider maps to exactly
one; there is no fifth.

### 1. Self-Rotating Token — shipped (Vercel)

The credential can mint its own successor.

- One consent: create a token in the Vercel dashboard.
- Forever after: `VercelRotationProvider` uses the current token to `POST
  /v3/user/tokens`, verifies the successor against `GET /v2/user` (2xx-only),
  stores it in the vault, then best-effort revokes the old token in
  `post_store_cleanup` — only **after** the new value is durably stored, so a
  crash can never strand you with zero valid tokens.
- Bootstrap resolution is env-then-vault: `api_key_env` is read from the
  process environment first, then from the vault under the same name — after
  the first rotation the chain is fully vault-resident.

### 2. App Identity — provider core shipped (GitHub); grant UX open

The consent creates an *identity*, not a token. Tokens are derived,
short-lived, and disposable.

- One consent: create a GitHub App, install it on the org/repos, download the
  private key PEM.
- Forever after: `GitHubRotationProvider` mints installation access tokens
  via `POST /app/installations/{id}/access_tokens` (1-hour expiry, stamped on
  the stored secret). Already on `main`.
- The missing UX this spec commits to — today the operator must hand-mint the
  App JWT (which expires in ~10 minutes) as the bootstrap credential, which
  no human can sustain and no agent should be handed:

```bash
phantom grant add github --app-id 12345 --installation-id 987 --key-file app.private-key.pem
```

  - The PEM is stored in the vault (keychain-backed, never in `.phantom.toml`,
    never in git); the file copy can be deleted.
  - On every rotation Phantom mints the RS256 App JWT **in-process** from the
    vaulted PEM — the JWT never exists outside the rotation call, is never an
    env var, and is zeroized after use.
  - The grant writes the corresponding `rotation_provider` block so
    `phantom rotate` and `phantom watch --auto-rotate` work unchanged.

### 3. OAuth Refresh — future (Supabase, Sentry)

The vendor gates minting behind a browser session — so the grant *is* a
browser session, exactly once.

- One consent: `phantom grant add supabase` opens the vendor's OAuth consent
  page in the browser. Authorization Code + **PKCE**, with a loopback
  redirect: Phantom binds an ephemeral localhost callback listener, receives
  the code, exchanges it in-process. No client secret on disk, no
  copy-pasting tokens.
- Forever after: the **refresh token** lives in the vault; access tokens are
  minted from it on demand, stamped with their expiry, and never shown.
  Refresh-token rotation (vendors that one-time-use them) follows the same
  store-then-invalidate ordering as Vercel: the successor refresh token is
  vaulted before the old one is considered spent.
- If the vendor revokes the refresh token (password change, org policy), the
  grant reports `broken` and asks for one new consent — it never silently
  falls back to a lesser credential.

### 4. Manual — honest (Stripe et al.)

No API, no session to automate — and Phantom says so instead of pretending.

- The provider is a fail-closed `NotSupported` implementation: it performs no
  network I/O and returns the exact dashboard URL where the human rotates.
- The grant's job is *scheduling*, not minting: `rotation_policy` warn
  thresholds drive `phantom doctor` warnings and `phantom watch` reminders,
  so the one thing a human must still do arrives as a prompt, on time, with
  the link — and the new value goes into the vault through the same audited
  write path.

## Command Surface

```bash
phantom grant add <provider> [--app-id --installation-id --key-file | --oauth | --token-env <NAME>]
phantom grant list                 # provider, type, state, next renewal — never values
phantom grant status [<provider>]  # chain health: last renewal, expiry, broken-chain diagnosis
phantom grant revoke <provider>    # revoke vaulted material at the vendor where possible, then locally
```

- `grant add` performs the one consent for the provider's grant type, vaults
  the seed material, and **writes the matching `rotation_provider` block** in
  `.phantom.toml` — grants configure rotation; they do not replace it.
- `grant status` is metadata-only, JSON-capable, and safe to expose to agents
  via MCP: state ∈ `active | expiring | broken | manual`.
- `grant revoke` is the lifecycle bookend: best-effort vendor-side
  revocation, vault removal, audit event.

### Composition with rotation

Grants sit *above* the shipped rotation machinery, never beside it:

- `rotation_provider` blocks remain the per-secret execution config;
  dispatch stays by provider **identity**, never by secret-name heuristics.
- `phantom rotate --name KEY` and `phantom rotate --batch` consume grant
  material exactly as they consume any bootstrap credential today
  (env-then-vault).
- `phantom watch --auto-rotate` closes the loop: schedules from
  `rotation_policy` fire, rotation draws on the grant, successors are
  vaulted, expiries restamped — the perpetual half of the promise, unattended.
- Agents get the same flow through `phantom_rotate_provider` MCP, still gated
  behind `confirm: true` plus an out-of-band `phantom mcp-approve` token,
  still returning status metadata only.

## Security Invariants

Inherited from the shipped rotation implementation; grants add material to
the vault, never new exposure paths.

- **Values are keychain-only.** Grant seeds (PEMs, refresh tokens) and every
  minted successor go through the same encrypted-vault write path as
  `phantom add`. Never in `.phantom.toml`, never in git, never printed,
  never in MCP responses.
- **`Zeroizing` in memory.** New values travel as `Zeroizing<String>`;
  bootstrap credentials and in-process JWTs are zeroized after the vendor
  call.
- **Fail closed.** Unsupported providers return `NotSupported` with an
  operator-facing reason — no guessing, no partial rotation. Mock fast-paths
  are guarded (`cfg(test)` or explicit `PHANTOM_ALLOW_MOCK_ROTATION=1`) and
  audit-tagged `vault.rotation.mock` so a mock can never masquerade as a real
  rotation.
- **No silent demotion.** A broken grant surfaces as `broken` and blocks; it
  never falls back to a weaker credential, a cached value, or heuristic
  provider matching. A secret's bootstrap credential is never sent to any
  vendor other than its configured provider.
- **Store before destroy.** Successors are durably vaulted before
  predecessors are revoked; cleanup is fail-open by design (a revoke failure
  must not undo a completed rotation) and is always audited
  (`vault.rotation.old_token_revoke_failed` / `_skipped`, name only).
- **Everything audited.** `vault.rotation.initiated` / `.completed` /
  `.failed` with the provider source label; grants add
  `grant.added` / `grant.renewed` / `grant.broken` / `grant.revoked` — names
  and metadata only, values never.

## Roadmap

- [x] Vercel self-rotating token chain (mint → verify → store → revoke-after-store)
- [x] GitHub installation-token provider core (App JWT bootstrap, 1 h expiry stamping)
- [x] Google GSM version-add rotation (Google-issued credential names refused)
- [x] Fail-closed `NotSupported` providers with dashboard guidance (Stripe, Sentry, Supabase, AWS)
- [x] Env-then-vault bootstrap resolution; `Zeroizing` value handling
- [x] Dispatch by provider identity; guarded, audit-tagged mock paths
- [x] `phantom rotate --batch` with per-provider rate limits and shared audit `batch_id`
- [x] `rotation_policy` schedules + `phantom watch --auto-rotate` + doctor warnings
- [ ] `phantom grant add github --app-id --installation-id --key-file` (PEM in vault, in-process JWT minting)
- [ ] `phantom grant list` / `status` / `revoke` + grant state model (`active | expiring | broken | manual`)
- [ ] Grant-aware MCP surface (`phantom_grant_status`, metadata-only)
- [ ] OAuth refresh grants: PKCE loopback-callback flow (Supabase first, then Sentry)
- [ ] Refresh-token rotation with store-then-invalidate ordering
- [ ] Manual-grant reminder polish: scheduled warn → dashboard link → audited vault re-entry
- [ ] AWS IAM access-key-pair rotation (SigV4) as a self-rotating grant
- [ ] Broken-chain diagnosis in `phantom doctor` (which link died, which consent to redo)
