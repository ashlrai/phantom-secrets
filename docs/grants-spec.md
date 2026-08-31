# Phantom Grants — Design-Era Lifecycle Specification

> **Status: historical design document, not a statement of shipped behavior.**
> The current CLI implements trusted-terminal issuance and value-blind grant
> metadata, but remote revocation is not wired and therefore fails closed before
> local mutation. Renewal/provider claims below describe the intended design and
> require provider-specific acceptance. Use the root README, CLI `--help`, current
> architecture guide, and threat model for the implemented contract.

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
| Sentry | Static token creation is web-session-gated; the sanctioned headless path is a published-integration install that mints 8h org tokens via JWT-bearer |
| Supabase | Management API is authenticated *with* a PAT and exposes no endpoint to mint or rotate PATs |
| Stripe | No public key-mint/roll API for `rk_`/`sk_` (dashboard only). A **Stripe App with `stripe_api_access_type=oauth`** yields a 1-hour access token off a 1-year rolling refresh token |

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

### 2. App Identity — shipped (GitHub App manifest bootstrap)

The consent creates an *identity*, not a token. Tokens are derived,
short-lived, and disposable.

- One consent (**"FOUR clicks, ever"**): `phantom grant add github-app` opens a
  loopback-served, self-submitting launch page that POSTs a least-privilege
  manifest (`contents:write`, `pull_requests:write`, `issues:write`,
  `metadata:read`; `public:false`) to `github.com/settings/apps/new`. The human
  clicks **"Create GitHub App"** once; GitHub redirects the code back to the
  loopback listener; Phantom exchanges it at
  `POST /app-manifests/{code}/conversions` and receives the full credential set
  (App id, PEM, client id/secret, webhook secret) in one response. Then one
  **"Install"** click per account/org.

```bash
phantom grant add github-app [--org <ORG>] [--name <APP_NAME>] [--rotate-secret <KEY>] [--no-browser] [--json]
```

  - The PEM, client secret and webhook secret are vaulted (keychain-backed,
    never in `.phantom.toml`, never in git, never printed, never in `--json`).
    The client id is vaulted non-sensitive (needed as the JWT `iss`).
  - Installations are discovered via `GET /app/installations`, authenticated
    with an in-process App JWT minted from the just-issued PEM.
  - Forever after: `GitHubRotationProvider` mints installation access tokens
    via `POST /app/installations/{id}/access_tokens` (1-hour expiry, stamped on
    the stored secret). On every rotation Phantom mints the RS256 App JWT
    **in-process** from the vaulted PEM (`GithubAppJwtProvider::mint_app_jwt`,
    `iss = client_id`, `exp < 10 min`) — the JWT never exists outside the
    rotation call, is never an env var, and is zeroized after use.
  - `grant add` writes the corresponding `rotation_provider` block (under
    `GITHUB_TOKEN` by default, or `--rotate-secret`) so `phantom rotate --name
    <KEY>` and `phantom watch --auto-rotate` work unchanged.

#### 2b. App Identity — Vercel Integration (shipped)

The same app-identity shape, but the durable root is a **non-expiring,
team-scoped access token** rather than a private key — so there is no
short-lived-token minting step; the token *is* the identity, and renewal is a
no-op by construction.

- One-time vendor step (ever): fill the self-serve **Create Integration** form in
  the Vercel Integrations Console (Community-badge integrations are installable
  immediately by direct URL — no Vercel review below 500 installs). This yields
  the Integration's `client_id` / `client_secret`.
- One consent per user/team: `phantom grant add vercel-integration` binds an
  ephemeral `127.0.0.1` loopback listener, opens the hosted install page, and the
  human clicks **"Add Integration"** once. Vercel redirects the one-time code
  (30-minute, single-use) back to the loopback; Phantom verifies the CSRF
  `state`, then exchanges the code at
  `POST https://api.vercel.com/v2/oauth/access_token`
  (`client_id` + `client_secret` + `code` + `redirect_uri`, form-encoded).

```bash
phantom grant add vercel-integration \
  --client-id <INTEGRATION_CLIENT_ID> \
  --client-secret-env VERCEL_INTEGRATION_SECRET \
  [--team <TEAM_ID>] [--no-browser] [--json]
```

  - The scoped token is vaulted under `VERCEL_INTEGRATION_TOKEN` (keychain-backed,
    never in `.phantom.toml`, never in git, never printed, never in `--json`).
    The `client_secret` is supplied via `--client-secret-env` and is never read
    from disk.
  - **teamId plumbing:** a team install returns `team_id` in the exchange body
    (`null` = personal account); an explicit `--team` overrides it. The team id
    is *not* a secret — it lands in the grant metadata and in the
    `rotation_provider` block's `account_id`, so every subsequent team-scoped
    REST call (`?teamId=…`) is correctly scoped. A missing teamId on a team
    install is the documented cause of Vercel 403s.
  - `grant add` writes the `rotation_provider` block under
    `VERCEL_INTEGRATION_TOKEN` (provider `"vercel"`), so `phantom rotate` and
    whoami dispatch with the right teamId. Because the token never expires, this
    is a no-op by construction; the shipped self-rotating chain (grant #1) stays
    the fallback whenever a genuinely rotating **raw user token** is required.
  - **Not** the device grant: Vercel's `device_code` grant is empirically closed
    to third-party clients (DCR strips it, verified 2026-08-18), and reusing the
    first-party CLI `client_id` would be unsanctioned impersonation. The
    connectable-account Integration is the only sanctioned app-identity path.

#### 2c. App Identity — Sentry Integration (shipped)

The GitHub-App shape almost verbatim: a long-lived **app identity** (the
published integration's `client_id` / `client_secret`) is the durable root, and
short-lived **8-hour org tokens** are minted on demand from it — issuance and
renewal are the same operation. The `client_secret` plays the role GitHub's
private-key PEM plays; renewal is **stateless** (no stored refresh token to
lose) via the JWT-bearer grant.

- One-time vendor step (ever): create the integration in **Sentry → Settings →
  Developer Settings** (client id/secret, scopes, redirect + webhook URL).
- One consent per org: `phantom grant add sentry` binds an ephemeral
  `127.0.0.1` loopback listener, opens the integration's
  `…/sentry-apps/<slug>/external-install/` page, and the human clicks **"Accept &
  Install"** once (selecting the org). Sentry redirects the grant `code` +
  `installationId` back to the loopback; Phantom verifies the CSRF `state`, then
  exchanges the code at
  `POST /api/0/sentry-app-installations/{uuid}/authorizations/`
  (`grant_type=authorization_code`, `code`, `client_id`, `client_secret`).

```bash
phantom grant add sentry \
  --client-id <INTEGRATION_CLIENT_ID> \
  --client-secret-env SENTRY_CLIENT_SECRET \
  [--org <integration-slug>] [--no-browser] [--json]
```

  - Vaulted (keychain-backed, never in `.phantom.toml`, never in git, never
    printed, never in `--json`): the JWT-bearer **seed** `SENTRY_APP_JWT_SEED`
    (the packed `client_id` + `client_secret` app identity), `SENTRY_CLIENT_ID`
    (non-secret), and the first minted `SENTRY_ORG_TOKEN`. The `client_secret`
    is supplied via `--client-secret-env` and is never read from disk.
  - `grant add` writes the `rotation_provider` block under `SENTRY_ORG_TOKEN`
    (provider `"sentry"`, `api_key_env = SENTRY_APP_JWT_SEED`, `account_id =
    <installation-uuid>`). `phantom rotate --name SENTRY_ORG_TOKEN` then signs a
    fresh HS256 JWT from the seed (`iss = client_id`, signed with
    `client_secret`) and mints the next 8-hour token via
    `grant_type=urn:sentry:params:oauth:grant-type:jwt-bearer` — **forever, with
    no stored refresh token and no human**.
  - **Consent transport — loopback vs webhook.** Sentry delivers the grant code
    two ways: the redirect query params (the loopback landing implemented here)
    **and** the `installation.created` webhook payload (`data.installation.code`
    + `uuid`). A hosted server can skip the loopback entirely and pick the code
    off the webhook — the user can even close the install tab. That webhook
    receiver is a server-side concern **out of scope for the local CLI**; the
    loopback landing is the local-first path and needs no inbound endpoint.
  - **Legacy static tokens stay manual.** Org auth tokens (`sntrys_…`),
    internal-integration tokens, and personal tokens are all session-gated
    (token-cannot-mint-token) and dashboard-only; store any of those as a
    `manual` grant. The install flow is the only headless path to Sentry
    credentials.

### 3. OAuth Refresh — shipped (Supabase, Stripe); future (Sentry)

The vendor gates minting behind a browser session — so the grant *is* a
browser session, exactly once.

- One-time vendor ceremony (Supabase): ~2-minute creation of a Phantom-owned
  OAuth App in **Organization Settings → OAuth Apps** (dashboard-only; request
  every scope up front — they are fixed per app and a change forces re-consent).
- One consent: `phantom grant add supabase [--org <slug>]` opens the vendor's
  OAuth consent page in the browser. Authorization Code + **PKCE S256**, with a
  `127.0.0.1` loopback redirect and a CSRF `state` check: Phantom binds an
  ephemeral localhost callback listener, receives the code, and exchanges it
  in-process. The exchange authenticates the **confidential client with HTTP
  Basic auth** (`base64(client_id:client_secret)`), and `--org` pre-selects the
  `organization_slug` on the consent page. The client secret is resolved from
  `--client-secret-env`, never read from disk; no tokens are copy-pasted.
- Forever after: the **refresh token** is the vaulted root, dispatched to the
  `supabase-management` rotation provider (distinct from the manual-only
  `supabase` PAT provider). `phantom rotate --name SUPABASE_REFRESH_TOKEN`
  performs the refresh grant — Supabase **rotates the refresh token on every
  use**, so the successor is vaulted before the predecessor is spent (the same
  store-then-invalidate ordering as Vercel). From that refreshed management
  token the same provider becomes the **issuer** of downstream project
  credentials: `POST /v1/projects/{ref}/api-keys` mints a fresh `sb_secret_`
  key, verifies it, and DELETEs the rotated-out key after the successor is
  stored (Mode B, `account_id` = the project ref).
- If the vendor revokes the refresh token (password change, org policy,
  disconnect), the refresh returns `401` and Phantom surfaces it as a broken
  grant needing one new consent — it never silently falls back to a lesser
  credential.

#### 3b. OAuth Refresh — Stripe App (shipped)

Stripe's only self-refreshing credential is a **Stripe App with
`stripe_api_access_type=oauth`** — a 1-hour access token off a **1-year rolling
refresh token**.

- One-time vendor ceremony: `stripe apps create` + a manifest
  (`stripe_api_access_type=oauth`, minimal permissions, loopback redirect URIs)
  + `stripe apps upload`. External-test authorize links work immediately for
  your own accounts with no marketplace review; public distribution needs review.
- One consent: `phantom grant add stripe --client-id <ca_…> [--account <acct_…>]`
  opens the Stripe authorize page. Authorization Code with a `127.0.0.1` loopback
  redirect and a CSRF `state` check (Stripe has **no PKCE** — confidential client
  only). The token exchange authenticates with **HTTP Basic auth using Phantom's
  own developer secret key** (`-u "sk_…:"`), resolved from `--client-secret-env`
  (default `STRIPE_APP_SECRET_KEY`), never read from disk. No tokens are
  copy-pasted; the 1-hour access token is never stored (minted on demand).
- Forever after: the **refresh token** is the vaulted root (`STRIPE_REFRESH_TOKEN`),
  dispatched to the `stripe` rotation provider's **additive oauth-refresh path**.
  `phantom rotate --name STRIPE_REFRESH_TOKEN` performs `grant_type=refresh_token`
  against `POST /v1/oauth/token` — Stripe **rolls the refresh token on every
  exchange**, so the successor is vaulted before the predecessor is spent (the
  same store-then-invalidate ordering as Vercel/Supabase). Any refresh cadence
  under a year keeps the 1-year chain immortal.
- The raw restricted-key path (`--flow rak`, e.g. for `STRIPE_KOALA_TEST`) stays
  a fail-closed `NotSupported` with the sandbox dashboard link — Stripe exposes
  no public API to create `rk_`/`sk_` keys — and steers the operator to the
  OAuth route.

### 4. Manual — honest (Stripe raw keys et al.)

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
  are compiled only into unit tests and audit-tagged `vault.rotation.mock`;
  runtime environment variables cannot activate a mock credential or alternate
  credential-bearing endpoint in a shipped binary.
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
- [x] Fail-closed `NotSupported` providers with dashboard guidance (Stripe raw-key, AWS)
- [x] Env-then-vault bootstrap resolution; `Zeroizing` value handling
- [x] Dispatch by provider identity; guarded, audit-tagged mock paths
- [x] `phantom rotate --batch` with per-provider rate limits and shared audit `batch_id`
- [x] `rotation_policy` schedules + `phantom watch --auto-rotate` + doctor warnings
- [x] `phantom grant add github-app` (manifest bootstrap → PEM/client-id/secret/webhook vaulted, installations discovered, in-process RS256 App-JWT minting wired into `phantom rotate`)
- [x] `phantom grant add vercel-integration` (connectable-account Integration → non-expiring team-scoped token vaulted, teamId plumbed into the rotation block)
- [x] `phantom grant list` / `status` / `revoke` + grant state model (`active | expiring | broken | manual`)
- [ ] Grant-aware MCP surface (`phantom_grant_status`, metadata-only)
- [x] `phantom grant add supabase` (S256 PKCE loopback + Basic client auth + `--org` organization_slug → refresh token vaulted; `supabase-management` self-rotates the management token and mints/rotates project `sb_secret_` API keys)
- [x] `phantom grant add stripe` (Stripe App OAuth: loopback code capture + HTTP Basic developer-secret exchange → 1-year rolling refresh token vaulted; `stripe` provider's additive oauth-refresh path rolls it; `--flow rak` fail-closed dashboard path for raw `rk_`/`sk_` keys)
- [x] `phantom grant add sentry` (published-integration install: loopback `external-install` code capture → app identity (`client_id`/`client_secret`) vaulted as the `SENTRY_APP_JWT_SEED`, installation uuid recorded; `sentry` provider mints 8-hour org tokens statelessly via the `client_secret`-signed JWT-bearer grant; webhook-receiver server variant documented, out of scope for local CLI)
- [ ] OAuth refresh grants: PKCE loopback-callback flow (Sentry user-scoped device/pkce)
- [ ] Manual-grant reminder polish: scheduled warn → dashboard link → audited vault re-entry
- [ ] AWS IAM access-key-pair rotation (SigV4) as a self-rotating grant
- [ ] Broken-chain diagnosis in `phantom doctor` (which link died, which consent to redo)
