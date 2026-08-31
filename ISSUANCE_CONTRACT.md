# Phantom Credential Issuance — Implementation Contract

Bootstrapping the *first* credential (durable root) via sanctioned human
consent, complementing the shipped `RotationProvider` (which renews from a root
that already exists). Issuance produces what rotation consumes.

Status: historical implementation contract. The current shipped behavior is
documented in `docs/grants-spec.md` and governed by the code and tests; this
file is retained as design history and must not be used as an operations
runbook.

---

## 0. Orientation — what already exists (studied, reused, not duplicated)

| Shipped surface | File | What issuance reuses |
|---|---|---|
| `RotationProvider` trait, `default_rotation_providers()`, `GitHubRotationProvider` (mints installation tokens from a *pre-minted* App JWT), `VercelRotationProvider` | `crates/phantom-core/src/rotation_provider.rs` | Issuance writes the `rotation_provider` block these consume; issuance produces the PEM/refresh-token that these renew from. |
| `RotationProviderConfig` (`provider`, `api_key_env`, `account_id`, `region`, `timeout_secs`, `enabled`), `#[serde(deny_unknown_fields)]` | same | Issuance *emits* this config so `phantom rotate` / `watch --auto-rotate` work unchanged. |
| Value hygiene idiom: `Zeroizing<String>` everywhere; `encode_challenge_payload`/`decode_challenge_payload` (base64url, `payload_` prefix); `redact_challenge_id`; `summarize_error_body` (allowlists only `type`/`code`/`status`, withholds body); redacting `Debug` on `AutoSyncOutcome` | same | Issuance imports the identical helpers (promote them to `pub(crate)`); `IssuanceOutcome` gets the same redacting `Debug`. |
| Mock guard: `mock_rotation_allowed()` is compiled only for unit tests; runtime environment variables cannot activate mock rotation or alternate credential-bearing endpoints | same | Issuance test seams must remain compiled-test-only or accept explicitly supplied test clients without production credentials. |
| `build_http_client(timeout_secs)` → `reqwest::blocking::Client` (rustls, json, blocking) | same | Issuance uses `reqwest::blocking` too — same runtime story, no async infection of core. |
| Vault trait `VaultBackend` (`store`, `retrieve`, `store_with_expiry`, `set_rotation_policy`, `record_provider_rotation`, `get/set_metadata`) | `crates/phantom-vault/src/traits.rs` | **Core never calls the vault** (dependency direction is vault → core). Issuance follows rotation's split: core returns `Zeroizing` materials + a store-plan; the **CLI/MCP layer** performs `vault.store(...)`. |
| CLI auto-sync wiring: reads bootstrap env-then-vault, calls `auto_sync_rotation_with_bootstrap`, then `vault.store(name, secret.as_str())`, then `record_provider_rotation`, then `post_store_cleanup` | `crates/phantom-cli/src/commands/rotate.rs:500-570` | `phantom grant add` mirrors this exact ordering (issue → vault.store the root → write config → audit). |
| MCP gate: `require_confirm` + `require_approval_token(tool, token, params_json, project_id)`, metadata-only returns | `crates/phantom-mcp/src/server.rs:551`, `tools/helpers.rs` | `phantom_grant_status` is metadata-only; issuance *itself* is **not** exposed as an agent-callable MCP tool (consent is a human act — see §4.4). |
| Test idiom: `assert_cmd` CLI tests + `wiremock = "0.6"` (dev-dep, phantom-cli) + magic-prefix hermetic mocks; tests assert the known fake value is **never** in stdout/stderr | `crates/phantom-cli/tests/rotate_provider_test.rs` | Issuance tests reuse all three (§5). |
| Phantom Cloud credential origin is fixed to `https://phm.dev/api/v1`; `PHANTOM_API_URL` is rejected | `crates/phantom-core/src/auth.rs` | Credential-bearing production endpoints must not be redirected by agent-controlled environment variables. |

**Two gaps this contract closes** (neither is a blocker; both are net-new work):

1. **No RS256 signer in the tree today.** `GitHubRotationProvider` requires the
   caller to hand it a *freshly minted* App JWT (expires ~10 min) as the
   bootstrap credential — no human can sustain that. The grants-spec commits to
   minting the App JWT **in-process from the vaulted PEM**. → add
   `jsonwebtoken = "9"` to `phantom-core` (`EncodingKey::from_rsa_pem`, alg
   `RS256`). This is used *only* inside a new `GithubAppJwtProvider` bootstrap
   adapter (§3.4), never exposed.
2. **No endpoint override in `rotation_provider.rs`** (hardcoded
   `https://api.github.com`). Issuance hits browser + loopback + device/manifest
   endpoints that tests must redirect. → §5.1 defines the override seam.

---

## 1. Module layout

New surface under `crates/phantom-core/src/issuance/` (core = provider-agnostic
mechanics; **vault-free**, mirrors how `rotation_provider.rs` never touches the
vault):

```
crates/phantom-core/src/issuance/
├── mod.rs            # ConsentEngine trait, IssuanceOutcome, IssuedMaterial,
│                     #   IssuanceError, GrantType, endpoints seam, dispatch,
│                     #   default_consent_engines(), mock guard
├── pkce.rs           # LoopbackPkceEngine (RFC 8252 + RFC 7636 S256)
├── device.rs         # DeviceFlowEngine (RFC 8628)
├── loopback.rs       # LoopbackListener trait + StdLoopbackListener (127.0.0.1
│                     #   ephemeral, std::net::TcpListener, one-request capture)
├── browser.rs        # BrowserOpener trait (+ NoBrowser sentinel for headless)
│                     #   real `open`-based impl lives in phantom-cli, not core
├── github_app.rs     # GithubAppManifestFlow + GithubAppJwtProvider bootstrap
└── endpoints.rs      # base-URL resolution (prod defaults, test overrides)
```

Wiring:
- `crates/phantom-core/src/lib.rs` → `pub mod issuance;`
- CLI: `crates/phantom-cli/src/commands/grant/{mod,add,list,status,revoke}.rs`
  + a `Grant { #[command(subcommand)] .. }` arm in `main.rs` (no `Grant`
    variant exists today — net-new).
- MCP: one metadata-only read tool `phantom_grant_status` in
  `crates/phantom-mcp/src/server.rs`.

### 1.1 How issuance relates to `RotationProvider`

```
                 ┌──────────────── ISSUANCE (new) ─────────────────┐
   human consent │ ConsentEngine::issue()                          │
   (browser/     │   → IssuedMaterial { phm-named Zeroizing roots } │
    device code) │   → RotationProviderConfig to write              │
                 └───────────────────────┬─────────────────────────┘
                                         │ CLI/MCP vaults roots under phm: names,
                                         │ writes [rotation_provider] block
                                         ▼
                 ┌──────────────── ROTATION (shipped) ─────────────┐
   zero human    │ auto_sync_rotation_with_bootstrap()             │
                 │   reads root from vault (env-then-vault)         │
                 │   mints short-lived successor, stores, revokes  │
                 └─────────────────────────────────────────────────┘
```

Issuance produces the **durable root** (GitHub App PEM + client_id/secret; OAuth
**refresh token**). Rotation renews the **disposable successor** (installation
`ghs_` token; access token) from that root. They compose via the
`rotation_provider` block — issuance is the writer, rotation is the reader.
Dispatch stays by provider **identity**, never secret-name heuristics (§3.4).

### 1.2 Core types (`issuance/mod.rs`)

```rust
/// The four grant shapes from docs/grants-spec.md. Issuance seeds #2/#3;
/// #1 (self-rotating) and #4 (manual) need no consent engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum GrantType { SelfRotating, AppIdentity, OauthRefresh, Manual }

/// One durable secret to be vaulted. `phm_name` is the phm: ref the vault
/// stores under; `value` is the root credential. NEVER Debug-printed in full.
pub struct IssuedMaterial {
    pub phm_name: String,                 // e.g. "GITHUB_APP_PEM"
    pub value: zeroize::Zeroizing<String>,
    pub kind: MaterialKind,               // Pem | ClientId | ClientSecret | RefreshToken | WebhookSecret
    pub sensitive: bool,                  // client_id=false; pem/secret/refresh=true
}

/// Result of a successful consent. Returned to the CLI/MCP layer, which does
/// ALL vault writes (core stays vault-free). Carries a redacting Debug.
pub struct IssuanceOutcome {
    pub provider: String,                 // "github-app", "supabase", ...
    pub grant_type: GrantType,
    pub materials: Vec<IssuedMaterial>,   // roots to vault under phm: names
    pub rotation_config: RotationProviderConfig, // [rotation_provider] block to write
    pub metadata: IssuanceMetadata,       // app id, installation ids, expiry — NON-secret, safe to print
}

/// Non-secret facts safe for stdout/--json (§4.3). No token bytes ever.
pub struct IssuanceMetadata {
    pub display_name: String,
    pub account: Option<String>,          // login/org, if known
    pub installation_ids: Vec<String>,    // GitHub App installs discovered
    pub scopes: Vec<String>,
    pub expires_at: Option<u64>,          // refresh-token lifetime, if any
    pub notes: Vec<String>,               // human next-steps (e.g. "click Install")
}

pub enum IssuanceError {
    ConsentTimeout { waited_secs: u64 },          // loopback/device never completed
    ConsentDenied,                                // access_denied
    BrowserUnavailable { fallback: &'static str },// headless → device-flow hint
    LoopbackBindFailed { reason: String },
    Exchange { status: u16, reason: String },     // reason via summarize_error_body
    Network { reason: String },
    UnexpectedResponse { reason: String },
    NotSupported { reason: String },              // provider has no automatable consent
    MockDisabled,                                 // fail-closed, mirrors rotation
}
```

`IssuanceOutcome` and `IssuedMaterial` implement **redacting `Debug`** exactly
like `AutoSyncOutcome`: `value` renders as `[redacted]`, and any `reason`
string that transits a vendor body is pre-passed through `summarize_error_body`.

### 1.3 The trait

```rust
pub trait ConsentEngine: Send + Sync {
    fn name(&self) -> &str;               // "loopback-pkce", "device-flow", "github-app-manifest"
    fn grant_type(&self) -> GrantType;

    /// Run the ONE human consent and return the durable root(s). Core performs
    /// no vault I/O. MUST NOT log/print any returned value; MUST zeroize every
    /// intermediate (code, code_verifier, client_secret) after the exchange.
    fn issue(&self, req: &IssuanceRequest, deps: &IssuanceDeps)
        -> Result<IssuanceOutcome, IssuanceError>;
}

/// Injected side-effects → makes core hermetically testable and cleanly
/// handles headless environments (fake browser / fake loopback in tests).
pub struct IssuanceDeps<'a> {
    pub browser: &'a dyn BrowserOpener,   // real impl in CLI (uses `open`)
    pub loopback: &'a dyn LoopbackListener,
    pub http: &'a reqwest::blocking::Client,
    pub endpoints: &'a Endpoints,         // prod URLs or test overrides
}

pub struct IssuanceRequest {
    pub provider: String,
    pub client_id: Option<String>,        // for pkce/device against an existing app
    pub client_secret_env: Option<String>,// resolved env-then-(caller-supplied), never on disk
    pub scopes: Vec<String>,
    pub flow: Option<FlowKind>,           // Pkce | Device (CLI --flow override)
    pub app_manifest: Option<GithubManifestSpec>, // github-app only
}
```

---

## 2. The two shared consent engines

Both live in core, both use `reqwest::blocking`, both return roots via
`IssuanceOutcome` — **the value never returns to the model**: the CLI vaults it,
the MCP surface never carries it.

### 2.1 `LoopbackPkceEngine` (RFC 8252 loopback + RFC 7636 S256)

`issuance/pkce.rs`. Grant type `OauthRefresh`. For providers whose consent is a
browser "Authorize" click (Supabase, Sentry, GitHub user-to-server).

```rust
pub struct LoopbackPkceEngine;
impl ConsentEngine for LoopbackPkceEngine { /* name="loopback-pkce" */ }
```

Sequence:
1. Generate PKCE: `code_verifier` = 43–128 chars base64url of 32 random bytes
   (`rand::thread_rng`, already a dep), held in `Zeroizing`.
   `code_challenge = BASE64URL_NOPAD(SHA256(code_verifier))` (`sha2` already a
   dep). **S256 only** — GitHub/Sentry reject `plain`.
2. `deps.loopback.bind()` → `LoopbackBinding { port, redirect_uri }` on
   **`127.0.0.1:0`** (ephemeral; RFC 8252 §7.3). Never `0.0.0.0`, never a public
   host. `redirect_uri = http://127.0.0.1:{port}/callback`.
3. Build authorize URL (`endpoints.authorize`) with `client_id`,
   `redirect_uri`, `state` (32 random bytes, base64url), `code_challenge`,
   `code_challenge_method=S256`, `scope`. `deps.browser.open(url)`.
4. Print exactly **one** line to stderr: the authorize URL (so a headless user
   can paste it). Nothing else.
5. `deps.loopback.wait(timeout)` blocks for the redirect, returns
   `(code: Zeroizing, returned_state)`. **Verify `returned_state == state`**
   (CSRF) → else `ConsentDenied`. Respond `200 text/plain "You may close this
   tab."` and close. Timeout (default 300 s) → `ConsentTimeout`.
6. Exchange `POST endpoints.token`
   (`grant_type=authorization_code`, `code`, `redirect_uri`, `client_id`,
   `code_verifier`, + `client_secret` if the provider requires one — resolved
   from `client_secret_env`, never written to disk). Non-2xx →
   `Exchange { status, reason: summarize_error_body(&body) }`.
7. Parse `refresh_token` (the durable root) + `access_token`/`expires_in`
   (metadata only). Return `IssuanceOutcome`:
   - `materials`: `[{ phm_name: "<PROVIDER>_REFRESH_TOKEN", value: refresh, kind: RefreshToken, sensitive: true }]`
     (+ client secret if the provider needs it stored for refresh).
   - `rotation_config`: `{ provider: "<provider>", api_key_env: "<PROVIDER>_REFRESH_TOKEN", enabled: true, .. }`.
   - `metadata.expires_at`: refresh-token lifetime if the vendor returns it.

Where the value lands: **vault**, under the `phm_name`, by the CLI/MCP caller
(§4.2). The engine returns it up the stack inside `Zeroizing`; it is never
logged, never in `--json`, never in an MCP response.

Headless handling: if `deps.browser` is the `NoBrowser` sentinel (CLI detected
`$DISPLAY`/`$SSH_CONNECTION`/`--no-browser`), the engine still binds loopback
and prints the URL to paste — **but** if loopback itself can't be reached from
the user's browser (truly remote box), the exchange will simply time out. The
CLI catches `ConsentTimeout`/`BrowserUnavailable` and **fails closed** with the
device-flow instruction: `retry with --flow device`. No silent degradation.

### 2.2 `DeviceFlowEngine` (RFC 8628)

`issuance/device.rs`. Grant type `OauthRefresh` (or `AppIdentity`-adjacent for
GitHub user tokens). The headless/no-browser path.

```rust
pub struct DeviceFlowEngine;
impl ConsentEngine for DeviceFlowEngine { /* name="device-flow" */ }
```

Sequence:
1. `POST endpoints.device_code` `{ client_id, scope }` →
   `{ device_code (Zeroizing), user_code, verification_uri, expires_in, interval }`.
2. Print exactly **two** non-secret facts (§4.3): the `verification_uri` and the
   `user_code`. Optionally `deps.browser.open(verification_uri_complete)` if the
   vendor supplies it and a browser exists — but the code is shown regardless.
3. Poll `POST endpoints.token`
   `{ client_id, device_code, grant_type: "urn:ietf:params:oauth:grant-type:device_code" }`
   every `interval` seconds. Honor RFC 8628 precisely:
   - `authorization_pending` → keep polling at current interval.
   - `slow_down` → **increase interval by 5 s** and continue.
   - `access_denied` → `ConsentDenied`. `expired_token` → `ConsentTimeout`.
   - 2xx → parse tokens.
   Cap total wait at `device_code.expires_in`; a monotonic clock, not a fixed
   loop count. `device_code` is `Zeroizing`, dropped after the terminal poll.
4. Return `IssuanceOutcome` identical in shape to the PKCE engine (refresh token
   is the root; access token is metadata). GitHub App device flow yields
   `ghu_` (8 h) + `ghr_` (6 mo, rotating) — the `ghr_` is the durable root.

No loopback, no redirect URI, no local listener — works on a truly headless box.
This is the fallback the CLI names when PKCE loopback is unreachable.

---

## 3. GitHub App bootstrap — `GithubAppManifestFlow`

`issuance/github_app.rs`. Grant type `AppIdentity`. This is the north-star path
(dossier `best_path`: "FOUR clicks, ever"). It is a *third* consent engine
(manifest flow is neither pure PKCE nor device), but it **reuses
`LoopbackListener`** for code capture.

```rust
pub struct GithubAppManifestFlow;
impl ConsentEngine for GithubAppManifestFlow { /* name="github-app-manifest" */ }
```

### 3.1 Build the manifest

`GithubManifestSpec` → serialized to the `manifest` JSON field:

```json
{
  "name": "phantom-<project>",
  "url": "https://phm.dev",
  "redirect_url": "http://127.0.0.1:{port}/callback",
  "public": false,
  "default_permissions": {
    "contents": "write",
    "pull_requests": "write",
    "issues": "write",
    "metadata": "read"
  },
  "default_events": []
}
```

Least-privilege by construction; `public:false` (private app). No webhook URL by
default (webhook_secret still returned and vaulted).

### 3.2 Browser POST + loopback capture

- `deps.loopback.bind()` first → gives the ephemeral `{port}` baked into
  `redirect_url` above.
- The consent is a **form POST** to
  `{endpoints.github_web}/settings/apps/new?state={state}` (or
  `/organizations/{org}/settings/apps/new` when creating under an org) with the
  `manifest` field. Since `deps.browser.open()` can only open a GET URL, the CLI
  emits a tiny **self-submitting HTML page** served by the *same loopback
  listener* on `GET /`:  the browser opens `http://127.0.0.1:{port}/`, which
  returns an auto-POSTing `<form method="post" action="github.com/...">`. (RFC
  8252 loopback doubles as the launch page — no external hosting, CSP-free,
  matches "self-contained" constraints.) The listener then also handles the
  redirect-back `GET /callback?code=...&state=...`.
- Human clicks **"Create GitHub App"** once. GitHub redirects to
  `redirect_url?code={TEMP_CODE}&state={state}`. Verify `state`. Capture
  `code` (`Zeroizing`). Code must be exchanged within 1 hour.

### 3.3 Exchange → durable root

- `POST {endpoints.github_api}/app-manifests/{code}/conversions` (unauthenticated).
- 201 body → `{ id, slug, client_id, client_secret, pem, webhook_secret, ... }`.
- Build `IssuanceOutcome`:
  - `materials` (all vaulted under `phm:` names by the caller):
    - `GITHUB_APP_PEM`  → `kind: Pem`, sensitive (the perpetual root).
    - `GITHUB_APP_CLIENT_SECRET` → sensitive.
    - `GITHUB_APP_WEBHOOK_SECRET` → sensitive.
    - `GITHUB_APP_CLIENT_ID` → non-sensitive (still vaulted for completeness).
  - `metadata`: `display_name`, app `id` (→ `notes`), `slug`, no secrets.
  - `rotation_config`: `{ provider: "github", api_key_env: "GITHUB_APP_JWT", account_id: <installation_id>, enabled: true }`
    — but see §3.4: `api_key_env` points at an **in-process minted** JWT, not a
    static vault entry.

### 3.4 Discover installations + wire to the shipped provider

- `GET {endpoints.github_api}/app/installations` authenticated with an App JWT
  minted **in-process from the just-issued PEM** (never printed, never vaulted,
  zeroized after the call). Populate `metadata.installation_ids`. If none, add a
  `notes` entry: "Install the app: {html_url}".
- **The wiring problem**: shipped `GitHubRotationProvider::initiate_rotation`
  expects `api_key_env` to resolve to a *ready* App JWT (10-min TTL). Issuance
  closes the grants-spec gap by adding a **bootstrap adapter**,
  `GithubAppJwtProvider`, that sits *below* the rotation call:

  ```rust
  /// Mints a fresh RS256 App JWT from the vaulted PEM immediately before each
  /// rotation, installs it as the thread-local bootstrap override, and zeroizes
  /// it after. iss = client_id, iat = now-60, exp = now+540 (<10 min).
  pub fn mint_app_jwt(pem: &Zeroizing<String>, client_id: &str)
      -> Result<Zeroizing<String>, IssuanceError>;
  ```

  Uses `jsonwebtoken = "9"` (`EncodingKey::from_rsa_pem`, `Algorithm::RS256`).
  The CLI/MCP rotation path, when `provider == "github"` **and** a
  `GITHUB_APP_PEM` grant exists, retrieves the PEM from the vault, calls
  `mint_app_jwt`, and feeds the JWT to `auto_sync_rotation_with_bootstrap` as
  the `bootstrap` argument (the existing env-then-vault-then-override chain).
  The JWT never becomes an env var, never hits disk, is zeroized on drop.
  Dispatch stays by identity — the PEM is only ever sent to GitHub.

Result: `phantom grant add github-app` (one consent) → PEM vaulted → every
`phantom rotate --name X --provider github` mints a 1-hour `ghs_` token forever,
unattended. Four human clicks total (create app + one install per account).

---

## 4. CLI surface

New `grant` command tree (`crates/phantom-cli/src/commands/grant/`). Mirrors
`docs/grants-spec.md §Command Surface`.

### 4.1 Commands

```bash
# GitHub App manifest bootstrap (the headline path)
phantom grant add github-app [--org <ORG>] [--name <APP_NAME>] [--no-browser] [--json]

# Generic OAuth-refresh grant against an existing app/client
phantom grant add <provider> --flow pkce|device \
    --client-id <ID> [--client-secret-env <ENV>] [--scope a,b,c] [--no-browser] [--json]

phantom grant list                 # provider, type, state, next renewal — NEVER values
phantom grant status [<provider>]  # chain health; --json; MCP-safe metadata
phantom grant revoke <provider>    # best-effort vendor revoke, then vault delete, audit
```

`grant add` flow (mirrors `rotate.rs:500-570` ordering):
1. Select engine: `github-app` → `GithubAppManifestFlow`; else `--flow` →
   `LoopbackPkceEngine` | `DeviceFlowEngine`. `--no-browser` (or auto-detected
   headless) forces device flow for generic providers; for `github-app` it
   prints the launch URL to paste (manifest needs a browser POST).
2. Build `IssuanceDeps` with the real `OpenCrateBrowser` (uses `open = "5"`,
   already a CLI dep) and `StdLoopbackListener`.
3. `engine.issue(&req, &deps)?` → `IssuanceOutcome`.
4. **Vault the roots** (the ONE place values are written; same path as
   `phantom add` / `rotate.rs:528`): for each `IssuedMaterial`,
   `vault.store(&m.phm_name, m.value.as_str())`.
5. **Write the `[phantom.secrets.<name>.rotation_provider]` block** into
   `.phantom.toml` from `outcome.rotation_config` (grants configure rotation;
   they never replace it).
6. Audit `grant.added` (name + provider + type only). Print metadata (§4.3).

### 4.2 Where the value goes — never the model

The root credential travels: vendor → `reqwest` response (in core) → `Zeroizing`
in `IssuanceOutcome.materials` → CLI `vault.store(...)` → encrypted vault
(keychain/file). It is **never** returned by `engine.issue` to anything but the
CLI/MCP store step, **never** printed, **never** in `--json`, **never** in an
MCP response. `.phantom.toml` gets only the `phm:` *name*, never the value
(exactly like `rotation_provider.api_key_env` today).

### 4.3 What `grant add` prints (metadata + the ONE consent artifact only)

Non-`--json` (human): a single consent artifact, then metadata.
- PKCE: one line — the authorize URL (to click/paste).
- Device: two lines — `verification_uri` and `user_code`.
- github-app: one line — the launch URL (`http://127.0.0.1:{port}/`).
- On success: `display_name`, app id, discovered `installation_ids`, scopes,
  next-step `notes` (e.g. "Install on ashlrai: {url}"). **No token bytes.**

`--json` emits only `IssuanceMetadata` + `{ "state": "active", "provider": ...,
"grant_type": ..., "vaulted": ["GITHUB_APP_PEM", "GITHUB_APP_CLIENT_ID", ...] }`
— names, never values. Same shape as `rotate.rs` `--json` (`stored_in_vault:
true`, no secret).

### 4.4 MCP surface

- Issuance is **not** an agent-callable tool. Consent is a human browser act;
  exposing "create a GitHub App" to an agent would violate the "identity
  resolved at the gate, not the prompt" principle. Agents may only *observe*.
- Add one read tool: `phantom_grant_status` → returns `IssuanceMetadata`-level
  JSON (`state ∈ active|expiring|broken|manual`, provider, next renewal, never
  values). Gated like other reads; no `require_approval_token` needed (read).
- The renewal half already flows through `phantom_rotate_provider`
  (`server.rs:551`), unchanged: once a grant is seeded, agents rotate under the
  existing `confirm:true` + `require_approval_token` gate, still metadata-only.

---

## 5. Test strategy

Matches the repo exactly: **`wiremock = "0.6"`** (async, already a phantom-cli
dev-dep) as the HTTP stub, `assert_cmd` for CLI e2e, and magic-prefix hermetic
mocks for pure-unit core tests. Core unit tests live in
`#[cfg(test)] mod tests` inside each `issuance/*.rs` (per CONTRIBUTING);
integration tests in `crates/phantom-cli/tests/grant_*.rs`.

### 5.1 Historical injection-seam proposal (superseded)

The environment-override proposal below is not an approved production pattern.
Current credential-bearing endpoint selection is closed in production. Tests
must use compiled test-only seams or explicitly injected clients that cannot
load real keychain or vault credentials.

`issuance/endpoints.rs`:

```rust
pub struct Endpoints { pub github_web, github_api, authorize, token, device_code: String }
impl Endpoints {
    /// Historical proposal only. Current production endpoint selection is
    /// closed and must not be redirected through agent-controlled env vars.
    pub fn for_provider(p: &str) -> Result<Self, IssuanceError>;
}
```

The design originally proposed localhost/HTTPS overrides such as `PHANTOM_GITHUB_API_BASE`,
`PHANTOM_GITHUB_WEB_BASE`, `PHANTOM_OAUTH_AUTHORIZE_BASE`,
`PHANTOM_OAUTH_TOKEN_BASE`, `PHANTOM_OAUTH_DEVICE_BASE`. Defaults:
`https://api.github.com`, `https://github.com`, vendor authorize/token URLs.
That runtime override pattern is superseded and must not be reintroduced.

### 5.2 Fake browser + fake loopback (deterministic, no real ports/tabs)

```rust
// tests: capture the URL instead of opening a tab
struct FakeBrowser { opened: Mutex<Vec<String>> }
impl BrowserOpener for FakeBrowser { fn open(&self, url:&str){ self.opened.lock().push(url.into()) } }

// tests: return a canned code+state instead of binding a socket
struct FakeLoopback { code: String, state_echo: bool }
impl LoopbackListener for FakeLoopback {
    fn bind(&self) -> LoopbackBinding { LoopbackBinding{ port: 0, redirect_uri: "http://127.0.0.1:0/callback".into() } }
    fn wait(&self, _t: Duration) -> Result<(Zeroizing<String>, String)> { Ok((self.code.clone().into(), captured_state)) }
}
```

- PKCE unit test: `LoopbackPkceEngine::issue` with `FakeBrowser` + `FakeLoopback`
  + wiremock token endpoint returning `{ "refresh_token": "test_refresh_MOCK", ... }`.
  Assert: authorize URL the FakeBrowser saw contains `code_challenge_method=S256`
  and a `state`; the exchange sent that exact `code_verifier`; the outcome's
  material `value` equals the mock refresh token; **`state` mismatch →
  `ConsentDenied`** (dedicated CSRF test).
- Device unit test: wiremock returns `authorization_pending` twice, then
  `slow_down`, then success; assert the poll interval increased by 5 s after
  `slow_down` and total polls honor `expires_in`. Use an injected clock or a
  tiny/zeroed interval so the test runs in ms.
- Manifest unit test: `FakeLoopback` yields the temp `code`; wiremock stubs
  `POST /app-manifests/{code}/conversions` → 201 `{ id, pem:"-----BEGIN...MOCK", client_id, client_secret:"MOCK", webhook_secret:"MOCK" }`
  and `GET /app/installations` → `[{id:"987"}]`. Assert `installation_ids==["987"]`
  and the four `phm_name`s are present with `sensitive` set correctly.

### 5.3 The load-bearing assertion — NO secret in any output

Mirror `rotate_provider_test.rs`: seed known mock values, run the real `phantom
grant add ...` binary via `assert_cmd` against wiremock (`PHANTOM_*_BASE`
overrides pointing at the mock server, `PHANTOM_ALLOW_MOCK_ISSUANCE=1`), then:

```rust
let stdout = String::from_utf8_lossy(&out.stdout);
let stderr = String::from_utf8_lossy(&out.stderr);
for needle in ["test_refresh_MOCK", "-----BEGIN", "client_secret_MOCK", "webhook_secret_MOCK"] {
    assert!(!stdout.contains(needle), "secret leaked to stdout");
    assert!(!stderr.contains(needle), "secret leaked to stderr");
}
// but the vault DID receive it:
assert!(vault_retrieve("GITHUB_APP_PEM").starts_with("-----BEGIN"));
```

Plus: `--json` output parses and contains only names (`vaulted: [...]`), never a
value; the written `.phantom.toml` contains the `[rotation_provider]` block and
**no** secret; `PHANTOM_ALLOW_MOCK_ISSUANCE` unset → mock prefixes fail closed
(`MockDisabled`), proving shipped binaries can't be tricked into a fake issuance.
A `Debug`-format test asserts `format!("{:?}", outcome)` renders `[redacted]`.

### 5.4 Fail-closed / headless tests

- `--no-browser` with the generic provider forces `DeviceFlowEngine` (assert the
  device endpoint was hit, not authorize/loopback).
- PKCE `ConsentTimeout` (FakeLoopback returns `Err(Timeout)`) → CLI exits
  non-zero with the exact "retry with --flow device" instruction; **no partial
  vault write** (assert `GITHUB_APP_PEM` absent afterward).
- Endpoint override rejects a non-localhost `http://` base (reuse the
  `is_acceptable_api_url` check) → hard error before any network I/O.

---

## 6. Security invariants (inherited, restated for issuance)

- **Values are keychain-only.** Roots go through the same `vault.store` path as
  `phantom add`; `.phantom.toml` holds only `phm:` names.
- **`Zeroizing` throughout.** `code_verifier`, `code`, `device_code`,
  `client_secret`, the in-process App JWT, and every `IssuedMaterial.value` are
  `Zeroizing`; the JWT is minted per-rotation and dropped immediately.
- **Redacting `Debug`** on `IssuanceOutcome`/`IssuedMaterial`; vendor bodies
  only ever surface through `summarize_error_body` (`type`/`code`/`status`).
- **Fail closed.** Headless-without-fallback, `state` mismatch, non-2xx
  exchange, missing PEM, unknown provider → hard error, no partial write, no
  guessing. Mock paths guarded by `cfg(test)`/`PHANTOM_ALLOW_MOCK_ISSUANCE=1`
  and audit-tagged `grant.issuance.mock`.
- **No silent demotion.** A broken grant reports `broken` and asks for one new
  consent; issuance never falls back to a weaker credential class.
- **Loopback is 127.0.0.1-only**, ephemeral port, single request, closes
  immediately (matches the proxy's "127.0.0.1 only" rule).
- **Everything audited** (names/metadata only): `grant.added`, `grant.renewed`,
  `grant.broken`, `grant.revoked`, `grant.issuance.mock`.

## 7. New dependencies

| Crate | Where | Why | Alternative considered |
|---|---|---|---|
| `jsonwebtoken = "9"` | `phantom-core` | RS256 App-JWT minting from the vaulted PEM (grants-spec commitment) | hand-rolled RS256 with `rsa`+`sha2`; rejected — `jsonwebtoken` is the audited standard and smaller surface than DIY |
| (dev) reuse `wiremock = "0.6"` | `phantom-cli` tests | HTTP stub — already the repo's mock | mockito; rejected — repo standardized on wiremock |
| (none) `open = "5"` | `phantom-cli` | browser launch — already present | webbrowser; rejected — `open` already a dep |
| (none) `std::net::TcpListener` | `phantom-core` | loopback capture — no new dep | tiny_http/hyper; rejected — one-request capture needs no framework |

No new async runtime in core (issuance stays `reqwest::blocking`, matching
`rotation_provider.rs`). wiremock's async server is driven by the test's own
`#[tokio::test]` or a `Runtime`, exactly as `cloud_test.rs` already does.
