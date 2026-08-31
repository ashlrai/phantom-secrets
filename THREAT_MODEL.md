# Phantom Secrets — Threat Model

This document is for security engineers evaluating whether Phantom meets their team's security bar. It describes the assets Phantom protects, the threat actors it considers, the mitigations in place (with code citations), known gaps, and the cryptographic primitives used. It does not describe the product's feature set — see the README for that.

For responsible disclosure, see [SECURITY.md](./SECURITY.md).

---

## Table of Contents

1. [Asset Inventory](#1-asset-inventory)
2. [Threat Actors](#2-threat-actors)
3. [Mitigations by Asset and Threat](#3-mitigations-by-asset-and-threat)
4. [Cryptography Summary](#4-cryptography-summary)
5. [Trust Boundaries](#5-trust-boundaries)
6. [Out of Scope](#6-out-of-scope)
7. [Known Gaps and Non-Mitigations](#7-known-gaps-and-non-mitigations)
8. [Reporting a Vulnerability](#8-reporting-a-vulnerability)

---

## 1. Asset Inventory

### 1.1 Real secret values

The actual API keys, tokens, passwords, and database URLs that Phantom is asked to manage. These are the primary target of any attacker.

**Storage locations:**

- **OS keychain** (primary): macOS Keychain, Linux Secret Service, or Windows Credential Manager, depending on platform. Access control is supplied by the native credential store and the user's operating-system session. Phantom uses password/secret entries and does not claim Secure Enclave hardware binding.
- **Encrypted file vault** (fallback when no OS keychain is available): `~/.phantom/vaults/<project_id>.vault`. The file is encrypted with ChaCha20-Poly1305 keyed via Argon2id. Permissions are set to `0600` on Unix. See [§4](#4-cryptography-summary).
- **Phantom Cloud** (optional): Server stores only ciphertext. Encryption key is derived from a key in the OS keychain and never leaves the device.

**Sensitivity:** Highest. Compromise allows an attacker to impersonate the developer to third-party services.

### 1.2 The proxy session token (`PHANTOM_PROXY_TOKEN`)

A 32-byte (256-bit) CSPRNG value generated fresh each time `phantom exec` starts the local proxy. The proxy accepts it through the `x-phantom-proxy-token` request header. For generic SDK compatibility, `phantom exec` and `phantom start` include it in local `*_BASE_URL` values as `/_phantom/<token>/`; set `PHANTOM_PROXY_HEADER_AUTH_ONLY=1` to emit token-free URLs and require the header path.

**Sensitivity:** High during a session. Compromising it allows a local process to use the running proxy to obtain real secrets injected into outbound requests. The token is ephemeral — it disappears when the proxy process exits.

### 1.3 Team vault X25519 private keys

Each team member generates a long-lived X25519 keypair. The private key is stored in the OS keychain. The public key is published to the Phantom Cloud team record. When a team member pushes a vault, they encrypt a per-push symmetric key to each member's X25519 public key. Only holders of the matching private key can decrypt their share and recover the vault contents.

**Sensitivity:** High. Compromise allows decryption of any team vault push that included the member as a recipient.

### 1.4 The `.phantom.toml` configuration file

Contains project ID, service mappings (which upstream URLs map to which secret keys), vault backend preference, cloud sync settings, and team configuration. Does not contain secret values.

**Sensitivity:** Low for confidentiality; moderate for integrity. Agentic proxy
execution derives its local vault namespace from a domain-separated SHA-256
digest of the canonical config directory instead of the committed portable
project ID, and accepts only exact built-in service routes, so a tampered config
cannot feasibly select another vault or redirect credentials. The former
64-bit namespace is not opened automatically. Tampering can still cause denial
of service or alter non-route behavior, and the file has no cryptographic
signature.

### 1.5 The audit log

Stored at `~/.phantom/audit.log` when `PHANTOM_AUDIT=1`. Contains JSONL records of vault operations: monotonic sequence number, timestamp, operation name, secret name (never value), process name, and PID. Signed entries include an HMAC-SHA256 chain over the previous entry hash.

**Sensitivity:** Low for confidentiality (names only, no values). Moderate for integrity — a tampered or deleted log undermines incident response.

### 1.6 The Phantom Cloud auth token

A GitHub OAuth token scoped to the user's GitHub identity, used to authenticate against the Phantom Cloud API. Stored in the OS keychain under the `phantom-secrets` service prefix.

**Sensitivity:** Moderate. Compromise allows an attacker to push a malicious encrypted vault blob to the cloud (overwriting legitimate data) or to pull the encrypted blob (though they cannot decrypt it without the vault encryption key, which is separate). It does not directly expose plaintext secrets.

### 1.7 Provider issuance credentials and metadata

`phantom grant add` can receive credential roots from a provider after a human
consent flow. Roots are transient secret values returned to the CLI in
zeroizing containers and written directly to the vault. `.phantom.toml` stores
provider, expiry, and renewal configuration, not the issued value. Provider
client secrets are resolved through a named environment variable and are not
accepted as command-line values.

**Sensitivity:** Issued roots and provider client secrets are highest
sensitivity. Provider-grant names, provider types, expiry, and state are
value-free metadata but remain integrity-sensitive.

---

## 2. Threat Actors

### 2.1 Malicious LLM context (prompt injection, malicious MCP servers)

An AI coding agent operating in the developer's environment is given or constructs a malicious prompt that attempts to exfiltrate secrets. This includes:

- Prompt injection via user-supplied content that instructs the agent to call `phantom_add_secret` with a value parameter.
- A malicious or compromised MCP server that impersonates Phantom tools and attempts to harvest values passed to it.
- An AI agent that reads `.env` and finds only phantom tokens, then attempts to resolve them by calling the proxy directly.

This is the **primary threat actor** Phantom was designed to address.

### 2.2 Local process with non-root access (same user)

Another process running under the same OS user account that:

- Reads files accessible to the user (`.env`, `.phantom.toml`, vault files).
- Connects to the localhost proxy port.
- Enumerates keychain entries to discover secret names.

This actor represents rogue software (malware, a compromised npm dependency, a malicious VSCode extension) running with the same effective UID.

### 2.3 Local attacker with root / admin access

A process or person with root access to the developer's machine. **This is explicitly out of scope** — see [§6](#6-out-of-scope). Any local secret manager is defeated by root access.

### 2.4 Remote attacker against Phantom Cloud

An external attacker who:

- Compromises the Phantom Cloud backend (server-side breach).
- Intercepts network traffic between the client and the cloud API.
- Steals the user's GitHub OAuth token and calls cloud API endpoints.

### 2.5 Compromised package / supply-chain attacker

A malicious or backdoored dependency in the project's software supply chain (npm package, Rust crate, system tool) that executes code in the developer's environment. Treated similarly to Threat Actor 2.2 from a capability standpoint.

### 2.6 AI tool publishing malicious PR templates or config files

An AI-generated or attacker-controlled pull request that adds or modifies:

- `.env` files to introduce real secrets (instead of phantom tokens).
- `.phantom.toml` to attempt cross-project vault selection or credential routing; current agentic execution ignores the committed portable project ID for local state and rejects any non-built-in or altered proxy route.
- GitHub Actions workflows or other CI config to capture secrets at runtime.

This actor has write access to the repository contents but not to the developer's local machine or vault.

### 2.7 Insider attacker on a team

A current or former team member who has a valid registered X25519 public key and legitimate access to the team vault. This actor can pull any team vault push that includes their key as a recipient. The threat is key retention after offboarding — a removed member whose key was included in a past push can still decrypt that push's ciphertext if they retained the private key.

---

## 3. Mitigations by Asset and Threat

The table below is the primary reference. A mitigation is marked **covered** only when there is a code path implementing it. **Partial** means the mechanism exists but has documented limitations. **Not covered** means no mitigation is in place today.

| Asset | Threat | Mitigation | Status | Code reference |
|-------|--------|-----------|--------|---------------|
| Real secret values | LLM reads `.env` | `.env` contains only phantom tokens (`phm_` + 64 hex chars); real values never written to `.env` | Covered | `crates/phantom-core/src/dotenv.rs` — token substitution on `phantom init` / `phantom sync` |
| Real secret values | LLM calls `phantom_add_secret` with plaintext value | MCP tool unconditionally refuses any call that includes a value; returns error directing caller to `phantom_add_secret_interactive` | Covered | `crates/phantom-mcp/src/server.rs`, add-secret schema and refusal tests |
| Real secret values | LLM calls destructive MCP tools without user consent | All mutating MCP tools require `confirm: true` parameter; tool description instructs the agent to ask the user first | Covered | `crates/phantom-mcp/src/server.rs` — `require_confirm()` called at every mutating entry point |
| Real secret values | Local process reads vault file | File vault encrypted with ChaCha20-Poly1305 + Argon2id (m=64 MiB); file permissions `0600`; attacker needs passphrase | Covered | `crates/phantom-vault/src/crypto.rs`, `crates/phantom-vault/src/file.rs` |
| Real secret values | Local process reads OS keychain entries | Secret names are stored as SHA-256-derived identifiers (first 8 bytes, hex-encoded), reducing metadata disclosure during enumeration. Value access is governed by the native credential store and its session/application policy; a hostile same-user process may share that authority on some platforms | Partial — native policy, not a Phantom sandbox | `crates/phantom-vault/src/keychain.rs` (name hashing and native `keyring` entries) |
| Real secret values | Proxy used without a session token to extract secrets | Proxy validates the session token on every request using constant-time comparison; unauthenticated requests receive HTTP 401. CLI-generated URLs use a local `/_phantom/<token>/` path segment for SDK compatibility unless `PHANTOM_PROXY_HEADER_AUTH_ONLY=1` is set. | Covered | `crates/phantom-proxy/src/server.rs`, proxy auth regression tests |
| Real secret values | Proxy token brute-forced via timing side-channel | Comparison uses `subtle::ConstantTimeEq`; length mismatch returns early (token length is not secret) | Covered | `crates/phantom-proxy/src/server.rs`, proxy authentication tests |
| Real secret values | Secret injected into non-auth fields (prompt injection via body) | F9 scoping: for JSON bodies, token substitution is restricted to a whitelist of known-secret fields; tokens in `prompt`, `messages`, `content` fields are left as phantom tokens and not substituted | Covered | `crates/phantom-proxy/src/server.rs`, `body_scope.rs`, field-scope tests |
| Real secret values | Secret injected into non-auth headers (e.g. User-Agent) | F9 scoping: header substitution restricted to auth-bearing headers and the per-route configured header | Covered | `crates/phantom-proxy/src/server.rs`, header-scope tests |
| Real secret values | Secret leaked in upstream API response back to LLM | Response headers plus buffered and streaming bodies are scanned; configured values and recognized credential formats are redacted before forwarding | Covered for supported proxy paths | `crates/phantom-proxy/src/server.rs`, response leak/scrubber tests |
| Real secret values | Memory exposure after use | Major vault retrieval, serialization, and decrypted-file buffers use `Zeroizing`; some proxy lookup copies and the file-vault passphrase remain ordinary strings | Partial — defense in depth remains | `crates/phantom-vault/src/file.rs`, `crates/phantom-vault/src/traits.rs`, `crates/phantom-proxy/src/interceptor.rs` |
| Real secret values | Body too large for safe buffering | Every request body is completely accepted under a hard byte cap before any upstream request starts; buffered upstream responses use the same cap and streaming responses remain memory-bounded | Covered for supported paths | `crates/phantom-proxy/src/server.rs`, oversized request/response and zero-upstream-call tests |
| Real secret values | Cloud server compromised — server reads plaintext | Vault is encrypted client-side before upload; server stores only ciphertext; encryption key never transmitted | Covered | `crates/phantom-core/src/cloud.rs`, `crates/phantom-vault/src/crypto.rs` |
| Real secret values | Supply-chain attack injects `.env` real secrets | `phantom check` (including `--staged`) scans for real secret patterns and warns before commit; `pre-commit` hook integration | Covered | `crates/phantom-cli/src/commands/check.rs` (invoked by `phantom check --staged`) |
| Provider issuance roots | Agent attempts to invoke consent or receive a root through MCP | Provider issuance is exposed through the trusted-terminal `phantom grant` CLI, not an MCP tool; output is metadata-only | Covered for the repository interface | `crates/phantom-cli/src/commands/grant/add.rs`, `crates/phantom-mcp/src/server.rs` |
| Provider issuance roots | CLI leaks an issued root in output | The issuance engine returns zeroizing roots to the CLI, which writes them to the vault; successful human and JSON output contain lifecycle metadata and `value_printed: false` rather than values | Covered | `crates/phantom-core/src/issuance/mod.rs`, `crates/phantom-cli/src/commands/grant/add.rs` |
| Provider consent | Attacker redirects OAuth/device flow to an arbitrary endpoint | Production provider endpoints are selected from a closed compile-time allowlist rather than accepted from CLI input | Covered for endpoint selection | `crates/phantom-core/src/issuance/endpoints.rs` |
| Provider-grant lifecycle | User assumes local deletion remotely revokes a provider credential | `phantom grant revoke` fails closed before local mutation because remote revocation is not wired | Partial — credential must be revoked at the provider | `crates/phantom-cli/src/commands/grant/revoke.rs` |
| Proxy session token | Sniffed on localhost | Token is only ever transmitted over the loopback interface (127.0.0.1), which is not network-accessible | Covered | `crates/phantom-proxy/src/server.rs:66` — bind to `[127, 0, 0, 1]` only |
| Proxy session token | Leaked via process environment to child | The proxy token is set in the environment of the `phantom exec` child process as `PHANTOM_PROXY_TOKEN`; any subprocess spawned by that child can read it. This is intentional — the child needs it — but a compromised child process can use it | Partial — by design; mitigated by proxy's localhost-only binding and ephemeral token lifetime |
| Proxy session token | Token persists after session ends | Token is generated fresh on each `phantom exec` invocation and exists only in the running process's memory | Covered | `crates/phantom-proxy/src/server.rs:104–109` |
| Team X25519 private key | Exfiltration from OS keychain | Private key is stored in the native credential store, whose protection depends on platform and session/application policy | Partial — same native-policy limit as real secret values in the credential store |
| Team X25519 private key | Insider reads another member's private key | Each member's private key never leaves their machine; the team vault push protocol encrypts to public keys only | Covered | `crates/phantom-core/src/team_crypto.rs:109–138` — `seal_sym_key` uses recipient public key only |
| Team X25519 private key | Key revocation after member leaves team | No automated key-revocation or re-encryption flow exists. Removing a member from the team prevents future pushes encrypting to their key, but does not invalidate past pushes that included them | Not covered — see [§7](#7-known-gaps-and-non-mitigations) |
| `.phantom.toml` integrity | LLM or PR tampers with vault selector or service mappings | The local namespace is a domain-separated SHA-256 digest of the canonical directory, independently of the committed portable project ID, and agentic execution accepts only exact built-in route definitions. The former collision-selectable namespace is not reopened automatically. The file is still unsigned, so other tampering can fail the session or alter non-route settings | Covered for practical cross-vault selection and credential redirection; partial overall | `crates/phantom-core/src/config.rs`, CLI config-boundary tests |
| Audit log | Log tampered or deleted to cover tracks | Signed entries use an HMAC-SHA256 chain, monotonic sequence numbers, and a signed `audit-head.json` checkpoint. `phantom audit verify` fails on malformed lines, modified entries, inserted entries, sequence gaps, missing head checkpoints, and log tail/head mismatches. Deleting both log and checkpoint still requires external evidence | Partial — see [§7](#7-known-gaps-and-non-mitigations) |
| Audit log | Sensitive values written to log | The log schema has no `value` field; callers are typed to pass `name: Option<&str>` only; a compile-time assertion test verifies the serialized schema contains no `value` key | Covered | `crates/phantom-core/src/audit.rs:36`, test at line 237 |
| Cloud auth token | GitHub OAuth token stolen | Token stored in OS keychain; attacker with the token can call cloud API but cannot decrypt vault data (separate encryption key) | Partial — OS keychain protection; no second-factor for cloud API calls |
| Cloud auth token | Phishing for GitHub OAuth token | Out of scope — see [§6](#6-out-of-scope) |

---

## 4. Cryptography Summary

The implementations below use Rust crates including `chacha20poly1305`, `argon2`, `crypto_box`, and `subtle`. Dependency use is not itself evidence of an independent audit of Phantom's composition.

### 4.1 File vault encryption

**Algorithm:** ChaCha20-Poly1305 (IETF variant, 96-bit nonce)

**Key derivation:** Argon2id with parameters selected per OWASP "balanced" recommendation (2024):
- Memory: 64 MiB (`m = 65536 KiB`)
- Iterations: 3 (`t = 3`)
- Parallelism: 1 lane (`p = 1`)
- Output length: 32 bytes

**Wire format:** `salt (32 bytes) || nonce (12 bytes) || ciphertext`

Both salt and nonce are generated fresh per encryption via `rand::thread_rng().fill_bytes()`. The AEAD tag is appended to the ciphertext by the `chacha20poly1305` crate. Decryption failure is detected by the AEAD tag verification and returns an error — no partial plaintext is ever returned.

A legacy fallback path exists for vaults encrypted under earlier Phantom releases (which used `Argon2::default()` parameters: m≈19 MiB, t=2). When the hardened-parameter decryption fails, the legacy parameters are tried automatically. New encryptions always use the hardened parameters.

**Code:** `crates/phantom-vault/src/crypto.rs`

### 4.2 Team vault envelope encryption

Each team vault push uses a two-layer scheme:

**Layer 1 — Vault encryption:** A fresh 32-byte symmetric key is generated per push (`OsRng`). The vault plaintext is encrypted with this key using ChaCha20-Poly1305.

**Layer 2 — Key encapsulation per recipient:** For each team member with a registered public key, an ephemeral X25519 keypair is generated. The X25519 DH output (ephemeral secret × recipient public) is used as the key for a `ChaChaBox` (XChaCha20-Poly1305 with 24-byte nonce) that encrypts the 32-byte symmetric key. The ephemeral public key, nonce, and ciphertext are stored as the member's `KeyShare`.

**Forward secrecy property:** Ephemeral sender keys are never reused between pushes. Tests verify that two seals of the same payload produce different ephemeral pubkeys and nonces (`crates/phantom-core/src/team_crypto.rs:212–223`).

**Isolation property:** A `KeyShare` encrypted to member B cannot be decrypted by member A — verified in tests at `crates/phantom-core/src/team_crypto.rs:200–209`.

**Code:** `crates/phantom-core/src/team_crypto.rs`

### 4.3 Phantom tokens

**Format:** `phm_` prefix + 64 lowercase hex characters (32 bytes = 256 bits of randomness)

**Generation:** `rand::thread_rng().fill_bytes()` — the `rand` crate uses the OS CSPRNG (getrandom) seeded on first use.

**Properties:**
- 256-bit keyspace makes brute-force infeasible.
- Tokens are opaque references — they carry no HMAC or signature. This is intentional: they are not authenticators, they are placeholders. The proxy's session token (`PHANTOM_PROXY_TOKEN`) is the authenticator.
- Tokens can be rotated (`phantom rotate`) to invalidate any that have leaked into logs or LLM context.

**Code:** `crates/phantom-core/src/token.rs:5–22`

### 4.4 Proxy session token

**Format:** 64 lowercase hex characters (32 bytes = 256 bits of randomness)

**Generation:** `rand::thread_rng().fill_bytes()` — fresh per proxy session.

**Comparison:** `subtle::ConstantTimeEq` — constant-time byte comparison to prevent timing side-channel attacks from a colocated local process.

**Code:** `crates/phantom-proxy/src/server.rs:104–109` (generation), `server.rs:620–623` (comparison)

### 4.5 Keychain secret name obfuscation

Secret names stored in the OS keychain use a SHA-256 derived identifier (first 8 bytes = 16 hex chars) as both the service key and account field. This prevents processes that enumerate keychain entries from learning which secret names are stored for a project.

**Code:** `crates/phantom-vault/src/keychain.rs:12–18`

---

## 5. Trust Boundaries

### What Phantom trusts

| Component | Why trusted |
|-----------|-------------|
| OS keychain | Access control is supplied by macOS Keychain, Linux Secret Service, or Windows Credential Manager and depends on platform and session policy. Phantom does not configure or claim hardware-bound storage. |
| OS process model | The platform's user and process isolation restricts cross-user access to files, process memory, handles, and descriptors. Same-user processes remain in the threat model, and root/administrator compromise is out of scope. |
| The user's terminal for confirmation prompts | `phantom_add_secret_interactive` initiates a terminal prompt outside any AI agent context. The terminal is trusted; the MCP channel is not. |
| The user's terminal and provider consent page for issuance | Provider grants require a human to complete a provider flow. This boundary does not make the resulting credential an execution authority grant. |
| `rustls` system CA roots | Outbound TLS from the proxy uses `rustls` with system CA roots; no custom CA certificates are accepted, making a local CA injection attack ineffective. |

### What Phantom verifies

| Check | Mechanism |
|-------|-----------|
| MCP tool arguments never carry plaintext secrets | `phantom_add_secret` unconditionally rejects calls with a value parameter — `crates/phantom-mcp/src/server.rs:227–240` |
| Destructive MCP operations have user consent | `require_confirm()` gate on all mutating tools — `crates/phantom-mcp/src/server.rs` |
| Proxy requests are authenticated | Session token checked via constant-time compare before any request is processed; CLI-generated URLs use `/_phantom/<token>/` for SDK compatibility, while `PHANTOM_PROXY_HEADER_AUTH_ONLY=1` requires `x-phantom-proxy-token` — `crates/phantom-proxy/src/server.rs` |
| Vault ciphertext integrity | ChaCha20-Poly1305 AEAD — decryption fails with an error if ciphertext has been tampered with |
| Team vault key registration before send | `seal_sym_key` requires the recipient's public key to be present before encrypting their share — `crates/phantom-core/src/team_crypto.rs:111` |
| Provider endpoint identity | Issuance selects an endpoint set from the closed production provider map rather than accepting an arbitrary authorization or token URL — `crates/phantom-core/src/issuance/endpoints.rs` |

### What Phantom does NOT trust

| Source | Rationale |
|--------|-----------|
| Any value passed through the MCP channel | MCP arguments are reachable by LLM context and by any process that can speak MCP. Treated as adversarial. |
| Contents of `.env` (for security decisions) | The `.env` file may be committed, synced, or readable by other processes. Only phantom tokens should ever appear there. |
| Upstream API responses (for absence of secrets) | The proxy scrubs real secrets from upstream responses before returning them to the caller, on the assumption that a response might echo back a value that was injected into the request. |

---

## 6. Out of Scope

The following are explicitly not addressed by Phantom's design. Documenting them here sets accurate expectations.

**Local attacker with root / admin access.**
A process or user with root privileges can read the OS keychain, inspect process memory, attach a debugger, or replace the `phantom` binary. No local secret manager can defend against this. If your threat model includes malicious insiders with admin access to developer machines, a hardware security key or remote secrets service (Vault, AWS Secrets Manager) is more appropriate.

**Side-channel attacks on the native credential store itself.**
Cache-timing, power analysis, or EM side-channels against operating-system credential-store implementations or underlying hardware are out of scope.

**Quantum-capable attackers.**
X25519 is not post-quantum safe. A cryptographically relevant quantum computer could break the team vault key encapsulation scheme. This is a future upgrade path; classical X25519 is appropriate for current threat landscapes.

**Phishing for the user's GitHub OAuth token.**
Phantom Cloud authentication uses GitHub OAuth. If an attacker tricks the user into authorizing a malicious OAuth app, the resulting token could be used to call Phantom Cloud APIs. Phantom has no control over GitHub's OAuth flow.

**Hardware-level attacks.**
RowHammer, cold-boot attacks against DRAM, or DMA attacks via malicious peripherals are out of scope.

**Malicious `phantom` binary.**
If the `phantom` binary itself has been replaced or backdoored, all guarantees are void. Users should verify release checksums and install from trusted sources. Phantom does not currently publish signed release binaries with hardware-backed signing; this is a roadmap item.

**AI training data exposure.**
If an LLM provider incorporates conversation content into training data, phantom tokens that appeared in prompts could propagate. However, phantom tokens are worthless without the local proxy — the real secret is never in the conversation.

---

## 7. Known Gaps and Non-Mitigations

These are security properties that are not yet implemented. They are documented here to be honest with evaluators and to set roadmap expectations.

### 7.1 Audit log rollback still requires out-of-band evidence

The audit log at `~/.phantom/audit.log` is append-only by file-open semantics
(`O_APPEND`), signed entries use an HMAC chain with monotonic sequence numbers,
and the authenticated head is retained separately. `phantom audit verify` detects
malformed JSON, modified or inserted entries, prefix and tail truncation, marker
removal, and whole-log deletion or replacement while that head remains intact.
An attacker who can delete or roll back both the log and the machine-local head
can still erase evidence without an external checkpoint or backup of the
expected head.

### 7.2 Proxy limits are not identity- or secret-aware anomaly controls

The proxy enforces aggregate rate, concurrency, byte, idle, and total-time limits,
but those controls are not a per-identity or per-secret behavioral policy. A rogue
local process that obtains the session token can use any configured mapping within
the session limits. Stronger mitigation requires identity-bound authority grants and
per-secret/use accounting at the authority boundary.

### 7.3 `.phantom.toml` has no integrity protection

There is no signature or hash commitment on `.phantom.toml`. Agentic execution
therefore derives the machine-local vault, shadow, and scheduler namespace from
a domain-separated SHA-256 digest of the canonical directory containing the
config; the committed `project_id` is a portable cloud/team identity and cannot
select local state. The former 64-bit namespace is not used as a compatibility
fallback. Agentic execution
also rejects any custom or altered proxy route instead of trusting repository
state with a credential destination. A malicious change can still deny service
or alter unrelated settings. Supporting custom gateways safely requires a
future value-blind, machine-local trusted-terminal approval record; code review
remains required for all other config changes.

### 7.4 Atomic team offboarding is unavailable

The current server has no atomic membership-removal and vault-key-rotation route.
The CLI `team revoke` operation therefore fails closed. Existing versions already
received by a member remain decryptable if the member retained their private key.
Strict offboarding requires an external administrative workflow and rotation of
the underlying provider credentials until the server transaction is implemented
and accepted end to end.

### 7.5 Proxy session token exposed to child process environment

`phantom exec` injects `PHANTOM_PROXY_TOKEN` into the child process environment. Any subprocess spawned by the child process inherits this variable. A compromised child process can use the token to make proxy requests for the lifetime of the session. This is a known, unavoidable trade-off for the current architecture (the child needs the token to authenticate). The impact is bounded by the token's ephemeral lifetime and the proxy's localhost-only binding.

### 7.6 Request-body handling is path-specific and bounded

JSON and other buffered proxy paths collect input under byte and time limits
before scoped substitution; oversized input receives a bounded failure. Supported
`text/*` and form bodies use incremental token replacement with a bounded carry
window so uploads are not fully buffered. Both paths remain content-type scoped
and belong in performance and capacity planning.

### 7.7 Plaintext reveal needs OS-backed user presence

Plaintext JSON export is disabled and reveal has no noninteractive bypass. Reveal
requires attached terminals plus an exact typed phrase, but a hostile same-user
process may be able to emulate a terminal. Phantom does not yet bind reveal to an
OS-backed biometric/user-presence or separate operator authorization primitive.

### 7.8 Audit log disabled by default

The audit log requires `PHANTOM_AUDIT=1` to be set. Teams that want audit trails must set this variable in their development environment. There is no mechanism to enforce this policy across a team. A future `phantom.toml` option to require audit logging is planned.

### 7.9 Provider issuance requires external acceptance and revocation

Provider-grant source and mock tests do not prove that a live provider
application is configured, a consent screen is correct, a remote credential was
accepted, renewal works, or a customer workflow passed. Those require separate,
authorized acceptance with throwaway accounts. Remote revocation is not wired;
`phantom grant revoke` fails closed before changing local state.

In this document, a **provider grant** is vaulted credential and renewal state.
It is not an **authority grant** from the inactive execution kernel and cannot
be used as a Locus credential, broker lease, or execution permit.

---

## 8. Reporting a Vulnerability

See [SECURITY.md](./SECURITY.md) for the responsible disclosure policy, contact information, and expected response timeline.

Do not open public GitHub issues for security vulnerabilities.
