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

- **OS keychain** (primary): macOS Keychain, Linux Secret Service, or Windows Credential Manager, depending on platform. The OS keychain gates access by the user's session credentials and, on macOS, by Secure Enclave on supported hardware.
- **Encrypted file vault** (fallback when no OS keychain is available): `~/.phantom/vaults/<project_id>.vault`. The file is encrypted with ChaCha20-Poly1305 keyed via Argon2id. Permissions are set to `0600` on Unix. See [§4](#4-cryptography-summary).
- **Phantom Cloud** (optional): Server stores only ciphertext. Encryption key is derived from a key in the OS keychain and never leaves the device.

**Sensitivity:** Highest. Compromise allows an attacker to impersonate the developer to third-party services.

### 1.2 The proxy session token (`PHANTOM_PROXY_TOKEN`)

A 32-byte (256-bit) CSPRNG value generated fresh each time `phantom exec` starts the local proxy. It is required in the `x-phantom-proxy-token` request header (or `phantom_token` query parameter) for every request to the proxy. Without it, the proxy returns HTTP 401.

**Sensitivity:** High during a session. Compromising it allows a local process to use the running proxy to obtain real secrets injected into outbound requests. The token is ephemeral — it disappears when the proxy process exits.

### 1.3 Team vault X25519 private keys

Each team member generates a long-lived X25519 keypair. The private key is stored in the OS keychain. The public key is published to the Phantom Cloud team record. When a team member pushes a vault, they encrypt a per-push symmetric key to each member's X25519 public key. Only holders of the matching private key can decrypt their share and recover the vault contents.

**Sensitivity:** High. Compromise allows decryption of any team vault push that included the member as a recipient.

### 1.4 The `.phantom.toml` configuration file

Contains project ID, service mappings (which upstream URLs map to which secret keys), vault backend preference, cloud sync settings, and team configuration. Does not contain secret values.

**Sensitivity:** Low for confidentiality; moderate for integrity. A tampered `.phantom.toml` could redirect the proxy to an attacker-controlled upstream, or remove service mappings causing secrets to stop being injected (denial of service).

### 1.5 The audit log

Stored at `~/.phantom/audit.log` when `PHANTOM_AUDIT=1`. Contains JSONL records of vault operations: timestamp, operation name, secret name (never value), process name, and PID.

**Sensitivity:** Low for confidentiality (names only, no values). Moderate for integrity — a tampered or deleted log undermines incident response.

### 1.6 The Phantom Cloud auth token

A GitHub OAuth token scoped to the user's GitHub identity, used to authenticate against the Phantom Cloud API. Stored in the OS keychain under the `phantom-secrets` service prefix.

**Sensitivity:** Moderate. Compromise allows an attacker to push a malicious encrypted vault blob to the cloud (overwriting legitimate data) or to pull the encrypted blob (though they cannot decrypt it without the vault encryption key, which is separate). It does not directly expose plaintext secrets.

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
- `.phantom.toml` to redirect service mappings to attacker-controlled upstream URLs.
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
| Real secret values | LLM calls `phantom_add_secret` with plaintext value | MCP tool unconditionally refuses any call that includes a value; returns error directing caller to `phantom_add_secret_interactive` | Covered | `crates/phantom-mcp/src/server.rs:227–240` |
| Real secret values | LLM calls destructive MCP tools without user consent | All mutating MCP tools require `confirm: true` parameter; tool description instructs the agent to ask the user first | Covered | `crates/phantom-mcp/src/server.rs` — `require_confirm()` called at every mutating entry point |
| Real secret values | Local process reads vault file | File vault encrypted with ChaCha20-Poly1305 + Argon2id (m=64 MiB); file permissions `0600`; attacker needs passphrase | Covered | `crates/phantom-vault/src/crypto.rs`, `crates/phantom-vault/src/file.rs:130` |
| Real secret values | Local process reads OS keychain entries | OS keychain access is gated by the session login. Secret names are stored as SHA-256 hashes (first 8 bytes, hex-encoded) so enumeration does not reveal which secrets are stored | Covered | `crates/phantom-vault/src/keychain.rs:12–18` (hashing); OS keychain access control is enforced by the platform |
| Real secret values | Proxy used without a session token to extract secrets | Proxy validates `x-phantom-proxy-token` header (or `phantom_token` query param) on every request using constant-time comparison; unauthenticated requests receive HTTP 401 | Covered | `crates/phantom-proxy/src/server.rs:208–231`, `server.rs:620–623` |
| Real secret values | Proxy token brute-forced via timing side-channel | Comparison uses `subtle::ConstantTimeEq`; length mismatch returns early (token length is not secret) | Covered | `crates/phantom-proxy/src/server.rs:620–623` |
| Real secret values | Secret injected into non-auth fields (prompt injection via body) | F9 scoping: for JSON bodies, token substitution is restricted to a whitelist of known-secret fields; tokens in `prompt`, `messages`, `content` fields are left as phantom tokens and not substituted | Covered | `crates/phantom-proxy/src/server.rs:444–456` and `body_scope.rs` |
| Real secret values | Secret injected into non-auth headers (e.g. User-Agent) | F9 scoping: header substitution restricted to auth-bearing headers and the per-route configured header | Covered | `crates/phantom-proxy/src/server.rs:282–319` |
| Real secret values | Secret leaked in upstream API response back to LLM | Response body (buffered and streaming) is scanned and secrets scrubbed before returning to the caller | Covered | `crates/phantom-proxy/src/server.rs:533–610` |
| Real secret values | Memory exposure after use | All secret values wrapped in `zeroize::Zeroizing<T>` which overwrites the heap buffer on drop | Covered | `crates/phantom-vault/src/file.rs:88,114`, `crates/phantom-vault/src/keychain.rs:155` |
| Real secret values | Body too large for safe buffering | Buffered path capped at 10 MB (`max_body_size`); exceeding returns HTTP 413 | Covered | `crates/phantom-proxy/src/server.rs:418–441` |
| Real secret values | Cloud server compromised — server reads plaintext | Vault is encrypted client-side before upload; server stores only ciphertext; encryption key never transmitted | Covered | `crates/phantom-mcp/src/server.rs:356–363` (cloud push encryption) |
| Real secret values | Supply-chain attack injects `.env` real secrets | `phantom check` (including `--staged`) scans for real secret patterns and warns before commit; `pre-commit` hook integration | Covered | `crates/phantom-cli/src/commands/check.rs` (invoked by `phantom check --staged`) |
| Proxy session token | Sniffed on localhost | Token is only ever transmitted over the loopback interface (127.0.0.1), which is not network-accessible | Covered | `crates/phantom-proxy/src/server.rs:66` — bind to `[127, 0, 0, 1]` only |
| Proxy session token | Leaked via process environment to child | The proxy token is set in the environment of the `phantom exec` child process as `PHANTOM_PROXY_TOKEN`; any subprocess spawned by that child can read it. This is intentional — the child needs it — but a compromised child process can use it | Partial — by design; mitigated by proxy's localhost-only binding and ephemeral token lifetime |
| Proxy session token | Token persists after session ends | Token is generated fresh on each `phantom exec` invocation and exists only in the running process's memory | Covered | `crates/phantom-proxy/src/server.rs:104–109` |
| Team X25519 private key | Exfiltration from OS keychain | Private key stored in OS keychain; access requires user session authentication same as all keychain secrets | Covered — same as real secret values in keychain |
| Team X25519 private key | Insider reads another member's private key | Each member's private key never leaves their machine; the team vault push protocol encrypts to public keys only | Covered | `crates/phantom-core/src/team_crypto.rs:109–138` — `seal_sym_key` uses recipient public key only |
| Team X25519 private key | Key revocation after member leaves team | No automated key-revocation or re-encryption flow exists. Removing a member from the team prevents future pushes encrypting to their key, but does not invalidate past pushes that included them | Not covered — see [§7](#7-known-gaps-and-non-mitigations) |
| `.phantom.toml` integrity | LLM or PR tampers with service mappings to redirect proxy | No cryptographic integrity protection on `.phantom.toml`. The file is checked into the repository and subject to standard code review. Tampering would require either direct file access or a merged malicious PR | Not covered — relies on code review and filesystem permissions |
| Audit log | Log tampered or deleted to cover tracks | The log is append-only by file-open mode (`O_APPEND`) but is not cryptographically chained. An attacker with file write access can truncate or overwrite it | Partial — O_APPEND prevents casual concurrent corruption; no HMAC chain — see [§7](#7-known-gaps-and-non-mitigations) |
| Audit log | Sensitive values written to log | The log schema has no `value` field; callers are typed to pass `name: Option<&str>` only; a compile-time assertion test verifies the serialized schema contains no `value` key | Covered | `crates/phantom-core/src/audit.rs:36`, test at line 237 |
| Cloud auth token | GitHub OAuth token stolen | Token stored in OS keychain; attacker with the token can call cloud API but cannot decrypt vault data (separate encryption key) | Partial — OS keychain protection; no second-factor for cloud API calls |
| Cloud auth token | Phishing for GitHub OAuth token | Out of scope — see [§6](#6-out-of-scope) |

---

## 4. Cryptography Summary

All primitives below are from audited Rust crates (`chacha20poly1305`, `argon2`, `crypto_box`, `subtle`).

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
| OS keychain | Access is gated by the user's login session. On macOS with Secure Enclave hardware, private keys are hardware-bound. Phantom inherits whatever guarantee the OS provides. |
| OS process model | UNIX process isolation: a process running as user A cannot read another user's memory or file descriptors without root. Phantom relies on this for vault file and proxy socket isolation. |
| The user's terminal for confirmation prompts | `phantom_add_secret_interactive` initiates a terminal prompt outside any AI agent context. The terminal is trusted; the MCP channel is not. |
| `rustls` system CA roots | Outbound TLS from the proxy uses `rustls` with system CA roots; no custom CA certificates are accepted, making a local CA injection attack ineffective. |

### What Phantom verifies

| Check | Mechanism |
|-------|-----------|
| MCP tool arguments never carry plaintext secrets | `phantom_add_secret` unconditionally rejects calls with a value parameter — `crates/phantom-mcp/src/server.rs:227–240` |
| Destructive MCP operations have user consent | `require_confirm()` gate on all mutating tools — `crates/phantom-mcp/src/server.rs` |
| Proxy requests are authenticated | `x-phantom-proxy-token` header checked via constant-time compare before any request is processed — `crates/phantom-proxy/src/server.rs:208–231` |
| Vault ciphertext integrity | ChaCha20-Poly1305 AEAD — decryption fails with an error if ciphertext has been tampered with |
| Team vault key registration before send | `seal_sym_key` requires the recipient's public key to be present before encrypting their share — `crates/phantom-core/src/team_crypto.rs:111` |

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

**Side-channel attacks on the OS keychain itself.**
Cache-timing, power analysis, or EM side-channels against the Secure Enclave or TPM are out of scope.

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

### 7.1 Audit log has no integrity protection

The audit log at `~/.phantom/audit.log` is append-only by file-open semantics (`O_APPEND`) but has no cryptographic chain. An attacker with write access to the user's home directory can truncate, modify, or delete the log without detection. An HMAC chain (each entry signing the previous entry's hash) is the planned mitigation. No issue number exists yet.

### 7.2 No proxy-layer rate limiting or anomaly detection

The proxy does not rate-limit requests or detect unusual access patterns (e.g., a process making thousands of requests per second, or requests for secrets outside the project's configured mappings). A rogue local process that obtains the session token could drain secrets at high speed. Mitigation would require per-secret access counts and configurable rate limits.

### 7.3 `.phantom.toml` has no integrity protection

There is no signature or hash commitment on `.phantom.toml`. A malicious PR that adds a service mapping redirecting `openai` → `http://attacker.example.com` would take effect silently on the next `phantom exec`. Mitigations include: code review (current), and a future signed-config mechanism.

### 7.4 Team key revocation requires manual re-encryption

Removing a team member from the team UI prevents future vault pushes from including their `KeyShare`. However, any team vault push that was made while they were a member remains decryptable by them if they retained their private key. There is no automated key-rotation flow that re-encrypts historical pushes excluding the removed member. Teams with strict offboarding requirements should rotate all secrets after removing a member.

### 7.5 Proxy session token exposed to child process environment

`phantom exec` injects `PHANTOM_PROXY_TOKEN` into the child process environment. Any subprocess spawned by the child process inherits this variable. A compromised child process can use the token to make proxy requests for the lifetime of the session. This is a known, unavoidable trade-off for the current architecture (the child needs the token to authenticate). The impact is bounded by the token's ephemeral lifetime and the proxy's localhost-only binding.

### 7.6 Streaming body path enforces size limit via drop, not 413

For streaming content types (`text/*`, `application/x-www-form-urlencoded`), if the body exceeds `max_body_size` the streaming task is dropped (channel closed), which surfaces to the upstream as a broken connection rather than a clean HTTP 413. A clean 413 for the streaming path is a planned improvement.

### 7.7 Audit log disabled by default

The audit log requires `PHANTOM_AUDIT=1` to be set. Teams that want audit trails must set this variable in their development environment. There is no mechanism to enforce this policy across a team. A future `phantom.toml` option to require audit logging is planned.

---

## 8. Reporting a Vulnerability

See [SECURITY.md](./SECURITY.md) for the responsible disclosure policy, contact information, and expected response timeline.

Do not open public GitHub issues for security vulnerabilities.
