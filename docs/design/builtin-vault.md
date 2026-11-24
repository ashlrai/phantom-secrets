# Phantom Secrets as Phantom's built-in vault

Status: design plus first building block (`secret://NAME` launcher references in `phantom exec`).
Owners: phantom-secrets side, Security Hardening Engineer. Phantom integration side, Phantom Core.
Facts were checked on 2026-11-24 against phantom-secrets `main` at `3c3e723` and phantom `master` at `97b01540`, and against the live Mac launcher (read only). Line numbers for `exec.rs` refer to this branch.

## 1. Goal and UX model

A secret is saved once by a human, agents hold only its name, and the value never reaches an agent, a transcript, a log, or a file the agent can read. The model is a consumer vault: the human types the value into a masked prompt the agent never sees, the agent is told only where the secret lives (a name), uses it by name, and the value is filled into the target directly.

For Phantom that means:

1. One save path, human only: `phantom add NAME` (hidden prompt) or a local UI that pipes into `phantom add NAME --stdin`.
2. One reference form: `secret://NAME`.
3. One resolution point: the trusted launcher calls `phantom exec`, which turns each reference into a session-scoped phantom token. The local proxy injects the real value into the matched provider route. The child never holds the value.
4. Names-only everywhere else: listing, metadata, audit, refusals.

## 2. Current state (phantom-secrets `main`)

| Area | What exists | Evidence |
|---|---|---|
| Save | `phantom add NAME` reads the value with a hidden prompt; `--stdin` reads a pipe; a positional value is rejected because argv is observable | `crates/phantom-cli/src/commands/add.rs:217`, `crates/phantom-cli/src/main.rs:330-333` |
| Agent save | MCP `phantom_add_secret` refuses plaintext; the interactive variant returns the terminal command for a human | `docs/design/model-blind-agent-secrets.md` section 2, `crates/phantom-mcp/src/server.rs:1302` |
| List | `phantom list [--json] [--env E]` prints names and value-free metadata (service, expiry, anomaly) | `crates/phantom-cli/src/commands/list.rs:106-148`, MCP `phantom_list_secrets` at `crates/phantom-mcp/src/server.rs:997` |
| Reveal | `phantom reveal` needs an attached terminal on stdin and stderr plus a typed confirmation, and writes an audit event first | `crates/phantom-cli/src/commands/reveal.rs:26,40,51` |
| Storage | OS keychain first; encrypted-file vault (Argon2id + ChaCha20-Poly1305) when `PHANTOM_VAULT_PASSPHRASE` is set or the keychain is unavailable; `PHANTOM_REQUIRE_KEYCHAIN=1` hard-fails instead | `crates/phantom-vault/src/lib.rs:41-99`, `crates/phantom-vault/src/crypto.rs:1-3,68-70` |
| Namespace | Vault namespace is derived from the project checkout; linked worktrees need `--bind-source` | `exec.rs:98-110`, phantom `src/core/run/phantom-custody.ts:44-50` |
| Use | `phantom exec` resolves dotenv `phm_` tokens, mints a fresh session token per secret, starts a loopback proxy, exports base-URL overrides, and spawns the child with protected names removed and session tokens set | `exec.rs:210-275`, `exec.rs:647-660` (env removal), `exec.rs:432-460` (spawn) |
| No raw env injection | Connection strings are refused: "direct environment injection is disabled" | `exec.rs:155-168` |
| Output scrub | `phantom exec --scrub-output` streams child stdout and stderr through `ResponseScrubber` built from the resolved values plus known shapes | `exec.rs:286`, `crates/phantom-proxy/src/response_scrubber.rs:263`, `main.rs:254-256` |
| Audit | Opt-in via `PHANTOM_AUDIT` (`1` best effort, `required` fail closed); events carry an op and a name only, in `~/.phantom/audit.log`; the file vault logs every store, retrieve and injection read | `crates/phantom-core/src/audit.rs:196-232,1709`, `crates/phantom-vault/src/file.rs:389-461` |
| Secret-shape gate | Required CI job `Secret-shape scan` runs a sha-pinned `scrub.pl --check --allow-fixtures` over the candidate diff | `.github/workflows/ci.yml:918-946` |
| Release | Release workflow requests artifact and SBOM attestations with SHA-pinned `actions/attest`; release-build runs gitleaks | `.github/workflows/release.yml:52-100`, `.github/workflows/release-build.yml:75-78` |

## 3. Current state (Phantom side, for Core)

| Where | What it does today | Evidence |
|---|---|---|
| Engine wrap | `phantomWrap` rewrites an engine command to `phantom exec -- <bin> <args>` when the project has `.phantom.toml` | phantom `src/core/run/engines.ts:367`, call at `:891`, probe at `:135-150` |
| Custody record | One value-free record per spawn: wrapped or a closed-list reason (self-authenticating engines `claude`, `codex` are never wrapped) | phantom `src/core/run/phantom-custody.ts:11-36` |
| Direct env reads | Some workers read keys straight from `process.env` | phantom `src/core/fabric/readers/devin-usage-worker.ts:8`, `src/core/run/provider-client.ts:1670`, `src/core/run/router.ts:132` |
| Mac launcher | `launch.sh` builds every lane env with `env -i` and an allowlist that passes only `PHANTOM_SESSION_KEYS` among Phantom names | `~/.ashlr-runs/bin/launch.sh:431` |
| claude-api lane | Detects `ANTHROPIC_API_KEY` with `phantom list --json`, then runs `phantom exec -- env -u CLAUDE_CODE_OAUTH_TOKEN ...`; fallbacks read mode-600 key files on fd 3 | `launch.sh:560-587` |
| Logs | Lane stdout and stderr pass through `scrub.pl` before touching disk | `launch.sh:431,587` |

## 4. Design

### 4.1 Reference scheme

`secret://NAME`, where NAME matches `[A-Za-z_][A-Za-z0-9_]*` and is at most 128 bytes (`crates/phantom-core/src/secret_ref.rs`). A string that starts with `secret://` but is malformed is an error, never a literal. A reference is not a secret and may appear in prompts, configs and logs.

### 4.2 Save path (humans only)

- Terminal: `phantom add NAME` (hidden prompt) or `phantom add NAME --stdin` from a pipe.
- Local UI (Core, later): a masked field in the Phantom desktop app that spawns `phantom add NAME --stdin` and writes the value to its stdin. The value never passes through an agent, an MCP tool argument, argv, or a log.
- Agents may only ask a human to save a name (MCP `phantom_add_secret_interactive`) or generate one in process (`--generate`, see `model-blind-agent-secrets.md` C1).

### 4.3 Agent-facing API (names, metadata, handles; never values)

- `phantom list --json` (exists): names plus value-free metadata.
- `phantom ref check --json secret://A ...` (proposed, PR 2): per reference `{"ref","name","status"}` with status `ok`, `missing`, `denied` or `invalid`. Reads names only.
- MCP mirrors of both (proposed). No tool, flag or mode returns a value to an agent. `phantom reveal` stays terminal-only and out of the agent API.

### 4.4 Resolution at exec (built in this PR)

The trusted launcher sets `NAME=secret://NAME` in the environment it passes to `phantom exec`. Exec then (`exec.rs:123-126,223-273,540-590`):

1. Collects every inherited variable whose value starts with `secret://`, before any vault access. Malformed values, a name that differs from the variable, and reserved `PHANTOM_*` variables stop the launch. Errors name the variable only.
2. Treats each referenced name exactly like a dotenv `phm_` key: it joins the protected set, so the connection-string refusal, command coverage check and rotation gate all apply.
3. Writes an `exec.secret_ref` audit event naming the secret before reading its value; with `PHANTOM_AUDIT=required` a failed write stops the launch.
4. Reads the value with `retrieve_for_injection` for the active environment, mints a fresh session token, and hands the value only to the in-process proxy and output scrubber.
5. Removes the inherited `secret://` assignment and sets `NAME=<session token>` in the child. The value is never in the child environment, argv, stdout, stderr or the audit log.

Raw value injection into the child environment is deliberately not offered (see section 7, question 1).

### 4.5 Output scrubbing and the secret-shape gate

- `--scrub-output` scrubs every resolved value and known credential shapes from child stdout and stderr. The launcher must pass it for agent lanes.
- The launcher keeps piping lane output through `scrub.pl` (the secret-shape gate) before anything reaches disk. Both layers stay; neither is weakened.
- Anything an agent writes for publication still passes the CI `Secret-shape scan` and `publish.sh` checks unchanged.

### 4.6 Audit

Per use, names only: `exec.secret_ref` plus the vault's `vault.retrieve_for_injection`. Agent lanes run with `PHANTOM_AUDIT=required` so an unwritable log fails closed. `phantom audit verify` checks the chain.

### 4.6a Serve only the references (`--refs-only`, built)

Without the flag, a session serves every protected dotenv name plus the references. The proxy authorizes a caller by `PHANTOM_PROXY_TOKEN` and injects by route, not by which session token the caller holds, so a child that was meant to use one name could still call the route of any other name the session loaded. It never sees those values, but it can use them.

With `phantom exec --refs-only`:

- Only names passed as `NAME=secret://NAME` are read from the vault. Dotenv phantom tokens are not loaded, and their keys are still removed from the child environment.
- The proxy registry keeps only routes whose credential was loaded. A request to any other route, including a routed dotenv name, is refused and nothing is injected.
- The child gets a session token, a base-URL override and a `PHANTOM_SESSION_KEYS` entry only for referenced names.
- The rotation gate checks only the referenced names.
- With no reference in the environment the launch is refused before the vault is opened.

Launchers that scope a child to a subset of names (for example `phm vault exec`) must pass `--refs-only`.

Follow-up, not built: bind each route to its session token, so the proxy also requires the caller to present the referenced name's session token and not only `PHANTOM_PROXY_TOKEN`. SDKs place the session token in provider-specific headers, so this needs per-route token extraction and its own tests.

### 4.7 Scope (proposed, PR 3)

Each lane gets an allowlist of names, set by the launcher from a root-owned or launcher-owned scope file the agent cannot write (for example `PHANTOM_REF_SCOPE=<path>`). A reference outside the scope is `denied` before any value read, audited as `exec.secret_ref_denied`. Cross-person access (Mason, Sco, Evan, Alex) goes through the separately reviewed grant model: a grant adds names to a scope, is revocable, and is never a copy of the value.

### 4.8 Revocation and rotation

Session tokens die when `phantom exec` exits (`exec.rs:481-483`). Removing a name from a scope stops new sessions at once. Rotation uses the existing `phantom rotate` and rotation gate; references do not change because they hold no value.

### 4.9 Failure modes (never leak)

| Case | Behavior |
|---|---|
| Malformed reference | Exit 1 before vault access; message names the variable and the rule |
| Name mismatch or reserved variable | Exit 1 before vault access; message names the variable |
| Missing secret | Exit 1; message names the key and environment only |
| Locked vault | Existing "Vault locked" refusal; no plaintext fallback |
| Connection-string secret | Existing refusal; protocol broker required |
| Audit unwritable (required mode) | Exit 1 before the value read |
| Denied scope (PR 3) | Exit 1 before the value read; audited by name |

### 4.10 Threat model

| Threat | Mitigation |
|---|---|
| Prompt injection asks the agent for a value | The agent never holds one; no agent API returns values; reveal is terminal-only |
| Child runs `env`, `printenv` or reads `/proc/self/environ` | Child sees only a session token that dies with the session and only works through the loopback proxy for its route |
| Child exfiltrates the session token | Token is session scoped and loopback bound; proxy requires `PHANTOM_PROXY_TOKEN` |
| Core dumps of the phantom process | Values are `Zeroizing`; Core should run lanes with core dumps disabled (`ulimit -c 0`) |
| Logs and transcripts | `--scrub-output`, `scrub.pl` on lane logs, names-only audit |
| CI | Fork PRs get no secrets; tests use synthetic values that match no credential shape |
| Agent forges a reference to an unscoped name | Today any vault name in the project namespace can be referenced; PR 3 scope closes this |
| Child uses a route of a name it was not given | `--refs-only` (section 4.6a): only referenced routes exist on the proxy |

## 5. Interface Core builds against (v1)

Stable from this PR:

1. Invocation: `NAME=secret://NAME ... phantom exec --refs-only --scrub-output -- <cmd> <args>`, run in a managed project directory (or with `--bind-source`).
2. Variable form: the variable name must equal the referenced name. Aliases are not supported in v1.
3. Child environment: `NAME=phm_<session token>`, base-URL overrides for routed names, `PHANTOM_PROXY_PORT`, `PHANTOM_PROXY_TOKEN`, `PHANTOM_SESSION_KEYS`. Never the value, never the `secret://` string.
4. Exit status: the child's status when it ran; 1 with a value-free stderr line when a reference is refused.
5. Audit: set `PHANTOM_AUDIT=required`; one `exec.secret_ref` event per referenced name per launch.
6. Listing: `phantom list --json` for names and metadata.

v1 limits: the project must already have a token-bearing managed dotenv (the existing "no unprotected direct launch" guard in `crates/phantom-core/src/managed_dotenv.rs:228-231` is unchanged), and a name is useful only if a proxy route serves it (unrouted names get a warning, `exec.rs:416-423`).

Planned (not yet built): `phantom ref check --json`, `PHANTOM_REF_SCOPE`, references counted as protection by the dotenv guard, a fleet-level vault namespace.

## 6. Migration

1. PR 1 (this): references in `phantom exec`.
2. PR 2: `phantom ref check --json` and MCP mirror; `ref` field in `list --json`.
3. PR 3: lane scope file and denied audit; link to grants.
4. Core: launcher sets references per lane instead of relying on dotenv tokens; workers that read `process.env` keys run under the launcher.
5. Mac launcher (`launch.sh`, sandbox profiles, `git-safe-env.sh`): frozen package to Security, adding the reference variables to the `env -i` allowlist and `--scrub-output`. Key-file fallbacks are retired lane by lane once the Phantom path is proven.

## 7. Open questions for Mason

1. Some tools need a raw value in their environment (non-HTTP CLIs, database clients). Keep the current rule (no raw env injection; broker or proxy only), or allow a per-name opt-in raw mode with mandatory scrub?
2. One fleet vault namespace for all lanes, or keep per-project namespaces with `--bind-source`?
3. Which secrets move first, and when do the mode-600 key-file fallbacks get retired?
