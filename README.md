<div align="center">

<img src="https://phm.dev/og-image.png" alt="Phantom — Delegate supported API work to AI" width="720" />

<h1>Phantom</h1>

**Delegate more to AI without putting real keys in agent context.**

Phantom replaces project secrets with scoped `phm_` placeholders. Applications use those placeholders through an authenticated local proxy, while agents use value-blind MCP tools for inventory, diagnostics, and governed requests.

[![GitHub stars](https://img.shields.io/github/stars/ashlrai/phantom-secrets?style=for-the-badge&logo=github&color=blue&labelColor=0b0b14)](https://github.com/ashlrai/phantom-secrets/stargazers)
[![CI](https://img.shields.io/github/actions/workflow/status/ashlrai/phantom-secrets/ci.yml?style=for-the-badge&label=CI&logo=github&labelColor=0b0b14)](https://github.com/ashlrai/phantom-secrets/actions/workflows/ci.yml)
[![Reviewed release](https://img.shields.io/badge/reviewed_release-v0.7.3-2f81f7?style=for-the-badge&labelColor=0b0b14)](https://github.com/ashlrai/phantom-secrets/releases/tag/v0.7.3)
[![Staged source](https://img.shields.io/badge/staged_source-v0.7.4-f5a623?style=for-the-badge&labelColor=0b0b14)](CHANGELOG.md#074---2026-08-31)
[![Pinned toolchain: Rust 1.95](https://img.shields.io/badge/pinned_toolchain-Rust_1.95-CE412B?style=for-the-badge&logo=rust&labelColor=0b0b14)](rust-toolchain.toml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg?style=for-the-badge&labelColor=0b0b14)](LICENSE)

[**Quick start**](#quick-start) ·
[**Delegate safely**](docs/delegation-quickstart.md) ·
[**Why Phantom?**](#why-phantom) ·
[**MCP setup**](#mcp-integration-claude-code-cursor-windsurf-codex) ·
[**Docs**](docs/README.md) ·
[**Contribute**](CONTRIBUTING.md) ·
[**phm.dev**](https://phm.dev)

</div>

---

> **▶ [Historical v0.4 demo — current behavior differs](https://github.com/ashlrai/phantom-secrets/releases/download/v0.4.0/phantom-demo.mp4)** &nbsp;·&nbsp;
> **🛡 [Security model](SECURITY.md)** &nbsp;·&nbsp;
> **📋 [Threat model](THREAT_MODEL.md)** &nbsp;·&nbsp;
> **💬 [Discussions](https://github.com/ashlrai/phantom-secrets/discussions)**

> [!IMPORTANT]
> **Release boundary:** `v0.7.3` is the reviewed public distribution. This
> repository stages `0.7.4`; source, changelog entries, workflow definitions,
> and local test results do not prove that a `0.7.4` artifact or package was
> published, deployed, provider-enabled, or accepted on any platform. See
> [release readiness](docs/release-readiness.md) and
> [platform support](docs/platform-support.md).

## Why Phantom?

AI coding agents routinely work in repositories that also contain local credentials. Once a real API key enters an agent context, transcript, tool call, or generated file, you have lost control of where that value may persist.

Traditional secrets managers focus on keys *at rest* and *in transit*. Phantom adds a boundary for agent **context**:

- 🔒 **Reduces one credential-exposure path** — managed project dotenv files contain sensitive `phm_` mappings, MCP responses remain value-blind, and exact proxy routes inject their own configured authentication values. Unmanaged files, broader shell authority, and same-user processes remain in the threat model.
- ⚡ **Fast local setup** — after installing the reviewed `v0.7.3` release, `phantom init` protects a project without requiring an account, DNS changes, or a custom CA.
- 🧰 **Agent-native integrations** — setup helpers and value-blind MCP workflows for Claude Code, Cursor, Windsurf, and Codex, plus project instructions for GitHub Copilot.
- 🦀 **Open source, local-first, MIT** — secrets use the native OS credential store when it is available, with an explicit encrypted-file fallback. Optional cloud sync encrypts vault payloads client-side before the server stores them.

### Project status and trust boundary

Phantom's implemented user-facing surfaces are the CLI, vault, authenticated local proxy, MCP server, and optional cloud/team workflows documented below. Cloud and team behavior additionally depends on the deployed service, account plan, and provider configuration; source code alone is not deployment or customer-acceptance evidence. The conversation facade is intentionally narrow:

- `phantom_do` is **proposal-only**. It canonicalizes a closed Cargo action and reports its digest, effect, and activation blockers; `execute` is hard denied.
- `phantom_setup_workspace` can propose setup, create a bearerless request, and report authenticated status. Applying a request remains a separate trusted-terminal operation.
- Advanced MCP tools remain a compatibility catalog, disabled by default, with separate explicit confirmation and informed terminal-approval gates. They are not governed by the conversation facade's capability card.
- `phantom grant` retains value-blind lifecycle metadata and design-source foundations, but 0.7.4 hard-denies every live provider issuance/renewal path before credential or network access. A provider grant is not an execution-kernel **authority grant**, broker lease, or permission for an agent to execute work.
- The authority, broker, runtime, session, and evidence crates are **inactive, fail-closed foundations**. They do not establish live Locus authority, broker credentials, execute agent actions, or produce externally trusted receipts today.

See the [documentation map](docs/README.md), [architecture](docs/architecture.md),
[security policy](SECURITY.md), and [threat model](THREAT_MODEL.md) for the
evidence behind those boundaries.

## Quick Start

Install the reviewed `v0.7.3` release first. On macOS, the verified Homebrew
path is:

```bash
$ brew tap ashlrai/phantom
$ brew trust --formula ashlrai/phantom/phantom
$ brew install ashlrai/phantom/phantom
```

Linux and Windows users should use the exact `v0.7.3` assets in
[Installation](#installation). Then protect and verify the project:

```bash
$ phantom init
# Auto-detects .env, .env.local, or .env in subdirectories
# Stores real secrets in the native credential store or encrypted vault,
# then rewrites .env with phantom tokens
# Auto-configures Claude Code MCP server if detected

$ phantom agent doctor
# One human-readable readiness check for AI-agent safety

$ phantom exec -- claude
# Authenticated proxy running on an ephemeral 127.0.0.1 port
# App/test processes use phantom tokens; agents use value-blind metadata
```

For a task contract you can hand to Claude Code, Codex, Cursor, Windsurf, or
Copilot, use the [safe delegation quickstart](docs/delegation-quickstart.md) and
the [copyable policy and task templates](examples/agent-delegation/README.md).
Teams evaluating a controlled rollout can start with the
[enterprise adoption guide](docs/enterprise-adoption.md).

### Windows

The same core commands work on native Windows. Install the exact `v0.7.3`
Windows ZIP for your architecture from [Installation](#installation), verify its
published `.sha256` sidecar, and place both executables on `PATH`. WSL is a
separate Linux environment with its own filesystem and credential-store context.

For an explicitly supervised foreground proxy, run `phantom start` with stdin,
stdout, and stderr each attached to a trusted terminal. Terminal attachment is
an admission check, not proof of who controls a PTY. The CLI detects your shell and prints the matching env-var syntax;
copy those exports into the terminal that launches the client, keep the owning
terminal open, and press Ctrl-C there to stop. Detached `--daemon` mode and
external process control are fail-closed until Phantom has a separately reviewed
private cross-platform control channel. `phantom stop` only authenticates a
legacy v0.7.3 `.phantom.pid` session to report migration guidance; v0.7.3 had no
authenticated shutdown endpoint, so the new binary never kills that process or
deletes its record. Stop it from its owning v0.7.3 terminal with Ctrl-C, or use
the bounded recovery procedure in [Troubleshooting](docs/troubleshooting.md).
For reference:

**PowerShell:**
```powershell
$env:OPENAI_BASE_URL = "http://127.0.0.1:PORT/openai/_phantom/TOKEN/"
$env:PHANTOM_PROXY_PORT = "PORT"
$env:PHANTOM_PROXY_TOKEN = "TOKEN"
```

**cmd.exe:**
```cmd
set OPENAI_BASE_URL=http://127.0.0.1:PORT/openai/_phantom/TOKEN/
set PHANTOM_PROXY_PORT=PORT
set PHANTOM_PROXY_TOKEN=TOKEN
```

**Git Bash / WSL:** use the `export X=Y` syntax from the main quick-start.

Notes:
- `PHANTOM_PROXY_TOKEN` is the proxy session authenticator. By default, `phantom exec` and `phantom start` include it in local `*_BASE_URL` values as `/_phantom/TOKEN/` so unmodified SDKs work. Header-aware clients can set `PHANTOM_PROXY_HEADER_AUTH_ONLY=1` and send `x-phantom-proxy-token: $PHANTOM_PROXY_TOKEN` instead.
- If `phantom.exe` is blocked by Windows application-control policy, do not automatically remove Mark-of-the-Web. First verify the archive checksum and both binary identities against the release metadata. If local policy permits the verified binaries, a user may then remove the mark explicitly with PowerShell: `Get-ChildItem "$env:USERPROFILE\.phantom-secrets\bin\*.exe" | Unblock-File`.
- The pre-commit hook installed by `phantom init` is a `#!/bin/sh` script. Native git from the command line invokes it via Git for Windows' bundled `sh.exe`, which is what the official Git for Windows installer ships. GUI clients (GitHub Desktop, some IDE integrations) may run with a stripped-down `PATH` that lacks `sh.exe` and silently skip the hook — for these, run commits from a terminal, or use `phantom check --staged` directly. CI is the durable safety net regardless.
- The release workflow defines x64 and ARM64 Windows ZIPs, and the npm and PowerShell installers map both targets. A workflow definition is not evidence that an exact archive was published, signed, or passed native acceptance. See the [platform support matrix](docs/platform-support.md).

## How It Works

```
  .env file (AI read denied)       OS Keychain / Vault
  +--------------------------+      +---------------------+
  | OPENAI_API_KEY=phm_a7f3  | ---> | sk-real-secret-key  |
  | STRIPE_KEY=phm_c9d1...   |      | sk_live_real-key... |
  +--------------------------+      +---------------------+
           |                                 |
           v                                 v
  App / test process                Phantom Proxy (127.0.0.1)
  +--------------------------+      +------------------------------+
  | Loads phm_ tokens        |      | Intercepts HTTP requests     |
  | Agent gets MCP metadata  | ---> | Injects route-owned auth key |
  | Makes API calls to proxy |      | Forwards over TLS to real API|
  +--------------------------+      +------------------------------+
```

1. `phantom init` reads `.env`, stores real secrets in the native OS credential store or encrypted-file fallback, and rewrites `.env` with `phm_` tokens
2. `phantom exec -- claude` starts a local reverse proxy, sets SDK-compatible service base URLs such as `OPENAI_BASE_URL=http://127.0.0.1:PORT/openai/_phantom/TOKEN/`, exposes `PHANTOM_PROXY_TOKEN` to the child process, and launches the command
3. API calls hit the proxy, which authenticates the local session, removes its local auth token, injects only the matched route's vault value into that route's exact configured authentication header, and forwards over TLS. Client-controlled headers and bodies never resolve `phm_` tokens.
4. When the session ends, the proxy shuts down and its bearer is invalid. `phantom exec` also replaces project tokens with fresh child-process tokens for that run. Project `phm_` values persist until rotation; they are not provider credentials and are never client-resolved, but a process controlling an authenticated active proxy can still invoke its configured provider routes.

Phantom does not grant AI tools permission to read `.env` or other dotenv files. `phantom setup` removes legacy Phantom-managed dotenv read grants and preserves deny rules; agents use value-blind MCP inventory instead.

### Provider grants

`phantom grant` retains value-blind lifecycle metadata and provider protocol
design foundations. In 0.7.4, all live provider issuance, enrollment exchange,
refresh, renewal, and revocation execution is hard-denied before Phantom reads a
provider credential or opens a provider network connection. Do not use grant or
rotation commands expecting a vendor-side change. Test-only mocks demonstrate
local transaction behavior only; they are not live-provider acceptance.

In these docs, **provider grant** means design-era credential lifecycle metadata;
no live grant flow runs in 0.7.4. **Authority grant** means the inactive, value-free execution
authority type in `phantom-authority`. A provider grant cannot be reinterpreted
as an authority grant, Locus credential, broker lease, or execution permit. See
the [design-era grant lifecycle specification](docs/grants-spec.md); the
[issuance contract](ISSUANCE_CONTRACT.md) is the original design contract and
retains design-era status language.

## MCP Integration (Claude Code, Cursor, Windsurf, Codex)

Phantom ships an MCP server so AI coding tools can inspect value-blind metadata
and request gated lifecycle operations. MCP responses do not return real secret
values.

- **Conversation facade** — `phantom_capability` reports authority and hard denials for the small facade (not the separately gated advanced compatibility catalog); `phantom_do` canonicalizes one closed Cargo action and reports the exact activation blockers without executing it; `phantom_setup_workspace` proposes an exact value-blind plan, creates a bearerless apply request after revalidation, or reads authenticated request status. Provisioning the machine-local seal key and creating a request both require `confirm` plus an out-of-band approval token; MCP never claims or applies the request.
- **Vault** — `phantom_list_secrets`, `phantom_status`, `phantom_init`, `phantom_add_secret_interactive`, `phantom_add_secret` (deprecated; refuses plaintext), `phantom_remove_secret`, `phantom_rotate`, `phantom_copy_secret`
- **Detection + diagnostics** — `phantom_doctor`, `phantom_why`, `phantom_check`, `phantom_env`, `phantom_validate_secret`, `phantom_validate_all`
- **Local-to-cloud** — `phantom_wrap`, `phantom_unwrap`, `phantom_sync`, `phantom_cloud_push`, `phantom_cloud_pull`, `phantom_cloud_status`
- **Teams** — `phantom_team_list`, `phantom_team_create`, `phantom_team_members`, `phantom_team_invite`, `phantom_team_key_publish`, `phantom_team_vault_push`, `phantom_team_vault_pull`
- **Advanced audit, rotation, expiry, and compliance** — `phantom_audit_recent`, `phantom_audit_stats`, `phantom_audit_analytics`, `phantom_audit_anomalies`, `phantom_audit_anomalies_realtime`, `phantom_audit_hotspot_alerts`, `phantom_audit_incidents`, `phantom_leak_incidents_realtime`, `phantom_audit_alerts`, `phantom_audit_export_report`, `phantom_compliance_status`, `phantom_rotate_with_candidate`, `phantom_rotate_promote`, `phantom_rotate_provider`, `phantom_rotate_with_expiry`, `phantom_list_with_expiry`, `phantom_secret_rotation_due`, `phantom_validation_schedule`, `phantom_validation_history`, `phantom_secrets_expiry_check`, `phantom_secrets_auto_rotate`, `phantom_expiry_enforce`, `phantom_rotation_schedule_next`, `phantom_apply_expiry_policy`

`phantom_secrets_auto_rotate` and `phantom_rotate_with_expiry` are deprecated
compatibility names for approved local `phm_` token remaps. They do not rotate
a provider credential, renew TTL/`rotated_at` metadata, clear leak incidents,
or sync credentials. `phantom_rotate_provider` is also hard-denied before
credential or network access in 0.7.4. Team invites may assign only `member` or `admin`; ownership transfer
is not an invite role.

Tools that write state, retrieve or use credentials, or make provider/network
requests are disabled by default. They can reach their `confirm: true` and
one-use `approval_token` gates only when the operator sets
`PHANTOM_MCP_EFFECTS=trusted-terminal` in a server environment outside agent
authority. `phantom mcp-approve` requires attached stdin/stderr, shows the
bounded value-blind effect plus exact parameters, and requires a fresh typed
challenge before approval. A same-user shell or agent-controlled PTY can
defeat that ceremony; leave effects disabled unless the approval command and
`~/.phantom` approval storage are outside the requesting agent's authority.
Conditional tools keep
their inspection mode ungated and activate both gates only for the effectful
parameters. Real secret values are never accepted as MCP tool arguments; new
secrets are entered out-of-band in a trusted terminal. The exact 54-tool names,
descriptions, and JSON schemas are mirrored from runtime `tools/list` into
[`mcp-registry/server.json`](mcp-registry/server.json), and release smoke tests
reject any drift.

`phantom_rotate_with_candidate` and `phantom_rotate_promote` remain in the
54-tool compatibility catalog as deprecated hard denials. They never create,
validate, or promote a candidate and never change vault or shadow metadata;
`phantom_rotate_provider` is also hard-denied before credential or network
access in 0.7.4. `phantom add` creates new names only and refuses existing-name
replacement before reading a value. Replacing a credential therefore requires
a separately reviewed provider rotation plus an explicit trusted-terminal
remove-and-add sequence; those are distinct, non-atomic operations.

Workspace setup is deliberately split across trust boundaries. MCP can call
`phantom_setup_workspace` with `phase=propose`, then `phase=request_apply` using
the exact returned `plan_id` and `pre_state_id`. The first proposal requires
dual approval only when it must provision the machine-local plan-seal key;
`request_apply` always requires dual approval because it persists a value-free
request outside the repository. Apply it from an attached trusted terminal
with `phantom workspace apply --request <ID>`; MCP has no claim or apply
operation.

One command per AI client — Phantom writes the right config file in the right place:

```bash
phantom setup --client claude     # .claude/settings.local.json (project)
phantom setup --client cursor     # ~/.cursor/mcp.json
phantom setup --client windsurf   # ~/.codeium/windsurf/mcp_config.json
phantom setup --client codex      # ~/.codex/config.toml
phantom setup --client claude --print   # snippet to stdout for any other client
```

Install both `v0.7.3` release binaries before setup. Released `v0.7.3` normally
records the running `phantom` executable with `mcp serve`; if that executable
cannot be resolved, it looks for the local standalone `phantom-mcp`. Its final
legacy fallback is unpinned `npx -y phantom-secrets-mcp`, which currently
resolves an older registry track. Do not rely on that path: keep both verified
release binaries installed and inspect the generated entry. Current main removes
the registry fallback and fails closed when neither local runtime is executable;
that hardening is not part of `v0.7.3` and awaits a later release. Restart the AI
tool after setup so it picks up the new config.

Phantom's stdio MCP server can be configured in MCP clients that support local
command servers. The setup writer currently has reviewed presets for Claude
Code, Cursor, Windsurf, and Codex; other clients require their own compatible
configuration.

## Cloud backup + Dashboard

Back up and restore a vault on the same keychain machine with client-side
encryption. Phantom Cloud receives the encrypted vault payload rather than the
decrypted secret values; endpoint, client, account, and OS-keychain security
remain part of the trust boundary. The cloud encryption key is generated and
stored in the local OS keychain. Phantom does not currently ship key transfer or
recovery, so account sign-in without that key cannot decrypt this backup.
Login, logout, cloud push/pull, and browser open are not headless agent actions:
run them with stdin, stdout, and stderr attached to a terminal outside the
requesting agent's authority and complete each fresh exact typed challenge.

```bash
$ phantom login
# Opens GitHub OAuth (device code flow)

$ phantom cloud push
# Encrypted client-side, uploaded to phm.dev

$ phantom cloud pull   # restore on the machine that holds the original cloud key
# Downloaded and decrypted locally

$ phantom open
# Opens https://phm.dev/dashboard — read-only view of your projects,
# vault sizes, last sync, plan tier, and team membership.
```

Cloud backup uses ChaCha20-Poly1305 with a random client-side passphrase stored
in the OS keychain and derived via Argon2id for encryption. The server stores
only ciphertext. Team vaults are separate: they wrap a shared vault key to each
registered member's X25519 public key; that does not make personal cloud backups
portable.

## Team vaults (source-backed pilot)

The repository includes fixed-membership team-vault workflows intended for a
planned hosted Pro pilot. Pilot eligibility, team and vault limits, and pricing
are TBD; no self-serve checkout is commissioned. The
service path stores ciphertext plus per-member encrypted key shares. Team roles
gate invitation management, but all members can read and write the shared vault;
member removal and atomic offboarding rotation are not shipped. Treat this as a
pilot capability until the hosted service and account entitlement are commissioned.
CLI team mutations require the same attached trusted-terminal ceremony before
credential, keypair, vault-value, or network access. MCP team reads and writes
are provider requests and remain disabled by default behind `confirm` plus a
one-use out-of-band approval token.

```bash
$ phantom team create "engineering"
# Creates a team; you become the owner.

$ phantom team invite <team_id> <github-username>
# Invites by GitHub login.

$ phantom team key-publish <team_id>
# Registers your X25519 public key on the team.
# (Run once per team; the private key stays in the OS keychain.)

$ phantom team vault-push <team_id>
# Encrypts the current project's vault with a fresh symmetric key,
# wraps that key (X25519 + ChaCha20-Poly1305) for every member that
# has a registered public key, then uploads.

$ phantom team vault-pull <team_id>   # on a teammate's machine
# Pulls, decrypts the per-member share with their private key,
# decrypts the vault, writes secrets locally.
```

Team memberships and member lists are visible in the read-only dashboard at [phm.dev/dashboard/team](https://phm.dev/dashboard/team).

## Command Reference

| Command | Description |
|---------|-------------|
| `phantom init` | Import `.env` secrets into vault and rewrite with phantom tokens. Use `--empty` to initialize a new project before its first `phantom add`; `add` does not auto-create project state. `--all <DIR>` processes eligible repositories found by the bounded five-level scan; discovery stops below the first matching repository. Use `--dry-run` to inspect the exact set and `--jobs N` / `-j N` to control parallelism. |
| `phantom exec -- <cmd>` | Start an authenticated proxy and run a command with secret injection |
| `phantom start` | Run an explicitly supervised foreground proxy; keep its trusted terminal open and press Ctrl-C there to stop |
| `phantom start --daemon` / `phantom stop` | Detached start fails closed; stop is a TTY-only legacy-state diagnostic that never kills or deletes, not current process control |
| `phantom list` | Show secret names stored in vault (never values; `--json` for machine-readable output) |
| `phantom add <KEY>` | Create a new secret name transactionally in an initialized project through a hidden terminal prompt or trusted `--stdin` producer; existing names are denied before any value read and are never replaced |
| `phantom remove <KEY>` | After exact trusted-terminal confirmation, transactionally remove the vault value, lifecycle config, and exact managed-dotenv mapping; headless use fails before value access or mutation |
| `phantom reveal <KEY>` | From an attached trusted terminal, review and type the exact challenge before printing one value or copying it for an auto-cleared 30-second clipboard window |
| `phantom status` | Show vault/mapping state and whether the machine-local lifecycle lock is held; a held lock does not authenticate or identify a listener |
| `phantom rotate` | After an exact attached-terminal challenge bound to the project, config, managed dotenv, and sorted protected-name digest, regenerate every local phantom token (old mappings become invalid). Headless use fails before vault access or mutation. Provider-backed `--name`/`--provider` execution is hard-denied before credential or network access in 0.7.4. |
| `phantom grant add <provider>` | Reserved provider-enrollment surface; hard-denied before credential or network access in 0.7.4. See [Provider grants](#provider-grants). |
| `phantom grant list` / `status` | Read provider-grant names, providers, lifecycle state, and expiry metadata without returning credential values. |
| `phantom grant revoke <provider>` | Reserved remote-revocation surface; currently fails closed before local mutation because provider revocation is not wired. |
| `phantom doctor` | Check configuration and vault health (`--fix` to auto-repair). Reports install source, vault backend, audit-log status, Argon2 params, and MCP wiring per client |
| `phantom agent report` | Emit a read-only AI-agent readiness report (`--json` for automation). Reports `unsafe`, `protected`, `verified`, `team-ready`, or `compliance-ready` |
| `phantom agent doctor` | Human-readable agent readiness view backed by the same policy engine |
| `phantom agent setup` | Preview or apply safe defaults for agent use (`--dry-run` first, `--apply` to write changes) |
| `phantom workspace plan [--json]` | Build an exact sealed setup plan and create a value-free pending request; does not change the workspace or vault |
| `phantom workspace apply --request <ID>` | Recompute and claim the exact request in an attached trusted terminal, require typed confirmation, then apply transactionally with rollback on failure |
| `phantom workspace status --request <ID> [--json]` | Read authenticated, value-free request state |
| `phantom check` | Scan for unprotected secrets (pre-commit hook, `--staged`, `--runtime`) |
| `phantom sync` | Push secrets to Vercel / Railway (`--dry-run --json` previews safely; `--only PATTERN` filters by glob, repeatable) |
| `phantom pull` | Pull secrets from Vercel / Railway into vault |
| `phantom setup` | Wire Phantom into an AI client. `--client claude` (default), `cursor`, `windsurf`, or `codex`. Add `--print` to emit the config snippet to stdout |
| `phantom env` | Generate `.env.example` for team onboarding |
| `phantom export` | From an attached trusted terminal, review an exact value-blind plan, type its fresh challenge, and enter a dedicated passphrase through the hidden prompt. Export `--passphrase-file`, plaintext export, argv passphrases, existing targets, symlinks, and paths outside the project fail closed. |
| `phantom import` | From an attached trusted terminal, review and type the exact source/target/name/overwrite challenge before restoring a backup or importing Doppler, Infisical, dotenvx, 1Password, or env data. `--force` selects the reviewed overwrite set but never bypasses consent. A bounded private passphrase file is accepted only on non-Windows platforms and still requires the terminal ceremony. |
| `phantom audit show` | Print recent audit events (`--last N`, `--op OP`, `--name NAME`, `--json`). Requires `PHANTOM_AUDIT=1` |
| `phantom audit tail` | Follow the audit log live (`--op`, `--name` filters) |
| `phantom audit path` | Print the absolute path to the audit log file |
| `phantom audit verify` | Verify HMAC-SHA256 chain integrity; exits 1 if tampering detected |
| `phantom login` | From an attached trusted terminal, approve an exact network plan, then separately approve browser opening/polling and keychain persistence |
| `phantom logout` | From an attached trusted terminal, approve deletion of persistent cloud authorization from the OS keychain |
| `phantom cloud push` | After exact trusted-terminal confirmation, push a client-encrypted vault. A remote success followed by local reconciliation failure is partial success and must not be retried automatically. |
| `phantom cloud pull` | After exact trusted-terminal confirmation, pull and decrypt a vault. With `force=false`, skipped existing entries preserve the prior merge base and block later push until a fully reconciled approved pull. |
| `phantom cloud status` | Authenticated provider read; requires attached trusted terminals and an exact challenge before stored-bearer or network access |
| `phantom wrap` | Wrap package.json scripts with `phantom exec` automatically |
| `phantom unwrap` | Restore original package.json scripts |
| `phantom watch` | Watch managed dotenv files and report new unprotected secrets. `--auto` hard-denies before mutation in 0.7.4; use transactional `phantom init`. |
| `phantom why <KEY>` | Explain why a key is or is not protected |
| `phantom copy <KEY>` | Copy a secret to an initialized target after exact trusted-terminal confirmation; refuses existing target vault, config, or managed-dotenv ownership rather than overwriting |
| `phantom team list/members` | Authenticated, value-blind provider reads. CLI requires attached trusted terminals and an exact challenge before bearer/network access; MCP requires `confirm` plus out-of-band approval. |
| `phantom team create/invite/key-publish/vault-push/vault-pull/rotate-vault` | Run CLI team effects only from an attached trusted terminal and complete the exact challenge before credential, keypair, vault-value, or network access. Invites assign only `member` or `admin`. |
| `phantom validate` / `--watch` | Send selected credentials to configured validators only after exact trusted-terminal consent; watch authorization ends when config or the vault name set changes |
| `phantom validate schedule` | Read status without mutation; setting or disabling persistent scheduler policy requires attached terminals and an exact typed challenge |
| `phantom expiry set` | Persist lifecycle policy only after attached-terminal confirmation; `expiry enforce` is read-only, while `expiry rotate` is only a deprecated local token remap |
| `phantom open [page]` | From an attached trusted terminal, open only the reviewed aliases `dashboard`, `billing`, `team`, `docs`, `pricing`, `github`, `issues`, or `site`; arbitrary URLs, paths, and unknown aliases are rejected |
| `phantom upgrade` | `--check-only` performs a read-only version lookup only for an eligible standalone install. Live standalone replacement requires attached terminals and two exact challenges; managed installs route to their owner, ambiguous installs fail closed, and `--force` is rejected. |
| `phantom completion <shell>` | Print a shell-completion script (bash, zsh, fish, powershell, elvish) |

## Rotating real provider credentials

Phantom 0.7.4 does **not** execute live provider issuance or rotation. Every
provider path—single-provider CLI, batch CLI, MCP, grant enrollment, additive
issuance, and destructive/rolling refresh—is hard-denied before provider
credential access and before network I/O. Operators must rotate at the vendor,
then use Phantom's trusted local secret-entry path. Source adapters and exact
`cfg(test)` mocks are transaction-design evidence, not provider activation,
commissioning, or acceptance.

### Provider support matrix

| Provider | Support | Notes |
|----------|---------|-------|
| `vercel` | Hard denied | Additive issuance can orphan a live successor after a local failure; no provider call in 0.7.4 |
| `google` | Hard denied | Secret Manager version creation remains disabled pending durable successor recovery and verified abort |
| `github` | Hard denied | GitHub App installation-token issuance remains disabled pending the same recovery contract |
| `stripe` | Hard denied | Raw keys are manual; rolling OAuth refresh can invalidate the predecessor before successor recovery |
| `aws` | Hard denied | SigV4 access-key-pair rotation is not implemented |
| `sentry` | Hard denied | Installation-token issuance remains disabled pending durable successor recovery |
| `supabase` | Hard denied | PAT rotation is manual; OAuth/additive issuance paths are not commissioned |

`phantom rotate --batch` remains metadata-only discovery/manual guidance and
fails closed before vendor execution. No single-provider exception exists.

## Features

- **Encrypted vault** -- macOS Keychain, Linux Secret Service, or Windows Credential Manager, with a ChaCha20-Poly1305 encrypted-file fallback for CI and headless environments. Phantom does not claim Secure Enclave hardware binding. Argon2id uses m=64 MiB, t=3, p=1.
- **Phantom tokens** -- 256-bit CSPRNG `phm_` placeholders in `.env`, rotatable on demand
- **Authenticated proxy sessions** -- each proxy run generates a fresh `PHANTOM_PROXY_TOKEN`; CLI-generated SDK URLs include it for compatibility, and header-aware clients can opt into `x-phantom-proxy-token` with `PHANTOM_PROXY_HEADER_AUTH_ONLY=1`
- **Route-owned credential injection** -- Client headers and bodies never resolve `phm_` tokens. After authenticating and matching an exact built-in route, the proxy injects that route's configured vault secret only into its fixed authentication header; a missing mapping fails before any upstream call. Request bodies are still collected under a hard byte cap before forwarding.
- **Full SSE/streaming support** -- Response streaming preserved end-to-end for OpenAI, Anthropic, and other streaming APIs
- **Smart detection** -- Heuristic engine distinguishes secrets (`*_KEY`, `*_TOKEN`, `sk-*`, `ghp_*`) from config (`NODE_ENV`, `PORT`)
- **Platform sync** -- Push/pull secrets to Vercel and Railway
- **Pre-commit hook** -- Runs `phantom check --staged` when Git invokes the hook; it checks staged dotenv content plus a bounded set of hardcoded-key prefixes. Hooks can be bypassed or skipped, so CI and a broader secret scanner remain necessary.
- **MCP server** -- value-blind vault, diagnostics, cloud, team, audit, rotation, validation, expiry, and compliance responses for Claude Code, Cursor, Windsurf, and Codex; effectful compatibility tools remain separately gated and disabled by default
- **Cloud backup** -- client-encrypted same-keychain-machine backup and restore; key transfer and recovery are not shipped, and deployed-service and account configuration remain separate operational gates
- **Export/import** -- Encrypted export requires an attached terminal, exact challenge, and hidden passphrase; export passphrase files, plaintext, and argv passphrases are disabled. Import uses its own exact terminal ceremony; only non-Windows encrypted-backup import may read a bounded private passphrase file. Competitor imports support Doppler, Infisical, dotenvx, 1Password, and plain `.env`.
- **Tamper-evident audit log** -- `PHANTOM_AUDIT=1` writes vault events as JSONL to `~/.phantom/audit.log`. Each entry is chained with HMAC-SHA256; `phantom audit verify` detects tampering. `phantom audit show/tail/path` for log access.
- **Response scrubbing** -- Scrubs configured secret values from supported API response paths before returning data to the caller
- **Script wrapping** -- `phantom wrap` wraps selected runtime/build scripts (`dev`, `start`, `serve`, `build`, `deploy`, `preview`) and deliberately leaves test, lint, type, and format scripts alone
- **Watch mode** -- `phantom watch` reports new unprotected secrets; legacy `--auto` hard-denies before mutation, so protection stays a reviewed transactional `phantom init`
- **Multi-project scanner** -- `phantom init --all <DIR>` processes eligible repositories found within a five-level bounded scan and stops below the first matching repository; use `--dry-run` to verify the exact set and `--jobs N` to control parallelism
- **Multi-IDE setup** -- `phantom setup --client claude|cursor|windsurf|codex` writes the right MCP config for each AI tool, or `--print` for a generic snippet
- **Agent readiness** -- `phantom agent doctor` and `phantom agent report --json` report bounded protection findings and activation gaps; they do not certify a repository or agent as safe
- **Enriched diagnostics** -- `phantom doctor` reports install source, vault backend, audit-log status, Argon2 params, and MCP wiring per client
- **Secret explainer** -- `phantom why <KEY>` explains detection heuristics
- **Cross-project copy** -- `phantom copy` shares secrets between project vaults
- **Team vaults** -- Fixed-membership encrypted sharing; owner/admin roles gate invitations, while current vault access is member-wide and offboarding rotation is not shipped
- **Fail-closed service routing** -- agentic proxy sessions accept Phantom's exact built-in OpenAI, Anthropic, Stripe, Supabase, and other reviewed routes; repository-defined destinations are rejected pending trusted-terminal approval support
- **Threat model** -- See [THREAT_MODEL.md](THREAT_MODEL.md) for assets, actors, mitigations, and known gaps

## Installation

### Homebrew (macOS, reviewed v0.7.3 release)

Homebrew 6 requires explicit formula trust for third-party taps:

```bash
$ brew tap ashlrai/phantom
$ brew trust --formula ashlrai/phantom/phantom
$ brew install ashlrai/phantom/phantom
```

This formula installs both `phantom` and `phantom-mcp` from the immutable
[`v0.7.3` GitHub release](https://github.com/ashlrai/phantom-secrets/releases/tag/v0.7.3).

### Exact GitHub assets (Linux and Windows)

Use the asset matching your OS and architecture. Download its adjacent
`.sha256` file from the release, verify it before extraction, and place both
`phantom` and `phantom-mcp` (`.exe` on Windows) on `PATH`.

| Platform | `v0.7.3` archive | Published checksum |
|---|---|---|
| Linux x86_64 | [`phantom-x86_64-unknown-linux-gnu.tar.gz`](https://github.com/ashlrai/phantom-secrets/releases/download/v0.7.3/phantom-x86_64-unknown-linux-gnu.tar.gz) | [`sha256`](https://github.com/ashlrai/phantom-secrets/releases/download/v0.7.3/phantom-x86_64-unknown-linux-gnu.tar.gz.sha256) |
| Linux ARM64 | [`phantom-aarch64-unknown-linux-gnu.tar.gz`](https://github.com/ashlrai/phantom-secrets/releases/download/v0.7.3/phantom-aarch64-unknown-linux-gnu.tar.gz) | [`sha256`](https://github.com/ashlrai/phantom-secrets/releases/download/v0.7.3/phantom-aarch64-unknown-linux-gnu.tar.gz.sha256) |
| Windows x64 | [`phantom-x86_64-pc-windows-msvc.zip`](https://github.com/ashlrai/phantom-secrets/releases/download/v0.7.3/phantom-x86_64-pc-windows-msvc.zip) | [`sha256`](https://github.com/ashlrai/phantom-secrets/releases/download/v0.7.3/phantom-x86_64-pc-windows-msvc.zip.sha256) |
| Windows ARM64 | [`phantom-aarch64-pc-windows-msvc.zip`](https://github.com/ashlrai/phantom-secrets/releases/download/v0.7.3/phantom-aarch64-pc-windows-msvc.zip) | [`sha256`](https://github.com/ashlrai/phantom-secrets/releases/download/v0.7.3/phantom-aarch64-pc-windows-msvc.zip.sha256) |

On Linux, verify with `sha256sum -c <archive>.sha256`. On Windows, compare
`Get-FileHash -Algorithm SHA256 <archive>` with the published sidecar.

### Build the exact release source

The `v0.7.3` tag resolves to source commit
`cffd0f29ab85a45358f011fdcfd40667d576c420`:

```bash
$ git clone https://github.com/ashlrai/phantom-secrets.git
$ cd phantom-secrets
$ git checkout cffd0f29ab85a45358f011fdcfd40667d576c420
$ cargo build --release --locked --bin phantom --bin phantom-mcp
```

Do not treat unpinned package-manager commands as `v0.7.3`. As verified on
2026-08-31, npm and the MCP Registry publish `0.6.0`, while crates.io publishes
`0.5.1`; those are older distribution tracks, not the reviewed current release.

### Connect an MCP client

```bash
$ phantom setup --client claude   # or cursor, windsurf, codex
```

## Architecture

The Rust workspace is organized as product crates plus fail-closed execution-kernel foundations. Presence in the workspace does not mean a foundation is activated in production.

| Layer | Crate | Role and current status |
|-------|-------|-------------------------|
| Product | `phantom-core` | Config, dotenv parsing/rewriting, tokens, auth, cloud client, audit, validation, and shared policy. |
| Product | `phantom-vault` | `VaultBackend` trait, OS keychain and encrypted-file backends, and shared cryptography. |
| Product | `phantom-proxy` | Authenticated loopback reverse proxy with fixed route-owned auth-header injection, inert client tokens, response scrubbing, and streaming support. |
| Product | `phantom-cli` | Operator CLI for initialization, proxy lifecycle, readiness, audit, import/export, sync, team, and workspace workflows. |
| Product | `phantom-mcp` | Stdio MCP server. The governed conversation facade is narrow; the advanced compatibility catalog uses separate legacy gates. |
| Product | `phantom-core/src/issuance`, CLI `grant` | Provider protocol/design foundations and value-free grant metadata. All live provider issuance/enrollment execution is hard-denied before credential or network access in 0.7.4. |
| Local effect layer | `phantom-core::fs`, `phantom-vault` transactions | Retained project/config directory capabilities, exact identity/content/permission before-images, no-follow targets, single-link checks, and typed durable, committed-verified-with-durability-warning, or `CommittedButUncertain` (**Partial**) effects. |
| Setup kernel | `phantom-workspace` | Value-blind discovery, sealed planning, and recoverable trusted-terminal setup transactions. Non-Unix durable mutation fails closed. |
| Inactive foundation | `phantom-authority` | Closed authority contracts and deny-all production verification boundary. No live Locus verifier. |
| Inactive foundation | `phantom-locus-contract` | Value-free compatibility contract describing requirements for a future Phantom/Locus integration. |
| Inactive foundation | `phantom-broker` | Bounded broker protocol and durable replay/accounting primitives. No active transport, lease issuer, or runtime connection. |
| Inactive foundation | `phantom-runtime` | Closed engineering action schemas with a deny-all production executor. |
| Inactive foundation | `phantom-session` | Crash-explicit session journal. Not wired into active execution. |
| Inactive foundation | `phantom-evidence` | Value-free evidence and receipt primitives. Not externally anchored or wired into active execution. |

Project-local effects resolve from the retained root acquired with the project
transaction lock; global editor configuration is separately bounded beneath a
retained user-config authority. A renamed ambient path and replacement decoy do
not redirect those in-progress governed writes. These controls are not a
same-user sandbox: local locks coordinate Phantom writers, and another process
with equivalent user authority remains inside the threat model. See the
[architecture](docs/architecture.md), [threat model](THREAT_MODEL.md), and
[platform evidence matrix](docs/platform-support.md).

Initialization retains the reviewed project-root identity and exact
dotenv/config leaf snapshots before vault provisioning, then revalidates root
and leaf identity, bytes, and permissions under the project lock before
mutation. On Windows, new private anchored files/directories establish a
protected current-user DACL before content bytes, while replacements preserve
the reviewed exact DACL and inheritance state before writing. Those Windows
properties are source contracts; protected native Windows CI acceptance remains
pending.

`CommittedVerifiedButDurabilityUncertain` is committed, exactly verified
success with a value-free warning/receipt and must not be rolled back or
retried. `CommittedButUncertain` is the distinct **Partial** case requiring
operator reconciliation because verification or durability remains unresolved.

Vault-backed mutations resolve machine-local vault/application authority before
the project transaction lock, then compare the acquired root identity and
reread the exact config through that lock. This avoids the shared
process-environment/project-lock inversion without trusting project bytes during
the gap.

Phantom also tracks a pinned [Rama-derived engineering
standard](docs/rama-design-standard.md) for explicit network stacks, modular
crates, runnable examples, and tiered platform CI. Rama is a benchmark, not a
dependency, and the comparison is not a feature or platform-parity claim.

**`apps/web`** contains the Next.js site and backend routes for cloud vault sync, GitHub device authentication, and Stripe billing. The repository source and local tests are separate evidence from the currently deployed state at [phm.dev](https://phm.dev).

**Older registry tracks**: npm currently publishes
[`phantom-secrets`](https://www.npmjs.com/package/phantom-secrets) and
[`phantom-secrets-mcp`](https://www.npmjs.com/package/phantom-secrets-mcp) at
`0.6.0`; these are not the reviewed `v0.7.3` release.

CI runs locked, all-target workspace builds and tests on macOS, Linux, and Windows runner environments, plus formatting, Clippy, and npm release-mapping checks. Release builds and native end-to-end acceptance are separate evidence layers; see [Platform support](docs/platform-support.md).

## Security

- **Managed dotenv replacement** -- after successful initialization, Phantom-managed dotenv values are tokens; unmanaged files, backups, logs, and external tools remain outside this claim
- **ChaCha20-Poly1305** encryption for file vault and cloud sync, **Argon2id** key derivation
- **Client-encrypted cloud vaults** -- the cloud vault API stores ciphertext; decryption happens in the authenticated client. This claim does not cover plaintext sent intentionally to deployment providers during `phantom sync`.
- **256-bit CSPRNG tokens** -- `phm_` prefix distinguishes Phantom tokens from supported real-key formats; random collisions are cryptographically negligible, not mathematically impossible
- **Proxy binds 127.0.0.1 only** -- not bound to a non-loopback interface; same-user local-process and bearer theft remain in the threat model
- **Targeted memory zeroization** for major vault retrieval, serialization, and decrypted-file buffers; some proxy lookup copies remain ordinary strings, so zeroization is defense in depth rather than a complete memory-erasure guarantee
- **Allowlist model** -- proxy only injects secrets for explicitly configured service patterns

See [SECURITY.md](SECURITY.md) for the responsible disclosure policy and [THREAT_MODEL.md](THREAT_MODEL.md) for the full threat model (assets, actors, mitigations, known gaps, cryptography summary).

## Pricing

| Packaging direction | Local open source | Pro (planned hosted pilot) | Enterprise (planned contract) |
|---|---|---|---|
| Local vault | Available without a hosted entitlement | Available | Available |
| Hosted cloud vaults | No commissioned entitlement represented here | Eligibility and limits TBD | Scope defined by written agreement |
| MCP server | Yes | Yes | Yes |
| Personal cloud backup | Same-keychain-machine restore only | Key portability evaluation planned | Scope defined by written agreement |
| Team features | -- | Fixed-membership pilot; eligibility and limits TBD | Planned enterprise controls; scope TBD |
| Price | No charge for local open-source use | Pricing TBD; no self-serve checkout commissioned | Written agreement |

This table is packaging direction, not evidence that a hosted entitlement,
enterprise control, support term, or price is active for a particular account.
The planned Pro pilot has no commissioned self-serve checkout; eligibility,
team and vault limits, and pricing remain TBD. Verify the deployed service and
written plan terms; see the
[enterprise adoption guide](docs/enterprise-adoption.md) for shipped-versus-planned gates.

## Links

- [phm.dev](https://phm.dev) -- Cloud dashboard and account management
- [Documentation map](docs/README.md)
- [Getting Started Guide](docs/getting-started.md)
- [Safe delegation quickstart](docs/delegation-quickstart.md)
- [Enterprise adoption guide](docs/enterprise-adoption.md)
- [Agent delegation templates](examples/agent-delegation/README.md)
- [Examples index](examples/README.md)
- [Security Model](SECURITY.md)
- [Threat Model](THREAT_MODEL.md)
- [Roadmap](ROADMAP.md)
- [Troubleshooting](docs/troubleshooting.md)
- [Changelog](CHANGELOG.md)
- [Contributing](CONTRIBUTING.md)
- [Support](SUPPORT.md)
- [Governance](GOVERNANCE.md)
- [Citation](CITATION.cff)

## Contributing

Focused contributions are welcome. Start with
[`CONTRIBUTING.md`](CONTRIBUTING.md), the
[examples index](examples/README.md), or a
[discussion](https://github.com/ashlrai/phantom-secrets/discussions). The
project does not assume that a `good first issue` label is populated. Follow
[`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md), and use
[`SECURITY.md`](SECURITY.md) rather than a public issue for vulnerabilities.

## Star history

<a href="https://star-history.com/#ashlrai/phantom-secrets&Date">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://api.star-history.com/svg?repos=ashlrai/phantom-secrets&type=Date&theme=dark" />
    <source media="(prefers-color-scheme: light)" srcset="https://api.star-history.com/svg?repos=ashlrai/phantom-secrets&type=Date" />
    <img alt="Phantom Secrets star history" src="https://api.star-history.com/svg?repos=ashlrai/phantom-secrets&type=Date" />
  </picture>
</a>

If Phantom saves you from leaking a key — or even just from worrying about it — please **[star the repo ⭐](https://github.com/ashlrai/phantom-secrets/stargazers)**. It's the single biggest signal we use to know what to build next.

## License

MIT — see [LICENSE](LICENSE).
