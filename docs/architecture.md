# Phantom architecture

This document explains the current source architecture and its trust boundaries.
It is for contributors, security reviewers, and integrators deciding which parts
of Phantom are usable today and which parts must remain fail-closed.

Phantom has three deliberately separate layers:

1. shipped secret-protection product paths;
2. a functional, value-blind workspace setup transaction on Unix; and
3. inactive execution-kernel foundations that cannot authorize or run agent
   work in production.

Source presence and passing tests do not mean a component is deployed,
provider-enabled, or accepted in a real customer workflow.

## Status vocabulary

| Status | Meaning in this document |
|---|---|
| Shipped product path | Reachable from the CLI, MCP server, proxy, vault, or web source. Repository evidence does not prove the public service is deployed. |
| Functional setup path | Implemented source path that can apply a reviewed workspace setup transaction under the platform limits below. |
| Inactive foundation | Compiled and tested primitives whose production constructor, verifier, transport, or backend denies use or is unavailable. |
| Target architecture | A design requirement. It is not current capability. |

## Current-state map

| Layer | Components | Current responsibility and boundary |
|---|---|---|
| Product | `phantom-cli`, `phantom-core` | Project configuration, dotenv classification and rewriting, tokens, authentication, cloud clients, audit, sync, validation, and operator workflows. |
| Provider foundations | `phantom-core/src/issuance`, CLI `grant` commands | Protocol/design source plus value-free lifecycle metadata. All live issuance/enrollment/renewal/revocation is hard-denied before credential or network access in 0.7.4. This is not execution authority. |
| Secret storage | `phantom-vault` | Native credential-store and encrypted-file backends behind `VaultBackend`. Real values remain behind this interface. |
| Local effect layer | `phantom-core::fs`, `phantom-vault` transactions | Retained directory capabilities, exact before-images, no-follow target resolution, effect receipts, and explicit durable versus committed-but-uncertain outcomes for governed project and client-config mutation. |
| Network edge | `phantom-proxy` | Authenticated loopback HTTP proxy, fixed route-owned auth-header injection, inert client headers/bodies, response scrubbing, streaming, size/time/concurrency limits, and upstream dispatch. |
| Agent interface | `phantom-mcp` | Stdio MCP tools that return value-free metadata. The small conversation facade is distinct from the advanced compatibility catalog and its legacy gates. |
| Cloud application | `apps/web` | Next.js routes and UI for device authentication, encrypted cloud-vault storage, teams, and billing. Local source does not prove live deployment state. |
| Setup kernel | `phantom-workspace` plus workspace-request code in `phantom-core` | Value-blind inspection, deterministic sealed plans, bearerless requests, and recoverable trusted-terminal apply on Unix. |
| Inactive kernel | `phantom-authority`, `phantom-locus-contract`, `phantom-broker`, `phantom-runtime`, `phantom-session`, `phantom-evidence` | Closed, fail-closed foundations for a future governed execution path. They are not wired into one production system. |

## System context and trust boundaries

```text
                       value-free names, plans, status
  AI client  <---------------------------------------------->  phantom-mcp
     |                                                            |
     | phm_ placeholders and proxy session coordinates            | no secret-value tool result
     v                                                            v
  application  ---- authenticated loopback HTTP ---->  phantom-proxy
                                                           |
                    fixed route-owned auth-header injection | real provider credential
                                                           v
                                                    external provider API

  human/operator  ---- phantom CLI ---->  vault + project files
        |                                  |
        |                                  +---- encrypted ciphertext ----> Phantom Cloud
        |
        +---- separate trusted terminal ----> workspace setup transaction (Unix)

  ----------------------- inactive activation boundary -----------------------
  Locus verifier -> broker/lease -> confined runtime -> correlated evidence
  No production connection across this boundary exists.
```

The project directory is not a trusted authority source. An agent can influence
workspace contents, MCP arguments, process output, timing, and retries. Local
user storage is a stronger boundary than the workspace, but it is not secure
against a fully compromised same-user account or an administrator.

The loopback proxy is a credential injection boundary, not a general sandbox.
The upstream provider and Phantom Cloud are separate remote trust boundaries.
Cloud vault and team-vault payloads are encrypted client-side; web
authentication, billing, and metadata still have their own server-side access
control requirements.

## Shipped secret-protection flows

### Protect a project

1. `phantom init` parses the selected dotenv file and classifies entries.
2. Detected secret values are stored through `VaultBackend`.
3. The dotenv file is rewritten with `phm_` placeholders and supporting
   project files are generated or updated.
4. Agent-facing inspection and MCP results expose names, classifications,
   hashes, status, and counts rather than secret values.

Public configuration and explicitly classified public keys are not vaulted by
default. Detection is a policy aid, not proof that every sensitive value was
identified; `phantom check` and human review remain important.

### Run through the proxy

1. `phantom exec` opens the project vault and creates an ephemeral proxy
   session.
2. The proxy binds to loopback, authenticates the local request, matches an
   exact route, discards client control of that route's auth header, and injects
   only the route-owned vault value there. Client placeholders remain inert.
3. The proxy bounds request/response resources, preserves supported streaming,
   and scrubs known secret values from responses before returning data to the
   child process.
4. Shutdown ends the proxy session and its ephemeral authentication token.

`PHANTOM_PROXY_TOKEN` is a plaintext session bearer in the `phantom exec` child
environment by design. It is not a provider credential, but a compromised
child can use the local proxy while that session is alive. URL-carried proxy
authentication exists for SDK compatibility and has a stricter header-only
mode. These are explicit limitations, not evidence of process isolation.

### Use MCP and cloud features

The MCP transport is stdio. Core tools operate on the local project and vault;
cloud and team tools use the authenticated cloud client. Tool responses must
remain value-free. The deprecated plaintext MCP add path refuses values, while
interactive secret entry happens in an attached terminal.

Effectful advanced compatibility tools are disabled by default. An operator
may set `PHANTOM_MCP_EFFECTS=trusted-terminal` outside agent authority to reach
their explicit confirmation and one-use approval checks. `phantom mcp-approve`
inspects the pending record before mutation, displays its bounded value-blind
effect and exact parameters, requires attached stdin/stderr, and asks for a
fresh typed challenge. A same-user shell or agent-controlled PTY can defeat
that ceremony; when the command or `~/.phantom` approval storage is in agent
scope, effects must remain disabled. These gates are not Locus grants, broker
leases, or proof that the inactive execution kernel is active.

### Provider-grant foundations

Provider protocol source and value-free metadata remain design foundations.
In 0.7.4, CLI single-provider rotation, batch rotation, MCP rotation, enrollment
exchange, additive issuance, rolling refresh, and remote revocation all fail
before provider credential access and before network I/O. Exact `cfg(test)`
mocks prove local transaction scaffolding only, not provider activation,
commissioning, or acceptance. See the [provider-grant specification](grants-spec.md).

A **provider grant** is design-era credential lifecycle metadata. It is not an **authority
grant** from `phantom-authority`, a Locus credential, a broker lease, or an
execution permit. The MCP server has no provider-consent or provider-grant
issuance tool.

## Retained local filesystem effects

Phantom treats an ambient pathname as a locator, not durable authority. A
governed writer first retains a real directory, then keeps target resolution and
effects relative to that retained directory identity:

```text
acquire retained root + stable lock
  -> resolve no-follow relative target
  -> read identity + bytes + permissions before-image
  -> compare-and-swap atomic replace or exact unlink
  -> Durable
     | CommittedVerifiedButDurabilityUncertain (committed success + warning)
     | CommittedButUncertain (Partial; reconcile)
```

When an operation needs both project state and a machine-local vault, Phantom
uses one cross-domain lock order:

```text
retain reviewed project identity
  -> resolve vault/application authority (may take the process-environment guard)
  -> acquire project transaction lock
  -> compare acquired root identity with reviewed identity
  -> reread exact config identity + bytes + permissions through the lock
  -> use vault and commit the governed project effect
```

No project mutation is authorized during the gap before the transaction lock.
The retained review anchor and exact post-lock reread close that gap: replacing
the project with a different directory at the same canonical spelling is
rejected. Resolving vault authority before the project lock also avoids an
environment-guard/project-lock inversion with other Phantom threads.

`phantom init` additionally binds the exact dotenv/config leaf identity, bytes,
and permissions during review before vault provisioning. The transaction
revalidates the retained root after lock acquisition and every reviewed leaf
before mutation, so a byte-identical replacement inode/file identity is drift.

- Symlink and Windows reparse-point components are rejected. Sensitive file
  effects require a regular, single-link target, so a hard link cannot silently
  redirect a governed update to a second name.
- Exact target identity and bytes are checked immediately before replacement or
  unlink. A same-content file on a different inode/file identity is drift.
- Renaming the ambient root and installing a decoy at its old path does not
  redirect the in-progress effect. Tests verify that the retained tree is
  updated or rolled back while the decoy remains unchanged.
- Newly created private directories carry identity-bound receipts. Cleanup
  removes only an empty directory with the exact created identity, after
  descendant handles have been released.
- A verified rename, unlink, or create can commit on a platform that cannot
  prove directory crash durability. `CommittedVerifiedButDurabilityUncertain`
  is committed success with a value-free warning/receipt; callers do not roll
  it back or retry it.
- If post-publish verification or durability remains unresolved,
  `CommittedButUncertain` is a **Partial** outcome: callers require
  reconciliation rather than claiming rollback or retry safety.
- On Windows, a new private file or directory receives and verifies a protected
  current-user DACL before content bytes. A replacement staging file receives
  and verifies the reviewed target's exact DACL, inheritance state, and
  read-only state before content is copied; NULL/nonrestrictive DACLs fail
  closed.

Authorities remain intentionally separate:

| Effect | Retained authority |
|---|---|
| Project dotenv, config, guidance, doctor, rotation, and workspace files | The acquisition-time project root held by `ProjectTransactionLock` |
| Project-local or linked-worktree Git hook | The effective Git hook parent resolved from the retained project/Git context |
| Explicit external `core.hooksPath` | A separately retained hook root plus an exact attached trusted-terminal authorization; project authority is not widened, and MCP refuses the external write |
| Claude project settings | The retained project root |
| Cursor, Windsurf, and Codex user config | A retained home/config ancestor traversed component by component; setup coordination is under retained `~/.phantom` app state |

These are path-integrity and transaction controls, not same-user isolation.
Locks serialize cooperating Phantom writers. A process with equivalent user
filesystem or terminal authority can still mutate state before acquisition or
after handles are released, race ungoverned tools, or defeat a terminal
ceremony. The Windows implementation has source-contract tests for reparse,
identity, handle ordering, exact ACL establishment/preservation, and both
uncertainty outcomes; protected native Windows CI acceptance remains pending.

Read-only check, status, audit, and proposal discovery is intentionally distinct
from a governed effect. Those paths may resolve ambient state for observation;
their output is not a retained before-image, a sealed mutation target, or an
authority grant. A later effect must independently acquire its lock/capability
and revalidate the exact state it will mutate.

Terminal admission is likewise ordered before approval-state inspection and
input. A noninteractive `phantom mcp-approve` request is rejected before the
pending record is inspected, a challenge is generated, or stdin is read; it
cannot hold an environment guard while waiting for terminal input.

## Functional workspace setup transaction

Workspace setup is the only active execution-kernel slice. Its lifecycle keeps
conversation planning separate from local mutation:

```text
inspect -> sealed proposal -> bearerless pending request
                              |
                              | exact recomputation + typed confirmation
                              v
                       claimed in trusted terminal
                              |
                       apply + durable journal
                         /              \
                    applied       failed / rolled back
```

- `phantom_setup_workspace` with `phase: propose` inspects the workspace and
  returns a sealed, value-blind plan. It does not mutate workspace or vault
  contents, but it can create or harden machine-local Phantom state and reports
  whether it provisioned the plan-seal key.
- `phase: request_apply` requires the exact plan and pre-state identifiers,
  recomputes both without provisioning a missing seal key, rejects drift, and
  creates a pending request.
- A request identifier locates authenticated local state; it is not an approval
  bearer. MCP cannot claim or apply it.
- `phantom workspace apply --request <id>` must run from an attached trusted
  terminal. It recomputes the workspace, claims the exact unexpired request,
  prints the plan, requires typed confirmation, and applies through the
  transaction participant.
- The out-of-workspace authenticated journal supports crash reconciliation and
  rollback. A claimed request is never silently expired because effects might
  already exist.
- Place review remains deferred. An applied setup transaction does not create
  Locus authority or authorize external work.

Descriptor-relative, no-follow durable mutation is implemented on Unix.
Windows can inspect and propose, but durable apply fails closed with
`SafeMutationUnsupported`. See [Platform support](platform-support.md) for the
evidence by operating system and architecture.

## Inactive execution-kernel foundations

The future lifecycle is intended to be:

```text
closed action intent
  -> externally verified authority
  -> peer-authenticated broker and durable single-use permit
  -> sealed workspace/toolchain handles and OS-confined runtime
  -> value-free correlated evidence and externally verifiable receipt
```

Every arrow above is currently an activation boundary, not a production call
path.

| Crate | Implemented foundation | Why it remains inactive |
|---|---|---|
| `phantom-authority` | Closed actions, identifiers, constraints, narrowing, canonical local encoding, and opaque verified-grant type. | The only production verifier is deny-all; no Locus signature or grant is accepted. |
| `phantom-locus-contract` | Value-free compatibility profiles and pinned candidate metadata. | Negotiation is caller-supplied metadata, not peer/source/signature verification. Audited candidate work is not one coherent compatible artifact. |
| `phantom-broker` | Bounded protocol, lifecycle types, descriptor-owned Unix replay storage, use accounting, and non-cloneable execution permits. | Transport is deny-all; no verifier, credential resolver, proxy, or worker is connected. Valid old snapshots need an external monotonic rollback anchor. |
| `phantom-runtime` | Closed Cargo actions, policy binding, revocation/cancellation contracts, and single-use runtime ownership. | Production handle minters do not exist and `DenyAllConfinement` is the production backend. The direct runner is test-only. |
| `phantom-session` | Crash-explicit, value-free transition journal with immutable genesis and exact recovery semantics. | Its public production factory always refuses construction, and no subsystem consumes it. |
| `phantom-evidence` | Closed events, bounded local HMAC chain, lifecycle validation, summaries, and receipt primitives. | Local integrity is not external trust; no trusted signer registry or end-to-end execution correlation is wired. |

`phantom_do` exposes only a closed proposal for Cargo check, test, Clippy, or
format-check actions. It returns the canonical digest, effect classification,
workspace fingerprint, and activation blockers. Its execute phase is hard
denied and creates neither an approval request nor a legacy mutating-tool call.

## Credential and authority invariants

The governed execution design has no field or fallback for a plaintext
provider credential, approval bearer, arbitrary command, environment map, URL,
header, body, stdout payload, or secret locator. A future Locus integration
must transfer an exact, value-free, revocable lease over a peer-authenticated
native transport. It must never call a reveal command or capture a secret from
stdout.

This invariant is narrower than saying Phantom has no bearer tokens at all:
the shipped proxy session uses an ephemeral bearer, cloud clients authenticate
to the web API, and legacy MCP mutations have separate local approval gates.
None of those values can be reinterpreted as execution-kernel authority.

Other non-negotiable boundaries are:

- untrusted input can narrow authority but cannot expand it;
- one request, plan, digest, receipt, or compatibility offer is never authority
  by possession alone;
- rollback and recovery are explicit lifecycle states, not best-effort cleanup;
- network, time, bytes, concurrency, retries, subprocesses, and output need
  owner-enforced bounds before a production runtime can exist;
- secret values must not appear in MCP, argv, logs, evidence, receipts, or
  crash diagnostics; and
- same-user compromise, host administrator compromise, and rollback of valid
  authenticated local snapshots remain outside current local-HMAC guarantees.

## Resource and lifecycle ownership

| Resource | Owner today | Lifecycle rule |
|---|---|---|
| Real secret value | `VaultBackend` and proxy interceptor | Resolve only for a scoped operation; do not serialize into agent-facing results. |
| Project Phantom token | Project dotenv/config | Random placeholder, not a provider credential. It persists until rotation and is never resolved from a client header/body; treat exposure as sensitive metadata and rotate it. |
| Proxy session bearer | CLI/proxy session | Fresh per run, loopback-scoped, invalid after shutdown; exposed to the child environment. |
| Workspace request | Authenticated machine-local request store | `Pending -> Claimed -> Applied`, or explicit `Expired`, `Failed`, or `RolledBack`; claimed work may require recovery. |
| Setup recovery journal | Workspace transaction engine | Authenticate before recovery; reconcile or roll back before accepting new conclusions. |
| Replay permit | Inactive broker foundation | Non-cloneable and single use, but not obtainable through an active production transport. |
| Session journal | Inactive session foundation | Persist intent before effect and completion after observation; a pending transition requires explicit recovery. |
| Execution evidence | Inactive evidence foundation | Value-free and locally integrity-checked; not externally trusted without a signer and rollback anchor. |

## Platform boundary

The ordinary Rust workspace is built and tested by CI on macOS, Linux, and
Windows runners. The release workflow defines six archives: macOS, GNU Linux,
and Windows on `arm64`/`x64`. That does not prove native keychain, installer,
signing, proxy, shell, or AI-client behavior for every exact archive.

Security-sensitive filesystem guarantees differ:

- macOS and Linux have the Unix descriptor-relative workspace transaction and
  broker replay foundation;
- Windows workspace mutation and replay storage fail closed today;
- evidence and session storage compile on Windows with fewer filesystem
  ownership/mode guarantees; and
- production OS confinement is unavailable on every platform.

Keep platform claims tied to [the support matrix](platform-support.md), and use
the [release-readiness guide](release-readiness.md) before describing a source
candidate as a trusted release.

## Sources of truth and update triggers

Use code and executable contracts before prose:

- product composition: [`Cargo.toml`](../Cargo.toml) and crate manifests;
- provider denial and design foundations: [`issuance`](../crates/phantom-core/src/issuance/), CLI
  [`grant`](../crates/phantom-cli/src/commands/grant/), and the current
  [provider-grant specification](grants-spec.md);
- proxy boundary: [`phantom-proxy`](../crates/phantom-proxy/);
- workspace transaction: [`phantom-workspace`](../crates/phantom-workspace/),
  [`workspace_request.rs`](../crates/phantom-core/src/workspace_request.rs), and
  [`workspace.rs`](../crates/phantom-cli/src/commands/workspace.rs);
- retained filesystem effects:
  [`anchored.rs`](../crates/phantom-core/src/fs/anchored.rs),
  [`transaction_lock.rs`](../crates/phantom-vault/src/transaction_lock.rs),
  [`init_transaction.rs`](../crates/phantom-vault/src/init_transaction.rs), and
  [`precommit_hook.rs`](../crates/phantom-core/src/precommit_hook.rs);
- MCP facade: [`server.rs`](../crates/phantom-mcp/src/server.rs) and
  [`params.rs`](../crates/phantom-mcp/src/tools/params.rs);
- inactive boundaries: the public module documentation in each execution-kernel
  crate; and
- external design benchmark: the pinned
  [Rama-derived standard](rama-design-standard.md), which is inspiration rather
  than a dependency or parity claim; and
- activation gates and non-mitigations: this document, the
  [threat model](../THREAT_MODEL.md), and public module documentation in the
  inactive crates.

Update this document when a component crosses a status boundary, when a public
constructor or transport becomes reachable, when a secret/authority field
changes, or when a platform begins or stops enforcing a filesystem or process
guarantee.
