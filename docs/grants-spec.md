# Phantom Grants — Design-Era Lifecycle Specification

> **Status: historical design document, not shipped provider behavior.**
> Phantom 0.7.8 hard-denies every live provider issuance, enrollment exchange,
> refresh, renewal, rotation, and revocation path before provider credential
> access and before network I/O. Exact `cfg(test)` mocks exercise local
> transaction scaffolding only; they are not provider activation,
> commissioning, or acceptance.

## Purpose

This document records the intended long-term design for provider credential
lifecycle grants. It is useful architecture input, but it is not a command
guide and must not be read as evidence that any provider has been enabled.
Current behavior is defined by the root README, CLI `--help`, security policy,
and threat model.

A future **provider grant** would record a human consent ceremony, the vaulted
root material created by it, and the protocol required to renew or revoke its
credentials. It is separate from an execution-kernel **authority grant**. A
provider grant cannot become a Locus credential, broker lease, or permission
for an agent to execute work.

## 0.7.8 enforced boundary

- Production provider dispatch returns a hard denial before reading bootstrap
  credentials from the environment or vault and before opening a network
  connection.
- The denial applies equally to CLI single-provider rotation, batch rotation,
  MCP provider rotation, grant enrollment exchange, additive issuance, rolling
  refresh, and remote revocation.
- Vercel, Google, GitHub, Stripe, AWS, Sentry, Supabase, and generic provider
  identifiers have no live exception.
- Local `phm_` placeholder remapping is not provider rotation and must not
  advance provider lifecycle metadata.
- Source adapters, protocol parsers, and test-only mock issuers are design and
  transaction evidence only. They do not prove provider applications,
  permissions, consent screens, vendor responses, cleanup, rollback, customer
  workflows, or production acceptance.

Operators must rotate credentials through the provider's trusted interface and
then use Phantom's trusted local secret-entry path. No README or example command
in 0.7.8 should invite a live vendor issuance call.

## Provider mechanics under consideration

The research that motivated the design identified four broad shapes. Each
remains future work until its failure modes have a durable recovery contract.

### 1. Additive successor

A provider can create a successor without invalidating the predecessor (for
example, a new version or installation token). This is safer than destructive
rotation but can still orphan a live credential if local persistence or
verification fails after issuance. Enabling it requires:

1. durable intent before the provider call;
2. a value-free issuance receipt that survives process failure;
3. recoverable successor escrow or a provider-verified abort;
4. compare-and-swap local persistence;
5. explicit cleanup state and safe retry semantics;
6. live acceptance against a throwaway provider account.

The source contains design foundations for Vercel, Google Secret Manager,
GitHub App installation tokens, Sentry installation tokens, and Supabase modes.
None is live in 0.7.8.

### 2. Destructive or rolling refresh

Some refresh exchanges may invalidate or replace the predecessor as part of
issuance. Stripe OAuth refresh and the destructive Supabase mode illustrate
this shape. A local crash between provider success and durable successor
recovery can strand the operator. These paths require provider-specific
successor escrow and verified abort/reconciliation before they may be enabled.

### 3. App identity and human enrollment

GitHub App manifests, integration installs, OAuth authorization-code flows, and
similar ceremonies can seed durable application identity. Future enrollment
must bind exact provider endpoints, redirect URIs, CSRF state, PKCE where
available, scopes, account identity, and a trusted-terminal human ceremony.
The presence of protocol source does not commission this workflow.

### 4. Manual lifecycle

Where no safe API exists, Phantom should remain honest: metadata and reminders
may point the operator to the provider's trusted interface, but Phantom must not
pretend a local token remap changed the vendor credential.

## Required transaction invariants before activation

Any future provider implementation must satisfy all of these in production,
not only under mocks:

- **Fail before credential/network on unsupported paths.** No heuristic
  fallback and no alternate credential-bearing endpoint.
- **No value in output or receipts.** Values remain in zeroizing memory and
  approved vault storage; terminal, JSON, MCP, logs, and audit events are
  value-free.
- **Durable successor recovery.** A process crash after provider issuance
  cannot lose the only usable successor.
- **Verified abort or reconciliation.** Phantom can prove whether a partially
  issued successor exists and direct a safe next action without blind retry.
- **Store-before-cleanup where provider semantics allow it.** Cleanup never
  runs before the successor is durably recoverable.
- **Compare-and-swap local state.** Concurrent config, dotenv, metadata, and
  vault changes cannot be silently overwritten.
- **Provider-bound identity.** Bootstrap material is sent only to the exact
  reviewed provider/account endpoint and never selected from secret-name
  heuristics.
- **Independent acceptance.** Live throwaway-account tests validate scopes,
  issuance, persistence failure, retry, revocation/cleanup, and rollback on
  every supported OS before public activation claims.

## Future command model (not active)

The intended model separates metadata inspection from provider execution:

```text
grant list/status       value-blind local lifecycle metadata
grant add/revoke        trusted-terminal provider ceremony, currently denied
rotate --name/--provider provider execution, currently denied
rotate --batch          metadata/manual guidance only in 0.7.8
MCP provider rotation   effect-gated compatibility surface, still denied
```

Confirmation and MCP approval are necessary authorization controls, but they do
not make an unsafe provider transaction recoverable. The production denial
remains in force even after confirmation.

## Roadmap — no shipped provider-issuance checkmarks

- [ ] Durable provider-agnostic issuance intent and recovery journal
- [ ] Successor escrow or provider-verified abort for additive issuance
- [ ] Rolling-refresh recovery for Stripe/Supabase destructive modes
- [ ] Provider-specific cleanup and idempotent reconciliation receipts
- [ ] Trusted-terminal enrollment ceremonies with exact endpoint binding
- [ ] Native macOS, Linux, and Windows provider failure-path acceptance
- [ ] Grant-aware metadata-only MCP status surface
- [ ] Safe provider-backed scheduler after transaction activation
- [ ] Remote revocation that cannot destroy local recovery state first
- [ ] Customer acceptance and operational rollback evidence per provider

Until those gates are implemented and accepted, the correct 0.7.8 behavior is
the universal pre-credential, pre-network denial described above.
