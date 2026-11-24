# DESIGN: Provider connector packs — proposal (not implemented)

Status: proposal. Nothing below is built.

## Problem

Provider-specific behavior is hard-coded in the CLI today: rotation providers
(`crates/phantom-core/src/rotation_provider.rs`), live validators
(`crates/phantom-core/src/validator.rs`), deployment sync targets (`phantom sync --platform vercel|railway`), and secret importers
(doppler/infisical/dotenvx/1password/env). Adding a provider means changing
CLI source. There is no third-party extension point, deliberately, since every
provider path touches credentials.

## Proposal

A **connector pack** model with a deliberately narrow, auditable surface:

- A pack is a signed manifest + a constrained capability list (for example
  `validate-only`, `sync-target`, `import-source`). No arbitrary code execution
  in the credential path; packs declare JSON-schema'd operations the CLI
  already knows how to sandbox.
- Packs are installed explicitly by the operator in a trusted terminal
  (`phantom connector add <pack>`), pinned by hash, and listed by
  `phantom connector list`. No auto-discovery, no auto-update. These commands
  do not exist; they are part of the proposal.
- The MCP surface stays value-blind: packs can add *validators* and *sync
  targets*, never new ways to exfiltrate values. Shipped builds hard-deny
  every live provider issuance and rotation path before credential or network
  access. A pack can only *request* capabilities the operator explicitly
  grants per pack.
- Distribution could be a curated registry (signed manifests, provenance
  attestations) or stay fully local (git submodules / vendored packs).
  Registry vs. vendored is the key decision below.

## Non-goals

- Not a general plugin runtime (no WASM/dylib loading into the proxy).
- No change to the `phm_` token model or vault encryption.

## Open questions

- Curated registry (discoverability, signing burden) vs. vendored packs
  (simpler, no new infrastructure)?
- Which provider should be the reference pack: a validator (for example Stripe)
  or a sync target?
- Should packs be versioned/locked alongside `Cargo.lock`-style integrity, and
  who signs the root of trust?
- Does this belong in phantom-secrets at all, or in the Phantom workbench with
  secrets exposing only the capability-request API?
