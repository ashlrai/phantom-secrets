# DESIGN: Provider connector packs — IMPLEMENTED (MVP)

Status: MVP implemented as `phantom connector` + `phantom_core::connector`.
The design below was the proposal; the implementation notes at the end record
the decisions taken.

## Problem

Provider-specific behavior is hard-coded in the CLI today: rotation providers
(`crates/phantom-core/src/rotation_provider.rs`), live validators
(`validator.rs`), deployment sync targets (`phantom sync --platform
vercel|railway`), and secret importers (doppler/infisical/dotenvx/1password/env).
Adding a provider means changing CLI source. There is no third-party extension
point — deliberately, since every provider path touches credentials.

## Proposal

A **connector pack** model with a deliberately narrow, auditable surface:

- A pack is a signed manifest + a constrained capability list (e.g.
  `validate-only`, `sync-target`, `import-source`). No arbitrary code execution
  in the credential path; packs declare JSON-schema'd operations the CLI
  already knows how to sandbox.
- Packs are installed explicitly by the operator in a trusted terminal
  (`phantom connector add <pack>`), pinned by hash, and listed by
  `phantom connector list`. No auto-discovery, no auto-update.
- The MCP surface stays value-blind: packs can add *validators* and *sync
  targets*, never new ways to exfiltrate values. The existing hard-denial
  posture (0.7.9 denies all live provider issuance/rotation) remains the
  default; a pack can only *request* capabilities the operator explicitly
  grants per pack.
- Distribution could be a curated registry (signed manifests, provenance
  attestations) — or stay fully local (git submodules / vendored packs).
  Registry vs. vendored is the key decision below.

## Non-goals

- Not a general plugin runtime (no WASM/dylib loading into the proxy).
- No change to the `phm_` token model or vault encryption.

## Questions for Mason

- Curated registry (discoverability, signing burden) vs. vendored packs
  (simpler, no new infrastructure)?
- Which provider should be the reference pack — a validator (e.g. Stripe) or a
  sync target?
- Should packs be versioned/locked alongside `Cargo.lock`-style integrity, and
  who signs the root of trust?
- Does this belong in phantom-secrets at all, or in the Phantom workbench with
  secrets exposing only the capability-request API?

## Implementation notes (phase 2 MVP)

Decisions taken (defaults; reversible):

- **Vendored + signed, no registry.** Packs are installed from a local
  directory (`phantom connector add <dir>`); there is no curated registry and
  no network fetch. This answers the registry-vs-vendored question for the
  MVP: vendored keeps the supply chain fully in the operator's hands, and a
  registry can be layered later as "signed pack directories over HTTPS"
  without changing the manifest format.
- **Reference pack: a validator.** The scaffolded template (`phantom
  connector pack init`) ships a `validate` capability example; validator
  packs are the primary MVP path and join `phantom validate` automatically.
- **Integrity = Ed25519 signature + SHA-256 hash pin.** The manifest is
  signed (detached `connector.sig`, `<key-id>:<hex-signature>`); trust
  anchors live in `~/.phantom/connectors/anchors/` (trust-on-first-use —
  the operator vouches for the first anchor they add). Installed packs are
  hash-pinned in `installed.json` and re-verified on every load, so
  post-install tampering fails closed. There is no separate "root of trust"
  ceremony beyond the operator's anchor management; document accordingly.
- **It lives in phantom-secrets.** The CLI already owns the validator, sync,
  and importer extension points, so packs plug in here; the workbench
  consumes them through `--json` surfaces (`connector list --json`,
  validate reports). A capability-request API for the workbench is future
  work, not a blocker.
- **Capability boundaries enforced at install time:** validator URLs must be
  `https://` and must not contain `{value}` (values travel in declared
  header values only, never in URLs that could land in logs); sync targets
  are POST/PUT to HTTPS with the credential resolved from the vault by name;
  import sources parse `dotenv` or `json-map` files the operator hands over.
- **No WASM/dylib, no arbitrary code** — the non-goal stands; the manifest
  is purely declarative.
- **MCP surface untouched.** Connector management is CLI/trusted-terminal
  only; packs cannot add MCP tools or new exfiltration paths.
