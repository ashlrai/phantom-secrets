# Local signed connector packs

Status: unreleased phase-2 source MVP following the phase-1 proposal. There is
no published marketplace, automatic discovery, network fetch or automatic
update. A pack is a local declarative JSON manifest and detached Ed25519
signature, not executable plugin code.

## Operator trust and scope

The operator obtains a public key through an independently trusted channel and
explicitly adds it with `phantom connector anchor add`. Phantom can verify that
the manifest was signed by that currently installed key; it cannot establish
the author's real identity, official provider affiliation, endpoint ownership
or distribution provenance. The short key identifier is a lookup label, not a
sufficient independent fingerprint for authenticating a publisher.

Installation retains the exact verified manifest/signature snapshot through
consent; it never rereads a mutable source directory after approval. Installed
manifests are SHA-256-pinned. Every capability load rechecks the current trust
anchor, signature, pin and signed/indexed identity. Removing an anchor leaves
the installed files present but prevents their capabilities from loading.
A mutable index pin alone cannot authorize an unsigned replacement.

Schema version 1 has no signed expiration, anti-replay, monotonic-version or
anti-rollback policy. A still-signed older pack can be manually reinstalled.
Anchor removal is the available local revocation control. `connector remove`
removes installed registry ownership; signed cache files remain inert locally,
and are not recursively deleted through ambient paths. No pack can grant
execution authority, provision credentials or activate live issuance, enrollment
exchange or provider credential rotation; those paths remain denied.

## Declared capabilities

- `validate`: HTTPS credential checks against declared destinations. Values
  are substituted into declared header values, never URLs or header names.
- `sync-target`: a POST/PUT request to a declared HTTPS destination, using a
  named vault credential and the operator's selected secret names.
- `import-source`: parse an explicitly supplied `dotenv` or `json-map` file.
  No pack command, shell, WASM or shared library is executed.

HTTPS parsing rejects embedded URL credentials and fragments. Transport ignores
ambient proxy configuration and does not follow credential-bearing redirects.
Signing and declarative syntax do not make an endpoint safe: validation and sync
send approved credential material to their declared endpoints. The operator
must review the exact destination, request and selected names. They are not
confined to an official-provider domain allowlist.

Live validation/sync retain attached-terminal consent. The displayed,
project-bound challenge binds signed provenance, destination/request details,
configuration and name selection; drift is checked again before credential
retrieval and transport. A pack sync `--dry-run` reports signed metadata without
opening a vault or inventing a secret inventory. Sync transport runs outside
Tokio's async runtime thread. These boundaries require source tests and normal
owner review; signatures alone do not establish live-provider acceptance.

## Workbench and lifecycle limits

The CLI owns these extension points. JSON inspection is available to consumers;
no deployed workbench UI or capability-request bridge is claimed. Packs add no
MCP tools and do not bypass the existing value-blind MCP approval ceremony.
Installation is local and explicit. No cross-file or cross-phase transaction,
automatic rollback, registry attestation or cloud commissioning is claimed.
