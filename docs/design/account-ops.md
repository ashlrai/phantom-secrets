# Account operations layer (value-free)

Status: library only. No CLI or MCP command calls it yet.

`phantom_core::account_ops` runs four provider-neutral operations (create,
rotate, revoke, status) and returns an opaque handle plus value-free metadata.
It supplies the two prerequisites that the shipped hard-deny in
`rotation_provider` and `issuance` names as missing:

1. A durable, value-free recovery handle written before any provider call.
2. A verified compensating revoke when the vault store fails after issuance.

## Order of checks

1. Validate request fields against strict identifier character sets, so a
   value cannot be smuggled into the ledger as a name.
2. `~/.ashlr/KILL`: any entry (file, directory, symlink, dangling symlink)
   refuses. Any error other than "not found" also refuses (fail closed).
3. Provider lookup and `supports(op)`.
4. Name binding (all operations except status): the secret name must be in
   the adapter's own namespace (`owns_name`, for GitHub the fixed prefix
   `GITHUB_APP_INSTALL_`, never the App key name). Create refuses a name that
   already exists in the vault (and fails closed if existence cannot be
   checked). Rotate and revoke also need a verified ledger record of a
   succeeded create or rotate by the same provider for the same target and
   name.
5. `plan()`: no network. The GitHub adapter refuses an empty or malformed
   token scope here.
6. Append an `intent` ledger entry with a locally minted `aop_` handle. If the
   append fails, refuse before the provider call.
7. Dry run (the default) stops here and records `dry-run`.
8. Re-check KILL, then call the provider.
9. An issued value goes only to the `ValueSink` (the vault writer) inside
   `Zeroizing`. If the sink fails, the adapter revokes the value it just
   issued, and the result is `compensated` or `compensation-failed`.
10. Append the `result` entry and mirror the name-only event into the existing
   opt-in audit log (`account_ops.<op>.<result>`). Under
   `PHANTOM_AUDIT=required` a failed mirror write sets `audited=false`.

Every adapter's metadata is filtered by the engine: keys must be snake_case
identifiers, values must pass a length and charset limit, and any entry that
contains the value just issued is withheld.

The compensating revoke after a failed store runs without a third KILL check,
because it only invalidates a token this same call just minted. Rotate does
not revoke the predecessor: a GitHub installation token stays valid until
GitHub expires it, one hour after it was minted.

## Ledger

`~/.phantom/account-ops.jsonl`, mode 0600, one JSON object per line: `seq`,
`ts`, `phase`, `actor`, `op`, `provider`, `target`, `secret_name`, `handle`,
`mode`, `result`, `reason`, `scope`, `prev_sha256`, `sha256`. Each `sha256`
covers the line with `sha256` empty, chained from `GENESIS`. A head anchor,
`account-ops.jsonl.head` (`"<seq> <sha256>"`, 0600), records the last entry
outside the file. `OpsLedger::verify` detects edits, deletions, reorders and
truncation, and every append verifies first and refuses a broken ledger.
Both files are opened with `O_NOFOLLOW` and must be regular files owned by
the caller with no group or other bits; a missing `~/.phantom` is created
0700. A same-user process that rewrites both files consistently is not
detected; the anchor is a tamper signal, not a signature. Values never
appear.

## GitHub App adapter

`github-app`, target `installation:<id>`:

| Operation | Call | Auth |
|---|---|---|
| create, rotate | `POST /app/installations/{id}/access_tokens` with a required `repositories` list and `permissions` map | App JWT signed in process from the vaulted PEM |
| revoke, compensation | `DELETE /installation/token` | the token being revoked, only if it has the `ghs_` installation-token shape |
| status | `GET /app/installations/{id}` | App JWT |

Installation tokens expire one hour after creation. The live transport is
https-only with no proxy and no redirects, a bounded body and a sensitive
Authorization header. Error reasons carry only the HTTP status and allowlisted
fields.

## Tests

`crates/phantom-core/src/account_ops/tests.rs` uses a fake provider, a fake
GitHub transport and a runtime-generated throwaway RSA key. One test re-runs
the test binary as a child process with an isolated `HOME` and
`PHANTOM_AUDIT=1`, drives every path, and asserts no fake value appears in
the child's stdout, stderr, ledger or audit log.

## Not in this change

- CLI and MCP wiring, and lifting the existing `GitHubRotationProvider`
  hard-deny. Both need Security review.
- Other providers (npm trusted publishing, Devin, Anthropic, Apple
  notarization).
