# Signing and notarization readiness

Phantom's current release workflow contains no Apple Developer ID signing,
Apple notarization, Windows Authenticode signing, or Azure Artifact Signing
step. The committed
[`release-signing-policy.json`](../.github/release-signing-policy.json) is
explicitly `disabled`, and no signing credential, protected signing
environment, provider action, or signing-specific OIDC permission is wired into
the workflows.

The policy validator, receipt schema, and fictional fixtures in this repository
are readiness contracts only. Their presence does not enable signing, authorize
a provider operation, prove that a credential or provider account exists, or
show that a released artifact was signed. GitHub artifact attestations remain
separate from independent publisher signatures. This source review does not
establish the signing state of a previously hosted artifact; verify an exact
download independently before making that claim.

## Current source contract

The policy has only two legal states:

- `disabled`: the only current state; both platform objects must also be closed
  `disabled` objects with no provider configuration.
- `required`: a future fail-closed state that is valid only when the complete
  macOS and Windows configuration is present. There is no `optional`, `auto`,
  or partially configured mode.

[`signing-readiness.mjs`](../scripts/release/signing-readiness.mjs) is a pure
validator. It reads no environment variables, files, credentials, or network
state and starts no subprocess. The schema
[`signing-receipt.schema.json`](../scripts/release/signing-receipt.schema.json)
describes a future sanitized `SIGNING-RECEIPTS.json` evidence file. The current
19-file GitHub release bundle does not include that file; adding it would be a
separate reviewed release-contract change.

The pure source validators reconcile already-collected, value-free evidence;
they do not inspect binaries, invoke `codesign` or `signtool`, or query Apple or
Microsoft. Cryptographic and provider verification must happen in the future
protected native jobs before those jobs construct a receipt. The validators
then reject:

- an unknown policy state, a mixed platform state, partial required
  configuration, or an unknown field;
- a non-stable release tag, including leading-zero versions and every
  prerelease or build-metadata form; signing evidence accepts only the strict
  `vX.Y.Z` contract used by the pre-tag release gate;
- a missing, duplicated, or reordered signing input;
- a receipt whose tag, source SHA, unsigned digest, signing subject, provider
  identity, target, or binary does not match the approved inputs;
- a receipt that does not record successful native signature verification;
- missing hardened runtime, non-accepted notarization, incorrect raw-binary
  stapling claims, an invalid Windows timestamp, or evidence timestamps in an
  impossible order; and
- any signed receipt presented while the policy is `disabled`.

## Future gated design — not implemented

Moving the policy to `required` is not sufficient to enable signing. A separate
reviewed implementation must preserve a 22-job fail-closed order:

1. Six raw-build jobs produce the exact binaries for the supported target
   matrix and bind their SHA-256 digests to the source SHA and tag.
2. Two signing jobs consume only those approved bytes: one macOS job signs both
   macOS architectures, and one Windows x64 job signs both Windows
   architectures.
3. Six package-and-SBOM jobs construct archives and SPDX documents from the
   signed macOS/Windows bytes and the unchanged Linux bytes.
4. Six native-acceptance jobs install and execute the exact final archives on
   their target operating-system and architecture rows.
5. One source-verification job and one exact-bundle verification job complete
   the 22-job graph before attestation or publication.

No job may package, attest, or publish unsigned macOS or Windows bytes after
signing becomes required. A signing, notarization, timestamping, receipt, or
verification failure must stop the graph; there is no unsigned fallback.
Linux remains unsigned, with its existing checksum, SBOM, provenance, and
native-acceptance controls.

### Future macOS gate

The future macOS job must run behind a protected `release-sign-macos`
environment with required human reviewers. It must import a Developer ID
Application identity into an ephemeral keychain, sign `phantom` and
`phantom-mcp` for both Apple targets with the hardened runtime, and verify each
signed binary with `codesign` before packaging.

Notarization must use `notarytool`, preserve the submission identifier, require
Apple's terminal `Accepted` status, and verify the accepted submission
container. For each architecture, the evidence must bind the submitted ZIP,
package, or disk-image SHA-256 and its exact two signed member digests to the
approved signed binaries. Developer ID verification must also prove the
hardened runtime and secure signing timestamp, and the sanitized evidence must
match the exact Apple team ID in the reviewed required policy. Raw Mach-O
CLI binaries cannot carry a stapled notarization ticket, so the receipt must say
`not_applicable_raw_binary`; it must never claim the raw binaries were stapled.
The final archives must be built from the exact signed and notarization-approved
bytes.

The proposed environment identifiers are exact:

- secrets: `APPLE_DEVELOPER_ID_CERTIFICATE_P12`,
  `APPLE_DEVELOPER_ID_CERTIFICATE_PASSWORD`, and
  `APPLE_NOTARYTOOL_KEY_P8`;
- variables: `APPLE_DEVELOPER_ID_APPLICATION`, `APPLE_TEAM_ID`,
  `APPLE_NOTARYTOOL_KEY_ID`, and `APPLE_NOTARYTOOL_ISSUER_ID`.

These names are design inputs, not evidence that the secrets, variables,
environment, Apple account, certificate, or notary profile is configured.

### Future Windows gate

The future Windows signing job must run on `windows-latest` x64 behind a
protected `release-sign-windows` environment with required human reviewers. It
must use Azure Artifact Signing with OIDC to sign both the
`x86_64-pc-windows-msvc` and `aarch64-pc-windows-msvc` `phantom.exe` and
`phantom-mcp.exe` inputs. Each result must retain a trusted timestamp and pass
native Authenticode verification before packaging. The job's permissions must
remain `contents: read` plus job-scoped `id-token: write`; Azure login must use
only the reviewed federated OIDC credential path, with no client secret or
fallback authentication. Provider actions must be pinned to reviewed immutable
commits.

The required policy pins Microsoft's reviewed Artifact Signing timestamp
authority, `http://timestamp.acs.microsoft.com`. The receipt must match that
exact value. It cannot contain URL credentials, query parameters, or fragments.
This provider-documented HTTP RFC 3161 endpoint is a narrow exception to the
general HTTPS-only network policy; do not generalize it to any other endpoint.

The proposed environment variables are exact: `AZURE_CLIENT_ID`,
`AZURE_TENANT_ID`, `AZURE_SUBSCRIPTION_ID`,
`AZURE_ARTIFACT_SIGNING_ENDPOINT`, `AZURE_ARTIFACT_SIGNING_ACCOUNT_NAME`, and
`AZURE_ARTIFACT_SIGNING_CERTIFICATE_PROFILE_NAME`. No long-lived Azure client
secret is part of the design. These names are not evidence that GitHub OIDC,
Azure federation, an Artifact Signing account, a certificate profile, or the
protected environment is configured.

## Sanitized receipt boundary

A future successful signing tranche may create an internal
`SIGNING-RECEIPTS.json` that conforms to the committed schema and validator. It
contains only:

- release tag and source SHA;
- approved unsigned and observed signed SHA-256 digests;
- expected signer subjects, the Apple team ID, and provider account/profile
  identifiers;
- signature-verification results;
- Apple submission identifier, accepted status, hardened-runtime state, and
  bounded timestamps; and
- Windows timestamp authority, valid status, and bounded timestamps.

The receipt is generated only after the native verification commands and
provider-status reconciliation succeed. The pure validator checks its closed
shape, identities (including the exact Apple team ID), digests, and chronology,
but the validated JSON is not by itself cryptographic or provider proof. Schema
conformance alone is also insufficient: the pure semantic validator must pass
against the reviewed policy and signing inputs. Preserve the native command and
provider receipts separately
under the protected release evidence policy.

The sanitized receipt must never contain certificate material, passwords, private keys,
tokens, OIDC assertions, authorization headers, environment dumps, raw provider
responses, or command output that may embed credentials. It is evidence to
review, not authority to sign, attest, or publish, and it is not currently a
release asset.

## Activation and recovery gates

Signing can be commissioned only through a separate consequential change that:

1. changes the policy atomically from `disabled` to a complete `required`
   policy;
2. adds and reviews the 22-job graph without widening unrelated workflow
   permissions or triggers;
3. provisions the protected environments and exact external configuration
   outside agent authority;
4. verifies Apple and Microsoft provider enrollment from trusted operator
   sessions;
5. exercises failure fixtures and exact native acceptance with value-free
   receipts; and
6. receives explicit maintainer approval after source, provider, and generated
   artifact reconciliation.

On partial failure, preserve only sanitized identifiers and digests, reconcile
the provider's terminal status from a trusted operator session, destroy
ephemeral local credentials, and rerun from clean raw inputs. Never reuse a
partially signed bundle. If a defective immutable release was already
published, use a higher fix-forward tag; do not move or overwrite the tag or
release.

See [Release and readiness](release-readiness.md) for the current release gates
and the distinction between source, artifact, provider, and publication proof.
