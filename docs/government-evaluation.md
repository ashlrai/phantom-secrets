# Government evaluation guide

This guide helps a public-sector team evaluate Phantom without turning source
features or local test results into an authorization claim. Phantom's repository
source remains available under the [MIT License](../LICENSE). Ashlr AI can
separately discuss a bounded technical evaluation under written terms.

Phantom is not represented as FedRAMP authorized, FIPS validated, CMMC assessed,
or approved for any agency, impact level, controlled environment, or regulated
data class. No government contract vehicle or procurement schedule is claimed.

## Start with a local non-production boundary

Choose one reversible workflow using test accounts and non-sensitive data. Do
not begin with classified information, controlled unclassified information,
production credentials, payment movement, privileged infrastructure, public
safety systems, weapons systems, or an autonomous deployment.

Before execution, record:

1. the agency or program decision owner and technical owners;
2. the exact repository, source SHA, installed artifact, platform, and client;
3. data categories and handling rules;
4. allowed endpoints, test providers, actions, and authorization boundaries;
5. prohibited actions and stop conditions;
6. acceptance tests, evidence retention, and independent review; and
7. recovery, incident, and exit owners.

Use the [pilot acceptance template](../examples/agent-delegation/PILOT_ACCEPTANCE.md)
and [enterprise adoption guide](enterprise-adoption.md) as starting points.

## Build an evidence packet

Keep each evidence layer separate:

| Layer | Minimum evidence |
|---|---|
| Scope | Signed or approved evaluation scope, owners, systems, exclusions, and expiry. |
| Source | Full commit SHA, dirty state, dependency lock, reviewed paths, and known limitations. |
| Artifact | Immutable artifact identity, checksum, provenance evidence, and native platform result where available. |
| Configuration | Exact client, vault backend, approved service routes, audit settings, and environment assumptions without secret values. |
| Verification | Commands, outputs, failures, skipped checks, reviewer, and timestamp. |
| Deployment | Named environment, change approval, rollback, health checks, and deployment identifier. |
| Authorization and acceptance | Separate agency decision, user acceptance, residual risks, and expiry or reauthorization date. |

A passing local posture badge is not a regulatory assessment. Local HMAC audit
verification is not an independent timestamp or central record. The
[security evaluation guide](security-evaluation.md), [threat model](../THREAT_MODEL.md),
and [audit index](audit-index.md) identify the canonical review sources.

## Current blockers to treat as blockers

- No generally available Phantom hosted service or supported self-hosted
  enterprise control plane is represented.
- SSO, SAML, and SCIM are not shipped.
- Provider issuance and lifecycle operations are hard-denied in 0.7.8.
- Central audit retention and independently trusted execution receipts are not
  commissioned.
- Independent binary signing, macOS notarization, Windows Authenticode, and
  regulatory certification are not claimed.
- Same-user shell, debugger, filesystem, or terminal-control authority can
  defeat the trusted-terminal separation.

Do not work around these blockers with ambient credentials, an undocumented
endpoint, a manual database edit, or an assertion in the evaluation report.
Missing controls can be recorded as proposed work, subject to a separate scope
and acceptance gate.

## Commercial and procurement boundary

The MIT License governs the open-source rights it grants. Any evaluation,
integration, support, data-handling, residency, indemnity, response, or
procurement commitment must appear in a separate executed agreement. See
[commercial offerings](commercial-offerings.md) and [commercial support](commercial-support.md).

Email [mason@ashlr.ai](mailto:mason@ashlr.ai) with a value-free summary of the
environment and requirements. Do not include credentials, controlled data, or
operational details that are not approved for that channel.
