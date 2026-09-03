# Security evaluation guide

Use this guide to review the security boundary that Phantom actually ships.
The [threat model](../THREAT_MODEL.md), [security policy](../SECURITY.md), code,
tests, and exact release evidence remain authoritative; this page is a review
route, not a certification or independent audit.

## State the intended control precisely

Phantom is designed to let a supported agent-driven HTTP workflow use a
configured provider credential without placing the provider value in the
managed dotenv context. The shipped local path combines phantom placeholders,
a local vault, explicit service mappings, and an authenticated loopback proxy.

That boundary does not make the AI agent trustworthy, isolate a same-user
process, secure the operating system, certify the organization, or authorize a
provider or production action.

## Verify the evaluation inputs

Record the repository, full source SHA, dirty state, installed artifact and
checksum, operating system and architecture, vault backend, AI client, and
Phantom configuration. Then run the read-only and test commands appropriate to
the exact version, including the paths in:

- [Getting started](getting-started.md)
- [Platform support](platform-support.md)
- [Security and audit index](audit-index.md)
- [Release readiness](release-readiness.md)
- [Signing and notarization readiness](signing-and-notarization.md)

Do not copy a result from another operating system, commit, artifact, or
deployment and represent it as acceptance for the evaluated environment.

## Review the trust boundaries

At minimum, test and document:

- whether real provider values remain absent from source, managed dotenv files,
  agent prompts, transcripts, generated files, and retained logs;
- vault-backend behavior, recovery, and permissions on the evaluated platform;
- exact route matching, proxy authentication, fixed header injection, request
  bounds, and response redaction limits;
- process-environment scrubbing and the child process's authorized proxy scope;
- consequences of same-user shell, filesystem, debugger, and terminal control;
- audit enablement, metadata sensitivity, local-chain limits, and retention;
- client setup behavior and any client- or extension-specific authority;
- provider, cloud, team, deployment, and billing paths that are disabled or not
  commissioned; and
- release integrity, native acceptance, signing, and installer limitations.

Use test credentials and a reversible non-production workflow. A scanner result
or passing unit test supports only the layer it exercised.

## Current non-claims

Phantom does not claim a completed independent security audit, paid bug bounty,
regulatory certification, generally available hosted control plane, shipped
SSO/SAML/SCIM, contractual SLA, or supported self-hosted enterprise control
plane. The local compliance status is a product posture check, not SOC 2, ISO
27001, PCI DSS, HIPAA, FedRAMP, FIPS, or another external attestation.

## Report findings

Report a suspected vulnerability privately using
[GitHub private vulnerability reporting](https://github.com/ashlrai/phantom-secrets/security/advisories/new)
or [security@ashlr.ai](mailto:security@ashlr.ai). Do not open a public issue or
include real credentials, vault contents, cookies, personal data, or persistent
token mappings. Use [SUPPORT.md](../SUPPORT.md) for non-security questions.
