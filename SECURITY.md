# Security Policy

For the detailed technical threat model, see [THREAT_MODEL.md](./THREAT_MODEL.md). This file covers disclosure, support, researcher expectations, and the metadata Phantom may record.

## Supported Versions

Phantom is still pre-1.0, so security support is focused on the reviewed public
release and active development branch. Repository version metadata can move
ahead of published artifacts.

The table below is a release-state snapshot verified on 2026-09-05. The
immutable `v0.7.8` GitHub release binds its 19 assets to source commit
`f065b13462f9eaf27e0443f8911f021575b7c409`; all six native rows and the
GitHub provenance and SPDX attestations are bound to that immutable release.

| Version or surface | Security support | Notes |
|--------------------|------------------|-------|
| Reviewed GitHub release, `v0.7.8` | Supported | Security fixes are prioritized for the immutable GitHub release and active development. Its native artifacts passed the tag-bound six-row release workflow; this is not a signing, notarization, certification, hosted-service, or customer-acceptance claim. |
| Registry distributions | Mixed | The exact 2026-09-05 snapshot has Homebrew `v0.7.8` supported after native macOS/Linux checks, while npm `latest` remains `0.6.0` and its `0.7.4` wrappers remain failed release candidates rather than the default install path. crates.io and MCP Registry do not yet publish `0.7.8`. |
| Releases before `v0.7.4` | Best effort only | Please upgrade first when possible. Backports are not guaranteed. |
| Forks, unofficial builds, or modified binaries | Not supported | Maintainers cannot verify the provenance or behavior of modified distributions. |

### Urgent 0.7.0 upgrade notice

`0.7.0` is superseded by the reviewed `v0.7.8` GitHub release. Upgrade before using
Phantom Cloud, team-vault, local proxy, protected connection-string,
provider-rotation, or agent execution workflows. The immutable `0.7.0` release
remains available as historical evidence and will not be edited in place.

The local vault namespace changes in `0.7.3`. For an offline-only `0.7.0`
checkout, create an encrypted `phantom export --output FILE` backup from a
trusted terminal before upgrading, then restore it with `phantom import FILE`.
Cloud/team users may instead restore through an encrypted pull. Phantom does
not automatically reopen the former 64-bit local namespace.

## Reporting a Vulnerability

Please report suspected vulnerabilities privately. Do not open a public GitHub issue for a security report.

Private reporting channel:

- Email: [security@ashlr.ai](mailto:security@ashlr.ai)
- [GitHub private vulnerability reporting](https://github.com/ashlrai/phantom-secrets/security/advisories/new)

Please include:

- Affected component: CLI, provider issuance/grants, MCP server, local proxy, vault, Phantom Cloud/web API, npm wrapper, install script, release artifact, or documentation.
- Affected version, commit, operating system, install method, and any relevant configuration flags.
- Reproduction steps, proof of concept, expected impact, and whether you believe the issue is actively exploitable.
- Logs or screenshots only after redacting secrets, tokens, vault contents,
  OAuth tokens, cookies, personal data, and persistent `phm_` mappings.

Use throwaway test credentials whenever possible. If you encounter a real credential, stop testing, redact it from your report, and rotate the credential.

## Response Targets (SLA)

These are response targets, not contractual promises or service-level warranties.

| Step | Target |
|------|--------|
| Initial acknowledgement | Within 3 business days |
| Triage and severity assessment | Within 7 business days after enough detail is available |
| Remediation plan for confirmed high or critical issues | Within 14 business days when the issue is reproducible and under project control |
| Coordinated public disclosure | Normally after a fix is available, or after 90 days by mutual agreement |

If there is evidence of active exploitation, say so in the report subject and body.

## Scope

In scope:

- `phantom` CLI behavior that can expose, corrupt, or misuse secret material.
- The MCP server and tools, especially paths that accept input from AI agents.
- Local proxy authentication, request rewriting, response scrubbing, and secret injection behavior.
- Local vault storage, keychain integration, encryption, import/export, and rotation flows.
- The universal pre-credential/pre-network denial for provider issuance, enrollment, refresh, renewal, rotation, and revocation, plus value-free grant metadata.
- Phantom Cloud, device auth, cloud sync, team vault APIs, billing/auth boundaries, and deployed `phm.dev` security controls.
- npm packages, install scripts, release artifacts, checksums, and wrapper behavior when they affect install trust.
- Documentation that could cause users to leak secrets or rely on a security property that Phantom does not provide.

Out of scope unless paired with a concrete Phantom-specific security impact:

- Denial-of-service, spam, scraping, or resource-exhaustion reports.
- Social engineering, phishing, physical attacks, or attacks requiring root/admin control of a developer machine.
- Vulnerabilities only in third-party services, package managers, GitHub, Stripe, Supabase, PostHog, or OAuth providers.
- Scanner-only findings without a reproducible exploit path.
- Self-XSS, browser UI polish issues, or missing security headers on non-sensitive static pages.
- Public disclosure before maintainers have had a reasonable chance to investigate.

## Safe Harbor

We will not pursue legal action on behalf of Phantom or AshlrAI for good-faith research that:

- Stays within this policy and avoids privacy violations, data destruction, persistence, and lateral movement.
- Uses the minimum access needed to prove impact.
- Does not exfiltrate secrets, vault contents, OAuth tokens, cookies, payment data, or personal data beyond what is strictly necessary for a proof of concept.
- Reports the issue privately and gives maintainers a reasonable opportunity to remediate before public disclosure.

This safe harbor is not legal advice and cannot bind third parties or platforms outside Phantom's control.

## Rewards and Acknowledgement

Phantom does not operate a paid bug bounty program at this time. We may acknowledge valid reports in release notes or advisories if the reporter wants credit, but no payment, reward, swag, or public acknowledgement is promised.

## Telemetry, Audit, and Metadata Disclosure

Phantom's security boundary is that secret values should not enter AI context, logs, telemetry, or cloud services in plaintext. Metadata may still be created by the product:

- CLI audit logging is off by default. When `PHANTOM_AUDIT=1` or `PHANTOM_AUDIT=required` is set, Phantom writes JSONL audit events under `~/.phantom/` with operation names, timestamps, sequence/HMAC data, process metadata, PID, and secret names when an operation is tied to a specific secret. Audit events must never contain secret values.
- `PHANTOM_AUDIT_ENCRYPTION=local` encrypts selected context metadata locally. `cloud-signed` remains a protocol-only reserved value: setup refuses it before mutation, and legacy shell settings retain events with local encryption while making no audit-delivery network request.
- Audit analytics, anomaly detection, rate-limit events, and response-leak incidents are derived from the local audit log. Central audit collection, retention, signer enrollment, and independent reviewer workflows are not commissioned in this release.
- Phantom Cloud receives account, device, team, billing, project, encrypted-vault, and sync metadata needed to operate the service. Vault contents are intended to be encrypted client-side before upload; the server should not receive plaintext secret values.
- The web application may send browser analytics events through PostHog when `NEXT_PUBLIC_POSTHOG_KEY` is configured. Current events include page views and high-level UI actions such as copied install commands or pricing/device-auth button clicks. These events should not include secret values or vault contents.

Do not include real secrets in support requests, vulnerability reports, screenshots, telemetry examples, or reproduction repositories.

For non-security questions, use the routes in [SUPPORT.md](SUPPORT.md). Project
decision and escalation authority is described in
[GOVERNANCE.md](GOVERNANCE.md).

## Known Limitations

Phantom narrows the risk of AI agents seeing real secrets, but it is not a
complete endpoint security product. Its operator boundary is meaningful only
when the trusted terminal, vault or native credential store, and user
configuration roots are outside the agent's authority. Giving an agent
equivalent same-user shell, filesystem, debugger, or terminal-control authority
defeats that separation; Phantom does not convert a same-user process into a
sandboxed principal.

- A compromised operating system, root/admin attacker, malicious debugger, or replaced `phantom` binary can defeat local protections.
- `PHANTOM_PROXY_TOKEN` is exposed to the `phantom exec` child process by design. A compromised child process can use the local proxy until the session ends.
- `phantom exec` removes `PHANTOM_VAULT_PASSPHRASE`, inherited proxy session
  controls/base URLs, every configured service credential, rotation bootstrap,
  sync token, and connection-string variable from both proxied and direct child
  environments before selectively adding fresh session tokens for protected API
  keys. A command launched manually
  outside `phantom exec` still inherits whatever its parent shell exports.
- Standalone proxy lifecycle is foreground-only and requires all three standard
  streams to be terminals before vault access. The stable exclusivity lock is
  advisory state in the OS user-data directory keyed by the local project
  identity and contains no PID, port, or bearer. Unix permissions are
  restricted; on Windows Phantom relies on the inherited directory ACL and
  does not independently verify its effectiveness. A held lock is not listener
  authentication. Detached `--daemon` mode and external shutdown fail closed.
  `phantom stop` authenticates legacy v0.7.3 state only to report migration
  guidance; it never kills a process or deletes the record. Stop a current
  proxy with Ctrl-C in its owning terminal.
- Client-controlled request headers and bodies never resolve phantom tokens.
  After authentication and exact route matching, the proxy injects only that
  route's configured vault secret into its fixed authentication header; a
  missing mapping fails before any upstream call. Connection-string tokens are
  never registered. Credential-bearing upstream HTTP ignores inherited
  `HTTP_PROXY`, `HTTPS_PROXY`, and `ALL_PROXY`; enterprise forward proxies are
  intentionally unsupported until a separately reviewed trust configuration exists.
- Zeroization is a partial defense in depth. Major vault retrieval,
  serialization, and decrypted-file buffers use zeroizing containers, but some
  proxy lookup copies and the file-vault passphrase remain ordinary strings.
- `.phantom.toml` does not have cryptographic integrity protection. Agentic proxy execution therefore accepts only exact built-in service routes and binds the project ID to the config directory; custom route approval is not yet supported.
- Governed project and client-configuration writers retain their acquisition-time
  directory identity, reject outside-root and symlink/reparse traversal, reject
  multiply linked sensitive files, and compare exact target identity plus bytes.
  These controls prevent an ambient rename-and-decoy swap from redirecting the
  governed operation; they do not exclude a process with equivalent same-user
  authority before acquisition or after handles are released.
- Vault-backed project mutations resolve process-environment-dependent
  vault/application authority before acquiring the project transaction lock,
  then compare the acquired directory identity and reread exact config state.
  This avoids the inverse lock order and rejects a same-path root replacement
  during vault resolution.
- Initialization binds both the reviewed project-root identity and exact leaf
  identity, bytes, and permissions before vault provisioning, then revalidates
  them after acquiring the project lock and before mutation. A byte-identical
  replacement leaf or same-path replacement root is rejected as drift.
- `CommittedVerifiedButDurabilityUncertain` is a committed and exactly verified
  success with a value-free warning/receipt; callers must not roll it back or
  retry it. It is distinct from `CommittedButUncertain`, a **Partial** outcome
  where post-publish verification or durability is unresolved and the operator
  must reconcile before retrying.
- On Windows, new private anchored files/directories establish and verify a
  protected current-user DACL before bytes are written; replacements preserve
  and verify the reviewed exact DACL, inheritance state, and read-only state
  before writing. Windows no-follow, ACL, and shared-handle behavior is
  source-contract tested, but protected native Windows filesystem and
  Credential Manager acceptance remains pending.
- Audit logging is opt-in and local by default. It cannot prove deletion of both the audit log and its local checkpoint without external evidence.
- Team member removal does not retroactively revoke access to vault pushes that were encrypted to that member before removal. Rotate affected secrets after offboarding.
- All live provider issuance, enrollment exchange, refresh, renewal, and revocation paths are hard-denied before credential or network access in 0.7.8. Source adapters and exact `cfg(test)` mocks demonstrate local transaction scaffolding only; they do not prove provider activation, renewal, commissioning, or customer acceptance.
- `phantom grant revoke` currently fails closed before local mutation because remote revocation is not wired for the supported providers.
- A provider grant is credential lifecycle state, not an execution-kernel authority grant. It cannot activate Locus verification, a broker lease, or production engineering execution.
- GitHub immutable release controls, checksums, archive-specific SPDX SBOMs, and GitHub attestations protect the published exact `v0.7.8` release artifacts at source commit `f065b13462f9eaf27e0443f8911f021575b7c409`. All six native release rows and both attestation predicates are bound to that immutable release record. Installers and the self-updater verify checksums but do not yet verify attestations directly. Independent signatures, macOS notarization, Windows Authenticode, protected native credential-store/ACL/editor acceptance, and npm-channel acceptance remain open.

See [THREAT_MODEL.md](./THREAT_MODEL.md#7-known-gaps-and-non-mitigations) for the full list of known gaps and non-mitigations.
