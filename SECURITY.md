# Security Policy

For the detailed technical threat model, see [THREAT_MODEL.md](./THREAT_MODEL.md). This file covers disclosure, support, researcher expectations, and the metadata Phantom may record.

## Supported Versions

Phantom is still pre-1.0, so security support is focused on the current release line and active development branch.

| Version or surface | Security support | Notes |
|--------------------|------------------|-------|
| Latest release line, currently `0.7.x` | Supported | Security fixes are prioritized for the latest published CLI, MCP server, proxy, vault, npm wrappers, and web API surface. |
| Active development branch | Supported for validation | Reports against unreleased code are welcome when the issue can affect an upcoming release or deployed service. |
| Older release lines before `0.7.x` | Best effort only | Please upgrade first when possible. Backports are not guaranteed. |
| Forks, unofficial builds, or modified binaries | Not supported | Maintainers cannot verify the provenance or behavior of modified distributions. |

### Urgent 0.7.0 upgrade notice

`0.7.0` is superseded by the `0.7.3` security fix-forward. Upgrade before using
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
- Logs or screenshots only after redacting secrets, tokens, vault contents, OAuth tokens, cookies, and personal data.

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
- Trusted-terminal provider issuance, provider endpoint selection, direct-to-vault credential handling, and value-free `phantom grant` lifecycle output.
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
- `PHANTOM_AUDIT_ENCRYPTION=local` encrypts selected context metadata locally. `PHANTOM_AUDIT_ENCRYPTION=cloud-signed` signs audit events and attempts asynchronous upload to `phm.dev`; do not enable it unless you are comfortable sending that audit metadata to Phantom Cloud.
- Audit analytics, anomaly detection, rate-limit events, and response-leak incidents are derived from the local audit log unless cloud-signed audit upload is explicitly enabled.
- Phantom Cloud receives account, device, team, billing, project, encrypted-vault, and sync metadata needed to operate the service. Vault contents are intended to be encrypted client-side before upload; the server should not receive plaintext secret values.
- The web application may send browser analytics events through PostHog when `NEXT_PUBLIC_POSTHOG_KEY` is configured. Current events include page views and high-level UI actions such as copied install commands or pricing/device-auth button clicks. These events should not include secret values or vault contents.

Do not include real secrets in support requests, vulnerability reports, screenshots, telemetry examples, or reproduction repositories.

## Known Limitations

Phantom narrows the risk of AI agents seeing real secrets, but it is not a complete endpoint security product.

- A compromised operating system, root/admin attacker, malicious debugger, or replaced `phantom` binary can defeat local protections.
- `PHANTOM_PROXY_TOKEN` is exposed to the `phantom exec` child process by design. A compromised child process can use the local proxy until the session ends.
- `phantom exec` removes `PHANTOM_VAULT_PASSPHRASE` from both proxied and direct
  child environments. It also removes ambient values for protected dotenv keys
  before selectively adding fresh session tokens. A command launched manually
  outside `phantom exec` still inherits whatever its parent shell exports.
- Standalone proxy lifecycle is foreground-only. `phantom start` persists only
  a bearerless exclusivity lock, never a PID, port, or proxy bearer. Detached
  `--daemon` mode, the external shutdown endpoint, and `phantom stop` fail
  closed; stop the proxy with Ctrl-C in its owning terminal.
- Zeroization is a partial defense in depth. Major vault retrieval,
  serialization, and decrypted-file buffers use zeroizing containers, but some
  proxy lookup copies and the file-vault passphrase remain ordinary strings.
- `.phantom.toml` does not have cryptographic integrity protection. Agentic proxy execution therefore accepts only exact built-in service routes and binds the project ID to the config directory; custom route approval is not yet supported.
- Audit logging is opt-in and local by default. It cannot prove deletion of both the audit log and its local checkpoint without external evidence.
- Team member removal does not retroactively revoke access to vault pushes that were encrypted to that member before removal. Rotate affected secrets after offboarding.
- Provider-grant issuance requires a human provider-consent flow and separately configured provider application. Source and mock tests do not prove live provider, renewal, or customer acceptance.
- `phantom grant revoke` currently fails closed before local mutation because remote revocation is not wired for the supported providers.
- A provider grant is credential lifecycle state, not an execution-kernel authority grant. It cannot activate Locus verification, a broker lease, or production engineering execution.
- GitHub immutable releases, checksums, archive-specific SPDX SBOMs, and GitHub attestations protect the published `v0.7.x` release artifacts. Installers and the self-updater verify checksums but do not yet verify attestations directly. Independent signatures, macOS notarization, Windows Authenticode, and exact-archive native acceptance remain open.

See [THREAT_MODEL.md](./THREAT_MODEL.md#7-known-gaps-and-non-mitigations) for the full list of known gaps and non-mitigations.
