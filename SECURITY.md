# Security Model

## Threat Model

Phantom is designed to prevent AI coding agents from leaking secrets. Here is the threat model and how each threat is mitigated.

### Threats Addressed

| Threat | Attack Vector | Mitigation |
|--------|--------------|------------|
| AI reads `.env` secrets | Agent reads file, secret enters LLM context | `.env` contains only phantom tokens; real secrets in OS keychain |
| Secret in LLM context leaked | Prompt injection, session logs, training data | Phantom tokens are worthless outside the local proxy |
| Malicious code exfiltrates secrets | AI generates code that sends env vars to attacker | Env vars contain phantom tokens; real secrets only injected at network layer for configured hosts |
| Phantom token brute-forced | Attacker guesses token to use proxy | 256-bit CSPRNG tokens (2^256 keyspace); proxy is localhost-only |
| Vault file stolen | Attacker copies encrypted vault | OS keychain protected by login password / Secure Enclave; file fallback encrypted |
| Secrets persist in memory | Memory dump attack | `zeroize` crate scrubs secrets from memory after use |
| Other local process abuses proxy | Process sends requests through localhost proxy | Proxy on ephemeral port; optional session token for proxy auth |
| MITM on outgoing TLS | Attacker intercepts proxy-to-API connection | rustls with system CA roots; no custom CA certificates |

### Threats NOT Addressed

- **Compromised OS**: If an attacker has root access to the developer's machine, they can read the OS keychain directly. Phantom cannot protect against a fully compromised operating system.
- **Malicious phantom binary**: If the `phantom` binary itself is compromised, all bets are off. Verify checksums and install from trusted sources.
- **Side-channel attacks**: Phantom does not defend against timing attacks or other side-channel analysis on the proxy process.

## Security Principles

1. **Real secrets never on disk in project directory** — they exist only in the OS keychain or encrypted vault
2. **Allowlist, not blocklist** — the proxy only injects secrets for explicitly configured service patterns
3. **Localhost only** — the proxy never binds to network-accessible interfaces
4. **Short-lived proxy sessions** — proxy starts with `exec`, stops when the command exits
5. **Phantom tokens are identifiable** — `phm_` prefix makes them easy to detect in code review and pre-commit hooks

## Cloud Sync Security

Phantom Cloud uses a **zero-knowledge architecture**. The server never sees your plaintext secrets.

- **Client-side encryption**: Secrets are encrypted with ChaCha20-Poly1305 before upload. The encryption key is derived from a key stored in your OS keychain and never leaves your device.
- **End-to-end encryption**: The server stores only encrypted blobs. Even Phantom Cloud operators cannot decrypt your vault.
- **Authentication**: GitHub OAuth is used for device authentication. Each device must be explicitly authorized.
- **Transport security**: All cloud API calls use TLS 1.3.

| Threat | Mitigation |
|--------|------------|
| Cloud server compromised | Zero-knowledge: server only stores encrypted blobs, cannot decrypt |
| Cloud credentials stolen | GitHub OAuth tokens are device-scoped; vault data is still encrypted |
| Man-in-the-middle on cloud API | TLS 1.3 for all cloud communication |

## Responsible Disclosure

If you discover a security vulnerability, please report it privately via GitHub Security Advisories or email security@ashlr.ai. Do not open a public issue.
