# Hacker News Submission

**Title:** Show HN: Phantom – Stop AI coding agents from leaking your API keys

**URL:** https://phm.dev

---

## First Comment

I built Phantom because I watched Claude Code read my .env, grab my OpenAI key, and paste it into a shell script. The key was now in a file on disk, in session history, and in API logs. I didn't ask it to — it just wired things up like a good agent does.

The core architecture: `phantom init` replaces every real secret in your .env with a phantom token — a 256-bit CSPRNG value prefixed with `phm_`. Your real keys go into the OS keychain (macOS Keychain / Linux Secret Service / encrypted file fallback). The AI reads your .env and sees tokens that parse like API keys but are cryptographically worthless.

When you run `phantom exec -- claude`, a local reverse proxy starts on 127.0.0.1. It rewrites `OPENAI_BASE_URL` to point at localhost. Your code (or the AI's code) sends requests there with phantom tokens; the proxy swaps them for real credentials and forwards over TLS to the actual API. Not a MITM proxy — no CA certs, no TLS interception. Standard reverse proxy pattern.

Allowlist model: secrets only go to configured endpoints. Localhost-bound. Session-scoped — proxy dies when your session ends.

5-crate Rust workspace. 56 tests. MIT licensed. No SaaS dependency.

```
npx phantom-secrets init
```

GitHub: https://github.com/ashlrai/phantom-secrets
