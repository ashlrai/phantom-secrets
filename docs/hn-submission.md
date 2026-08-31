# Hacker News Submission

**Title:** Show HN: Phantom – Stop AI coding agents from leaking your API keys

**URL:** https://phm.dev

---

## First Comment

I built Phantom because I watched Claude Code read my .env, grab my OpenAI key, and paste it into a shell script. The key was now in a file on disk, in session history, and in API logs. I didn't ask it to — it just wired things up like a good agent does.

The core architecture: `phantom init` replaces managed real secrets in your .env with phantom tokens — 256-bit CSPRNG values prefixed with `phm_`. Your real keys go into the OS credential store or encrypted-file fallback. Application and test processes load the tokens, while agents use value-blind MCP metadata without dotenv read access.

When you run `phantom exec -- claude`, a local reverse proxy starts on 127.0.0.1. It rewrites `OPENAI_BASE_URL` to point at localhost. Your code (or the AI's code) sends requests there with phantom tokens; the proxy swaps them for real credentials and forwards over TLS to the actual API. Not a MITM proxy — no CA certs, no TLS interception. Standard reverse proxy pattern.

Allowlist model: secrets only go to configured endpoints. Localhost-bound. Session-scoped — proxy dies when your session ends.

Modular Rust workspace. MIT licensed. No SaaS dependency for local protection.

```
npx phantom-secrets init
```

GitHub: https://github.com/ashlrai/phantom-secrets
