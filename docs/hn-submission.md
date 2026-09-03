# Hacker News Submission

**Title:** Show HN: Phantom – Stop AI coding agents from leaking your API keys

**URL:** https://phm.dev

---

## First Comment

I built Phantom because I watched Claude Code read my .env, grab my OpenAI key, and paste it into a shell script. The key was now in a file on disk, in session history, and in API logs. I didn't ask it to — it just wired things up like a good agent does.

The core architecture: `phantom init` replaces managed real secrets in your .env with phantom tokens — 256-bit CSPRNG values prefixed with `phm_`. Your real keys go into the OS credential store or encrypted-file fallback. Application and test processes load the tokens, while agents use value-blind MCP metadata without dotenv read access.

When you run `phantom exec -- claude`, a local reverse proxy starts on 127.0.0.1 and rewrites implemented SDK base URLs to point at localhost. After authenticating and matching an exact route, the proxy discards client control of that route's auth header and injects only the route-owned vault value there before forwarding over TLS. Client headers and bodies never resolve phantom tokens. Not a MITM proxy — no CA certs, no TLS interception. Standard reverse proxy pattern.

Reviewed-route model: the agentic proxy accepts Phantom's exact built-in API
destinations and binds to loopback. Each `phantom exec` run has a fresh proxy
bearer and fresh child-process placeholders; the persistent project tokens remain
in dotenv until rotation. Client placeholders are inert. Protected database connection strings currently fail
closed rather than being injected into the child process.

Modular Rust workspace. MIT licensed. No SaaS dependency for local protection.

Install the reviewed `v0.7.4` release using the checksum-verified
[platform instructions](./getting-started.md#install), then run `phantom init`.

GitHub: https://github.com/ashlrai/phantom-secrets
