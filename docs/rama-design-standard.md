# Rama-derived network engineering standard

Phantom uses [Rama](https://github.com/plabayo/rama) as a reference for how a
serious Rust networking project makes its stack explicit, modular, observable,
bounded, cross-platform, and operable. This is an engineering comparison and
adoption standard, not a claim that Phantom embeds Rama or inherits Rama's
production history.

Snapshot reviewed: 2026-09-01. Rama's upstream README, book, examples, release
notes, CI, and crate layout remain the authoritative sources for Rama.

## What Phantom adopts as a standard

Rama's useful lesson is not a checklist of protocols. It is that network
behavior should be visible in code as composed services, layers, transports,
protocols, and state. For Phantom, every credential-bearing request path should
make these stages independently reviewable:

```text
loopback accept
  -> session authentication
  -> closed route match
  -> rate and resource admission
  -> bounded request collection
  -> route-owned credential injection
  -> pinned upstream policy
  -> bounded response handling
  -> value scrubbing
  -> downstream response
```

The current proxy implements that order in `phantom-proxy`, although it has not
yet been refactored into a public service/layer API. Its present controls include
a fixed loopback listener, a 256-connection ceiling, a 10-second request-header
deadline, a 64 KiB HTTP/1 buffer ceiling, bounded bodies and responses, fixed
route-owned authentication headers, disabled ambient forward proxies, disabled
redirect following, streaming scrubbing, and a bounded shutdown drain.

Phantom applies the same standard outside the proxy:

- Network response bodies must have explicit byte and shape limits before
  deserialization.
- Retry, timeout, redirect, proxy, DNS, and partial-success behavior must be
  deliberate and testable.
- Secret values must have one narrow owner, use zeroizing storage where
  practical, and never enter agent-facing results or diagnostics.
- Cross-platform support requires an executed artifact receipt for each stated
  target; source configuration is not acceptance evidence.
- Smaller crates and feature surfaces are preferred when they create a real
  trust or dependency boundary, not merely more package names.
- Examples are executable contracts. Security-critical examples must be tested
  against redirects, truncation, oversized input, streaming boundaries, and
  shutdown.

## Current differences

| Area | Rama reference | Phantom 0.7.4 candidate |
|---|---|---|
| Primary abstraction | Composable services, layers, transports, protocols, and typed context | A purpose-built authenticated HTTP/1 credential proxy with internal registry/interceptor/scrubber components |
| Protocol breadth | HTTP, WebSocket, gRPC, TCP, UDP, DNS, TLS, SOCKS5, proxy protocols, and platform networking | Deliberately narrow reviewed HTTP API routes; it is not a general network framework |
| Platforms | Upstream describes Linux, macOS, and Windows as tier 1, with mobile targets checked in CI | Six desktop release targets are configured; exact-candidate native execution remains a release gate |
| Supply chain | Upstream reports `cargo vet` use | Phantom uses locked dependencies, Cargo policy checks, artifact checksums, SBOM/provenance contracts, secret scanning, and release verification; these are not `cargo vet` equivalence |
| Toolchain | Upstream currently reports Rust 1.96 | Phantom pins Rust 1.95.0; adding Rama now would require a reviewed MSRV/toolchain change |
| Commercial model | Open source with commercial support and partner offerings | Open-source local product plus separately evidenced cloud/team and future enterprise plans |

## Dependency decision

Phantom must not add Rama merely for association or replace the current proxy
inside a patch release. A dependency proposal is acceptable only when it:

1. identifies a smaller, measurable component that Rama improves;
2. preserves the closed route registry and route-owned credential boundary;
3. proves no placeholder substitution is added to client-controlled headers or
   bodies;
4. disables ambient proxies and cross-origin redirects for credential-bearing
   traffic;
5. preserves response scrubbing across arbitrary stream chunk boundaries;
6. provides explicit limits for connections, headers, bodies, responses,
   concurrency, time, retries, and shutdown;
7. passes the six-target native artifact workflow and the existing proxy attack
   corpus; and
8. includes dependency, license, MSRV, binary-size, latency, throughput, and
   memory comparisons against the current implementation.

Until those gates pass, Rama is an architectural benchmark rather than a
runtime dependency.

## Ordered roadmap

These are target milestones, not shipped capability:

1. Extract the current proxy stages into private typed services with explicit
   input/output contracts while preserving byte-for-byte behavior.
2. Add deterministic transport fault tests for slow headers, disconnects,
   truncated streams, redirect attempts, DNS changes, backpressure, and drain
   deadlines.
3. Publish a stable extension boundary only after it cannot expand routes,
   destinations, credential placement, or authority from repository input.
4. Benchmark a minimal Rama-backed spike behind a non-default feature and keep
   it only if every dependency-decision gate above passes.
5. Consider lower-level or platform proxy capabilities only as separate threat
   models and release trains. Phantom's secret-injection proxy must not silently
   become a general MITM or system proxy.

## Review rule

Every proxy or network-client change should answer four questions in its pull
request: what stage changed, which authority can select it, which resources are
bounded, and which exact test proves failure is closed. If any answer is
implicit, the change is not ready.
