# Task Plan: Phantom North Star Stabilization Waves

## Goal
Land verifiable security and readiness slices from the north-star plan without widening changes beyond what can be tested.

## Phases
- [x] Phase 1: Rehydrate state and create planning files
- [x] Phase 2: Research proxy authentication and related tests
- [x] Phase 3: Implement header-only default proxy auth with explicit query compatibility path
- [x] Phase 4: Verify targeted tests and update notes
- [x] Phase 5: Deliver concise readiness report
- [x] Phase 6: Parallel discovery for next foundation slice
- [x] Phase 7: Implement one bounded next slice
- [x] Phase 8: Verify and update readiness notes
- [x] Phase 9: Fix isolated web device-auth blocker
- [x] Phase 10: Add advisory `.phantom.toml` service-route risk warnings
- [x] Phase 11: Fix Rust team API response-envelope parsing
- [x] Phase 12: Align public proxy-auth documentation with header-only defaults
- [x] Phase 13: Quarantine broken GitHub Action docs and workflow examples
- [x] Phase 14: Fix team invite API compatibility with CLI/MCP `github_login`
- [x] Phase 15: Restore SDK-compatible proxy auth while preserving strict header mode
- [x] Phase 16: Harden device-code duplicates/collisions
- [x] Phase 17: Serialize audit HMAC/head writes and add required mode

## Key Questions
1. Where are proxy auth URLs generated and consumed?
2. Which tests already cover query-token proxy auth?
3. What smallest compatibility switch can preserve legacy behavior without making query auth the default?
4. Which security-foundation slice has the best ratio of risk reduction to testability after proxy auth?

## Decisions Made
- First implementation slice: proxy auth hardening, because it is a concrete foundation item with bounded Rust surface area.
- Persistent files will live at repo root per the provided operating loop.
- Query-token proxy auth is controlled by `PHANTOM_PROXY_ALLOW_QUERY_TOKEN=1`; default generated base URLs no longer include `phantom_token`.
- Second wave discovery is split across audit integrity, MCP approval gates, config tamper warnings, docs drift, and web/cloud/team blockers.
- Second implementation slice: audit verifier hardening with signed sequence numbers, malformed-line failure, and head checkpointing.
- Third implementation slice: canonicalize device auth user codes across initiate, browser approval, approve route, and database uniqueness.
- Fourth implementation slice: advisory service-route risk analysis in core, surfaced by `doctor` and non-blocking staged `check` warnings.
- Fifth implementation slice: align Rust team client parsing with web API response envelopes for list/create/members.
- Sixth implementation slice: align README, getting-started docs, LLM reference docs, and static site feature/pricing copy with header-authenticated proxy sessions.
- Seventh implementation slice: disable the GitHub Action fail-fast and replace CI docs/examples that referenced unsupported non-interactive cloud auth flags.
- Eighth implementation slice: keep the public team invite contract as GitHub login by accepting `github_login` in the web team-members route and resolving it to the stored user UUID.
- Ninth implementation slice: restore generic SDK compatibility by using path-scoped local proxy auth in CLI-generated base URLs by default, while keeping `PHANTOM_PROXY_HEADER_AUTH_ONLY=1` for strict header-aware clients.
- Tenth implementation slice: make device-code approval/migration resilient to historical duplicate canonical codes and rare generated-code collisions.
- Eleventh implementation slice: add audit file locking around HMAC/head transactions plus `PHANTOM_AUDIT=required` fail-closed API.

## Errors Encountered
- `cargo fmt --all -- --check` reported a formatting-only diff in `crates/phantom-proxy/src/server.rs`; resolved with `cargo fmt --all`.
- `cargo test -p phantom-proxy` used the library crate name instead of package name; rerun with `-p phantom-secrets-proxy`.
- `cargo check -p phantom-secrets-cli` used a nonexistent package name; rerun with `-p phantom-secrets`.
- `cargo fmt` was required after audit checkpoint edits; final `cargo fmt --all -- --check` passed.

## Status
**Complete** - Proxy auth, audit integrity/concurrency, device auth canonicalization, service-route warnings, team response-envelope parsing, proxy-auth docs alignment, GitHub Action drift cleanup, and team invite compatibility implemented and verified; next candidate slices recorded in notes.
