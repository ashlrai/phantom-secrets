# Consolidation findings

Source PRs requested: #506, #524, #530, #534, #556.
Remote inspection blocked by Locus authority error, so exact mapping of PR numbers to branches is unverified.

Cached source branches all share HEAD 3d062e9 as merge base:
- RQ-PS-EXEC-API: e28245b (cached tip 906c9e2), GitHub lifecycle and REST/GraphQL loopback tests, private registry test seam.
- RQ-PS-EXEC-COVERAGE: adfd52f (cached tip 8340de2), unsupported CLI refusals before vault access, coverage documentation and mock tests.
- RQ-PS-EXEC-JSON-SCHEMA-r2: b8d3421 (cached tip c566820), fixed-vocabulary error envelope and refusal classification.
- RQ-PS-EXEC-RS-TESTS: 2601025, value-free launch/spawn diagnostics and boundary tests.
- RQ-PS-EXEC-SCRUB: 2ff0d24 (cached tip 2aa0e34), opt-in streaming stdout/stderr scrubbing, signal forwarding for direct launches.

Three-way merged source deltas directly into the working tree without staging or commits.
Resolved exec entry point and CLI dispatch to preserve JSON + output scrubbing together.
Added combination coverage for JSON refusals and scrubbed child output/exit status. Fixed JSON spawn refusals with typed, value-free errors preserving exit codes 126/127; added both-path regression matrix. Independent review found no further concrete blockers.
No tracked CODEOWNERS file exists at HEAD. No .github or release configuration changes.

Validation findings: Rust typecheck and web TypeScript/ESLint passed. Initial full Rust run hit an existing 1-second workspace lock timeout, which passed in isolation; full serial CLI unit retry is running. New JSON unknown-route fixture lacked a route pattern, so it correctly reached spawn instead of route refusal. Added complete custom route metadata; all 4 JSON tests then passed. Initial full web run from correct directory: 249 passed, 1 cancelled by existing build timeout; isolated retry running with unchanged limits.

Final validation: latest per-target Rust results 2,974 passed / 0 failed / 3 pre-existing ignored across 91 targets. Web latest results 250 passed / 0 failed. Production-build retry passed in 433 seconds with original timeout. Both typechecks, Clippy, ESLint, formatting and diff checks passed. No commits or publication.
