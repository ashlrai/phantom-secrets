# Consolidation findings

GitHub access through Locus is blocked: the existing session needs a human re-pin because its broker owner executable is unavailable. No new token was created. Six local family branches exist, but their association with the requested PR numbers remains unverified.

## Local source heads

- CREATE: 008cc5b7eaed07c92c51104b0039c41f35a68356
- GET: 3ae0abe3f5b61c86d4ce602a20fc556b17a0c55f
- REQUEST: 8e4209708a117d41508a53ab5c0c01fc6c909a43
- ROTATE: 6fe65428296313dc4a578d366c3dea5e4af972a6
- AUDIT: 356589d182c7566968fb265d833c689dfe58260c
- RUN-NOVALUE: 0ff4d4908f7259ded3a1b2b881aeb6732428d155

## Integration decisions

- Combined generation, metadata, requests, local rotation, audit, and no-value tests with three-way patches against the current default-branch checkout.
- Retained rotation-history deletion in the audited delete/CAS paths.
- Generated fulfillment now preserves the reserved request mapping and marks the request fulfilled in the same transaction.
- Local generated rotation and rollback now use mandatory audit admission before mutation.
- Registry publication manifest and release scripts remain unchanged under the job restrictions. The added phantom_get tool requires a later authorized catalog parity update before merge.
- No CODEOWNERS exists in this checkout. No .github changes are permitted.

## Validation findings

- Initial web validation ran while dependency installation was still in progress. It must be rerun after npm ci succeeds. Initial result: 248 passed, 2 failed due to missing Next.js modules; typecheck and lint executables were not yet installed.
- Rust workspace suite is compiling from a cold target cache. A separate clone of the existing local target cache is being prepared to speed final validation without modifying the shared cache.

- Cached Rust compilation found that the CREATE branch imports rand without declaring it in the MCP crate. Added the existing workspace dependency and its already locked 0.8.6 edge; no dependency version or publishing metadata changed.
- The first cached compile was interrupted after reporting the missing dependency, so its remaining compilation jobs would not delay the corrected final run. Final workspace Clippy now precedes the corrected full test run on the same cloned target cache.
- README now enumerates the 55-tool development runtime and explicitly identifies the protected registry/release parity work still required.

- Corrected full-workspace compilation also found an old add::run signature in the existing malformed-config guard test. Updated the call and added the generated mode to that same vault-must-not-be-reached regression.
- Web typecheck and ESLint completed with exit 0. The web production-readiness test exceeded its unchanged 600-second deadline under host contention.

- Clippy identified run_query after the audit test module. Moved the production helper before tests, retaining strict warnings-as-errors and all tests.

- Corrected the generation test fixture's platform vault path and isolated XDG data/config paths. Targeted rerun passed all 3 tests; final full-workspace Clippy recheck also passed.

- The MCP generated-add test inherited the initialization-only test approval bypass, so its effects-gate assertion was invalid. Cleared the bypass before checking either gate, added no-mutation assertions, and retained strict production gates. The final Clippy recheck passed; the corrected targeted gate-test rerun passed (exit 0).

## Final validation

Full Rust run: 95 targets, 2,987 passed, 4 failed, 3 existing ignored. Both corrected fixture failures passed targeted reruns. The unchanged vault concurrency test passed its isolated rerun in 47.20 seconds within the original 120-second bound. Protected catalog parity remains unresolved. Web: 249 passed, 1 timeout cancellation. Final strict Clippy, formatting, TypeScript, and ESLint passed. See BRIDGE_NOTES.md for commands and constraints.
