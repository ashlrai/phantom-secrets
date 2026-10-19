# Autonomous leak response and rotation flow, built on leases

Status: proposal for security review. Docs only. Nothing here is implemented, and nothing in this document activates live revoke, live rotation, lease issuance, or any broker path. Line references are to `main` at commit `34513e2` and should be rechecked before acting on them.

Related: PR #224 (`on_leak` policy, merged), PR #230 (lease store key provisioning, draft, open reviewer checklist).

## 1. What exists today (verified in code)

1. Detection. The proxy writes `proxy.response_leak` audit events. `LeakCorrelationEngine` (`crates/phantom-core/src/leak_correlation.rs`) groups them by secret name and location within a window. One event scores 0.5, more than three events for one secret within an hour scores 0.95, and two or three events interpolate. Incidents are persisted only by an explicit backfill; a read-only path (`incident_view`) also reports unpersisted ones. A later `vault.store` event for the same name clears an incident.
2. Plan. `phantom leaks plan` (`crates/phantom-cli/src/commands/leaks.rs`) is pure and read-only. At confidence 0.7 or more (`REVOKE_THRESHOLD`) it proposes `revoke_and_rotate` with three manual steps; below that it proposes `review`. It prints secret names only, never values. Provider is matched by secret name through `default_rotation_providers()`.
3. Policy. `[leak_response]` in `.phantom.toml` has `on_leak = off | plan | revoke` and `allow_revoke`. `revoke` fails closed without `allow_revoke = true`, and live revoke is unavailable in shipped builds (`live_revoke_available` is always false). With `off`, the command still reports how many incidents it is suppressing, so a repository cannot hide the user's incidents.
4. Providers. The `RotationProvider` trait (`rotation_provider.rs:187`) has `initiate_rotation`, `finalize_rotation`, and an optional `post_store_cleanup` that runs only after the new value is durably stored. In shipped builds every provider refuses live issuance before credential access or network I/O (module header, and the `NotSupported` returns for Stripe, GitHub, AWS, Google, Vercel, Sentry and Supabase). Stripe and Supabase state that their keys are dashboard-only. The mock fast paths are compiled only under `cfg(test)` (`mock_rotation_allowed`).
5. Leases. Per #230, the broker's `DurableReplayStore` needs a 32-byte MAC key that nothing in the repository provisions, there is no value-free list method, and the store is not an activation authority until a monotonic rollback anchor exists. So no lease can be issued or revoked by the CLI today.

Consequence: the only automatable parts today are the read-only ones. Every state-changing step is a human step at the provider dashboard.

## 2. Target flow

```
detect -> correlate -> plan -> inventory -> approve -> rotate -> verify -> retire old -> audit
  (1)        (2)       (3)       (4)         (5)       (6)       (7)         (8)        (9)
```

| Step | What happens | Automation level now | Needs leases or MAC key |
|---|---|---|---|
| 1 detect | proxy flags a real secret in an upstream response | automatic, exists | no |
| 2 correlate | incidents grouped, confidence scored | automatic, exists | no |
| 3 plan | `phantom leaks plan` renders the response | automatic, read-only, exists | no |
| 4 inventory | list which vault entries, projects and placeholders reference the leaked name | read-only, proposed | no |
| 5 approve | a human confirms the exact action from a trusted terminal | human only, always | the approval itself does not; binding it to a lease would |
| 6 rotate | provider issues a successor, successor is stored in the vault | human today (dashboard); live is disabled | yes, see section 5 |
| 7 verify | confirm the successor works and the old one is dead | human today | no for a read-only check, yes if it needs a credential |
| 8 retire old | provider-side revoke of the leaked value | human today | yes |
| 9 audit | every step is recorded with names and outcomes, no values | partly exists | the audit chain key is separate from the lease MAC key |

## 3. Safe to automate now (no values, no network, no writes beyond a plan)

These can ship as small PRs without any lease work.

1. Plan generation (exists). Improve it with provider facts that are static and value-free: whether the provider has a programmatic rotation API at all, the dashboard location where a human rotates, and whether live revoke is disabled in this build. Source these from a static table next to the providers, not from the `NotSupported` prose, so tests can pin them.
2. Read-only inventory. For each planned incident, list the project names and `.phantom.toml` entries that reference the secret name, and the count of placeholders mapped to it. Names and counts only. Reads the local config and vault index, never a value. Open question 4 asks whether the vault index read is acceptable.
3. Dry-run rotation command. A `phantom leaks plan --rotation-preview` style output that prints, per incident, the exact ordered commands a human would run (for example `phantom add <NAME>` from a trusted terminal, `phantom sync`), the verify step, and the retire step, marked as not executed. It must not accept a value, must not call a provider, and must not require the vault to be unlocked.
4. A human approval step as a data shape, not a behavior. The plan JSON can carry an `approval_required: true` field and the exact confirmation text a future approver must type. Nothing consumes it yet.
5. Audit of the plan itself. Today the plan writes no audit event (documented in `leaks.rs`). Whether viewing a plan should be audited is an open question (section 8, question 5), because writing from a read-only command changes its contract.

## 4. Per-provider rotation steps (what the plan should say)

All steps are manual in shipped builds. The table records only what the code states.

| Provider | Programmatic rotation | Plan should say |
|---|---|---|
| Stripe | no public API for raw keys (dashboard-only, stated in `STRIPE_NOT_SUPPORTED_REASON`) | roll the key at the Stripe dashboard API keys page, then store the replacement with trusted-terminal `phantom add` |
| Supabase | personal access tokens are dashboard-only (stated in `SUPABASE_NOT_SUPPORTED_REASON`) | create a replacement at the Supabase account tokens page, then `phantom add` |
| GitHub | installation-token issuance disabled in this build; PATs dashboard-only | revoke and replace in GitHub settings, then `phantom add` |
| AWS | live rotation disabled in this build | rotate with the AWS CLI or console, then `phantom add` |
| Google | provider only covers application-owned shared secrets; service-account and ADC credentials refused | rotate in Google Cloud, then `phantom add` |
| Vercel | issuance and prior-token cleanup disabled in this build | use the Vercel dashboard, verify, then `phantom add` |
| Sentry | installation-token issuance disabled in this build | rotate in Sentry, then `phantom add` |
| No provider match | none | the generic "provider that issued it" wording (exists) |

If a provider later gains a verified live path, the ordering in the trait already encodes the safe sequence: issue, store durably, verify, and only then `post_store_cleanup` to retire the old value. The module header explains why live issuance is off: the challenge contract cannot yet carry a value-free resource handle for a compensating abort if local persistence fails. That contract fix is a prerequisite for step 6, independent of leases.

## 5. What needs leases and the unprovisioned MAC key

Steps 6 and 8 are the only ones that change provider state. The proposal is that a future automated rotation runs only inside a lease:

1. A lease scoped to one operation (rotate one named secret for one project), single use, short expiry, bound to the approval from step 5.
2. The lease store can only be trusted once #230 is resolved: the MAC key must be provisioned (OS credential store primary, per #230), a value-free `list_leases` must exist, and the rollback anchor gap must be closed or explicitly accepted. Until then the store is not an activation authority (#230, section 1).
3. "A new broker run revokes every lease" (#230, section 7) means a crash mid-rotation drops the lease. The flow must treat that as the safe failure: no lease means no further provider action, and the plan remains the manual fallback.
4. The MAC key protects the lease state file against other users and backups. It does not stop an agent running as the same OS user (#230, section 2, threat 3). The approval ceremony and process separation are the control for that case, so no design here may rely on the key for that adversary.

Hold: none of this is wired. Section 7 lists what must be true before it could be.

## 6. Approval gates

1. Gate A, policy. `on_leak = "revoke"` plus `allow_revoke = true` in the repository config is necessary but never sufficient, because a repository file is attacker-influenced in a shared checkout. It must never by itself trigger a live action. It could be read as an upper bound only.
2. Gate B, per-incident human approval from a trusted terminal, with the exact secret name and provider in the confirmation text. An agent cannot satisfy it (same approach as the existing trusted-terminal challenge for adding values).
3. Gate C, lease. The approval mints a single-use lease for exactly one operation. No standing permission.
4. Gate D, build capability. `live_revoke_available` remains false until a reviewed release flips it. Tests assert it stays false.
5. Gate E, confidence. Below 0.7 the plan is `review` only and no lease may be minted. Confidence is derived from event counts, and a single event is 0.5, so one event never reaches the revoke path. Flooding the audit log with events can raise confidence, so confidence is advice for a human, not authorization.

## 7. Audit trail

1. Names, outcomes, timestamps and incident ids only. No values, no challenge ids, no old or new credentials, no lease secrets.
2. One event per state transition: plan viewed (open question 5), approval granted or refused, lease minted, provider issue attempted, store written, verify result, retire result, lease consumed or expired.
3. The existing rotation clearing rule (a `vault.store` after the incident clears it) is the success signal. It clears on any store of that name, including a store of the same leaked value. The verify step should therefore compare identity without reading values (for example a vault entry version or fingerprint change), which needs a design of its own and is not proposed here.
4. The audit chain key and the lease MAC key are separate secrets with separate failure modes. #270 notes the audit HMAC key loader accepts a key file of any length; that should be fixed before audit events are relied on to gate a flow.

## 8. Failure modes

| Failure | Required behavior |
|---|---|
| Provider issues a successor but local store write fails | no live path until the abort contract exists (module header); manual flow tells the human to revoke the unstored successor |
| Successor stored, retire of old value fails | report truthfully, do not undo the replacement (`post_store_cleanup` contract), leave the incident open, tell the human the old value is still live |
| Crash or restart mid-flow | all leases revoked by the new broker run; flow stops; plan regenerated |
| Lease store key lost | store unreadable, bootstrap new, same as restart (#230, option A) |
| Incident flood from an attacker-controlled upstream | confidence is advice only, per-incident human approval, rate limit on plans is not needed because plans are read-only |
| Repository sets `on_leak = "off"` | suppressed count is still reported (exists) |
| Same secret leaks again after rotation | new incident, new approval, no carried-over lease |
| Mis-matched provider (name heuristic, for example a name containing STRIPE) | plan shows the provider as a label and a human confirms; a wrong match must never select a different provider's credentials automatically |
| Rotation of a value other systems still use | the inventory step lists known consumers; unknown consumers are a residual risk that only a human can judge |
| Approval fatigue | one approval per incident, never batch approval across providers |

## 9. Phased plan

1. Phase 0 (this note): review and decisions.
2. Phase 1, safe pieces, each a small tested value-free PR: static provider facts in the plan (dashboard location, programmatic or manual, live disabled), then the read-only inventory, then the dry-run command list. Tests: no value in output, no vault unlock, no network, `live_revoke_available` stays false, JSON fields additive only.
3. Phase 2, prerequisites that are not about leases: the provider challenge contract with a value-free resource handle and verified compensating abort; #270 audit key length.
4. Phase 3, after #230 is decided and implemented: key provisioning, `list_leases`, rollback anchor decision.
5. Phase 4, one provider with a verified live path, behind Gates A to E, behind a build flag, with fault-injection tests for every row in section 8. Stripe and Supabase stay manual regardless, since they have no API.

Nothing in phases 2 to 4 starts without a reviewed decision on the open questions.

## 10. Open questions for the reviewer

1. Is Gate B (trusted-terminal approval naming secret and provider) the right ceremony, and should it be per incident or per provider?
2. Should `on_leak = "revoke"` stay a repository-level setting at all, given Gate A says it can only ever be an upper bound? Alternative: move live-response opt-in to user-level config under HOME.
3. Which provider, if any, is first for a verified live path, given that most refuse issuance until the abort contract exists?
4. Is reading the vault index (names only) acceptable for the inventory step, or must inventory read only config files?
5. Should viewing a plan write an audit event? Doing so gives a trail but breaks the documented "no writes" contract of `leaks plan`.
6. How should verification detect "the value actually changed" without reading values?
7. Is the proposed order of #230 before any live flow accepted, including the rollback anchor gap?
