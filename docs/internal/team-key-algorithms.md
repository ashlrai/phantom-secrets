# Hosted team key route: algorithm-tagged keys

`POST /api/v1/teams/:team_id/key` registers a member public key.

- Default (unchanged): `{ "public_key": "<base64 of 32 bytes>" }` is an X25519 key. Old clients send exactly this and see the same responses and error text as before.
- Hybrid (opt in): `{ "public_key": "<base64 of 1216 bytes>", "v": 2, "alg": "xwing-chacha20poly1305" }` is an X-Wing (X25519 + ML-KEM-768) encapsulation key. `v` is the share format version from the format tag work (#217) and `alg` matches `team_crypto_pq::ALG`. The 1216-byte size comes from `crates/phantom-core/src/team_crypto_pq.rs` (`public_b64`, asserted in its tests) in the pq-hybrid PR (#218).
- An untagged key is always treated as classic, so a 1216-byte key without the tag is rejected. A tagged key must match its algorithm's exact size. The base64 string is capped at 1624 characters (the length for 1216 bytes) before decoding, inside the existing 4096-byte body limit.

`GET /api/v1/teams/:team_id/key` is unchanged by default: a member with a hybrid key is listed with `public_key: null`, the same as a member who has not registered, so old clients never see a key they cannot use. Pass `?algs=all` to get every key plus an `alg` field (`x25519`, `xwing-chacha20poly1305`, or `null`).

## Mixed teams: fail closed, never downgrade (decision 2026-10-19 06:27 ET)

Decision (Engineering Orchestrator, under Mason's delegation): a push to a team that has a hybrid-key member is refused unless that member gets a hybrid share. The server never accepts classic-only wrapping for such a team and never drops the hybrid member from the coverage check.

Server (`POST /api/v1/teams/:team_id/vaults/:project_id`, `refuseClassicOnlyPush` in `apps/web/src/lib/team-key.ts`):

- For every member whose registered key is X-Wing (1216 bytes), the push must carry a `HybridKeyShare` (`v: 3`, `alg: "xwing-chacha20poly1305"`, `kem_ct`, `nonce`, `ciphertext`; the wire type in `crates/phantom-core/src/team_crypto_pq.rs`). A missing share or any other share shape for that member is refused before any write with HTTP 426:
  `{ "error": "client_upgrade_required", "min_client_version": <string or null>, "hybrid_members": [<user ids>], "message": "..." }`.
  The message says Phantom never falls back to classic-only wrapping and how to upgrade (Homebrew `brew upgrade ashlrai/phantom/phantom`, or the release asset for Linux and Windows).
- A share whose `v` or `alg` does not match either share shape is refused with the existing 400 shape error. A hybrid share given to a classic-key member is refused with 400 `share_alg_mismatch`.
- Classic-only teams are unchanged: same checks, same errors, same stored shares.

Minimum client version: `HYBRID_TEAM_MIN_CLIENT_VERSION_SET_AT_RELEASE` is a PLACEHOLDER and is `null` today, because no released Phantom client can wrap for a hybrid member yet. While it is null the response carries `min_client_version: null` and the message says no released version can push to the team yet. Set it to the real version in the release that ships hybrid team wrapping, and not before. No version number is claimed until then.

Client (`phantom-secrets-core`, `phantom team vault-push`):

- `push_team_vault` maps HTTP 426 to `PhantomError::ClientUpgradeRequired`. The printed text is built by the client. Only `min_client_version` is read from the body, and only if it is 1 to 32 characters of letters, digits, `.`, `-`, `+`; any other server text is ignored.
- The push stage receipt records `remote_ciphertext_push: "refused"` and `failure_code: "client_upgrade_required"`, and the upgrade text is appended. The CLI says the push was refused before any write, instead of "outcome unknown".
- This builds no hybrid push path. Clients from this change on print the clear refusal. Already released clients (0.7.9 and earlier) have no 426 case, so they show their generic "Phantom Cloud rejected the request" with failure code `provider_rejected`. They still cannot downgrade the team, because the server refuses.

Still open (for Mason): a CLI path that registers hybrid keys and wraps hybrid shares (gated on this decision, not built); crypto review and an audit decision for the unaudited `x-wing` crate (#218); review of the hosted API change and the Vercel production branch before merge.
