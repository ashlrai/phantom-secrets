# Hosted team key route: algorithm-tagged keys

`POST /api/v1/teams/:team_id/key` registers a member public key.

- Default (unchanged): `{ "public_key": "<base64 of 32 bytes>" }` is an X25519 key. Old clients send exactly this and see the same responses and error text as before.
- Hybrid (opt in): `{ "public_key": "<base64 of 1216 bytes>", "v": 2, "alg": "xwing-chacha20poly1305" }` is an X-Wing (X25519 + ML-KEM-768) encapsulation key. `v` is the share format version from the format tag work (#217) and `alg` matches `team_crypto_pq::ALG`. The 1216-byte size comes from `crates/phantom-core/src/team_crypto_pq.rs` (`public_b64`, asserted in its tests) in the pq-hybrid PR (#218).
- An untagged key is always treated as classic, so a 1216-byte key without the tag is rejected. A tagged key must match its algorithm's exact size. The base64 string is capped at 1624 characters (the length for 1216 bytes) before decoding, inside the existing 4096-byte body limit.

`GET /api/v1/teams/:team_id/key` is unchanged by default: a member with a hybrid key is listed with `public_key: null`, the same as a member who has not registered, so old clients never see a key they cannot use. Pass `?algs=all` to get every key plus an `alg` field (`x25519`, `xwing-chacha20poly1305`, or `null`).

Known gap, not changed here: `PUT`/`POST` of a team vault requires wrapped keys for every member with a registered key. While a member has a hybrid key, an old client pushing a vault is rejected, because it cannot see that member. Vault push for mixed teams needs its own follow-up. The hybrid share is experimental and unaudited (#218), and no released CLI sends the tagged registration yet.
