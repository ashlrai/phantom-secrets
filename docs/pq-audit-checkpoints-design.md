# Design note: optional ML-DSA signed audit checkpoints (proposal only)

Status: proposal for review. Nothing in this note is implemented. No code, dependency or format change is made by this PR.

## What the code does today (verified in `crates/phantom-core/src/audit.rs`)

- Each audit line carries `hmac` = HMAC-SHA256 over the canonical JSON, chained through `prev_hmac`. The key is a per-machine 32-byte secret at `~/.phantom/audit-hmac-key`.
- The head checkpoint `~/.phantom/audit-head.json` (`AuditHead`: `version`, `last_seq`, `last_hmac`, `hmac`) is also authenticated with that same HMAC key.
- The log header comment names Ed25519 only for sidecar event envelopes (`SidecarEvent`), not for the head checkpoint.

So the existing checkpoint is symmetric. A 256-bit HMAC key is not broken by Shor's algorithm, and Grover reduces it to roughly 128-bit effective strength, so the local tamper evidence does not need a post-quantum signature to stay sound.

## Correction to the earlier plan

The research file proposed "dual-signing audit log checkpoints (Ed25519 plus ML-DSA-65)". The checkpoint has no Ed25519 signature today, so there is nothing to dual-sign. A post-quantum signature only adds value if a third party must verify a checkpoint without holding the local HMAC key (for example an exported checkpoint attached to an incident report, or a team-shared log). That is the real question for review.

## Proposal

1. Opt-in cargo feature `pq-sign` (off by default, never in default builds or release binaries until decided).
2. When enabled and a signing key exists, `audit-head.json` gains optional fields: `sig_alg` (`"ml-dsa-65"`), `sig` (base64) and `sig_key_id` (hash of the public key). The signature covers the same canonical bytes the HMAC covers, so the HMAC stays authoritative for local verification.
3. Optional Ed25519 companion signature (`sig_alg_2`) only if reviewers want a classical fallback in case ML-DSA is weakened. Default: ML-DSA alone, plus the existing HMAC.
4. Verification: files without the new fields verify exactly as today. Files with them verify HMAC first, then the signature if the feature is compiled in; with the feature off, the fields are ignored and reported as "unverified signature present".
5. Key handling: a separate signing key file (0600, same directory rules as the HMAC key), never derived from the HMAC key. Public key export through a new read-only command. Key rotation and who may hold the key are open questions.
6. Size: ML-DSA-65 signatures are 3309 bytes and public keys 1952 bytes (FIPS 204 parameter set; figures as quoted in the research file). One checkpoint file per log, so the cost is small. Per-line signatures are explicitly out of scope.

## Risks and open questions

- Library maturity: the RustCrypto `ml-dsa` crate was 0.1.1 at research time and states it has not been independently audited. Alternative backends exist; none is chosen here. Do not adopt liboqs.
- Value: if no third-party verification use case exists, the recommendation is not to build this and to document the HMAC reasoning above instead.
- Format: new fields must stay optional so old binaries keep reading new files (serde unknown fields behavior to be confirmed before implementation).
- Code ownership: phantom-secrets has no CODEOWNERS file on main, but this touches security-sensitive audit code, so Mason should review before implementation.

## Not in scope

Lease token signatures (blocked on the lease key-provisioning review, PR #230), release signing, any change to the HMAC chain.

## Decision requested

Approve, change or reject the proposal, and answer: is there a third-party verification use case that justifies it?
