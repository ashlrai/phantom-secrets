# Vercel OAuth commissioning boundary

The Vercel install and callback routes remain disabled and return HTTP 503.
The migration and TypeScript helpers in this directory are source foundations;
they are not evidence that the database migration has been applied or that a
provider integration has been commissioned.

Before activation, all of these gates remain required:

- Execute the migration against an isolated local Supabase stack, then pass
  database lint, advisors, RLS/grant assertions, and concurrent issuance and
  consumption tests.
- Confirm `platform_tokens` has no legacy plaintext rows. The migration aborts
  if any exist so an operator can make an explicit incident and migration
  decision.
- Replace the current single-active-key environment loader with a reviewed
  multi-version key provider, retain old decryption keys during rotation, and
  define re-encryption, rollback, recovery, and key-destruction procedures.
  The `encryption_key_version` column does not provide rotation by itself.
- Provision server-only key material and Vercel OAuth credentials through the
  approved production secret-management path. Never use a `NEXT_PUBLIC_` key.
- Register and independently verify exact callback URLs, least-privilege
  scopes, bounded token-exchange timeouts, install/uninstall behavior, provider
  revocation, and audit events that never include state or token values.
- Authenticate the browser session before state issuance and again before the
  callback consumes that same user-bound state.
- Add a scheduled global retention job. Issuance currently deletes at most 100
  rows for that user when they are more than one hour past expiry and caps each
  user at eight active states; users who never issue again are not cleaned up.
- Pass a reviewed staging deployment and adversarial browser acceptance before
  changing either fail-closed route.
