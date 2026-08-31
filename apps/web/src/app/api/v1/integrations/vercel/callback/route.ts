const INTEGRATION_DISABLED = {
  error: "integration_disabled",
  message:
    "Vercel OAuth callback handling is unavailable until Phantom can verify one-time user-bound state and encrypt platform tokens at rest.",
};

/**
 * Fail closed before reading an authorization code or calling Vercel.
 *
 * Re-enabling this callback requires all of the following as one reviewed
 * change: exact state consumption, authenticated Phantom-user binding,
 * bounded token exchange, encrypted credential storage, and adversarial
 * replay/cross-user tests. A placeholder user or plaintext token column is
 * never an acceptable intermediate state.
 */
export async function GET() {
  return Response.json(INTEGRATION_DISABLED, {
    status: 503,
    headers: { "Cache-Control": "no-store" },
  });
}
