const INTEGRATION_DISABLED = {
  error: "integration_disabled",
  message:
    "Vercel OAuth installation is unavailable until Phantom can bind one-time state to an authenticated user and encrypt the resulting platform token at rest.",
};

/**
 * This route is intentionally fail-closed.
 *
 * The previous draft accepted an unauthenticated request and forwarded a
 * caller-controlled value as OAuth state. Re-enable only with a one-time,
 * expiring, user-bound state record and a callback that consumes it exactly
 * once before any token exchange.
 */
export async function GET() {
  return Response.json(INTEGRATION_DISABLED, {
    status: 503,
    headers: { "Cache-Control": "no-store" },
  });
}
