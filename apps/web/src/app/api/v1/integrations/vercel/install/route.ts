import { requireAuth } from "@/lib/auth";

export async function GET(req: Request) {
  // Redirect to Vercel OAuth with our client ID
  const clientId = process.env.VERCEL_INTEGRATION_CLIENT_ID;
  if (!clientId) {
    return Response.json({ error: "Vercel integration not configured" }, { status: 500 });
  }

  const { searchParams } = new URL(req.url);
  const next = searchParams.get("next") || "/";

  const params = new URLSearchParams({
    client_id: clientId,
    redirect_uri: "https://phm.dev/api/v1/integrations/vercel/callback",
    state: next,
  });

  return Response.redirect(`https://vercel.com/integrations/${process.env.VERCEL_INTEGRATION_SLUG}/new?${params}`);
}
