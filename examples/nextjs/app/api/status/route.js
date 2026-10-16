export const dynamic = "force-dynamic";

// Reports what the Next.js server process received from `phantom exec`,
// without echoing any full credential, and checks the local proxy is reachable.
export async function GET() {
  const key = process.env.OPENAI_API_KEY ?? "";
  const base = process.env.OPENAI_BASE_URL ?? "";
  const port = process.env.PHANTOM_PROXY_PORT;
  let proxyHealthy = false;
  if (port) {
    try {
      const res = await fetch(`http://127.0.0.1:${port}/phantom/health`, {
        headers: { "x-phantom-proxy-token": process.env.PHANTOM_PROXY_TOKEN ?? "" },
      });
      proxyHealthy = res.ok;
    } catch {}
  }
  return Response.json({
    keyIsPlaceholder: key.startsWith("phm_"),
    baseUrlIsLocalProxy: /^http:\/\/127\.0\.0\.1:\d+\//.test(base),
    proxyHealthy,
  });
}
