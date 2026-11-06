import configJson from "../../../../ecosystem-repos.json";
import historyJson from "@/lib/star-history.json";
import {
  STAR_HISTORY_URL,
  fetchPublicStars,
  githubToken,
  mergeHistories,
  parseHistory,
  payloadFromHistory,
  payloadFromLive,
} from "@/lib/stars";

export const revalidate = 600;

const FRESH = "public, max-age=600, s-maxage=600, stale-while-revalidate=86400";
const BRIEF = "public, max-age=60, s-maxage=60, stale-while-revalidate=600";

function json(body: unknown, cacheControl: string) {
  return Response.json(body, {
    headers: {
      "cache-control": cacheControl,
      "access-control-allow-origin": "*",
    },
  });
}

async function storedHistory(fetchImpl: typeof fetch) {
  const bundled = parseHistory(historyJson);
  let remote = null;
  try {
    const response = await fetchImpl(STAR_HISTORY_URL, {
      headers: { accept: "application/json" },
      signal: AbortSignal.timeout(8000),
    });
    if (response.ok) remote = parseHistory(await response.json());
  } catch {
    remote = null;
  }
  if (!bundled && !remote) return null;
  return mergeHistories([bundled, remote]);
}

export async function GET() {
  const cached: typeof fetch = (input, init) => fetch(input, { ...init, next: { revalidate: 600 } });
  const history = await storedHistory(cached);
  const fallback = history ? payloadFromHistory(history, { stale: true }) : null;
  if (!history || !fallback) {
    return json({
      schemaVersion: 1,
      source: "snapshot",
      stale: true,
      total: null,
      repoCount: 0,
      repos: [],
      history: [],
      delta: { since: null, stars: null },
      error: "unavailable",
    }, "no-store");
  }

  const live = await fetchPublicStars({
    config: configJson,
    fetchImpl: cached,
    token: githubToken(process.env),
  });
  const fresh = payloadFromLive(history, live);
  if (fresh) return json(fresh, FRESH);
  return json(fallback, BRIEF);
}
