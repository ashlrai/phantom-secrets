import { aggregateStarCount, GITHUB_STAR_REPOS } from "@/lib/github-stars";

export const revalidate = 3600;

async function starCount(repo: string): Promise<number | null> {
  const response = await fetch(`https://api.github.com/repos/${repo}`, {
    headers: {
      Accept: "application/vnd.github+json",
      "User-Agent": "phm-dev",
      "X-GitHub-Api-Version": "2022-11-28",
    },
    next: { revalidate: 3600 },
  });
  if (!response.ok) return null;
  const body: unknown = await response.json();
  if (!body || typeof body !== "object" || !("stargazers_count" in body)) return null;
  const count = body.stargazers_count;
  return typeof count === "number" ? count : null;
}

export async function GET() {
  try {
    const counts = await Promise.all(GITHUB_STAR_REPOS.map((repo) => starCount(repo)));
    const stars = aggregateStarCount(counts);
    if (stars === null) {
      return Response.json({ ok: false }, { status: 502, headers: { "Cache-Control": "no-store" } });
    }
    return Response.json(
      { ok: true, stars, repositories: GITHUB_STAR_REPOS },
      { headers: { "Cache-Control": "public, max-age=3600" } },
    );
  } catch {
    return Response.json({ ok: false }, { status: 502, headers: { "Cache-Control": "no-store" } });
  }
}
