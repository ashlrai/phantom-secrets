export const GITHUB_STAR_REPOS = ["ashlrai/phantom", "ashlrai/phantom-secrets"] as const;

export function aggregateStarCount(counts: Array<number | null>): number | null {
  if (counts.length !== GITHUB_STAR_REPOS.length) return null;
  const stars: number[] = [];
  for (const count of counts) {
    if (count === null || !Number.isInteger(count) || count < 0) return null;
    stars.push(count);
  }
  return stars.reduce((sum, count) => sum + count, 0);
}
