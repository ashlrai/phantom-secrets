// Exact IDs from the Secrets home at source 8f3795b. Shared shell and new
// workbench anchors stay on their own page; unknown fragments never redirect.
const legacySecretsIds = new Set([
  "trusted-route-marquee",
  "ecosystem-title",
  "credential-ecosystem-marquee",
  "transformation-title",
  "request-proof-title",
  "install",
  "passage-title",
  "connect",
  "client-connection-panel",
  "how",
  "features",
  "comparison",
  "docs-gateway-title",
  "evidence-title",
  "pricing",
  "faq",
]);

export function legacySecretsDestination(pathname: string, hash: string): string | null {
  if (pathname !== "/" || !hash.startsWith("#")) return null;
  let id: string;
  try {
    id = decodeURIComponent(hash.slice(1));
  } catch {
    return null;
  }
  return legacySecretsIds.has(id) ? `/secrets#${id}` : null;
}
