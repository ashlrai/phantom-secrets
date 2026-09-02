export function extractReadmeMcpToolNames(readme) {
  // Git may materialize CRLF checkouts on Windows. Keep the release contract
  // independent of the runner's configured working-tree line endings.
  const normalizedReadme = readme.replace(/\r\n?/g, "\n");
  const catalogStart = normalizedReadme.indexOf("- **Conversation facade**");
  const catalogEnd = normalizedReadme.indexOf(
    "\n\nTools that write state",
    catalogStart
  );
  if (catalogStart < 0 || catalogEnd < 0) {
    throw new Error("README MCP catalog boundaries are missing");
  }

  return [
    ...new Set(
      normalizedReadme
        .slice(catalogStart, catalogEnd)
        .match(/`(phantom_[a-z_]+)`/g)
        ?.map((match) => match.slice(1, -1)) ?? []
    ),
  ].sort();
}
