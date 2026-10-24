// Provider query parameters are best-effort links, not provider API contracts.
// Only a canonical public documentation URL enters the prompt; no local state.
export const DOCUMENTATION_ASSISTANTS = Object.freeze([
  { id: "chatgpt", name: "ChatGPT", base: "https://chatgpt.com/", query: "q" },
  { id: "claude", name: "Claude", base: "https://claude.ai/new", query: null },
  { id: "perplexity", name: "Perplexity", base: "https://www.perplexity.ai/search/new", query: "q" },
  { id: "gemini", name: "Gemini", base: "https://gemini.google.com/app", query: null },
  { id: "grok", name: "Grok", base: "https://grok.com/", query: null },
]);

/** @param {string} path */
export function documentationPrompt(path) {
  if (!/^\/docs(?:\/[a-z0-9]+(?:-[a-z0-9]+)*)?$/.test(path)) {
    throw new Error("Expected a canonical public documentation path");
  }
  return `Read https://phm.dev${path} and its linked public guides. Summarize what this guide explains, give a practical setup checklist, and distinguish interactive work, operator-only authorization, and verified runtime readiness. Cite the documentation and say when a source cannot be accessed. Do not infer my local account state or ask for credentials.`;
}

/** @param {string} id @param {string} path */
export function documentationAssistantLink(id, path) {
  const provider = DOCUMENTATION_ASSISTANTS.find((candidate) => candidate.id === id);
  if (!provider) throw new Error("Unknown documentation assistant");
  const prompt = documentationPrompt(path);
  const url = new URL(provider.base);
  if (provider.query) url.searchParams.set(provider.query, prompt);
  return { href: url.toString(), prompt, attemptsPrefill: provider.query !== null };
}
