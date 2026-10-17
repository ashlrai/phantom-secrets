import "server-only";

import docsCatalog from "../../docs-catalog.json";
import gettingStarted from "../../../../docs/getting-started.md";
import delegationQuickstart from "../../../../docs/delegation-quickstart.md";
import protectApiKeys from "../../../../docs/protect-api-keys-from-ai-coding-agents.md";
import mcpSecretsManager from "../../../../docs/mcp-secrets-manager.md";
import publicFactSheet from "../../../../docs/public-fact-sheet.md";
import claudeCode from "../../../../docs/claude-code.md";
import cursor from "../../../../docs/cursor.md";
import windsurf from "../../../../docs/windsurf.md";
import codex from "../../../../docs/codex.md";
import platformSupport from "../../../../docs/platform-support.md";
import troubleshooting from "../../../../docs/troubleshooting.md";
import architecture from "../../../../docs/architecture.md";
import enterpriseAdoption from "../../../../docs/enterprise-adoption.md";

export interface PublicDocConfig {
  slug: string;
  file: string;
  title: string;
  description: string;
  modified: string;
}

export interface PublicDoc extends PublicDocConfig {
  markdown: string;
  sourceUrl: string;
}

const REPOSITORY_URL = "https://github.com/ashlrai/phantom-secrets";
// These imports are escaped text modules, not runtime filesystem reads. The
// exact catalog bijection below refuses drift if a guide is added or removed.
const MARKDOWN_BY_FILE: Readonly<Record<string, string>> = {
  "getting-started.md": gettingStarted,
  "delegation-quickstart.md": delegationQuickstart,
  "protect-api-keys-from-ai-coding-agents.md": protectApiKeys,
  "mcp-secrets-manager.md": mcpSecretsManager,
  "public-fact-sheet.md": publicFactSheet,
  "claude-code.md": claudeCode,
  "cursor.md": cursor,
  "windsurf.md": windsurf,
  "codex.md": codex,
  "platform-support.md": platformSupport,
  "troubleshooting.md": troubleshooting,
  "architecture.md": architecture,
  "enterprise-adoption.md": enterpriseAdoption,
};
const SAFE_SLUG = /^[a-z0-9]+(?:-[a-z0-9]+)*$/;
const SAFE_FILE = /^[a-z0-9]+(?:-[a-z0-9]+)*\.md$/;
const ISO_DATE = /^\d{4}-\d{2}-\d{2}$/;

export const PUBLIC_DOCS = docsCatalog as readonly PublicDocConfig[];

for (const entry of PUBLIC_DOCS) {
  if (
    !SAFE_SLUG.test(entry.slug) ||
    !SAFE_FILE.test(entry.file) ||
    !ISO_DATE.test(entry.modified) ||
    typeof MARKDOWN_BY_FILE[entry.file] !== "string"
  ) {
    throw new Error(`Unsafe public documentation catalog entry: ${entry.slug}`);
  }
}
if (
  new Set(PUBLIC_DOCS.map(({ file }) => file)).size !== PUBLIC_DOCS.length ||
  Object.keys(MARKDOWN_BY_FILE).length !== PUBLIC_DOCS.length
) {
  throw new Error("Public documentation catalog and embedded Markdown must match exactly");
}

export function getPublicDocConfig(slug: string): PublicDocConfig | undefined {
  return PUBLIC_DOCS.find((entry) => entry.slug === slug);
}

export function getPublicDoc(slug: string): PublicDoc | undefined {
  const entry = getPublicDocConfig(slug);
  if (!entry) return undefined;

  return {
    ...entry,
    markdown: MARKDOWN_BY_FILE[entry.file],
    sourceUrl: `${REPOSITORY_URL}/blob/main/docs/${entry.file}`,
  };
}

export function publicDocHrefForMarkdownFile(file: string): string | undefined {
  const entry = PUBLIC_DOCS.find((candidate) => candidate.file === file);
  return entry ? `/docs/${entry.slug}` : undefined;
}
