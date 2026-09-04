import "server-only";

import { readFileSync } from "node:fs";
import path from "node:path";
import docsCatalog from "../../docs-catalog.json";

export interface PublicDocConfig {
  slug: string;
  file: string;
  title: string;
  description: string;
}

export interface PublicDoc extends PublicDocConfig {
  markdown: string;
  sourceUrl: string;
}

const REPOSITORY_URL = "https://github.com/ashlrai/phantom-secrets";
const DOCS_ROOT = path.resolve(process.cwd(), "..", "..", "docs");
const SAFE_SLUG = /^[a-z0-9]+(?:-[a-z0-9]+)*$/;
const SAFE_FILE = /^[a-z0-9]+(?:-[a-z0-9]+)*\.md$/;

export const PUBLIC_DOCS = docsCatalog as readonly PublicDocConfig[];

for (const entry of PUBLIC_DOCS) {
  if (!SAFE_SLUG.test(entry.slug) || !SAFE_FILE.test(entry.file)) {
    throw new Error(`Unsafe public documentation catalog entry: ${entry.slug}`);
  }
}

export function getPublicDocConfig(slug: string): PublicDocConfig | undefined {
  return PUBLIC_DOCS.find((entry) => entry.slug === slug);
}

export function getPublicDoc(slug: string): PublicDoc | undefined {
  const entry = getPublicDocConfig(slug);
  if (!entry) return undefined;

  return {
    ...entry,
    markdown: readFileSync(path.join(DOCS_ROOT, entry.file), "utf8"),
    sourceUrl: `${REPOSITORY_URL}/blob/main/docs/${entry.file}`,
  };
}

export function publicDocHrefForMarkdownFile(file: string): string | undefined {
  const entry = PUBLIC_DOCS.find((candidate) => candidate.file === file);
  return entry ? `/docs/${entry.slug}` : undefined;
}
