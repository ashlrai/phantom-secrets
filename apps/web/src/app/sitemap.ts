import type { MetadataRoute } from "next";
import { PUBLIC_DOCS } from "@/lib/public-docs";

const SITE_URL = "https://phm.dev";

// fresh:begin sitemap-pages
const pages = [
  { path: "/", modified: "2026-10-24" },
  { path: "/secrets", modified: "2026-10-24" },
  { path: "/docs", modified: "2026-10-24" },
  { path: "/docs/manifest.json", modified: "2026-10-24" },
  { path: "/workbench/llms.txt", modified: "2026-10-24" },
  { path: "/workbench/llms-full.txt", modified: "2026-10-24" },
  { path: "/pricing", modified: "2026-09-03" },
  { path: "/enterprise", modified: "2026-09-03" },
  { path: "/government", modified: "2026-09-03" },
  { path: "/security", modified: "2026-09-29" },
  { path: "/llms.txt", modified: "2026-09-06" },
  { path: "/llms-full.txt", modified: "2026-09-06" },
] as const;
// fresh:end

export default function sitemap(): MetadataRoute.Sitemap {
  const documentationPages = PUBLIC_DOCS.map(({ slug, modified }) => ({
    path: `/docs/${slug}`,
    modified,
  }));

  return [...pages, ...documentationPages].map(({ path, modified }) => ({
    url: new URL(path, SITE_URL).toString(),
    lastModified: modified,
  }));
}
