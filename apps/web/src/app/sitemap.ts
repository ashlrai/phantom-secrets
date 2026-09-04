import type { MetadataRoute } from "next";
import { PUBLIC_DOCS } from "@/lib/public-docs";

const SITE_URL = "https://phm.dev";

const pages = [
  { path: "/", modified: "2026-09-04" },
  { path: "/docs", modified: "2026-09-04" },
  { path: "/pricing", modified: "2026-09-03" },
  { path: "/enterprise", modified: "2026-09-03" },
  { path: "/government", modified: "2026-09-03" },
  { path: "/security", modified: "2026-09-03" },
  { path: "/llms.txt", modified: "2026-09-04" },
  { path: "/llms-full.txt", modified: "2026-09-03" },
] as const;

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
