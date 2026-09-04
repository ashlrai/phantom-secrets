import type { MetadataRoute } from "next";
import { PUBLIC_DOCS } from "@/lib/public-docs";

const SITE_URL = "https://phm.dev";

const pages = [
  { path: "/", changeFrequency: "weekly", priority: 1 },
  { path: "/docs", changeFrequency: "weekly", priority: 0.9 },
  { path: "/pricing", changeFrequency: "monthly", priority: 0.8 },
  { path: "/enterprise", changeFrequency: "monthly", priority: 0.8 },
  { path: "/government", changeFrequency: "monthly", priority: 0.8 },
  { path: "/security", changeFrequency: "monthly", priority: 0.8 },
  { path: "/llms.txt", changeFrequency: "weekly", priority: 0.7 },
  { path: "/llms-full.txt", changeFrequency: "weekly", priority: 0.7 },
] as const;

export default function sitemap(): MetadataRoute.Sitemap {
  const documentationPages = PUBLIC_DOCS.map(({ slug }) => ({
    path: `/docs/${slug}`,
    changeFrequency: "weekly" as const,
    priority: 0.8,
  }));

  return [...pages, ...documentationPages].map(({ path, changeFrequency, priority }) => ({
    url: new URL(path, SITE_URL).toString(),
    changeFrequency,
    priority,
  }));
}
