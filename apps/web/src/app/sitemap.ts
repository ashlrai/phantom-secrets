import type { MetadataRoute } from "next";

const SITE_URL = "https://phm.dev";

const pages = [
  { path: "/", changeFrequency: "weekly", priority: 1 },
  { path: "/pricing", changeFrequency: "monthly", priority: 0.8 },
  { path: "/enterprise", changeFrequency: "monthly", priority: 0.8 },
  { path: "/government", changeFrequency: "monthly", priority: 0.8 },
  { path: "/security", changeFrequency: "monthly", priority: 0.8 },
  { path: "/llms.txt", changeFrequency: "weekly", priority: 0.7 },
  { path: "/llms-full.txt", changeFrequency: "weekly", priority: 0.7 },
] as const;

export default function sitemap(): MetadataRoute.Sitemap {
  return pages.map(({ path, changeFrequency, priority }) => ({
    url: new URL(path, SITE_URL).toString(),
    changeFrequency,
    priority,
  }));
}
