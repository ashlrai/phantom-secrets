import type { MetadataRoute } from "next";

const SITE_URL = "https://phm.dev";
const REPO_URL = "https://github.com/ashlrai/phantom-secrets";

export default function sitemap(): MetadataRoute.Sitemap {
  const now = new Date();
  return [
    // Marketing pages
    {
      url: `${SITE_URL}/`,
      lastModified: now,
      changeFrequency: "weekly",
      priority: 1,
    },
    {
      url: `${SITE_URL}/pricing`,
      lastModified: now,
      changeFrequency: "monthly",
      priority: 0.8,
    },

    // AI-agent-facing entry points (must be crawlable)
    {
      url: `${SITE_URL}/llms.txt`,
      lastModified: now,
      changeFrequency: "weekly",
      priority: 0.9,
    },
    {
      url: `${SITE_URL}/llms-full.txt`,
      lastModified: now,
      changeFrequency: "weekly",
      priority: 0.9,
    },
    {
      url: `${SITE_URL}/.well-known/ai-plugin.json`,
      lastModified: now,
      changeFrequency: "monthly",
      priority: 0.7,
    },

    // Documentation hosted on GitHub (canonical source)
    {
      url: `${REPO_URL}/blob/main/docs/getting-started.md`,
      lastModified: now,
      changeFrequency: "weekly",
      priority: 0.8,
    },
    {
      url: `${REPO_URL}/blob/main/docs/claude-code.md`,
      lastModified: now,
      changeFrequency: "weekly",
      priority: 0.8,
    },
    {
      url: `${REPO_URL}/blob/main/SECURITY.md`,
      lastModified: now,
      changeFrequency: "monthly",
      priority: 0.6,
    },
    {
      url: `${REPO_URL}/blob/main/README.md`,
      lastModified: now,
      changeFrequency: "weekly",
      priority: 0.7,
    },
  ];
}
